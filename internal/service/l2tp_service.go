package service

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

func stripCIDR(addr string) string {
	ip, _, err := net.ParseCIDR(addr)
	if err != nil {
		if parsed := net.ParseIP(addr); parsed != nil {
			return parsed.String()
		}
		return addr
	}
	return ip.String()
}

// stripPort returns just the host portion of an address that may be in
// "host:port" form. RouterIP is sometimes stored as "10.0.0.1:9291" because
// MikroTik's API port is configurable; iptables -s and the strongswan/xl2tpd
// configs expect a bare IP or CIDR, so any port suffix breaks them silently.
//
// Inputs accepted: "10.0.0.1", "10.0.0.1:9291", "10.0.0.1/24", "[::1]:500".
// Anything net.SplitHostPort can't parse is returned unchanged.
func stripPort(addr string) string {
	if addr == "" {
		return addr
	}
	// Already a CIDR (no port suffix possible) — leave it.
	if _, _, err := net.ParseCIDR(addr); err == nil {
		return addr
	}
	// Bare IP — fast path.
	if net.ParseIP(addr) != nil {
		return addr
	}
	// Try host:port. SplitHostPort handles [v6]:port and host:port.
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

type L2TPService struct {
	nsSvc       *NamespaceService
	log         *zap.Logger
	vpsPublicIP string
}

func NewL2TPService(nsSvc *NamespaceService, vpsPublicIP string, log *zap.Logger) *L2TPService {
	svc := &L2TPService{nsSvc: nsSvc, vpsPublicIP: vpsPublicIP, log: log}
	svc.installIPUpScript()
	return svc
}

func (s *L2TPService) installIPUpScript() {
	scriptPath := "/etc/ppp/ip-up.d/99-jinom-routes"
	scriptContent := `#!/bin/sh
# $1: IFNAME (e.g. ppp0)
# $6: IPPARAM (e.g. ns-res-11)

if [ -n "$6" ] && [ -f "/etc/ppp/routes.$6" ]; then
    while read subnet; do
        if [ -n "$subnet" ]; then
            ip route add "$subnet" dev "$1" || true
        fi
    done < "/etc/ppp/routes.$6"
fi
`
	if err := os.MkdirAll("/etc/ppp/ip-up.d", 0755); err != nil {
		s.log.Warn("Failed to create /etc/ppp/ip-up.d; per-tunnel routes will not auto-install", zap.Error(err))
		return
	}
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		s.log.Warn("Failed to install ip-up route hook; per-tunnel routes will not auto-install",
			zap.String("path", scriptPath), zap.Error(err))
	}
}

func (s *L2TPService) Setup(t *tunnel.ResellerTunnel) (err error) {
	s.log.Info("Setting up L2TP/IPSec tunnel",
		zap.String("namespace", t.Namespace),
		zap.String("tunnel", t.Name),
		zap.Int("tunnel_index", t.TunnelIndex),
	)

	// Any failure beyond this point may leave veth, iptables rules, daemons,
	// or config files behind. Teardown is idempotent — running it on a
	// partial setup is safe and the cheapest way to keep state consistent.
	defer func() {
		if err != nil {
			s.log.Warn("L2TP setup failed, rolling back",
				zap.String("namespace", t.Namespace), zap.Error(err))
			_ = s.Teardown(t)
		}
	}()

	hostIP, nsIP, nsIPNoMask, _ := indexToVethIPs(t.TunnelIndex)
	vethHost := fmt.Sprintf("vh-%d", t.TunnelIndex)
	vethNs := fmt.Sprintf("vn-%d", t.TunnelIndex)

	runCmd := func(name string, args ...string) error {
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			s.log.Warn("Command failed", zap.String("cmd", name), zap.Strings("args", args), zap.Error(err), zap.String("out", string(out)))
			return err
		}
		return nil
	}

	exec.Command("ip", "link", "del", vethHost).CombinedOutput()
	time.Sleep(100 * time.Millisecond)

	if err := runCmd("ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethNs); err != nil {
		return fmt.Errorf("failed to create veth interface: %w", err)
	}
	if err := runCmd("ip", "link", "set", vethNs, "netns", t.Namespace); err != nil {
		return fmt.Errorf("failed to move veth to namespace: %w", err)
	}
	if err := runCmd("ip", "addr", "add", hostIP, "dev", vethHost); err != nil {
		return fmt.Errorf("failed to add host veth address: %w", err)
	}
	if err := runCmd("ip", "link", "set", vethHost, "up"); err != nil {
		return fmt.Errorf("failed to bring up host veth: %w", err)
	}

	if _, err := s.nsSvc.ExecInNS(t.Namespace, "ip", "addr", "add", nsIP, "dev", vethNs); err != nil {
		return fmt.Errorf("failed to add namespace veth address: %w", err)
	}
	if _, err := s.nsSvc.ExecInNS(t.Namespace, "ip", "link", "set", vethNs, "up"); err != nil {
		return fmt.Errorf("failed to bring up namespace veth: %w", err)
	}
	gwIP, _, _, _ := indexToVethIPs(t.TunnelIndex)
	gwIPNoMask := stripCIDR(gwIP)
	if _, err := s.nsSvc.ExecInNS(t.Namespace, "ip", "route", "add", "default", "via", gwIPNoMask); err != nil {
		return fmt.Errorf("failed to add default route in namespace: %w", err)
	}

	s.cleanupRouting(stripPort(t.RouterIP), nsIPNoMask, t.TunnelIndex, t.ClientIPAddress)
	if err := s.setupRouting(runCmd, t, nsIPNoMask, t.TunnelIndex, vethHost, vethNs); err != nil {
		return fmt.Errorf("setup routing: %w", err)
	}

	if err := s.writeIPSecConfig(t, nsIPNoMask); err != nil {
		return fmt.Errorf("write ipsec config: %w", err)
	}
	if err := s.writeXL2TPDConfig(t); err != nil {
		return fmt.Errorf("write xl2tpd config: %w", err)
	}
	if err := s.updateChapSecrets(t); err != nil {
		s.log.Warn("Failed to update chap-secrets", zap.Error(err))
	}

	if err := s.startIPSec(t); err != nil {
		return fmt.Errorf("start ipsec: %w", err)
	}
	if err := s.startXL2TPD(t.Namespace); err != nil {
		return fmt.Errorf("start xl2tpd: %w", err)
	}

	return nil
}

func indexToVethIPs(index int) (hostIP, nsIP, nsIPNoMask, subnet string) {
	a := index / 64
	b := (index % 64) * 4
	hostIP = fmt.Sprintf("10.254.%d.%d/30", a, b+1)
	nsIP = fmt.Sprintf("10.254.%d.%d/30", a, b+2)
	nsIPNoMask = fmt.Sprintf("10.254.%d.%d", a, b+2)
	subnet = fmt.Sprintf("10.254.%d.%d/30", a, b)
	return
}

// deleteRule repeatedly deletes a matching iptables rule until no more copies
// remain. The "-w" flag makes iptables wait for the xtables lock instead of
// failing instantly when another setup/teardown runs concurrently — without it
// a lock contention would look like "rule absent" and stop the loop early,
// leaving duplicate rules behind.
func (s *L2TPService) deleteRule(args ...string) {
	for {
		full := append([]string{"-w"}, args...)
		if exec.Command("iptables", full...).Run() != nil {
			break
		}
	}
}

func (s *L2TPService) routeTableID(index int) string {
	return fmt.Sprintf("%d", 1000+index)
}

func (s *L2TPService) cleanupRouting(routerIP, nsIPNoMask string, index int, clientIP string) {
	_, _, _, subnet := indexToVethIPs(index)

	// List of potential internal IPs to clean up (current, old legacy, and zero-index)
	oldIPs := []string{nsIPNoMask, "10.254.222.2", "10.254.0.2"}
	
	for _, ip := range oldIPs {
		// Cleanup DNAT rules for IPSec and L2TP forwarding to namespace
		s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-d", s.vpsPublicIP, "-p", "udp", "--dport", "500", "-j", "DNAT", "--to-destination", ip+":500")
		s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-d", s.vpsPublicIP, "-p", "udp", "--dport", "4500", "-j", "DNAT", "--to-destination", ip+":4500")
		s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-d", s.vpsPublicIP, "-p", "udp", "--dport", "1701", "-j", "DNAT", "--to-destination", ip+":1701")

		// Cleanup legacy DNAT rules without -d filter
		s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-p", "udp", "--dport", "500", "-j", "DNAT", "--to-destination", ip+":500")
		s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-p", "udp", "--dport", "4500", "-j", "DNAT", "--to-destination", ip+":4500")
		s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-p", "udp", "--dport", "1701", "-j", "DNAT", "--to-destination", ip+":1701")
		
		// Cleanup SNAT rules
		s.deleteRule("-t", "nat", "-D", "POSTROUTING", "-s", ip, "-p", "udp", "--sport", "500", "-j", "SNAT", "--to-source", s.vpsPublicIP+":500")
		s.deleteRule("-t", "nat", "-D", "POSTROUTING", "-s", ip, "-p", "udp", "--sport", "4500", "-j", "SNAT", "--to-source", s.vpsPublicIP+":4500")
		s.deleteRule("-t", "nat", "-D", "POSTROUTING", "-s", ip, "-p", "udp", "--sport", "1701", "-j", "SNAT", "--to-source", s.vpsPublicIP+":1701")
		
		// Cleanup FORWARD rules
		s.deleteRule("-t", "filter", "-D", "FORWARD", "-d", ip, "-j", "ACCEPT")
		s.deleteRule("-t", "filter", "-D", "FORWARD", "-s", ip, "-j", "ACCEPT")
	}

	// Cleanup MASQUERADE and other router-specific rules
	s.deleteRule("-t", "nat", "-D", "POSTROUTING", "-s", routerIP, "-j", "MASQUERADE")
	s.deleteRule("-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE")
	s.deleteRule("-t", "nat", "-D", "POSTROUTING", "-s", clientIP, "-j", "MASQUERADE")

	// Cleanup legacy policy routing
	tableID := s.routeTableID(index)
	for {
		if exec.Command("ip", "rule", "del", "from", routerIP, "lookup", tableID).Run() != nil {
			break
		}
	}
	exec.Command("ip", "route", "flush", "table", tableID).Run()

	exec.Command("conntrack", "-D", "-s", routerIP, "-p", "udp", "--dport", "500").Run()
	exec.Command("conntrack", "-D", "-s", routerIP, "-p", "udp", "--dport", "4500").Run()
	exec.Command("conntrack", "-D", "-s", routerIP, "-p", "udp", "--dport", "1701").Run()
	exec.Command("conntrack", "-D", "-d", routerIP, "-p", "udp", "--sport", "500").Run()
	exec.Command("conntrack", "-D", "-d", routerIP, "-p", "udp", "--sport", "4500").Run()
	exec.Command("conntrack", "-D", "-d", routerIP, "-p", "udp", "--sport", "1701").Run()
}

func (s *L2TPService) setupRouting(runCmd func(string, ...string) error, t *tunnel.ResellerTunnel, nsIPNoMask string, index int, vethHost, vethNs string) error {
	_, _, _, subnet := indexToVethIPs(index)

	// RouterIP may carry a port suffix ("1.2.3.4:9291" — MikroTik's API port is
	// configurable and is stored alongside the host). iptables -s and -d only
	// accept host or CIDR, so always strip the port before passing through.
	routerHost := stripPort(t.RouterIP)

	// s.nsSvc.ExecInNS(t.Namespace, "ip", "addr", "add", s.vpsPublicIP+"/32", "dev", vethNs)

	// ipt wraps runCmd with the "-w" flag so every rule mutation waits for the
	// xtables lock instead of failing under concurrent setup/teardown.
	ipt := func(args ...string) error {
		return runCmd("iptables", append([]string{"-w"}, args...)...)
	}

	// Use DNAT to redirect IPSec/L2TP traffic from router to namespace.
	// Policy routing cannot work because the host's local table (priority 0)
	// intercepts packets destined for vpsPublicIP before custom rules are checked.
	ipt("-t", "nat", "-A", "PREROUTING", "-s", routerHost, "-d", s.vpsPublicIP, "-p", "udp", "--dport", "500", "-j", "DNAT", "--to-destination", nsIPNoMask+":500")
	ipt("-t", "nat", "-A", "PREROUTING", "-s", routerHost, "-d", s.vpsPublicIP, "-p", "udp", "--dport", "4500", "-j", "DNAT", "--to-destination", nsIPNoMask+":4500")
	ipt("-t", "nat", "-A", "PREROUTING", "-s", routerHost, "-d", s.vpsPublicIP, "-p", "udp", "--dport", "1701", "-j", "DNAT", "--to-destination", nsIPNoMask+":1701")

	ipt("-t", "nat", "-I", "POSTROUTING", "1", "-s", nsIPNoMask, "-p", "udp", "--sport", "500", "-j", "SNAT", "--to-source", s.vpsPublicIP+":500")
	ipt("-t", "nat", "-I", "POSTROUTING", "2", "-s", nsIPNoMask, "-p", "udp", "--sport", "4500", "-j", "SNAT", "--to-source", s.vpsPublicIP+":4500")
	ipt("-t", "nat", "-I", "POSTROUTING", "3", "-s", nsIPNoMask, "-p", "udp", "--sport", "1701", "-j", "SNAT", "--to-source", s.vpsPublicIP+":1701")
	ipt("-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE")
	ipt("-t", "nat", "-A", "POSTROUTING", "-s", t.ClientIPAddress, "-j", "MASQUERADE")
	ipt("-t", "filter", "-I", "FORWARD", "1", "-d", nsIPNoMask, "-j", "ACCEPT")
	ipt("-t", "filter", "-I", "FORWARD", "1", "-s", nsIPNoMask, "-j", "ACCEPT")

	return nil
}

func (s *L2TPService) ipsecConfDir(ns string) string {
	return fmt.Sprintf("/etc/ipsec.d/%s", ns)
}

// ipsecRunDir is the per-tunnel runtime directory bind-mounted over /run inside
// the tunnel's private mount namespace. strongSwan's `ipsec` wrapper hard-codes
// IPSEC_PIDDIR=/var/run (a symlink to /run on Ubuntu) and the charon control
// socket /run/charon.ctl, so charon's pidfiles and control socket all resolve
// into THIS directory once /run is bound — giving each tunnel a fully isolated
// charon. /run is tmpfs and cleared on reboot, so nothing leaks across boots.
func (s *L2TPService) ipsecRunDir(ns string) string {
	return filepath.Join("/run/ipsec", ns)
}

// netnsMountExec runs a shell script inside the tunnel's network namespace AND a
// fresh private mount namespace, so bind-mounts performed by the script (e.g.
// /run, /etc/ipsec.conf) are confined to that tunnel and never touch the host.
//
// Why this isolates a daemon that outlives the command: `ipsec start` forks
// starter+charon, which inherit the mount ns and keep it alive after the
// launcher shell exits. Re-entering a fresh mount ns later (stop/statusall) and
// re-binding the same real host dir over /run exposes the identical charon.pid
// and charon.ctl inode, so control operations reach exactly this tunnel's charon.
func (s *L2TPService) netnsMountExec(ns, script string) *exec.Cmd {
	return exec.Command("ip", "netns", "exec", ns,
		"unshare", "--mount", "--propagation", "private",
		"/bin/sh", "-c", script)
}

func (s *L2TPService) startIPSec(t *tunnel.ResellerTunnel) error {
	ns := t.Namespace
	confDir := s.ipsecConfDir(ns)
	runDir := s.ipsecRunDir(ns)

	// Best-effort stop of any prior instance for THIS tunnel, then wipe its
	// runtime dir so a crashed charon can't leave a stale pid/control socket.
	s.stopIPSecInNS(ns, confDir)
	_ = os.RemoveAll(runDir)
	time.Sleep(300 * time.Millisecond)

	// Bind /run -> per-tunnel runDir (isolates charon.pid/ctl), and bind this
	// tunnel's ipsec.conf/ipsec.secrets over the wrapper's hard-coded /etc paths
	// so the PSK and conn actually load. `set -e`: every bind must succeed.
	script := fmt.Sprintf(`set -e
mkdir -p %[1]s
mount --bind %[1]s /run
mount --bind %[2]s/ipsec.conf /etc/ipsec.conf
mount --bind %[2]s/ipsec.secrets /etc/ipsec.secrets
exec ipsec start`, runDir, confDir)

	out, err := s.netnsMountExec(ns, script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipsec start: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	time.Sleep(2 * time.Second)

	statusOut, _ := s.IPSecStatusall(ns)
	s.log.Info("IPSec status after start", zap.String("namespace", ns), zap.String("status", string(statusOut)))

	return nil
}

// IPSecStatusall queries ONLY this tunnel's charon via its private control
// socket (charon.ctl inside ipsecRunDir), by re-binding /run in a fresh mount
// namespace. Used by startIPSec verification and by the health monitor so SA
// counts never bleed across tunnels.
func (s *L2TPService) IPSecStatusall(ns string) ([]byte, error) {
	runDir := s.ipsecRunDir(ns)
	script := fmt.Sprintf(`mkdir -p %[1]s; mount --bind %[1]s /run; exec ipsec statusall`, runDir)
	return s.netnsMountExec(ns, script).CombinedOutput()
}

// stopIPSecInNS stops ONLY this tunnel's charon. It binds /run to the tunnel's
// runtime dir (so `ipsec stop` reads this tunnel's starter.charon.pid) and then
// hard-kills by the per-tunnel pidfiles as a backstop. It never uses a global
// `pkill charon`, which would take down every tunnel. The confDir arg is unused
// now (conf binding is only needed for start) but kept for caller stability.
func (s *L2TPService) stopIPSecInNS(ns, _ string) {
	runDir := s.ipsecRunDir(ns)

	// No `set -e` and no conf binds: during Teardown the config files may be
	// gone, but `ipsec stop` only needs /run to find the pidfile.
	stop := fmt.Sprintf(`mkdir -p %[1]s; mount --bind %[1]s /run; exec ipsec stop`, runDir)
	_, _ = s.netnsMountExec(ns, stop).CombinedOutput()

	// Backstop: PIDs are global (no PID-ns), so a bare `kill <pid>` from the
	// host reaches this tunnel's charon/starter even if `ipsec stop` failed.
	for _, f := range []string{"charon.pid", "starter.charon.pid"} {
		if data, err := os.ReadFile(filepath.Join(runDir, f)); err == nil {
			if pid := strings.TrimSpace(string(data)); pid != "" {
				_ = exec.Command("kill", pid).Run()
			}
		}
	}
}

func (s *L2TPService) xl2tpdControlPath(ns string) string {
	return filepath.Join("/run/xl2tpd", fmt.Sprintf("%s-control", ns))
}

func (s *L2TPService) startXL2TPD(ns string) error {
	s.killXL2TPD(ns)

	confPath := filepath.Join("/etc/xl2tpd", fmt.Sprintf("%s.conf", ns))
	pidPath := filepath.Join("/run", fmt.Sprintf("xl2tpd-%s.pid", ns))
	ctlPath := s.xl2tpdControlPath(ns)

	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		return fmt.Errorf("config file not found: %s", confPath)
	}

	// xl2tpd defaults its control socket to the global /run/xl2tpd/l2tp-control,
	// which would collide across namespaces (netns does not isolate the
	// filesystem). A per-tunnel -C path keeps each instance independent.
	if err := os.MkdirAll("/run/xl2tpd", 0755); err != nil {
		return fmt.Errorf("create xl2tpd control dir: %w", err)
	}
	_ = os.Remove(ctlPath) // drop a stale socket from a crashed instance

	cmd := exec.Command("ip", "netns", "exec", ns,
		"xl2tpd", "-c", confPath, "-p", pidPath, "-C", ctlPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("exec in %s: %s: %w", ns, strings.TrimSpace(string(out)), err)
	}

	time.Sleep(500 * time.Millisecond)

	if _, err := os.Stat(pidPath); os.IsNotExist(err) {
		s.log.Warn("xl2tpd PID file not created, checking if process is running",
			zap.String("namespace", ns))
	}

	s.log.Info("xl2tpd started", zap.String("namespace", ns), zap.String("pid_file", pidPath))
	return nil
}

func (s *L2TPService) killXL2TPD(ns string) {
	pidPath := filepath.Join("/run", fmt.Sprintf("xl2tpd-%s.pid", ns))
	data, err := os.ReadFile(pidPath)
	if err == nil {
		pidStr := strings.TrimSpace(string(data))
		_, _ = s.nsSvc.ExecInNS(ns, "kill", pidStr)
		_ = os.Remove(pidPath)
		time.Sleep(300 * time.Millisecond)
	}

	// Also kill any lingering xl2tpd using this config
	_, _ = s.nsSvc.ExecInNS(ns, "pkill", "-f", fmt.Sprintf("xl2tpd.*%s.conf", ns))
	time.Sleep(200 * time.Millisecond)

	_ = os.Remove(s.xl2tpdControlPath(ns))
}

func (s *L2TPService) Teardown(t *tunnel.ResellerTunnel) error {
	s.log.Info("Tearing down L2TP/IPSec tunnel",
		zap.String("namespace", t.Namespace),
	)

	s.killXL2TPD(t.Namespace)
	_ = s.removeChapSecrets(t.Namespace)
	s.stopIPSecInNS(t.Namespace, s.ipsecConfDir(t.Namespace))

	_, _, nsIPNoMask, _ := indexToVethIPs(t.TunnelIndex)
	vethHost := fmt.Sprintf("vh-%d", t.TunnelIndex)

	s.cleanupRouting(stripPort(t.RouterIP), nsIPNoMask, t.TunnelIndex, t.ClientIPAddress)
	exec.Command("ip", "link", "del", vethHost).CombinedOutput()

	confDir := s.ipsecConfDir(t.Namespace)
	_ = os.RemoveAll(confDir)
	_ = os.RemoveAll(s.ipsecRunDir(t.Namespace))
	_ = os.Remove(filepath.Join("/etc/xl2tpd", t.Namespace+".conf"))
	_ = os.Remove(filepath.Join("/run", fmt.Sprintf("xl2tpd-%s.pid", t.Namespace)))
	_ = os.Remove(s.xl2tpdControlPath(t.Namespace))
	_ = os.Remove(filepath.Join("/etc/ppp", fmt.Sprintf("options.%s", t.Namespace)))
	_ = os.Remove(filepath.Join("/etc/ppp", fmt.Sprintf("routes.%s", t.Namespace)))

	return nil
}

// buildConnConf renders the strongSwan `conn` block. The cipher proposals list
// strong, modern algorithms FIRST (aes256-sha256-modp2048) so capable routers
// negotiate them, then keep legacy fallbacks (down to 3des-sha1) for old
// RouterOS 6 devices. Both proposal sets are strict ("!") so nothing weaker
// than what's listed can be silently negotiated. left is the namespace veth IP,
// leftid the VPS public IP, right the router host (port already stripped).
func (s *L2TPService) buildConnConf(connName, leftIP, routerHost string) string {
	return fmt.Sprintf(`conn %s
    authby=secret
    auto=add
    type=transport
    leftfirewall=yes
    left=%s
    leftid=%s
    right=%s
    keyingtries=3
    ikelifetime=28800s
    lifetime=3600s
    ike=aes256-sha256-modp2048,aes128-sha256-modp2048,aes128-sha1-modp1024,aes128-md5-modp1024,3des-sha1-modp1024!
    esp=aes256-sha256,aes256-sha1,aes128-sha1,aes128-sha1-modp1024,3des-sha1!
`, connName, leftIP, s.vpsPublicIP, routerHost)
}

func (s *L2TPService) writeIPSecConfig(t *tunnel.ResellerTunnel, nsIPNoMask string) error {
	connName := fmt.Sprintf("jinom-%s", t.Namespace)
	nsConfDir := s.ipsecConfDir(t.Namespace)

	if err := os.MkdirAll(nsConfDir, 0700); err != nil {
		return err
	}

	routerHost := stripPort(t.RouterIP)
	connConf := s.buildConnConf(connName, nsIPNoMask, routerHost)

	connPath := filepath.Join(nsConfDir, connName+".conf")
	if err := os.WriteFile(connPath, []byte(connConf), 0600); err != nil {
		return err
	}

	secrets := fmt.Sprintf(`%s %s : PSK "%s"
`, s.vpsPublicIP, routerHost, t.PSK)
	secretsPath := filepath.Join(nsConfDir, connName+".secrets")
	if err := os.WriteFile(secretsPath, []byte(secrets), 0600); err != nil {
		return err
	}

	mainConf := fmt.Sprintf(`config setup
    charondebug="ike 2, enc 1, knl 2, cfg 2, net 2"
    uniqueids=yes

include %s/%s.conf
`, nsConfDir, connName)
	mainConfPath := filepath.Join(nsConfDir, "ipsec.conf")
	if err := os.WriteFile(mainConfPath, []byte(mainConf), 0600); err != nil {
		return err
	}

	mainSecrets := fmt.Sprintf("include %s/%s.secrets\n", nsConfDir, connName)
	mainSecretsPath := filepath.Join(nsConfDir, "ipsec.secrets")
	return os.WriteFile(mainSecretsPath, []byte(mainSecrets), 0600)
}

func (s *L2TPService) writeXL2TPDConfig(t *tunnel.ResellerTunnel) error {
	optsPath := filepath.Join("/etc/ppp", fmt.Sprintf("options.%s", t.Namespace))
	routesPath := filepath.Join("/etc/ppp", fmt.Sprintf("routes.%s", t.Namespace))

	opts := fmt.Sprintf(`ipcp-accept-local
ipcp-accept-remote
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 8.8.4.4
asyncmap 0
crtscts
lock
hide-password
modem
debug
name jinom-vpn
proxyarp
lcp-echo-interval 60
lcp-echo-failure 10
mtu 1100
mru 1100
ipparam %s
`, t.Namespace)
	if err := os.WriteFile(optsPath, []byte(opts), 0600); err != nil {
		return err
	}

	routesData := strings.Join(effectiveSubnets(t.MonitoringSubnets), "\n") + "\n"
	if err := os.WriteFile(routesPath, []byte(routesData), 0600); err != nil {
		return err
	}

	conf := fmt.Sprintf(`[global]
port = 1701
access control = no
force userspace = yes

[lns default]
ip range = %s
local ip = %s
require chap = yes
refuse pap = yes
require authentication = no
name = %s
pppoptfile = %s
length bit = no
`, stripCIDR(t.ClientIPAddress), stripCIDR(t.ServerIPAddress), t.Namespace, optsPath)

	if err := os.MkdirAll("/etc/xl2tpd", 0755); err != nil {
		return err
	}
	confPath := filepath.Join("/etc/xl2tpd", t.Namespace+".conf")
	return os.WriteFile(confPath, []byte(conf), 0600)
}

func (s *L2TPService) updateChapSecrets(t *tunnel.ResellerTunnel) error {
	// Remove existing entries for this namespace first to avoid duplicates
	_ = s.removeChapSecrets(t.Namespace)

	line := fmt.Sprintf("\"%s\" * \"%s\" * # jinom-vpn: %s\n", t.L2TPUsername, t.L2TPPassword, t.Namespace)

	f, err := os.OpenFile("/etc/ppp/chap-secrets", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(line)
	return err
}

func (s *L2TPService) removeChapSecrets(ns string) error {
	path := "/etc/ppp/chap-secrets"
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	lines := strings.Split(string(data), "\n")
	var newLines []string
	tag := fmt.Sprintf("# jinom-vpn: %s", ns)

	for _, line := range lines {
		if line != "" && !strings.Contains(line, tag) {
			newLines = append(newLines, line)
		}
	}

	// Add a trailing newline if we have lines
	content := strings.Join(newLines, "\n")
	if content != "" {
		content += "\n"
	}

	return os.WriteFile(path, []byte(content), 0600)
}
