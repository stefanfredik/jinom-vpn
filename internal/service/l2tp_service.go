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

type L2TPService struct {
	nsSvc       *NamespaceService
	log         *zap.Logger
	vpsPublicIP string
}

func NewL2TPService(nsSvc *NamespaceService, vpsPublicIP string, log *zap.Logger) *L2TPService {
	return &L2TPService{nsSvc: nsSvc, vpsPublicIP: vpsPublicIP, log: log}
}

func (s *L2TPService) Setup(t *tunnel.ResellerTunnel) error {
	s.log.Info("Setting up L2TP/IPSec tunnel",
		zap.String("namespace", t.Namespace),
		zap.String("tunnel", t.Name),
	)

	clientIP := stripCIDR(t.ClientIPAddress)
	octets := strings.Split(clientIP, ".")
	if len(octets) != 4 {
		return fmt.Errorf("invalid client IP: %s", t.ClientIPAddress)
	}

	X := octets[2]
	hostIP := fmt.Sprintf("10.254.%s.1/30", X)
	nsIP := fmt.Sprintf("10.254.%s.2/30", X)
	nsIPNoMask := fmt.Sprintf("10.254.%s.2", X)
	vethHost := fmt.Sprintf("vh-%s", X)
	vethNs := fmt.Sprintf("vn-%s", X)

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
	if _, err := s.nsSvc.ExecInNS(t.Namespace, "ip", "route", "add", "default", "via", fmt.Sprintf("10.254.%s.1", X)); err != nil {
		return fmt.Errorf("failed to add default route in namespace: %w", err)
	}

	s.cleanupRouting(t.RouterIP, nsIPNoMask, X, t.ClientIPAddress)
	if err := s.setupRouting(runCmd, t, nsIPNoMask, X, vethHost, vethNs); err != nil {
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

func (s *L2TPService) deleteRule(args ...string) {
	for {
		if exec.Command("iptables", args...).Run() != nil {
			break
		}
	}
}

func (s *L2TPService) routeTableID(octet string) string {
	return fmt.Sprintf("1%s", octet)
}

func (s *L2TPService) cleanupRouting(routerIP, nsIPNoMask, octet, clientIP string) {
	// Derive baseIP from nsIPNoMask (assumes nsIPNoMask is x.y.z.2)
	ipParts := strings.Split(nsIPNoMask, ".")
	if len(ipParts) != 4 {
		return
	}
	baseIP := fmt.Sprintf("%s.%s.%s", ipParts[0], ipParts[1], ipParts[2])
	subnet := fmt.Sprintf("%s.0/30", baseIP)

	// Cleanup DNAT rules for IPSec and L2TP forwarding to namespace
	s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-d", s.vpsPublicIP, "-p", "udp", "--dport", "500", "-j", "DNAT", "--to-destination", nsIPNoMask+":500")
	s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-d", s.vpsPublicIP, "-p", "udp", "--dport", "4500", "-j", "DNAT", "--to-destination", nsIPNoMask+":4500")
	s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-d", s.vpsPublicIP, "-p", "udp", "--dport", "1701", "-j", "DNAT", "--to-destination", nsIPNoMask+":1701")

	// Cleanup SNAT rules
	s.deleteRule("-t", "nat", "-D", "POSTROUTING", "-s", nsIPNoMask, "-p", "udp", "--sport", "500", "-j", "SNAT", "--to-source", s.vpsPublicIP+":500")
	s.deleteRule("-t", "nat", "-D", "POSTROUTING", "-s", nsIPNoMask, "-p", "udp", "--sport", "4500", "-j", "SNAT", "--to-source", s.vpsPublicIP+":4500")
	s.deleteRule("-t", "nat", "-D", "POSTROUTING", "-s", nsIPNoMask, "-p", "udp", "--sport", "1701", "-j", "SNAT", "--to-source", s.vpsPublicIP+":1701")

	s.deleteRule("-t", "nat", "-D", "POSTROUTING", "-s", routerIP, "-j", "MASQUERADE") // Old legacy rule
	s.deleteRule("-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE")
	s.deleteRule("-t", "nat", "-D", "POSTROUTING", "-s", clientIP, "-j", "MASQUERADE")
	s.deleteRule("-t", "filter", "-D", "FORWARD", "-d", nsIPNoMask, "-j", "ACCEPT")
	s.deleteRule("-t", "filter", "-D", "FORWARD", "-s", nsIPNoMask, "-j", "ACCEPT")

	// Cleanup legacy policy routing rules from previous versions
	tableID := s.routeTableID(octet)
	for {
		if exec.Command("ip", "rule", "del", "from", routerIP, "lookup", tableID).Run() != nil {
			break
		}
	}
	exec.Command("ip", "route", "flush", "table", tableID).Run()

	// Cleanup legacy DNAT rules without -d filter
	s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-p", "udp", "--dport", "500", "-j", "DNAT", "--to-destination", nsIPNoMask+":500")
	s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-p", "udp", "--dport", "4500", "-j", "DNAT", "--to-destination", nsIPNoMask+":4500")
	s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-p", "50", "-j", "DNAT", "--to-destination", nsIPNoMask)
	s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-p", "udp", "--dport", "1701", "-j", "DNAT", "--to-destination", nsIPNoMask+":1701")

	exec.Command("conntrack", "-D", "-s", routerIP).Run()
	exec.Command("conntrack", "-D", "-d", routerIP).Run()
}

func (s *L2TPService) setupRouting(runCmd func(string, ...string) error, t *tunnel.ResellerTunnel, nsIPNoMask, octet, vethHost, vethNs string) error {
	subnet := fmt.Sprintf("10.254.%s.0/30", octet)

	// s.nsSvc.ExecInNS(t.Namespace, "ip", "addr", "add", s.vpsPublicIP+"/32", "dev", vethNs)

	// Use DNAT to redirect IPSec/L2TP traffic from router to namespace.
	// Policy routing cannot work because the host's local table (priority 0)
	// intercepts packets destined for vpsPublicIP before custom rules are checked.
	runCmd("iptables", "-t", "nat", "-A", "PREROUTING", "-s", t.RouterIP, "-d", s.vpsPublicIP, "-p", "udp", "--dport", "500", "-j", "DNAT", "--to-destination", nsIPNoMask+":500")
	runCmd("iptables", "-t", "nat", "-A", "PREROUTING", "-s", t.RouterIP, "-d", s.vpsPublicIP, "-p", "udp", "--dport", "4500", "-j", "DNAT", "--to-destination", nsIPNoMask+":4500")
	runCmd("iptables", "-t", "nat", "-A", "PREROUTING", "-s", t.RouterIP, "-d", s.vpsPublicIP, "-p", "udp", "--dport", "1701", "-j", "DNAT", "--to-destination", nsIPNoMask+":1701")

	runCmd("iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", nsIPNoMask, "-p", "udp", "--sport", "500", "-j", "SNAT", "--to-source", s.vpsPublicIP+":500")
	runCmd("iptables", "-t", "nat", "-I", "POSTROUTING", "2", "-s", nsIPNoMask, "-p", "udp", "--sport", "4500", "-j", "SNAT", "--to-source", s.vpsPublicIP+":4500")
	runCmd("iptables", "-t", "nat", "-I", "POSTROUTING", "3", "-s", nsIPNoMask, "-p", "udp", "--sport", "1701", "-j", "SNAT", "--to-source", s.vpsPublicIP+":1701")
	runCmd("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE")
	runCmd("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", t.ClientIPAddress, "-j", "MASQUERADE")
	runCmd("iptables", "-t", "filter", "-I", "FORWARD", "1", "-d", nsIPNoMask, "-j", "ACCEPT")
	runCmd("iptables", "-t", "filter", "-I", "FORWARD", "1", "-s", nsIPNoMask, "-j", "ACCEPT")

	return nil
}

func (s *L2TPService) ipsecConfDir(ns string) string {
	return "/etc/ipsec.d"
}

func (s *L2TPService) ipsecEnv(nsConfDir string) []string {
	return append(os.Environ(),
		"IPSEC_CONFS="+nsConfDir,
	)
}

func (s *L2TPService) startIPSec(t *tunnel.ResellerTunnel) error {
	ns := t.Namespace
	nsConfDir := s.ipsecConfDir(ns)

	s.stopIPSecInNS(ns, nsConfDir)
	time.Sleep(500 * time.Millisecond)

	mainConf := filepath.Join(nsConfDir, "ipsec.conf")
	cmd := exec.Command("ip", "netns", "exec", ns, "ipsec", "start", "--conf", mainConf)
	cmd.Env = s.ipsecEnv(nsConfDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipsec start: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	time.Sleep(2 * time.Second)

	out, _ = s.nsSvc.ExecInNS(ns, "ipsec", "statusall")
	s.log.Info("IPSec status after start", zap.String("namespace", ns), zap.String("status", string(out)))

	return nil
}

func (s *L2TPService) stopIPSecInNS(ns, nsConfDir string) {
	cmd := exec.Command("ip", "netns", "exec", ns, "ipsec", "stop")
	cmd.Env = s.ipsecEnv(nsConfDir)
	cmd.CombinedOutput()
}

func (s *L2TPService) startXL2TPD(ns string) error {
	s.killXL2TPD(ns)

	confPath := filepath.Join("/etc/xl2tpd", fmt.Sprintf("%s.conf", ns))
	pidPath := filepath.Join("/run", fmt.Sprintf("xl2tpd-%s.pid", ns))

	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		return fmt.Errorf("config file not found: %s", confPath)
	}

	cmd := exec.Command("ip", "netns", "exec", ns,
		"xl2tpd", "-c", confPath, "-p", pidPath)
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
}

func (s *L2TPService) Teardown(t *tunnel.ResellerTunnel) error {
	s.log.Info("Tearing down L2TP/IPSec tunnel",
		zap.String("namespace", t.Namespace),
	)

	s.killXL2TPD(t.Namespace)
	_ = s.removeChapSecrets(t.Namespace)
	s.stopIPSecInNS(t.Namespace, s.ipsecConfDir(t.Namespace))

	clientIP := stripCIDR(t.ClientIPAddress)
	octets := strings.Split(clientIP, ".")
	if len(octets) == 4 {
		X := octets[2]
		baseIP := fmt.Sprintf("%s.%s.%s", octets[0], octets[1], octets[2])
		nsIPNoMask := fmt.Sprintf("%s.2", baseIP)
		vethHost := fmt.Sprintf("vh-%s", X)

		s.cleanupRouting(t.RouterIP, nsIPNoMask, X, t.ClientIPAddress)
		exec.Command("ip", "link", "del", vethHost).CombinedOutput()
	}

	confDir := s.ipsecConfDir(t.Namespace)
	_ = os.Remove(filepath.Join(confDir, "jinom-"+t.Namespace+".conf"))
	_ = os.Remove(filepath.Join(confDir, "jinom-"+t.Namespace+".secrets"))
	_ = os.Remove(filepath.Join("/etc/xl2tpd", t.Namespace+".conf"))
	_ = os.Remove(filepath.Join("/run", fmt.Sprintf("xl2tpd-%s.pid", t.Namespace)))

	return nil
}

func (s *L2TPService) writeIPSecConfig(t *tunnel.ResellerTunnel, nsIPNoMask string) error {
	connName := fmt.Sprintf("jinom-%s", t.Namespace)
	nsConfDir := s.ipsecConfDir(t.Namespace)

	if err := os.MkdirAll(nsConfDir, 0700); err != nil {
		return err
	}

	connConf := fmt.Sprintf(`conn %s
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
    ike=aes128-sha1-modp1024,aes128-md5-modp1024,3des-sha1-modp1024!
    esp=aes256-sha1-modp1024,aes192-sha1-modp1024,aes128-sha1-modp1024!
`, connName, nsIPNoMask, s.vpsPublicIP, t.RouterIP)

	connPath := filepath.Join(nsConfDir, connName+".conf")
	if err := os.WriteFile(connPath, []byte(connConf), 0600); err != nil {
		return err
	}

	secrets := fmt.Sprintf(`%s %s : PSK "%s"
`, s.vpsPublicIP, t.RouterIP, t.PSK)
	secretsPath := filepath.Join(nsConfDir, connName+".secrets")
	if err := os.WriteFile(secretsPath, []byte(secrets), 0600); err != nil {
		return err
	}

	mainConf := fmt.Sprintf(`config setup
    charondebug="ike 4, enc 4, knl 2, cfg 2, net 2"
    uniqueids=no

include %s/jinom-*.conf
`, nsConfDir)
	mainConfPath := filepath.Join(nsConfDir, "ipsec.conf")
	if err := os.WriteFile(mainConfPath, []byte(mainConf), 0600); err != nil {
		return err
	}

	mainSecrets := fmt.Sprintf("include %s/jinom-*.secrets\n", nsConfDir)
	mainSecretsPath := filepath.Join(nsConfDir, "ipsec.secrets")
	return os.WriteFile(mainSecretsPath, []byte(mainSecrets), 0600)
}

func (s *L2TPService) writeXL2TPDConfig(t *tunnel.ResellerTunnel) error {
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
name = jinom-vpn
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
`, stripCIDR(t.ClientIPAddress), stripCIDR(t.ServerIPAddress))

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
