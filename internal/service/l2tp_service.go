package service

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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

func stripPort(addr string) string {
	if addr == "" {
		return addr
	}
	if _, _, err := net.ParseCIDR(addr); err == nil {
		return addr
	}
	if net.ParseIP(addr) != nil {
		return addr
	}
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
	svc.initGlobalDaemons()
	svc.installIPUpScript()
	return svc
}

func (s *L2TPService) initGlobalDaemons() {
	// 1. Setup IPsec (StrongSwan) Global Config
	ipsecConf := `config setup
    uniqueids=never
    charondebug="ike 1, knl 1, cfg 1"

conn %%default
    keyingtries=3
    ikelifetime=28800s
    lifetime=3600s
    dpddelay=15s
    dpdtimeout=45s
    dpdaction=clear
    ike=aes256-sha256-modp2048,aes128-sha256-modp2048,aes128-sha1-modp1024,aes128-md5-modp1024,3des-sha1-modp1024!
    esp=aes256-sha256,aes256-sha1,aes128-sha1,aes128-sha1-modp1024,3des-sha1!

conn L2TP-PSK
    authby=secret
    auto=add
    type=transport
    left=%s
    right=%%any
    rightprotoport=17/%%any
    leftprotoport=17/1701
`
	_ = os.WriteFile("/etc/ipsec.conf", []byte(fmt.Sprintf(ipsecConf, s.vpsPublicIP)), 0644)

	// Global PSK
	ipsecSecrets := `: PSK "JinomGlobalSecret2026!"\n`
	_ = os.WriteFile("/etc/ipsec.secrets", []byte(ipsecSecrets), 0600)

	// 2. Setup XL2TPD Global Config
	xl2tpdConf := `[global]
port = 1701
access control = no

[lns default]
exclusive = no
ip range = 10.255.255.100-10.255.255.250
local ip = 10.255.255.1
require chap = yes
refuse pap = yes
require authentication = yes
name = jinom-vpn
pppoptfile = /etc/ppp/options.xl2tpd
length bit = no
`
	os.MkdirAll("/etc/xl2tpd", 0755)
	_ = os.WriteFile("/etc/xl2tpd/xl2tpd.conf", []byte(xl2tpdConf), 0644)

	// 3. Setup PPP Options
	pppOpts := `ipcp-accept-local
ipcp-accept-remote
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 8.8.4.4
asyncmap 0
noccp
novj
novjccomp
nobsdcomp
nodeflate
hide-password
debug
name jinom-vpn
proxyarp
lcp-echo-interval 15
lcp-echo-failure 4
mtu 1400
mru 1400
`
	os.MkdirAll("/etc/ppp", 0755)
	_ = os.WriteFile("/etc/ppp/options.xl2tpd", []byte(pppOpts), 0644)

	// 4. Restart services gracefully
	_ = exec.Command("systemctl", "enable", "strongswan-starter").Run()
	_ = exec.Command("systemctl", "enable", "xl2tpd").Run()
	_ = exec.Command("systemctl", "restart", "strongswan-starter").Run()
	_ = exec.Command("systemctl", "restart", "xl2tpd").Run()
}

func (s *L2TPService) installIPUpScript() {
	scriptPath := "/etc/ppp/ip-up.d/99-jinom-routes"
	scriptContent := `#!/bin/sh
# Called by pppd when link comes up.
# PEERNAME contains the authenticated username (e.g., jinom-res-123)

exec >> /var/log/jinom-vpn-ppp.log 2>&1
echo "=== ip-up triggered at $(date) ==="
echo "Args: 1:$1 2:$2 3:$3 4:$4 5:$5 6:$6"
echo "Env PEERNAME: $PEERNAME"

if [ -n "$PEERNAME" ]; then
    # Extract namespace from username
    NS_NAME=$(echo "$PEERNAME" | sed 's/jinom-/ns-/')
    echo "Derived namespace: $NS_NAME"
    
    # Check if namespace exists
    if ip netns list | grep -q "^$NS_NAME"; then
        echo "Moving $1 to namespace $NS_NAME"
        # Move PPP interface to namespace
        ip link set "$1" netns "$NS_NAME"
        
        # Bring it up inside namespace
        ip netns exec "$NS_NAME" ip link set "$1" up
        
        # Re-assign the point-to-point IP addresses inside the namespace
        echo "Assigning IP $4 peer $5 inside namespace"
        ip netns exec "$NS_NAME" ip addr add $4 peer $5 dev "$1"
        
        # Set as default route
        ip netns exec "$NS_NAME" ip route add default dev "$1"
        
        # Ensure packets sent to the reseller are masqueraded inside the namespace
        # so the reseller's MikroTik routes the reply back to the L2TP gateway IP.
        ip netns exec "$NS_NAME" iptables -t nat -A POSTROUTING -o "$1" -j MASQUERADE
        
        # Add additional monitored routes
        if [ -f "/etc/ppp/routes.$NS_NAME" ]; then
            while read subnet; do
                if [ -n "$subnet" ]; then
                    echo "Adding route to $subnet"
                    ip netns exec "$NS_NAME" ip route add "$subnet" dev "$1" || true
                fi
            done < "/etc/ppp/routes.$NS_NAME"
        fi
    else
        echo "Namespace $NS_NAME not found!"
    fi
fi
`
	os.MkdirAll("/etc/ppp/ip-up.d", 0755)
	_ = os.WriteFile(scriptPath, []byte(scriptContent), 0755)
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
	oldIPs := []string{nsIPNoMask, "10.254.222.2", "10.254.0.2"}
	
	for _, ip := range oldIPs {
		s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-d", s.vpsPublicIP, "-p", "udp", "--dport", "500", "-j", "DNAT", "--to-destination", ip+":500")
		s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-d", s.vpsPublicIP, "-p", "udp", "--dport", "4500", "-j", "DNAT", "--to-destination", ip+":4500")
		s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-d", s.vpsPublicIP, "-p", "udp", "--dport", "1701", "-j", "DNAT", "--to-destination", ip+":1701")
		s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-p", "udp", "--dport", "500", "-j", "DNAT", "--to-destination", ip+":500")
		s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-p", "udp", "--dport", "4500", "-j", "DNAT", "--to-destination", ip+":4500")
		s.deleteRule("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-p", "udp", "--dport", "1701", "-j", "DNAT", "--to-destination", ip+":1701")
		s.deleteRule("-t", "nat", "-D", "POSTROUTING", "-s", ip, "-p", "udp", "--sport", "500", "-j", "SNAT", "--to-source", s.vpsPublicIP+":500")
		s.deleteRule("-t", "nat", "-D", "POSTROUTING", "-s", ip, "-p", "udp", "--sport", "4500", "-j", "SNAT", "--to-source", s.vpsPublicIP+":4500")
		s.deleteRule("-t", "nat", "-D", "POSTROUTING", "-s", ip, "-p", "udp", "--sport", "1701", "-j", "SNAT", "--to-source", s.vpsPublicIP+":1701")
		s.deleteRule("-t", "filter", "-D", "FORWARD", "-d", ip, "-j", "ACCEPT")
		s.deleteRule("-t", "filter", "-D", "FORWARD", "-s", ip, "-j", "ACCEPT")
	}

	s.deleteRule("-t", "nat", "-D", "POSTROUTING", "-s", routerIP, "-j", "MASQUERADE")
	s.deleteRule("-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE")
	s.deleteRule("-t", "nat", "-D", "POSTROUTING", "-s", clientIP, "-j", "MASQUERADE")

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

func (s *L2TPService) Setup(t *tunnel.ResellerTunnel) (err error) {
	s.log.Info("Setting up L2TP/IPSec tunnel (Global Mode)",
		zap.String("namespace", t.Namespace),
		zap.String("tunnel", t.Name),
	)

	// Clean up legacy artifacts (if migrating from old architecture)
	_, _, nsIPNoMask, _ := indexToVethIPs(t.TunnelIndex)
	s.cleanupRouting(stripPort(t.RouterIP), nsIPNoMask, t.TunnelIndex, t.ClientIPAddress)
	vethHost := fmt.Sprintf("vh-%d", t.TunnelIndex)
	_ = exec.Command("ip", "link", "del", vethHost).Run()

	// 1. Add credentials to global chap-secrets
	if err := s.updateChapSecrets(t); err != nil {
		return fmt.Errorf("update chap secrets: %w", err)
	}

	// 2. Save routing subnets for ip-up script
	routesPath := filepath.Join("/etc/ppp", fmt.Sprintf("routes.%s", t.Namespace))
	routesData := strings.Join(effectiveSubnets(t.MonitoringSubnets), "\n") + "\n"
	if err := os.WriteFile(routesPath, []byte(routesData), 0600); err != nil {
		return fmt.Errorf("write routes file: %w", err)
	}

	// 3. Create veth jembatan to namespace
	if err := s.setupVeth(t); err != nil {
		s.log.Error("Failed to setup veth for namespace", zap.Error(err))
		return fmt.Errorf("setup veth: %w", err)
	}

	return nil
}

// ReloadRoutes menerapkan perubahan monitoring subnet pada tunnel L2TP.
//
// Dua lapis, karena sesi PPP bisa saja belum terbentuk:
//
//  1. Tulis ulang /etc/ppp/routes.<ns> — sumber kebenaran yang dibaca ip-up
//     setiap kali MikroTik dial masuk. Ini SELALU dilakukan.
//  2. Kalau interface ppp untuk namespace ini sudah hidup, terapkan selisihnya
//     langsung supaya tidak perlu menunggu dial ulang.
//
// PENTING — keterbatasan yang diketahui: ip-up memasang `ip route add default
// dev ppp` di dalam namespace (lihat installIPUpScript). Selama default route
// itu ada, SELURUH trafik keluar namespace sudah masuk tunnel, sehingga
// menambah/menghapus subnet spesifik praktis tidak mengubah jangkauan. Route
// per-subnet tetap dikelola di sini agar tetap benar bila default route hilang
// (mis. sesi PPP putus sebagian) dan agar berhenti berperilaku berbeda dari
// WireGuard. Perilaku ini belum diverifikasi di lab.
//
// Pemanggil wajib memegang setupMu.
func (s *L2TPService) ReloadRoutes(t *tunnel.ResellerTunnel, oldSubnets []string) error {
	routesPath := filepath.Join("/etc/ppp", fmt.Sprintf("routes.%s", t.Namespace))
	routesData := strings.Join(effectiveSubnets(t.MonitoringSubnets), "\n") + "\n"
	if err := os.WriteFile(routesPath, []byte(routesData), 0600); err != nil {
		return fmt.Errorf("write routes file: %w", err)
	}

	ifName := s.findPPPInterface(t.Namespace)
	if ifName == "" {
		s.log.Info("ReloadRoutes: no active ppp session, routes file updated only",
			zap.String("namespace", t.Namespace))
		return nil
	}

	added, removed := tunnel.DiffSubnets(
		effectiveSubnets(oldSubnets),
		effectiveSubnets(t.MonitoringSubnets),
	)

	for _, subnet := range removed {
		if _, err := s.nsSvc.ExecInNS(t.Namespace, "ip", "route", "del", subnet, "dev", ifName); err != nil {
			s.log.Warn("ReloadRoutes: remove route failed (continuing)",
				zap.String("subnet", subnet), zap.Error(err))
		}
	}
	for _, subnet := range added {
		if _, err := s.nsSvc.ExecInNS(t.Namespace, "ip", "route", "add", subnet, "dev", ifName); err != nil {
			return fmt.Errorf("add route %s: %w", subnet, err)
		}
	}

	s.log.Info("ReloadRoutes: applied",
		zap.String("namespace", t.Namespace),
		zap.String("interface", ifName),
		zap.Strings("added", added),
		zap.Strings("removed", removed),
	)
	return nil
}

// findPPPInterface mengembalikan nama interface ppp di dalam namespace, atau
// string kosong bila belum ada.
//
// Nama interface tidak bisa diturunkan dari data tunnel: pppd yang menentukan
// nomornya saat MikroTik dial masuk, dan nomor itu berubah tiap sesi. Satu-
// satunya cara adalah membacanya dari kernel.
func (s *L2TPService) findPPPInterface(ns string) string {
	out, err := s.nsSvc.ExecInNS(ns, "ip", "-o", "link", "show")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		// Format `ip -o link show`: "3: ppp0: <POINTOPOINT,...> mtu 1400 ..."
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		name := strings.TrimSpace(parts[1])
		// Buang sufiks "@if4" pada interface berpasangan.
		if at := strings.Index(name, "@"); at != -1 {
			name = name[:at]
		}
		if strings.HasPrefix(name, "ppp") {
			return name
		}
	}
	return ""
}

func (s *L2TPService) Teardown(t *tunnel.ResellerTunnel) error {
	s.log.Info("Tearing down L2TP/IPSec tunnel (Global Mode)",
		zap.String("namespace", t.Namespace),
	)

	_ = s.removeChapSecrets(t.Namespace)
	_ = os.Remove(filepath.Join("/etc/ppp", fmt.Sprintf("routes.%s", t.Namespace)))

	// Clean up veth and forwarding rules
	_, _, nsIPNoMask, _ := indexToVethIPs(t.TunnelIndex)
	s.cleanupRouting(stripPort(t.RouterIP), nsIPNoMask, t.TunnelIndex, t.ClientIPAddress)
	vethHost := fmt.Sprintf("vh-%d", t.TunnelIndex)
	_ = exec.Command("ip", "link", "del", vethHost).Run()

	// Kill active PPP session for this user
	_ = exec.Command("pkill", "-f", fmt.Sprintf("pppd.*%s", t.L2TPUsername)).Run()

	return nil
}

func (s *L2TPService) updateChapSecrets(t *tunnel.ResellerTunnel) error {
	_ = s.removeChapSecrets(t.Namespace)
	
	// Format: "client" server "secret" IP
	nsIPNoMask := stripCIDR(t.ClientIPAddress)
	line := fmt.Sprintf("\"%s\" * \"%s\" %s # jinom-vpn: %s\n", t.L2TPUsername, t.L2TPPassword, nsIPNoMask, t.Namespace)

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

	content := strings.Join(newLines, "\n")
	if content != "" {
		content += "\n"
	}

	return os.WriteFile(path, []byte(content), 0600)
}

// IPSecStatusall is kept as a dummy to satisfy any remaining interface signatures.
func (s *L2TPService) IPSecStatusall(ns string) ([]byte, error) {
	return []byte("Security Associations (0 up, 0 connecting)"), nil
}

func (s *L2TPService) setupVeth(t *tunnel.ResellerTunnel) error {
	hostIP, nsIP, _, _ := indexToVethIPs(t.TunnelIndex)
	vethHost := fmt.Sprintf("vh-%d", t.TunnelIndex)
	vethNS := fmt.Sprintf("vn-%d", t.TunnelIndex)

	// Clean up old ones first
	_ = exec.Command("ip", "link", "del", vethHost).Run()

	// 1. Create veth pair
	if err := exec.Command("ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethNS).Run(); err != nil {
		return fmt.Errorf("create veth: %w", err)
	}

	// 2. Set IP on host end and bring it up
	if err := exec.Command("ip", "addr", "add", hostIP, "dev", vethHost).Run(); err != nil {
		return fmt.Errorf("assign host veth ip: %w", err)
	}
	if err := exec.Command("ip", "link", "set", vethHost, "up").Run(); err != nil {
		return fmt.Errorf("bring up host veth: %w", err)
	}

	// 3. Move peer to namespace
	if err := exec.Command("ip", "link", "set", vethNS, "netns", t.Namespace).Run(); err != nil {
		return fmt.Errorf("move peer to namespace: %w", err)
	}

	// 4. Configure IP inside namespace and bring it up
	if err := exec.Command("ip", "netns", "exec", t.Namespace, "ip", "addr", "add", nsIP, "dev", vethNS).Run(); err != nil {
		return fmt.Errorf("assign ns veth ip: %w", err)
	}
	if err := exec.Command("ip", "netns", "exec", t.Namespace, "ip", "link", "set", vethNS, "up").Run(); err != nil {
		return fmt.Errorf("bring up ns veth: %w", err)
	}

	// 5. Add route to reach the NOC VPN subnet (10.50.0.0/24) via host end of veth
	hostIPNoMask := stripCIDR(hostIP)
	_ = exec.Command("ip", "netns", "exec", t.Namespace, "ip", "route", "add", "10.50.0.0/24", "via", hostIPNoMask, "dev", vethNS).Run()

	// 6. Enable forwarding on the host for this veth subnet
	_ = exec.Command("iptables", "-w", "-t", "filter", "-I", "FORWARD", "-i", vethHost, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-w", "-t", "filter", "-I", "FORWARD", "-o", vethHost, "-j", "ACCEPT").Run()

	return nil
}
