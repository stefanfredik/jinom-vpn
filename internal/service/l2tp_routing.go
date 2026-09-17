package service

import (
	"fmt"
	"net"
	"strings"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

// maxRuleDeleteIterations membatasi loop penghapusan rule duplikat. Tanpa batas
// ini, satu kondisi tak terduga di mana `iptables -D` selalu sukses akan
// memutar loop tanpa henti dan mengunci jalur Setup/Teardown.
const maxRuleDeleteIterations = 50

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

func indexToVethIPs(index int) (hostIP, nsIP, nsIPNoMask, subnet string) {
	a := index / 64
	b := (index % 64) * 4
	hostIP = fmt.Sprintf("10.254.%d.%d/30", a, b+1)
	nsIP = fmt.Sprintf("10.254.%d.%d/30", a, b+2)
	nsIPNoMask = fmt.Sprintf("10.254.%d.%d", a, b+2)
	subnet = fmt.Sprintf("10.254.%d.%d/30", a, b)
	return
}

// deleteRuleRepeatedly menghapus rule yang sama berulang kali sampai tidak ada
// lagi salinannya, dengan batas iterasi agar tidak pernah berputar tak hingga.
func deleteRuleRepeatedly(args ...string) {
	for i := 0; i < maxRuleDeleteIterations; i++ {
		full := append([]string{"-w"}, args...)
		if !runQuiet("iptables", full...) {
			return
		}
	}
}

// ensureRule memasang rule hanya bila belum ada, memakai `iptables -C` sebagai
// pemeriksa.
//
// Versi sebelumnya selalu memakai `-I` tanpa pemeriksaan, sementara jalur
// teardown menghapus rule dalam bentuk yang berbeda (`-s <ip>` alih-alih
// `-i <veth>`). Akibatnya chain FORWARD bertambah dua rule setiap Setup — dan
// Setup dijalankan ulang pada setiap Reconcile — sehingga chain tumbuh tanpa
// batas dan menjadi beban per-paket.
func ensureRule(table, chain string, spec ...string) {
	check := append([]string{"-w", "-t", table, "-C", chain}, spec...)
	if runQuiet("iptables", check...) {
		return
	}
	insert := append([]string{"-w", "-t", table, "-I", chain}, spec...)
	_ = runQuiet("iptables", insert...)
}

func (s *L2TPService) routeTableID(index int) string {
	return fmt.Sprintf("%d", 1000+index)
}

// forwardRuleSpecs mengembalikan rule FORWARD milik satu veth host.
func forwardRuleSpecs(vethHost string) [][]string {
	return [][]string{
		{"-i", vethHost, "-j", "ACCEPT"},
		{"-o", vethHost, "-j", "ACCEPT"},
	}
}

func (s *L2TPService) findPPPInterfaces(ns string) []string {
	out, err := s.nsSvc.ExecInNS(ns, "ip", "-o", "link", "show")
	if err != nil {
		return nil
	}
	var found []string
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		name := strings.TrimSpace(parts[1])
		if at := strings.Index(name, "@"); at != -1 {
			name = name[:at]
		}
		if strings.HasPrefix(name, "ppp") {
			found = append(found, name)
		}
	}
	return found
}

func (s *L2TPService) findPPPInterface(ns string) string {
	if ifaces := s.findPPPInterfaces(ns); len(ifaces) > 0 {
		return ifaces[0]
	}
	return ""
}

func (s *L2TPService) setupVeth(t *tunnel.ResellerTunnel) error {
	hostIP, nsIP, _, _ := indexToVethIPs(t.TunnelIndex)
	vethHost := fmt.Sprintf("vh-%d", t.TunnelIndex)
	vethNS := fmt.Sprintf("vn-%d", t.TunnelIndex)

	_ = runQuiet("ip", "link", "del", vethHost)

	if _, err := runCmd(defaultCmdTimeout, "ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethNS); err != nil {
		return fmt.Errorf("create veth: %w", err)
	}

	if _, err := runCmd(defaultCmdTimeout, "ip", "addr", "add", hostIP, "dev", vethHost); err != nil {
		return fmt.Errorf("assign host veth ip: %w", err)
	}
	if _, err := runCmd(defaultCmdTimeout, "ip", "link", "set", vethHost, "up"); err != nil {
		return fmt.Errorf("bring up host veth: %w", err)
	}

	if _, err := runCmd(defaultCmdTimeout, "ip", "link", "set", vethNS, "netns", t.Namespace); err != nil {
		return fmt.Errorf("move peer to namespace: %w", err)
	}

	if _, err := s.nsSvc.ExecInNS(t.Namespace, "ip", "addr", "add", nsIP, "dev", vethNS); err != nil {
		return fmt.Errorf("assign ns veth ip: %w", err)
	}
	if _, err := s.nsSvc.ExecInNS(t.Namespace, "ip", "link", "set", vethNS, "up"); err != nil {
		return fmt.Errorf("bring up ns veth: %w", err)
	}

	hostIPNoMask := stripCIDR(hostIP)
	_, _ = s.nsSvc.ExecInNS(t.Namespace, "ip", "route", "replace", "10.50.0.0/24", "via", hostIPNoMask, "dev", vethNS)

	for _, spec := range forwardRuleSpecs(vethHost) {
		ensureRule("filter", "FORWARD", spec...)
	}

	return nil
}

// teardownVeth melepas veth berikut rule FORWARD-nya. Bentuk rule yang dihapus
// sengaja identik dengan yang dipasang setupVeth.
func (s *L2TPService) teardownVeth(index int) {
	vethHost := fmt.Sprintf("vh-%d", index)
	_ = runQuiet("ip", "link", "del", vethHost)
	for _, spec := range forwardRuleSpecs(vethHost) {
		deleteRuleRepeatedly(append([]string{"-t", "filter", "-D", "FORWARD"}, spec...)...)
	}
}

// PurgeLegacyRouting menghapus sisa konfigurasi dari desain lama, ketika setiap
// namespace menjalankan strongswan/xl2tpd sendiri dan trafik IPSec di-DNAT ke
// dalam namespace.
//
// Pada mode global sekarang tidak ada satu pun kode yang membuat rule tersebut,
// sehingga penghapusannya adalah migrasi sekali jalan — bukan pekerjaan yang
// perlu diulang pada setiap Setup dan Teardown seperti sebelumnya. Versi lama
// menjalankan lebih dari 80 proses iptables/conntrack per tunnel di jalur
// panas, masing-masing mengantre pada xtables lock global.
//
// Daftar IP hardcoded "10.254.222.2" dan "10.254.0.2" juga dibuang: yang kedua
// adalah persis nsIP milik tunnel index 0, sehingga setiap Setup/Teardown
// tunnel mana pun ikut menghapus rule milik tunnel pertama.
func (s *L2TPService) PurgeLegacyRouting(tunnels []tunnel.ResellerTunnel) {
	if len(tunnels) == 0 {
		return
	}
	s.log.Info("Purging legacy per-namespace IPSec routing artifacts",
		zap.Int("tunnels", len(tunnels)))

	for i := range tunnels {
		t := &tunnels[i]
		if t.VPNType != tunnel.VPNTypeL2TP {
			continue
		}
		routerIP := stripPort(t.RouterIP)
		if routerIP == "" {
			continue
		}
		_, _, nsIPNoMask, subnet := indexToVethIPs(t.TunnelIndex)

		for _, port := range []string{"500", "4500", "1701"} {
			deleteRuleRepeatedly("-t", "nat", "-D", "PREROUTING", "-s", routerIP, "-d", s.vpsPublicIP,
				"-p", "udp", "--dport", port, "-j", "DNAT", "--to-destination", nsIPNoMask+":"+port)
			deleteRuleRepeatedly("-t", "nat", "-D", "PREROUTING", "-s", routerIP,
				"-p", "udp", "--dport", port, "-j", "DNAT", "--to-destination", nsIPNoMask+":"+port)
			deleteRuleRepeatedly("-t", "nat", "-D", "POSTROUTING", "-s", nsIPNoMask,
				"-p", "udp", "--sport", port, "-j", "SNAT", "--to-source", s.vpsPublicIP+":"+port)
		}
		deleteRuleRepeatedly("-t", "filter", "-D", "FORWARD", "-d", nsIPNoMask, "-j", "ACCEPT")
		deleteRuleRepeatedly("-t", "filter", "-D", "FORWARD", "-s", nsIPNoMask, "-j", "ACCEPT")

		deleteRuleRepeatedly("-t", "nat", "-D", "POSTROUTING", "-s", routerIP, "-j", "MASQUERADE")
		deleteRuleRepeatedly("-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE")
		if t.ClientIPAddress != "" {
			deleteRuleRepeatedly("-t", "nat", "-D", "POSTROUTING", "-s", t.ClientIPAddress, "-j", "MASQUERADE")
		}

		tableID := s.routeTableID(t.TunnelIndex)
		for attempt := 0; attempt < maxRuleDeleteIterations; attempt++ {
			if !runQuiet("ip", "rule", "del", "from", routerIP, "lookup", tableID) {
				break
			}
		}
		_ = runQuiet("ip", "route", "flush", "table", tableID)
	}
}
