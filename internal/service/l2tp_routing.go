package service

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

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
	_ = exec.Command("ip", "route", "flush", "table", tableID).Run()

	_ = exec.Command("conntrack", "-D", "-s", routerIP, "-p", "udp", "--dport", "500").Run()
	_ = exec.Command("conntrack", "-D", "-s", routerIP, "-p", "udp", "--dport", "4500").Run()
	_ = exec.Command("conntrack", "-D", "-s", routerIP, "-p", "udp", "--dport", "1701").Run()
	_ = exec.Command("conntrack", "-D", "-d", routerIP, "-p", "udp", "--sport", "500").Run()
	_ = exec.Command("conntrack", "-D", "-d", routerIP, "-p", "udp", "--sport", "4500").Run()
	_ = exec.Command("conntrack", "-D", "-d", routerIP, "-p", "udp", "--sport", "1701").Run()
}

func (s *L2TPService) findPPPInterface(ns string) string {
	out, err := s.nsSvc.ExecInNS(ns, "ip", "-o", "link", "show")
	if err != nil {
		return ""
	}
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
			return name
		}
	}
	return ""
}

func (s *L2TPService) setupVeth(t *tunnel.ResellerTunnel) error {
	hostIP, nsIP, _, _ := indexToVethIPs(t.TunnelIndex)
	vethHost := fmt.Sprintf("vh-%d", t.TunnelIndex)
	vethNS := fmt.Sprintf("vn-%d", t.TunnelIndex)

	_ = exec.Command("ip", "link", "del", vethHost).Run()

	if err := exec.Command("ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethNS).Run(); err != nil {
		return fmt.Errorf("create veth: %w", err)
	}

	if err := exec.Command("ip", "addr", "add", hostIP, "dev", vethHost).Run(); err != nil {
		return fmt.Errorf("assign host veth ip: %w", err)
	}
	if err := exec.Command("ip", "link", "set", vethHost, "up").Run(); err != nil {
		return fmt.Errorf("bring up host veth: %w", err)
	}

	if err := exec.Command("ip", "link", "set", vethNS, "netns", t.Namespace).Run(); err != nil {
		return fmt.Errorf("move peer to namespace: %w", err)
	}

	if err := exec.Command("ip", "netns", "exec", t.Namespace, "ip", "addr", "add", nsIP, "dev", vethNS).Run(); err != nil {
		return fmt.Errorf("assign ns veth ip: %w", err)
	}
	if err := exec.Command("ip", "netns", "exec", t.Namespace, "ip", "link", "set", vethNS, "up").Run(); err != nil {
		return fmt.Errorf("bring up ns veth: %w", err)
	}

	hostIPNoMask := stripCIDR(hostIP)
	_ = exec.Command("ip", "netns", "exec", t.Namespace, "ip", "route", "add", "10.50.0.0/24", "via", hostIPNoMask, "dev", vethNS).Run()

	_ = exec.Command("iptables", "-w", "-t", "filter", "-I", "FORWARD", "-i", vethHost, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-w", "-t", "filter", "-I", "FORWARD", "-o", vethHost, "-j", "ACCEPT").Run()

	return nil
}
