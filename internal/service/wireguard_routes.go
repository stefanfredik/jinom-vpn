package service

import (
	"fmt"
	"os/exec"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

// ReloadRoutes applies monitoring subnet changes to an active WireGuard interface live.
func (s *WireGuardService) ReloadRoutes(t *tunnel.ResellerTunnel, oldSubnets []string) error {
	ns := t.Namespace
	ifName := fmt.Sprintf("wg-%s", ns)

	added, removed := tunnel.DiffSubnets(
		effectiveSubnets(oldSubnets),
		effectiveSubnets(t.MonitoringSubnets),
	)

	if len(added) == 0 && len(removed) == 0 {
		s.log.Debug("ReloadRoutes: no effective route change",
			zap.String("namespace", ns))
	}

	for _, subnet := range removed {
		if _, err := s.nsSvc.ExecInNS(ns, "ip", "route", "del", subnet, "dev", ifName); err != nil {
			s.log.Warn("ReloadRoutes: remove route failed (continuing)",
				zap.String("subnet", subnet), zap.Error(err))
		}
	}

	for _, subnet := range added {
		if _, err := s.nsSvc.ExecInNS(ns, "ip", "route", "add", subnet, "dev", ifName); err != nil {
			return fmt.Errorf("add route %s: %w", subnet, err)
		}
	}

	if t.ClientPublicKey == "" {
		s.log.Info("ReloadRoutes: peer not provisioned yet, skipping AllowedIPs refresh",
			zap.String("namespace", ns))
		return nil
	}

	if err := s.AttachPeer(t); err != nil {
		return fmt.Errorf("refresh allowed-ips: %w", err)
	}

	s.log.Info("ReloadRoutes: applied",
		zap.String("namespace", ns),
		zap.Strings("added", added),
		zap.Strings("removed", removed),
	)
	return nil
}

func (s *WireGuardService) setupVeth(t *tunnel.ResellerTunnel) error {
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
