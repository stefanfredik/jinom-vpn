package service

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type NOCUser struct {
	Name            string `json:"name"`
	PublicKey       string `json:"public_key"`
	IP              string `json:"ip"`
	LatestHandshake int64  `json:"latest_handshake"`
	TransferRx      int64  `json:"transfer_rx"`
	TransferTx      int64  `json:"transfer_tx"`
	Status          string `json:"status"`
}

func (s *TunnelService) calculateTableID(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return "", fmt.Errorf("invalid IPv4 address: %s", ipStr)
	}
	// Derive unique table ID in range 10000..59999 from 3rd and 4th octets
	offset := (int(ip[2])*256 + int(ip[3])) % 50000
	return fmt.Sprintf("%d", 10000+offset), nil
}

func (s *TunnelService) SelectNOCReseller(ctx context.Context, technicianIP string, id uuid.UUID) (string, error) {
	s.nocMu.Lock()
	defer s.nocMu.Unlock()

	vpnIP := s.findVPNIPByEndpointIP(technicianIP)
	effectiveIP := technicianIP
	if vpnIP != "" {
		effectiveIP = vpnIP
	}

	// Always derive tableID from effectiveIP (preferring VPN IP 10.50.0.x if available)
	tableID, err := s.calculateTableID(effectiveIP)
	if err != nil {
		return "", err
	}

	// Clean up any existing technician rules for technicianIP and vpnIP
	s.cleanupTechnicianIPRules(technicianIP, vpnIP)
	_ = exec.Command("ip", "route", "flush", "table", tableID).Run()

	// Flush active conntrack entries for technician IPs to prevent TCP session sticking
	s.flushConntrackForIP(technicianIP)
	if vpnIP != "" && vpnIP != technicianIP {
		s.flushConntrackForIP(vpnIP)
	}

	if id == uuid.Nil {
		s.log.Info("Technician cleared reseller tunnel routing",
			zap.String("technician_ip", technicianIP), zap.String("vpn_ip", vpnIP))
		return effectiveIP, nil
	}

	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return "", fmt.Errorf("get tunnel: %w", err)
	}

	if err := exec.Command("ip", "rule", "add", "from", effectiveIP, "lookup", tableID).Run(); err != nil {
		return "", fmt.Errorf("add ip rule: %w", err)
	}
	if vpnIP != "" && vpnIP != technicianIP {
		if err := exec.Command("ip", "rule", "add", "from", technicianIP, "lookup", tableID).Run(); err != nil {
			s.log.Warn("Failed to add ip rule for technician public IP", zap.String("public_ip", technicianIP), zap.Error(err))
		}
	}

	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipv4 := ipNet.IP.To4(); ipv4 != nil {
					netIP := ipNet.IP.Mask(ipNet.Mask)
					ones, _ := ipNet.Mask.Size()
					cidr := fmt.Sprintf("%s/%d", netIP.String(), ones)
					_ = exec.Command("ip", "route", "add", "throw", cidr, "table", tableID).Run()
				}
			}
		}
	}
	_ = exec.Command("ip", "route", "add", "throw", "127.0.0.0/8", "table", tableID).Run()

	_, _, nsIPNoMask, _ := indexToVethIPs(t.TunnelIndex)
	vethHost := fmt.Sprintf("vh-%d", t.TunnelIndex)

	for _, subnet := range effectiveSubnets(t.MonitoringSubnets) {
		if err := exec.Command("ip", "route", "add", subnet, "via", nsIPNoMask, "dev", vethHost, "table", tableID).Run(); err != nil {
			s.log.Warn("Failed to add route to technician table", zap.String("subnet", subnet), zap.Error(err))
		}
	}

	s.log.Info("Technician selected reseller tunnel",
		zap.String("technician_ip", technicianIP), zap.String("vpn_ip", vpnIP), zap.String("tunnel", t.Name), zap.String("table", tableID))
	return effectiveIP, nil
}

func (s *TunnelService) cleanupTechnicianIPRules(ips ...string) {
	out, err := exec.Command("ip", "rule", "show").Output()
	if err != nil {
		return
	}
	targetIPs := make(map[string]bool)
	for _, ip := range ips {
		trimmed := strings.TrimSpace(ip)
		if trimmed != "" {
			targetIPs[trimmed] = true
		}
	}
	if len(targetIPs) == 0 {
		return
	}

	for _, line := range netSplitLines(string(out)) {
		if isTechnicianTableRule(line) {
			fromIP, tableID := extractRuleFields(line)
			if targetIPs[fromIP] {
				_ = exec.Command("ip", "rule", "del", "from", fromIP, "lookup", tableID).Run()
				_ = exec.Command("ip", "route", "flush", "table", tableID).Run()
			}
		}
	}
}

func (s *TunnelService) flushConntrackForIP(ipStr string) {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return
	}
	_ = exec.Command("conntrack", "-D", "-s", ipStr).Run()
	_ = exec.Command("conntrack", "-D", "-d", ipStr).Run()
}

func (s *TunnelService) flushStaleTechnicianRules() {
	s.log.Info("Cleaning up stale technician policy routing rules...")
	out, err := exec.Command("ip", "rule", "show").Output()
	if err != nil {
		return
	}
	for _, line := range netSplitLines(string(out)) {
		if isTechnicianTableRule(line) {
			fromIP, tableID := extractRuleFields(line)
			if fromIP != "" && tableID != "" {
				_ = exec.Command("ip", "rule", "del", "from", fromIP, "lookup", tableID).Run()
				_ = exec.Command("ip", "route", "flush", "table", tableID).Run()
			}
		}
	}
}
