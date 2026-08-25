package service

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

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

type NOCStatus struct {
	TechnicianIP      string `json:"technician_ip"`
	MappedIP          string `json:"mapped_ip"`
	IsConnected       bool   `json:"is_connected"`
	ActiveTunnelID    string `json:"active_tunnel_id,omitempty"`
	ActiveTunnelName  string `json:"active_tunnel_name,omitempty"`
	ActiveTunnelIndex int    `json:"active_tunnel_index,omitempty"`
}

func cleanIP(ipStr string) string {
	ipStr = strings.TrimSpace(ipStr)
	if strings.Contains(ipStr, ",") {
		ipStr = strings.TrimSpace(strings.Split(ipStr, ",")[0])
	}
	if host, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = host
	}
	return strings.TrimSpace(ipStr)
}

func (s *TunnelService) GetNOCStatus(ctx context.Context, technicianIP string) (*NOCStatus, error) {
	s.nocMu.Lock()
	defer s.nocMu.Unlock()

	technicianIP = cleanIP(technicianIP)
	vpnIP := s.findVPNIPByEndpointIP(technicianIP)
	effectiveIP := technicianIP
	if vpnIP != "" {
		effectiveIP = vpnIP
	}

	status := &NOCStatus{
		TechnicianIP: technicianIP,
		MappedIP:     effectiveIP,
		IsConnected:  strings.HasPrefix(effectiveIP, "10.50."),
	}

	tableID, err := s.calculateTableID(effectiveIP)
	if err != nil {
		return status, nil
	}

	out, err := exec.Command("ip", "route", "show", "table", tableID).Output()
	if err == nil && len(out) > 0 {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			for i, field := range fields {
				if field == "dev" && i+1 < len(fields) {
					devName := fields[i+1]
					if strings.HasPrefix(devName, "vh-") {
						idxStr := strings.TrimPrefix(devName, "vh-")
						var idx int
						if _, err := fmt.Sscanf(idxStr, "%d", &idx); err == nil && idx > 0 {
							status.ActiveTunnelIndex = idx
							if t, err := s.repo.FindByTunnelIndex(ctx, idx); err == nil && t != nil {
								status.ActiveTunnelID = t.ID.String()
								status.ActiveTunnelName = t.Name
							}
							break
						}
					}
				}
			}
			if status.ActiveTunnelID != "" {
				break
			}
		}
	}

	return status, nil
}

func (s *TunnelService) calculateTableID(ipStr string) (string, error) {
	ipStr = cleanIP(ipStr)
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

	technicianIP = cleanIP(technicianIP)
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
	s.cleanupTechnicianIPRules(tableID, technicianIP, vpnIP)

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

func (s *TunnelService) cleanupTechnicianIPRules(tableID string, ips ...string) {
	targetIPs := make(map[string]bool)
	for _, ip := range ips {
		trimmed := cleanIP(ip)
		if trimmed != "" {
			targetIPs[trimmed] = true
		}
	}

	if tableID != "" {
		_ = exec.Command("ip", "route", "flush", "table", tableID).Run()
	}

	out, err := exec.Command("ip", "rule", "show").Output()
	if err != nil {
		return
	}

	for _, line := range netSplitLines(string(out)) {
		if isTechnicianTableRule(line) {
			fromIP, tid := extractRuleFields(line)
			if targetIPs[fromIP] || (tableID != "" && tid == tableID) {
				for i := 0; i < 5; i++ {
					if err := exec.Command("ip", "rule", "del", "from", fromIP, "lookup", tid).Run(); err != nil {
						break
					}
				}
				_ = exec.Command("ip", "route", "flush", "table", tid).Run()
			}
		}
	}
}

func (s *TunnelService) flushConntrackForIP(ipStr string) {
	ipStr = cleanIP(ipStr)
	if ipStr == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = exec.CommandContext(ctx, "conntrack", "-D", "-s", ipStr).Run()
	_ = exec.CommandContext(ctx, "conntrack", "-D", "-d", ipStr).Run()
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
