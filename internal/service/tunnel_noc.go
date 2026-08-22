package service

import (
	"context"
	"fmt"
	"net"
	"os/exec"

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

func (s *TunnelService) SelectNOCReseller(ctx context.Context, technicianIP string, id uuid.UUID) error {
	s.nocMu.Lock()
	defer s.nocMu.Unlock()

	tableID, err := s.calculateTableID(technicianIP)
	if err != nil {
		return err
	}

	vpnIP := s.findVPNIPByEndpointIP(technicianIP)

	_ = exec.Command("ip", "rule", "del", "from", technicianIP, "lookup", tableID).Run()
	if vpnIP != "" && vpnIP != technicianIP {
		_ = exec.Command("ip", "rule", "del", "from", vpnIP, "lookup", tableID).Run()
	}
	_ = exec.Command("ip", "route", "flush", "table", tableID).Run()

	if id == uuid.Nil {
		s.log.Info("Technician cleared reseller tunnel routing",
			zap.String("technician_ip", technicianIP), zap.String("vpn_ip", vpnIP))
		return nil
	}

	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("get tunnel: %w", err)
	}

	if err := exec.Command("ip", "rule", "add", "from", technicianIP, "lookup", tableID).Run(); err != nil {
		return fmt.Errorf("add ip rule: %w", err)
	}
	if vpnIP != "" && vpnIP != technicianIP {
		_ = exec.Command("ip", "rule", "add", "from", vpnIP, "lookup", tableID).Run()
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

	for _, subnet := range []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"} {
		if err := exec.Command("ip", "route", "add", subnet, "via", nsIPNoMask, "dev", vethHost, "table", tableID).Run(); err != nil {
			s.log.Warn("Failed to add route to technician table", zap.String("subnet", subnet), zap.Error(err))
		}
	}

	s.log.Info("Technician selected reseller tunnel",
		zap.String("technician_ip", technicianIP), zap.String("tunnel", t.Name), zap.String("table", tableID))
	return nil
}

func (s *TunnelService) flushStaleTechnicianRules() {
	s.log.Info("Cleaning up stale technician policy routing rules...")
	out, err := exec.Command("ip", "rule", "show").Output()
	if err != nil {
		return
	}
	for _, line := range netSplitLines(string(out)) {
		if containsLookup(line) {
			fromIP, tableID := extractRuleFields(line)
			if fromIP != "" && tableID != "" {
				_ = exec.Command("ip", "rule", "del", "from", fromIP, "lookup", tableID).Run()
				_ = exec.Command("ip", "route", "flush", "table", tableID).Run()
			}
		}
	}
}
