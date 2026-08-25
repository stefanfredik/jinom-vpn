package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/jinom/vpn/internal/domain/tunnel"
	"github.com/jinom/vpn/pkg/mikrotik"
)

type TunnelStatus struct {
	ID                uuid.UUID     `json:"id"`
	Status            tunnel.Status `json:"status"`
	Namespace         string        `json:"namespace"`
	LastError         string        `json:"last_error,omitempty"`
	PeerReachable     bool          `json:"peer_reachable"`
	MikrotikStatus    string        `json:"mikrotik_status,omitempty"`
	MikrotikIP        string        `json:"mikrotik_ip,omitempty"`
	MikrotikUptime    string        `json:"mikrotik_uptime,omitempty"`
	Uptime            string        `json:"uptime,omitempty"`
	ConfiguredSubnets []string      `json:"configured_subnets"`
	ActiveSubnets     []string      `json:"active_subnets"`
}

func (s *TunnelService) CheckPeerConnection(t *tunnel.ResellerTunnel) bool {
	if !t.IsActive() || !s.nsSvc.Exists(t.Namespace) {
		return false
	}

	// 1. Try ICMP ping inside namespace
	peerIP := extractIP(t.ClientIPAddress)
	if peerIP != "" {
		if _, err := s.nsSvc.ExecInNS(t.Namespace, "ping", "-c", "1", "-W", "1", peerIP); err == nil {
			return true
		}
	}

	// 2. Protocol-specific checks
	if t.VPNType == tunnel.VPNTypeWireGuard {
		ifName := fmt.Sprintf("wg-%s", t.Namespace)
		if hsOut, err := s.nsSvc.ExecInNS(t.Namespace, "wg", "show", ifName, "latest-handshakes"); err == nil {
			parts := strings.Fields(string(hsOut))
			if len(parts) >= 2 {
				if ts, err := strconv.ParseInt(parts[1], 10, 64); err == nil && ts > 0 {
					if time.Since(time.Unix(ts, 0)) <= 3*time.Minute {
						return true
					}
				}
			}
		}
	} else if t.VPNType == tunnel.VPNTypeL2TP {
		if out, err := s.nsSvc.ExecInNS(t.Namespace, "ip", "-br", "link", "show"); err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				fields := strings.Fields(line)
				if len(fields) >= 2 && strings.HasPrefix(fields[0], "ppp") && fields[1] == "UP" {
					return true
				}
			}
		}
	}

	return false
}

func (s *TunnelService) GetStatus(ctx context.Context, id uuid.UUID) (*TunnelStatus, error) {
	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	status := &TunnelStatus{
		ID:             t.ID,
		Status:         t.Status,
		Namespace:      t.Namespace,
		LastError:      t.LastError,
		MikrotikStatus: "unknown",
		MikrotikIP:     "0.0.0.0",
	}

	status.ConfiguredSubnets = effectiveSubnets(t.MonitoringSubnets)

	if t.IsActive() && s.nsSvc.Exists(t.Namespace) {
		status.PeerReachable = s.CheckPeerConnection(t)
		status.ActiveSubnets = s.activeRoutes(t)
	}

	client, err := mikrotik.NewClient(t.RouterIP, t.EffectiveAPIPort(), t.RouterUsername, t.RouterPassword, t.RouterOSVersion >= 7)
	if err == nil {
		defer client.Close()
		var path string
		name := t.Name
		if t.VPNType == tunnel.VPNTypeWireGuard {
			path = "/interface/wireguard/print"
			name = "wg-jinom"
		} else {
			path = "/interface/l2tp-client/print"
			name = "l2tp-jinom"
		}

		res, err := client.Run(path, map[string]string{"?name": name})
		if err == nil && len(res) > 0 {
			row := res[0]
			if row["disabled"] == "true" {
				status.MikrotikStatus = "disabled"
			} else if row["running"] == "true" {
				status.MikrotikStatus = "running"
			} else {
				status.MikrotikStatus = "enabled"
			}
			status.MikrotikUptime = firstNonEmpty(row["uptime"], row["last-link-up-time"])
		} else {
			status.MikrotikStatus = "not found"
		}

		if ipRes, err := client.Run("/ip/address/print", map[string]string{"?interface": name}); err == nil && len(ipRes) > 0 {
			status.MikrotikIP = ipRes[0]["address"]
		}
	} else {
		status.MikrotikStatus = "unreachable"
	}

	status.Uptime = status.MikrotikUptime
	if status.Uptime == "" && t.IsActive() {
		status.Uptime = formatTunnelUptime(time.Since(s.activeSince(ctx, t)))
	}

	return status, nil
}

func (s *TunnelService) GetMetrics(ctx context.Context, id uuid.UUID, limit int) ([]tunnel.TunnelMetric, error) {
	return s.repo.GetMetrics(ctx, id, limit)
}

func (s *TunnelService) GetStatusHistory(ctx context.Context, id uuid.UUID, limit int) ([]tunnel.TunnelStatusHistory, error) {
	return s.repo.GetStatusHistory(ctx, id, limit)
}

func (s *TunnelService) activeSince(ctx context.Context, t *tunnel.ResellerTunnel) time.Time {
	history, err := s.repo.GetStatusHistory(ctx, t.ID, 20)
	if err != nil {
		return t.UpdatedAt
	}
	for _, item := range history {
		if item.Status == tunnel.StatusActive {
			return item.CreatedAt
		}
	}
	return t.UpdatedAt
}

func formatTunnelUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd%dh%dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func extractIP(cidr string) string {
	for i, c := range cidr {
		if c == '/' {
			return cidr[:i]
		}
	}
	return cidr
}
