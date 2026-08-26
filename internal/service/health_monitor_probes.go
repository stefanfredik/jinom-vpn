package service

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

const wgHandshakeStaleAfter = 3 * time.Minute

var (
	pingLossRegex    = regexp.MustCompile(`([\d.]+)% packet loss`)
	pingLatencyRegex = regexp.MustCompile(`rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms`)
)

func (s *HealthMonitorService) checkTunnel(ctx context.Context, t *tunnel.ResellerTunnel) {
	metric := &tunnel.TunnelMetric{
		TunnelID:  t.ID,
		Timestamp: time.Now(),
	}

	if !s.nsSvc.Exists(t.Namespace) {
		s.handleFailure(ctx, t, "namespace does not exist")
		return
	}

	if t.VPNType == tunnel.VPNTypeWireGuard {
		s.checkWireGuard(ctx, t, metric)
		return
	}

	if t.VPNType == tunnel.VPNTypeL2TP {
		if handled := s.checkL2TPViaIPSec(ctx, t, metric); handled {
			return
		}
	}

	peerIP := extractIP(t.ClientIPAddress)
	out, err := s.nsSvc.ExecInNS(t.Namespace, "ping", "-c", "3", "-W", "2", peerIP)

	if err != nil {
		loss := 100.0
		metric.PacketLoss = &loss
		_ = s.repo.SaveMetric(ctx, metric)
		s.handleFailure(ctx, t, "peer unreachable")
		return
	}

	outStr := string(out)
	if m := pingLossRegex.FindStringSubmatch(outStr); len(m) > 1 {
		if loss, e := strconv.ParseFloat(m[1], 64); e == nil {
			metric.PacketLoss = &loss
		}
	}
	if m := pingLatencyRegex.FindStringSubmatch(outStr); len(m) > 1 {
		if lat, e := strconv.ParseFloat(m[1], 64); e == nil {
			metric.LatencyMS = &lat
		}
	}

	_ = s.repo.SaveMetric(ctx, metric)
	s.handleSuccess(ctx, t)
}

func (s *HealthMonitorService) checkWireGuard(ctx context.Context, t *tunnel.ResellerTunnel, metric *tunnel.TunnelMetric) {
	ifName := fmt.Sprintf("wg-%s", t.Namespace)

	if t.ClientPublicKey == "" {
		_ = s.repo.SaveMetric(ctx, metric)
		s.handleSuccess(ctx, t)
		return
	}

	if wgOut, e := s.nsSvc.ExecInNS(t.Namespace, "wg", "show", ifName, "transfer"); e == nil {
		parts := strings.Fields(string(wgOut))
		if len(parts) >= 3 {
			if rx, e2 := strconv.ParseInt(parts[1], 10, 64); e2 == nil {
				metric.RxBytes = &rx
			}
			if tx, e2 := strconv.ParseInt(parts[2], 10, 64); e2 == nil {
				metric.TxBytes = &tx
			}
		}
	}

	hsOut, err := s.nsSvc.ExecInNS(t.Namespace, "wg", "show", ifName, "latest-handshakes")
	if err != nil {
		_ = s.repo.SaveMetric(ctx, metric)
		s.handleFailure(ctx, t, "wg show failed: "+err.Error())
		return
	}

	parts := strings.Fields(string(hsOut))
	if len(parts) < 2 {
		_ = s.repo.SaveMetric(ctx, metric)
		s.handleFailure(ctx, t, "no peer configured on wg interface")
		return
	}
	ts, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		_ = s.repo.SaveMetric(ctx, metric)
		s.handleFailure(ctx, t, "unparseable handshake timestamp")
		return
	}

	if ts == 0 {
		_ = s.repo.SaveMetric(ctx, metric)
		s.handleSuccess(ctx, t)
		return
	}

	last := time.Unix(ts, 0)
	metric.HandshakeTime = &last
	_ = s.repo.SaveMetric(ctx, metric)

	if age := time.Since(last); age > wgHandshakeStaleAfter {
		s.handleFailure(ctx, t, fmt.Sprintf("last handshake %s ago", age.Truncate(time.Second)))
		return
	}
	s.handleSuccess(ctx, t)
}

func (s *HealthMonitorService) checkL2TPViaIPSec(_ context.Context, _ *tunnel.ResellerTunnel, _ *tunnel.TunnelMetric) bool {
	return false
}
