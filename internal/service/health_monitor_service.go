package service

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

var (
	pingLossRegex    = regexp.MustCompile(`([\d.]+)% packet loss`)
	pingLatencyRegex = regexp.MustCompile(`rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms`)
)

type tunnelHealthState struct {
	failCount    int
	lastRecovery time.Time
	recoveryCount int
}

type HealthMonitorService struct {
	repo       tunnel.Repository
	nsSvc      *NamespaceService
	wgSvc      *WireGuardService
	l2tpSvc    *L2TPService
	vpsPublicIP string
	interval   time.Duration
	failThreshold int
	maxRecoveries int
	log        *zap.Logger
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	states     map[string]*tunnelHealthState
	mu         sync.Mutex
}

func NewHealthMonitorService(
	repo tunnel.Repository,
	nsSvc *NamespaceService,
	wgSvc *WireGuardService,
	l2tpSvc *L2TPService,
	vpsPublicIP string,
	log *zap.Logger,
) *HealthMonitorService {
	return &HealthMonitorService{
		repo:          repo,
		nsSvc:         nsSvc,
		wgSvc:         wgSvc,
		l2tpSvc:       l2tpSvc,
		vpsPublicIP:   vpsPublicIP,
		interval:      60 * time.Second,
		failThreshold: 5,
		maxRecoveries: 3,
		log:           log,
		states:        make(map[string]*tunnelHealthState),
	}
}

func (s *HealthMonitorService) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.log.Info("Health monitor started",
			zap.Duration("interval", s.interval),
			zap.Int("fail_threshold", s.failThreshold),
			zap.Int("max_recoveries", s.maxRecoveries),
		)

		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				s.log.Info("Health monitor stopped")
				return
			case <-ticker.C:
				s.checkAllTunnels(ctx)
			}
		}
	}()
}

func (s *HealthMonitorService) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

func (s *HealthMonitorService) getState(id string) *tunnelHealthState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.states[id]
	if !ok {
		st = &tunnelHealthState{}
		s.states[id] = st
	}
	return st
}

func (s *HealthMonitorService) checkAllTunnels(ctx context.Context) {
	tunnels, err := s.repo.FindActive(ctx)
	if err != nil {
		s.log.Error("Failed to fetch active tunnels", zap.Error(err))
		return
	}

	for i := range tunnels {
		t := &tunnels[i]
		s.checkTunnel(ctx, t)
	}
}

func (s *HealthMonitorService) checkTunnel(ctx context.Context, t *tunnel.ResellerTunnel) {
	metric := &tunnel.TunnelMetric{
		TunnelID:  t.ID,
		Timestamp: time.Now(),
	}

	if !s.nsSvc.Exists(t.Namespace) {
		s.handleFailure(ctx, t, "namespace does not exist")
		return
	}

	peerIP := extractIP(t.ClientIPAddress)
	out, err := s.nsSvc.ExecInNS(t.Namespace, "ping", "-c", "2", "-W", "3", peerIP)

	if err != nil {
		loss := 100.0
		metric.PacketLoss = &loss
		s.repo.SaveMetric(ctx, metric)
		s.handleFailure(ctx, t, "peer unreachable")
		return
	}

	// Parse Ping
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

	// Fetch Wireguard Rx/Tx if applicable
	if t.VPNType == tunnel.VPNTypeWireGuard {
		ifName := fmt.Sprintf("wg-%s", t.Namespace)
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
		if wgOut, e := s.nsSvc.ExecInNS(t.Namespace, "wg", "show", ifName, "latest-handshakes"); e == nil {
			parts := strings.Fields(string(wgOut))
			if len(parts) >= 2 {
				if ts, e2 := strconv.ParseInt(parts[1], 10, 64); e2 == nil && ts > 0 {
					ht := time.Unix(ts, 0)
					metric.HandshakeTime = &ht
				}
			}
		}
	}

	// Save Metric
	s.repo.SaveMetric(ctx, metric)

	s.handleSuccess(ctx, t)
}

func (s *HealthMonitorService) handleFailure(ctx context.Context, t *tunnel.ResellerTunnel, reason string) {
	st := s.getState(t.ID.String())

	s.mu.Lock()
	st.failCount++
	count := st.failCount
	s.mu.Unlock()

	if count < s.failThreshold {
		return
	}

	if count == s.failThreshold {
		s.log.Warn("Tunnel unhealthy, attempting recovery",
			zap.String("tunnel_id", t.ID.String()),
			zap.String("namespace", t.Namespace),
			zap.String("reason", reason),
			zap.Int("consecutive_failures", count),
		)

		s.mu.Lock()
		canRecover := st.recoveryCount < s.maxRecoveries &&
			time.Since(st.lastRecovery) > 5*time.Minute
		if canRecover {
			st.recoveryCount++
			st.lastRecovery = time.Now()
			st.failCount = 0
		}
		s.mu.Unlock()

		if canRecover {
			s.attemptRecovery(ctx, t)
			return
		}
	}

	if count == s.failThreshold && !s.canRecover(t.ID.String()) {
		s.log.Warn("Tunnel marked as down (max recoveries exhausted)",
			zap.String("tunnel_id", t.ID.String()),
			zap.String("namespace", t.Namespace),
			zap.String("reason", reason),
		)
		_ = s.repo.UpdateStatus(ctx, t.ID, tunnel.StatusDown, reason)
		_ = s.repo.SaveStatusHistory(ctx, &tunnel.TunnelStatusHistory{
			TunnelID: t.ID,
			Status:   tunnel.StatusDown,
			Reason:   reason,
		})
	}
}

func (s *HealthMonitorService) canRecover(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.states[id]
	if st == nil {
		return true
	}
	return st.recoveryCount < s.maxRecoveries
}

func (s *HealthMonitorService) attemptRecovery(ctx context.Context, t *tunnel.ResellerTunnel) {
	s.log.Info("Attempting tunnel recovery",
		zap.String("tunnel_id", t.ID.String()),
		zap.String("namespace", t.Namespace),
		zap.String("vpn_type", string(t.VPNType)),
	)

	var err error
	switch t.VPNType {
	case tunnel.VPNTypeWireGuard:
		_ = s.wgSvc.Teardown(t)
		err = s.wgSvc.Setup(t)
	case tunnel.VPNTypeL2TP:
		_ = s.l2tpSvc.Teardown(t)
		err = s.l2tpSvc.Setup(t)
	}

	if err != nil {
		s.log.Error("Tunnel recovery failed",
			zap.String("tunnel_id", t.ID.String()),
			zap.Error(err),
		)
		_ = s.repo.UpdateStatus(ctx, t.ID, tunnel.StatusDown, "recovery failed: "+err.Error())
		_ = s.repo.SaveStatusHistory(ctx, &tunnel.TunnelStatusHistory{
			TunnelID: t.ID,
			Status:   tunnel.StatusDown,
			Reason:   "recovery failed: " + err.Error(),
		})
		return
	}

	s.log.Info("Tunnel recovery initiated",
		zap.String("tunnel_id", t.ID.String()),
	)
}

func (s *HealthMonitorService) handleSuccess(ctx context.Context, t *tunnel.ResellerTunnel) {
	st := s.getState(t.ID.String())

	s.mu.Lock()
	prevFail := st.failCount
	st.failCount = 0
	if prevFail >= s.failThreshold {
		st.recoveryCount = 0
	}
	s.mu.Unlock()

	if t.Status == tunnel.StatusDown {
		s.log.Info("Tunnel recovered",
			zap.String("tunnel_id", t.ID.String()),
			zap.String("namespace", t.Namespace),
		)
		_ = s.repo.UpdateStatus(ctx, t.ID, tunnel.StatusActive, "")
		_ = s.repo.SaveStatusHistory(ctx, &tunnel.TunnelStatusHistory{
			TunnelID: t.ID,
			Status:   tunnel.StatusActive,
			Reason:   "tunnel recovered",
		})
	}
}
