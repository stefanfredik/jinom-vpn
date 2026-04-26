package service

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

type HealthMonitorService struct {
	repo       tunnel.Repository
	nsSvc      *NamespaceService
	interval   time.Duration
	failCount  int
	log        *zap.Logger
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	failCounts map[string]int
	mu         sync.Mutex
}

func NewHealthMonitorService(
	repo tunnel.Repository,
	nsSvc *NamespaceService,
	log *zap.Logger,
) *HealthMonitorService {
	return &HealthMonitorService{
		repo:       repo,
		nsSvc:      nsSvc,
		interval:   30 * time.Second,
		failCount:  3,
		log:        log,
		failCounts: make(map[string]int),
	}
}

func (s *HealthMonitorService) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.log.Info("Health monitor started", zap.Duration("interval", s.interval))

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
	if !s.nsSvc.Exists(t.Namespace) {
		s.handleFailure(ctx, t, "namespace does not exist")
		return
	}

	peerIP := extractIP(t.ClientIPAddress)
	_, err := s.nsSvc.ExecInNS(t.Namespace, "ping", "-c", "1", "-W", "3", peerIP)

	if err != nil {
		s.handleFailure(ctx, t, "peer unreachable")
		return
	}

	s.handleSuccess(ctx, t)
}

func (s *HealthMonitorService) handleFailure(ctx context.Context, t *tunnel.ResellerTunnel, reason string) {
	s.mu.Lock()
	s.failCounts[t.ID.String()]++
	count := s.failCounts[t.ID.String()]
	s.mu.Unlock()

	if count >= s.failCount {
		s.log.Warn("Tunnel marked as down",
			zap.String("tunnel_id", t.ID.String()),
			zap.String("namespace", t.Namespace),
			zap.String("reason", reason),
			zap.Int("consecutive_failures", count),
		)
		_ = s.repo.UpdateStatus(ctx, t.ID, tunnel.StatusDown, reason)
	}
}

func (s *HealthMonitorService) handleSuccess(ctx context.Context, t *tunnel.ResellerTunnel) {
	s.mu.Lock()
	prevCount := s.failCounts[t.ID.String()]
	s.failCounts[t.ID.String()] = 0
	s.mu.Unlock()

	if prevCount >= s.failCount {
		s.log.Info("Tunnel recovered",
			zap.String("tunnel_id", t.ID.String()),
			zap.String("namespace", t.Namespace),
		)
		_ = s.repo.UpdateStatus(ctx, t.ID, tunnel.StatusActive, "")
	}
}
