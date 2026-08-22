package service

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

type tunnelHealthState struct {
	failCount     int
	lastRecovery  time.Time
	recoveryCount int
}

type HealthMonitorService struct {
	repo          tunnel.Repository
	nsSvc         *NamespaceService
	wgSvc         *WireGuardService
	l2tpSvc       *L2TPService
	vpsPublicIP   string
	interval      time.Duration
	failThreshold int
	maxRecoveries int
	workerCount   int
	log           *zap.Logger
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	states        map[string]*tunnelHealthState
	mu            sync.Mutex
	recoverFn     func(t *tunnel.ResellerTunnel) error
}

func (s *HealthMonitorService) SetRecoverHook(fn func(t *tunnel.ResellerTunnel) error) {
	s.recoverFn = fn
}

func (s *HealthMonitorService) SetWorkerCount(count int) {
	if count > 0 {
		s.workerCount = count
	}
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
		workerCount:   20,
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
			zap.Int("worker_count", s.workerCount),
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

func (s *HealthMonitorService) Forget(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, id)
}

func (s *HealthMonitorService) checkAllTunnels(ctx context.Context) {
	tunnels, err := s.repo.FindActiveOrDown(ctx)
	if err != nil {
		s.log.Error("Failed to fetch tunnels for health check", zap.Error(err))
		return
	}

	if len(tunnels) == 0 {
		return
	}

	workerCount := s.workerCount
	if workerCount <= 0 {
		workerCount = 20
	}
	if workerCount > len(tunnels) {
		workerCount = len(tunnels)
	}

	jobs := make(chan *tunnel.ResellerTunnel, len(tunnels))
	var wg sync.WaitGroup

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case t, ok := <-jobs:
					if !ok {
						return
					}
					s.checkTunnel(ctx, t)
				}
			}
		}()
	}

	for i := range tunnels {
		jobs <- &tunnels[i]
	}
	close(jobs)

	wg.Wait()
	s.purgeStale(tunnels)
}
