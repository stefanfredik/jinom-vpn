package service

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

func (s *HealthMonitorService) handleFailure(ctx context.Context, t *tunnel.ResellerTunnel, reason string) {
	st := s.getState(t.ID.String())

	s.mu.Lock()
	st.failCount++
	count := st.failCount
	s.mu.Unlock()

	if count < s.failThreshold {
		return
	}

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
		s.log.Warn("Tunnel unhealthy, attempting recovery",
			zap.String("tunnel_id", t.ID.String()),
			zap.String("namespace", t.Namespace),
			zap.String("reason", reason),
			zap.Int("consecutive_failures", count),
		)
		s.attemptRecovery(ctx, t)
		return
	}

	if t.Status != tunnel.StatusDown {
		s.log.Warn("Tunnel marked as down (recovery unavailable)",
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

func (s *HealthMonitorService) attemptRecovery(ctx context.Context, t *tunnel.ResellerTunnel) {
	s.log.Info("Attempting tunnel recovery",
		zap.String("tunnel_id", t.ID.String()),
		zap.String("namespace", t.Namespace),
		zap.String("vpn_type", string(t.VPNType)),
	)

	var err error
	if s.recoverFn != nil {
		err = s.recoverFn(t)
	} else {
		switch t.VPNType {
		case tunnel.VPNTypeWireGuard:
			_ = s.wgSvc.Teardown(t)
			err = s.wgSvc.Setup(t)
		case tunnel.VPNTypeL2TP:
			_ = s.l2tpSvc.Teardown(t)
			err = s.l2tpSvc.Setup(t)
		}
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

	s.log.Info("Tunnel recovery initiated", zap.String("tunnel_id", t.ID.String()))
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

func (s *HealthMonitorService) purgeStale(active []tunnel.ResellerTunnel) {
	live := make(map[string]struct{}, len(active))
	for i := range active {
		live[active[i].ID.String()] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.states {
		if _, ok := live[id]; !ok {
			delete(s.states, id)
		}
	}
}
