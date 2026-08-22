package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

type UpdateSubnetsRequest struct {
	Subnets   []string  `json:"monitoring_subnets"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s *TunnelService) UpdateSubnets(
	ctx context.Context,
	id uuid.UUID,
	req UpdateSubnetsRequest,
) (*tunnel.ResellerTunnel, error) {
	if req.UpdatedAt.IsZero() {
		return nil, fmt.Errorf("%w: updated_at is required for optimistic locking", tunnel.ErrConflict)
	}

	normalized, err := tunnel.NormalizeSubnets(req.Subnets, s.vpsPublicIP)
	if err != nil {
		return nil, err
	}

	s.setupMu.Lock()
	defer s.setupMu.Unlock()

	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	oldSubnets := t.MonitoringSubnets

	newUpdatedAt, err := s.repo.UpdateSubnets(ctx, id, normalized, req.UpdatedAt)
	if err != nil {
		return nil, err
	}
	t.MonitoringSubnets = normalized
	t.UpdatedAt = newUpdatedAt

	if !t.IsActive() {
		s.log.Info("Monitoring subnets updated (tunnel inactive, applied on next activate)",
			zap.String("id", id.String()), zap.Strings("subnets", normalized))
		return t, nil
	}

	if err := s.reloadRuntimeRoutes(t, oldSubnets); err != nil {
		if _, rbErr := s.repo.UpdateSubnets(ctx, id, oldSubnets, newUpdatedAt); rbErr != nil {
			s.log.Error("CRITICAL: reload failed and DB rollback also failed",
				zap.String("id", id.String()),
				zap.NamedError("reload_error", err),
				zap.NamedError("rollback_error", rbErr),
			)
		}
		return nil, fmt.Errorf("apply subnets to runtime: %w", err)
	}

	s.log.Info("Monitoring subnets updated and applied live",
		zap.String("id", id.String()), zap.Strings("old", oldSubnets), zap.Strings("new", normalized))
	return t, nil
}

func (s *TunnelService) reloadRuntimeRoutes(t *tunnel.ResellerTunnel, oldSubnets []string) error {
	if !s.nsSvc.Exists(t.Namespace) {
		s.log.Warn("Namespace missing during subnet reload, rebuilding runtime", zap.String("namespace", t.Namespace))
		if err := s.nsSvc.Create(t.Namespace); err != nil {
			return fmt.Errorf("recreate namespace: %w", err)
		}
		switch t.VPNType {
		case tunnel.VPNTypeWireGuard:
			return s.wgSvc.Setup(t)
		case tunnel.VPNTypeL2TP:
			return s.l2tpSvc.Setup(t)
		}
		return fmt.Errorf("unknown vpn type %q", t.VPNType)
	}

	switch t.VPNType {
	case tunnel.VPNTypeWireGuard:
		return s.wgSvc.ReloadRoutes(t, oldSubnets)
	case tunnel.VPNTypeL2TP:
		return s.l2tpSvc.ReloadRoutes(t, oldSubnets)
	}
	return fmt.Errorf("unknown vpn type %q", t.VPNType)
}

func (s *TunnelService) activeRoutes(t *tunnel.ResellerTunnel) []string {
	switch t.VPNType {
	case tunnel.VPNTypeWireGuard:
		return s.nsSvc.ListRoutes(t.Namespace, fmt.Sprintf("wg-%s", t.Namespace))
	case tunnel.VPNTypeL2TP:
		ifName := s.l2tpSvc.findPPPInterface(t.Namespace)
		if ifName == "" {
			return []string{}
		}
		return s.nsSvc.ListRoutes(t.Namespace, ifName)
	}
	return []string{}
}
