package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

func (s *TunnelService) Activate(ctx context.Context, id uuid.UUID) error {
	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if !t.CanActivate() {
		return tunnel.ErrAlreadyActive
	}

	s.setupMu.Lock()
	defer s.setupMu.Unlock()

	s.log.Info("Activating tunnel", zap.String("id", id.String()), zap.String("namespace", t.Namespace))

	if err := s.repo.UpdateStatus(ctx, id, tunnel.StatusProvisioning, ""); err != nil {
		return fmt.Errorf("update status to provisioning: %w", err)
	}

	if !s.nsSvc.Exists(t.Namespace) {
		if err := s.nsSvc.Create(t.Namespace); err != nil {
			s.setError(ctx, id, err)
			return fmt.Errorf("create namespace: %w", err)
		}
	}

	var setupErr error
	switch t.VPNType {
	case tunnel.VPNTypeWireGuard:
		setupErr = s.wgSvc.Setup(t)
	case tunnel.VPNTypeL2TP:
		setupErr = s.l2tpSvc.Setup(t)
	}

	if setupErr != nil {
		switch t.VPNType {
		case tunnel.VPNTypeWireGuard:
			_ = s.wgSvc.Teardown(t)
		case tunnel.VPNTypeL2TP:
			_ = s.l2tpSvc.Teardown(t)
		}
		if s.nsSvc.Exists(t.Namespace) {
			_ = s.nsSvc.Delete(t.Namespace)
		}
		s.setError(ctx, id, setupErr)
		return fmt.Errorf("setup vpn: %w", setupErr)
	}

	if err := s.repo.UpdateStatus(ctx, id, tunnel.StatusActive, ""); err != nil {
		return fmt.Errorf("update status to active: %w", err)
	}
	s.log.Info("Tunnel activated", zap.String("id", id.String()))
	return nil
}

func (s *TunnelService) Deactivate(ctx context.Context, id uuid.UUID) error {
	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if !t.CanDeactivate() {
		return tunnel.ErrNotActive
	}

	s.setupMu.Lock()
	defer s.setupMu.Unlock()

	s.log.Info("Deactivating tunnel", zap.String("id", id.String()))

	switch t.VPNType {
	case tunnel.VPNTypeWireGuard:
		_ = s.wgSvc.Teardown(t)
	case tunnel.VPNTypeL2TP:
		_ = s.l2tpSvc.Teardown(t)
	}

	if s.nsSvc.Exists(t.Namespace) {
		_ = s.nsSvc.Delete(t.Namespace)
	}

	return s.repo.UpdateStatus(ctx, id, tunnel.StatusPending, "")
}

func (s *TunnelService) Provision(ctx context.Context, id uuid.UUID) error {
	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}

	s.setupMu.Lock()
	defer s.setupMu.Unlock()

	if err := s.provisioner.Provision(t, s.vpsPublicIP); err != nil {
		s.setError(ctx, id, err)
		return fmt.Errorf("provision mikrotik: %w", err)
	}

	if t.VPNType == tunnel.VPNTypeWireGuard && t.ClientPublicKey != "" {
		if err := s.repo.Save(ctx, t); err != nil {
			return fmt.Errorf("persist client public key: %w", err)
		}
		if t.IsActive() && s.nsSvc.Exists(t.Namespace) {
			if err := s.wgSvc.AttachPeer(t); err != nil {
				s.log.Warn("Failed to attach wg peer live", zap.Error(err))
			}
		}
	}

	newStatus := tunnel.StatusPending
	if t.Status == tunnel.StatusActive {
		newStatus = tunnel.StatusActive
	}
	if err := s.repo.UpdateStatus(ctx, id, newStatus, ""); err != nil {
		return fmt.Errorf("update status after provision: %w", err)
	}

	s.log.Info("Tunnel provisioned to MikroTik", zap.String("id", id.String()))
	return nil
}

func (s *TunnelService) Delete(ctx context.Context, id uuid.UUID) error {
	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}

	s.setupMu.Lock()
	defer s.setupMu.Unlock()

	s.log.Info("Deleting tunnel",
		zap.String("id", t.ID.String()),
		zap.String("namespace", t.Namespace),
		zap.String("router_ip", t.RouterIP),
	)

	s.cleanupRouterBestEffort(t)
	s.cleanupVPSBestEffort(t)

	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete tunnel row: %w", err)
	}

	if s.onDelete != nil {
		s.onDelete(id.String())
	}

	s.log.Info("Tunnel deleted", zap.String("id", id.String()))
	return nil
}

func (s *TunnelService) cleanupRouterBestEffort(t *tunnel.ResellerTunnel) {
	if t.RouterIP == "" {
		return
	}
	if err := s.provisioner.Deprovision(t); err != nil {
		s.log.Warn("Router cleanup failed — manual cleanup may be required",
			zap.String("tunnel_id", t.ID.String()), zap.Error(err))
	}
}

func (s *TunnelService) cleanupVPSBestEffort(t *tunnel.ResellerTunnel) {
	switch t.VPNType {
	case tunnel.VPNTypeWireGuard:
		_ = s.wgSvc.Teardown(t)
	case tunnel.VPNTypeL2TP:
		_ = s.l2tpSvc.Teardown(t)
	}
	if s.nsSvc.Exists(t.Namespace) {
		_ = s.nsSvc.Delete(t.Namespace)
	}
}
