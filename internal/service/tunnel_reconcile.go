package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

func (s *TunnelService) Reconcile(ctx context.Context) {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()

	s.flushStaleTechnicianRules()

	tunnels, err := s.repo.FindActive(ctx)
	if err != nil {
		s.log.Error("Reconcile: failed to list active tunnels", zap.Error(err))
		return
	}
	if len(tunnels) == 0 {
		s.log.Info("Reconcile: no active tunnels to restore")
		return
	}
	s.log.Info("Reconcile: restoring active tunnels", zap.Int("count", len(tunnels)))

	for i := range tunnels {
		t := &tunnels[i]

		if s.tunnelRuntimeHealthy(t) {
			s.log.Debug("Reconcile: tunnel already healthy", zap.String("id", t.ID.String()))
			continue
		}

		s.log.Info("Reconcile: re-setting up tunnel",
			zap.String("id", t.ID.String()),
			zap.String("namespace", t.Namespace),
			zap.String("vpn_type", string(t.VPNType)),
		)

		if !s.nsSvc.Exists(t.Namespace) {
			if err := s.nsSvc.Create(t.Namespace); err != nil {
				s.log.Error("Reconcile: create namespace failed",
					zap.String("id", t.ID.String()), zap.Error(err))
				s.setError(ctx, t.ID, err)
				continue
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
			s.log.Error("Reconcile: setup failed",
				zap.String("id", t.ID.String()), zap.Error(setupErr))
			s.setError(ctx, t.ID, setupErr)
			continue
		}
		s.log.Info("Reconcile: tunnel restored", zap.String("id", t.ID.String()))
	}
}

func (s *TunnelService) RecoverTunnel(t *tunnel.ResellerTunnel) error {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()

	if !s.nsSvc.Exists(t.Namespace) {
		if err := s.nsSvc.Create(t.Namespace); err != nil {
			return fmt.Errorf("recover: create namespace: %w", err)
		}
	}

	switch t.VPNType {
	case tunnel.VPNTypeWireGuard:
		_ = s.wgSvc.Teardown(t)
		return s.wgSvc.Setup(t)
	case tunnel.VPNTypeL2TP:
		_ = s.l2tpSvc.Teardown(t)
		return s.l2tpSvc.Setup(t)
	}
	return fmt.Errorf("recover: unknown vpn type %q", t.VPNType)
}

func (s *TunnelService) tunnelRuntimeHealthy(t *tunnel.ResellerTunnel) bool {
	if !s.nsSvc.Exists(t.Namespace) {
		return false
	}
	if t.VPNType == tunnel.VPNTypeL2TP {
		return s.l2tpDaemonsAlive(t.Namespace)
	}
	return s.interfaceUpInNS(t.Namespace, fmt.Sprintf("wg-%s", t.Namespace))
}

func (s *TunnelService) l2tpDaemonsAlive(ns string) bool {
	pidPath := filepath.Join("/run", fmt.Sprintf("xl2tpd-%s.pid", ns))
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return false
	}
	pid := strings.TrimSpace(string(data))
	if pid == "" {
		return false
	}
	return exec.Command("kill", "-0", pid).Run() == nil
}

func (s *TunnelService) interfaceUpInNS(ns, ifName string) bool {
	if !s.nsSvc.Exists(ns) {
		return false
	}
	out, err := s.nsSvc.ExecInNS(ns, "ip", "-br", "link", "show", ifName)
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "UP") || strings.Contains(string(out), "UNKNOWN")
}
