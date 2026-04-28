package service

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
	"github.com/jinom/vpn/pkg/mikrotik"
)

type TunnelService struct {
	repo        tunnel.Repository
	nsSvc       *NamespaceService
	wgSvc       *WireGuardService
	l2tpSvc     *L2TPService
	provisioner *ProvisionerService
	vpsPublicIP string
	log         *zap.Logger
	setupMu     sync.Mutex
}

func NewTunnelService(
	repo tunnel.Repository,
	nsSvc *NamespaceService,
	wgSvc *WireGuardService,
	l2tpSvc *L2TPService,
	provisioner *ProvisionerService,
	vpsPublicIP string,
	log *zap.Logger,
) *TunnelService {
	return &TunnelService{
		repo:        repo,
		nsSvc:       nsSvc,
		wgSvc:       wgSvc,
		l2tpSvc:     l2tpSvc,
		provisioner: provisioner,
		vpsPublicIP: vpsPublicIP,
		log:         log,
	}
}

func (s *TunnelService) Create(ctx context.Context, req CreateTunnelRequest) (*tunnel.ResellerTunnel, error) {
	t := &tunnel.ResellerTunnel{
		ResellerID:        req.ResellerID,
		CompanyID:         req.CompanyID,
		Name:              req.Name,
		VPNType:           tunnel.VPNType(req.VPNType),
		RouterIP:          req.RouterIP,
		RouterUsername:    req.RouterUsername,
		RouterPassword:    req.RouterPassword,
		RouterOSVersion:   req.RouterOSVersion,
		MonitoringSubnets: req.MonitoringSubnets,
		Status:            tunnel.StatusPending,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if err := t.Validate(); err != nil {
		return nil, err
	}

	t.GenerateNamespace()

	tunnelIdx, err := s.repo.NextTunnelIndex(ctx)
	if err != nil {
		return nil, fmt.Errorf("allocate tunnel index: %w", err)
	}
	t.TunnelIndex = tunnelIdx
	t.ServerIPAddress, t.ClientIPAddress = indexToSubnet(tunnelIdx)

	if t.VPNType == tunnel.VPNTypeWireGuard {
		serverPriv, serverPub, err := s.wgSvc.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("generate server keypair: %w", err)
		}
		t.ServerPrivateKey = serverPriv
		t.ServerPublicKey = serverPub
		t.ServerListenPort = 51820 + tunnelIdx
	} else {
		t.L2TPUsername = fmt.Sprintf("jinom-res-%d", t.ResellerID)
		t.L2TPPassword = generatePassword(24)
		t.PSK = generatePassword(32)
	}

	if err := s.repo.Save(ctx, t); err != nil {
		return nil, fmt.Errorf("save tunnel: %w", err)
	}

	s.log.Info("Tunnel created",
		zap.String("id", t.ID.String()),
		zap.String("namespace", t.Namespace),
		zap.String("vpn_type", string(t.VPNType)),
	)

	return t, nil
}

func (s *TunnelService) GetByID(ctx context.Context, id uuid.UUID) (*tunnel.ResellerTunnel, error) {
	return s.repo.FindByID(ctx, id)
}

func (s *TunnelService) List(ctx context.Context, filter tunnel.Filter) ([]tunnel.ResellerTunnel, int64, error) {
	return s.repo.FindAll(ctx, filter)
}

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

	if err := s.provisioner.Provision(t, s.vpsPublicIP); err != nil {
		s.setError(ctx, id, err)
		return fmt.Errorf("provision mikrotik: %w", err)
	}

	s.log.Info("Tunnel provisioned to MikroTik", zap.String("id", id.String()))
	return nil
}

func (s *TunnelService) Delete(ctx context.Context, id uuid.UUID) error {
	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}

	if t.IsActive() {
		if err := s.Deactivate(ctx, id); err != nil {
			s.log.Warn("Failed to deactivate before delete", zap.Error(err))
		}
	}

	return s.repo.Delete(ctx, id)
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

	if t.IsActive() && s.nsSvc.Exists(t.Namespace) {
		peerIP := extractIP(t.ClientIPAddress)
		out, err := s.nsSvc.ExecInNS(t.Namespace, "ping", "-c", "1", "-W", "2", peerIP)
		status.PeerReachable = err == nil
		_ = out
	}

	// Try to fetch Mikrotik status
	client, err := mikrotik.NewClient(t.RouterIP, t.RouterUsername, t.RouterPassword, t.RouterOSVersion >= 7)
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
			if res[0]["disabled"] == "true" {
				status.MikrotikStatus = "disabled"
			} else {
				if res[0]["running"] == "true" {
					status.MikrotikStatus = "running"
				} else {
					status.MikrotikStatus = "enabled"
				}
			}
		} else {
			status.MikrotikStatus = "not found"
		}

		// Fetch IP address in mikrotik
		ipRes, err := client.Run("/ip/address/print", map[string]string{"?interface": name})
		if err == nil && len(ipRes) > 0 {
			status.MikrotikIP = ipRes[0]["address"]
		}
	} else {
		status.MikrotikStatus = "unreachable"
	}

	return status, nil
}

func (s *TunnelService) GetMetrics(ctx context.Context, id uuid.UUID, limit int) ([]tunnel.TunnelMetric, error) {
	return s.repo.GetMetrics(ctx, id, limit)
}

func (s *TunnelService) GetStatusHistory(ctx context.Context, id uuid.UUID, limit int) ([]tunnel.TunnelStatusHistory, error) {
	return s.repo.GetStatusHistory(ctx, id, limit)
}

func (s *TunnelService) setError(ctx context.Context, id uuid.UUID, err error) {
	_ = s.repo.UpdateStatus(ctx, id, tunnel.StatusError, err.Error())
}

func indexToSubnet(index int) (serverIP, clientIP string) {
	a := index / 64
	b := (index % 64) * 4
	serverIP = fmt.Sprintf("10.250.%d.%d/30", a, b+1)
	clientIP = fmt.Sprintf("10.250.%d.%d/30", a, b+2)
	return
}

type CreateTunnelRequest struct {
	ResellerID        int64    `json:"reseller_id" validate:"required"`
	CompanyID         int64    `json:"company_id" validate:"required"`
	Name              string   `json:"name" validate:"required"`
	VPNType           string   `json:"vpn_type" validate:"required,oneof=wireguard l2tp"`
	RouterIP          string   `json:"router_ip" validate:"required"`
	RouterUsername    string   `json:"router_username" validate:"required"`
	RouterPassword    string   `json:"router_password" validate:"required"`
	RouterOSVersion   int      `json:"routeros_version"`
	MonitoringSubnets []string `json:"monitoring_subnets"`
}

type TunnelStatus struct {
	ID             uuid.UUID     `json:"id"`
	Status         tunnel.Status `json:"status"`
	Namespace      string        `json:"namespace"`
	LastError      string        `json:"last_error,omitempty"`
	PeerReachable  bool          `json:"peer_reachable"`
	MikrotikStatus string        `json:"mikrotik_status,omitempty"`
	MikrotikIP     string        `json:"mikrotik_ip,omitempty"`
}

func extractIP(cidr string) string {
	for i, c := range cidr {
		if c == '/' {
			return cidr[:i]
		}
	}
	return cidr
}

func generatePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.IntN(len(charset))]
	}
	return string(b)
}
