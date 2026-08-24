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
	nocMu       sync.Mutex
	onDelete    func(id string)
}

func (s *TunnelService) SetOnDeleteHook(fn func(id string)) {
	s.onDelete = fn
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

type CreateTunnelRequest struct {
	ResellerID        int64    `json:"reseller_id" validate:"required"`
	CompanyID         int64    `json:"company_id" validate:"required"`
	Name              string   `json:"name" validate:"required"`
	VPNType           string   `json:"vpn_type" validate:"required,oneof=wireguard l2tp"`
	RouterIP          string   `json:"router_ip" validate:"required"`
	RouterUsername    string   `json:"router_username" validate:"required"`
	RouterPassword    string   `json:"router_password" validate:"required"`
	RouterOSVersion   int      `json:"routeros_version"`
	RouterAPIPort     *int     `json:"router_api_port,omitempty" validate:"omitempty,min=1,max=65535"`
	MonitoringSubnets []string `json:"monitoring_subnets"`
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

	if req.RouterAPIPort != nil {
		t.RouterAPIPort = *req.RouterAPIPort
	}
	t.RouterAPIPort = t.EffectiveAPIPort()

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
		t.PSK = s.l2tpSvc.GetPSK()
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

func generatePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.IntN(len(charset))]
	}
	return string(b)
}
