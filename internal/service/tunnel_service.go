package service

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
	// onDelete dipanggil oleh Delete() setelah row DB sukses dihapus. Dipakai
	// untuk membersihkan state in-memory pihak ketiga (HealthMonitor map).
	// Optional — boleh nil. Decoupling ini menghindari import cycle antara
	// TunnelService dan HealthMonitorService.
	onDelete func(id string)
}

// SetOnDeleteHook mendaftarkan hook yang dipanggil sekali setelah delete
// berhasil persisten ke DB. Idempotent: hanya satu hook didukung; pemanggilan
// kedua menggantikan yang pertama.
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
	// reseller_tunnels.router_api_port is NOT NULL with a BETWEEN 1 AND 65535
	// check, so an omitted (0) port has to fall back to the RouterOS default.
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
		t.PSK = "JinomGlobalSecret2026!"
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
		// Roll back so a partial setup doesn't leave the namespace or
		// interface behind. WireGuardService.Setup already cleans its own
		// interface, but we still own the namespace we created above.
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

	// Provision can run concurrently with Activate/Deactivate/Reconcile, all of
	// which mutate the same MikroTik interface and the same host-side
	// namespace/iptables state. Without the same mutex they hold we hit races
	// where (e.g.) an Activate tears down a half-finished provision or two
	// concurrent Provisions both try to remove and re-add wg-jinom on the
	// router. Hold setupMu for the full duration including the post-provision
	// AttachPeer call below.
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

	// Provision pushed config to the MikroTik (client-side) successfully.
	// Clear any stale last_error and move out of terminal-failure states so
	// the tunnel is ready for Activate. Preserve StatusActive when re-provisioning
	// a running tunnel — Save() above does not touch Status/LastError.
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

// Delete melepaskan tunnel sepenuhnya: artefak di MikroTik (interface, peer,
// IP, route), state di VPS (namespace, veth, iptables, config files), lalu
// row DB. Bersifat best-effort untuk setiap layer:
//
//   - Kalau Deprovision ke router gagal (router unreachable, password salah,
//     dll), kami log warn lalu LANJUT — operator bisa cleanup manual lewat
//     log message yang menyebut router_ip & tunnel_id eksplisit.
//   - Kalau Teardown VPS gagal sebagian, log warn dan tetap lanjut hapus row.
//   - Row DB selalu dihapus terakhir; semua orphan rows anak (metrics,
//     status_history) dihapus oleh ON DELETE CASCADE di migration.
//
// Penting: cleanup VPS dilakukan TANPA syarat IsActive(). Tunnel dengan
// status pending / provisioning / error masih bisa meninggalkan namespace,
// veth, iptables, dan config files; tanpa cleanup unconditional, sisa-sisa
// ini menumpuk seumur hidup VPS.
func (s *TunnelService) Delete(ctx context.Context, id uuid.UUID) error {
	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}

	s.setupMu.Lock()
	defer s.setupMu.Unlock()

	s.log.Info("Deleting tunnel",
		zap.String("id", id.String()),
		zap.String("namespace", t.Namespace),
		zap.String("router_ip", t.RouterIP),
		zap.String("vpn_type", string(t.VPNType)),
		zap.String("status_at_delete", string(t.Status)),
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

// cleanupRouterBestEffort memanggil Deprovisioner ke MikroTik. Kegagalan
// hanya menghasilkan log warn supaya operator bisa membersihkan manual —
// tidak menghalangi penghapusan DB.
func (s *TunnelService) cleanupRouterBestEffort(t *tunnel.ResellerTunnel) {
	if t.RouterIP == "" {
		s.log.Warn("Skip router cleanup: empty router_ip",
			zap.String("tunnel_id", t.ID.String()))
		return
	}
	if err := s.provisioner.Deprovision(t); err != nil {
		s.log.Warn("Router cleanup failed — manual cleanup may be required",
			zap.String("tunnel_id", t.ID.String()),
			zap.String("router_ip", t.RouterIP),
			zap.String("namespace", t.Namespace),
			zap.Error(err),
		)
	}
}

// cleanupVPSBestEffort menjalankan teardown VPN (per type) + namespace delete.
// Teardown semua idempotent, jadi memanggilnya saat artefak tidak ada hanya
// menghasilkan warning di dalam, bukan error fatal.
func (s *TunnelService) cleanupVPSBestEffort(t *tunnel.ResellerTunnel) {
	switch t.VPNType {
	case tunnel.VPNTypeWireGuard:
		if err := s.wgSvc.Teardown(t); err != nil {
			s.log.Warn("WireGuard teardown returned error",
				zap.String("tunnel_id", t.ID.String()), zap.Error(err))
		}
	case tunnel.VPNTypeL2TP:
		if err := s.l2tpSvc.Teardown(t); err != nil {
			s.log.Warn("L2TP teardown returned error",
				zap.String("tunnel_id", t.ID.String()), zap.Error(err))
		}
	}

	if s.nsSvc.Exists(t.Namespace) {
		if err := s.nsSvc.Delete(t.Namespace); err != nil {
			s.log.Warn("Namespace delete failed — manual cleanup may be required",
				zap.String("tunnel_id", t.ID.String()),
				zap.String("namespace", t.Namespace),
				zap.Error(err),
			)
		}
	}
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
	client, err := mikrotik.NewClient(t.RouterIP, t.EffectiveAPIPort(), t.RouterUsername, t.RouterPassword, t.RouterOSVersion >= 7)
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
			row := res[0]
			if row["disabled"] == "true" {
				status.MikrotikStatus = "disabled"
			} else {
				if row["running"] == "true" {
					status.MikrotikStatus = "running"
				} else {
					status.MikrotikStatus = "enabled"
				}
			}
			status.MikrotikUptime = firstNonEmpty(row["uptime"], row["last-link-up-time"])
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

	status.Uptime = status.MikrotikUptime
	if status.Uptime == "" && t.IsActive() {
		status.Uptime = formatTunnelUptime(time.Since(s.activeSince(ctx, t)))
	}

	return status, nil
}

// Reconcile re-creates the namespace and VPN interface for every tunnel that
// the database believes is active but whose runtime state has been wiped
// (e.g. after the host rebooted). Tunnels whose setup fails are flagged as
// error so an operator can investigate; we never silently downgrade them to
// pending because the MikroTik side may still have a working configuration.
func (s *TunnelService) Reconcile(ctx context.Context) {
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

// RecoverTunnel tears down and re-sets-up a tunnel's host-side runtime under
// the SAME setupMu that Activate/Deactivate/Provision/Delete hold. The health
// monitor calls this (via a hook) instead of touching wgSvc/l2tpSvc directly,
// so an automatic recovery can never race a concurrent operator action on the
// same namespace, iptables chain, or chap-secrets file.
//
// It returns the setup error (if any) but does NOT change persisted status —
// the caller (health monitor) owns the status/last_error/history transitions.
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

// tunnelRuntimeHealthy reports whether a tunnel's host-side runtime is already
// in place, so Reconcile can skip re-running Setup. The check differs per type:
//
//   - WireGuard creates a real wg-<ns> interface in the namespace; presence +
//     UP/UNKNOWN oper-state is an accurate liveness signal.
//   - L2TP has NO l2tp-<ns> interface on the VPS side — the ppp* interface only
//     appears when the MikroTik actually dials in, which may legitimately not
//     have happened yet. Probing a fictional interface always failed, so every
//     boot re-ran Setup needlessly. Instead we require the namespace to exist
//     and the per-tunnel xl2tpd process to be alive; charon/xl2tpd are what
//     Setup brings up, so their presence means the runtime is provisioned.
func (s *TunnelService) tunnelRuntimeHealthy(t *tunnel.ResellerTunnel) bool {
	if !s.nsSvc.Exists(t.Namespace) {
		return false
	}
	if t.VPNType == tunnel.VPNTypeL2TP {
		return s.l2tpDaemonsAlive(t.Namespace)
	}
	return s.interfaceUpInNS(t.Namespace, fmt.Sprintf("wg-%s", t.Namespace))
}

// l2tpDaemonsAlive returns true if this namespace's xl2tpd process (recorded in
// its per-tunnel pidfile) is running. /run is tmpfs, so after a reboot the
// pidfile is gone and this returns false, correctly triggering re-Setup.
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
	// kill -0 probes liveness without signalling.
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
	RouterAPIPort     *int     `json:"router_api_port,omitempty" validate:"omitempty,min=1,max=65535"`
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
	MikrotikUptime string        `json:"mikrotik_uptime,omitempty"`
	Uptime         string        `json:"uptime,omitempty"`
}

func extractIP(cidr string) string {
	for i, c := range cidr {
		if c == '/' {
			return cidr[:i]
		}
	}
	return cidr
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (s *TunnelService) activeSince(ctx context.Context, t *tunnel.ResellerTunnel) time.Time {
	history, err := s.repo.GetStatusHistory(ctx, t.ID, 20)
	if err != nil {
		return t.UpdatedAt
	}
	for _, item := range history {
		if item.Status == tunnel.StatusActive {
			return item.CreatedAt
		}
	}
	return t.UpdatedAt
}

func formatTunnelUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd%dh%dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

func generatePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.IntN(len(charset))]
	}
	return string(b)
}

func (s *TunnelService) SelectNOCReseller(ctx context.Context, technicianIP string, id uuid.UUID) error {
	parts := strings.Split(technicianIP, ".")
	if len(parts) != 4 {
		return fmt.Errorf("invalid technician IP format: %s", technicianIP)
	}
	lastOctet, err := strconv.Atoi(parts[3])
	if err != nil {
		return fmt.Errorf("invalid technician IP octet: %w", err)
	}
	tableID := fmt.Sprintf("%d", 10000+lastOctet)

	// Attempt to find the corresponding VPN IP if technicianIP is a public IP endpoint in WireGuard
	vpnIP := s.findVPNIPByEndpointIP(technicianIP)

	if id == uuid.Nil {
		// Clean up any existing rules for this technician IP and VPN IP
		_ = exec.Command("ip", "rule", "del", "from", technicianIP, "lookup", tableID).Run()
		if vpnIP != "" && vpnIP != technicianIP {
			_ = exec.Command("ip", "rule", "del", "from", vpnIP, "lookup", tableID).Run()
		}
		_ = exec.Command("ip", "route", "flush", "table", tableID).Run()
		s.log.Info("Technician cleared reseller tunnel routing",
			zap.String("technician_ip", technicianIP),
			zap.String("vpn_ip", vpnIP),
		)
		return nil
	}

	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("get tunnel: %w", err)
	}

	// Clean up any existing rules for this technician IP and VPN IP
	_ = exec.Command("ip", "rule", "del", "from", technicianIP, "lookup", tableID).Run()
	if vpnIP != "" && vpnIP != technicianIP {
		_ = exec.Command("ip", "rule", "del", "from", vpnIP, "lookup", tableID).Run()
	}

	// Add the ip rule: all packets from technicianIP lookup tableID
	if err := exec.Command("ip", "rule", "add", "from", technicianIP, "lookup", tableID).Run(); err != nil {
		return fmt.Errorf("failed to add ip rule: %w", err)
	}
	if vpnIP != "" && vpnIP != technicianIP {
		_ = exec.Command("ip", "rule", "add", "from", vpnIP, "lookup", tableID).Run()
	}

	// Flush and populate the routing table
	_ = exec.Command("ip", "route", "flush", "table", tableID).Run()

	// Add throw routes for all local/host subnets so they are not routed into the namespace
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipv4 := ipNet.IP.To4(); ipv4 != nil {
					// Zero out the host bits of the IP net to get a valid route prefix
					netIP := ipNet.IP.Mask(ipNet.Mask)
					ones, _ := ipNet.Mask.Size()
					cidr := fmt.Sprintf("%s/%d", netIP.String(), ones)
					_ = exec.Command("ip", "route", "add", "throw", cidr, "table", tableID).Run()
				}
			}
		}
	}

	// Also add throw for loopback range explicitly if not present
	_ = exec.Command("ip", "route", "add", "throw", "127.0.0.0/8", "table", tableID).Run()

	a := t.TunnelIndex / 64
	b := (t.TunnelIndex % 64) * 4
	nsIPNoMask := fmt.Sprintf("10.254.%d.%d", a, b+2)
	vethHost := fmt.Sprintf("vh-%d", t.TunnelIndex)

	// Route private subnet ranges to the namespace veth IP
	privateRanges := []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"}
	for _, subnet := range privateRanges {
		if err := exec.Command("ip", "route", "add", subnet, "via", nsIPNoMask, "dev", vethHost, "table", tableID).Run(); err != nil {
			s.log.Warn("Failed to add route to technician table", zap.String("subnet", subnet), zap.Error(err))
		}
	}

	s.log.Info("Technician selected reseller tunnel",
		zap.String("technician_ip", technicianIP),
		zap.String("vpn_ip", vpnIP),
		zap.String("tunnel", t.Name),
		zap.String("veth_host", vethHost),
		zap.String("ns_ip", nsIPNoMask),
	)
	return nil
}

func (s *TunnelService) CreateNOCTechnician(ctx context.Context, name string) (ip string, config string, err error) {
	if name == "" {
		return "", "", fmt.Errorf("technician name cannot be empty")
	}

	// 1. Generate client keys using native wg commands
	privBytes, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", "", fmt.Errorf("generate private key: %w", err)
	}
	clientPriv := strings.TrimSpace(string(privBytes))

	pubBytes, err := exec.Command("sh", "-c", fmt.Sprintf("echo %s | wg pubkey", clientPriv)).Output()
	if err != nil {
		return "", "", fmt.Errorf("generate public key: %w", err)
	}
	clientPub := strings.TrimSpace(string(pubBytes))

	// 2. Fetch server public key
	serverPubBytes, err := exec.Command("wg", "show", "wg-noc", "public-key").Output()
	if err != nil {
		return "", "", fmt.Errorf("fetch server public key: %w", err)
	}
	serverPub := strings.TrimSpace(string(serverPubBytes))

	// 3. Find next available IP
	clientIP, _, err := getNextFreeIP()
	if err != nil {
		return "", "", err
	}

	// 4. Append to server config file
	f, err := os.OpenFile("/etc/wireguard/wg-noc.conf", os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return "", "", fmt.Errorf("open wg-noc.conf: %w", err)
	}
	defer f.Close()

	peerEntry := fmt.Sprintf("\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32\n", name, clientPub, clientIP)
	if _, err := f.WriteString(peerEntry); err != nil {
		return "", "", fmt.Errorf("write peer entry: %w", err)
	}

	// 5. Apply peer to running WireGuard interface dynamically
	if err := exec.Command("wg", "set", "wg-noc", "peer", clientPub, "allowed-ips", clientIP+"/32").Run(); err != nil {
		return "", "", fmt.Errorf("apply wireguard peer: %w", err)
	}

	// 6. Generate client config file content
	clientConfig := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/24
DNS = 8.8.8.8

[Peer]
PublicKey = %s
AllowedIPs = 10.50.0.0/24, 10.250.0.0/16, 10.254.0.0/16, 192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8
Endpoint = %s:51820
PersistentKeepalive = 25
`, clientPriv, clientIP, serverPub, s.vpsPublicIP)

	return clientIP, clientConfig, nil
}

func getNextFreeIP() (string, int, error) {
	data, err := os.ReadFile("/etc/wireguard/wg-noc.conf")
	if err != nil {
		return "", 0, fmt.Errorf("read wg-noc.conf: %w", err)
	}

	used := make(map[int]bool)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "AllowedIPs") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				ipVal := strings.TrimSpace(parts[1])
				ipVal = strings.Split(ipVal, "/")[0] // Strip mask
				ipParts := strings.Split(ipVal, ".")
				if len(ipParts) == 4 && ipParts[0] == "10" && ipParts[1] == "50" && ipParts[2] == "0" {
					octet, err := strconv.Atoi(ipParts[3])
					if err == nil {
						used[octet] = true
					}
				}
			}
		}
	}

	for i := 2; i <= 254; i++ {
		if !used[i] {
			return fmt.Sprintf("10.50.0.%d", i), i, nil
		}
	}
	return "", 0, fmt.Errorf("no free IP addresses left in 10.50.0.0/24 range")
}

func (s *TunnelService) findVPNIPByEndpointIP(endpointIP string) string {
	out, err := exec.Command("wg", "show", "wg-noc", "dump").Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			endpoint := fields[2]
			allowedIPs := fields[3]
			if endpoint != "(none)" && endpoint != "" {
				host := endpoint
				if h, _, err := net.SplitHostPort(endpoint); err == nil {
					host = h
				}
				if host == endpointIP {
					vpnParts := strings.Split(allowedIPs, "/")
					if len(vpnParts) > 0 {
						firstIP := strings.Split(vpnParts[0], ",")[0]
						return strings.TrimSpace(firstIP)
					}
				}
			}
		}
	}
	return ""
}

func (s *TunnelService) flushStaleTechnicianRules() {
	s.log.Info("Cleaning up any stale technician policy routing rules...")
	out, err := exec.Command("ip", "rule", "show").Output()
	if err != nil {
		s.log.Warn("Failed to show ip rules during startup cleanup", zap.Error(err))
		return
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		// Look for lines containing "lookup 10" (which corresponds to 10XXX table range)
		if strings.Contains(line, "lookup 10") {
			// Example output format: "32765:	from 10.50.0.7 lookup 10200"
			fields := strings.Fields(line)
			var fromIP string
			var tableID string
			for i, field := range fields {
				if field == "from" && i+1 < len(fields) {
					fromIP = fields[i+1]
				}
				if field == "lookup" && i+1 < len(fields) {
					tableID = fields[i+1]
				}
			}
			if fromIP != "" && tableID != "" {
				s.log.Info("Removing stale technician rule", zap.String("from", fromIP), zap.String("table", tableID))
				_ = exec.Command("ip", "rule", "del", "from", fromIP, "lookup", tableID).Run()
				_ = exec.Command("ip", "route", "flush", "table", tableID).Run()
			}
		}
	}
}

type NOCUser struct {
	Name            string `json:"name"`
	PublicKey       string `json:"public_key"`
	IP              string `json:"ip"`
	LatestHandshake int64  `json:"latest_handshake"`
	TransferRx      int64  `json:"transfer_rx"`
	TransferTx      int64  `json:"transfer_tx"`
	Status          string `json:"status"`
}

func (s *TunnelService) ListNOCTechnicians(ctx context.Context) ([]NOCUser, error) {
	data, err := os.ReadFile("/etc/wireguard/wg-noc.conf")
	if err != nil {
		return nil, fmt.Errorf("read wg-noc.conf: %w", err)
	}

	activePeers := make(map[string]NOCUser)
	if out, err := exec.Command("wg", "show", "wg-noc", "dump").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 8 {
				pubKey := fields[0]
				handshake, _ := strconv.ParseInt(fields[4], 10, 64)
				tx, _ := strconv.ParseInt(fields[5], 10, 64)
				rx, _ := strconv.ParseInt(fields[6], 10, 64)
				
				status := "offline"
				if handshake > 0 && time.Now().Unix()-handshake < 180 {
					status = "online"
				}

				activePeers[pubKey] = NOCUser{
					PublicKey:       pubKey,
					LatestHandshake: handshake,
					TransferTx:      tx,
					TransferRx:      rx,
					Status:          status,
				}
			}
		}
	}

	lines := strings.Split(string(data), "\n")
	var users []NOCUser
	var current NOCUser
	inPeer := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "[Peer]" {
			if inPeer && current.PublicKey != "" {
				if active, ok := activePeers[current.PublicKey]; ok {
					current.LatestHandshake = active.LatestHandshake
					current.TransferTx = active.TransferTx
					current.TransferRx = active.TransferRx
					current.Status = active.Status
				} else {
					current.Status = "offline"
				}
				users = append(users, current)
			}
			current = NOCUser{}
			inPeer = true
			continue
		}

		if inPeer {
			if strings.HasPrefix(line, "#") {
				current.Name = strings.TrimSpace(strings.TrimPrefix(line, "#"))
			} else if strings.HasPrefix(line, "PublicKey") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					current.PublicKey = strings.TrimSpace(parts[1])
				}
			} else if strings.HasPrefix(line, "AllowedIPs") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					ipVal := strings.TrimSpace(parts[1])
					current.IP = strings.Split(ipVal, "/")[0]
				}
			}
		}
	}

	if inPeer && current.PublicKey != "" {
		if active, ok := activePeers[current.PublicKey]; ok {
			current.LatestHandshake = active.LatestHandshake
			current.TransferTx = active.TransferTx
			current.TransferRx = active.TransferRx
			current.Status = active.Status
		} else {
			current.Status = "offline"
		}
		users = append(users, current)
	}

	return users, nil
}

func (s *TunnelService) DeleteNOCTechnician(ctx context.Context, publicKey string) error {
	if publicKey == "" {
		return fmt.Errorf("public key cannot be empty")
	}

	data, err := os.ReadFile("/etc/wireguard/wg-noc.conf")
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	var newLines []string
	var peerLines []string
	inPeer := false
	isTargetPeer := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		if trimmed == "[Peer]" {
			if inPeer {
				if !isTargetPeer {
					newLines = append(newLines, peerLines...)
				}
				peerLines = nil
			}
			inPeer = true
			isTargetPeer = false
			peerLines = append(peerLines, line)
			continue
		}

		if inPeer {
			peerLines = append(peerLines, line)
			if strings.Contains(trimmed, publicKey) {
				isTargetPeer = true
			}
		} else {
			newLines = append(newLines, line)
		}
	}

	if inPeer {
		if !isTargetPeer {
			newLines = append(newLines, peerLines...)
		}
	}

	output := strings.Join(newLines, "\n")
	for strings.Contains(output, "\n\n\n") {
		output = strings.ReplaceAll(output, "\n\n\n", "\n\n")
	}
	if err := os.WriteFile("/etc/wireguard/wg-noc.conf", []byte(output), 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	_ = exec.Command("wg", "set", "wg-noc", "peer", publicKey, "remove").Run()
	s.log.Info("Deleted NOC technician WireGuard peer", zap.String("public_key", publicKey))
	return nil
}
