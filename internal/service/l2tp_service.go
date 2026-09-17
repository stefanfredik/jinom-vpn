package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

// SNAT mode menentukan bagaimana trafik NMS keluar melalui interface ppp.
const (
	// SNATModeServerIP mem-SNAT trafik ke ServerIPAddress tunnel (10.250.x.1),
	// sehingga sumber paket masuk ke rentang 10.250.0.0/16 yang sudah menjadi
	// acuan rule filter, NAT, dan route di sisi MikroTik.
	SNATModeServerIP = "snat"
	// SNATModeMasquerade mempertahankan perilaku lama: sumber paket menjadi
	// alamat lokal ppp (10.255.255.1 untuk semua reseller). Disediakan sebagai
	// jalan mundur operasional tanpa perlu deploy ulang.
	SNATModeMasquerade = "masquerade"
)

const (
	pppDir        = "/etc/ppp"
	pskPath       = "/etc/ipsec.d/jinom-psk"
	ipsecConfPath = "/etc/ipsec.conf"
	ipsecSecPath  = "/etc/ipsec.secrets"
)

// chapSecrets adalah var, bukan const, semata agar tes dapat mengarahkannya ke
// direktori sementara. Produksi tidak pernah mengubahnya.
var chapSecrets = "/etc/ppp/chap-secrets"

type L2TPService struct {
	nsSvc       *NamespaceService
	log         *zap.Logger
	vpsPublicIP string
	snatMode    string

	pskMu sync.RWMutex
	psk   string

	// secretsMu menjaga operasi baca-ubah-tulis pada /etc/ppp/chap-secrets.
	// Jalur pemanggil memang diserialisasi oleh TunnelService.setupMu, tetapi
	// file ini juga ditulis oleh RebuildChapSecrets di luar jalur tersebut.
	secretsMu sync.Mutex
}

func NewL2TPService(nsSvc *NamespaceService, vpsPublicIP, snatMode string, log *zap.Logger) *L2TPService {
	if snatMode != SNATModeMasquerade {
		snatMode = SNATModeServerIP
	}
	svc := &L2TPService{
		nsSvc:       nsSvc,
		vpsPublicIP: vpsPublicIP,
		snatMode:    snatMode,
		log:         log,
	}
	svc.initGlobalDaemons()
	svc.installPPPHooks()
	return svc
}

// GetPSK returns the active global IPSec Pre-Shared Key.
func (s *L2TPService) GetPSK() string {
	s.pskMu.RLock()
	psk := s.psk
	s.pskMu.RUnlock()
	if psk != "" {
		return psk
	}

	s.pskMu.Lock()
	defer s.pskMu.Unlock()
	if s.psk != "" {
		return s.psk
	}
	if data, err := os.ReadFile(pskPath); err == nil {
		s.psk = strings.TrimSpace(string(data))
	}
	return s.psk
}

func (s *L2TPService) setPSK(psk string) {
	s.pskMu.Lock()
	s.psk = psk
	s.pskMu.Unlock()
}

func routesFilePath(ns string) string {
	return filepath.Join(pppDir, fmt.Sprintf("routes.%s", ns))
}

func srcIPFilePath(ns string) string {
	return filepath.Join(pppDir, fmt.Sprintf("srcip.%s", ns))
}

// writeSrcIPFile menulis alamat sumber SNAT untuk namespace ini, dibaca oleh
// skrip ip-up. Ketidakhadiran file berarti "pakai MASQUERADE", sehingga mode
// dikendalikan sepenuhnya oleh ada/tidaknya file — tanpa percabangan tambahan
// di dalam skrip shell.
func (s *L2TPService) writeSrcIPFile(t *tunnel.ResellerTunnel) error {
	path := srcIPFilePath(t.Namespace)

	srcIP := stripCIDR(t.ServerIPAddress)
	if s.snatMode != SNATModeServerIP || srcIP == "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove srcip file: %w", err)
		}
		return nil
	}
	return writeFileAtomic(path, []byte(srcIP+"\n"), 0600)
}

func (s *L2TPService) writeRoutesFile(t *tunnel.ResellerTunnel) error {
	data := strings.Join(effectiveSubnets(t.MonitoringSubnets), "\n") + "\n"
	if err := writeFileAtomic(routesFilePath(t.Namespace), []byte(data), 0600); err != nil {
		return fmt.Errorf("write routes file: %w", err)
	}
	return nil
}

func (s *L2TPService) Setup(t *tunnel.ResellerTunnel) error {
	s.log.Info("Setting up L2TP/IPSec tunnel (Global Mode)",
		zap.String("namespace", t.Namespace),
		zap.String("tunnel", t.Name),
		zap.String("snat_mode", s.snatMode),
	)

	if err := s.updateChapSecrets(t); err != nil {
		return fmt.Errorf("update chap secrets: %w", err)
	}

	if err := s.writeRoutesFile(t); err != nil {
		return err
	}

	if err := s.writeSrcIPFile(t); err != nil {
		return err
	}

	if err := s.setupVeth(t); err != nil {
		s.log.Error("Failed to setup veth for namespace", zap.Error(err))
		return fmt.Errorf("setup veth: %w", err)
	}

	return nil
}

func (s *L2TPService) ReloadRoutes(t *tunnel.ResellerTunnel, oldSubnets []string) error {
	if err := s.writeRoutesFile(t); err != nil {
		return err
	}

	ifName := s.findPPPInterface(t.Namespace)
	if ifName == "" {
		s.log.Info("ReloadRoutes: no active ppp session, routes file updated only",
			zap.String("namespace", t.Namespace))
		return nil
	}

	added, removed := tunnel.DiffSubnets(
		effectiveSubnets(oldSubnets),
		effectiveSubnets(t.MonitoringSubnets),
	)

	for _, subnet := range removed {
		if _, err := s.nsSvc.ExecInNS(t.Namespace, "ip", "route", "del", subnet, "dev", ifName); err != nil {
			s.log.Warn("ReloadRoutes: remove route failed (continuing)",
				zap.String("subnet", subnet), zap.Error(err))
		}
	}
	for _, subnet := range added {
		// "replace" bukan "add": bila sesi PPP lama belum hilang, route yang
		// sama masih terpasang pada interface lain dan "add" akan gagal.
		if _, err := s.nsSvc.ExecInNS(t.Namespace, "ip", "route", "replace", subnet, "dev", ifName); err != nil {
			return fmt.Errorf("add route %s: %w", subnet, err)
		}
	}

	s.log.Info("ReloadRoutes: applied",
		zap.String("namespace", t.Namespace),
		zap.String("interface", ifName),
		zap.Strings("added", added),
		zap.Strings("removed", removed),
	)
	return nil
}

func (s *L2TPService) Teardown(t *tunnel.ResellerTunnel) error {
	s.log.Info("Tearing down L2TP/IPSec tunnel (Global Mode)",
		zap.String("namespace", t.Namespace),
	)

	if err := s.removeChapSecrets(t.Namespace); err != nil {
		s.log.Warn("Teardown: failed to remove chap secrets",
			zap.String("namespace", t.Namespace), zap.Error(err))
	}
	_ = os.Remove(routesFilePath(t.Namespace))
	_ = os.Remove(srcIPFilePath(t.Namespace))

	s.disconnectSessions(t.Namespace)
	s.teardownVeth(t.TunnelIndex)

	return nil
}

// disconnectSessions memutus sesi PPP milik satu namespace saja.
//
// Versi sebelumnya memakai `pkill -f "pppd.*<username>"`, yang bermasalah dua
// arah: pola itu juga cocok dengan cmdline reseller lain yang namanya berawalan
// sama (jinom-res-1 cocok dengan jinom-res-12), sementara pppd yang di-spawn
// xl2tpd umumnya tidak memuat username di argv sehingga pola itu justru tidak
// pernah cocok. Menghapus interface di dalam namespace bersifat terbatas pada
// namespace tersebut dan membuat pppd keluar karena hangup.
func (s *L2TPService) disconnectSessions(ns string) {
	if !s.nsSvc.Exists(ns) {
		return
	}
	for _, ifName := range s.findPPPInterfaces(ns) {
		if _, err := s.nsSvc.ExecInNS(ns, "ip", "link", "del", ifName); err != nil {
			s.log.Warn("Failed to remove ppp interface during teardown",
				zap.String("namespace", ns), zap.String("interface", ifName), zap.Error(err))
		}
	}
}
