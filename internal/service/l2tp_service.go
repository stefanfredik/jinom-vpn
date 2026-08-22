package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

type L2TPService struct {
	nsSvc       *NamespaceService
	log         *zap.Logger
	vpsPublicIP string
}

func NewL2TPService(nsSvc *NamespaceService, vpsPublicIP string, log *zap.Logger) *L2TPService {
	svc := &L2TPService{nsSvc: nsSvc, vpsPublicIP: vpsPublicIP, log: log}
	svc.initGlobalDaemons()
	svc.installIPUpScript()
	return svc
}

func (s *L2TPService) Setup(t *tunnel.ResellerTunnel) (err error) {
	s.log.Info("Setting up L2TP/IPSec tunnel (Global Mode)",
		zap.String("namespace", t.Namespace),
		zap.String("tunnel", t.Name),
	)

	_, _, nsIPNoMask, _ := indexToVethIPs(t.TunnelIndex)
	s.cleanupRouting(stripPort(t.RouterIP), nsIPNoMask, t.TunnelIndex, t.ClientIPAddress)
	vethHost := fmt.Sprintf("vh-%d", t.TunnelIndex)
	_ = exec.Command("ip", "link", "del", vethHost).Run()

	if err := s.updateChapSecrets(t); err != nil {
		return fmt.Errorf("update chap secrets: %w", err)
	}

	routesPath := filepath.Join("/etc/ppp", fmt.Sprintf("routes.%s", t.Namespace))
	routesData := strings.Join(effectiveSubnets(t.MonitoringSubnets), "\n") + "\n"
	if err := os.WriteFile(routesPath, []byte(routesData), 0600); err != nil {
		return fmt.Errorf("write routes file: %w", err)
	}

	if err := s.setupVeth(t); err != nil {
		s.log.Error("Failed to setup veth for namespace", zap.Error(err))
		return fmt.Errorf("setup veth: %w", err)
	}

	return nil
}

func (s *L2TPService) ReloadRoutes(t *tunnel.ResellerTunnel, oldSubnets []string) error {
	routesPath := filepath.Join("/etc/ppp", fmt.Sprintf("routes.%s", t.Namespace))
	routesData := strings.Join(effectiveSubnets(t.MonitoringSubnets), "\n") + "\n"
	if err := os.WriteFile(routesPath, []byte(routesData), 0600); err != nil {
		return fmt.Errorf("write routes file: %w", err)
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
		if _, err := s.nsSvc.ExecInNS(t.Namespace, "ip", "route", "add", subnet, "dev", ifName); err != nil {
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

	_ = s.removeChapSecrets(t.Namespace)
	_ = os.Remove(filepath.Join("/etc/ppp", fmt.Sprintf("routes.%s", t.Namespace)))

	_, _, nsIPNoMask, _ := indexToVethIPs(t.TunnelIndex)
	s.cleanupRouting(stripPort(t.RouterIP), nsIPNoMask, t.TunnelIndex, t.ClientIPAddress)
	vethHost := fmt.Sprintf("vh-%d", t.TunnelIndex)
	_ = exec.Command("ip", "link", "del", vethHost).Run()

	_ = exec.Command("pkill", "-f", fmt.Sprintf("pppd.*%s", t.L2TPUsername)).Run()

	return nil
}

func (s *L2TPService) IPSecStatusall(_ string) ([]byte, error) {
	return []byte("Security Associations (0 up, 0 connecting)"), nil
}
