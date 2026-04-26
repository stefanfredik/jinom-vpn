package service

import (
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

type L2TPService struct {
	nsSvc *NamespaceService
	log   *zap.Logger
}

func NewL2TPService(nsSvc *NamespaceService, log *zap.Logger) *L2TPService {
	return &L2TPService{nsSvc: nsSvc, log: log}
}

func (s *L2TPService) Setup(t *tunnel.ResellerTunnel) error {
	s.log.Info("Setting up L2TP/IPSec tunnel",
		zap.String("namespace", t.Namespace),
		zap.String("tunnel", t.Name),
	)

	if err := s.writeIPSecConfig(t); err != nil {
		return fmt.Errorf("write ipsec config: %w", err)
	}

	if err := s.writeXL2TPDConfig(t); err != nil {
		return fmt.Errorf("write xl2tpd config: %w", err)
	}

	if _, err := s.nsSvc.ExecInNS(t.Namespace, "ipsec", "restart"); err != nil {
		return fmt.Errorf("restart ipsec: %w", err)
	}

	if _, err := s.nsSvc.ExecInNS(t.Namespace, "xl2tpd", "-c",
		filepath.Join("/etc/xl2tpd", fmt.Sprintf("%s.conf", t.Namespace))); err != nil {
		return fmt.Errorf("start xl2tpd: %w", err)
	}

	return nil
}

func (s *L2TPService) Teardown(t *tunnel.ResellerTunnel) error {
	s.log.Info("Tearing down L2TP/IPSec tunnel",
		zap.String("namespace", t.Namespace),
	)

	_, _ = s.nsSvc.ExecInNS(t.Namespace, "ipsec", "stop")

	connName := fmt.Sprintf("jinom-%s", t.Namespace)
	_ = os.Remove(filepath.Join("/etc/ipsec.d", connName+".conf"))
	_ = os.Remove(filepath.Join("/etc/ipsec.d", connName+".secrets"))
	_ = os.Remove(filepath.Join("/etc/xl2tpd", t.Namespace+".conf"))

	return nil
}

func (s *L2TPService) writeIPSecConfig(t *tunnel.ResellerTunnel) error {
	connName := fmt.Sprintf("jinom-%s", t.Namespace)

	conf := fmt.Sprintf(`conn %s
    authby=secret
    auto=start
    type=transport
    left=%%defaultroute
    leftprotoport=17/1701
    right=%%any
    rightprotoport=17/1701
    ike=aes256-sha1-modp1024
    esp=aes256-sha1
`, connName)

	confPath := filepath.Join("/etc/ipsec.d", connName+".conf")
	if err := os.MkdirAll("/etc/ipsec.d", 0755); err != nil {
		return err
	}
	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		return err
	}

	secrets := fmt.Sprintf(`%%any %%any : PSK "%s"
`, t.PSK)

	secretsPath := filepath.Join("/etc/ipsec.d", connName+".secrets")
	return os.WriteFile(secretsPath, []byte(secrets), 0600)
}

func (s *L2TPService) writeXL2TPDConfig(t *tunnel.ResellerTunnel) error {
	conf := fmt.Sprintf(`[global]
port = 1701

[lns %s]
ip range = %s
local ip = %s
require chap = yes
refuse pap = yes
require authentication = yes
name = jinom-vpn
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
`, t.Namespace, t.ClientIPAddress, t.ServerIPAddress)

	if err := os.MkdirAll("/etc/xl2tpd", 0755); err != nil {
		return err
	}
	confPath := filepath.Join("/etc/xl2tpd", t.Namespace+".conf")
	return os.WriteFile(confPath, []byte(conf), 0600)
}
