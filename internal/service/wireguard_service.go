package service

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/crypto/curve25519"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

type WireGuardService struct {
	nsSvc     *NamespaceService
	configDir string
	log       *zap.Logger
}

func NewWireGuardService(nsSvc *NamespaceService, log *zap.Logger) *WireGuardService {
	return &WireGuardService{
		nsSvc:     nsSvc,
		configDir: "/etc/wireguard",
		log:       log,
	}
}

func (s *WireGuardService) GenerateKeyPair() (privateKey, publicKey string, err error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", fmt.Errorf("generate random key: %w", err)
	}

	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	privateKey = base64.StdEncoding.EncodeToString(priv[:])
	publicKey = base64.StdEncoding.EncodeToString(pub[:])
	return privateKey, publicKey, nil
}

func (s *WireGuardService) Setup(t *tunnel.ResellerTunnel) error {
	ns := t.Namespace
	ifName := fmt.Sprintf("wg-%s", ns)

	s.log.Info("Setting up WireGuard interface",
		zap.String("namespace", ns),
		zap.String("interface", ifName),
	)

	confPath := filepath.Join(s.configDir, fmt.Sprintf("%s.conf", ifName))
	conf := s.generateConfig(t)
	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		return fmt.Errorf("write wireguard config: %w", err)
	}

	if err := run("ip", "link", "add", ifName, "type", "wireguard"); err != nil {
		return fmt.Errorf("create wg interface: %w", err)
	}

	if err := run("ip", "link", "set", ifName, "netns", ns); err != nil {
		return fmt.Errorf("move wg to namespace: %w", err)
	}

	if _, err := s.nsSvc.ExecInNS(ns, "wg", "setconf", ifName, confPath); err != nil {
		return fmt.Errorf("apply wg config: %w", err)
	}

	if _, err := s.nsSvc.ExecInNS(ns, "ip", "addr", "add", t.ServerIPAddress, "dev", ifName); err != nil {
		return fmt.Errorf("assign ip to wg: %w", err)
	}

	if _, err := s.nsSvc.ExecInNS(ns, "ip", "link", "set", ifName, "up"); err != nil {
		return fmt.Errorf("bring up wg: %w", err)
	}

	for _, subnet := range t.MonitoringSubnets {
		if _, err := s.nsSvc.ExecInNS(ns, "ip", "route", "add", subnet, "dev", ifName); err != nil {
			s.log.Warn("Failed to add route for subnet", zap.String("subnet", subnet), zap.Error(err))
		}
	}

	return nil
}

func (s *WireGuardService) Teardown(t *tunnel.ResellerTunnel) error {
	ns := t.Namespace
	ifName := fmt.Sprintf("wg-%s", ns)

	s.log.Info("Tearing down WireGuard interface",
		zap.String("namespace", ns),
		zap.String("interface", ifName),
	)

	if _, err := s.nsSvc.ExecInNS(ns, "ip", "link", "del", ifName); err != nil {
		s.log.Warn("Failed to delete wg interface", zap.Error(err))
	}

	confPath := filepath.Join(s.configDir, fmt.Sprintf("%s.conf", ifName))
	_ = os.Remove(confPath)

	return nil
}

func (s *WireGuardService) generateConfig(t *tunnel.ResellerTunnel) string {
	allowedIPs := "0.0.0.0/0"
	if len(t.MonitoringSubnets) > 0 {
		allowedIPs = strings.Join(t.MonitoringSubnets, ", ")
	}

	return fmt.Sprintf(`[Interface]
ListenPort = %d
PrivateKey = %s

[Peer]
PublicKey = %s
AllowedIPs = %s
`, t.ServerListenPort, t.ServerPrivateKey, t.ClientPublicKey, allowedIPs)
}
