package service

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
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

func (s *WireGuardService) Setup(t *tunnel.ResellerTunnel) (err error) {
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

	s.cleanupStaleInterface(ns, ifName)

	if err := run("ip", "link", "add", ifName, "type", "wireguard"); err != nil {
		return fmt.Errorf("create wg interface: %w", err)
	}

	defer func() {
		if err != nil {
			s.log.Warn("Setup failed, rolling back wg interface",
				zap.String("interface", ifName), zap.Error(err))
			s.cleanupStaleInterface(ns, ifName)
		}
	}()

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

	for _, subnet := range effectiveSubnets(t.MonitoringSubnets) {
		if _, err := s.nsSvc.ExecInNS(ns, "ip", "route", "add", subnet, "dev", ifName); err != nil {
			s.log.Warn("Failed to add route for subnet", zap.String("subnet", subnet), zap.Error(err))
		}
	}

	_, _ = s.nsSvc.ExecInNS(ns, "iptables", "-t", "nat", "-D", "POSTROUTING", "-o", ifName, "-j", "MASQUERADE")
	if _, err := s.nsSvc.ExecInNS(ns, "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", ifName, "-j", "MASQUERADE"); err != nil {
		s.log.Warn("Failed to enable masquerade inside namespace", zap.String("ns", ns), zap.Error(err))
	}

	if err := s.setupVeth(t); err != nil {
		s.log.Error("Failed to setup veth for namespace", zap.Error(err))
		return fmt.Errorf("setup veth: %w", err)
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

	s.cleanupStaleInterface(ns, ifName)

	confPath := filepath.Join(s.configDir, fmt.Sprintf("%s.conf", ifName))
	_ = os.Remove(confPath)

	vethHost := fmt.Sprintf("vh-%d", t.TunnelIndex)
	_ = exec.Command("ip", "link", "del", vethHost).Run()

	_ = exec.Command("iptables", "-w", "-t", "filter", "-D", "FORWARD", "-i", vethHost, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-w", "-t", "filter", "-D", "FORWARD", "-o", vethHost, "-j", "ACCEPT").Run()

	return nil
}

func (s *WireGuardService) cleanupStaleInterface(ns, ifName string) {
	if s.nsSvc.Exists(ns) {
		if _, err := s.nsSvc.ExecInNS(ns, "ip", "link", "del", ifName); err != nil {
			s.log.Debug("No stale wg interface in namespace", zap.String("ns", ns), zap.Error(err))
		}
	}
	if err := run("ip", "link", "del", ifName); err != nil {
		s.log.Debug("No stale wg interface in default ns", zap.String("if", ifName), zap.Error(err))
	}
}

func (s *WireGuardService) generateConfig(t *tunnel.ResellerTunnel) string {
	iface := fmt.Sprintf("[Interface]\nListenPort = %d\nPrivateKey = %s\n", t.ServerListenPort, t.ServerPrivateKey)
	if t.ClientPublicKey == "" {
		return iface
	}
	return iface + fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n", t.ClientPublicKey, peerAllowedIPs(t))
}

func peerAllowedIPs(t *tunnel.ResellerTunnel) string {
	subnets := effectiveSubnets(t.MonitoringSubnets)
	clientHost := extractIP(t.ClientIPAddress) + "/32"
	seen := map[string]struct{}{clientHost: {}}
	out := []string{clientHost}
	for _, s := range subnets {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return strings.Join(out, ", ")
}

func (s *WireGuardService) AttachPeer(t *tunnel.ResellerTunnel) error {
	if t.ClientPublicKey == "" {
		return fmt.Errorf("client public key is empty")
	}
	ns := t.Namespace
	ifName := fmt.Sprintf("wg-%s", ns)
	allowedIPs := strings.ReplaceAll(peerAllowedIPs(t), " ", "")

	if _, err := s.nsSvc.ExecInNS(ns, "wg", "set", ifName,
		"peer", t.ClientPublicKey, "allowed-ips", allowedIPs, "persistent-keepalive", "25"); err != nil {
		return fmt.Errorf("attach wg peer: %w", err)
	}

	confPath := filepath.Join(s.configDir, fmt.Sprintf("%s.conf", ifName))
	if err := os.WriteFile(confPath, []byte(s.generateConfig(t)), 0600); err != nil {
		s.log.Warn("Failed to refresh wg config on disk", zap.Error(err))
	}
	return nil
}
