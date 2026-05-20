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

	// From this point the interface exists; on any error below, roll it back
	// so it doesn't survive as an orphan in the default ns or target ns.
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

	return nil
}

// cleanupStaleInterface removes any pre-existing wg interface with the same
// name, both inside the target namespace and in the host's default namespace.
// A previous Setup that failed mid-flight (after `ip link add` but before
// `ip link set netns`) leaves an orphan in the default ns; subsequent Setups
// hit "RTNETLINK answers: File exists" without this cleanup.
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

	// Without a client public key, wg setconf rejects an empty [Peer] block.
	// Write interface-only config; the peer is attached live by AttachPeer
	// once provisioning collects the MikroTik public key.
	if t.ClientPublicKey == "" {
		return iface
	}

	return iface + fmt.Sprintf("\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", t.ClientPublicKey, peerAllowedIPs(t))
}

// peerAllowedIPs returns the comma-separated AllowedIPs for the WireGuard
// peer. The tunnel's client /32 is always included so return traffic to the
// peer's WG-side address survives even when MonitoringSubnets is overridden
// to ranges that don't cover 10.250.0.0/16.
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

// AttachPeer adds (or replaces) the client peer on a running interface.
// Called by Provision once the MikroTik public key is known so an already-
// active tunnel picks up the peer without a teardown.
func (s *WireGuardService) AttachPeer(t *tunnel.ResellerTunnel) error {
	if t.ClientPublicKey == "" {
		return fmt.Errorf("client public key is empty")
	}
	ns := t.Namespace
	ifName := fmt.Sprintf("wg-%s", ns)
	allowedIPs := strings.ReplaceAll(peerAllowedIPs(t), " ", "")

	if _, err := s.nsSvc.ExecInNS(ns, "wg", "set", ifName,
		"peer", t.ClientPublicKey, "allowed-ips", allowedIPs); err != nil {
		return fmt.Errorf("attach wg peer: %w", err)
	}

	confPath := filepath.Join(s.configDir, fmt.Sprintf("%s.conf", ifName))
	if err := os.WriteFile(confPath, []byte(s.generateConfig(t)), 0600); err != nil {
		s.log.Warn("Failed to refresh wg config on disk", zap.Error(err))
	}
	return nil
}
