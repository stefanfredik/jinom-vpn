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

	// Enable masquerade inside the namespace for WireGuard interface
	// so the reseller's router replies back to the VPS namespace IP
	_, _ = s.nsSvc.ExecInNS(ns, "iptables", "-t", "nat", "-D", "POSTROUTING", "-o", ifName, "-j", "MASQUERADE")
	if _, err := s.nsSvc.ExecInNS(ns, "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", ifName, "-j", "MASQUERADE"); err != nil {
		s.log.Warn("Failed to enable masquerade inside namespace", zap.String("ns", ns), zap.Error(err))
	}

	// Create veth jembatan to namespace for NOC Routing support
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

	// Clean up veth jembatan
	vethHost := fmt.Sprintf("vh-%d", t.TunnelIndex)
	_ = exec.Command("ip", "link", "del", vethHost).Run()

	// Clean up iptables forwarding rules
	_ = exec.Command("iptables", "-w", "-t", "filter", "-D", "FORWARD", "-i", vethHost, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-w", "-t", "filter", "-D", "FORWARD", "-o", vethHost, "-j", "ACCEPT").Run()

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

// ReloadRoutes menerapkan perubahan monitoring subnet ke interface yang SEDANG
// BERJALAN, tanpa teardown.
//
// Sengaja tidak memakai teardown+setup: itu mereset handshake WireGuard, dan
// health monitor menilai kesehatan tunnel dari umur handshake
// (wgHandshakeStaleAfter). Tunnel yang baru di-restart akan tampak "tanpa
// handshake" dan bisa dinilai gagal, yang lalu memakan jatah recoveryCount.
// Reload selektif menghindari keduanya: nol downtime, handshake utuh.
//
// t harus SUDAH memuat daftar subnet yang baru; oldSubnets adalah nilai
// sebelum perubahan (bentuk mentah, sebelum fallback RFC-1918).
//
// Pemanggil wajib memegang setupMu.
func (s *WireGuardService) ReloadRoutes(t *tunnel.ResellerTunnel, oldSubnets []string) error {
	ns := t.Namespace
	ifName := fmt.Sprintf("wg-%s", ns)

	// Diff dihitung atas daftar EFEKTIF, bukan mentah: daftar kosong berarti
	// RFC-1918 terpasang sebagai route nyata. Membandingkan bentuk mentah
	// membuat perubahan []->["10.0.0.0/8"] terlihat sebagai "tambah 10/8"
	// padahal 10/8 sudah terpasang, dan 172.16/12 + 192.168/16 yang seharusnya
	// dicabut malah tertinggal sebagai route yatim.
	added, removed := tunnel.DiffSubnets(
		effectiveSubnets(oldSubnets),
		effectiveSubnets(t.MonitoringSubnets),
	)

	if len(added) == 0 && len(removed) == 0 {
		s.log.Debug("ReloadRoutes: no effective route change",
			zap.String("namespace", ns))
	}

	for _, subnet := range removed {
		if _, err := s.nsSvc.ExecInNS(ns, "ip", "route", "del", subnet, "dev", ifName); err != nil {
			// Route yang memang sudah tidak ada bukan kegagalan — bisa saja
			// hilang karena recovery sebelumnya. Yang penting state akhirnya.
			s.log.Warn("ReloadRoutes: remove route failed (continuing)",
				zap.String("subnet", subnet), zap.Error(err))
		}
	}

	// Berbeda dengan penghapusan, kegagalan memasang route DI-ESKALASI jadi
	// error: subnet yang gagal dipasang berarti device di dalamnya tidak akan
	// terjangkau, sementara UI melaporkan tunnel sehat. Caller me-rollback DB.
	for _, subnet := range added {
		if _, err := s.nsSvc.ExecInNS(ns, "ip", "route", "add", subnet, "dev", ifName); err != nil {
			return fmt.Errorf("add route %s: %w", subnet, err)
		}
	}

	// AllowedIPs adalah filter kripto WireGuard, terpisah dari tabel route
	// kernel: paket ke subnet baru akan di-drop peer meski route-nya ada.
	// Dilewati kalau peer belum ter-provision — Setup/AttachPeer nanti yang
	// memasangnya dari MonitoringSubnets yang sudah tersimpan.
	if t.ClientPublicKey == "" {
		s.log.Info("ReloadRoutes: peer not provisioned yet, skipping AllowedIPs refresh",
			zap.String("namespace", ns))
		return nil
	}

	if err := s.AttachPeer(t); err != nil {
		return fmt.Errorf("refresh allowed-ips: %w", err)
	}

	s.log.Info("ReloadRoutes: applied",
		zap.String("namespace", ns),
		zap.Strings("added", added),
		zap.Strings("removed", removed),
	)
	return nil
}

func (s *WireGuardService) setupVeth(t *tunnel.ResellerTunnel) error {
	hostIP, nsIP, _, _ := indexToVethIPs(t.TunnelIndex)
	vethHost := fmt.Sprintf("vh-%d", t.TunnelIndex)
	vethNS := fmt.Sprintf("vn-%d", t.TunnelIndex)

	// Clean up old ones first
	_ = exec.Command("ip", "link", "del", vethHost).Run()

	// 1. Create veth pair
	if err := exec.Command("ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethNS).Run(); err != nil {
		return fmt.Errorf("create veth: %w", err)
	}

	// 2. Set IP on host end and bring it up
	if err := exec.Command("ip", "addr", "add", hostIP, "dev", vethHost).Run(); err != nil {
		return fmt.Errorf("assign host veth ip: %w", err)
	}
	if err := exec.Command("ip", "link", "set", vethHost, "up").Run(); err != nil {
		return fmt.Errorf("bring up host veth: %w", err)
	}

	// 3. Move peer to namespace
	if err := exec.Command("ip", "link", "set", vethNS, "netns", t.Namespace).Run(); err != nil {
		return fmt.Errorf("move peer to namespace: %w", err)
	}

	// 4. Configure IP inside namespace and bring it up
	if err := exec.Command("ip", "netns", "exec", t.Namespace, "ip", "addr", "add", nsIP, "dev", vethNS).Run(); err != nil {
		return fmt.Errorf("assign ns veth ip: %w", err)
	}
	if err := exec.Command("ip", "netns", "exec", t.Namespace, "ip", "link", "set", vethNS, "up").Run(); err != nil {
		return fmt.Errorf("bring up ns veth: %w", err)
	}

	// 5. Add route to reach the NOC VPN subnet (10.50.0.0/24) via host end of veth
	hostIPNoMask := stripCIDR(hostIP)
	_ = exec.Command("ip", "netns", "exec", t.Namespace, "ip", "route", "add", "10.50.0.0/24", "via", hostIPNoMask, "dev", vethNS).Run()

	// 6. Enable forwarding on the host for this veth subnet
	_ = exec.Command("iptables", "-w", "-t", "filter", "-I", "FORWARD", "-i", vethHost, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-w", "-t", "filter", "-I", "FORWARD", "-o", vethHost, "-j", "ACCEPT").Run()

	return nil
}
