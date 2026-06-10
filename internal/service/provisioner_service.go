package service

import (
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
	"github.com/jinom/vpn/pkg/mikrotik"
)

type ProvisionerService struct {
	log *zap.Logger
}

func NewProvisionerService(log *zap.Logger) *ProvisionerService {
	return &ProvisionerService{log: log}
}

func (s *ProvisionerService) Provision(t *tunnel.ResellerTunnel, vpsPublicIP string) error {
	// Validate VPS IP address
	if vpsPublicIP == "" || vpsPublicIP == "0.0.0.0" || vpsPublicIP == "127.0.0.1" {
		return fmt.Errorf("invalid VPS public IP: %q - must set VPS_PUBLIC_IP environment variable to a valid public IP address", vpsPublicIP)
	}

	if t.VPNType == tunnel.VPNTypeL2TP && t.PSK == "" {
		return fmt.Errorf("tunnel PSK not set - cannot provision without IPSec pre-shared key")
	}

	s.log.Info("Provisioning MikroTik router",
		zap.String("router_ip", t.RouterIP),
		zap.Int("api_port", t.EffectiveAPIPort()),
		zap.Int("ros_version", t.RouterOSVersion),
		zap.String("vpn_type", string(t.VPNType)),
		zap.String("vps_public_ip", vpsPublicIP),
	)

	client, err := mikrotik.NewClient(t.RouterIP, t.EffectiveAPIPort(), t.RouterUsername, t.RouterPassword, t.RouterOSVersion >= 7)
	if err != nil {
		return fmt.Errorf("connect to mikrotik: %w", err)
	}
	defer client.Close()

	if t.VPNType == tunnel.VPNTypeWireGuard {
		return s.provisionWireGuard(client, t, vpsPublicIP)
	}
	return s.provisionL2TP(client, t, vpsPublicIP)
}

func (s *ProvisionerService) provisionWireGuard(c *mikrotik.Client, t *tunnel.ResellerTunnel, vpsIP string) error {
	// Find and remove existing interface
	res, err := c.Run("/interface/wireguard/print", map[string]string{"?name": "wg-jinom"})
	if err == nil && len(res) > 0 {
		c.Run("/interface/wireguard/remove", map[string]string{".id": res[0][".id"]})
	}

	// Find and remove existing route
	resRoute, err := c.Run("/ip/route/print", map[string]string{"?comment": "jinom-nms"})
	if err == nil && len(resRoute) > 0 {
		c.Run("/ip/route/remove", map[string]string{".id": resRoute[0][".id"]})
	}

	// Find and remove existing IP address
	resIp, err := c.Run("/ip/address/print", map[string]string{"?interface": "wg-jinom"})
	if err == nil && len(resIp) > 0 {
		c.Run("/ip/address/remove", map[string]string{".id": resIp[0][".id"]})
	}

	if err := c.RunCommand(mikrotik.Command{
		Path: "/interface/wireguard/add",
		Params: map[string]string{
			"name":        "wg-jinom",
			"listen-port": "13231",
			"comment":     "JINOM VPN",
			"disabled":    "no",
		},
	}); err != nil {
		return fmt.Errorf("provision wireguard cmd /interface/wireguard/add: %w", err)
	}

	wgRes, err := c.Run("/interface/wireguard/print", map[string]string{"?name": "wg-jinom"})
	if err != nil || len(wgRes) == 0 {
		return fmt.Errorf("read wg-jinom public-key from mikrotik: %w", err)
	}
	clientPubKey := wgRes[0]["public-key"]
	if clientPubKey == "" {
		return fmt.Errorf("mikrotik returned empty public-key for wg-jinom (router fields: %v)", wgRes[0])
	}
	t.ClientPublicKey = clientPubKey
	s.log.Info("Captured WireGuard client public key from MikroTik",
		zap.String("client_public_key", clientPubKey),
	)

	commands := []mikrotik.Command{
		{
			Path: "/interface/wireguard/peers/add",
			Params: map[string]string{
				"interface":           "wg-jinom",
				"public-key":          t.ServerPublicKey,
				"endpoint-address":    vpsIP,
				"endpoint-port":       fmt.Sprintf("%d", t.ServerListenPort),
				"allowed-address":     "0.0.0.0/0",
				"persistent-keepalive": "25s",
				"disabled":            "no",
			},
		},
		{
			Path: "/ip/address/add",
			Params: map[string]string{
				"address":   t.ClientIPAddress,
				"interface": "wg-jinom",
			},
		},
		{
			Path: "/ip/route/add",
			Params: map[string]string{
				"dst-address": "10.250.0.0/16",
				"gateway":     "wg-jinom",
				"comment":     "jinom-nms",
			},
		},
	}

	for _, cmd := range commands {
		if err := c.RunCommand(cmd); err != nil {
			return fmt.Errorf("provision wireguard cmd %s: %w", cmd.Path, err)
		}
	}
	return nil
}

func (s *ProvisionerService) provisionL2TP(c *mikrotik.Client, t *tunnel.ResellerTunnel, vpsIP string) error {
	// Validate L2TP credentials
	if t.L2TPUsername == "" || t.L2TPPassword == "" || t.PSK == "" {
		return fmt.Errorf("incomplete L2TP configuration: username=%q, password=%q, psk=%q",
			t.L2TPUsername, t.L2TPPassword, t.PSK)
	}

	// Never log PSK material (even a prefix). t.PSK[:8] would also panic for a
	// short legacy PSK. Log only its length for debugging.
	s.log.Info("L2TP provisioning parameters",
		zap.String("username", t.L2TPUsername),
		zap.String("vps_ip", vpsIP),
		zap.Int("psk_len", len(t.PSK)),
	)

	// Find and remove existing interface - MUST disable first to allow proper cleanup
	res, err := c.Run("/interface/l2tp-client/print", map[string]string{"?name": "l2tp-jinom"})
	if err == nil && len(res) > 0 {
		interfaceID := res[0][".id"]
		s.log.Info("Found existing L2TP interface, disabling first", zap.String("id", interfaceID))

		// First disable the interface to allow tunnel to close properly
		if disableErr := c.RunCommand(mikrotik.Command{
			Path:   "/interface/l2tp-client/set",
			Params: map[string]string{".id": interfaceID, "disabled": "yes"},
		}); disableErr != nil {
			s.log.Warn("Failed to disable L2TP interface", zap.Error(disableErr))
		}

		// Wait for tunnel to terminate gracefully
		s.log.Info("Waiting for tunnel termination...")
		time.Sleep(2 * time.Second)

		// Now remove the interface
		if removeErr := c.RunCommand(mikrotik.Command{
			Path:   "/interface/l2tp-client/remove",
			Params: map[string]string{".id": interfaceID},
		}); removeErr != nil {
			s.log.Error("Failed to remove existing L2TP interface", zap.Error(removeErr))
			return fmt.Errorf("cleanup l2tp interface: %w", removeErr)
		}
		s.log.Info("Old L2TP interface removed successfully")
		time.Sleep(1 * time.Second)
	}

	// Find and remove existing IP address
	resIp, err := c.Run("/ip/address/print", map[string]string{"?interface": "l2tp-jinom"})
	if err == nil && len(resIp) > 0 {
		s.log.Info("Removing existing L2TP IP address")
		if removeErr := c.RunCommand(mikrotik.Command{
			Path:   "/ip/address/remove",
			Params: map[string]string{".id": resIp[0][".id"]},
		}); removeErr != nil {
			s.log.Warn("Failed to remove existing L2TP IP", zap.Error(removeErr))
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Find and remove existing route
	resRoute, err := c.Run("/ip/route/print", map[string]string{"?comment": "jinom-nms"})
	if err == nil && len(resRoute) > 0 {
		s.log.Info("Removing existing route")
		if removeErr := c.RunCommand(mikrotik.Command{
			Path:   "/ip/route/remove",
			Params: map[string]string{".id": resRoute[0][".id"]},
		}); removeErr != nil {
			s.log.Warn("Failed to remove existing route", zap.Error(removeErr))
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Create L2TP client interface
	commands := []mikrotik.Command{
		{
			Path: "/interface/l2tp-client/add",
			Params: map[string]string{
				"name":         "l2tp-jinom",
				"connect-to":   vpsIP,
				"user":         t.L2TPUsername,
				"password":     t.L2TPPassword,
				"use-ipsec":    "yes",
				"ipsec-secret": t.PSK,
				"comment":      "JINOM VPN",
				"disabled":     "no",
			},
		},
	}

	for _, cmd := range commands {
		if err := c.RunCommand(cmd); err != nil {
			s.log.Error("Failed to create L2TP interface",
				zap.String("path", cmd.Path),
				zap.Error(err),
				zap.Any("params", redactParams(cmd.Params)),
			)
			return fmt.Errorf("provision l2tp cmd %s: %w", cmd.Path, err)
		}
	}

	// Give Mikrotik time to register the new interface
	time.Sleep(2 * time.Second)

	// Verify that the interface was created successfully
	verifyRes, verifyErr := c.Run("/interface/l2tp-client/print", map[string]string{"?name": "l2tp-jinom"})
	if verifyErr != nil || len(verifyRes) == 0 {
		s.log.Error("L2TP interface not found after creation",
			zap.Error(verifyErr),
			zap.Int("result_count", len(verifyRes)),
		)
		return fmt.Errorf("l2tp interface creation verification failed: %w", verifyErr)
	}

	s.log.Info("L2TP interface created successfully",
		zap.Any("interface_status", redactRouterReply(verifyRes[0])),
	)

	// Add route to tunnel
	errRoute := c.RunCommand(mikrotik.Command{
		Path: "/ip/route/add",
		Params: map[string]string{
			"dst-address": "10.250.0.0/16",
			"gateway":     "l2tp-jinom",
			"comment":     "jinom-nms",
		},
	})
	if errRoute != nil {
		s.log.Error("Failed to add route to L2TP interface",
			zap.Error(errRoute),
		)
		// Don't fail on route error - interface is created, route can be added manually
	}

	return nil
}

// Deprovision adalah inverse dari Provision. Connect ke router lalu hapus
// SEMUA artefak yang pernah kami pasang: interface wg-jinom/l2tp-jinom,
// /ip/address terkait, dan route comment "jinom-nms".
//
// Bersifat best-effort:
//   - Setiap step diperiksa terpisah; satu kegagalan tidak menghentikan
//     yang lain.
//   - Kalau router tidak bisa di-dial sama sekali kami return error supaya
//     caller bisa memutuskan (biasanya tetap hapus DB tapi log warn).
//   - Jangan return error untuk artefak yang memang tidak ada — itu kondisi
//     bersih, bukan kegagalan.
func (s *ProvisionerService) Deprovision(t *tunnel.ResellerTunnel) error {
	if t.RouterIP == "" {
		return fmt.Errorf("router_ip empty, cannot deprovision")
	}

	s.log.Info("Deprovisioning MikroTik router",
		zap.String("router_ip", t.RouterIP),
		zap.Int("api_port", t.EffectiveAPIPort()),
		zap.String("vpn_type", string(t.VPNType)),
	)

	client, err := mikrotik.NewClient(t.RouterIP, t.EffectiveAPIPort(), t.RouterUsername, t.RouterPassword, t.RouterOSVersion >= 7)
	if err != nil {
		return fmt.Errorf("connect to mikrotik: %w", err)
	}
	defer client.Close()

	switch t.VPNType {
	case tunnel.VPNTypeWireGuard:
		s.deprovisionWireGuard(client)
	case tunnel.VPNTypeL2TP:
		s.deprovisionL2TP(client)
	}
	return nil
}

// deprovisionWireGuard menghapus wg-jinom + IP + route + peer.
// Urutan: peer dulu (anak), baru interface (induk), supaya RouterOS tidak
// menolak penghapusan interface karena peer masih merujuk.
func (s *ProvisionerService) deprovisionWireGuard(c *mikrotik.Client) {
	// Peer entries: cari semua yang punya interface=wg-jinom (jumlah tidak
	// pasti — kalau ada residu dari Provision sebelumnya, semua dihapus).
	if peers, err := c.Run("/interface/wireguard/peers/print", map[string]string{"?interface": "wg-jinom"}); err == nil {
		for _, p := range peers {
			if id := p[".id"]; id != "" {
				if err := c.RunCommand(mikrotik.Command{
					Path:   "/interface/wireguard/peers/remove",
					Params: map[string]string{".id": id},
				}); err != nil {
					s.log.Warn("Deprovision: remove wireguard peer failed",
						zap.String("id", id), zap.Error(err))
				}
			}
		}
	}

	s.removeAddressOnInterface(c, "wg-jinom")
	s.removeRouteByComment(c, "jinom-nms")

	if res, err := c.Run("/interface/wireguard/print", map[string]string{"?name": "wg-jinom"}); err == nil && len(res) > 0 {
		if err := c.RunCommand(mikrotik.Command{
			Path:   "/interface/wireguard/remove",
			Params: map[string]string{".id": res[0][".id"]},
		}); err != nil {
			s.log.Warn("Deprovision: remove wireguard interface failed", zap.Error(err))
		}
	}
}

// deprovisionL2TP menghapus l2tp-jinom + IP + route. Tidak ada peer tabel
// terpisah seperti WireGuard — credential ada di interface itu sendiri,
// jadi cukup hapus interface-nya.
func (s *ProvisionerService) deprovisionL2TP(c *mikrotik.Client) {
	s.removeAddressOnInterface(c, "l2tp-jinom")
	s.removeRouteByComment(c, "jinom-nms")

	if res, err := c.Run("/interface/l2tp-client/print", map[string]string{"?name": "l2tp-jinom"}); err == nil && len(res) > 0 {
		// Disable dulu agar tunnel turun bersih sebelum dihapus, sama
		// seperti yang kami lakukan di provisionL2TP.
		id := res[0][".id"]
		if err := c.RunCommand(mikrotik.Command{
			Path:   "/interface/l2tp-client/set",
			Params: map[string]string{".id": id, "disabled": "yes"},
		}); err != nil {
			s.log.Warn("Deprovision: disable l2tp-client failed", zap.Error(err))
		}
		if err := c.RunCommand(mikrotik.Command{
			Path:   "/interface/l2tp-client/remove",
			Params: map[string]string{".id": id},
		}); err != nil {
			s.log.Warn("Deprovision: remove l2tp-client failed", zap.Error(err))
		}
	}
}

// removeAddressOnInterface menghapus semua /ip/address dengan interface
// tertentu. Pengirim diharapkan memanggilnya HANYA untuk interface
// jinom-managed (wg-jinom / l2tp-jinom), bukan untuk interface umum.
func (s *ProvisionerService) removeAddressOnInterface(c *mikrotik.Client, iface string) {
	addrs, err := c.Run("/ip/address/print", map[string]string{"?interface": iface})
	if err != nil {
		return
	}
	for _, a := range addrs {
		if id := a[".id"]; id != "" {
			if err := c.RunCommand(mikrotik.Command{
				Path:   "/ip/address/remove",
				Params: map[string]string{".id": id},
			}); err != nil {
				s.log.Warn("Deprovision: remove ip address failed",
					zap.String("interface", iface), zap.String("id", id), zap.Error(err))
			}
		}
	}
}

// removeRouteByComment menghapus semua /ip/route dengan comment tertentu.
// Kami pakai comment "jinom-nms" sebagai marker eksklusif, jadi aman
// menghapus semua match-nya.
func (s *ProvisionerService) removeRouteByComment(c *mikrotik.Client, comment string) {
	routes, err := c.Run("/ip/route/print", map[string]string{"?comment": comment})
	if err != nil {
		return
	}
	for _, r := range routes {
		if id := r[".id"]; id != "" {
			if err := c.RunCommand(mikrotik.Command{
				Path:   "/ip/route/remove",
				Params: map[string]string{".id": id},
			}); err != nil {
				s.log.Warn("Deprovision: remove route failed",
					zap.String("comment", comment), zap.String("id", id), zap.Error(err))
			}
		}
	}
}

// sensitiveParamKeys lists MikroTik command parameter names whose values must
// be masked when logged. The set covers L2TP/IPSec PSK & passwords plus any
// WireGuard key material that might appear in command params.
var sensitiveParamKeys = map[string]struct{}{
	"password":      {},
	"ipsec-secret":  {},
	"psk":           {},
	"private-key":   {},
	"preshared-key": {},
	"secret":        {},
	"user":          {}, // usernames are also identifying, redact to be safe
}

// redactParams returns a copy of params with sensitive values replaced by "***".
// Use this before any zap log that includes raw RouterOS command parameters.
func redactParams(params map[string]string) map[string]string {
	out := make(map[string]string, len(params))
	for k, v := range params {
		if _, sensitive := sensitiveParamKeys[k]; sensitive && v != "" {
			out[k] = "***"
		} else {
			out[k] = v
		}
	}
	return out
}

// redactRouterReply masks sensitive fields in a RouterOS reply row map
// (e.g. `/interface/wireguard/print` returns private-key in cleartext).
func redactRouterReply(row map[string]string) map[string]string {
	return redactParams(row)
}
