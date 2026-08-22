package service

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
	"github.com/jinom/vpn/pkg/mikrotik"
)

func (s *ProvisionerService) provisionWireGuard(c *mikrotik.Client, t *tunnel.ResellerTunnel, vpsIP string) error {
	// Find and remove existing interface
	res, err := c.Run("/interface/wireguard/print", map[string]string{"?name": "wg-jinom"})
	if err == nil && len(res) > 0 {
		_, _ = c.Run("/interface/wireguard/remove", map[string]string{".id": res[0][".id"]})
	}

	// Find and remove existing route
	resRoute, err := c.Run("/ip/route/print", map[string]string{"?comment": "jinom-nms"})
	if err == nil && len(resRoute) > 0 {
		_, _ = c.Run("/ip/route/remove", map[string]string{".id": resRoute[0][".id"]})
	}

	// Find and remove existing NAT rule
	s.removeNATByComment(c, "JINOM NMS")

	// Find and remove existing IP address
	resIp, err := c.Run("/ip/address/print", map[string]string{"?interface": "wg-jinom"})
	if err == nil && len(resIp) > 0 {
		_, _ = c.Run("/ip/address/remove", map[string]string{".id": resIp[0][".id"]})
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
				"interface":            "wg-jinom",
				"public-key":           t.ServerPublicKey,
				"endpoint-address":     vpsIP,
				"endpoint-port":        fmt.Sprintf("%d", t.ServerListenPort),
				"allowed-address":      "0.0.0.0/0",
				"persistent-keepalive": "25s",
				"disabled":             "no",
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
		{
			Path: "/ip/firewall/nat/add",
			Params: map[string]string{
				"chain":       "srcnat",
				"action":      "masquerade",
				"src-address": "10.250.0.0/16",
				"comment":     "JINOM NMS",
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
