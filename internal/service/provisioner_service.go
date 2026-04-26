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
	s.log.Info("Provisioning MikroTik router",
		zap.String("router_ip", t.RouterIP),
		zap.Int("ros_version", t.RouterOSVersion),
		zap.String("vpn_type", string(t.VPNType)),
	)

	client, err := mikrotik.NewClient(t.RouterIP, t.RouterUsername, t.RouterPassword, t.RouterOSVersion >= 7)
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

	commands := []mikrotik.Command{
		{
			Path: "/interface/wireguard/add",
			Params: map[string]string{
				"name":        "wg-jinom",
				"listen-port": "13231",
				"disabled":    "no",
			},
		},
		{
			Path: "/interface/wireguard/peers/add",
			Params: map[string]string{
				"interface":        "wg-jinom",
				"public-key":       t.ServerPublicKey,
				"endpoint-address": vpsIP,
				"endpoint-port":    fmt.Sprintf("%d", t.ServerListenPort),
				"allowed-address":  "0.0.0.0/0",
				"disabled":         "no",
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
	// Find and remove existing interface
	res, err := c.Run("/interface/l2tp-client/print", map[string]string{"?name": "l2tp-jinom"})
	if err == nil && len(res) > 0 {
		c.Run("/interface/l2tp-client/remove", map[string]string{".id": res[0][".id"]})
	}

	// Find and remove existing route
	resRoute, err := c.Run("/ip/route/print", map[string]string{"?comment": "jinom-nms"})
	if err == nil && len(resRoute) > 0 {
		c.Run("/ip/route/remove", map[string]string{".id": resRoute[0][".id"]})
	}

	// Find and remove existing IP address
	resIp, err := c.Run("/ip/address/print", map[string]string{"?interface": "l2tp-jinom"})
	if err == nil && len(resIp) > 0 {
		c.Run("/ip/address/remove", map[string]string{".id": resIp[0][".id"]})
	}

	commands := []mikrotik.Command{
		{
			Path: "/interface/l2tp-client/add",
			Params: map[string]string{
				"name":         "l2tp-jinom",
				"connect-to":  vpsIP,
				"user":        t.L2TPUsername,
				"password":    t.L2TPPassword,
				"use-ipsec":   "yes",
				"ipsec-secret": t.PSK,
				"disabled":     "no",
			},
		},
	}

	for _, cmd := range commands {
		if err := c.RunCommand(cmd); err != nil {
			return fmt.Errorf("provision l2tp cmd %s: %w", cmd.Path, err)
		}
	}

	// Give Mikrotik time to register the new interface
	time.Sleep(2 * time.Second)

	errRoute := c.RunCommand(mikrotik.Command{
		Path: "/ip/route/add",
		Params: map[string]string{
			"dst-address": "10.250.0.0/16",
			"gateway":     "l2tp-jinom",
			"comment":     "jinom-nms",
		},
	})
	if errRoute != nil {
		s.log.Warn("Failed to add route, but continuing", zap.Error(errRoute))
	}

	return nil
}
