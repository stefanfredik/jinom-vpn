package service

import (
	"fmt"

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
	commands := []mikrotik.Command{
		{
			Path: "/interface/wireguard/add",
			Params: map[string]string{
				"name":        "wg-jinom",
				"listen-port": "13231",
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
			},
		},
		{
			Path: "/ip/address/add",
			Params: map[string]string{
				"address":   t.ClientIPAddress,
				"interface": "l2tp-jinom",
			},
		},
		{
			Path: "/ip/route/add",
			Params: map[string]string{
				"dst-address": "10.250.0.0/16",
				"gateway":     "l2tp-jinom",
				"comment":     "jinom-nms",
			},
		},
	}

	for _, cmd := range commands {
		if err := c.RunCommand(cmd); err != nil {
			return fmt.Errorf("provision l2tp cmd %s: %w", cmd.Path, err)
		}
	}
	return nil
}
