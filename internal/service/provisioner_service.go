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

	// Validate tunnel has credentials before provisioning
	if t.PSK == "" {
		return fmt.Errorf("tunnel PSK not set - cannot provision without IPSec pre-shared key")
	}

	s.log.Info("Provisioning MikroTik router",
		zap.String("router_ip", t.RouterIP),
		zap.Int("ros_version", t.RouterOSVersion),
		zap.String("vpn_type", string(t.VPNType)),
		zap.String("vps_public_ip", vpsPublicIP),
		zap.String("psk_configured", "yes"),
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
	// Validate L2TP credentials
	if t.L2TPUsername == "" || t.L2TPPassword == "" || t.PSK == "" {
		return fmt.Errorf("incomplete L2TP configuration: username=%q, password=%q, psk=%q",
			t.L2TPUsername, t.L2TPPassword, t.PSK)
	}

	s.log.Info("L2TP provisioning parameters",
		zap.String("username", t.L2TPUsername),
		zap.String("vps_ip", vpsIP),
		zap.String("psk_first_chars", t.PSK[:8]+"***"),
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
				"disabled":     "no",
			},
		},
	}

	for _, cmd := range commands {
		if err := c.RunCommand(cmd); err != nil {
			s.log.Error("Failed to create L2TP interface",
				zap.String("path", cmd.Path),
				zap.Error(err),
				zap.Any("params", cmd.Params),
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
		zap.Any("interface_status", verifyRes[0]),
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
