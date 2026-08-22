package service

import (
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
	"github.com/jinom/vpn/pkg/mikrotik"
)

func (s *ProvisionerService) provisionL2TP(c *mikrotik.Client, t *tunnel.ResellerTunnel, vpsIP string) error {
	if t.L2TPUsername == "" || t.L2TPPassword == "" || t.PSK == "" {
		return fmt.Errorf("incomplete L2TP configuration: username=%q, password=%q, psk=%q",
			t.L2TPUsername, t.L2TPPassword, t.PSK)
	}

	s.log.Info("L2TP provisioning parameters",
		zap.String("username", t.L2TPUsername),
		zap.String("vps_ip", vpsIP),
		zap.Int("psk_len", len(t.PSK)),
	)

	// Clean up existing L2TP client interface
	res, err := c.Run("/interface/l2tp-client/print", map[string]string{"?name": "l2tp-jinom"})
	if err == nil && len(res) > 0 {
		interfaceID := res[0][".id"]
		_ = c.RunCommand(mikrotik.Command{
			Path:   "/interface/l2tp-client/set",
			Params: map[string]string{".id": interfaceID, "disabled": "yes"},
		})
		time.Sleep(2 * time.Second)
		if removeErr := c.RunCommand(mikrotik.Command{
			Path:   "/interface/l2tp-client/remove",
			Params: map[string]string{".id": interfaceID},
		}); removeErr != nil {
			return fmt.Errorf("cleanup l2tp interface: %w", removeErr)
		}
		time.Sleep(1 * time.Second)
	}

	// Clean up existing IP address, route, NAT, and filters
	resIp, err := c.Run("/ip/address/print", map[string]string{"?interface": "l2tp-jinom"})
	if err == nil && len(resIp) > 0 {
		_ = c.RunCommand(mikrotik.Command{
			Path:   "/ip/address/remove",
			Params: map[string]string{".id": resIp[0][".id"]},
		})
	}

	resRoute, err := c.Run("/ip/route/print", map[string]string{"?comment": "jinom-nms"})
	if err == nil && len(resRoute) > 0 {
		_ = c.RunCommand(mikrotik.Command{
			Path:   "/ip/route/remove",
			Params: map[string]string{".id": resRoute[0][".id"]},
		})
	}

	s.removeNATByComment(c, "JINOM NMS")
	s.removeFilterByComment(c, "JINOM VPN")
	s.removeFilterByComment(c, "JINOM VPN ICMP")

	commands := []mikrotik.Command{
		{
			Path: "/ip/firewall/filter/add",
			Params: map[string]string{
				"chain":        "input",
				"action":       "accept",
				"protocol":     "udp",
				"port":         "500,4500,1701",
				"src-address":  vpsIP,
				"comment":      "JINOM VPN",
				"place-before": "0",
			},
		},
		{
			Path: "/ip/firewall/filter/add",
			Params: map[string]string{
				"chain":        "input",
				"action":       "accept",
				"protocol":     "icmp",
				"src-address":  "10.250.0.0/16",
				"comment":      "JINOM VPN ICMP",
				"place-before": "0",
			},
		},
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
			s.log.Error("Failed to configure MikroTik L2TP",
				zap.String("path", cmd.Path),
				zap.Error(err),
				zap.Any("params", redactParams(cmd.Params)),
			)
			return fmt.Errorf("provision l2tp cmd %s: %w", cmd.Path, err)
		}
	}

	time.Sleep(2 * time.Second)

	verifyRes, verifyErr := c.Run("/interface/l2tp-client/print", map[string]string{"?name": "l2tp-jinom"})
	if verifyErr != nil || len(verifyRes) == 0 {
		return fmt.Errorf("l2tp interface creation verification failed: %w", verifyErr)
	}

	_ = c.RunCommand(mikrotik.Command{
		Path: "/ip/route/add",
		Params: map[string]string{
			"dst-address": "10.250.0.0/16",
			"gateway":     "l2tp-jinom",
			"comment":     "jinom-nms",
		},
	})

	_ = c.RunCommand(mikrotik.Command{
		Path: "/ip/firewall/nat/add",
		Params: map[string]string{
			"chain":       "srcnat",
			"action":      "masquerade",
			"src-address": "10.250.0.0/16",
			"comment":     "JINOM NMS",
		},
	})

	return nil
}
