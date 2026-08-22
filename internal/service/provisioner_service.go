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
	if vpsPublicIP == "" || vpsPublicIP == "0.0.0.0" || vpsPublicIP == "127.0.0.1" {
		return fmt.Errorf("invalid VPS public IP: %q - set VPS_PUBLIC_IP in environment", vpsPublicIP)
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

var sensitiveParamKeys = map[string]struct{}{
	"password":      {},
	"ipsec-secret":  {},
	"psk":           {},
	"private-key":   {},
	"preshared-key": {},
	"secret":        {},
	"user":          {},
}

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
