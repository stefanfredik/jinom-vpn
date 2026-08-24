package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

// GenerateRouterOSScript generates a MikroTik RouterOS script for a manual setup
func (s *TunnelService) GenerateRouterOSScript(ctx context.Context, id uuid.UUID) (string, error) {
	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return "", err
	}
	vpsPublicIP := s.vpsPublicIP
	vpnType := strings.ToLower(strings.TrimSpace(string(t.VPNType)))

	if vpnType == string(tunnel.VPNTypeWireGuard) || vpnType == "wg" {
		clientPriv, clientPub, err := s.wgSvc.GenerateKeyPair()
		if err != nil {
			return "", fmt.Errorf("generate wg keys: %w", err)
		}

		t.ClientPublicKey = clientPub
		if err := s.repo.Save(ctx, t); err != nil {
			return "", fmt.Errorf("persist client public key: %w", err)
		}

		if t.IsActive() && s.nsSvc.Exists(t.Namespace) {
			if err := s.wgSvc.AttachPeer(t); err != nil {
				s.log.Warn("Failed to attach new wg peer live for script", zap.Error(err))
			}
		}

		script := fmt.Sprintf(`# JINOM NMS - WireGuard Tunnel Setup
# VPN ID: %s
# Execute this script in your MikroTik terminal (Winbox/WebFig)

/interface wireguard remove [find name="wg-jinom"]
/ip route remove [find comment="jinom-nms"]
/ip firewall nat remove [find comment="JINOM NMS"]
/ip address remove [find interface="wg-jinom"]

/interface wireguard add name="wg-jinom" listen-port="13231" private-key="%s" comment="JINOM VPN" disabled=no
/interface wireguard peers add interface="wg-jinom" public-key="%s" endpoint-address="%s" endpoint-port="%d" allowed-address="0.0.0.0/0" persistent-keepalive="25s" disabled="no"
/ip address add address="%s" interface="wg-jinom"
/ip route add dst-address="10.250.0.0/16" gateway="wg-jinom" comment="jinom-nms"
/ip firewall nat add chain="srcnat" action="masquerade" src-address="10.250.0.0/16" comment="JINOM NMS"
`,
			t.ID, clientPriv, t.ServerPublicKey, vpsPublicIP, t.ServerListenPort, t.ClientIPAddress,
		)
		return script, nil
	}

	if vpnType == string(tunnel.VPNTypeL2TP) {
		psk := s.l2tpSvc.GetPSK()
		if psk == "" {
			psk = t.PSK
		}
		script := fmt.Sprintf(`# JINOM NMS - L2TP/IPSec Tunnel Setup
# VPN ID: %s
# Execute this script in your MikroTik terminal (Winbox/WebFig)

/interface l2tp-client remove [find name="l2tp-jinom"]
/ip address remove [find interface="l2tp-jinom"]
/ip route remove [find comment="jinom-nms"]
/ip firewall nat remove [find comment="JINOM NMS"]
/ip firewall filter remove [find comment="JINOM VPN"]
/ip firewall filter remove [find comment="JINOM VPN ICMP"]

/ip firewall filter add chain="input" action="accept" protocol="udp" port="500,4500,1701" src-address="%s" comment="JINOM VPN" place-before=0
/ip firewall filter add chain="input" action="accept" protocol="icmp" src-address="10.250.0.0/16" comment="JINOM VPN ICMP" place-before=0
/interface l2tp-client add name="l2tp-jinom" connect-to="%s" user="%s" password="%s" use-ipsec="yes" ipsec-secret="%s" comment="JINOM VPN" disabled=no
/ip address add address="%s" interface="l2tp-jinom"
/ip route add dst-address="10.250.0.0/16" gateway="l2tp-jinom" comment="jinom-nms"
/ip firewall nat add chain="srcnat" action="masquerade" src-address="10.250.0.0/16" comment="JINOM NMS"
`,
			t.ID, vpsPublicIP, vpsPublicIP, t.L2TPUsername, t.L2TPPassword, psk, t.ClientIPAddress,
		)
		return script, nil
	}

	return "", fmt.Errorf("unsupported VPN type: %s", t.VPNType)
}
