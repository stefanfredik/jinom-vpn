package service

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
	"github.com/jinom/vpn/pkg/mikrotik"
)

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

func (s *ProvisionerService) deprovisionWireGuard(c *mikrotik.Client) {
	if peers, err := c.Run("/interface/wireguard/peers/print", map[string]string{"?interface": "wg-jinom"}); err == nil {
		for _, p := range peers {
			if id := p[".id"]; id != "" {
				_ = c.RunCommand(mikrotik.Command{
					Path:   "/interface/wireguard/peers/remove",
					Params: map[string]string{".id": id},
				})
			}
		}
	}

	s.removeAddressOnInterface(c, "wg-jinom")
	s.removeRouteByComment(c, "jinom-nms")
	s.removeNATByComment(c, "JINOM NMS")

	if res, err := c.Run("/interface/wireguard/print", map[string]string{"?name": "wg-jinom"}); err == nil && len(res) > 0 {
		_ = c.RunCommand(mikrotik.Command{
			Path:   "/interface/wireguard/remove",
			Params: map[string]string{".id": res[0][".id"]},
		})
	}
}

func (s *ProvisionerService) deprovisionL2TP(c *mikrotik.Client) {
	s.removeAddressOnInterface(c, "l2tp-jinom")
	s.removeRouteByComment(c, "jinom-nms")
	s.removeNATByComment(c, "JINOM NMS")
	s.removeFilterByComment(c, "JINOM VPN")
	s.removeFilterByComment(c, "JINOM VPN ICMP")

	if res, err := c.Run("/interface/l2tp-client/print", map[string]string{"?name": "l2tp-jinom"}); err == nil && len(res) > 0 {
		id := res[0][".id"]
		_ = c.RunCommand(mikrotik.Command{
			Path:   "/interface/l2tp-client/set",
			Params: map[string]string{".id": id, "disabled": "yes"},
		})
		_ = c.RunCommand(mikrotik.Command{
			Path:   "/interface/l2tp-client/remove",
			Params: map[string]string{".id": id},
		})
	}
}

func (s *ProvisionerService) removeAddressOnInterface(c *mikrotik.Client, iface string) {
	addrs, err := c.Run("/ip/address/print", map[string]string{"?interface": iface})
	if err != nil {
		return
	}
	for _, a := range addrs {
		if id := a[".id"]; id != "" {
			_ = c.RunCommand(mikrotik.Command{
				Path:   "/ip/address/remove",
				Params: map[string]string{".id": id},
			})
		}
	}
}

func (s *ProvisionerService) removeNATByComment(c *mikrotik.Client, comment string) {
	rules, err := c.Run("/ip/firewall/nat/print", map[string]string{"?comment": comment})
	if err != nil {
		return
	}
	for _, r := range rules {
		if id := r[".id"]; id != "" {
			_ = c.RunCommand(mikrotik.Command{
				Path:   "/ip/firewall/nat/remove",
				Params: map[string]string{".id": id},
			})
		}
	}
}

func (s *ProvisionerService) removeRouteByComment(c *mikrotik.Client, comment string) {
	routes, err := c.Run("/ip/route/print", map[string]string{"?comment": comment})
	if err != nil {
		return
	}
	for _, r := range routes {
		if id := r[".id"]; id != "" {
			_ = c.RunCommand(mikrotik.Command{
				Path:   "/ip/route/remove",
				Params: map[string]string{".id": id},
			})
		}
	}
}

func (s *ProvisionerService) removeFilterByComment(c *mikrotik.Client, comment string) {
	rules, err := c.Run("/ip/firewall/filter/print", map[string]string{"?comment": comment})
	if err != nil {
		return
	}
	for _, r := range rules {
		if id := r[".id"]; id != "" {
			_ = c.RunCommand(mikrotik.Command{
				Path:   "/ip/firewall/filter/remove",
				Params: map[string]string{".id": id},
			})
		}
	}
}
