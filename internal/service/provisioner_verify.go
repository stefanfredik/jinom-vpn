package service

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/jinom/vpn/internal/domain/tunnel"
	"github.com/jinom/vpn/pkg/mikrotik"
)

// RouterCheck adalah hasil satu pemeriksaan objek di sisi MikroTik.
type RouterCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// RouterVerification melaporkan kesiapan sebuah router, tanpa mengubah apa pun.
type RouterVerification struct {
	TunnelID  uuid.UUID     `json:"tunnel_id"`
	Namespace string        `json:"namespace"`
	RouterIP  string        `json:"router_ip"`
	Reachable bool          `json:"reachable"`
	OK        bool          `json:"ok"`
	Checks    []RouterCheck `json:"checks"`
}

// VerifyL2TP memeriksa objek MikroTik yang dibutuhkan tunnel L2TP.
//
// Fungsi ini HANYA membaca (/print) — tidak ada add, set, atau remove. Ia tidak
// pernah menyentuh interface l2tp-jinom, sehingga aman dijalankan terhadap
// tunnel produksi yang sedang melayani trafik. Bandingkan dengan Provision,
// yang selalu disable + sleep + remove + add interface, dan karenanya memutus
// sesi setiap kali dipanggil.
//
// Tiga objek pertama layak diperhatikan khusus: selama trafik monitoring keluar
// dengan sumber 10.255.255.1 (mode masquerade lama), ketiganya tidak pernah
// cocok dengan paket apa pun sehingga ketiadaannya tidak terasa. Dalam mode
// SNAT ke 10.250.x.1 ketiganya menjadi penentu — dan pembuatannya dulu
// dilakukan dengan error yang dibuang, jadi sebagian router mungkin memang
// tidak memilikinya.
func (s *ProvisionerService) VerifyL2TP(t *tunnel.ResellerTunnel) (*RouterVerification, error) {
	result := &RouterVerification{
		TunnelID:  t.ID,
		Namespace: t.Namespace,
		RouterIP:  t.RouterIP,
	}

	if t.VPNType != tunnel.VPNTypeL2TP {
		return nil, fmt.Errorf("verify supports l2tp tunnels only, got %q", t.VPNType)
	}

	client, err := mikrotik.NewClient(t.RouterIP, t.EffectiveAPIPort(), t.RouterUsername, t.RouterPassword, t.RouterOSVersion >= 7)
	if err != nil {
		result.Checks = append(result.Checks, RouterCheck{
			Name:   "api-reachable",
			OK:     false,
			Detail: err.Error(),
		})
		return result, nil
	}
	defer client.Close()

	result.Reachable = true
	result.Checks = append(result.Checks, RouterCheck{Name: "api-reachable", OK: true})

	result.Checks = append(result.Checks,
		s.checkL2TPInterface(client),
		s.checkPresence(client, "route-10.250.0.0/16",
			"/ip/route/print", map[string]string{"?comment": "jinom-nms"},
			"required so replies to the monitoring source address return through the tunnel"),
		s.checkPresence(client, "nat-masquerade-10.250.0.0/16",
			"/ip/firewall/nat/print", map[string]string{"?comment": "JINOM NMS"},
			"required so LAN devices can reply without a route back to 10.250.0.0/16"),
		s.checkPresence(client, "filter-ipsec-ports",
			"/ip/firewall/filter/print", map[string]string{"?comment": "JINOM VPN"},
			"accepts udp 500/4500/1701 from the VPS"),
		s.checkPresence(client, "filter-icmp-10.250.0.0/16",
			"/ip/firewall/filter/print", map[string]string{"?comment": "JINOM VPN ICMP"},
			"required for the health monitor ping to be accepted"),
	)

	result.OK = true
	for _, c := range result.Checks {
		if !c.OK {
			result.OK = false
			break
		}
	}
	return result, nil
}

func (s *ProvisionerService) checkL2TPInterface(c *mikrotik.Client) RouterCheck {
	res, err := c.Run("/interface/l2tp-client/print", map[string]string{"?name": "l2tp-jinom"})
	if err != nil {
		return RouterCheck{Name: "interface-l2tp-jinom", OK: false, Detail: err.Error()}
	}
	if len(res) == 0 {
		return RouterCheck{Name: "interface-l2tp-jinom", OK: false, Detail: "interface not found"}
	}
	if res[0]["disabled"] == "true" {
		return RouterCheck{Name: "interface-l2tp-jinom", OK: false, Detail: "interface is disabled"}
	}
	return RouterCheck{Name: "interface-l2tp-jinom", OK: true, Detail: "running=" + res[0]["running"]}
}

func (s *ProvisionerService) checkPresence(c *mikrotik.Client, name, path string, query map[string]string, why string) RouterCheck {
	res, err := c.Run(path, query)
	if err != nil {
		return RouterCheck{Name: name, OK: false, Detail: err.Error()}
	}
	if len(res) == 0 {
		return RouterCheck{Name: name, OK: false, Detail: "missing — " + why}
	}
	return RouterCheck{Name: name, OK: true}
}
