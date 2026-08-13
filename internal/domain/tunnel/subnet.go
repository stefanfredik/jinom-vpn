package tunnel

import (
	"fmt"
	"net"
	"strings"
)

// NormalizeSubnets memvalidasi dan membakukan daftar monitoring subnet.
//
// Mengembalikan daftar bersih dalam bentuk kanonik (hasil ParseCIDR, host bits
// sudah di-mask) tanpa duplikat, dengan urutan input dipertahankan.
//
// vpsPublicIP adalah IP publik VPS; subnet yang mencakupnya ditolak karena
// route-nya akan dipasang di dalam namespace dan membajak trafik balik ke VPS
// itu sendiri. Boleh kosong kalau pemanggil tidak tahu IP-nya — pengecekan
// tersebut lalu dilewati.
//
// Daftar kosong adalah input sah: artinya "pakai default RFC-1918".
func NormalizeSubnets(subnets []string, vpsPublicIP string) ([]string, error) {
	out := make([]string, 0, len(subnets))
	seen := make(map[string]struct{}, len(subnets))

	for _, raw := range subnets {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}

		canonical, err := canonicalizeCIDR(s)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[canonical]; dup {
			continue
		}
		if err := rejectDangerousSubnet(canonical, vpsPublicIP); err != nil {
			return nil, err
		}

		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}

	return out, nil
}

// canonicalizeCIDR mengubah "192.168.1.5/24" menjadi "192.168.1.0/24".
//
// Menerima bentuk CIDR saja, bukan IP telanjang: "192.168.1.5" tanpa prefix
// hampir selalu salah ketik dari "/32" atau "/24", dan menebaknya diam-diam
// memasang route yang tidak diniatkan operator.
func canonicalizeCIDR(s string) (string, error) {
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return "", fmt.Errorf("%w: %q bukan CIDR yang valid (contoh: 192.168.1.0/24)", ErrInvalidSubnet, s)
	}
	if ip.To4() == nil {
		return "", fmt.Errorf("%w: %q adalah IPv6, hanya IPv4 yang didukung", ErrInvalidSubnet, s)
	}
	return ipNet.String(), nil
}

// rejectDangerousSubnet menolak prefix yang akan merusak konektivitas VPS.
//
// Dua kelas yang ditolak:
//
//   - Default route (0.0.0.0/0) — mengubah namespace jadi full-tunnel tanpa
//     diniatkan; semua trafik keluar namespace dibuang ke router reseller.
//   - Prefix yang mencakup IP publik VPS — route balik ke VPS ikut masuk
//     tunnel, memutus jalur manajemen (SSH) dan underlay WireGuard.
func rejectDangerousSubnet(cidr, vpsPublicIP string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("%w: %q", ErrInvalidSubnet, cidr)
	}

	if ones, _ := ipNet.Mask.Size(); ones == 0 {
		return fmt.Errorf("%w: %q adalah default route dan akan memutus konektivitas VPS", ErrInvalidSubnet, cidr)
	}

	if vpsPublicIP != "" {
		if vpsIP := net.ParseIP(vpsPublicIP); vpsIP != nil && ipNet.Contains(vpsIP) {
			return fmt.Errorf("%w: %q mencakup IP publik VPS (%s) dan akan memutus akses ke server",
				ErrInvalidSubnet, cidr, vpsPublicIP)
		}
	}

	return nil
}

// DiffSubnets menghitung perubahan dari oldSubnets ke newSubnets.
//
// Dipakai reload runtime supaya hanya route yang benar-benar berubah yang
// disentuh — menghapus lalu memasang ulang seluruh daftar akan membuang paket
// pada subnet yang sebenarnya tidak berubah.
//
// Kedua input diasumsikan sudah lewat NormalizeSubnets sehingga perbandingan
// string cukup (bentuknya sudah kanonik).
func DiffSubnets(oldSubnets, newSubnets []string) (added, removed []string) {
	oldSet := make(map[string]struct{}, len(oldSubnets))
	for _, s := range oldSubnets {
		oldSet[s] = struct{}{}
	}
	newSet := make(map[string]struct{}, len(newSubnets))
	for _, s := range newSubnets {
		newSet[s] = struct{}{}
	}

	for _, s := range newSubnets {
		if _, ok := oldSet[s]; !ok {
			added = append(added, s)
		}
	}
	for _, s := range oldSubnets {
		if _, ok := newSet[s]; !ok {
			removed = append(removed, s)
		}
	}
	return added, removed
}
