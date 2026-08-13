package tunnel

import (
	"errors"
	"reflect"
	"testing"
)

const testVPSIP = "203.0.113.10"

func TestNormalizeSubnetsAccepts(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"empty means fall back to RFC-1918", nil, []string{}},
		{"private range kept", []string{"192.168.1.0/24"}, []string{"192.168.1.0/24"}},
		// Inti fitur ini: IP publik HARUS lolos validasi. Sebelumnya tidak ada
		// validasi sama sekali, jadi tes ini mengunci perilaku yang diinginkan
		// agar tidak ikut tertutup saat validasi diperketat.
		{"public range accepted", []string{"103.10.20.0/24"}, []string{"103.10.20.0/24"}},
		{"single public host", []string{"103.10.20.5/32"}, []string{"103.10.20.5/32"}},
		{"mixed private and public", []string{"10.0.0.0/8", "103.10.20.0/24"}, []string{"10.0.0.0/8", "103.10.20.0/24"}},
		// Host bits di-mask supaya diff antar-versi membandingkan bentuk yang
		// sama; tanpa ini "192.168.1.5/24" dan "192.168.1.0/24" terlihat beda.
		{"host bits masked to network address", []string{"192.168.1.77/24"}, []string{"192.168.1.0/24"}},
		{"whitespace trimmed", []string{"  10.0.0.0/8  "}, []string{"10.0.0.0/8"}},
		{"blank entries skipped", []string{"10.0.0.0/8", "", "   "}, []string{"10.0.0.0/8"}},
		{"exact duplicates removed", []string{"10.0.0.0/8", "10.0.0.0/8"}, []string{"10.0.0.0/8"}},
		// Duplikat baru terlihat SETELAH masking — keduanya menghasilkan route
		// yang sama, dan `ip route add` kedua akan gagal "File exists".
		{"duplicates after masking removed", []string{"192.168.1.5/24", "192.168.1.99/24"}, []string{"192.168.1.0/24"}},
		{"input order preserved", []string{"172.16.0.0/12", "10.0.0.0/8"}, []string{"172.16.0.0/12", "10.0.0.0/8"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := NormalizeSubnets(c.in, testVPSIP)
			if err != nil {
				t.Fatalf("NormalizeSubnets(%v) unexpected error: %v", c.in, err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("NormalizeSubnets(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestNormalizeSubnetsRejects(t *testing.T) {
	cases := []struct {
		name string
		in   []string
	}{
		{"garbage string", []string{"not-a-cidr"}},
		{"prefix out of range", []string{"192.168.1.0/33"}},
		{"octet out of range", []string{"999.1.1.0/24"}},
		// IP telanjang ditolak: hampir selalu salah ketik dari /32 atau /24,
		// dan menebaknya memasang route yang tidak diniatkan operator.
		{"bare ip without prefix", []string{"192.168.1.1"}},
		{"ipv6 not supported", []string{"2001:db8::/32"}},
		// Dua kelas berbahaya: keduanya memutus konektivitas VPS.
		{"default route", []string{"0.0.0.0/0"}},
		{"subnet containing vps public ip", []string{"203.0.113.0/24"}},
		{"broad subnet swallowing vps ip", []string{"203.0.0.0/8"}},
		// Satu entri buruk membatalkan seluruh permintaan: menerima sebagian
		// akan memasang state yang tidak pernah diminta operator.
		{"one bad entry rejects whole list", []string{"10.0.0.0/8", "bogus"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := NormalizeSubnets(c.in, testVPSIP)
			if err == nil {
				t.Fatalf("NormalizeSubnets(%v) = %v, want error", c.in, got)
			}
			if !errors.Is(err, ErrInvalidSubnet) {
				t.Fatalf("NormalizeSubnets(%v) error = %v, want wrapping ErrInvalidSubnet", c.in, err)
			}
		})
	}
}

// Pengecekan IP VPS dilewati bila pemanggil tidak tahu IP-nya. Tanpa ini
// tunnel jadi tidak bisa diedit sama sekali saat VPS_PUBLIC_IP belum diset.
func TestNormalizeSubnetsSkipsVPSCheckWhenIPUnknown(t *testing.T) {
	got, err := NormalizeSubnets([]string{"203.0.113.0/24"}, "")
	if err != nil {
		t.Fatalf("unexpected error with empty vpsPublicIP: %v", err)
	}
	if want := []string{"203.0.113.0/24"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestDiffSubnets(t *testing.T) {
	cases := []struct {
		name         string
		old, updated []string
		wantAdded    []string
		wantRemoved  []string
	}{
		{
			name: "no change yields empty diff",
			old:  []string{"10.0.0.0/8"}, updated: []string{"10.0.0.0/8"},
		},
		{
			name: "pure addition",
			old:  []string{"10.0.0.0/8"}, updated: []string{"10.0.0.0/8", "103.10.20.0/24"},
			wantAdded: []string{"103.10.20.0/24"},
		},
		{
			name: "pure removal",
			old:  []string{"10.0.0.0/8", "103.10.20.0/24"}, updated: []string{"10.0.0.0/8"},
			wantRemoved: []string{"103.10.20.0/24"},
		},
		{
			name: "swap produces both",
			old:  []string{"10.0.0.0/8"}, updated: []string{"103.10.20.0/24"},
			wantAdded: []string{"103.10.20.0/24"}, wantRemoved: []string{"10.0.0.0/8"},
		},
		{
			name: "clearing removes everything",
			old:  []string{"10.0.0.0/8", "172.16.0.0/12"}, updated: nil,
			wantRemoved: []string{"10.0.0.0/8", "172.16.0.0/12"},
		},
		{
			// Reorder tanpa perubahan isi TIDAK boleh menghasilkan diff: kalau
			// tidak, menyimpan ulang daftar yang sama akan mencabut lalu
			// memasang kembali route dan membuang paket tanpa alasan.
			name: "reorder is not a change",
			old:  []string{"10.0.0.0/8", "172.16.0.0/12"}, updated: []string{"172.16.0.0/12", "10.0.0.0/8"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			added, removed := DiffSubnets(c.old, c.updated)
			if !equalStringSlices(added, c.wantAdded) {
				t.Fatalf("added = %v, want %v", added, c.wantAdded)
			}
			if !equalStringSlices(removed, c.wantRemoved) {
				t.Fatalf("removed = %v, want %v", removed, c.wantRemoved)
			}
		})
	}
}

// equalStringSlices memperlakukan nil dan slice kosong sebagai sama, karena
// DiffSubnets mengembalikan nil saat tidak ada perubahan.
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
