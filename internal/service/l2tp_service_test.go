package service

import (
	"testing"
	"time"
)

func TestStripPort(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"bare ipv4", "10.0.0.1", "10.0.0.1"},
		{"ipv4 with port", "10.0.0.1:9291", "10.0.0.1"},
		{"ipv4 with default api port", "192.168.88.1:8728", "192.168.88.1"},
		{"ipv4 cidr", "10.0.0.0/24", "10.0.0.0/24"},
		{"bracketed ipv6 with port", "[::1]:500", "::1"},
		{"hostname with port", "router.example.com:9291", "router.example.com"},
		{"hostname bare", "router.example.com", "router.example.com"},
		{"garbage stays untouched", "not an address", "not an address"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := stripPort(c.in)
			if got != c.want {
				t.Fatalf("stripPort(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestStripCIDR(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"10.0.0.1/24", "10.0.0.1"},
		{"10.0.0.1", "10.0.0.1"},
		{"invalid", "invalid"},
	}
	for _, c := range cases {
		if got := stripCIDR(c.in); got != c.want {
			t.Errorf("stripCIDR(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFormatTunnelUptime(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{45 * time.Second, "45s"},
		{5*time.Minute + 30*time.Second, "5m30s"},
		// Cabang jam sebelumnya mencetak "hours" dua kali, sehingga 2j5m9d
		// tampil sebagai "2h2m5s".
		{2*time.Hour + 5*time.Minute + 9*time.Second, "2h5m9s"},
		{25*time.Hour + 3*time.Minute, "1d1h3m"},
		{-time.Second, "0s"},
	}
	for _, c := range cases {
		if got := formatTunnelUptime(c.d); got != c.want {
			t.Errorf("formatTunnelUptime(%s) = %q, want %q", c.d, got, c.want)
		}
	}
}
