package service

import "testing"

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
