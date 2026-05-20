package mikrotik

import "testing"

func TestResolveAPIAddress(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		defPort  int
		expected string
	}{
		{"bare ipv4 default 8728", "10.0.0.1", 8728, "10.0.0.1:8728"},
		{"ipv4 with custom port", "10.0.0.1:9291", 8728, "10.0.0.1:9291"},
		{"ipv4 with tls port", "10.0.0.1:8729", 8728, "10.0.0.1:8729"},
		{"hostname", "rtr.example.com", 8728, "rtr.example.com:8728"},
		{"hostname with port", "rtr.example.com:9000", 8728, "rtr.example.com:9000"},
		{"bracketed ipv6 with port", "[::1]:9291", 8728, "[::1]:9291"},
		{"bare ipv6 gets bracketed", "::1", 8728, "[::1]:8728"},
		{"empty defaults to host-less port", "", 8728, ":8728"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := resolveAPIAddress(c.input, c.defPort)
			if got != c.expected {
				t.Fatalf("resolveAPIAddress(%q, %d) = %q, want %q",
					c.input, c.defPort, got, c.expected)
			}
		})
	}
}
