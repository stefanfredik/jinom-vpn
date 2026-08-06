package tunnel

import "testing"

// reseller_tunnels.router_api_port is NOT NULL with a BETWEEN 1 AND 65535 check,
// so every value handed to the repository has to land inside that range.
func TestEffectiveAPIPort(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want int
	}{
		{"omitted falls back to routeros default", 0, 8728},
		{"negative falls back", -1, 8728},
		{"above range falls back", 65536, 8728},
		{"lower bound kept", 1, 1},
		{"upper bound kept", 65535, 65535},
		{"custom port kept", 8730, 8730},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tun := &ResellerTunnel{RouterAPIPort: c.in}
			if got := tun.EffectiveAPIPort(); got != c.want {
				t.Fatalf("EffectiveAPIPort() with %d = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

func TestGenerateNamespaceUsesResellerID(t *testing.T) {
	a := &ResellerTunnel{ResellerID: 1042}
	b := &ResellerTunnel{ResellerID: 1043}
	a.GenerateNamespace()
	b.GenerateNamespace()

	if a.Namespace != "ns-res-1042" {
		t.Fatalf("Namespace = %q, want %q", a.Namespace, "ns-res-1042")
	}
	// The namespace column is UNIQUE, so distinct resellers must not collide.
	if a.Namespace == b.Namespace {
		t.Fatalf("namespaces collided: %q", a.Namespace)
	}
}
