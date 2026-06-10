package service

import (
	"strings"
	"testing"

	"go.uber.org/zap"
)

// TestWriteIPSecConfig_CryptoAndIsolation verifies the generated strongSwan
// config: strong proposals appear before legacy ones (so modern routers
// negotiate AES-256/SHA-256), the proposal list is strict ("!"), and the
// per-tunnel paths used for mount-namespace isolation are derived correctly.
func TestWriteIPSecConfig_CryptoAndIsolation(t *testing.T) {
	svc := &L2TPService{log: zap.NewNop(), vpsPublicIP: "203.0.113.10"}

	// The caller strips the port before building the conn (verified in
	// TestStripPort); here we pass the already-stripped host and assert the
	// crypto policy + that no port leaks through.
	routerHost := stripPort("198.51.100.5:9291")
	connConf := svc.buildConnConf("jinom-ns-res-test", "10.254.0.22", routerHost)

	// Strong-first ordering.
	idxStrongIKE := strings.Index(connConf, "aes256-sha256-modp2048")
	idxLegacyIKE := strings.Index(connConf, "3des-sha1-modp1024")
	if idxStrongIKE < 0 || idxLegacyIKE < 0 {
		t.Fatalf("ike proposals missing strong/legacy entries:\n%s", connConf)
	}
	if idxStrongIKE > idxLegacyIKE {
		t.Errorf("strong IKE proposal must come before legacy fallback")
	}

	idxStrongESP := strings.Index(connConf, "aes256-sha256")
	idxLegacyESP := strings.Index(connConf, "3des-sha1!")
	if idxStrongESP < 0 || idxLegacyESP < 0 {
		t.Fatalf("esp proposals missing strong/legacy entries:\n%s", connConf)
	}
	if idxStrongESP > idxLegacyESP {
		t.Errorf("strong ESP proposal must come before legacy fallback")
	}

	// Strict proposal sets end with "!".
	for _, line := range strings.Split(connConf, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "ike=") || strings.HasPrefix(l, "esp=") {
			if !strings.HasSuffix(l, "!") {
				t.Errorf("proposal line not strict (missing trailing !): %q", l)
			}
		}
	}

	// Router port suffix must be stripped in the conn's right= field.
	if strings.Contains(connConf, "9291") {
		t.Errorf("router port suffix leaked into ipsec conf:\n%s", connConf)
	}
	if !strings.Contains(connConf, "right=198.51.100.5") {
		t.Errorf("router host missing/incorrect in ipsec conf:\n%s", connConf)
	}
}

func TestIPSecRunDir_PerNamespace(t *testing.T) {
	svc := &L2TPService{log: zap.NewNop()}
	a := svc.ipsecRunDir("ns-res-1")
	b := svc.ipsecRunDir("ns-res-2")
	if a == b {
		t.Fatalf("run dirs must differ per namespace: %q == %q", a, b)
	}
	if !strings.HasPrefix(a, "/run/ipsec/") {
		t.Errorf("run dir not under /run/ipsec: %q", a)
	}
}

func TestXL2TPDControlPath_PerNamespace(t *testing.T) {
	svc := &L2TPService{log: zap.NewNop()}
	a := svc.xl2tpdControlPath("ns-res-1")
	b := svc.xl2tpdControlPath("ns-res-2")
	if a == b {
		t.Fatalf("control paths must differ per namespace: %q == %q", a, b)
	}
}
