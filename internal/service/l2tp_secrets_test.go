package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

func withTempChapSecrets(t *testing.T, initial string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "chap-secrets")
	if initial != "" {
		if err := os.WriteFile(path, []byte(initial), 0600); err != nil {
			t.Fatalf("seed chap-secrets: %v", err)
		}
	}
	original := chapSecrets
	chapSecrets = path
	t.Cleanup(func() { chapSecrets = original })
}

func newTestL2TPService() *L2TPService {
	return &L2TPService{log: zap.NewNop(), snatMode: SNATModeServerIP}
}

func testTunnel(resellerID int64, index int) *tunnel.ResellerTunnel {
	t := &tunnel.ResellerTunnel{
		ResellerID:      resellerID,
		VPNType:         tunnel.VPNTypeL2TP,
		L2TPUsername:    "jinom-res-" + itoa(resellerID),
		L2TPPassword:    "secret" + itoa(resellerID),
		TunnelIndex:     index,
		ClientIPAddress: "10.250.0.2/30",
	}
	t.GenerateNamespace()
	return t
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}

func readChapFile(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(chapSecrets)
	if err != nil {
		t.Fatalf("read chap-secrets: %v", err)
	}
	return string(data)
}

// Menghapus ns-res-1 tidak boleh menyentuh ns-res-12 atau ns-res-100.
// Pencocokan berawalan sebelumnya membuat ketiganya ikut terhapus, dan reseller
// yang bersangkutan tidak pernah bisa autentikasi PPP lagi.
func TestRemoveChapSecretsDoesNotTouchNamespacesSharingPrefix(t *testing.T) {
	withTempChapSecrets(t, "")
	svc := newTestL2TPService()

	for _, id := range []int64{1, 12, 100} {
		if err := svc.updateChapSecrets(testTunnel(id, int(id))); err != nil {
			t.Fatalf("updateChapSecrets(%d): %v", id, err)
		}
	}

	if err := svc.removeChapSecrets("ns-res-1"); err != nil {
		t.Fatalf("removeChapSecrets: %v", err)
	}

	content := readChapFile(t)
	if strings.Contains(content, chapMarker+" ns-res-1\n") {
		t.Error("ns-res-1 should have been removed")
	}
	for _, survivor := range []string{"ns-res-12", "ns-res-100"} {
		if !strings.Contains(content, chapMarker+" "+survivor) {
			t.Errorf("%s was wrongly removed:\n%s", survivor, content)
		}
	}
}

func TestUpdateChapSecretsReplacesOwnEntryOnly(t *testing.T) {
	withTempChapSecrets(t, "")
	svc := newTestL2TPService()

	tun := testTunnel(7, 7)
	if err := svc.updateChapSecrets(tun); err != nil {
		t.Fatalf("first update: %v", err)
	}
	tun.L2TPPassword = "rotated"
	if err := svc.updateChapSecrets(tun); err != nil {
		t.Fatalf("second update: %v", err)
	}

	content := readChapFile(t)
	if got := strings.Count(content, chapMarker+" ns-res-7"); got != 1 {
		t.Fatalf("expected exactly 1 entry, got %d:\n%s", got, content)
	}
	if !strings.Contains(content, "rotated") {
		t.Errorf("rotated password not written:\n%s", content)
	}
}

// Baris milik administrator lain di chap-secrets tidak boleh hilang.
func TestRebuildChapSecretsPreservesForeignLinesAndRestoresMissing(t *testing.T) {
	foreign := `"other-vpn" * "pw" 10.9.9.9` + "\n"
	withTempChapSecrets(t, foreign)
	svc := newTestL2TPService()

	tunnels := []tunnel.ResellerTunnel{*testTunnel(1, 1), *testTunnel(12, 12)}
	if err := svc.RebuildChapSecrets(tunnels); err != nil {
		t.Fatalf("RebuildChapSecrets: %v", err)
	}

	content := readChapFile(t)
	if !strings.Contains(content, "other-vpn") {
		t.Errorf("foreign entry was dropped:\n%s", content)
	}
	for _, ns := range []string{"ns-res-1", "ns-res-12"} {
		if !strings.Contains(content, chapMarker+" "+ns) {
			t.Errorf("%s missing after rebuild:\n%s", ns, content)
		}
	}
}

// Penulisan harus atomik: file tidak boleh pernah terlihat kosong oleh pppd.
func TestWriteChapLinesReplacesAtomically(t *testing.T) {
	withTempChapSecrets(t, "seed\n")
	if err := writeChapLines([]string{"a", "b"}); err != nil {
		t.Fatalf("writeChapLines: %v", err)
	}
	if got := readChapFile(t); got != "a\nb\n" {
		t.Fatalf("unexpected content %q", got)
	}
	entries, err := os.ReadDir(filepath.Dir(chapSecrets))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("temp file left behind: %v", entries)
	}
	info, err := os.Stat(chapSecrets)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestChapLineNamespaceExactMatch(t *testing.T) {
	cases := []struct {
		line string
		want string
		ok   bool
	}{
		{`"u" * "p" 10.0.0.1 # jinom-vpn: ns-res-12`, "ns-res-12", true},
		{`"u" * "p" 10.0.0.1 # jinom-vpn:ns-res-3`, "ns-res-3", true},
		{`"other" * "p" 10.0.0.1`, "", false},
	}
	for _, c := range cases {
		got, ok := chapLineNamespace(c.line)
		if ok != c.ok || got != c.want {
			t.Errorf("chapLineNamespace(%q) = (%q,%v), want (%q,%v)", c.line, got, ok, c.want, c.ok)
		}
	}
}
