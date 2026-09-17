package service

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"

	"github.com/jinom/vpn/internal/domain/tunnel"
)

const chapMarker = "# jinom-vpn:"

// chapLineNamespace mengembalikan namespace pemilik sebuah baris chap-secrets.
//
// Pencocokan harus persis. Versi sebelumnya memakai strings.Contains terhadap
// tag "# jinom-vpn: <ns>", padahal "ns-res-1" adalah substring dari
// "ns-res-12", "ns-res-100", dan seterusnya. Akibatnya menonaktifkan atau
// menghapus tunnel reseller 1 ikut menghapus kredensial belasan reseller lain,
// yang lalu gagal autentikasi PPP dan tidak pernah bisa tersambung kembali.
func chapLineNamespace(line string) (string, bool) {
	idx := strings.Index(line, chapMarker)
	if idx == -1 {
		return "", false
	}
	return strings.TrimSpace(line[idx+len(chapMarker):]), true
}

func chapLine(t *tunnel.ResellerTunnel) string {
	return fmt.Sprintf("%q * %q %s %s %s",
		t.L2TPUsername, t.L2TPPassword, stripCIDR(t.ClientIPAddress), chapMarker, t.Namespace)
}

func readChapLines() ([]string, error) {
	data, err := os.ReadFile(chapSecrets)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

// writeChapLines menulis seluruh file sekali jalan dan secara atomik.
//
// Sebelumnya penghapusan dan penambahan adalah dua operasi terpisah — truncate
// lalu write, disusul append — sehingga ada jendela di mana pppd, yang membaca
// file ini pada setiap autentikasi, bisa melihat file kosong atau separuh
// tertulis dan menolak sesi yang sah.
func writeChapLines(lines []string) error {
	content := ""
	if len(lines) > 0 {
		content = strings.Join(lines, "\n") + "\n"
	}
	return writeFileAtomic(chapSecrets, []byte(content), 0600)
}

func (s *L2TPService) updateChapSecrets(t *tunnel.ResellerTunnel) error {
	s.secretsMu.Lock()
	defer s.secretsMu.Unlock()

	lines, err := readChapLines()
	if err != nil {
		return fmt.Errorf("read chap-secrets: %w", err)
	}

	kept := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		if ns, ok := chapLineNamespace(line); ok && ns == t.Namespace {
			continue
		}
		kept = append(kept, line)
	}
	kept = append(kept, chapLine(t))

	return writeChapLines(kept)
}

func (s *L2TPService) removeChapSecrets(ns string) error {
	s.secretsMu.Lock()
	defer s.secretsMu.Unlock()

	lines, err := readChapLines()
	if err != nil {
		return fmt.Errorf("read chap-secrets: %w", err)
	}

	kept := make([]string, 0, len(lines))
	removed := 0
	for _, line := range lines {
		if lineNS, ok := chapLineNamespace(line); ok && lineNS == ns {
			removed++
			continue
		}
		kept = append(kept, line)
	}
	if removed == 0 {
		return nil
	}
	return writeChapLines(kept)
}

// RebuildChapSecrets menyusun ulang seluruh entri milik jinom-vpn dari database.
//
// Dipanggil sekali saat start. Kredensial yang sudah terlanjur terhapus oleh
// bug pencocokan berawalan tidak akan kembali dengan sendirinya: Setup hanya
// menulis ulang entri milik tunnel yang kebetulan sedang di-setup, dan setelah
// kriteria sehat L2TP diperbaiki, Reconcile justru melewati tunnel yang sehat.
// Nilai yang ditulis identik dengan yang sudah tersimpan di router, sehingga
// pemulihan ini tidak menyentuh sisi klien sama sekali.
//
// Baris di luar penanda jinom-vpn dipertahankan apa adanya.
func (s *L2TPService) RebuildChapSecrets(tunnels []tunnel.ResellerTunnel) error {
	s.secretsMu.Lock()
	defer s.secretsMu.Unlock()

	lines, err := readChapLines()
	if err != nil {
		return fmt.Errorf("read chap-secrets: %w", err)
	}

	foreign := make([]string, 0, len(lines))
	existing := make(map[string]bool, len(lines))
	for _, line := range lines {
		ns, ok := chapLineNamespace(line)
		if !ok {
			foreign = append(foreign, line)
			continue
		}
		existing[ns] = true
	}

	rebuilt := foreign
	restored := make([]string, 0)
	for i := range tunnels {
		t := &tunnels[i]
		if t.VPNType != tunnel.VPNTypeL2TP || t.L2TPUsername == "" || t.L2TPPassword == "" {
			continue
		}
		if !existing[t.Namespace] {
			restored = append(restored, t.Namespace)
		}
		rebuilt = append(rebuilt, chapLine(t))
	}

	if len(restored) > 0 {
		s.log.Warn("Restoring chap-secrets entries missing from disk",
			zap.Strings("namespaces", restored))
	}

	if err := writeChapLines(rebuilt); err != nil {
		return err
	}
	s.log.Info("chap-secrets rebuilt from database",
		zap.Int("jinom_entries", len(rebuilt)-len(foreign)),
		zap.Int("foreign_entries", len(foreign)),
		zap.Int("restored", len(restored)))
	return nil
}
