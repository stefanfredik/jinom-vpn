package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// defaultCmdTimeout membatasi setiap pemanggilan perintah sistem.
//
// Tanpa batas ini satu `ip netns exec` yang menggantung (netns sibuk, xtables
// lock dipegang proses lain, conntrack menunggu) akan memblokir worker health
// monitor selamanya — 20 kejadian sudah cukup untuk mematikan seluruh
// monitoring tanpa satu pun error muncul di log.
const defaultCmdTimeout = 5 * time.Second

// pingCmdTimeout memberi ruang untuk `ping -c N -W N` yang memang berdurasi
// beberapa detik secara sah.
const pingCmdTimeout = 15 * time.Second

// runCmd menjalankan perintah dengan batas waktu dan mengembalikan output
// gabungan. Timeout dilaporkan sebagai error biasa sehingga pemanggil tidak
// perlu membedakan "gagal" dari "menggantung".
func runCmd(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("%s timed out after %s", name, timeout)
	}
	if err != nil {
		return out, fmt.Errorf("%s: %s: %w", name, string(out), err)
	}
	return out, nil
}

// runQuiet menjalankan perintah best-effort dan hanya melaporkan berhasil/tidak.
func runQuiet(name string, args ...string) bool {
	_, err := runCmd(defaultCmdTimeout, name, args...)
	return err == nil
}

// writeFileAtomic menulis lewat file sementara di direktori yang sama lalu
// rename, sehingga pembaca lain (pppd membaca chap-secrets pada setiap
// autentikasi, charon membaca ipsec.secrets saat rekey) tidak pernah melihat
// file kosong atau separuh tertulis.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", path, err)
	}
	tmpName := tmp.Name()

	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp for %s: %w", path, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp for %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp for %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp to %s: %w", path, err)
	}
	tmpName = ""
	return nil
}

// fileContentEquals melaporkan apakah file di path sudah berisi persis data.
// Dipakai agar penulisan ulang konfigurasi yang identik tidak memicu restart
// daemon yang memutus seluruh sesi pelanggan.
func fileContentEquals(path string, data []byte) bool {
	existing, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return string(existing) == string(data)
}
