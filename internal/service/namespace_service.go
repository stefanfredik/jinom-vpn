package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

type NamespaceService struct {
	log *zap.Logger
}

func NewNamespaceService(log *zap.Logger) *NamespaceService {
	return &NamespaceService{log: log}
}

func (s *NamespaceService) Create(ns string) error {
	s.log.Info("Creating network namespace", zap.String("namespace", ns))

	if err := run("ip", "netns", "add", ns); err != nil {
		return fmt.Errorf("create namespace %s: %w", ns, err)
	}

	if err := run("ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"); err != nil {
		s.log.Warn("Failed to bring up loopback in namespace", zap.String("ns", ns), zap.Error(err))
	}

	if err := run("ip", "netns", "exec", ns,
		"sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		s.log.Warn("Failed to enable ip_forward in namespace", zap.String("ns", ns), zap.Error(err))
	}

	return nil
}

func (s *NamespaceService) Delete(ns string) error {
	s.log.Info("Deleting network namespace", zap.String("namespace", ns))
	if err := run("ip", "netns", "del", ns); err != nil {
		return fmt.Errorf("delete namespace %s: %w", ns, err)
	}
	return nil
}

// netnsDir adalah tempat `ip netns add` membuat handle namespace bernama.
const netnsDir = "/run/netns"

// Exists melaporkan apakah namespace bernama sudah dibuat.
//
// Sebelumnya ini menjalankan `ip netns exec <ns> true`, yang juga gagal ketika
// proses tidak punya hak (Operation not permitted). Kegagalan itu terbaca
// sebagai "namespace tidak ada", lalu pemanggil mencoba membuatnya, gagal
// lagi, dan menandai tunnel error — padahal namespace-nya ada dan sehat.
// Handle di /run/netns bisa di-stat tanpa hak istimewa, jadi jawabannya
// benar apa pun privilege proses.
func (s *NamespaceService) Exists(ns string) bool {
	_, err := os.Stat(filepath.Join(netnsDir, ns))
	return err == nil
}

// isPermissionError mengenali kegagalan karena proses tidak punya hak, bukan
// karena keadaan sistem. Kegagalan seperti ini tidak boleh dicatat sebagai
// status error tunnel: yang salah adalah cara prosesnya dijalankan.
func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "Operation not permitted") ||
		strings.Contains(msg, "Permission denied")
}

// ListRoutes mengembalikan prefix tujuan dari tabel route di dalam namespace,
// yaitu route yang BENAR-BENAR terpasang — bukan yang tercatat di database.
//
// Keduanya bisa berbeda: `ip route add` yang gagal saat Setup hanya di-log
// sebagai warning dan tunnel tetap dilaporkan aktif, sehingga UI yang membaca
// database saja akan mengklaim subnet termonitor padahal paketnya tidak pernah
// masuk tunnel. Fungsi ini dipakai untuk menampilkan kenyataan tersebut.
//
// Default route dinormalkan menjadi "0.0.0.0/0" karena `ip route` menuliskannya
// sebagai "default", dan host tunggal dinormalkan ke "/32" supaya sebanding
// dengan bentuk kanonik dari NormalizeSubnets.
//
// Mengembalikan slice kosong bila namespace tidak ada atau perintah gagal:
// pemanggilnya adalah jalur tampilan status, yang tidak boleh gagal total
// hanya karena route tidak terbaca.
func (s *NamespaceService) ListRoutes(ns, ifName string) []string {
	out, err := s.ExecInNS(ns, "ip", "-4", "route", "show", "dev", ifName)
	if err != nil {
		s.log.Debug("ListRoutes: failed to read routes",
			zap.String("ns", ns), zap.String("if", ifName), zap.Error(err))
		return []string{}
	}

	routes := make([]string, 0, 8)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		routes = append(routes, normalizeRouteDst(fields[0]))
	}
	return routes
}

// normalizeRouteDst menyamakan bentuk tujuan route dengan bentuk kanonik CIDR.
func normalizeRouteDst(dst string) string {
	if dst == "default" {
		return "0.0.0.0/0"
	}
	if !strings.Contains(dst, "/") {
		return dst + "/32"
	}
	return dst
}

func (s *NamespaceService) ExecInNS(ns string, name string, args ...string) ([]byte, error) {
	return s.ExecInNSTimeout(defaultCmdTimeout, ns, name, args...)
}

// ExecInNSTimeout menjalankan perintah di dalam namespace dengan batas waktu
// eksplisit. Perintah yang memang lambat secara sah (ping dengan beberapa
// percobaan) memakai batas lebih longgar lewat fungsi ini; sisanya memakai
// defaultCmdTimeout supaya satu perintah menggantung tidak mengunci pemanggil.
func (s *NamespaceService) ExecInNSTimeout(timeout time.Duration, ns string, name string, args ...string) ([]byte, error) {
	cmdArgs := append([]string{"netns", "exec", ns, name}, args...)
	out, err := runCmd(timeout, "ip", cmdArgs...)
	if err != nil {
		return out, fmt.Errorf("exec in %s: %w", ns, err)
	}
	return out, nil
}

func run(name string, args ...string) error {
	_, err := runCmd(defaultCmdTimeout, name, args...)
	return err
}
