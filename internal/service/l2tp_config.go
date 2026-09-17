package service

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

// daemonCmdTimeout memberi ruang untuk systemctl start/restart yang menunggu
// unit selesai berpindah state.
const daemonCmdTimeout = 30 * time.Second

// generateIPSecPSK generates a cryptographically random IPSec pre-shared key.
func generateIPSecPSK() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// writeConfigIfChanged menulis file hanya bila isinya berbeda, dan melaporkan
// apakah terjadi perubahan.
//
// Ini yang memungkinkan daemon tidak di-restart pada setiap start proses.
// Sebelumnya initGlobalDaemons selalu menjalankan `systemctl restart` untuk
// strongswan dan xl2tpd, sehingga setiap deploy, restart, atau crash-loop
// memutus seluruh sesi L2TP semua reseller sekaligus dan memicu renegosiasi
// IKE serempak dari semua router.
func (s *L2TPService) writeConfigIfChanged(path string, data []byte, perm os.FileMode) bool {
	if fileContentEquals(path, data) {
		return false
	}
	if err := writeFileAtomic(path, data, perm); err != nil {
		s.log.Error("Failed to write config file", zap.String("path", path), zap.Error(err))
		return false
	}
	s.log.Info("Config file updated", zap.String("path", path))
	return true
}

// ensureDaemon memastikan unit aktif, dan hanya me-restart bila konfigurasinya
// benar-benar berubah.
func (s *L2TPService) ensureDaemon(unit string, configChanged bool) {
	if _, err := runCmd(daemonCmdTimeout, "systemctl", "enable", unit); err != nil {
		s.log.Warn("Failed to enable unit", zap.String("unit", unit), zap.Error(err))
	}

	active := runQuiet("systemctl", "is-active", "--quiet", unit)

	switch {
	case !active:
		s.log.Info("Starting daemon", zap.String("unit", unit))
		if _, err := runCmd(daemonCmdTimeout, "systemctl", "start", unit); err != nil {
			s.log.Error("Failed to start daemon", zap.String("unit", unit), zap.Error(err))
		}
	case configChanged:
		s.log.Warn("Config changed, restarting daemon — active sessions will reconnect",
			zap.String("unit", unit))
		if _, err := runCmd(daemonCmdTimeout, "systemctl", "restart", unit); err != nil {
			s.log.Error("Failed to restart daemon", zap.String("unit", unit), zap.Error(err))
		}
	default:
		s.log.Info("Daemon already running with current config, not restarting",
			zap.String("unit", unit))
	}
}

func (s *L2TPService) initGlobalDaemons() {
	ipsecChanged := s.writeIPSecConf()
	secretsChanged := s.initPSK()
	xl2tpdChanged := s.writeXL2TPDConf()
	pppChanged := s.writePPPOptions()

	s.ensureDaemon("strongswan-starter", ipsecChanged || secretsChanged)
	// Perubahan pada options.xl2tpd baru berlaku untuk sesi pppd berikutnya,
	// yang di-spawn oleh xl2tpd — karena itu keduanya dikelompokkan di sini.
	s.ensureDaemon("xl2tpd", xl2tpdChanged || pppChanged)
}

func (s *L2TPService) writeIPSecConf() bool {
	if s.vpsPublicIP == "" || s.vpsPublicIP == "0.0.0.0" {
		// Menulis "left=" kosong menghasilkan conn yang gagal dimuat charon,
		// yang berarti seluruh L2TP mati. Lebih baik mempertahankan config
		// yang ada dan berteriak keras.
		s.log.Error("VPS public IP is not configured — refusing to rewrite /etc/ipsec.conf. " +
			"Set VPS_PUBLIC_IP; L2TP will keep using the previously written config, if any.")
		return false
	}

	conf := fmt.Sprintf(`config setup
    uniqueids=never
    charondebug="ike 0, knl 0, cfg 0"

conn %%default
    keyingtries=3
    ikelifetime=28800s
    lifetime=28800s
    dpddelay=30s
    dpdtimeout=120s
    dpdaction=clear
    ike=aes256-sha256-modp2048,aes128-sha256-modp2048,aes128-sha1-modp1024,aes128-md5-modp1024,3des-sha1-modp2048!
    esp=aes256-sha256,aes256-sha1,aes128-sha1,aes128-sha1-modp1024,3des-sha1!

conn L2TP-PSK
    authby=secret
    auto=add
    type=transport
    left=%s
    right=%%any
    rightprotoport=17/%%any
    leftprotoport=17/1701
`, s.vpsPublicIP)

	return s.writeConfigIfChanged(ipsecConfPath, []byte(conf), 0644)
}

// initPSK memuat PSK global yang persisten, atau membuatnya bila belum ada.
func (s *L2TPService) initPSK() bool {
	var psk string
	if data, err := os.ReadFile(pskPath); err == nil {
		psk = strings.TrimSpace(string(data))
	}

	if psk == "" {
		psk = generateIPSecPSK()
		if psk == "" {
			s.log.Error("Failed to generate IPSec PSK — L2TP provisioning will not work")
			return false
		}
		if err := os.MkdirAll("/etc/ipsec.d", 0755); err != nil {
			s.log.Error("Failed to create /etc/ipsec.d", zap.Error(err))
		}
		if err := writeFileAtomic(pskPath, []byte(psk+"\n"), 0600); err != nil {
			s.log.Error("Failed to persist IPSec PSK — a different key will be generated "+
				"on next restart and every router will need re-provisioning", zap.Error(err))
		} else {
			// Ini bukan kejadian rutin: PSK global dipakai bersama oleh semua
			// router. Kalau file-nya hilang, kunci baru ini tidak cocok dengan
			// yang sudah tersimpan di router mana pun.
			s.log.Warn("Generated a NEW global IPSec PSK. If L2TP tunnels already " +
				"existed, every MikroTik must be re-provisioned with this key.")
		}
	}

	s.setPSK(psk)
	s.log.Info("IPSec PSK initialized", zap.Int("length", len(psk)))

	return s.writeConfigIfChanged(ipsecSecPath, []byte(fmt.Sprintf(": PSK \"%s\"\n", psk)), 0600)
}

func (s *L2TPService) writeXL2TPDConf() bool {
	// Catatan: "require chap" sengaja tidak dipakai. Baris itu membuat xl2tpd
	// menambahkan "require-chap" (CHAP-MD5) ke pppd, sementara options.xl2tpd
	// menuntut "require-mschap-v2" — dua syarat yang saling bertabrakan dan
	// membuat hasil negosiasi bergantung pada urutan opsi. MikroTik menawarkan
	// MS-CHAPv2 secara default, jadi satu syarat itu saja yang ditegakkan.
	conf := `[global]
port = 1701
access control = no

[lns default]
exclusive = no
ip range = 10.255.255.100-10.255.255.250
local ip = 10.255.255.1
refuse pap = yes
require authentication = yes
name = jinom-vpn
pppoptfile = /etc/ppp/options.xl2tpd
length bit = no
`
	if err := os.MkdirAll("/etc/xl2tpd", 0755); err != nil {
		s.log.Error("Failed to create /etc/xl2tpd", zap.Error(err))
	}
	return s.writeConfigIfChanged("/etc/xl2tpd/xl2tpd.conf", []byte(conf), 0644)
}

func (s *L2TPService) writePPPOptions() bool {
	// lcp-echo-interval 30 x lcp-echo-failure 4 = 120 detik, sengaja disamakan
	// dengan dpdtimeout IPSec. Sebelumnya failure=8 (240 detik), sehingga ada
	// jendela dua menit di mana IPSec sudah lenyap tapi interface ppp masih
	// berstatus UP — dan pemeriksa status melaporkan tunnel sehat padahal
	// sudah tidak bisa melewatkan paket.
	//
	// MTU 1380: 1500 dikurangi UDP-encap NAT-T (8) + ESP (~56) + IP (20) +
	// UDP 1701 (8) + L2TP (12) + PPP (4) menyisakan ruang yang tipis pada 1400.
	opts := `ipcp-accept-local
ipcp-accept-remote
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 8.8.4.4
asyncmap 0
noccp
novj
novjccomp
nobsdcomp
nodeflate
hide-password
name jinom-vpn
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
mtu 1380
mru 1380
`
	if err := os.MkdirAll(pppDir, 0755); err != nil {
		s.log.Error("Failed to create /etc/ppp", zap.Error(err))
	}
	return s.writeConfigIfChanged("/etc/ppp/options.xl2tpd", []byte(opts), 0644)
}
