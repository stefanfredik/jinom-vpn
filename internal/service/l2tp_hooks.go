package service

import (
	"os"

	"go.uber.org/zap"
)

// Preamble bersama kedua hook: batasi ukuran log supaya partisi tidak penuh
// (pppd dipanggil untuk setiap sesi, dan file ini sebelumnya hanya pernah
// bertambah), lalu turunkan PEERNAME menjadi nama namespace.
//
// Penurunan nama memakai pemotongan prefiks shell, bukan `sed`, dan
// keberadaan namespace diperiksa dengan `grep -qx` (cocok persis) bukan
// `grep -q "^$NS"`. Pemeriksaan berawalan membuat "ns-res-1" dianggap ada
// hanya karena "ns-res-12" terdaftar.
const pppHookPreamble = `LOG=/var/log/jinom-vpn-ppp.log
if [ -f "$LOG" ] && [ "$(stat -c %s "$LOG" 2>/dev/null || echo 0)" -gt 8388608 ]; then
    mv -f "$LOG" "$LOG.1"
fi
exec >> "$LOG" 2>&1

case "$PEERNAME" in
    jinom-*) NS_NAME="ns-${PEERNAME#jinom-}" ;;
    *) echo "PEERNAME '$PEERNAME' is not managed by jinom-vpn, skipping"; exit 0 ;;
esac

if ! ip netns list | awk '{print $1}' | grep -qx "$NS_NAME"; then
    echo "Namespace $NS_NAME not found, skipping"
    exit 0
fi
`

const ipUpScript = `#!/bin/sh
# Dipasang oleh jinom-vpn. Dipanggil pppd saat link naik.
# $1=interface $2=tty $3=speed $4=local-ip $5=remote-ip $6=ipparam
` + pppHookPreamble + `
echo "=== ip-up $(date -Is) if=$1 local=$4 remote=$5 ns=$NS_NAME ==="

# Sesi PPP lama yang belum sempat dibersihkan masih memegang route "default"
# dan subnet monitoring. Tanpa langkah ini, "ip route add" untuk sesi baru
# gagal dan sesi baru berjalan tanpa satu pun route sampai sesi lama timeout.
for stale in $(ip netns exec "$NS_NAME" ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep '^ppp'); do
    echo "Removing stale ppp interface $stale"
    ip netns exec "$NS_NAME" ip link del "$stale" 2>/dev/null || true
done

if ! ip link set "$1" netns "$NS_NAME"; then
    echo "FATAL: failed to move $1 into $NS_NAME"
    exit 1
fi
ip netns exec "$NS_NAME" ip link set "$1" up
ip netns exec "$NS_NAME" ip addr add "$4" peer "$5" dev "$1"
ip netns exec "$NS_NAME" ip route replace default dev "$1"

# Alamat sumber untuk trafik monitoring. Keberadaan file srcip menentukan mode:
# ada  -> SNAT ke ServerIPAddress tunnel (10.250.x.1), cocok dengan rule
#         filter/NAT/route "10.250.0.0/16" yang sudah terpasang di MikroTik.
# tidak -> MASQUERADE, yang membuat sumber menjadi alamat lokal ppp
#         (10.255.255.1, sama untuk semua reseller) dan tidak cocok dengan
#         satu pun rule tersebut.
SRC_IP=""
if [ -r "/etc/ppp/srcip.$NS_NAME" ]; then
    SRC_IP=$(cat "/etc/ppp/srcip.$NS_NAME")
fi

if [ -n "$SRC_IP" ]; then
    echo "Source NAT to $SRC_IP on $1"
    ip netns exec "$NS_NAME" iptables -t nat -C POSTROUTING -o "$1" -j SNAT --to-source "$SRC_IP" 2>/dev/null || \
        ip netns exec "$NS_NAME" iptables -t nat -A POSTROUTING -o "$1" -j SNAT --to-source "$SRC_IP"
else
    echo "Masquerading on $1"
    ip netns exec "$NS_NAME" iptables -t nat -C POSTROUTING -o "$1" -j MASQUERADE 2>/dev/null || \
        ip netns exec "$NS_NAME" iptables -t nat -A POSTROUTING -o "$1" -j MASQUERADE
fi

# Tanpa clamping, TCP apa pun yang melewati tunnel (SSH, Winbox, HTTP ke
# perangkat) menggantung pada paket besar karena MTU tunnel lebih kecil dari
# MSS yang dinegosiasikan ujung-ke-ujung.
ip netns exec "$NS_NAME" iptables -t mangle -C FORWARD -o "$1" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
    ip netns exec "$NS_NAME" iptables -t mangle -A FORWARD -o "$1" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

if [ -f "/etc/ppp/routes.$NS_NAME" ]; then
    while read -r subnet; do
        [ -n "$subnet" ] || continue
        if ip netns exec "$NS_NAME" ip route replace "$subnet" dev "$1"; then
            echo "Route $subnet -> $1"
        else
            echo "WARN: failed to install route $subnet"
        fi
    done < "/etc/ppp/routes.$NS_NAME"
fi

echo "=== ip-up done for $NS_NAME ==="
exit 0
`

const ipDownScript = `#!/bin/sh
# Dipasang oleh jinom-vpn. Dipanggil pppd saat link turun.
# $1=interface $2=tty $3=speed $4=local-ip $5=remote-ip $6=ipparam
` + pppHookPreamble + `
echo "=== ip-down $(date -Is) if=$1 ns=$NS_NAME ==="

# Interface-nya sendiri hilang bersama pppd, tapi rule yang menyebut namanya
# tertinggal di dalam namespace. pppd tidak selalu memberi nomor interface yang
# sama pada sesi berikutnya, sehingga tanpa pembersihan ini tabel nat/mangle
# namespace terus menumpuk rule mati.
ip netns exec "$NS_NAME" iptables -t nat -D POSTROUTING -o "$1" -j MASQUERADE 2>/dev/null || true

SRC_IP=""
if [ -r "/etc/ppp/srcip.$NS_NAME" ]; then
    SRC_IP=$(cat "/etc/ppp/srcip.$NS_NAME")
fi
if [ -n "$SRC_IP" ]; then
    ip netns exec "$NS_NAME" iptables -t nat -D POSTROUTING -o "$1" -j SNAT --to-source "$SRC_IP" 2>/dev/null || true
fi

ip netns exec "$NS_NAME" iptables -t mangle -D FORWARD -o "$1" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

echo "=== ip-down done for $NS_NAME ==="
exit 0
`

func (s *L2TPService) installPPPHooks() {
	hooks := []struct {
		dir     string
		path    string
		content string
	}{
		{"/etc/ppp/ip-up.d", "/etc/ppp/ip-up.d/99-jinom-routes", ipUpScript},
		{"/etc/ppp/ip-down.d", "/etc/ppp/ip-down.d/99-jinom-routes", ipDownScript},
	}

	for _, h := range hooks {
		if err := os.MkdirAll(h.dir, 0755); err != nil {
			s.log.Error("Failed to create ppp hook directory",
				zap.String("dir", h.dir), zap.Error(err))
			continue
		}
		if s.writeConfigIfChanged(h.path, []byte(h.content), 0755) {
			s.log.Info("PPP hook installed", zap.String("path", h.path))
		}
	}
}
