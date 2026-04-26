#!/usr/bin/env bash
#
# setup-vpn-infra.sh — Install and configure VPN infrastructure for jinom-vpn
#
# Installs: WireGuard, StrongSwan (IPSec), xl2tpd (L2TP), iproute2
# Configures: kernel parameters, directories, PPP options, firewall
#
# Usage:
#   sudo ./scripts/setup-vpn-infra.sh
#
# Tested on: Ubuntu 22.04 / 24.04 LTS
#
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# ── Pre-flight checks ────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || fail "This script must be run as root (sudo)"

info "Detecting OS..."
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    info "OS: ${PRETTY_NAME}"
else
    fail "Cannot detect OS. Only Ubuntu/Debian supported."
fi

KERNEL_VERSION=$(uname -r)
info "Kernel: ${KERNEL_VERSION}"

# ── 1. Install packages ──────────────────────────────────────────────────────
info "Updating package index..."
apt-get update -qq || warn "Some repos failed to update (non-fatal, continuing...)"

info "Installing VPN infrastructure packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    iproute2 \
    wireguard \
    wireguard-tools \
    strongswan \
    strongswan-pki \
    libcharon-extra-plugins \
    xl2tpd \
    ppp \
    iptables \
    net-tools \
    iputils-ping \
    > /dev/null

ok "Packages installed"

# ── 2. Load WireGuard kernel module ──────────────────────────────────────────
info "Loading WireGuard kernel module..."
if modprobe wireguard 2>/dev/null; then
    ok "WireGuard module loaded"
else
    warn "WireGuard kernel module failed to load. Checking if built-in..."
    if [[ -d /sys/module/wireguard ]] || grep -q wireguard /proc/modules 2>/dev/null; then
        ok "WireGuard is built into kernel"
    else
        warn "WireGuard module not available. Install linux-headers and wireguard-dkms if needed."
    fi
fi

# Ensure WireGuard module loads on boot
if ! grep -q "^wireguard" /etc/modules 2>/dev/null; then
    echo "wireguard" >> /etc/modules
    ok "WireGuard added to /etc/modules for boot-time loading"
fi

# ── 3. Kernel parameters ─────────────────────────────────────────────────────
info "Configuring kernel parameters..."

SYSCTL_CONF="/etc/sysctl.d/99-jinom-vpn.conf"
cat > "${SYSCTL_CONF}" << 'EOF'
# jinom-vpn: Enable IP forwarding for VPN tunnel routing
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# jinom-vpn: Disable ICMP redirects (security)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# jinom-vpn: Required for L2TP/IPSec NAT traversal
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOF

sysctl -p "${SYSCTL_CONF}" > /dev/null 2>&1
ok "Kernel parameters applied (${SYSCTL_CONF})"

# Verify critical params
IP_FWD=$(cat /proc/sys/net/ipv4/ip_forward)
if [[ "${IP_FWD}" == "1" ]]; then
    ok "IPv4 forwarding: enabled"
else
    fail "IPv4 forwarding NOT enabled after sysctl apply"
fi

# ── 4. Create directories ────────────────────────────────────────────────────
info "Creating config directories..."

mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

mkdir -p /etc/ipsec.d
chmod 700 /etc/ipsec.d

mkdir -p /etc/xl2tpd
chmod 755 /etc/xl2tpd

mkdir -p /etc/ppp
chmod 755 /etc/ppp

ok "Directories created"

# ── 5. Configure StrongSwan (IPSec) ──────────────────────────────────────────
info "Configuring StrongSwan..."

# Main ipsec.conf — include per-tunnel configs from /etc/ipsec.d/
cat > /etc/ipsec.conf << 'EOF'
# /etc/ipsec.conf — StrongSwan base config for jinom-vpn
#
# Per-tunnel configs are dynamically written to /etc/ipsec.d/*.conf
# by jinom-vpn service.

config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

include /etc/ipsec.d/*.conf
EOF

# Secrets file — include per-tunnel secrets
cat > /etc/ipsec.secrets << 'EOF'
# /etc/ipsec.secrets — include per-tunnel PSKs
include /etc/ipsec.d/*.secrets
EOF

chmod 600 /etc/ipsec.secrets

ok "StrongSwan configured"

# ── 6. Configure xl2tpd (L2TP) ───────────────────────────────────────────────
info "Configuring xl2tpd..."

# Base xl2tpd.conf — jinom-vpn creates per-tunnel configs
cat > /etc/xl2tpd/xl2tpd.conf << 'EOF'
; /etc/xl2tpd/xl2tpd.conf — base config
; Per-tunnel configs are managed by jinom-vpn service.
;
[global]
port = 1701
EOF

ok "xl2tpd configured"

# ── 7. Configure PPP options for L2TP ────────────────────────────────────────
info "Configuring PPP options..."

cat > /etc/ppp/options.xl2tpd << 'EOF'
# PPP options for jinom-vpn L2TP tunnels
ipcp-accept-local
ipcp-accept-remote
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 8.8.4.4
asyncmap 0
auth
crtscts
lock
hide-password
modem
debug
name jinom-vpn
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
mtu 1400
mru 1400
EOF

ok "PPP options configured"

# ── 8. Stop default services ─────────────────────────────────────────────────
# jinom-vpn manages these per-namespace, don't run globally
info "Disabling global StrongSwan and xl2tpd services..."
info "(jinom-vpn manages these per-tunnel inside network namespaces)"

systemctl stop strongswan-starter 2>/dev/null || true
systemctl disable strongswan-starter 2>/dev/null || true
systemctl stop xl2tpd 2>/dev/null || true
systemctl disable xl2tpd 2>/dev/null || true

ok "Global services disabled (will be started per-namespace by jinom-vpn)"

# ── 9. Firewall rules ────────────────────────────────────────────────────────
info "Configuring firewall rules..."

# Check if ufw is active
if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    info "UFW detected, adding rules..."

    # WireGuard port range (51821-52074, based on reseller_id % 254 + 1)
    ufw allow 51821:52074/udp comment "jinom-vpn WireGuard tunnels" 2>/dev/null || true

    # L2TP/IPSec ports
    ufw allow 500/udp comment "jinom-vpn IKE (IPSec)" 2>/dev/null || true
    ufw allow 4500/udp comment "jinom-vpn NAT-T (IPSec)" 2>/dev/null || true
    ufw allow 1701/udp comment "jinom-vpn L2TP" 2>/dev/null || true

    ok "UFW rules added"
else
    info "UFW not active, adding iptables rules..."

    # WireGuard port range
    iptables -C INPUT -p udp --dport 51821:52074 -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -p udp --dport 51821:52074 -j ACCEPT

    # L2TP/IPSec
    iptables -C INPUT -p udp --dport 500 -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -p udp --dport 500 -j ACCEPT
    iptables -C INPUT -p udp --dport 4500 -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -p udp --dport 4500 -j ACCEPT
    iptables -C INPUT -p udp --dport 1701 -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -p udp --dport 1701 -j ACCEPT

    ok "iptables rules added"

    # Persist rules if iptables-persistent is available
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save 2>/dev/null || true
        ok "iptables rules persisted"
    else
        warn "Install iptables-persistent to persist rules across reboots:"
        warn "  apt install iptables-persistent"
    fi
fi

# ── 10. Verification ─────────────────────────────────────────────────────────
echo ""
info "═══════════════════════════════════════════════════════"
info " Verification"
info "═══════════════════════════════════════════════════════"

verify() {
    local name="$1" cmd="$2"
    if command -v "${cmd}" &>/dev/null; then
        ok "${name}: $(${cmd} --version 2>&1 | head -1 || echo 'installed')"
    else
        fail "${name}: NOT FOUND"
    fi
}

verify "WireGuard (wg)"    wg
verify "StrongSwan (ipsec)" ipsec
verify "xl2tpd"            xl2tpd
verify "iproute2 (ip)"     ip
verify "iptables"          iptables
verify "pppd"              pppd

echo ""
info "Kernel module check:"
if lsmod | grep -q wireguard; then
    ok "  wireguard module: loaded"
elif [[ -d /sys/module/wireguard ]]; then
    ok "  wireguard module: built-in"
else
    warn "  wireguard module: not loaded (will load on first use)"
fi

echo ""
info "Network namespace test:"
NS_TEST="__jinom_vpn_test__"
if ip netns add "${NS_TEST}" 2>/dev/null; then
    ip netns del "${NS_TEST}"
    ok "  Network namespaces: working"
else
    fail "  Network namespaces: FAILED"
fi

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN} VPN infrastructure setup complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e " Next steps:"
echo -e "  1. Set ${CYAN}VPS_PUBLIC_IP${NC} in .env to this server's public IP"
echo -e "  2. Generate MASTER_KEY: ${CYAN}openssl rand -base64 32${NC}"
echo -e "  3. Start jinom-vpn: ${CYAN}sudo ./bin/jinom-vpn${NC}"
echo -e "  4. Create a tunnel via API, then activate it"
echo ""
