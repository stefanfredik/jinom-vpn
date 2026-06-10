# jinom-vpn

VPN tunnel management service for Jinom NMS multi-reseller isolation. Manages WireGuard and L2TP/IPSec tunnels with per-reseller network namespaces, MikroTik router provisioning, and automated health monitoring.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [VPN Infrastructure Setup](#vpn-infrastructure-setup)
- [Configuration](#configuration)
- [Development Setup](#development-setup)
- [Production Deployment](#production-deployment)
- [API Reference](#api-reference)
- [Tunnel Lifecycle](#tunnel-lifecycle)
- [Health Monitoring](#health-monitoring)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
                                    jinom-vpn (this service)
                                    ========================
                                    :8090 HTTP API
                                           |
              +----------------------------+----------------------------+
              |                            |                            |
        TunnelService              ProvisionerService          HealthMonitorService
              |                            |                     (background, 60s)
     +--------+--------+          MikroTik API Client                   |
     |                  |          (RouterOS :8728)               ping per-tunnel
NamespaceService    WireGuardService / L2TPService                      |
     |                  |                                        active -> down
  ip netns          wg / ipsec+xl2tpd                            down -> active
     |                  |
     +------ Linux Kernel (host) ------+
                    |
           Network Namespaces
           ns-res-{reseller_id}
```

**Key concepts:**

- Setiap reseller mendapat **network namespace** terisolasi (`ns-res-{reseller_id}`)
- Tunnel interface (WireGuard/L2TP) dibuat **di dalam namespace** tersebut
- jinom-nms worker melakukan polling device melalui namespace → traffic terisolasi antar reseller
- MikroTik router di sisi reseller di-provision otomatis via RouterOS API

---

## Prerequisites

### System Packages

```bash
# Ubuntu/Debian
sudo apt install -y iproute2 wireguard-tools iptables strongswan xl2tpd

# Alpine
apk add iproute2 wireguard-tools iptables strongswan xl2tpd
```

| Package | Fungsi |
|---------|--------|
| `iproute2` | `ip netns` — network namespace management |
| `wireguard-tools` | `wg` — WireGuard configuration |
| `iptables` | Firewall rules dalam namespace |
| `strongswan` | IPSec untuk L2TP tunnels |
| `xl2tpd` | L2TP daemon |

### Runtime Requirements

- **Linux kernel** dengan network namespace support (semua kernel modern)
- **WireGuard kernel module** (built-in sejak Linux 5.6, atau install `wireguard-dkms`)
- **Root access** — `ip netns`, WireGuard, dan sysctl butuh root
- **PostgreSQL** — shared database dengan jinom-nms
- **Go 1.24+** — untuk build dari source

### MikroTik Router Requirements

- RouterOS 6 atau 7
- API service enabled di port `8728` (default)
- WireGuard package installed (untuk tunnel WireGuard)
- User dengan hak akses API

---

## VPN Infrastructure Setup

Sebelum menjalankan jinom-vpn, server VPS harus disiapkan dengan package dan konfigurasi VPN.

### Automated Setup (Recommended)

Script `scripts/setup-vpn-infra.sh` mengotomasi seluruh proses:

```bash
cd /path/to/jinom-vpn
sudo ./scripts/setup-vpn-infra.sh
```

Script ini melakukan:
1. Install semua package (WireGuard, StrongSwan, xl2tpd, ppp, iptables)
2. Load WireGuard kernel module
3. Konfigurasi kernel parameter (IP forwarding, rp_filter)
4. Setup StrongSwan dan xl2tpd base config
5. Konfigurasi PPP options untuk L2TP
6. Disable global services (jinom-vpn mengelola per-namespace)
7. Setup firewall rules
8. Verifikasi instalasi

### Manual Setup

Jika ingin setup manual atau troubleshooting, ikuti langkah-langkah berikut:

#### 1. Install Packages

```bash
# Ubuntu/Debian
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    iproute2 \
    wireguard wireguard-tools \
    strongswan strongswan-pki libcharon-extra-plugins \
    xl2tpd ppp \
    iptables net-tools iputils-ping
```

#### 2. Load WireGuard Kernel Module

```bash
# Load module
sudo modprobe wireguard

# Verify
lsmod | grep wireguard

# Auto-load on boot
echo "wireguard" | sudo tee -a /etc/modules
```

> **Note:** Kernel 5.6+ sudah memiliki WireGuard built-in. Untuk kernel lama, install `wireguard-dkms` dan `linux-headers-$(uname -r)`.

#### 3. Konfigurasi Kernel Parameters

Buat file `/etc/sysctl.d/99-jinom-vpn.conf`:

```bash
sudo tee /etc/sysctl.d/99-jinom-vpn.conf << 'EOF'
# Enable IP forwarding untuk VPN tunnel routing
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Disable ICMP redirects (security)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Required untuk L2TP/IPSec NAT traversal
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOF

# Apply
sudo sysctl -p /etc/sysctl.d/99-jinom-vpn.conf

# Verify
cat /proc/sys/net/ipv4/ip_forward  # harus 1
```

#### 4. Setup StrongSwan (IPSec)

StrongSwan menyediakan layer IPSec untuk L2TP tunnels.

**Base config** `/etc/ipsec.conf`:

```conf
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

include /etc/ipsec.d/*.conf
```

**Secrets file** `/etc/ipsec.secrets`:

```conf
include /etc/ipsec.d/*.secrets
```

```bash
sudo chmod 600 /etc/ipsec.secrets
sudo mkdir -p /etc/ipsec.d
sudo chmod 700 /etc/ipsec.d
```

> jinom-vpn secara dinamis menulis per-tunnel config ke `/etc/ipsec.d/*.conf` dan `/etc/ipsec.d/*.secrets` saat tunnel dibuat.

#### 5. Setup xl2tpd (L2TP)

**Base config** `/etc/xl2tpd/xl2tpd.conf`:

```ini
[global]
port = 1701
```

```bash
sudo mkdir -p /etc/xl2tpd
```

> Seperti StrongSwan, jinom-vpn mengelola per-tunnel L2TP config secara dinamis.

#### 6. Konfigurasi PPP Options

Buat `/etc/ppp/options.xl2tpd`:

```
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
```

#### 7. Disable Global Services

jinom-vpn menjalankan StrongSwan dan xl2tpd per-namespace, bukan secara global:

```bash
sudo systemctl stop strongswan-starter xl2tpd
sudo systemctl disable strongswan-starter xl2tpd
```

#### 8. Firewall Rules

**WireGuard** — port range berdasarkan `51820 + tunnel index`:

```bash
# UFW
sudo ufw allow 51821:67820/udp comment "jinom-vpn WireGuard"

# atau iptables
sudo iptables -A INPUT -p udp --dport 51821:67820 -j ACCEPT
```

**L2TP/IPSec**:

```bash
# UFW
sudo ufw allow 500/udp comment "IKE (IPSec)"
sudo ufw allow 4500/udp comment "NAT-T (IPSec)"
sudo ufw allow 1701/udp comment "L2TP"

# atau iptables
sudo iptables -A INPUT -p udp --dport 500 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 4500 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 1701 -j ACCEPT
```

Persist iptables rules:

```bash
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

#### 9. Verifikasi

```bash
# Check tools
wg --version
ipsec --version
xl2tpd --version
ip -V

# Check kernel module
lsmod | grep wireguard

# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward

# Test network namespaces
sudo ip netns add __test__
sudo ip netns del __test__
echo "Network namespaces working!"
```

### Port Summary

| Port | Protocol | Fungsi |
|------|----------|--------|
| `8090` | TCP | jinom-vpn HTTP API |
| `51821-67820` | UDP | WireGuard tunnels (per-tunnel) |
| `500` | UDP | IKE (IPSec key exchange) |
| `4500` | UDP | NAT-T (IPSec NAT traversal) |
| `1701` | UDP | L2TP |

---

## Configuration

Semua konfigurasi via environment variables. Copy `.env.example` ke `.env` lalu sesuaikan:

```bash
cp .env.example .env
```

### Application

| Variable | Default | Deskripsi |
|----------|---------|-----------|
| `APP_ENV` | `development` | `development` = colored logs, `production` = JSON structured logs |
| `LISTEN_ADDR` | `:8090` | HTTP listen address |

### Database

| Variable | Default | Deskripsi |
|----------|---------|-----------|
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_USER` | `jinom` | PostgreSQL user |
| `DB_PASSWORD` | `jinom` | PostgreSQL password |
| `DB_NAME` | `jinom_nms` | Database name (shared dengan jinom-nms) |
| `DB_SSL_MODE` | `disable` | SSL mode: `disable`, `require`, `verify-full` |

### Security

| Variable | Default | Deskripsi |
|----------|---------|-----------|
| `MASTER_KEY` | *(kosong)* | Base64-encoded 32-byte AES-256 key. Jika kosong, credentials disimpan plaintext |
| `API_KEY` | *(kosong)* | API key untuk autentikasi. Jika kosong, autentikasi dilewati |

### Network

| Variable | Default | Deskripsi |
|----------|---------|-----------|
| `VPS_PUBLIC_IP` | `0.0.0.0` | Public IP VPS ini. Digunakan saat provision MikroTik sebagai endpoint tunnel |

### Generate MASTER_KEY

```bash
# Generate random 32-byte key, base64 encoded
openssl rand -base64 32
```

---

## Development Setup

### 1. Database

jinom-vpn menggunakan database yang sama dengan jinom-nms. Jika jinom-nms stack sudah running:

```bash
# Database sudah tersedia via jinom-nms
# Host: localhost, Port: 15432, User: nms_user, Password: nms_pass, DB: nms_db
```

Sesuaikan `.env`:

```env
APP_ENV=development
LISTEN_ADDR=:8090

DB_HOST=127.0.0.1
DB_PORT=15432
DB_USER=nms_user
DB_PASSWORD=nms_pass
DB_NAME=nms_db
DB_SSL_MODE=disable

MASTER_KEY=jinom-vpn-master-key-2026
API_KEY=jinom-vpn-api-key-secret
VPS_PUBLIC_IP=127.0.0.1
```

### 2. Build & Run

```bash
# Build binary
make build

# Run (butuh sudo untuk ip netns, wireguard, sysctl)
sudo ./bin/jinom-vpn

# Atau build + run sekaligus
sudo make run

# Atau development mode dengan hot reload (jika air terinstall)
sudo make dev
```

### 3. Verify

```bash
curl http://localhost:8090/health
# {"status":"healthy","service":"jinom-vpn","database":"connected"}
```

### 4. Integrasi dengan jinom-nms

jinom-nms mengakses jinom-vpn via `VPN_SERVICE_URL`. Set di `.env` jinom-nms:

```env
VPN_SERVICE_URL=http://<vpn-host-ip>:8090/api/v1
VPN_SERVICE_API_KEY=jinom-vpn-api-key-secret
```

Gunakan IP yang menjangkau host tempat jinom-vpn berjalan (loopback bila satu host, IP private/public bila lintas host).

### 5. Menjalankan di Background

```bash
# Menggunakan nohup
sudo nohup ./bin/jinom-vpn > server.log 2>&1 &

# Cek log
tail -f server.log

# Stop
sudo kill $(pgrep jinom-vpn)
```

---

## Production Deployment

Bagian ini untuk setup `jinom-vpn` di server production. Rekomendasi deployment: binary Go + systemd, berjalan sebagai `root`, karena service membuat network namespace, interface WireGuard/L2TP, dan config IPSec di host.

### Ringkasan Flow

1. Siapkan server Linux production.
2. Pull source ke `/opt/jinom-vpn`.
3. Build binary.
4. Jalankan `scripts/setup-vpn-infra.sh`.
5. Buat `.env` production.
6. Daftarkan systemd service.
7. Buka firewall.
8. Update `.env` jinom-nms agar mengarah ke service ini.
9. Verifikasi `/health` dan log systemd.

### Setup Cepat Dengan Script

Setelah source tersedia di server production, jalankan installer:

```bash
cd /opt/jinom-vpn
sudo ./scripts/install-production.sh \
  --db-host <postgres-host-production> \
  --db-user <postgres-user> \
  --db-password '<postgres-password>' \
  --db-name <postgres-db-name> \
  --vps-public-ip <public-ip-server-vpn>
```

Script ini akan:

- Build binary `bin/jinom-vpn`.
- Jalankan `scripts/setup-vpn-infra.sh`.
- Buat/update `/opt/jinom-vpn/.env`.
- Generate `MASTER_KEY` dan `API_KEY` jika belum ada.
- Buat/update systemd unit `jinom-vpn.service`.
- Restart service dan cek `/health`.

Untuk melihat tanpa mengubah file/service:

```bash
./scripts/install-production.sh \
  --db-host <postgres-host-production> \
  --db-user <postgres-user> \
  --db-password '<postgres-password>' \
  --db-name <postgres-db-name> \
  --vps-public-ip <public-ip-server-vpn> \
  --dry-run
```

Integrasikan `jinom-nms` ke service VPN:

```bash
cd /opt/jinom-vpn
./scripts/integrate-jinom-nms.sh \
  --nms-dir /opt/jinom-nms \
  --vpn-url http://<vpn-server-private-or-public-ip>:8090/api/v1 \
  --from-vpn-env /opt/jinom-vpn/.env \
  --restart
```

Jika ingin review dulu:

```bash
./scripts/integrate-jinom-nms.sh \
  --nms-dir /opt/jinom-nms \
  --vpn-url http://<vpn-server-private-or-public-ip>:8090/api/v1 \
  --from-vpn-env /opt/jinom-vpn/.env \
  --dry-run
```

### 1. Server Requirements

Gunakan Ubuntu 22.04/24.04 LTS atau Debian compatible. Pastikan server punya:

- Public IP statis untuk endpoint VPN.
- Akses `root` atau user dengan `sudo`.
- Koneksi ke PostgreSQL production yang dipakai jinom-nms.
- Port masuk dari internet untuk WireGuard/L2TP.
- Port `8090/tcp` hanya dibuka dari server jinom-nms.

### 2. Clone Source

```bash
sudo mkdir -p /opt/jinom-vpn
sudo chown -R "$USER":"$USER" /opt/jinom-vpn

git clone <repo-url-jinom-vpn> /opt/jinom-vpn
cd /opt/jinom-vpn
```

Jika source sudah ada:

```bash
cd /opt/jinom-vpn
git pull
```

### 3. Install Go dan Build Binary

Install Go 1.24+ jika belum ada:

```bash
go version
```

Build binary:

```bash
cd /opt/jinom-vpn
make build
```

Hasil build berada di:

```text
/opt/jinom-vpn/bin/jinom-vpn
```

### 4. Setup Infrastruktur VPN Host

Jalankan script infra sekali di server production:

```bash
cd /opt/jinom-vpn
sudo ./scripts/setup-vpn-infra.sh
```

Script ini install package VPN, enable IP forwarding, setup StrongSwan/xl2tpd base config, setup PPP options, disable global StrongSwan/xl2tpd service, dan tambah firewall rule dasar.

Verifikasi cepat:

```bash
wg --version
ipsec --version
xl2tpd --version
cat /proc/sys/net/ipv4/ip_forward
sudo ip netns add __test__ && sudo ip netns del __test__
```

Nilai `cat /proc/sys/net/ipv4/ip_forward` harus `1`.

### 5. Buat `.env` Production

Generate secret:

```bash
openssl rand -base64 32
openssl rand -hex 32
```

Buat `/opt/jinom-vpn/.env`:

```env
APP_ENV=production
LISTEN_ADDR=:8090

DB_HOST=<postgres-host-production>
DB_PORT=5432
DB_USER=<postgres-user>
DB_PASSWORD=<postgres-password>
DB_NAME=<postgres-db-name>
DB_SSL_MODE=require

MASTER_KEY=<output-openssl-rand-base64-32>
API_KEY=<output-openssl-rand-hex-32>
VPS_PUBLIC_IP=<public-ip-server-vpn>
```

Catatan:

- `MASTER_KEY` wajib stabil. Jangan diganti setelah data terenkripsi tersimpan, kecuali ada proses migrasi key.
- `API_KEY` harus sama dengan `VPN_SERVICE_API_KEY` di jinom-nms.
- `VPS_PUBLIC_IP` harus IP publik yang bisa dijangkau router MikroTik customer.
- Pakai `DB_SSL_MODE=disable` hanya kalau PostgreSQL berada di private network yang dipercaya dan memang tidak memakai SSL.

Kunci permission file env:

```bash
sudo chown root:root /opt/jinom-vpn/.env
sudo chmod 600 /opt/jinom-vpn/.env
```

### 6. Buat Systemd Service

```bash
sudo tee /etc/systemd/system/jinom-vpn.service << 'EOF'
[Unit]
Description=Jinom VPN Tunnel Manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/jinom-vpn
EnvironmentFile=/opt/jinom-vpn/.env
ExecStart=/opt/jinom-vpn/bin/jinom-vpn
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
```

Start service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable jinom-vpn
sudo systemctl restart jinom-vpn
```

Cek status dan log:

```bash
sudo systemctl status jinom-vpn
sudo journalctl -u jinom-vpn -f
```

### 7. Firewall Production

Batasi HTTP API hanya dari server jinom-nms:

```bash
sudo ufw allow from <nms-server-ip> to any port 8090 proto tcp comment "jinom-vpn API from jinom-nms"
```

Buka port tunnel:

```bash
sudo ufw allow 51821:67820/udp comment "jinom-vpn WireGuard"
sudo ufw allow 500/udp comment "jinom-vpn IPSec IKE"
sudo ufw allow 4500/udp comment "jinom-vpn IPSec NAT-T"
sudo ufw allow 1701/udp comment "jinom-vpn L2TP"
```

Jika memakai iptables langsung:

```bash
sudo iptables -A INPUT -p tcp -s <nms-server-ip> --dport 8090 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 51821:67820 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 500 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 4500 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 1701 -j ACCEPT
sudo netfilter-persistent save
```

### 8. Integrasi Dengan Project Production `jinom-nms`

Di `.env` production jinom-nms, set:

```env
VPN_SERVICE_URL=http://<vpn-server-private-or-public-ip>:8090/api/v1
VPN_SERVICE_API_KEY=<API_KEY-yang-sama-dengan-jinom-vpn>
```

Gunakan private IP/VPC IP jika jinom-nms dan jinom-vpn berada di jaringan private yang sama. Gunakan public IP hanya jika perlu, dan pastikan firewall `8090/tcp` hanya menerima traffic dari IP server jinom-nms.

Restart service jinom-nms setelah env berubah.

### 9. Verifikasi Production

Dari server jinom-vpn:

```bash
curl http://127.0.0.1:8090/health
```

Dari server jinom-nms:

```bash
curl http://<vpn-server-ip>:8090/health
curl -H "X-API-Key: <API_KEY>" http://<vpn-server-ip>:8090/api/v1/tunnels
```

Response `/health` harus:

```json
{
  "status": "healthy",
  "service": "jinom-vpn",
  "database": "connected"
}
```

### 10. Update Deployment

Saat ada update source:

```bash
cd /opt/jinom-vpn
git pull
make build
sudo systemctl restart jinom-vpn
sudo journalctl -u jinom-vpn -n 100 --no-pager
```

### 11. Backup Yang Perlu Dijaga

Simpan aman file dan nilai berikut:

- `/opt/jinom-vpn/.env`
- Nilai `MASTER_KEY`
- Nilai `API_KEY`
- Backup database jinom-nms/jinom-vpn
- Config host di `/etc/ipsec.d`, `/etc/xl2tpd`, dan `/etc/wireguard` jika tunnel sudah pernah dibuat

### Firewall Rules

```bash
# Izinkan API access (batasi ke jinom-nms saja di production)
sudo ufw allow from <nms-server-ip> to any port 8090

# Izinkan WireGuard tunnel ports (range 51821-67820)
sudo ufw allow 51821:67820/udp

# Izinkan L2TP/IPSec
sudo ufw allow 500/udp    # IKE
sudo ufw allow 4500/udp   # NAT-T
sudo ufw allow 1701/udp   # L2TP
```

### Reverse Proxy (Optional)

Jika ingin expose API via HTTPS:

```nginx
# /etc/nginx/sites-available/jinom-vpn
server {
    listen 443 ssl;
    server_name vpn-api.example.com;

    ssl_certificate /etc/letsencrypt/live/vpn-api.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vpn-api.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## API Reference

Base URL: `http://localhost:8090`

Semua endpoint di bawah `/api/v1` memerlukan header `X-API-Key` atau query parameter `api_key`.

### Health Check

```
GET /health
```

Tanpa autentikasi. Response:

```json
{
  "status": "healthy",
  "service": "jinom-vpn",
  "database": "connected"
}
```

HTTP 503 jika database tidak terhubung.

---

### List Tunnels

```
GET /api/v1/tunnels?page=1&limit=50&company_id=123&reseller_id=456&status=active
```

| Parameter | Type | Default | Deskripsi |
|-----------|------|---------|-----------|
| `page` | int | 1 | Halaman |
| `limit` | int | 50 | Jumlah per halaman |
| `company_id` | int | - | Filter by company |
| `reseller_id` | int | - | Filter by reseller |
| `status` | string | - | Filter by status: `pending`, `active`, `down`, `error` |

Response:

```json
{
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "reseller_id": 123,
      "company_id": 456,
      "name": "customer-vpn",
      "vpn_type": "wireguard",
      "namespace": "ns-res-123",
      "server_public_key": "base64...",
      "server_listen_port": 51821,
      "server_ip_address": "10.250.1.1/30",
      "client_ip_address": "10.250.1.2/30",
      "router_ip": "192.168.1.1",
      "routeros_version": 7,
      "monitoring_subnets": ["10.0.0.0/8"],
      "status": "active",
      "created_at": "2026-04-26T10:00:00Z",
      "updated_at": "2026-04-26T10:05:00Z"
    }
  ],
  "total": 150,
  "page": 1,
  "limit": 50
}
```

---

### Create Tunnel

```
POST /api/v1/tunnels
```

Request body:

```json
{
  "reseller_id": 123,
  "company_id": 456,
  "name": "customer-vpn",
  "vpn_type": "wireguard",
  "router_ip": "192.168.1.1",
  "router_username": "admin",
  "router_password": "secret",
  "routeros_version": 7,
  "monitoring_subnets": ["10.0.0.0/8", "172.16.0.0/12"]
}
```

| Field | Required | Deskripsi |
|-------|----------|-----------|
| `reseller_id` | Ya | ID reseller |
| `company_id` | Ya | ID company |
| `name` | Ya | Nama tunnel (1-100 karakter) |
| `vpn_type` | Ya | `wireguard` atau `l2tp` |
| `router_ip` | Ya | IP MikroTik router reseller |
| `router_username` | Ya | Username RouterOS API |
| `router_password` | Ya | Password RouterOS API |
| `routeros_version` | Tidak | Major version RouterOS (default: 7) |
| `monitoring_subnets` | Tidak | Subnet yang akan di-route melalui tunnel |

Auto-generated saat create:

| Field | Format |
|-------|--------|
| `namespace` | `ns-res-{reseller_id}` |
| `server_ip_address` | `10.250.{index}.1/30` |
| `client_ip_address` | `10.250.{index}.2/30` |
| `server_listen_port` | `51820 + index` (WireGuard) |
| `server_public_key` | Curve25519 keypair (WireGuard) |
| `l2tp_username` | `jinom-res-{reseller_id}` (L2TP) |
| `l2tp_password` | Random 24 chars (L2TP) |
| `psk` | Random 32 chars (L2TP) |

Response: HTTP 201

```json
{
  "success": true,
  "data": { /* tunnel object */ }
}
```

---

### Get Tunnel

```
GET /api/v1/tunnels/{id}
```

Response: HTTP 200 atau 404.

---

### Get Tunnel Status

```
GET /api/v1/tunnels/{id}/status
```

Melakukan live ping ke peer IP di dalam namespace tunnel.

```json
{
  "success": true,
  "data": {
    "id": "550e8400-...",
    "status": "active",
    "namespace": "ns-res-123",
    "last_error": "",
    "peer_reachable": true
  }
}
```

---

### Provision to MikroTik

```
POST /api/v1/tunnels/{id}/provision
```

Menghubungi MikroTik router via RouterOS API (port 8728) dan mengkonfigurasi:

**WireGuard:**
1. Buat interface `wg-jinom`
2. Tambah peer dengan server public key
3. Assign client IP
4. Tambah route `10.250.0.0/16` via WireGuard

**L2TP:**
1. Buat L2TP client interface `l2tp-jinom`
2. Konfigurasi IPSec dengan PSK
3. Assign client IP
4. Tambah route `10.250.0.0/16` via L2TP

---

### Activate Tunnel

```
POST /api/v1/tunnels/{id}/activate
```

Setup infrastruktur VPN di sisi VPS:

1. Buat network namespace `ns-res-{reseller_id}`
2. Enable loopback & IP forwarding di namespace
3. Buat WireGuard/L2TP interface di dalam namespace
4. Assign IP dan routing
5. Status: `pending` -> `provisioning` -> `active`

Hanya bisa dilakukan jika status: `pending`, `down`, atau `error`.

---

### Deactivate Tunnel

```
POST /api/v1/tunnels/{id}/deactivate
```

Teardown infrastruktur VPN:

1. Hapus WireGuard/L2TP interface
2. Hapus network namespace
3. Status: `active`/`down` -> `pending`

---

### Delete Tunnel

```
DELETE /api/v1/tunnels/{id}
```

Deactivate (jika active) lalu hapus record dari database.

---

## Tunnel Lifecycle

```
                    POST /tunnels
                         |
                         v
                    [ pending ]
                         |
         POST /{id}/activate
                         |
                         v
                  [ provisioning ]
                         |
              setup namespace + tunnel
                         |
                +--------+---------+
                |                  |
              success            error
                |                  |
                v                  v
           [ active ]         [ error ]
                |                  |
       health monitor       POST /{id}/activate  (retry)
          (every 60s)              |
                |                  v
         3x ping fail        [ provisioning ] ...
                |
                v
            [ down ]
                |
         ping recovery
                |
                v
           [ active ]

  POST /{id}/deactivate     DELETE /{id}
         |                       |
         v                       v
    [ pending ]             (removed from DB)
```

### Status Values

| Status | Deskripsi |
|--------|-----------|
| `pending` | Baru dibuat, belum diaktifkan |
| `provisioning` | Sedang setup namespace & tunnel |
| `active` | Running dan healthy |
| `down` | Health monitor mendeteksi peer unreachable (3x berturut-turut) |
| `error` | Gagal saat setup |
| `deleted` | Ditandai untuk dihapus |

---

## Health Monitoring

Background goroutine yang berjalan otomatis saat service start.

| Parameter | Nilai |
|-----------|-------|
| Check interval | 60 detik |
| Failure threshold | 5 kali berturut-turut |
| Ping timeout | 3 detik per tunnel |
| Ping count | 2 packet |
| Max recovery attempts | 3 (cooldown 5 menit) |

**Alur:**

1. Ambil semua tunnel dengan status `active`
2. Untuk setiap tunnel:
   - Cek apakah namespace masih ada
   - Ping client IP di dalam namespace: `ip netns exec {ns} ping -c 1 -W 3 {client_ip}`
3. Jika gagal 3x berturut-turut -> status `active` -> `down`
4. Jika recover (ping berhasil setelah down) -> status `down` -> `active`

---

## Security

### Credential Encryption

Sensitive fields dienkripsi dengan **AES-256-GCM** jika `MASTER_KEY` di-set:

- `server_private_key_enc` — WireGuard server private key
- `l2tp_password_enc` — L2TP password
- `psk_enc` — IPSec Pre-Shared Key
- `router_password_enc` — MikroTik router password

Jika `MASTER_KEY` kosong, credentials disimpan plaintext (hanya untuk development).

### API Authentication

Semua endpoint `/api/v1/*` memerlukan:

- Header: `X-API-Key: <your-api-key>`
- Atau query param: `?api_key=<your-api-key>`

Endpoint `/health` tidak memerlukan autentikasi.

### Production Checklist

- [ ] Set `MASTER_KEY` dengan key yang di-generate via `openssl rand -base64 32`
- [ ] Set `API_KEY` yang kuat
- [ ] Set `DB_SSL_MODE=require`
- [ ] Batasi akses port 8090 hanya dari jinom-nms server
- [ ] Set `VPS_PUBLIC_IP` dengan IP publik yang benar
- [ ] Gunakan HTTPS jika API diakses melewati jaringan publik

---

## Troubleshooting

### Service tidak bisa start

```bash
# Cek apakah port sudah dipakai
ss -tlnp | grep 8090

# Cek koneksi database
psql -h localhost -p 15432 -U nms_user -d nms_db -c "SELECT 1"
```

### Health check dari jinom-nms gagal (`connection refused`)

Pastikan `VPN_SERVICE_URL` di `.env` jinom-nms menunjuk ke IP yang menjangkau host jinom-vpn (bukan `localhost` jika jinom-nms berada di host/jaringan berbeda), port `8090/tcp` terbuka dari sisi jinom-nms, dan `API_KEY` di kedua sisi identik. Lihat [Integrasi dengan jinom-nms](#4-integrasi-dengan-jinom-nms).

### Tunnel activate gagal

```bash
# Cek apakah jalan sebagai root
whoami  # harus root

# Cek apakah ip netns tersedia
ip netns list

# Cek WireGuard module
modprobe wireguard
lsmod | grep wireguard

# Cek manual namespace creation
sudo ip netns add test-ns
sudo ip netns del test-ns
```

### Tunnel status down padahal router online

```bash
# Cek namespace ada
sudo ip netns list | grep ns-res-

# Ping manual dari dalam namespace
sudo ip netns exec ns-res-123 ping -c 3 10.250.1.2

# Cek WireGuard interface di namespace
sudo ip netns exec ns-res-123 wg show

# Cek routing di namespace
sudo ip netns exec ns-res-123 ip route
```

### MikroTik provisioning gagal

```bash
# Cek apakah RouterOS API port terjangkau dari VPS
nc -zv <router-ip> 8728

# Cek di MikroTik
/ip service print  # pastikan api enabled
/user print        # pastikan user ada dan punya hak akses api
```

### Melihat logs

```bash
# Systemd
sudo journalctl -u jinom-vpn -f

# Binary langsung
tail -f server.log
```

---

## Project Structure

```
jinom-vpn/
├── cmd/server/main.go              # Entry point & dependency wiring
├── internal/
│   ├── api/
│   │   ├── router.go               # Route registration
│   │   ├── handler/
│   │   │   ├── tunnel_handler.go   # REST handlers
│   │   │   └── health_handler.go   # Health endpoint
│   │   ├── dto/tunnel_dto.go       # Request/response DTOs
│   │   └── middleware/auth.go      # API key auth
│   ├── domain/tunnel/
│   │   ├── entity.go               # ResellerTunnel domain model
│   │   └── repository.go           # Repository interface
│   ├── repository/postgres/
│   │   └── tunnel_repo.go          # PostgreSQL implementation
│   ├── service/
│   │   ├── tunnel_service.go       # Business logic
│   │   ├── provisioner_service.go  # MikroTik provisioning
│   │   ├── health_monitor_service.go # Background health checks
│   │   ├── namespace_service.go    # Linux namespace ops
│   │   ├── wireguard_service.go    # WireGuard setup
│   │   └── l2tp_service.go         # L2TP/IPSec setup
│   └── platform/
│       ├── config/config.go        # Env config loading
│       ├── crypto/crypto.go        # AES-256-GCM encryption
│       ├── database/postgres.go    # DB connection
│       └── logger/logger.go        # Zap logger
├── pkg/mikrotik/client.go          # MikroTik RouterOS API client
├── Makefile
├── .env
└── go.mod
```
