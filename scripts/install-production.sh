#!/usr/bin/env bash
#
# Install or update jinom-vpn on a production server.
#
# Usage:
#   sudo ./scripts/install-production.sh \
#     --db-host 10.0.0.10 \
#     --db-user nms_user \
#     --db-password 'secret' \
#     --db-name nms_db \
#     --vps-public-ip 203.0.113.10
#
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${APP_DIR}/.env"
SERVICE_NAME="jinom-vpn"
LISTEN_ADDR=":8090"
APP_ENV="production"
DB_HOST=""
DB_PORT="5432"
DB_USER=""
DB_PASSWORD=""
DB_NAME=""
DB_SSL_MODE="require"
MASTER_KEY=""
API_KEY=""
VPS_PUBLIC_IP=""
RUN_INFRA=1
RUN_BUILD=1
RUN_SYSTEMD=1
START_SERVICE=1
DRY_RUN=0

usage() {
    cat <<'EOF'
Install or update jinom-vpn on a production server.

Usage:
  sudo ./scripts/install-production.sh \
    --db-host 10.0.0.10 \
    --db-user nms_user \
    --db-password 'secret' \
    --db-name nms_db \
    --vps-public-ip 203.0.113.10

Options:
  --app-dir PATH             Project path. Default: script parent dir.
  --env-file PATH            Env file path. Default: <app-dir>/.env.
  --listen-addr VALUE        HTTP listen addr. Default: :8090.
  --db-host VALUE            PostgreSQL host.
  --db-port VALUE            PostgreSQL port. Default: 5432.
  --db-user VALUE            PostgreSQL user.
  --db-password VALUE        PostgreSQL password.
  --db-name VALUE            PostgreSQL database.
  --db-ssl-mode VALUE        PostgreSQL SSL mode. Default: require.
  --master-key VALUE         Existing/generated AES key. Generated if absent.
  --api-key VALUE            API key. Generated if absent.
  --vps-public-ip VALUE      Public IP used as VPN endpoint.
  --skip-infra               Skip scripts/setup-vpn-infra.sh.
  --skip-build               Skip make build.
  --skip-systemd             Skip systemd unit creation.
  --no-start                 Do not restart service.
  --dry-run                  Print actions without changing files/services.
  -h, --help                 Show help.
EOF
}

log() { printf '[INFO] %s\n' "$*"; }
ok() { printf '[OK] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

run() {
    if [[ "$DRY_RUN" == "1" ]]; then
        printf '[DRY-RUN] %q' "$1"
        shift
        for arg in "$@"; do printf ' %q' "$arg"; done
        printf '\n'
        return 0
    fi
    "$@"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --app-dir) APP_DIR="$2"; shift 2 ;;
        --env-file) ENV_FILE="$2"; shift 2 ;;
        --listen-addr) LISTEN_ADDR="$2"; shift 2 ;;
        --db-host) DB_HOST="$2"; shift 2 ;;
        --db-port) DB_PORT="$2"; shift 2 ;;
        --db-user) DB_USER="$2"; shift 2 ;;
        --db-password) DB_PASSWORD="$2"; shift 2 ;;
        --db-name) DB_NAME="$2"; shift 2 ;;
        --db-ssl-mode) DB_SSL_MODE="$2"; shift 2 ;;
        --master-key) MASTER_KEY="$2"; shift 2 ;;
        --api-key) API_KEY="$2"; shift 2 ;;
        --vps-public-ip) VPS_PUBLIC_IP="$2"; shift 2 ;;
        --skip-infra) RUN_INFRA=0; shift ;;
        --skip-build) RUN_BUILD=0; shift ;;
        --skip-systemd) RUN_SYSTEMD=0; shift ;;
        --no-start) START_SERVICE=0; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "Unknown option: $1" ;;
    esac
done

APP_DIR="$(cd "$APP_DIR" && pwd)"
ENV_FILE="$(readlink -m "$ENV_FILE")"

[[ -f "${APP_DIR}/go.mod" ]] || fail "go.mod not found in ${APP_DIR}"
[[ -f "${APP_DIR}/cmd/server/main.go" ]] || fail "cmd/server/main.go not found in ${APP_DIR}"

if [[ "$DRY_RUN" != "1" && "$EUID" -ne 0 && ( "$RUN_INFRA" == "1" || "$RUN_SYSTEMD" == "1" || "$START_SERVICE" == "1" ) ]]; then
    fail "Run as root: sudo $0 ..."
fi

existing_env_value() {
    local key="$1"
    [[ -f "$ENV_FILE" ]] || return 0
    awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$ENV_FILE"
}

backup_env() {
    [[ -f "$ENV_FILE" ]] || return 0
    local backup="${ENV_FILE}.bak.$(date +%Y%m%d%H%M%S)"
    run cp "$ENV_FILE" "$backup"
    ok "Backup env: ${backup}"
}

set_env_var() {
    local key="$1" value="$2"
    local dir tmp
    dir="$(dirname "$ENV_FILE")"
    if [[ "$DRY_RUN" == "1" ]]; then
        log "Set ${key} in ${ENV_FILE}"
        return 0
    fi
    mkdir -p "$dir"
    touch "$ENV_FILE"
    tmp="$(mktemp)"
    awk -v key="$key" -v value="$value" '
        BEGIN { done = 0 }
        $0 ~ "^" key "=" { print key "=" value; done = 1; next }
        { print }
        END { if (!done) print key "=" value }
    ' "$ENV_FILE" > "$tmp"
    cat "$tmp" > "$ENV_FILE"
    rm -f "$tmp"
}

require_value() {
    local name="$1" value="$2"
    [[ -n "$value" ]] || fail "${name} is required"
}

generate_base64_32() {
    openssl rand -base64 32
}

generate_hex_32() {
    openssl rand -hex 32
}

if [[ -z "$DB_HOST" ]]; then DB_HOST="$(existing_env_value DB_HOST)"; fi
if [[ -z "$DB_USER" ]]; then DB_USER="$(existing_env_value DB_USER)"; fi
if [[ -z "$DB_PASSWORD" ]]; then DB_PASSWORD="$(existing_env_value DB_PASSWORD)"; fi
if [[ -z "$DB_NAME" ]]; then DB_NAME="$(existing_env_value DB_NAME)"; fi
if [[ -z "$MASTER_KEY" ]]; then MASTER_KEY="$(existing_env_value MASTER_KEY)"; fi
if [[ -z "$API_KEY" ]]; then API_KEY="$(existing_env_value API_KEY)"; fi
if [[ -z "$VPS_PUBLIC_IP" ]]; then VPS_PUBLIC_IP="$(existing_env_value VPS_PUBLIC_IP)"; fi

require_value "--db-host/DB_HOST" "$DB_HOST"
require_value "--db-user/DB_USER" "$DB_USER"
require_value "--db-password/DB_PASSWORD" "$DB_PASSWORD"
require_value "--db-name/DB_NAME" "$DB_NAME"
require_value "--vps-public-ip/VPS_PUBLIC_IP" "$VPS_PUBLIC_IP"

if [[ -z "$MASTER_KEY" || "$MASTER_KEY" == "your-master-key-here" ]]; then
    MASTER_KEY="$(generate_base64_32)"
    ok "Generated MASTER_KEY"
else
    ok "Using existing MASTER_KEY"
fi

if [[ -z "$API_KEY" || "$API_KEY" == "your-api-key-here" ]]; then
    API_KEY="$(generate_hex_32)"
    ok "Generated API_KEY"
else
    ok "Using existing API_KEY"
fi

if [[ "$RUN_BUILD" == "1" ]]; then
    log "Building binary"
    run make -C "$APP_DIR" build
fi

if [[ "$RUN_INFRA" == "1" ]]; then
    log "Setting up host VPN infrastructure"
    run "${APP_DIR}/scripts/setup-vpn-infra.sh"
fi

log "Writing production env"
backup_env
set_env_var APP_ENV "$APP_ENV"
set_env_var LISTEN_ADDR "$LISTEN_ADDR"
set_env_var DB_HOST "$DB_HOST"
set_env_var DB_PORT "$DB_PORT"
set_env_var DB_USER "$DB_USER"
set_env_var DB_PASSWORD "$DB_PASSWORD"
set_env_var DB_NAME "$DB_NAME"
set_env_var DB_SSL_MODE "$DB_SSL_MODE"
set_env_var MASTER_KEY "$MASTER_KEY"
set_env_var API_KEY "$API_KEY"
set_env_var VPS_PUBLIC_IP "$VPS_PUBLIC_IP"
run chown root:root "$ENV_FILE"
run chmod 600 "$ENV_FILE"

if [[ "$RUN_SYSTEMD" == "1" ]]; then
    log "Installing systemd unit"
    if [[ "$DRY_RUN" == "1" ]]; then
        log "Would write /etc/systemd/system/${SERVICE_NAME}.service"
    else
        cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Jinom VPN Tunnel Manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${APP_DIR}/bin/jinom-vpn
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    fi
    run systemctl daemon-reload
    run systemctl enable "$SERVICE_NAME"
fi

if [[ "$START_SERVICE" == "1" ]]; then
    log "Restarting ${SERVICE_NAME}"
    run systemctl restart "$SERVICE_NAME"
    run systemctl --no-pager --lines=20 status "$SERVICE_NAME"
fi

if command -v curl >/dev/null 2>&1; then
    log "Health check"
    HEALTH_URL="http://127.0.0.1${LISTEN_ADDR}/health"
    if [[ "$DRY_RUN" == "1" ]]; then
        log "Would call ${HEALTH_URL}"
    else
        curl --connect-timeout 3 --max-time 5 -fsS "$HEALTH_URL" || warn "Health check failed"
        printf '\n'
    fi
fi

ok "Production install complete"
printf 'API_KEY=%s\n' "$API_KEY"
