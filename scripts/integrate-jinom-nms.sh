#!/usr/bin/env bash
#
# Wire jinom-nms to an existing jinom-vpn production service.
#
# Usage:
#   ./scripts/integrate-jinom-nms.sh \
#     --nms-dir /opt/jinom-nms \
#     --vpn-url http://10.0.0.20:8090/api/v1 \
#     --api-key 'same-key-as-jinom-vpn' \
#     --patch-compose \
#     --restart
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPN_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
NMS_DIR="$(readlink -m "${VPN_DIR}/../jinom-nms")"
ENV_FILE=""
COMPOSE_FILE=""
VPN_URL=""
API_KEY=""
PATCH_COMPOSE=0
RESTART_NMS=0
DRY_RUN=0

usage() {
    cat <<'EOF'
Wire jinom-nms to an existing jinom-vpn production service.

Usage:
  ./scripts/integrate-jinom-nms.sh \
    --nms-dir /opt/jinom-nms \
    --vpn-url http://10.0.0.20:8090/api/v1 \
    --api-key 'same-key-as-jinom-vpn' \
    --patch-compose \
    --restart

Options:
  --nms-dir PATH             jinom-nms project path. Default: sibling ../jinom-nms.
  --env-file PATH            jinom-nms env file. Default: <nms-dir>/.env.
  --compose-file PATH        Compose file. Default: <nms-dir>/deploy/docker-compose.prod.yml.
  --vpn-url URL              VPN API base URL, e.g. http://10.0.0.20:8090/api/v1.
  --api-key VALUE            Must match jinom-vpn API_KEY.
  --from-vpn-env PATH        Read API_KEY from jinom-vpn env if --api-key absent.
  --patch-compose            Add VPN_SERVICE_* env passthrough to compose server/worker.
  --restart                  Run make prod-restart in jinom-nms after changes.
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

env_value() {
    local file="$1" key="$2"
    [[ -f "$file" ]] || return 0
    awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$file"
}

set_env_var() {
    local file="$1" key="$2" value="$3"
    local tmp
    if [[ "$DRY_RUN" == "1" ]]; then
        log "Set ${key} in ${file}"
        return 0
    fi
    mkdir -p "$(dirname "$file")"
    touch "$file"
    tmp="$(mktemp)"
    awk -v key="$key" -v value="$value" '
        BEGIN { done = 0 }
        $0 ~ "^" key "=" { print key "=" value; done = 1; next }
        { print }
        END { if (!done) print key "=" value }
    ' "$file" > "$tmp"
    cat "$tmp" > "$file"
    rm -f "$tmp"
}

backup_file() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    local backup="${file}.bak.$(date +%Y%m%d%H%M%S)"
    run cp "$file" "$backup"
    ok "Backup: ${backup}"
}

patch_compose_file() {
    local file="$1"

    if grep -q "VPN_SERVICE_URL" "$file" && grep -q "VPN_SERVICE_API_KEY" "$file"; then
        ok "Compose already contains VPN_SERVICE_*"
        return 0
    fi

    if [[ "$DRY_RUN" == "1" ]]; then
        log "Would patch ${file} with VPN_SERVICE_* for server and worker"
        return 0
    fi

    local tmp
    tmp="$(mktemp)"
    awk '
        function emit_vpn() {
            if (!inserted[current]) {
                print "      - VPN_SERVICE_URL=${VPN_SERVICE_URL:-}"
                print "      - VPN_SERVICE_API_KEY=${VPN_SERVICE_API_KEY:-}"
                inserted[current] = 1
            }
        }

        /^  server:$/ { current = "server"; in_target = 1; in_env = 0; print; next }
        /^  worker:$/ { current = "worker"; in_target = 1; in_env = 0; print; next }
        /^  [A-Za-z0-9_-]+:$/ {
            if (in_target && in_env) emit_vpn()
            current = ""; in_target = 0; in_env = 0
            print; next
        }
        in_target && /^    environment:$/ { in_env = 1; print; next }
        in_target && in_env && /^    [A-Za-z0-9_-]+:/ {
            emit_vpn()
            in_env = 0
            print; next
        }
        in_target && in_env && /VPN_SERVICE_URL/ { inserted[current] = 1 }
        { print }
        END {
            if (in_target && in_env) emit_vpn()
        }
    ' "$file" > "$tmp"
    cat "$tmp" > "$file"
    rm -f "$tmp"

    if grep -q "VPN_SERVICE_URL" "$file" && grep -q "VPN_SERVICE_API_KEY" "$file"; then
        ok "Compose patched"
    else
        fail "Compose patch failed"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --nms-dir) NMS_DIR="$2"; shift 2 ;;
        --env-file) ENV_FILE="$2"; shift 2 ;;
        --compose-file) COMPOSE_FILE="$2"; shift 2 ;;
        --vpn-url) VPN_URL="$2"; shift 2 ;;
        --api-key) API_KEY="$2"; shift 2 ;;
        --from-vpn-env)
            if [[ -z "$API_KEY" ]]; then API_KEY="$(env_value "$2" API_KEY)"; fi
            shift 2
            ;;
        --patch-compose) PATCH_COMPOSE=1; shift ;;
        --restart) RESTART_NMS=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "Unknown option: $1" ;;
    esac
done

NMS_DIR="$(readlink -m "$NMS_DIR")"
if [[ -z "$ENV_FILE" ]]; then ENV_FILE="${NMS_DIR}/.env"; fi
if [[ -z "$COMPOSE_FILE" ]]; then COMPOSE_FILE="${NMS_DIR}/deploy/docker-compose.prod.yml"; fi
ENV_FILE="$(readlink -m "$ENV_FILE")"
COMPOSE_FILE="$(readlink -m "$COMPOSE_FILE")"

[[ -d "$NMS_DIR" ]] || fail "jinom-nms dir not found: ${NMS_DIR}"
[[ -f "${NMS_DIR}/Makefile" ]] || warn "Makefile not found in ${NMS_DIR}"
[[ -f "$COMPOSE_FILE" ]] || warn "Compose file not found: ${COMPOSE_FILE}"

if [[ -z "$API_KEY" && -f "${VPN_DIR}/.env" ]]; then
    API_KEY="$(env_value "${VPN_DIR}/.env" API_KEY)"
fi

[[ -n "$VPN_URL" ]] || fail "--vpn-url is required"
[[ -n "$API_KEY" ]] || fail "--api-key is required, or use --from-vpn-env PATH"

case "$VPN_URL" in
    */api/v1) ;;
    *) warn "VPN URL usually should end with /api/v1" ;;
esac

log "Updating jinom-nms env"
backup_file "$ENV_FILE"
set_env_var "$ENV_FILE" VPN_SERVICE_URL "$VPN_URL"
set_env_var "$ENV_FILE" VPN_SERVICE_API_KEY "$API_KEY"

if [[ "$PATCH_COMPOSE" == "1" ]]; then
    [[ -f "$COMPOSE_FILE" ]] || fail "Cannot patch missing compose file: ${COMPOSE_FILE}"
    log "Patching compose env passthrough"
    backup_file "$COMPOSE_FILE"
    patch_compose_file "$COMPOSE_FILE"
else
    if [[ -f "$COMPOSE_FILE" ]] && ! grep -q "VPN_SERVICE_URL" "$COMPOSE_FILE"; then
        warn "Compose file does not pass VPN_SERVICE_* into containers. Re-run with --patch-compose if production uses docker compose."
    fi
fi

log "Testing jinom-vpn health from this host"
HEALTH_URL="${VPN_URL%/api/v1}/health"
if command -v curl >/dev/null 2>&1; then
    if [[ "$DRY_RUN" == "1" ]]; then
        log "Would call ${HEALTH_URL}"
    else
        curl --connect-timeout 3 --max-time 5 -fsS "$HEALTH_URL" || warn "Health check failed: ${HEALTH_URL}"
        printf '\n'
    fi
else
    warn "curl not found; skip health check"
fi

if [[ "$RESTART_NMS" == "1" ]]; then
    log "Restarting jinom-nms production compose"
    run make -C "$NMS_DIR" prod-restart
else
    warn "jinom-nms not restarted. Use --restart after reviewing changes."
fi

ok "jinom-nms integration complete"
