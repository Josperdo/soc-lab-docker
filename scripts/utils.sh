#!/usr/bin/env bash
# ============================================================================
# SOC Lab Docker – Shared Script Utilities
# ============================================================================
#
# Source this file from attack simulation scripts:
#   source "$(dirname "$0")/utils.sh"
#
# Provides:
#   log_info, log_warn, log_error  – Colored timestamped output
#   check_lab_running               – Verify Elasticsearch is reachable
#   wait_for_service                – Poll a URL until it responds
#   write_event                     – Append a JSON event to the lab log file
#   random_ip                       – Generate a random IP in a given CIDR
#   cleanup                         – Graceful exit trap
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults (override via env)
# ---------------------------------------------------------------------------
ES_HOST="${ES_HOST:-http://localhost:9200}"
LOG_FILE="${LOG_FILE:-./data/logs/attack-simulation.json}"
SCRIPT_NAME="${SCRIPT_NAME:-$(basename "${BASH_SOURCE[1]:-utils.sh}")}"

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
_RED='\033[0;31m'
_YELLOW='\033[1;33m'
_GREEN='\033[0;32m'
_CYAN='\033[0;36m'
_BOLD='\033[1m'
_RESET='\033[0m'

# Disable colors if not a TTY
if [ ! -t 1 ]; then
    _RED='' _YELLOW='' _GREEN='' _CYAN='' _BOLD='' _RESET=''
fi

# ---------------------------------------------------------------------------
# Logging functions
# ---------------------------------------------------------------------------
_ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

log_info() {
    echo -e "${_GREEN}[$(_ts)]${_RESET} ${_BOLD}[INFO]${_RESET}  ${SCRIPT_NAME}: $*"
}

log_warn() {
    echo -e "${_YELLOW}[$(_ts)]${_RESET} ${_BOLD}[WARN]${_RESET}  ${SCRIPT_NAME}: $*" >&2
}

log_error() {
    echo -e "${_RED}[$(_ts)]${_RESET} ${_BOLD}[ERROR]${_RESET} ${SCRIPT_NAME}: $*" >&2
}

log_step() {
    echo -e "${_CYAN}[$(_ts)]${_RESET} ${_BOLD}[STEP]${_RESET}  ${SCRIPT_NAME}: $*"
}

# ---------------------------------------------------------------------------
# Service health checks
# ---------------------------------------------------------------------------

# Check if Elasticsearch is reachable and not red
check_lab_running() {
    local status
    status=$(curl -sf "${ES_HOST}/_cluster/health" 2>/dev/null | grep -o '"status":"[^"]*"' | cut -d'"' -f4 || true)
    if [[ "$status" == "green" || "$status" == "yellow" ]]; then
        return 0
    fi
    log_error "Elasticsearch not reachable at ${ES_HOST} (status=${status:-unreachable})"
    log_error "Is the lab running? Try: docker-compose up -d"
    return 1
}

# Poll a URL until it returns HTTP 200 or times out
# Usage: wait_for_service <url> [timeout_seconds] [description]
wait_for_service() {
    local url="${1:?URL required}"
    local timeout="${2:-60}"
    local desc="${3:-service}"
    local elapsed=0

    log_info "Waiting for ${desc} at ${url} (timeout: ${timeout}s)"
    while ! curl -sf "$url" > /dev/null 2>&1; do
        if (( elapsed >= timeout )); then
            log_error "Timed out waiting for ${desc}"
            return 1
        fi
        sleep 2
        elapsed=$(( elapsed + 2 ))
    done
    log_info "${desc} is ready"
}

# ---------------------------------------------------------------------------
# Event writer
# ---------------------------------------------------------------------------

# Append a single JSON event to the lab log file (picked up by Filebeat)
# Usage: write_event '{"@timestamp": "...", "event": {...}, ...}'
write_event() {
    local json="${1:?JSON event string required}"
    local dir
    dir="$(dirname "$LOG_FILE")"

    mkdir -p "$dir"
    printf '%s\n' "$json" >> "$LOG_FILE"
}

# Build a JSON authentication event string
# Usage: make_auth_event <outcome> <username> <src_ip> <dst_host> [service]
make_auth_event() {
    local outcome="${1:-failure}"
    local username="${2:-unknown}"
    local src_ip="${3:-127.0.0.1}"
    local dst_host="${4:-workstation-01}"
    local service="${5:-sshd}"
    local ts
    ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
    local username_j="${username//\\/\\\\}"
    username_j="${username_j//\"/\\\"}"

    cat <<JSON
{"@timestamp":"${ts}","event":{"category":["authentication"],"action":"logon","outcome":"${outcome}","kind":"event","dataset":"soc-lab.authentication"},"user":{"name":"${username_j}"},"source":{"ip":"${src_ip}","port":$((RANDOM % 60000 + 1024))},"destination":{"ip":"10.0.1.$((RANDOM % 200 + 10))","port":$([[ "$service" == "rdp" ]] && echo 3389 || echo 22)},"authentication":{"service":"${service}","type":"network"},"host":{"name":"${dst_host}"},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON
}

# Build a JSON process execution event string
# Usage: make_process_event <parent> <child> <cmdline> <username> <hostname>
make_process_event() {
    local parent="${1:-explorer.exe}"
    local child="${2:-cmd.exe}"
    local cmdline="${3:-cmd.exe}"
    local username="${4:-unknown}"
    local hostname="${5:-workstation-01}"
    local ts
    ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
    local cmdline_j="${cmdline//\\/\\\\}"
    cmdline_j="${cmdline_j//\"/\\\"}"

    cat <<JSON
{"@timestamp":"${ts}","event":{"category":["process"],"action":"process_started","outcome":"success","kind":"event","dataset":"soc-lab.process_execution","type":["start"]},"process":{"name":"${child}","executable":"C:\\\\Windows\\\\System32\\\\${child}","command_line":"${cmdline_j}","pid":$((RANDOM % 60000 + 1000)),"parent":{"name":"${parent}","pid":$((RANDOM % 1000 + 100))}},"user":{"name":"${username}"},"host":{"name":"${hostname}","os":{"type":"windows"}},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON
}

# Build a JSON network event string
# Usage: make_network_event <src_ip> <dst_ip> <dst_port> <bytes_out> <hostname>
make_network_event() {
    local src_ip="${1:-10.0.1.100}"
    local dst_ip="${2:-198.51.100.1}"
    local dst_port="${3:-443}"
    local bytes_out="${4:-1024}"
    local hostname="${5:-workstation-01}"
    local ts
    ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')

    cat <<JSON
{"@timestamp":"${ts}","event":{"category":["network"],"action":"network_flow","outcome":"success","kind":"event","dataset":"soc-lab.network"},"source":{"ip":"${src_ip}","port":$((RANDOM % 60000 + 1024)),"bytes":${bytes_out}},"destination":{"ip":"${dst_ip}","port":${dst_port},"bytes":$((bytes_out / 10))},"network":{"transport":"tcp","direction":"outbound","bytes":${bytes_out}},"host":{"name":"${hostname}"},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON
}

# Build a JSON registry modification event string
# Usage: make_registry_event <action> <key_path> <value_name> <value_data> <username> <hostname>
make_registry_event() {
    local action="${1:-value_set}"
    local key_path="${2:-HKCU\\SOFTWARE\\Test}"
    local value_name="${3:-NewValue}"
    local value_data="${4:-data}"
    local username="${5:-unknown}"
    local hostname="${6:-workstation-01}"
    local ts
    ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
    local kp="${key_path//\\/\\\\}"
    local vd="${value_data//\\/\\\\}"
    vd="${vd//\"/\\\"}"

    cat <<JSON
{"@timestamp":"${ts}","event":{"category":["registry"],"action":"${action}","outcome":"success","kind":"event","dataset":"soc-lab.registry"},"registry":{"path":"${kp}\\\\${value_name}","key":"${kp}","value":{"name":"${value_name}","data":"${vd}"}},"user":{"name":"${username}"},"host":{"name":"${hostname}","os":{"type":"windows"}},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON
}

# Build a JSON DNS query event string
# Usage: make_dns_event <query_name> <resolved_ip> <client_hostname>
make_dns_event() {
    local query="${1:-example.com}"
    local resolved="${2:-198.51.100.1}"
    local hostname="${3:-workstation-01}"
    local ts
    ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')

    cat <<JSON
{"@timestamp":"${ts}","event":{"category":["network"],"action":"dns_query","outcome":"success","kind":"event","dataset":"soc-lab.dns"},"dns":{"question":{"name":"${query}","type":"A"},"resolved_ip":["${resolved}"],"response_code":"NOERROR"},"source":{"ip":"$(random_internal_ip)"},"host":{"name":"${hostname}"},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Generate a random RFC 5737 test IP (or fake external IP)
random_external_ip() {
    echo "203.$((RANDOM % 255)).$((RANDOM % 255)).$((RANDOM % 254 + 1))"
}

random_internal_ip() {
    echo "10.0.$((RANDOM % 5 + 1)).$((RANDOM % 200 + 10))"
}

# Sleep with configurable delay (reads ATTACK_STEP_DELAY_MS env var)
step_delay() {
    local ms="${ATTACK_STEP_DELAY_MS:-500}"
    sleep "$(awk "BEGIN {printf \"%.3f\", $ms/1000}")"
}

# ---------------------------------------------------------------------------
# Cleanup trap
# ---------------------------------------------------------------------------
_cleanup() {
    local exit_code=$?
    if (( exit_code != 0 )); then
        log_warn "Script exited with code ${exit_code}"
    fi
    log_info "Simulation complete."
}
trap _cleanup EXIT
