#!/usr/bin/env bash
# ============================================================================
# SOC Lab Docker – Alert Notifier
# ============================================================================
#
# Polls Elasticsearch for events matching alert rules defined in
# alerts/rules/*.yml, evaluates thresholds, and sends notifications
# via Slack webhook or generic HTTP webhook when rules fire.
#
# Usage:
#   bash scripts/alert_notifier.sh [--once] [--rules-dir <path>]
#
# Options:
#   --once           Run evaluation once and exit (default: loop every 60s)
#   --rules-dir DIR  Override default rules directory (default: ./alerts/rules)
#   --dry-run        Evaluate rules and print alerts without sending notifications
#
# Environment variables (set in .env or export before running):
#   ES_HOST          Elasticsearch host (default: http://localhost:9200)
#   SLACK_WEBHOOK_URL  Slack Incoming Webhook URL for Slack notifications
#   WEBHOOK_URL        Generic HTTP webhook URL for custom integrations
#   ALERT_INTERVAL   Seconds between polling cycles (default: 60)
#   LOOKBACK         Seconds of history to search (default: 300 = 5 minutes)
#
# Alert rule format: alerts/rules/*.yml
#   See docs/ALERTING.md for the full rule schema.
#
# ============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ES_HOST="${ES_HOST:-http://localhost:9200}"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
WEBHOOK_URL="${WEBHOOK_URL:-}"
ALERT_INTERVAL="${ALERT_INTERVAL:-60}"
LOOKBACK="${LOOKBACK:-300}"
RULES_DIR="${RULES_DIR:-${REPO_ROOT}/alerts/rules}"
DRY_RUN=false
RUN_ONCE=false

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --once)        RUN_ONCE=true ;;
        --dry-run)     DRY_RUN=true ;;
        --rules-dir)   RULES_DIR="$2"; shift ;;
        *) echo "[WARN] Unknown option: $1" ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------
log()  { echo "[$(date -u '+%H:%M:%SZ')] $*"; }
warn() { echo "[$(date -u '+%H:%M:%SZ')] [WARN] $*" >&2; }

check_deps() {
    local missing=()
    for cmd in curl jq; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "Missing required tools: ${missing[*]}"
        warn "Install with: apt-get install ${missing[*]}  (or brew install ...)"
        exit 1
    fi
}

es_reachable() {
    local status
    status=$(curl -s --max-time 5 "${ES_HOST}/_cluster/health" | jq -r '.status' 2>/dev/null || echo "unreachable")
    [[ "$status" != "unreachable" ]]
}

# ---------------------------------------------------------------------------
# Query Elasticsearch
# ---------------------------------------------------------------------------
# Returns the document count matching the given ES query JSON body.
#
# Usage: es_count <index-pattern> <query-json>
es_count() {
    local index="$1"
    local query="$2"
    local now
    now=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    local since
    since=$(date -u -d "@$(( $(date +%s) - LOOKBACK ))" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
        || date -u -r "$(( $(date +%s) - LOOKBACK ))" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
        || echo "now-${LOOKBACK}s")

    # Wrap the caller's query in a time-bounded bool filter
    local full_query
    full_query=$(jq -n \
        --argjson inner "$query" \
        --arg since "$since" \
        --arg until "$now" \
        '{
            query: {
                bool: {
                    must: [$inner],
                    filter: [{
                        range: {
                            "@timestamp": { gte: $since, lte: $until }
                        }
                    }]
                }
            }
        }')

    curl -s --max-time 10 \
        -X GET "${ES_HOST}/${index}/_count" \
        -H 'Content-Type: application/json' \
        -d "$full_query" \
        | jq -r '.count // 0'
}

# ---------------------------------------------------------------------------
# Notification backends
# ---------------------------------------------------------------------------
send_slack() {
    local rule_name="$1"
    local severity="$2"
    local message="$3"
    local mitre="$4"

    [[ -z "$SLACK_WEBHOOK_URL" ]] && { warn "SLACK_WEBHOOK_URL not set — skipping Slack notification"; return; }

    local color
    case "$severity" in
        critical) color="#FF0000" ;;
        high)     color="#FF6600" ;;
        medium)   color="#FFCC00" ;;
        *)        color="#36A64F" ;;
    esac

    local payload
    payload=$(jq -n \
        --arg rule    "$rule_name" \
        --arg sev     "$severity" \
        --arg msg     "$message" \
        --arg color   "$color" \
        --arg mitre   "$mitre" \
        --arg ts      "$(date -u '+%Y-%m-%d %H:%M:%S UTC')" \
        '{
            text: ("🚨 SOC Lab Alert: " + $rule),
            attachments: [{
                color: $color,
                fields: [
                    { title: "Rule",     value: $rule,  short: true },
                    { title: "Severity", value: $sev,   short: true },
                    { title: "MITRE",    value: $mitre, short: true },
                    { title: "Time",     value: $ts,    short: true },
                    { title: "Details",  value: $msg,   short: false }
                ]
            }]
        }')

    if $DRY_RUN; then
        log "[DRY-RUN] Would send Slack: ${payload}"
    else
        curl -s -X POST -H 'Content-Type: application/json' \
            -d "$payload" "$SLACK_WEBHOOK_URL" >/dev/null
        log "Slack notification sent for rule: ${rule_name}"
    fi
}

send_webhook() {
    local rule_name="$1"
    local severity="$2"
    local message="$3"
    local mitre="$4"

    [[ -z "$WEBHOOK_URL" ]] && { warn "WEBHOOK_URL not set — skipping webhook notification"; return; }

    local payload
    payload=$(jq -n \
        --arg rule    "$rule_name" \
        --arg sev     "$severity" \
        --arg msg     "$message" \
        --arg mitre   "$mitre" \
        --arg ts      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        '{
            alert: {
                rule:      $rule,
                severity:  $sev,
                message:   $msg,
                mitre:     ($mitre | split(", ")),
                timestamp: $ts,
                source:    "soc-lab-docker"
            }
        }')

    if $DRY_RUN; then
        log "[DRY-RUN] Would POST webhook: ${WEBHOOK_URL}"
        log "[DRY-RUN] Payload: ${payload}"
    else
        curl -s -X POST -H 'Content-Type: application/json' \
            -d "$payload" "$WEBHOOK_URL" >/dev/null
        log "Webhook notification sent for rule: ${rule_name}"
    fi
}

notify() {
    local rule_name="$1"
    local severity="$2"
    local message="$3"
    local mitre="$4"
    local channels="$5"  # comma-separated: slack,webhook

    log "ALERT FIRED: [${severity^^}] ${rule_name}"
    log "  ${message}"

    if [[ "$channels" == *"slack"* ]]; then
        send_slack "$rule_name" "$severity" "$message" "$mitre"
    fi
    if [[ "$channels" == *"webhook"* ]]; then
        send_webhook "$rule_name" "$severity" "$message" "$mitre"
    fi
}

# ---------------------------------------------------------------------------
# Built-in rule evaluators
# Each function queries ES and fires an alert if the threshold is met.
# ---------------------------------------------------------------------------

eval_brute_force() {
    local count
    count=$(es_count "soc-lab*" \
        '{"bool":{"must":[{"term":{"event.category":"authentication"}},{"term":{"event.outcome":"failure"}}]}}')

    log "  brute_force_authentication: ${count} failures in last ${LOOKBACK}s"

    if (( count > 10 )); then
        notify \
            "brute_force_authentication" \
            "high" \
            "${count} authentication failures detected in the last ${LOOKBACK}s. Investigate source.ip distribution." \
            "T1110, T1110.001, T1110.003" \
            "slack,webhook"
    fi
}

eval_psexec() {
    local count
    count=$(es_count "soc-lab*" \
        '{"bool":{"must":[{"term":{"event.category":"process"}}],"should":[{"term":{"process.name":"PSEXESVC.exe"}},{"term":{"process.parent.name":"PSEXESVC.exe"}}],"minimum_should_match":1}}')

    log "  psexec_lateral_movement: ${count} events in last ${LOOKBACK}s"

    if (( count >= 1 )); then
        notify \
            "psexec_lateral_movement" \
            "high" \
            "${count} PSEXESVC.exe process events detected — possible lateral movement via PsExec." \
            "T1021.002, T1570, T1543.003" \
            "slack,webhook"
    fi
}

eval_large_transfer() {
    local count
    count=$(es_count "soc-lab*" \
        '{"bool":{"must":[{"term":{"event.category":"network"}},{"term":{"network.transport":"tcp"}},{"term":{"event.outcome":"success"}}],"must_not":[{"terms":{"destination.port":[80,443,53,22,25,143,465,587,993,995]}}]}}')

    log "  large_data_transfer: ${count} non-standard port connections in last ${LOOKBACK}s"

    if (( count > 10 )); then
        notify \
            "large_data_transfer" \
            "medium" \
            "${count} outbound connections on non-standard ports in the last ${LOOKBACK}s. Review destination IPs and ports." \
            "T1041, T1048, T1048.003" \
            "slack,webhook"
    fi
}

eval_wmi_execution() {
    local count
    count=$(es_count "soc-lab*" \
        '{"bool":{"must":[{"term":{"event.category":"process"}},{"term":{"process.parent.name":"WmiPrvSE.exe"}},{"terms":{"process.name":["cmd.exe","powershell.exe"]}}]}}')

    log "  wmi_remote_execution: ${count} WmiPrvSE.exe shell spawn events in last ${LOOKBACK}s"

    if (( count >= 1 )); then
        notify \
            "wmi_remote_execution" \
            "high" \
            "${count} event(s) of WmiPrvSE.exe spawning an interactive shell — possible WMI lateral movement." \
            "T1047, T1021" \
            "slack,webhook"
    fi
}

eval_scheduled_task() {
    local count
    count=$(es_count "soc-lab*" \
        '{"bool":{"must":[{"term":{"event.category":"process"}},{"term":{"process.name":"schtasks.exe"}}],"should":[{"match":{"process.command_line":"/create"}},{"match":{"process.command_line":"powershell"}},{"match":{"process.command_line":"-EncodedCommand"}}],"minimum_should_match":1}}')

    log "  scheduled_task_persistence: ${count} suspicious schtasks.exe events in last ${LOOKBACK}s"

    if (( count >= 1 )); then
        notify \
            "scheduled_task_persistence" \
            "medium" \
            "${count} schtasks.exe creation event(s) with suspicious parameters detected." \
            "T1053.005" \
            "slack,webhook"
    fi
}

# ---------------------------------------------------------------------------
# Main evaluation loop
# ---------------------------------------------------------------------------
run_evaluation() {
    log "Starting alert evaluation (lookback: ${LOOKBACK}s, rules dir: ${RULES_DIR})"

    if ! es_reachable; then
        warn "Elasticsearch not reachable at ${ES_HOST} — skipping evaluation"
        return
    fi

    log "Evaluating built-in alert rules..."
    eval_brute_force
    eval_psexec
    eval_large_transfer
    eval_wmi_execution
    eval_scheduled_task

    log "Evaluation complete."
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
check_deps

log "============================================"
log "  SOC Lab Alert Notifier"
log "============================================"
log "ES host        : ${ES_HOST}"
log "Lookback       : ${LOOKBACK}s"
log "Interval       : ${ALERT_INTERVAL}s"
log "Dry run        : ${DRY_RUN}"
log "Run once       : ${RUN_ONCE}"
log "Slack webhook  : ${SLACK_WEBHOOK_URL:+(configured)}"
log "Generic webhook: ${WEBHOOK_URL:+(configured)}"
log "--------------------------------------------"

if $RUN_ONCE; then
    run_evaluation
else
    log "Entering polling loop (Ctrl+C to stop)..."
    while true; do
        run_evaluation
        log "Sleeping ${ALERT_INTERVAL}s until next evaluation..."
        sleep "$ALERT_INTERVAL"
    done
fi
