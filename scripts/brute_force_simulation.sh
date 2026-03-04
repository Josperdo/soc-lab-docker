#!/usr/bin/env bash
# ============================================================================
# SOC Lab Docker – Brute Force Attack Simulation
# ============================================================================
#
# Simulates a credential brute force attack against a target host.
# Generates rapid successive authentication failure events followed by a
# final success (simulating a successful credential stuffing attempt).
#
# MITRE ATT&CK:
#   T1110     – Brute Force
#   T1110.001 – Password Guessing
#   T1110.003 – Password Spraying
#   T1078     – Valid Accounts (final success)
#
# DISCLAIMER:
#   This script generates SYNTHETIC LOG EVENTS ONLY. No real network connections
#   are made, no actual attacks are performed, and no systems are compromised.
#   For authorized lab and educational use only. Do not run against systems you
#   do not own or have explicit written permission to test.
#
# Usage:
#   bash scripts/brute_force_simulation.sh [options]
#
# Options (or set as environment variables):
#   TARGET_HOST     – Hostname of target (default: web-server-01)
#   TARGET_USER     – Username to attack (default: admin)
#   ATTEMPT_COUNT   – Number of failed attempts (default: 50)
#   ATTACK_DELAY_MS – Milliseconds between attempts (default: 100)
#   LOG_FILE        – Output log file (default: ./data/logs/attack-simulation.json)
#
# Expected detections:
#   - Brute force: >10 failures from same IP in 5 minutes
#   - Success after failures: auth success following run of failures (T1078)
#
# See detections/authentication/brute_force_detection.spl for the matching query.
# ============================================================================

set -euo pipefail
SCRIPT_NAME="brute_force_simulation"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TARGET_HOST="${TARGET_HOST:-web-server-01}"
TARGET_USER="${TARGET_USER:-admin}"
ATTEMPT_COUNT="${ATTEMPT_COUNT:-50}"
ATTACK_DELAY_MS="${ATTACK_STEP_DELAY_MS:-100}"
SERVICE="${SERVICE:-sshd}"

# Attacker comes from a single external IP (realistic credential stuffing)
ATTACKER_IP="$(random_external_ip)"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
log_info "============================================"
log_info "  Brute Force Attack Simulation"
log_info "============================================"
log_info "Target host : ${TARGET_HOST}"
log_info "Target user : ${TARGET_USER}"
log_info "Attempts    : ${ATTEMPT_COUNT} failures + 1 success"
log_info "Attacker IP : ${ATTACKER_IP}"
log_info "Service     : ${SERVICE}"
log_info "Output file : ${LOG_FILE}"
log_info "--------------------------------------------"

# Warn if lab is not running (non-fatal – events still get written)
if ! check_lab_running 2>/dev/null; then
    log_warn "Lab does not appear to be running. Events will be written to file only."
    log_warn "Start the lab with: docker-compose up -d"
fi

# ---------------------------------------------------------------------------
# Phase 1: Failed authentication attempts
# ---------------------------------------------------------------------------
log_step "Phase 1 – Generating ${ATTEMPT_COUNT} authentication failure events"

for i in $(seq 1 "$ATTEMPT_COUNT"); do
    event=$(make_auth_event "failure" "$TARGET_USER" "$ATTACKER_IP" "$TARGET_HOST" "$SERVICE")
    write_event "$event"

    if (( i % 10 == 0 )); then
        log_info "  → ${i}/${ATTEMPT_COUNT} failure events written"
    fi

    # Brief delay between attempts
    sleep "$(echo "scale=3; $ATTACK_DELAY_MS / 1000" | bc)"
done

log_info "Phase 1 complete – ${ATTEMPT_COUNT} failure events written"

# ---------------------------------------------------------------------------
# Phase 2: Successful authentication (credential found)
# ---------------------------------------------------------------------------
log_step "Phase 2 – Generating authentication success event (credential stuffing success)"
sleep 0.5

event=$(make_auth_event "success" "$TARGET_USER" "$ATTACKER_IP" "$TARGET_HOST" "$SERVICE")
write_event "$event"

log_info "Phase 2 complete – success event written"

# ---------------------------------------------------------------------------
# Phase 3: Post-compromise discovery (optional follow-on activity)
# ---------------------------------------------------------------------------
log_step "Phase 3 – Generating post-compromise discovery commands"
sleep 0.3

# Attacker runs discovery commands after gaining access
discovery_cmds=(
    "whoami.exe"
    "ipconfig /all"
    "net user"
    "net localgroup administrators"
    "systeminfo"
    "tasklist"
)

for cmd in "${discovery_cmds[@]}"; do
    binary="${cmd%% *}"
    event=$(make_process_event "cmd.exe" "$binary" "$cmd" "$TARGET_USER" "$TARGET_HOST")
    write_event "$event"
    sleep 0.1
done

log_info "Phase 3 complete – ${#discovery_cmds[@]} discovery command events written"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log_info "============================================"
log_info "  Simulation Complete"
log_info "============================================"
log_info "Total events written : $(( ATTEMPT_COUNT + 1 + ${#discovery_cmds[@]} ))"
log_info "Log file             : ${LOG_FILE}"
log_info ""
log_info "Expected detections:"
log_info "  - Multiple failed logins from ${ATTACKER_IP} (T1110)"
log_info "  - Auth success following failure run (T1078)"
log_info "  - Post-compromise discovery commands"
log_info ""
log_info "Run the detection query:"
log_info "  detections/authentication/brute_force_detection.kql"
log_info "  detections/authentication/brute_force_detection.spl"
