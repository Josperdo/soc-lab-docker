#!/usr/bin/env bash
# ============================================================================
# SOC Lab Docker – Lateral Movement Attack Simulation
# ============================================================================
#
# Simulates PsExec-style lateral movement: an attacker authenticates to a
# Domain Controller, spawns a remote process on a secondary host, and
# establishes a network connection for command and control.
#
# Event chain simulated:
#   1. Auth success on DC (stolen credential)
#   2. Net use to admin share (SMB connection)
#   3. PsExec service installation (remote process creation)
#   4. cmd.exe spawned remotely on target host
#   5. Discovery commands run on remote host
#   6. C2 beacon – outbound connection to external IP
#
# MITRE ATT&CK:
#   T1021.002 – Remote Services: SMB/Windows Admin Shares
#   T1570     – Lateral Tool Transfer
#   T1059.003 – Windows Command Shell
#   T1071.001 – Application Layer Protocol: Web Protocols (C2)
#
# Usage:
#   bash scripts/lateral_movement_simulation.sh [options]
#
# Options (env vars):
#   SOURCE_HOST   – Host the attacker moved from (default: workstation-03)
#   TARGET_HOST   – Host being moved to (default: dc-01)
#   PIVOT_HOST    – Secondary target (default: fileserver-01)
#   TARGET_USER   – Compromised domain admin (default: svc_backup)
#   LOG_FILE      – Output log file (default: ./data/logs/attack-simulation.json)
#
# Expected detections:
#   - Admin share access from non-DC host
#   - Remote process creation via PsExec
#   - Unusual parent/child process relationships
#   - Outbound C2 beacon traffic
#
# See detections/lateral_movement/psexec_detection.spl for the matching query.
# ============================================================================

set -euo pipefail
SCRIPT_NAME="lateral_movement_simulation"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SOURCE_HOST="${SOURCE_HOST:-workstation-03}"
TARGET_HOST="${TARGET_HOST:-dc-01}"
PIVOT_HOST="${PIVOT_HOST:-fileserver-01}"
TARGET_USER="${TARGET_USER:-svc_backup}"
ATTACKER_IP="$(random_external_ip)"
C2_IP="${C2_IP:-$(random_external_ip)}"
C2_PORT="${C2_PORT:-4444}"
DOMAIN="${DOMAIN:-CORP}"

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
log_info "============================================"
log_info "  Lateral Movement Simulation (PsExec)"
log_info "============================================"
log_info "Source host  : ${SOURCE_HOST}"
log_info "Target host  : ${TARGET_HOST}"
log_info "Pivot host   : ${PIVOT_HOST}"
log_info "Compromised  : ${DOMAIN}\\${TARGET_USER}"
log_info "C2 server    : ${C2_IP}:${C2_PORT}"
log_info "Output file  : ${LOG_FILE}"
log_info "--------------------------------------------"

if ! check_lab_running 2>/dev/null; then
    log_warn "Lab not running. Events will be written to file only."
fi

# Internal IP for the source host
SOURCE_IP="$(random_internal_ip)"
TARGET_IP="$(random_internal_ip)"
PIVOT_IP="$(random_internal_ip)"

# ---------------------------------------------------------------------------
# Step 1: Attacker authenticates to DC with stolen domain admin credentials
# ---------------------------------------------------------------------------
log_step "Step 1 – Auth to Domain Controller with stolen credentials"

event=$(make_auth_event "success" "${DOMAIN}\\${TARGET_USER}" "$SOURCE_IP" "$TARGET_HOST" "kerberos")
write_event "$event"
step_delay

# ---------------------------------------------------------------------------
# Step 2: Net use to ADMIN$ share (SMB lateral movement prep)
# ---------------------------------------------------------------------------
log_step "Step 2 – Mapping ADMIN\$ share on target"

event=$(make_network_event "$SOURCE_IP" "$TARGET_IP" "445" "8192" "$SOURCE_HOST")
write_event "$event"

event=$(make_process_event "cmd.exe" "net.exe" \
    "net.exe use \\\\${TARGET_HOST}\\ADMIN\$ /user:${DOMAIN}\\${TARGET_USER} *" \
    "$TARGET_USER" "$SOURCE_HOST")
write_event "$event"
step_delay

# ---------------------------------------------------------------------------
# Step 3: PsExec service binary dropped and service started
# ---------------------------------------------------------------------------
log_step "Step 3 – PsExec service installation on ${TARGET_HOST}"

event=$(make_process_event "cmd.exe" "psexec.exe" \
    "psexec.exe \\\\${TARGET_HOST} -u ${DOMAIN}\\${TARGET_USER} -p P@ssw0rd123 -i cmd.exe" \
    "$TARGET_USER" "$SOURCE_HOST")
write_event "$event"
step_delay

# Service creation event on the remote host (PSEXESVC)
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["process","configuration"],"action":"service_created","outcome":"success","kind":"event","dataset":"soc-lab.process_execution"},"service":{"name":"PSEXESVC","type":"Win32OwnProcess"},"process":{"name":"services.exe","pid":592,"parent":{"name":"wininit.exe","pid":436}},"host":{"name":"${TARGET_HOST}","os":{"type":"windows"}},"user":{"name":"SYSTEM"},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON
step_delay

# ---------------------------------------------------------------------------
# Step 4: Remote cmd.exe spawned on target host (SYSTEM integrity)
# ---------------------------------------------------------------------------
log_step "Step 4 – Remote cmd.exe spawned on ${TARGET_HOST}"

ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["process"],"action":"process_started","outcome":"success","kind":"event","dataset":"soc-lab.process_execution","type":["start"]},"process":{"name":"cmd.exe","executable":"C:\\\\Windows\\\\System32\\\\cmd.exe","command_line":"cmd.exe","pid":$((RANDOM % 60000 + 1000)),"integrity_level":"System","parent":{"name":"PSEXESVC.exe","pid":$((RANDOM % 60000 + 1000)),"executable":"C:\\\\Windows\\\\PSEXESVC.exe"}},"user":{"name":"SYSTEM","domain":"NT AUTHORITY"},"host":{"name":"${TARGET_HOST}","os":{"type":"windows"}},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON
step_delay

# ---------------------------------------------------------------------------
# Step 5: Discovery on remote host
# ---------------------------------------------------------------------------
log_step "Step 5 – Running discovery commands on ${TARGET_HOST}"

remote_cmds=(
    "net user /domain"
    "net group \"Domain Admins\" /domain"
    "nltest /dclist:${DOMAIN}"
    "ipconfig /all"
    "arp -a"
)

for cmd in "${remote_cmds[@]}"; do
    binary="${cmd%% *}"
    event=$(make_process_event "cmd.exe" "${binary}.exe" "$cmd" "SYSTEM" "$TARGET_HOST")
    write_event "$event"
    sleep 0.2
done

log_info "  → ${#remote_cmds[@]} discovery events written"

# ---------------------------------------------------------------------------
# Step 6: Lateral move to pivot (file server)
# ---------------------------------------------------------------------------
log_step "Step 6 – Moving laterally to ${PIVOT_HOST}"

event=$(make_network_event "$TARGET_IP" "$PIVOT_IP" "445" "4096" "$TARGET_HOST")
write_event "$event"

event=$(make_process_event "cmd.exe" "net.exe" \
    "net.exe use \\\\${PIVOT_HOST}\\C\$ /user:${DOMAIN}\\${TARGET_USER} *" \
    "SYSTEM" "$TARGET_HOST")
write_event "$event"
step_delay

# ---------------------------------------------------------------------------
# Step 7: C2 beacon – outbound connection to attacker infrastructure
# ---------------------------------------------------------------------------
log_step "Step 7 – Establishing C2 beacon to ${C2_IP}:${C2_PORT}"

event=$(make_network_event "$PIVOT_IP" "$C2_IP" "$C2_PORT" "1024" "$PIVOT_HOST")
write_event "$event"

# Repeated beacon pulses (typical C2 heartbeat)
for _ in 1 2 3; do
    sleep 1
    event=$(make_network_event "$PIVOT_IP" "$C2_IP" "$C2_PORT" "512" "$PIVOT_HOST")
    write_event "$event"
done

log_info "  → C2 beacon pulses written"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log_info "============================================"
log_info "  Simulation Complete"
log_info "============================================"
log_info "Output file : ${LOG_FILE}"
log_info ""
log_info "Expected detections:"
log_info "  - SMB admin share access from non-DC (T1021.002)"
log_info "  - PsExec service installation (T1570)"
log_info "  - Remote cmd.exe with SYSTEM integrity"
log_info "  - Outbound C2 beacon on port ${C2_PORT} (T1071)"
log_info ""
log_info "Run the detection query:"
log_info "  detections/lateral_movement/psexec_detection.spl"
