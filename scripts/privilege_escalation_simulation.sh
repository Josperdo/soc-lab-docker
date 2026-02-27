#!/usr/bin/env bash
# ============================================================================
# SOC Lab Docker – Privilege Escalation Simulation
# ============================================================================
#
# Simulates an attacker escalating privileges from a standard domain user to
# Domain Admin using a combination of Kerberoasting, UAC bypass, and token
# manipulation techniques.
#
# Event chain simulated:
#   1. Privilege Assessment  – attacker evaluates current privileges
#   2. SPN Enumeration       – discovery of service accounts with SPNs
#   3. Kerberoasting         – TGS ticket requested for offline cracking
#   4. UAC Bypass            – fodhelper.exe registry hijack
#   5. High-Integrity Shell  – elevated cmd.exe spawned without prompt
#   6. Token Impersonation   – SYSTEM token stolen via SeImpersonatePrivilege
#   7. Domain Admin Access   – privilege confirmed, lateral movement prepped
#
# MITRE ATT&CK:
#   T1069.001 – Permission Groups Discovery: Local Groups
#   T1069.002 – Permission Groups Discovery: Domain Groups
#   T1558.003 – Steal or Forge Kerberos Tickets: Kerberoasting
#   T1548.002 – Abuse Elevation Control Mechanism: Bypass User Account Control
#   T1134.001 – Access Token Manipulation: Token Impersonation/Theft
#   T1078.002 – Valid Accounts: Domain Accounts
#
# Usage:
#   bash scripts/privilege_escalation_simulation.sh [options]
#
# Options (env vars):
#   TARGET_HOST  – Host where escalation occurs (default: workstation-09)
#   TARGET_USER  – Starting compromised account (default: jroe)
#   DOMAIN       – Active Directory domain (default: CORP)
#   SVC_ACCOUNT  – Service account to Kerberoast (default: svc_mssql)
#   LOG_FILE     – Output log file (default: ./data/logs/attack-simulation.json)
#
# Expected detections:
#   - SPN enumeration via setspn/PowerShell (T1558.003 precursor)
#   - Kerberos TGS request for service account (T1558.003)
#   - HKCU ms-settings registry key created (UAC bypass indicator)
#   - fodhelper.exe spawning cmd.exe with higher integrity (T1548.002)
#   - Process running with SYSTEM integrity under unexpected parent (T1134.001)
#
# See detections/privilege_escalation/ for matching queries.
# ============================================================================

set -euo pipefail
SCRIPT_NAME="privilege_escalation_simulation"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TARGET_HOST="${TARGET_HOST:-workstation-09}"
TARGET_USER="${TARGET_USER:-jroe}"
DOMAIN="${DOMAIN:-CORP}"
SVC_ACCOUNT="${SVC_ACCOUNT:-svc_mssql}"
DC_HOST="${DC_HOST:-dc-01}"
HOST_IP="$(random_internal_ip)"
DC_IP="$(random_internal_ip)"

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
log_info "============================================"
log_info "  Privilege Escalation Simulation"
log_info "============================================"
log_info "Target host    : ${TARGET_HOST}"
log_info "Starting user  : ${DOMAIN}\\${TARGET_USER} (standard user)"
log_info "Target account : ${DOMAIN}\\${SVC_ACCOUNT} (Kerberoasting target)"
log_info "Domain ctrl    : ${DC_HOST}"
log_info "Output file    : ${LOG_FILE}"
log_info "--------------------------------------------"

if ! check_lab_running 2>/dev/null; then
    log_warn "Lab not running. Events will be written to file only."
fi

# ---------------------------------------------------------------------------
# Step 1: Privilege Assessment – enumerate current context
# ---------------------------------------------------------------------------
log_step "Step 1 – Privilege assessment: enumerating current account context"

assessment_cmds=(
    "whoami /all"
    "whoami /priv"
    "net user ${TARGET_USER} /domain"
    "net localgroup administrators"
    "net group \"Domain Admins\" /domain"
)

for cmd in "${assessment_cmds[@]}"; do
    binary="${cmd%% *}"
    event=$(make_process_event "cmd.exe" "${binary}.exe" "$cmd" "$TARGET_USER" "$TARGET_HOST")
    write_event "$event"
    sleep 0.15
done

log_info "  → ${#assessment_cmds[@]} privilege assessment events written"
step_delay

# ---------------------------------------------------------------------------
# Step 2: SPN Enumeration – discover Kerberoastable service accounts
# ---------------------------------------------------------------------------
log_step "Step 2 – SPN enumeration: discovering Kerberoastable accounts (T1558.003)"

# setspn.exe to query all SPNs in the domain
event=$(make_process_event "cmd.exe" "setspn.exe" \
    "setspn.exe -T ${DOMAIN} -Q */*" \
    "$TARGET_USER" "$TARGET_HOST")
write_event "$event"

# PowerShell LDAP query for user accounts with SPNs (more targeted)
ps_spn_cmd="powershell.exe -Command \"Get-ADUser -Filter {ServicePrincipalName -ne '\$null' -and PasswordNeverExpires -eq \$true} -Properties ServicePrincipalName,PasswordNeverExpires | Select-Object Name,ServicePrincipalName\""
event=$(make_process_event "cmd.exe" "powershell.exe" "$ps_spn_cmd" "$TARGET_USER" "$TARGET_HOST")
write_event "$event"

# Network event – LDAP query to DC for SPN enumeration
event=$(make_network_event "$HOST_IP" "$DC_IP" "389" "2048" "$TARGET_HOST")
write_event "$event"

log_info "  → SPN enumeration events written (setspn + LDAP query to DC)"
step_delay

# ---------------------------------------------------------------------------
# Step 3: Kerberoasting – request TGS ticket for service account
# ---------------------------------------------------------------------------
log_step "Step 3 – Kerberoasting: requesting TGS ticket for ${DOMAIN}\\${SVC_ACCOUNT} (T1558.003)"

# PowerShell Invoke-Kerberoast (Rubeus-style)
kerb_cmd="powershell.exe -Command \"Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/${DC_HOST}.${DOMAIN}:1433'\""
event=$(make_process_event "cmd.exe" "powershell.exe" "$kerb_cmd" "$TARGET_USER" "$TARGET_HOST")
write_event "$event"

# Kerberos TGS request – network event to DC on port 88 (Kerberos)
# This is the key detection signal: RC4-encrypted TGS request for a service SPN
event=$(make_network_event "$HOST_IP" "$DC_IP" "88" "1536" "$TARGET_HOST")
write_event "$event"

# Authentication event representing the TGS request (Kerberos service ticket)
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["authentication"],"action":"kerberos_tgs_request","outcome":"success","kind":"event","dataset":"soc-lab.authentication"},"user":{"name":"${TARGET_USER}","domain":"${DOMAIN}"},"source":{"ip":"${HOST_IP}"},"destination":{"ip":"${DC_IP}","port":88},"authentication":{"service":"kerberos","type":"network","ticket":{"encryption_type":"RC4-HMAC","service_name":"MSSQLSvc/${DC_HOST}.${DOMAIN}:1433","target_user":"${SVC_ACCOUNT}"}},"host":{"name":"${TARGET_HOST}"},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON

log_info "  → Kerberoasting events written (TGS request for ${SVC_ACCOUNT} via RC4)"
step_delay

# ---------------------------------------------------------------------------
# Step 4: UAC Bypass – fodhelper.exe registry hijack
# ---------------------------------------------------------------------------
log_step "Step 4 – UAC bypass via fodhelper.exe registry hijack (T1548.002)"

# Write to HKCU\SOFTWARE\Classes\ms-settings (the bypass key)
UA_KEY="HKCU\\SOFTWARE\\Classes\\ms-settings\\shell\\open\\command"
event=$(make_process_event "cmd.exe" "reg.exe" \
    "reg.exe add \"${UA_KEY}\" /ve /d \"cmd.exe\" /f" \
    "$TARGET_USER" "$TARGET_HOST")
write_event "$event"

event=$(make_registry_event "key_created" \
    "HKCU\\SOFTWARE\\Classes\\ms-settings\\shell\\open\\command" \
    "(Default)" \
    "cmd.exe" \
    "$TARGET_USER" "$TARGET_HOST")
write_event "$event"

# DelegateExecute value (required for the bypass to trigger)
event=$(make_registry_event "value_set" \
    "HKCU\\SOFTWARE\\Classes\\ms-settings\\shell\\open\\command" \
    "DelegateExecute" \
    "" \
    "$TARGET_USER" "$TARGET_HOST")
write_event "$event"

# fodhelper.exe launched (normal-looking, built-in binary)
event=$(make_process_event "cmd.exe" "fodhelper.exe" \
    "C:\\Windows\\System32\\fodhelper.exe" \
    "$TARGET_USER" "$TARGET_HOST")
write_event "$event"

log_info "  → UAC bypass events written (ms-settings registry key + fodhelper)"
step_delay

# ---------------------------------------------------------------------------
# Step 5: High-Integrity Shell – elevated cmd.exe spawned
# ---------------------------------------------------------------------------
log_step "Step 5 – High-integrity shell spawned by fodhelper (T1548.002)"

# cmd.exe spawned by fodhelper.exe with High integrity (UAC bypassed)
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["process"],"action":"process_started","outcome":"success","kind":"event","dataset":"soc-lab.process_execution","type":["start"]},"process":{"name":"cmd.exe","executable":"C:\\\\Windows\\\\System32\\\\cmd.exe","command_line":"cmd.exe","pid":$((RANDOM % 60000 + 1000)),"integrity_level":"High","parent":{"name":"fodhelper.exe","pid":$((RANDOM % 60000 + 1000)),"executable":"C:\\\\Windows\\\\System32\\\\fodhelper.exe","integrity_level":"High"}},"user":{"name":"${TARGET_USER}","domain":"${DOMAIN}"},"host":{"name":"${TARGET_HOST}","os":{"type":"windows"}},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON

# Attacker confirms elevated context
event=$(make_process_event "cmd.exe" "whoami.exe" "whoami /groups" "$TARGET_USER" "$TARGET_HOST")
write_event "$event"

log_info "  → High-integrity shell events written (fodhelper → cmd.exe High)"
step_delay

# ---------------------------------------------------------------------------
# Step 6: Token Impersonation – steal SYSTEM token
# ---------------------------------------------------------------------------
log_step "Step 6 – Token impersonation: SYSTEM token acquisition (T1134.001)"

# Process running a token impersonation tool (Incognito/Potato-style)
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["process"],"action":"process_started","outcome":"success","kind":"event","dataset":"soc-lab.process_execution","type":["start"]},"process":{"name":"cmd.exe","executable":"C:\\\\Windows\\\\System32\\\\cmd.exe","command_line":"cmd.exe","pid":$((RANDOM % 60000 + 1000)),"integrity_level":"System","parent":{"name":"cmd.exe","pid":$((RANDOM % 60000 + 1000)),"integrity_level":"High"}},"user":{"name":"SYSTEM","domain":"NT AUTHORITY"},"host":{"name":"${TARGET_HOST}","os":{"type":"windows"}},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON

# Token manipulation event
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["process"],"action":"token_impersonation","outcome":"success","kind":"event","dataset":"soc-lab.process_execution"},"process":{"name":"cmd.exe","pid":$((RANDOM % 60000 + 1000)),"integrity_level":"System"},"user":{"name":"SYSTEM","domain":"NT AUTHORITY","effective":{"name":"${TARGET_USER}","domain":"${DOMAIN}"}},"host":{"name":"${TARGET_HOST}","os":{"type":"windows"}},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON

log_info "  → Token impersonation events written (High → System)"
step_delay

# ---------------------------------------------------------------------------
# Step 7: Domain Admin Access confirmed
# ---------------------------------------------------------------------------
log_step "Step 7 – Domain Admin access: lateral movement preparation"

# With SYSTEM token, dump credentials or add to Domain Admins
da_cmds=(
    "net group \"Domain Admins\" ${TARGET_USER} /add /domain"
    "net user ${TARGET_USER} /domain"
)

for cmd in "${da_cmds[@]}"; do
    binary="${cmd%% *}"
    event=$(make_process_event "cmd.exe" "${binary}.exe" "$cmd" "SYSTEM" "$TARGET_HOST")
    write_event "$event"
    sleep 0.2
done

# Auth event – target user now authenticating as Domain Admin
event=$(make_auth_event "success" "${DOMAIN}\\${TARGET_USER}" "$HOST_IP" "$DC_HOST" "kerberos")
write_event "$event"

log_info "  → Domain Admin confirmation events written"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log_info "============================================"
log_info "  Simulation Complete"
log_info "============================================"
log_info "Output file : ${LOG_FILE}"
log_info ""
log_info "Expected detections:"
log_info "  - SPN enumeration via setspn.exe or LDAP query (T1558.003 precursor)"
log_info "  - RC4-encrypted TGS ticket request for ${SVC_ACCOUNT} (T1558.003)"
log_info "  - HKCU\\SOFTWARE\\Classes\\ms-settings\\shell registry modification (T1548.002)"
log_info "  - fodhelper.exe spawning child process with High integrity (T1548.002)"
log_info "  - Process with System integrity under unexpected parent (T1134.001)"
log_info "  - net group Domain Admins modification (T1078.002)"
log_info ""
log_info "Key fields to look for in Kibana:"
log_info "  process.name: (setspn.exe OR fodhelper.exe)"
log_info "  process.integrity_level: (High OR System)"
log_info "  authentication.ticket.encryption_type: RC4-HMAC"
log_info "  registry.path: *ms-settings*"
