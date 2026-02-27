#!/usr/bin/env bash
# ============================================================================
# SOC Lab Docker – Persistence Mechanism Simulation
# ============================================================================
#
# Simulates an attacker establishing multiple persistence mechanisms after
# gaining access to a host, ensuring they survive reboots and user logoffs.
#
# Event chain simulated:
#   1. Registry Run Key  – payload registered in HKCU Run for logon persistence
#   2. Scheduled Task    – hidden task created to run on logon and at startup
#   3. WMI Subscription  – event-triggered execution via WMI filter/consumer
#   4. Service Install   – malicious service installed as a Windows service
#   5. Startup Folder    – LNK shortcut dropped in user Startup directory
#
# MITRE ATT&CK:
#   T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys
#   T1053.005 – Scheduled Task/Job: Scheduled Task
#   T1546.003 – Event Triggered Execution: WMI Event Subscription
#   T1543.003 – Create or Modify System Process: Windows Service
#   T1547.001 – Boot or Logon Autostart Execution: Startup Folder (shared technique)
#
# Usage:
#   bash scripts/persistence_simulation.sh [options]
#
# Options (env vars):
#   TARGET_HOST  – Host where persistence is established (default: workstation-05)
#   TARGET_USER  – Compromised user account (default: jdoe)
#   DOMAIN       – Active Directory domain (default: CORP)
#   PAYLOAD_PATH – Simulated payload binary path (default: C:\ProgramData\MicrosoftUpdate\svcmon.exe)
#   LOG_FILE     – Output log file (default: ./data/logs/attack-simulation.json)
#
# Expected detections:
#   - New registry Run key added under HKCU (T1547.001)
#   - Scheduled task created with unusual name/path (T1053.005)
#   - WMI permanent event subscription registered (T1546.003)
#   - New service installed pointing to non-system32 executable (T1543.003)
#   - File created in Startup directory by non-installer process (T1547.001)
#
# See detections/persistence/ for matching queries.
# ============================================================================

set -euo pipefail
SCRIPT_NAME="persistence_simulation"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TARGET_HOST="${TARGET_HOST:-workstation-05}"
TARGET_USER="${TARGET_USER:-jdoe}"
DOMAIN="${DOMAIN:-CORP}"
PAYLOAD_PATH="${PAYLOAD_PATH:-C:\\ProgramData\\MicrosoftUpdate\\svcmon.exe}"
PAYLOAD_NAME="${PAYLOAD_PATH##*\\}"
HOST_IP="$(random_internal_ip)"

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
log_info "============================================"
log_info "  Persistence Mechanism Simulation"
log_info "============================================"
log_info "Target host  : ${TARGET_HOST}"
log_info "Target user  : ${DOMAIN}\\${TARGET_USER}"
log_info "Payload      : ${PAYLOAD_PATH}"
log_info "Output file  : ${LOG_FILE}"
log_info "--------------------------------------------"

if ! check_lab_running 2>/dev/null; then
    log_warn "Lab not running. Events will be written to file only."
fi

# ---------------------------------------------------------------------------
# Step 1: Registry Run Key – HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
# ---------------------------------------------------------------------------
log_step "Step 1 – Registry Run Key persistence (T1547.001)"

# reg.exe invocation to add run key
event=$(make_process_event "cmd.exe" "reg.exe" \
    "reg.exe add \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v WindowsUpdateMonitor /t REG_SZ /d \"${PAYLOAD_PATH} --autostart\" /f" \
    "$TARGET_USER" "$TARGET_HOST")
write_event "$event"

# Registry modification event
event=$(make_registry_event "value_set" \
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" \
    "WindowsUpdateMonitor" \
    "${PAYLOAD_PATH} --autostart" \
    "$TARGET_USER" "$TARGET_HOST")
write_event "$event"

# Also add a HKLM run key (requires higher privileges — confirms escalation prerequisite)
event=$(make_process_event "cmd.exe" "reg.exe" \
    "reg.exe add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v WindowsUpdateMonitor /t REG_SZ /d \"${PAYLOAD_PATH} --autostart\" /f" \
    "SYSTEM" "$TARGET_HOST")
write_event "$event"

event=$(make_registry_event "value_set" \
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" \
    "WindowsUpdateMonitor" \
    "${PAYLOAD_PATH} --autostart" \
    "SYSTEM" "$TARGET_HOST")
write_event "$event"

log_info "  → Registry Run Key events written (HKCU + HKLM)"
step_delay

# ---------------------------------------------------------------------------
# Step 2: Scheduled Task – schtasks.exe /create
# ---------------------------------------------------------------------------
log_step "Step 2 – Scheduled Task creation (T1053.005)"

# Create task via schtasks.exe (on-logon trigger, hidden)
schtask_cmd="schtasks.exe /create /tn \"\\Microsoft\\Windows\\UpdateOrchestrator\\WindowsUpdateMonitor\" /tr \"${PAYLOAD_PATH} --task\" /sc ONLOGON /ru ${DOMAIN}\\${TARGET_USER} /rl HIGHEST /f"
event=$(make_process_event "cmd.exe" "schtasks.exe" "$schtask_cmd" "$TARGET_USER" "$TARGET_HOST")
write_event "$event"

# Scheduled task creation event (raw – no make_* helper for this type)
_schtask_j="${schtask_cmd//\\/\\\\}"; _schtask_j="${_schtask_j//\"/\\\"}"
_payload_j="${PAYLOAD_PATH//\\/\\\\}"
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["process","configuration"],"action":"scheduled_task_created","outcome":"success","kind":"event","dataset":"soc-lab.scheduled_task"},"process":{"name":"schtasks.exe","executable":"C:\\\\Windows\\\\System32\\\\schtasks.exe","command_line":"${_schtask_j}","pid":$((RANDOM % 60000 + 1000)),"parent":{"name":"cmd.exe","pid":$((RANDOM % 1000 + 100))}},"task":{"name":"\\\\Microsoft\\\\Windows\\\\UpdateOrchestrator\\\\WindowsUpdateMonitor","trigger":"ONLOGON","action":"${_payload_j} --task","run_level":"HIGHEST","user":"${DOMAIN}\\\\${TARGET_USER}"},"user":{"name":"${TARGET_USER}","domain":"${DOMAIN}"},"host":{"name":"${TARGET_HOST}","os":{"type":"windows"}},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON

# Second task – startup trigger (belt and suspenders)
schtask_cmd2="schtasks.exe /create /tn \"\\Microsoft\\Windows\\UpdateOrchestrator\\StartupUpdate\" /tr \"${PAYLOAD_PATH} --startup\" /sc ONSTART /ru SYSTEM /f"
event=$(make_process_event "cmd.exe" "schtasks.exe" "$schtask_cmd2" "SYSTEM" "$TARGET_HOST")
write_event "$event"

log_info "  → Scheduled task events written (ONLOGON + ONSTART)"
step_delay

# ---------------------------------------------------------------------------
# Step 3: WMI Event Subscription
# ---------------------------------------------------------------------------
log_step "Step 3 – WMI permanent event subscription (T1546.003)"

# mofcomp.exe compiles MOF file defining the WMI subscription
mof_path="C:\\ProgramData\\MicrosoftUpdate\\sub.mof"
event=$(make_process_event "cmd.exe" "mofcomp.exe" \
    "mofcomp.exe ${mof_path}" \
    "$TARGET_USER" "$TARGET_HOST")
write_event "$event"

# wmic process create to test the subscription
event=$(make_process_event "cmd.exe" "wmic.exe" \
    "wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name=\"WindowsUpdateFilter\", EventNameSpace=\"root\\cimv2\", QueryLanguage=\"WQL\", Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour=12\"" \
    "$TARGET_USER" "$TARGET_HOST")
write_event "$event"

# WMI subscription creation events (filter, consumer, binding)
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
for wmi_type in "__EventFilter" "CommandLineEventConsumer" "__FilterToConsumerBinding"; do
    cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["configuration"],"action":"wmi_subscription_created","outcome":"success","kind":"event","dataset":"soc-lab.wmi"},"wmi":{"namespace":"root\\\\subscription","class":"${wmi_type}","instance_name":"WindowsUpdateFilter"},"process":{"name":"wmiprvse.exe","pid":$((RANDOM % 60000 + 1000)),"parent":{"name":"svchost.exe","pid":$((RANDOM % 1000 + 100))}},"user":{"name":"${TARGET_USER}"},"host":{"name":"${TARGET_HOST}","os":{"type":"windows"}},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON
done

log_info "  → WMI subscription events written (filter + consumer + binding)"
step_delay

# ---------------------------------------------------------------------------
# Step 4: Malicious Service Installation
# ---------------------------------------------------------------------------
log_step "Step 4 – Windows service installation (T1543.003)"

# sc.exe create to install service
sc_cmd="sc.exe create WindowsUpdateMonitorSvc binPath= \"${PAYLOAD_PATH} --service\" start= auto DisplayName= \"Windows Update Monitor\""
event=$(make_process_event "cmd.exe" "sc.exe" "$sc_cmd" "SYSTEM" "$TARGET_HOST")
write_event "$event"

# Service creation event
_payload_j="${PAYLOAD_PATH//\\/\\\\}"
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["process","configuration"],"action":"service_created","outcome":"success","kind":"event","dataset":"soc-lab.process_execution"},"service":{"name":"WindowsUpdateMonitorSvc","display_name":"Windows Update Monitor","type":"Win32OwnProcess","start_type":"AutoStart","binary_path":"${_payload_j} --service"},"process":{"name":"services.exe","pid":592,"parent":{"name":"wininit.exe","pid":436}},"host":{"name":"${TARGET_HOST}","os":{"type":"windows"}},"user":{"name":"SYSTEM"},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON

# Service start
event=$(make_process_event "services.exe" "${PAYLOAD_NAME}" \
    "${PAYLOAD_PATH} --service" \
    "SYSTEM" "$TARGET_HOST")
write_event "$event"

log_info "  → Service installation events written"
step_delay

# ---------------------------------------------------------------------------
# Step 5: Startup Folder Persistence (LNK file drop)
# ---------------------------------------------------------------------------
log_step "Step 5 – Startup folder shortcut (T1547.001)"

STARTUP_PATH="C:\\Users\\${TARGET_USER}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
LNK_PATH="${STARTUP_PATH}\\WindowsUpdate.lnk"

# PowerShell creates LNK via WScript.Shell COM object (common technique)
lnk_cmd="powershell.exe -Command \"\$s=(New-Object -ComObject WScript.Shell).CreateShortcut('${LNK_PATH}');\$s.TargetPath='${PAYLOAD_PATH}';\$s.Arguments='--startup';\$s.WindowStyle=7;\$s.Save()\""
event=$(make_process_event "cmd.exe" "powershell.exe" "$lnk_cmd" "$TARGET_USER" "$TARGET_HOST")
write_event "$event"

# File creation event for the LNK file
_lnk_j="${LNK_PATH//\\/\\\\}"
_startup_j="${STARTUP_PATH//\\/\\\\}"
ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
cat <<JSON | write_event "$(cat)"
{"@timestamp":"${ts}","event":{"category":["file"],"action":"file_created","outcome":"success","kind":"event","dataset":"soc-lab.file"},"file":{"path":"${_lnk_j}","name":"WindowsUpdate.lnk","extension":"lnk","directory":"${_startup_j}"},"process":{"name":"powershell.exe","pid":$((RANDOM % 60000 + 1000)),"parent":{"name":"cmd.exe","pid":$((RANDOM % 1000 + 100))}},"user":{"name":"${TARGET_USER}"},"host":{"name":"${TARGET_HOST}","os":{"type":"windows"}},"labels":{"lab":"soc-lab","synthetic":true,"simulation":"attack"}}
JSON

log_info "  → Startup folder LNK drop events written"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log_info "============================================"
log_info "  Simulation Complete"
log_info "============================================"
log_info "Output file : ${LOG_FILE}"
log_info ""
log_info "Expected detections:"
log_info "  - Registry Run Key modification (HKCU + HKLM) (T1547.001)"
log_info "  - Scheduled task created in UpdateOrchestrator path (T1053.005)"
log_info "  - WMI filter/consumer/binding created (T1546.003)"
log_info "  - New service with non-system32 binary path (T1543.003)"
log_info "  - LNK file created in Startup folder by powershell.exe (T1547.001)"
log_info ""
log_info "Key fields to look for in Kibana:"
log_info "  event.action: (value_set OR scheduled_task_created OR service_created OR wmi_subscription_created OR file_created)"
log_info "  process.name: (reg.exe OR schtasks.exe OR sc.exe OR mofcomp.exe)"
log_info "  registry.path: *CurrentVersion\\Run*"
