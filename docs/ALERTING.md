# Alerting Framework

This document covers the SOC Lab Docker alerting system: rule format, notifier
configuration, notification backends, and incident response playbooks for each
built-in detection rule.

---

## Overview

The alerting framework consists of three components:

| Component | Location | Purpose |
|-----------|----------|---------|
| Alert rules | `alerts/rules/*.yml` | Define what to detect and how to notify |
| Notifier script | `scripts/alert_notifier.sh` | Polls ES, evaluates rules, sends notifications |
| Playbooks | This document (below) | Step-by-step incident response guidance |

The notifier polls Elasticsearch at a configurable interval, runs a count query
for each rule, and fires notifications when the threshold is exceeded.

---

## Prerequisites

The notifier script requires `curl` and `jq`. Both are standard on Linux/macOS.
On Windows, neither is guaranteed to be on your PATH even if installed.

**Checking what you have:**

```bash
command -v curl && curl --version | head -1
command -v jq   && jq --version
```

**If `jq` is missing or not found:**

Common locations on Windows:

| Installation method | Likely path |
|---------------------|------------|
| Anaconda / Miniconda | `C:\Users\<you>\anaconda3\Library\mingw-w64\bin\jq.exe` |
| Scoop | `C:\Users\<you>\scoop\shims\jq.exe` |
| Chocolatey | `C:\ProgramData\chocolatey\bin\jq.exe` |
| Git for Windows | `C:\Program Files\Git\usr\bin\jq.exe` |
| Manual download | Wherever you saved it from [jqlang.org](https://jqlang.github.io/jq/download/) |

Once you find it, add the directory to your bash PATH for the session:

```bash
export PATH="/c/Users/<you>/anaconda3/Library/mingw-w64/bin:$PATH"
bash scripts/alert_notifier.sh --dry-run --once
```

To make this permanent, add the `export PATH=...` line to your `~/.bashrc` or
`~/.bash_profile` so it applies to every new terminal session.

**Troubleshooting tip:** If the script exits immediately with
`[WARN] Missing required tools: jq`, that is always a PATH issue — `jq` exists
on the machine but the shell can't find it. Use `find / -name "jq.exe" 2>/dev/null`
(or `where jq` in Command Prompt) to locate it, then add that directory to PATH.

---

## Quick Start

### 1. Configure credentials

Copy and populate `.env`:

```bash
cp .env.example .env
```

Set the following values:

```bash
# Elasticsearch connection
ES_HOST=http://localhost:9200

# Notification backends (set at least one)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
WEBHOOK_URL=https://your-soar-platform.example.com/alerts

# Polling settings
ALERT_INTERVAL=60      # Seconds between evaluation cycles
LOOKBACK=300           # Seconds of history to evaluate (5 minutes)
```

### 2. Run the notifier

```bash
# Continuous polling (recommended for lab use)
bash scripts/alert_notifier.sh

# Single evaluation run (useful for cron integration)
bash scripts/alert_notifier.sh --once

# Dry run — evaluate and print without sending notifications
bash scripts/alert_notifier.sh --dry-run --once
```

### 3. Generate test events

Run an attack simulation to trigger alerts:

```bash
bash scripts/brute_force_simulation.sh
# Wait 30-60 seconds, then check for notifications
```

---

## Alert Rule Format

Rules are YAML files in `alerts/rules/`. The notifier currently uses built-in
evaluator functions rather than parsing YAML at runtime; rule files serve as
human-readable configuration documentation and future integration targets.

```yaml
name: rule_identifier           # Unique snake_case name
enabled: true                   # Set false to suppress without deleting
description: What this detects  # Human-readable description

# Elasticsearch query
query:
  index: "soc-lab-*"
  filter:                       # All conditions must match (AND)
    - term:
        field.name: value
  any_of:                       # At least one must match (OR)
    - term:
        field.name: value

# Threshold configuration
aggregation:
  group_by: source.ip           # Field to aggregate by
  metric: count                 # count | sum | avg
  threshold: 10                 # Alert when metric exceeds this
  timeframe: 5m                 # Evaluation window

# Alert metadata
alert:
  severity: high                # informational | low | medium | high | critical
  mitre:
    - T1110                     # MITRE ATT&CK technique IDs
  runbook: docs/ALERTING.md#runbook-name
  message: |
    Template with {field} substitutions.

# Notification channels
notify:
  - slack
  - webhook
```

---

## Notification Backends

### Slack

Sends a formatted message with color-coded severity to a Slack channel.

**Setup:**
1. Create a Slack app at https://api.slack.com/apps
2. Enable Incoming Webhooks
3. Copy the webhook URL to `SLACK_WEBHOOK_URL` in `.env`

**Severity colors:**
- Critical → Red (#FF0000)
- High → Orange (#FF6600)
- Medium → Yellow (#FFCC00)
- Low/Info → Green (#36A64F)

### Generic Webhook

Posts a JSON payload to any HTTP endpoint. Compatible with:
- PagerDuty Events API
- Opsgenie
- Custom SOAR platforms
- Discord webhooks (use Slack format for Discord)
- Microsoft Teams incoming webhooks

**Payload format:**

```json
{
    "alert": {
        "rule": "brute_force_authentication",
        "severity": "high",
        "message": "50 authentication failures...",
        "mitre": ["T1110", "T1110.001"],
        "timestamp": "2026-02-27T14:30:00Z",
        "source": "soc-lab-docker"
    }
}
```

### Email (DIY Extension)

Email notifications are not built-in. To add email support, extend the
`notify()` function in `scripts/alert_notifier.sh`:

```bash
send_email() {
    local subject="[SOC Alert] ${1}"
    local body="$3"
    echo "$body" | mail -s "$subject" "$ALERT_EMAIL"
}
```

Requires `mailutils` or `sendmail` configured on the host.

---

## Adding a New Alert Rule

To add a new detection to the polling loop:

1. Create `alerts/rules/<name>.yml` with the rule definition
2. Add an `eval_<name>()` function in `scripts/alert_notifier.sh`
3. Call the new function inside `run_evaluation()`

Example:

```bash
eval_new_technique() {
    local count
    count=$(es_count "soc-lab-*" \
        '{"bool":{"must":[{"term":{"event.category":"process"}},{"term":{"process.name":"suspicious.exe"}}]}}')

    log "  new_technique: ${count} events in last ${LOOKBACK}s"

    if (( count >= 1 )); then
        notify \
            "new_technique" \
            "high" \
            "${count} suspicious.exe events detected." \
            "T1XXX" \
            "slack,webhook"
    fi
}
```

---

## Incident Response Playbooks

Each section below is a step-by-step response guide for alerts generated by
the built-in rules. Playbooks follow the structure:

1. **Triage** — determine if the alert is a true positive
2. **Investigation** — gather additional context
3. **Containment** — stop ongoing harm
4. **Eradication** — remove the threat
5. **Recovery** — restore normal operations
6. **Documentation** — capture findings

---

### Runbook: Brute Force Authentication

**Trigger:** `brute_force_authentication` — more than 10 authentication
failures from a single source IP within 5 minutes.

**Severity:** High

**MITRE:** T1110, T1110.001, T1110.003

#### Triage

- [ ] Is the source IP internal or external?
- [ ] Is the IP a known scanner, jump box, or monitoring system?
- [ ] Is the targeted account a service account or human account?
- [ ] Did any authentication succeed from this IP?

#### KQL Investigation Query (Kibana)

```kql
event.category: "authentication" AND source.ip: "<ATTACKER_IP>"
| sort @timestamp desc
```

Look for:
- `event.outcome: success` — credential found (critical escalation)
- Multiple `user.name` values — password spray pattern
- Geographic anomaly in `source.geo.country_name`

#### SPL Investigation (Splunk)

```spl
index=soc-lab-* event.category=authentication source.ip="<ATTACKER_IP>"
| table _time, user.name, event.outcome, host.name, authentication.service
| sort _time
```

#### Containment

- Block `source.ip` at the perimeter firewall or WAF
- If an account was compromised (success after failures):
  - Immediately disable the account
  - Force password reset
  - Revoke active sessions

#### Eradication

- Review all authentication events from `source.ip` in the past 7 days
- Check for any resources accessed by compromised accounts
- Reset all accounts that were targeted (not just the successfully brute-forced one)

#### Recovery

- Re-enable accounts after password resets are confirmed
- Enable MFA for targeted accounts if not already active
- Monitor for re-attempts from the same IP or IP ranges

#### Documentation

Record: source IP, targeted accounts, first/last seen timestamps, whether a
success event occurred, actions taken, and any indicator of compromise (IOC).

---

### Runbook: PsExec Lateral Movement

**Trigger:** `psexec_lateral_movement` — any PSEXESVC.exe process event.

**Severity:** High

**MITRE:** T1021.002, T1570, T1543.003

#### Triage

- [ ] Is PSEXESVC.exe expected on this host? (authorized IT admin use?)
- [ ] What account spawned it? Is that account authorized for remote admin?
- [ ] Are there related SMB connections to port 445 from the same source?
- [ ] Did the PsExec spawn a cmd.exe or PowerShell child?

#### KQL Investigation

```kql
host.name: "<TARGET_HOST>" AND (process.name: "PSEXESVC.exe" OR process.parent.name: "PSEXESVC.exe")
| sort @timestamp asc
```

#### Sequence Analysis

```kql
event.category: "network" AND destination.port: 445 AND destination.ip: "<TARGET_HOST_IP>"
```

Correlate the SMB connection time with the PSEXESVC.exe start time.

#### Containment

- Isolate the target host from the network immediately
- Block the source IP at the internal network level
- Disable the account used for remote execution

#### Eradication

- Remove the PSEXESVC.exe binary from the ADMIN$ share
- Remove any dropped payloads or persistence mechanisms
- Audit all processes started by PSEXESVC.exe in the incident window

#### Recovery

- Reimage the host if unauthorized code executed at SYSTEM level
- Restore from backup if files were modified
- Re-enable the host after validation

---

### Runbook: Large Data Transfer

**Trigger:** `large_data_transfer` — more than 10 outbound connections on
non-standard ports to external IPs within 10 minutes.

**Severity:** Medium

**MITRE:** T1041, T1048, T1048.003

#### Triage

- [ ] What application is making the connection? Is it a known business app?
- [ ] Is the destination IP a known cloud service, CDN, or corporate system?
- [ ] Are archiving tools (7z, rar, tar) also running on the same host?
- [ ] Is the connection count/volume anomalous compared to the baseline?

#### KQL Investigation

```kql
event.category: "network" AND host.name: "<HOST>" AND NOT destination.port: (80 OR 443)
| sort @timestamp asc
```

Check for:
- `source.bytes` — volume of data sent
- Consistent `destination.ip` — possible C2 channel
- Regular timing intervals — beaconing pattern

#### Containment

- Block the destination IP at the perimeter
- Isolate the host if data exfiltration is confirmed

#### Eradication

- Identify what data was transferred (audit file access logs before transfer)
- Remove the exfiltration mechanism (malware, compromised script)

#### Recovery

- Notify data owner and legal/compliance if PII or regulated data was involved
- File an incident report per data breach notification requirements

---

### Runbook: WMI Remote Execution

**Trigger:** `wmi_remote_execution` — WmiPrvSE.exe spawning cmd.exe or
powershell.exe.

**Severity:** High

**MITRE:** T1047, T1021

#### Triage

- [ ] Is the shell spawn associated with a known WMI management agent?
- [ ] What command was executed? (check `process.command_line`)
- [ ] Is there a corresponding network connection to port 135 from a remote host?

#### KQL Investigation

```kql
process.parent.name: "WmiPrvSE.exe" AND process.name: ("cmd.exe" OR "powershell.exe")
```

#### Containment

- Block DCOM/WMI traffic (port 135) from unauthorized hosts
- Disable remote WMI on affected hosts temporarily

---

### Runbook: Scheduled Task Persistence

**Trigger:** `scheduled_task_persistence` — schtasks.exe with creation
flags and LOLBin payload references.

**Severity:** Medium

**MITRE:** T1053.005

#### Triage

- [ ] Is the task created by a software installer or IT automation tool?
- [ ] Does the task action reference an unusual path (ProgramData, AppData)?
- [ ] Does the task name mimic a legitimate Windows task?

#### KQL Investigation

```kql
process.name: "schtasks.exe" AND process.command_line: "/create"
```

Review task name (`/tn`), action (`/tr`), and trigger (`/sc`).

#### Containment

- Delete the malicious scheduled task:
  ```
  schtasks /delete /tn "<TASK_NAME>" /f
  ```
- Remove any payload binaries referenced in the task action

#### Eradication

- Audit all scheduled tasks on the affected host:
  ```
  schtasks /query /fo LIST /v
  ```
- Remove all unauthorized tasks

---

## Tuning Guidance

### Reducing False Positives

1. **Build an allow-list** for known-good source IPs, accounts, and hosts
   that trigger rules legitimately (security scanners, IT admin jump boxes)
2. **Increase thresholds** if baseline failure rates in your environment
   are higher than the defaults
3. **Add time-of-day filters** to alert only on after-hours activity for
   rules that primarily catch human attackers (not automated)
4. **Stack rank alerts** — correlate multiple low-confidence signals before
   sending a high-severity notification

### Reducing False Negatives

1. **Lower thresholds** for high-value assets (domain controllers, file servers)
2. **Add geolocation filters** to alert on authentications from unexpected countries
3. **Combine network + process events** for higher-confidence correlated alerts
4. **Monitor baseline drift** — update thresholds quarterly

---

## Cron Integration

To run the notifier on a schedule without leaving a persistent process:

```cron
# Evaluate alert rules every 5 minutes
*/5 * * * * cd /path/to/soc-lab-docker && bash scripts/alert_notifier.sh --once >> /var/log/soc-lab-alerts.log 2>&1
```

---

## Related Documentation

- [Attack Scenarios](ATTACK_SCENARIOS.md) — event chains for each simulation
- [detections/sigma/README.md](../detections/sigma/README.md) — Sigma rule authoring guide
- [BEST_PRACTICES.md](../dashboards/BEST_PRACTICES.md) — dashboard design guide
