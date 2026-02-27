# Sigma Rules — Detection Library

This directory contains Sigma-format detection rules derived from the SPL/KQL
detections in the parent `detections/` folders. Sigma is a generic, open
signature format that compiles to platform-specific query languages, making
these rules portable across Splunk, Elasticsearch, Microsoft Sentinel, QRadar,
and others.

---

## Contents

| File | Techniques | Level |
|------|-----------|-------|
| `brute_force_authentication.yml` | T1110, T1110.001, T1110.003 | medium / high |
| `account_lockout_spike.yml` | T1110.001, T1110.003, T1110.004, T1078 | medium / high |
| `psexec_lateral_movement.yml` | T1021.002, T1543.003, T1570 | medium / high |
| `wmi_remote_execution.yml` | T1047, T1021, T1546.003 | medium / high |
| `privilege_escalation_system_integrity.yml` | T1068, T1134, T1548.002, T1548.003 | medium / critical |
| `scheduled_task_persistence.yml` | T1053.005, T1036.004 | medium / high |
| `data_exfiltration_nonstandard_port.yml` | T1041, T1048, T1560.001, T1027 | medium / high |
| `c2_beaconing.yml` | T1071.001, T1029, T1566.001, T1059.001 | medium / high |

Most files contain multiple variants (multi-document YAML separated by `---`).

---

## Converting Rules

Sigma rules require [sigma-cli](https://github.com/SigmaHQ/sigma-cli) or
[pySigma](https://github.com/SigmaHQ/pySigma) to compile to your SIEM's
query language. Install with:

```bash
pip install sigma-cli
```

### Convert to Elasticsearch ESQL

```bash
sigma convert -t elasticsearch -p ecs_windows detections/sigma/psexec_lateral_movement.yml
```

### Convert to Splunk SPL

```bash
sigma convert -t splunk -p splunk_windows detections/sigma/psexec_lateral_movement.yml
```

### Convert to KQL (Microsoft Sentinel)

```bash
sigma convert -t microsoft365defender -p microsoft365defender detections/sigma/brute_force_authentication.yml
```

### Batch Convert All Rules

```bash
sigma convert -t splunk -p splunk_windows detections/sigma/*.yml -o detections/sigma/compiled/splunk/
```

---

## Rule Format Reference

Each Sigma rule is a YAML document with the following required and optional fields:

```yaml
# REQUIRED
title: Human-readable detection name
id: UUID (unique, generated with uuidgen or online tool)
status: stable | experimental | test | deprecated
description: What this rule detects and why it matters
logsource:
  category: process_creation | network_connection | authentication | ...
  product: windows | linux | macos | (omit for agnostic)
detection:
  <keyword>:       # Named selection block
    field: value   # Field match
  condition: <keyword>  # Boolean logic over selection blocks
level: informational | low | medium | high | critical

# RECOMMENDED
tags:
  - attack.t<id>   # MITRE ATT&CK technique (lowercase)
  - attack.<tactic> # Tactic (e.g., attack.lateral_movement)
references:
  - https://attack.mitre.org/techniques/T...
author: Your name
date: YYYY-MM-DD
falsepositives:
  - Known benign trigger description
fields:
  - field.name  # Fields to surface in alert
```

---

## Detection Condition Syntax

### Basic Match

```yaml
detection:
  selection:
    process.name: cmd.exe
    user.name: SYSTEM
  condition: selection
```

### OR Within a Field (list)

```yaml
detection:
  selection:
    process.name:
      - cmd.exe
      - powershell.exe
  condition: selection
```

### Multiple Selection Blocks (OR)

```yaml
detection:
  selection1:
    process.name: PSEXESVC.exe
  selection2:
    process.parent.name: PSEXESVC.exe
  condition: 1 of selection*
```

### Negation / Filter

```yaml
detection:
  selection:
    process.integrity_level: System
  filter:
    process.parent.name:
      - services.exe
      - winlogon.exe
  condition: selection and not filter
```

### Wildcard / Substring Matching

```yaml
detection:
  selection:
    process.command_line|contains: '/node:'
    # Other modifiers: |startswith, |endswith, |re (regex), |cidr (IP ranges)
```

### Aggregation (Count Threshold)

```yaml
detection:
  selection:
    event.outcome: failure
  condition: selection | count() by source.ip > 10
  timeframe: 5m
```

### CIDR Matching

```yaml
detection:
  filter:
    destination.ip|cidr:
      - '10.0.0.0/8'
      - '172.16.0.0/12'
      - '192.168.0.0/16'
```

---

## Log Source Categories

| Category | Events Covered | ECS Equivalent |
|----------|----------------|----------------|
| `process_creation` | New process start events | `event.category: process` + `event.action: process_started` |
| `network_connection` | Outbound/inbound TCP/UDP flows | `event.category: network` |
| `authentication` | Login success/failure events | `event.category: authentication` |
| `registry_set` | Registry value modifications | `event.category: registry` + `event.action: value_set` |
| `file_event` | File create/modify/delete | `event.category: file` |
| `dns_query` | DNS resolution queries | `event.category: network` + `event.dataset: dns` |

---

## Writing a New Sigma Rule — Checklist

Use this checklist before committing a new rule:

- [ ] Title is concise and describes the behavior, not the tool
- [ ] `id` is a unique UUID (`uuidgen` or https://www.uuidgenerator.net/)
- [ ] `status` is `experimental` until validated against real data
- [ ] Description explains **what** is detected and **why** it matters
- [ ] At least one MITRE ATT&CK `tags` entry in format `attack.t<id>`
- [ ] `logsource.category` matches events available in this lab
- [ ] Detection logic is tested against lab data before setting status to `stable`
- [ ] `falsepositives` lists known benign triggers — do not leave empty
- [ ] `level` is calibrated: start at `medium`, raise only with strong evidence
- [ ] Rule is as specific as possible to minimize noise
- [ ] At least one variant (high-confidence + broad-coverage) considered

---

## Severity Level Guide

| Level | Meaning | Example |
|-------|---------|---------|
| `informational` | Low-noise visibility event; rarely actionable alone | Single authentication failure |
| `low` | Weak indicator; useful in correlation | One wmic.exe invocation |
| `medium` | Moderately suspicious; investigate with context | schtasks /create by PowerShell |
| `high` | Strong indicator of malicious activity | PSEXESVC.exe process creation |
| `critical` | Near-certain malicious; immediate action required | fodhelper.exe spawning shell |

---

## Validating Rules

Run `sigma check` to validate rule syntax before deploying:

```bash
sigma check detections/sigma/*.yml
```

Or validate all rules recursively:

```bash
find detections/sigma -name '*.yml' -exec sigma check {} \;
```

---

## Resources

- [SigmaHQ Rule Repository](https://github.com/SigmaHQ/sigma)
- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
- [pySigma Backends](https://github.com/SigmaHQ/pySigma-backend-elasticsearch)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [LOLBAS Project](https://lolbas-project.github.io/) — LOLBin reference for detection coverage
- [Florian Roth's Sigma rule best practices](https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide)
