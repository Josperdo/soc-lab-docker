# Attack Simulation Scripts

**Purpose:** Executable scripts that simulate realistic attack scenarios for detection testing

## Overview

This directory contains Bash scripts that simulate common attack patterns, generating coordinated event chains detectable by security monitoring tools. Events are written as JSON to a log file picked up by Filebeat and indexed into Elasticsearch, where they can be queried in Kibana alongside baseline traffic from the log generator.

All scripts generate **synthetic events only** — they do not execute actual attacks or make real network connections.

---

## Scripts

| Script | Scenario | MITRE Techniques |
|--------|----------|-----------------|
| `brute_force_simulation.sh` | Credential brute force + post-compromise discovery | T1110, T1078 |
| `lateral_movement_simulation.sh` | PsExec lateral movement + C2 beacon | T1021.002, T1570, T1071 |
| `exfiltration_simulation.sh` | Data staging and large outbound transfer | T1005, T1560, T1048 |
| `c2_beacon_simulation.sh` | Spearphishing → implant → persistent C2 callbacks | T1566.001, T1059.001, T1071.001, T1029 |
| `persistence_simulation.sh` | Registry, scheduled task, WMI, service, startup folder | T1547.001, T1053.005, T1546.003, T1543.003 |
| `privilege_escalation_simulation.sh` | Kerberoasting + UAC bypass + token impersonation | T1558.003, T1548.002, T1134.001 |
| `apt_scenario.sh` | Full 7-phase APT kill chain (coordinator) | T1566→T1070 (12 techniques) |
| `utils.sh` | Shared utilities — sourced by all other scripts | — |

---

## Quick Start

```bash
# Start the lab
docker compose up -d

# Wait for Elasticsearch to be healthy, then run any scenario
bash scripts/brute_force_simulation.sh
bash scripts/c2_beacon_simulation.sh
bash scripts/persistence_simulation.sh
bash scripts/privilege_escalation_simulation.sh
bash scripts/lateral_movement_simulation.sh
bash scripts/exfiltration_simulation.sh

# Full APT kill chain (runs all phases end-to-end)
bash scripts/apt_scenario.sh
```

After running a script, open Kibana Discover (`http://localhost:5601`) and filter on `labels.simulation: attack` to see the generated events.

---

## Usage

Each script supports configuration via environment variables. See the script header for the full list of options.

```bash
# Brute force with custom settings
ATTEMPT_COUNT=100 TARGET_USER=administrator bash scripts/brute_force_simulation.sh

# C2 beacon with more pulses and a fixed C2 IP
BEACON_COUNT=12 C2_IP=198.51.100.42 bash scripts/c2_beacon_simulation.sh

# Persistence against a specific host/user
TARGET_HOST=workstation-15 TARGET_USER=bsmith bash scripts/persistence_simulation.sh

# Privilege escalation with custom domain
DOMAIN=ACME DC_HOST=addc-01 SVC_ACCOUNT=svc_exchange bash scripts/privilege_escalation_simulation.sh

# Full APT scenario with custom victim context
VICTIM_HOST=workstation-08 VICTIM_USER=cjones C2_IP=198.51.100.77 bash scripts/apt_scenario.sh

# Isolate a scenario to its own log file
LOG_FILE=./data/logs/c2-test.json bash scripts/c2_beacon_simulation.sh
```

---

## Detection Workflow

1. Start the lab: `docker compose up -d`
2. Wait for baseline data to accumulate (5–10 minutes)
3. Run a simulation: `bash scripts/apt_scenario.sh`
4. Open Kibana Discover: `http://localhost:5601`
5. Filter: `labels.simulation: attack` to isolate simulation events
6. Run the matching detection query from `detections/`
7. Document which detections fired and where gaps exist
8. Tune thresholds as needed

For full event chain documentation, detection opportunities, blind spots, and MITRE mappings for each scenario, see [docs/ATTACK_SCENARIOS.md](../docs/ATTACK_SCENARIOS.md).

---

## How Events Flow

```
Script → data/logs/attack-simulation.json → Filebeat → Elasticsearch → Kibana
```

All events use `labels.simulation: attack` for easy filtering and `labels.synthetic: true` to distinguish them from real events.

---

## Safety & Ethics

- These scripts generate **synthetic log events only** — no real network connections, no actual privilege changes, no file system modifications outside `./data/logs/`
- For use **within the SOC Lab environment only**
- Do **not** run against production systems or real infrastructure

---

## Shared Utilities (`utils.sh`)

Sourced by all scripts. Provides:

| Function | Description |
|----------|-------------|
| `log_info` / `log_warn` / `log_error` / `log_step` | Timestamped colored output |
| `check_lab_running` | Verifies Elasticsearch is reachable |
| `write_event` | Appends a JSON event to `$LOG_FILE` |
| `make_auth_event` | Builds an ECS authentication event |
| `make_process_event` | Builds an ECS process execution event |
| `make_network_event` | Builds an ECS network flow event |
| `make_registry_event` | Builds an ECS registry modification event |
| `make_dns_event` | Builds an ECS DNS query event |
| `random_external_ip` | Returns a random RFC 5737 external IP |
| `random_internal_ip` | Returns a random 10.0.x.x internal IP |
| `step_delay` | Sleeps for `$ATTACK_STEP_DELAY_MS` ms (default 500ms) |
