# Attack Simulation Scripts

**Purpose:** Executable scripts that simulate realistic attack scenarios for detection testing

## Overview

This directory contains Bash and Python scripts that simulate common attack patterns, generating coordinated event chains detectable by security monitoring tools.

## Structure

This directory contains Bash and Python scripts that simulate common attack patterns, generating coordinated event chains detectable by security monitoring tools.

**Key files:**

- `brute_force_simulation.sh` – Simulate failed authentication attempts
- `lateral_movement_simulation.sh` – Simulate lateral movement (e.g., PsExec, SMB)
- `exfiltration_simulation.sh` – Simulate data exfiltration techniques
- `privilege_escalation_simulation.sh` – Simulate privilege escalation attempts
- `persistence_simulation.sh` – Simulate persistence mechanisms (scheduled tasks, registry keys)
- `c2_beacon_simulation.sh` – Simulate command-and-control beacon callbacks
- `utils.sh` – Shared utility functions (logging, event correlation, cleanup)
- `config/scenarios.yaml` – Attack scenario definitions and parameters

## Capabilities

✅ **Multi-step attack chains**

- Coordinated sequences of events (reconnaissance → exploitation → persistence)
- Realistic timing and intervals between steps
- Event correlation IDs for tracking attack chains

✅ **Configurable parameters**

- Target hosts and users
- Attack duration and intensity
- Success/failure ratio
- Detection avoidance techniques (optional, for advanced learning)

✅ **Artifact generation**

- Network connections (logs, DNS)
- Process execution chains
- File modifications
- Registry changes
- Auth events

✅ **Integration with event pipeline**

- Events written to log files
- Automatic pickup by log aggregator
- Correlation in detection engine

## Usage Examples

```bash
# Simulate brute force attack against admin account
./brute_force_simulation.sh --target-user admin --attempts 50 --delay 200ms

# Simulate lateral movement chain
./lateral_movement_simulation.sh --start-host web-01 --targets db-01,db-02,dc-01

# Simulate multi-phase APT scenario
./c2_beacon_simulation.sh --callback-interval 60s --duration 10m --data-transfer 5gb

# List all available scenarios
./attack_simulator.sh --list-scenarios
```

## Attack Scenarios

The scripts provide several core attack scenarios for learning and testing:

**Included Scenarios:**

1. **Brute Force Attack** (`brute_force_simulation.sh`)
   - Multiple failed login attempts
   - Ramp-up pattern (1 attempt, then escalation)
   - Expected detection: Failed login spike

2. **Lateral Movement** (`lateral_movement_simulation.sh`)
   - Initial compromise → lateral tool usage (PsExec, SMB)
   - Expected detection: Unusual lateral connection, suspicious process parent

3. **Data Exfiltration** (`exfiltration_simulation.sh`)
   - Large file access and transfer
   - DNS exfiltration (optional)
   - Expected detection: Unusual egress volume, DNS anomalies

For additional scenarios and advanced attack simulations, see [docs/roadmap.md](../docs/roadmap.md).

## Configuration

See `config/scenarios.yaml` for:

- Scenario definitions (steps, timings, targets)
- Event templates (what logs are generated)
- Parameter validation and constraints

## Integration with Lab Stack

Scripts assume:

1. **Mock event generator is running** – Events are written to `/var/log/soc-lab/`
2. **Log aggregator is monitoring logs** – Filebeat/Logstash picks up new events
3. **Elasticsearch/data lake is available** – Events are indexed for querying

## Safety & Ethics

⚠️ **Important Notes:**

- These scripts generate **synthetic events only** – they do NOT execute actual attacks
- Use **only within the SOC Lab environment**
- Do **not** run against production systems
- For learning purposes only
- Always document and timestamp attack simulations in lab notes

## Testing Detections

Typical workflow:

1. Start the lab with `docker-compose up`
2. Wait for baseline data to accumulate (5–10 minutes)
3. Run an attack simulation: `./brute_force_simulation.sh --target-user admin --attempts 50`
4. Observe detection queries firing: `http://localhost:5601`
5. Document which detections fired and any gaps
6. Tune detection thresholds if needed

## Next Steps

For advanced attack scenarios and additional simulation techniques, see [docs/roadmap.md](../docs/roadmap.md) for planned enhancements.
