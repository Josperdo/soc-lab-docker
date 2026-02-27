# Log Generator

**Purpose:** Synthetic log event generation for the SOC Lab

## Overview

This directory contains tooling for generating realistic, configurable security event logs that will be used to populate the lab environment.

## Structure

This directory contains tooling for generating realistic, configurable security event logs that populate the lab environment.

**Key files:**

- `Dockerfile` – Container image definition for the log generator service
- `generator.py` (or `.sh`) – Main log generation script
- `templates/` – Event template definitions (JSON/YAML)
  - `authentication_events.yaml` – Login, logout, failed auth attempts
  - `web_traffic.yaml` – HTTP requests, response codes, source IPs
  - `process_execution.yaml` – Process creation, parent/child relationships
  - `network_events.yaml` – Network connections, DNS queries
  - `security_alerts.yaml` – IDS/IPS, antivirus, EDR alerts
- `requirements.txt` – Python dependencies (if using Python)
- `config.yaml` – Generator configuration (event rates, distributions, etc.)

## Capabilities

**Configurable event generation**

- Event volume (events per second)
- Event type selection
- Time distribution (burst vs. normal)

**Realistic event structures**

- Timestamps and correlation IDs
- Synthetic user and host identities
- Realistic field values (source IPs, user agents, domains)

**Extensible template system**

- Add new event types without code changes
- YAML/JSON template definitions
- Macro substitution (${USER}, ${HOST}, etc.)

**Output formats**

- JSON (for Elasticsearch, data lakes)
- Syslog (for log aggregators)
- CSV (for analysis)

## Usage Examples

```bash
# Generate 10 events per second for 60 seconds
python generator.py --rate 10 --duration 60 --output-file logs.json

# Generate only authentication events
python generator.py --events authentication --rate 5

# Generate continuous stream (until stopped)
python generator.py --continuous --rate 20
```

## Configuration

See `config.yaml` for:

- Event type definitions
- Field value distributions
- Correlation rules (chaining events logically)
- Output path and format

## Integration with Docker Compose

The log generator runs as a service container in Docker Compose:

```yaml
log-generator:
  build: ./generator
  volumes:
    - ./data/logs:/var/log/soc-lab
  environment:
    - LOG_GENERATION_RATE=10
    - EVENT_TYPES=authentication,web_traffic
```

See [docker-compose.yml](../docker-compose.yml) for full configuration.

## Next Steps

- Implement template-based event generation
- Add synthetic user and host directory
- Integrate with log aggregator pipeline
- Validate event structure and field coverage
