# SOC Lab Docker

[![CI](https://github.com/Josperdo/soc-lab-docker/actions/workflows/ci.yml/badge.svg)](https://github.com/Josperdo/soc-lab-docker/actions/workflows/ci.yml)

**A Docker-based detection engineering lab for learning blue team skills**

---

## Overview

**SOC Lab Docker** is an open-source security operations center (SOC) lab environment designed for defenders, detection engineers, and security analysts to learn and practice blue team tradecraft in a controlled, reproducible setting.

This project provides:

- A **containerized lab stack** (Docker Compose) for instant deployment
- **Mock log generation** simulating realistic security events
- **Attack simulation scripts** to trigger detectable events
- **Detection queries & examples** for learning query languages (KQL, SPL, PromQL)
- **Pre-built dashboards** to visualize security data
- **Comprehensive documentation** for architecture, lab deployment, and learning paths

Whether you're new to detection engineering, preparing for security certifications, or building detection portfolios, SOC Lab Docker provides a hands-on learning environment without requiring enterprise infrastructure.

---

## Key Features

**Local Docker Stack**

- Compose-based deployment (Elasticsearch, data lake, log shipper, UI)
- One-command lab spin-up: `docker-compose up`
- Development-friendly with `.env` configuration

**Realistic Log Generation**

- Mock event generator (web traffic, auth, OS events, security tools)
- Configurable event volume and distribution
- Extensible for custom log types

**Attack Simulation**

- Bash/Python scripts simulating common attack patterns
- Coordinated event chains (reconnaissance → exploitation → exfiltration)
- Educational annotations explaining each step

**Detection Examples**

- Query templates for common SPL, KQL, PromQL use cases
- Best practices for detection tuning and baseline methodology
- Threat mappings (MITRE ATT&CK) where applicable

**Dashboard Gallery**

- Sample dashboards (event overview, alerts, anomalies)
- Guided walkthroughs for query building
- Export-ready configurations

**Comprehensive Documentation**

- Architecture overview
- Lab deployment guide
- Learning roadmap with milestones
- Security & engineering considerations

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     SOC Lab Docker Stack                    │
├──────────────────────────┬──────────────────────────────────┤
│  Event Generation Layer  │     Data Collection Layer        │
│  ┌────────────────────┐  │  ┌──────────────────────────────┐│
│  │ Mock Log Generator │  │  │  Log Forwarder / Aggregator  ││
│  │ (Python/Bash)      │  │  │  (Filebeat, Logstash, etc.)  ││
│  │ - Web Traffic      │  │  └────────────┬─────────────────┘│
│  │ - Auth Events      │  │               │                  │
│  │ - OS Logs          │  │  ┌────────────▼─────────────────┐│
│  │ - Security Alerts  │  │  │  Search & Index (Elastic)    ││
│  └────────────────────┘  │  │  or Data Lake (ADLS)         ││
│                          │  └────────────┬─────────────────┘│
├──────────────────────────┴──────────────────────────────────┤
│                    Query & Analysis Layer                   │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐     │
│  │ Detection    │  │  Interactive │  │   Dashboards   │     │
│  │ Queries      │  │  Query Tool  │  │  & Visualize   │     │
│  │ (SPL/KQL)    │  │              │  │                │     │
│  └──────────────┘  └──────────────┘  └────────────────┘     │
└─────────────────────────────────────────────────────────────┘

Attack Simulation Scripts ──► Event Generator ──► Logs ──► Detections
```

---

## Installation & Local Deployment

### Prerequisites

**Supported platforms:** Linux and Windows (via WSL2 + Docker Desktop). macOS has not been verified in CI and is not officially supported.

- Docker & Docker Compose (v20+)
- 4GB+ RAM available
- Git
- Bash (Linux / WSL2) or PowerShell terminal (Windows)

### Quick Start

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourusername/soc-lab-docker.git
   cd soc-lab-docker
   ```

2. **Configure environment variables**

   ```bash
   cp .env.example .env
   # Edit .env as needed for your deployment
   ```

3. **Spin up the lab stack**

   ```bash
   docker-compose up -d
   ```

4. **Verify deployment**

   ```bash
   docker-compose ps
   # All services should be "Up"
   ```

5. **Access the lab UI**
   - Dashboard: `http://localhost:5601` (or configured port)
   - Query tool: `http://localhost:9200` (or service endpoint)

### Full deployment instructions, environment setup, and troubleshooting available in [docs/SETUP.md](docs/SETUP.md)

---

## Simulating Attacks

### Basic Attack Simulation

The **scripts/** directory contains executable attack simulations that generate detectable events.

#### Example: Brute Force Attack

```bash
./scripts/brute_force_simulation.sh \
  --target-user admin \
  --attempt-count 50 \
  --delay-ms 200
```

This script will:

1. Generate failed authentication attempts
2. Timestamp and correlate events
3. Log activity to the event pipeline
4. Create artifact detection opportunities

#### Example: Lateral Movement Chain

```bash
./scripts/lateral_movement_simulation.sh \
  --start-host web-server-01 \
  --target-hosts internal-db-01,internal-db-02 \
  --tool psexec
```

This simulates reconnaissance → privilege escalation → lateral movement, with each step logged and detectable.

### Attack Simulation Reference

- [scripts/README.md](scripts/README.md) – Full script documentation and attack scenarios
- [docs/ATTACK_SCENARIOS.md](docs/ATTACK_SCENARIOS.md) – Detailed threat models and expected artifacts

---

## Viewing & Building Detections

### Query Examples

Sample detection queries are located in **detections/**:

```
detections/
├── authentication/
│   ├── failed_login_spike.spl          # Splunk query
│   ├── failed_login_spike.kql          # KQL (Sentinel/Analytics)
│   └── README.md
├── lateral_movement/
│   ├── psexec_detection.spl
│   ├── psexec_detection.kql
│   └── ...
└── exfiltration/
    └── ...
```

#### Example: View a Detection Query

```bash
cat detections/authentication/failed_login_spike.spl
```

#### Example: Load a Query into Your Dashboard

1. Copy the content from `detections/authentication/failed_login_spike.spl`
2. Paste into your search UI at `http://localhost:5601`
3. Run the query against the mock log data
4. Adjust thresholds and time windows for tuning

### Dashboards

Pre-built dashboards are located in **dashboards/**:

- Import `.json` files via your dashboard UI
- Customize visualizations and thresholds
- Export for team sharing

---

## Security & Engineering Considerations

### Design Philosophy

- **Learning-first**: Every component is documented; understand the "why" behind detections
- **Reproducibility**: Forkable and runnable in 5 minutes on any machine with Docker
- **Realism**: Mock logs match real security data structures and event volumes
- **Extensibility**: Add custom log generators, attack scripts, and detections

### Important Notes

- **Lab Environment Only**: This is not production-grade monitoring. Use for learning and testing only.
- **No Persistence**: By default, the lab runs in-memory; data is lost on container shutdown. See [docs/SETUP.md](docs/SETUP.md) for persistent storage options.
- **No Network Isolation**: For simplicity, containers communicate across a shared network. Use network policies and isolation in production.
- **Minimal Authentication**: The lab uses default credentials for ease of learning. Never expose to the internet without hardening.

### Best Practices

- Keep detection rules simple and well-documented for maintainability
- Use MITRE ATT&CK framework for categorizing detections
- Test detection efficacy using the provided attack scripts
- Version control detection queries separately from dashboards
- Reference external threat intelligence (MITRE, CIS, NIST) in detection notes

---

## Azure Sentinel Integration

Deploy the lab's detection library to Microsoft Sentinel — the leading enterprise cloud SIEM — using Terraform and ARM templates.

**What's included (`terraform/sentinel/`):**

- **Terraform IaC** — Log Analytics Workspace + Sentinel onboarding, fully parameterized
- **8 analytics rules** — All lab detections as `azurerm_sentinel_alert_rule_scheduled` resources with MITRE tactics, entity mappings, and tunable frequency/lookback
- **3 SOAR playbooks** — ARM Logic App templates for Slack notification, ticket creation (ServiceNow/JIRA pattern), and host isolation
- **Data connector guide** — Forward lab events via Filebeat → Azure Monitor for end-to-end pipeline experience

```bash
cd terraform/sentinel
terraform init
terraform apply -var-file="terraform.tfvars"
```

No live Azure subscription required to study or customize the templates. See [docs/SENTINEL_INTEGRATION.md](docs/SENTINEL_INTEGRATION.md) for the full deployment walkthrough.

See [docs/roadmap.md](docs/roadmap.md) for the full capabilities roadmap.

---

## License

This project is licensed under the [MIT License](LICENSE). Feel free to fork, modify, and use for educational purposes.

---

## Authors & Acknowledgments

**Created by:** John Sperry

**Inspired by:** Blue team tradecraft, detection engineering best practices, and the open-source security community.

---

## Learning Resources

| Guide | Level | Description |
|---|---|---|
| [Beginner Guide](docs/BEGINNER_GUIDE.md) | Beginner | End-to-end walkthrough: simulate an attack, find events, write your first detection query |
| [Intermediate Guide](docs/INTERMEDIATE_GUIDE.md) | Intermediate | Build a custom detection from scratch using the full detection engineering methodology |
| [Sentinel Integration](docs/SENTINEL_INTEGRATION.md) | Advanced | Deploy all lab detections to Azure Sentinel via Terraform; add SOAR playbooks |
| [Attack Scenarios](docs/ATTACK_SCENARIOS.md) | Reference | MITRE ATT&CK-mapped event chains for each simulation script |
| [Alerting Guide](docs/ALERTING.md) | Reference | Alert rule format, notification backends, and response playbooks |
| [Compliance Mapping](docs/COMPLIANCE_MAPPING.md) | Reference | CIS Controls v8 and NIST CSF 2.0 mapping for all lab detections |

**Other docs:**
- [Setup & Deployment Guide](docs/SETUP.md)
- [Architecture Deep Dive](docs/ARCHITECTURE.md)
- [Roadmap & Milestones](docs/roadmap.md)

For issues, questions, or feature requests, please open a GitHub issue.

---

**Happy detecting!**
