# SOC Lab Docker – Architecture Overview

---

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Component Descriptions](#component-descriptions)
3. [Data Flow](#data-flow)
4. [Technology Stack](#technology-stack)
5. [Design Decisions](#design-decisions)
6. [Future Extensibility](#future-extensibility)

---

## System Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                          SOC Lab Docker Stack                              │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │                      EVENT GENERATION LAYER                         │ │
│  │  ┌─────────────────────┐         ┌─────────────────────────────┐  │ │
│  │  │  Mock Log Generator │         │  Attack Simulation Scripts  │  │ │
│  │  │  (Container)        │         │  (On-demand)                │  │ │
│  │  │                     │         │                             │  │ │
│  │  │ • Auth events       │         │ • Brute force              │  │ │
│  │  │ • Web traffic       │         │ • Lateral movement         │  │ │
│  │  │ • Process exec      │         │ • Exfiltration            │  │ │
│  │  │ • Network events    │         │ • Privilege escalation     │  │ │
│  │  │ • Security alerts   │         │                             │  │ │
│  │  └──────────┬──────────┘         └────────────┬────────────────┘  │ │
│  │             │                                 │                   │ │
│  │             └─────────────────┬────────────────┘                   │ │
│  │                               ▼                                   │ │
│  │                       ┌──────────────────┐                         │ │
│  │                       │   Log Files      │                         │ │
│  │                       │  /var/log/       │                         │ │
│  │                       └────────┬─────────┘                         │ │
│  └────────────────────────────────┼─────────────────────────────────┘ │
│                                   │                                    │
│  ┌────────────────────────────────▼─────────────────────────────────┐ │
│  │                    DATA COLLECTION LAYER                        │ │
│  │  ┌──────────────────────────────────────────────────────────┐  │ │
│  │  │        Log Aggregator Container                         │ │ │
│  │  │  (Filebeat / Logstash / Fluentd)                        │  │
│  │  │                                                          │ │ │
│  │  │  • Monitors log files for new events                    │  │ │
│  │  │  • Parses and enriches events                           │  │ │
│  │  │  • Sends to data store                                  │  │ │
│  │  └────────────────┬─────────────────────────────────────┘  │ │
│  └──────────────────┼──────────────────────────────────────────┘ │
│                     │                                             │
│  ┌──────────────────▼──────────────────────────────────────────┐ │
│  │            STORAGE & INDEXING LAYER                        │ │
│  │  ┌────────────────────────────────────────────────────┐   │ │
│  │  │    Elasticsearch / Data Lake                       │   │ │
│  │  │    (Distributed search & index engine)             │   │ │
│  │  │                                                    │   │ │
│  │  │  • Indexes incoming events                         │   │ │
│  │  │  • Maintains time-based indices                    │   │ │
│  │  │  • Enforces retention policies                     │   │ │
│  │  │  • Provides REST API for queries                   │   │ │
│  │  └────────────────┬───────────────────────────────────┘   │ │
│  └──────────────────┼────────────────────────────────────────┘ │
│                     │                                            │
│  ┌──────────────────▼────────────────────────────────────────┐ │
│  │         QUERY & ANALYSIS LAYER                          │ │
│  │  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐  │ │
│  │  │ Query UI     │  │ Dashboards  │  │ Alerts       │  │ │
│  │  │ (Kibana,     │  │ (Pre-built) │  │ Framework    │  │ │
│  │  │  Grafana)    │  │             │  │ (In Phase 4) │  │ │
│  │  │              │  │             │  │              │  │ │
│  │  │ • Ad-hoc     │  │ • Overview  │  │ • Rules      │  │ │
│  │  │   queries    │  │ • Auth      │  │ • Triggers   │  │ │
│  │  │ • SPL/KQL    │  │ • Alerts    │  │ • Actions    │  │ │
│  │  │ • Result     │  │             │  │              │  │ │
│  │  │   export     │  │             │  │              │  │ │
│  │  └──────────────┘  └─────────────┘  └──────────────┘  │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                                │
└────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│                    EXTERNAL SERVICES & INTEGRATIONS (Future)                │
│                                                                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │ Cloud Providers  │  │ Threat Intel     │  │ SIEM Integrations│          │
│  │ (AWS, Azure,     │  │ (VirusTotal,     │  │ (Splunk, Sentinel│          │
│  │  GCP)            │  │  Shodan, etc.)   │  │  via REST API)    │          │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘          │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Descriptions

### 1. Event Generation Layer

#### Mock Log Generator

- **Purpose:** Generate synthetic security events resembling production logs
- **Type:** Containerized Python/Bash application
- **Output:** JSON, Syslog, or CSV logs written to shared volume
- **Configurability:**
  - Event volume (events per second)
  - Event types (authentication, web traffic, process execution, network, security alerts)
  - Temporal distribution (steady-state, burst, seasonal patterns)
  - Realistic field values (IPs, domains, user names, etc.)

**Event Types Supported:**

- **Authentication:** Login success/failure, password changes, privilege elevation
- **Web Traffic:** HTTP requests, response codes, user agents, domains
- **Process Execution:** Child/parent processes, command lines, users
- **Network Events:** Connection establishment, DNS queries, traffic volume
- **Security Alerts:** Antivirus, IDS/IPS, EDR tool alerts

#### Attack Simulation Scripts

- **Purpose:** On-demand generation of coordinated attack event chains
- **Type:** Bash/Python scripts executable manually or on schedule
- **Characteristics:**
  - Time-ordered sequences of related events
  - Realistic intervals between attack steps
  - Configurable targets, duration, intensity
  - Designed to trigger detection queries

**Scenarios (Phase 1):**

- Brute force authentication attacks
- Lateral movement (PsExec, SMB)
- Data exfiltration (large transfers, DNS tunneling)

### 2. Data Collection Layer

#### Log Aggregator (Filebeat / Logstash / Fluentd)

- **Purpose:** Collect, parse, and forward logs to central store
- **Responsibilities:**
  - Monitor log files for new entries
  - Parse semi-structured logs (extract fields)
  - Enrich events with metadata
  - Buffer and batch for performance
  - Forward to Elasticsearch/data lake

**Processing Steps:**

1. **Input:** Read from log files or syslog socket
2. **Parsing:** Extract fields using patterns or JSON parsing
3. **Enrichment:** Add context (timestamp normalization, GeoIP, threat intel)
4. **Output:** Send to Elasticsearch with proper indexing metadata

### 3. Storage & Indexing Layer

#### Elasticsearch (or Alternative Data Lake)

- **Purpose:** Centralized storage, indexing, and search of all lab events
- **Key Features:**
  - **Inverted index:** Fast full-text and field-based search
  - **Time-based indices:** Automatic daily index rollover (e.g., `logs-2026.02.26`)
  - **Retention policy:** Automatic deletion of old indices (configurable, default 7 days)
  - **REST API:** JSON-based query interface
  - **Horizontal scaling:** Add nodes for higher event volume

**Index Structure:**

```
Index: logs-2026.02.26
├── @timestamp (time of event)
├── source (hostname that originated event)
├── user (user associated with event)
├── event_type (authentication, network, etc.)
├── action (success, failure, created, deleted, etc.)
├── [type-specific fields]
```

### 4. Query & Analysis Layer

#### Web UI (Kibana / Grafana)

- **Purpose:** Interactive interface for searching, visualizing, and analyzing events
- **Capabilities:**
  - **Ad-hoc queries:** Write SPL/KQL/PromQL directly
  - **Dashboards:** Pre-built visualizations of key metrics
  - **Alerting:** Define rules that fire when conditions are met
  - **Export:** Download results as CSV, JSON, or visualizations as images

#### Detection Queries

- **Purpose:** Systematic identification of security events matching attack patterns
- **Format:** SPL (Splunk), KQL (Azure Sentinel), PromQL (Prometheus)
- **Execution:** Scheduled or on-demand
- **Output:** Alert notifications, dashboard panels, or investigation lists

---

## Data Flow

### Normal Event Pipeline (Continuous)

```
1. Mock Generator
   └─> Writes events to /var/log/soc-lab/events.json (continuously)

2. Log Aggregator
   └─> Monitors event log file
   └─> Parses JSON events
   └─> Enriches events (timestamps, GeoIP, metadata)
   └─> Sends to Elasticsearch HTTP API

3. Elasticsearch
   └─> Receives events
   └─> Indexes into time-based indices (logs-2026.02.26)
   └─> Available immediately for querying

4. Web UI (Kibana)
   └─> User queries Elasticsearch via UI
   └─> Displays results in tables, charts, maps
   └─> Visualizations update in real-time
```

### Attack Simulation Pipeline (On-Demand)

```
1. User executes attack script
   $ ./scripts/brute_force_simulation.sh --target-user admin --attempts 50

2. Script generates attack events
   └─> Multiple authentication failure events
   └─> Coordinated timestamps and source IPs
   └─> Written to event log

3. Aggregator picks up new events (within seconds)
   └─> Parses and forwards to Elasticsearch

4. Detection queries evaluate
   └─> "Brute force" query fires when failure count exceeds threshold
   └─> Alert displayed in UI
   └─> User investigates in dashboards
```

---

## Technology Stack

### Phase 1 (MVP)

| Layer         | Component      | Technology              | Purpose                          |
| ------------- | -------------- | ----------------------- | -------------------------------- |
| Generation    | Mock Generator | Python 3.9+             | Synthetic log generation         |
| Generation    | Attack Scripts | Bash / Python           | Attack simulation                |
| Collection    | Log Aggregator | Filebeat (or Logstash)  | Log shipping and parsing         |
| Storage       | Data Store     | Elasticsearch 8.x       | Centralized indexing/search      |
| Analysis      | Query UI       | Kibana 8.x              | Interactive search/visualization |
| Orchestration | Container Mgmt | Docker & Docker Compose | Local deployment                 |

### Phase 2+ (Planned Additions)

- **Sigma rules:** Community detection rule standard
- **Alerting framework:** Alert rule definition and execution
- **Advanced visualization:** Grafana, custom dashboards
- **Cloud integration:** AWS, Azure, GCP deployment options

---

## Design Decisions

### 1. **Why Elasticsearch?**

- Powerful full-text search for event discovery
- Native JSON support (no schema enforcement)
- Mature tooling (Kibana) for visualization
- Horizontal scaling for large datasets
- Industry-standard in SOC environments
- Trade-off: Higher memory overhead than some alternatives

**Alternatives considered:** ClickHouse, Loki, Splunk (commercial)

### 2. **Why Docker Compose (not Kubernetes)?**

- Simple, single-command deployment
- Perfect for learning and local development
- No container orchestration complexity
- Minimal system requirements
- Kubernetes support planned for Phase 5 (cloud deployment)

### 3. **Why Filebeat (not Logstash)?**

- Lightweight (minimal CPU/memory)
- Simple configuration for log file monitoring
- Good field parsing for common log formats
- Logstash support could be added later for complex transformations

### 4. **Mock Generation over Production Logs**

- Reproducible and forkable
- No privacy/compliance concerns
- Customizable for learning different scenarios
- No need for real data exports
- May not match 100% of production event structure

---

## Future Extensibility

### Easy Additions (Phase 2–3)

1. **New event types:**
   - Add event template to `generator/templates/`
   - Generator automatically includes in rotation

2. **New detection queries:**
   - Add `.spl` or `.kql` file to `detections/`
   - Load directly in query UI

3. **New dashboards:**
   - Import JSON dashboard template
   - Customize and export

### Moderate Additions (Phase 4–5)

1. **Alternative data stores:**
   - Swap Elasticsearch for ClickHouse, Loki, or ADLS
   - Update Docker Compose service definition
   - Adjust aggregator output configuration

2. **Alerting framework:**
   - Implement alert rule engine
   - Add webhook/email/Slack notifications
   - Integrate with alert suppression logic

3. **Cloud deployment:**
   - Create Terraform/Bicep templates
   - Add Kubernetes manifests
   - Support multi-tenant isolation

---

## Performance Characteristics

### Event Throughput

- **Designed for:** 10–100 events/second (MVP)
- **Limitation:** Docker resource constraints on single machine
- **Scaling:** Add Elasticsearch nodes, use cloud deployment (Phase 5)

### Query Latency

- **Ad-hoc queries:** <1 second (last 24 hours)
- **Dashboard loads:** <5 seconds
- **Large time ranges:** May require optimization

### Storage Per Day

- **Estimate:** ~5GB per day at 30 events/second (with typical field sizes)
- **Retention default:** 7 days (~35GB)
- **Adjustable:** Set `DATA_RETENTION_DAYS` in `.env`

---

## Security Considerations

**Important Notes:**

1. **Development-only:** This stack is NOT production-hardened
2. **Default credentials:** Change admin password immediately
3. **No TLS/SSL:** For development only; enable in production
4. **No authentication:** Container-to-container communication unrestricted
5. **No RBAC:** Elasticsearch has no role-based access control by default
6. **Network isolation:** For learning purposes; use network policies in production

**Hardening recommendations** available in [SETUP.md](SETUP.md#security--hardening).

---

## Glossary

- **Event:** A single log entry or alert
- **Index:** Elasticsearch collection of documents (documents = events)
- **Query:** SPL/KQL syntax to search and aggregate events
- **Detection:** A query designed to identify suspicious pattern
- **Dashboard:** Visual representation of query results
- **Aggregation:** Statistical operation on events (count, sum, avg, etc.)
- **Time-series:** Data point associated with timestamp
- **Baseline:** Normal expected behavior for comparison

---

**For detailed setup instructions, see [SETUP.md](SETUP.md).**  
**For learning paths and tutorials, see [LEARNING_PATH.md](LEARNING_PATH.md).**
