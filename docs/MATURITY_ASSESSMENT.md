# Detection Engineering Maturity Assessment

This document provides a self-assessment framework for evaluating your
detection engineering program's maturity. Use it to benchmark your current
state, identify gaps, and prioritize improvements.

---

## How to Use This Assessment

1. Read each capability area and its maturity levels (0–4)
2. Score your program at the level that best describes your **current state**
   (not aspirational state)
3. Sum your scores and divide by the number of sections for your overall score
4. Use the improvement roadmap to prioritize work in each area
5. Reassess quarterly to track progress

**Scoring Key:**
| Score | Level | Description |
|-------|-------|-------------|
| 0 | Initial | No capability — detection is ad hoc or absent |
| 1 | Developing | Basic capability exists but is inconsistent or undocumented |
| 2 | Defined | Capability is documented, repeatable, and team-understood |
| 3 | Managed | Capability is measured, tracked, and continuously improved |
| 4 | Optimizing | Industry-leading capability; contributes to external community |

---

## Section 1: Detection Coverage

### 1.1 MITRE ATT&CK Coverage

**Question:** What percentage of relevant ATT&CK techniques do you have
active detections for?

| Score | Criteria |
|-------|---------|
| 0 | No systematic mapping to ATT&CK |
| 1 | Ad hoc detections cover <20% of relevant techniques |
| 2 | Documented coverage of 20–50% of in-scope techniques |
| 3 | 50–80% coverage with regular gap analysis and prioritization |
| 4 | >80% coverage; actively triaging new techniques as they emerge |

**Your score:** ___

**Notes / Evidence:**

```
SOC Lab coverage as of Phase 4:
  Tactics covered: Initial Access, Execution, Persistence, Privilege Escalation,
                   Defense Evasion, Credential Access, Discovery, Lateral Movement,
                   Collection, Command & Control, Exfiltration
  Techniques with detections (22 unique IDs):
    T1110, T1110.001, T1110.003, T1110.004
    T1021, T1021.001, T1021.002
    T1047, T1546.003, T1543.003, T1570
    T1068, T1134, T1548.002, T1548.003, T1078
    T1053.005, T1547.001
    T1041, T1048, T1048.003, T1560.001
    T1566.001, T1059.001, T1059.003
    T1071.001, T1029, T1074.001, T1027, T1140
    T1005, T1070.001, T1070.004, T1558.003, T1132.001

  Lab score recommendation: 2 (detection library exists and is documented;
  coverage percentage vs. full ATT&CK matrix is unknown without a gap analysis)
```

---

### 1.2 Data Source Coverage

**Question:** Do your detections have access to the log sources they need?

| Score | Criteria |
|-------|---------|
| 0 | Log collection is inconsistent; major sources are missing |
| 1 | Core Windows/Linux OS logs collected but many gaps |
| 2 | Process, network, authentication logs collected across most assets |
| 3 | Endpoint, network, cloud, and identity logs unified in one platform |
| 4 | Real-time telemetry from all assets with < 30s ingestion latency |

**Your score:** ___

**Notes / Evidence:**

```
SOC Lab data sources (from generator.py):
  ✓ Authentication events (success/failure)
  ✓ Process execution (parent/child, command lines, integrity level)
  ✓ Network flows (TCP, bytes, ports)
  ✓ DNS queries (domain resolution)
  ✓ Registry modifications (value_set events)
  ✓ File events (create/delete)
  ✓ WMI events (subscription creation)
  ✓ Service installation events
  ✗ Cloud API logs
  ✗ Email/phishing events (simulated as process events only)
  ✗ Endpoint DLP events

  Lab score recommendation: 2
```

---

## Section 2: Detection Quality

### 2.1 False Positive Rate

**Question:** What is the signal-to-noise ratio of your active detections?

| Score | Criteria |
|-------|---------|
| 0 | Detections are not tuned; alert fatigue is severe |
| 1 | Most rules fire frequently; less than 30% are actionable |
| 2 | Majority of alerts are actionable; tuning happens reactively |
| 3 | Tracked FP rate per rule; systematic tuning on a monthly cadence |
| 4 | <5% FP rate fleet-wide; ML-assisted noise reduction |

**Your score:** ___

---

### 2.2 Detection Logic Validation

**Question:** Are your detection rules tested against known-good and attack data?

| Score | Criteria |
|-------|---------|
| 0 | Rules are deployed without testing |
| 1 | Rules are manually tested against attack data occasionally |
| 2 | Detections tested against attack simulations before deployment |
| 3 | Automated unit tests run in CI pipeline for every rule change |
| 4 | Red team exercises validate detection coverage end-to-end quarterly |

**Your score:** ___

**Notes / Evidence:**

```
SOC Lab validation approach:
  ✓ Attack simulation scripts generate events for each detection category
  ✓ ES|QL/SPL/KQL queries verified to run without errors in Kibana 8.11
  ✓ JSON event generation validated (all heredoc outputs validated via jq)
  ✗ Automated CI unit tests for detection logic
  ✗ Periodic red team exercises

  Lab score recommendation: 2
```

---

### 2.3 Severity Calibration

**Question:** Are severity levels accurate and consistently applied?

| Score | Criteria |
|-------|---------|
| 0 | Everything is HIGH; no calibration |
| 1 | Severity is set by intuition without documented criteria |
| 2 | Severity rubric exists and is applied to new rules |
| 3 | Severity is reviewed against real-world outcomes quarterly |
| 4 | Risk-based severity dynamically adjusts based on asset criticality |

**Your score:** ___

**Notes / Evidence:**

```
SOC Lab severity rubric (from detections/sigma/README.md):
  informational → single low-value events
  low           → weak individual indicators
  medium        → moderately suspicious, needs context
  high          → strong indicator; investigate promptly
  critical      → near-certain malicious; immediate action

  Lab score recommendation: 2
```

---

## Section 3: Detection Process

### 3.1 Detection Development Lifecycle

**Question:** Is there a documented process for creating, reviewing, and
deploying new detection rules?

| Score | Criteria |
|-------|---------|
| 0 | No process; detections created ad hoc |
| 1 | Informal process exists but is not documented |
| 2 | Documented lifecycle: proposal → review → test → deploy → tune |
| 3 | Lifecycle enforced by tooling (pull requests, CI pipeline) |
| 4 | Metrics tracked per stage; SLA targets met for deployment velocity |

**Your score:** ___

---

### 3.2 Threat Intelligence Integration

**Question:** Are new detections informed by current threat intelligence?

| Score | Criteria |
|-------|---------|
| 0 | No threat intelligence consumed |
| 1 | TI consumed informally; occasionally drives new detections |
| 2 | Structured TI feeds inform quarterly detection reviews |
| 3 | Automated IOC ingestion; new TTPs trigger detection tickets |
| 4 | Bi-directional TI sharing with industry groups; real-time TTP tracking |

**Your score:** ___

---

### 3.3 Coverage Gap Analysis

**Question:** Do you regularly identify and prioritize coverage gaps?

| Score | Criteria |
|-------|---------|
| 0 | No gap analysis; coverage is unknown |
| 1 | Ad hoc gap review when major incidents occur |
| 2 | Quarterly ATT&CK navigator review against active threat groups |
| 3 | Automated coverage heatmap updated on every deployment |
| 4 | Risk-weighted gap analysis tied to threat model and asset inventory |

**Your score:** ___

---

## Section 4: Response Capability

### 4.1 Playbook Coverage

**Question:** Are documented response playbooks available for active alerts?

| Score | Criteria |
|-------|---------|
| 0 | No playbooks; response is improvised |
| 1 | Playbooks exist for major incident types only |
| 2 | Playbooks documented for all active alert rules |
| 3 | Playbooks tested and updated quarterly via tabletop exercises |
| 4 | Playbooks integrated into SOAR for automated response steps |

**Your score:** ___

**Notes / Evidence:**

```
SOC Lab playbooks (in docs/ALERTING.md):
  ✓ Brute Force Authentication
  ✓ PsExec Lateral Movement
  ✓ Large Data Transfer
  ✓ WMI Remote Execution
  ✓ Scheduled Task Persistence

  Lab score recommendation: 2
```

---

### 4.2 Mean Time to Detect (MTTD)

**Question:** How quickly are threats detected after events occur?

| Score | Criteria |
|-------|---------|
| 0 | No measurement; detection is often days or weeks |
| 1 | MTTD not tracked; estimated >24 hours |
| 2 | MTTD tracked per incident; average <8 hours |
| 3 | MTTD average <1 hour for high-severity rules |
| 4 | MTTD <15 minutes for critical technique coverage |

**Your score:** ___

**Notes / Evidence:**

```
SOC Lab polling interval: 60 seconds (configurable)
Maximum MTTD in lab: ~ALERT_INTERVAL + LOOKBACK + investigation time
At defaults (60s interval, 5m lookback): effective MTTD ≈ 6 minutes

Lab score recommendation: 3 (for lab context;
apply a lower score for production environments without near-real-time alerting)
```

---

### 4.3 Alert Triage Workflow

**Question:** Is there a defined workflow for triaging incoming alerts?

| Score | Criteria |
|-------|---------|
| 0 | Alerts go unreviewed or are manually checked infrequently |
| 1 | Alerts reviewed when time permits; no SLA |
| 2 | Defined triage workflow with priority queue; SLA for high alerts |
| 3 | Alerts enriched automatically (user context, asset criticality) |
| 4 | Risk-scored triage with AI-assisted similarity detection |

**Your score:** ___

---

## Section 5: Detection Engineering Infrastructure

### 5.1 Detection-as-Code

**Question:** Are detection rules stored in version control with peer review?

| Score | Criteria |
|-------|---------|
| 0 | Rules stored in SIEM UI only; no version history |
| 1 | Rules exported and stored in files but no VCS |
| 2 | Rules in version control; changes require pull requests |
| 3 | CI pipeline validates syntax and tests rules before merge |
| 4 | Fully automated deployment pipeline with rollback capability |

**Your score:** ___

**Notes / Evidence:**

```
SOC Lab approach:
  ✓ All detections in Git (SPL, KQL, Sigma YAML)
  ✓ CI pipeline (.github/workflows/ci.yml) validates stack
  ✗ CI does not yet validate detection query syntax
  ✗ No automated deployment to SIEM

  Lab score recommendation: 2
```

---

### 5.2 Detection Library Management

**Question:** Is your detection library organized and easily searchable?

| Score | Criteria |
|-------|---------|
| 0 | No organization; detections scattered across tools |
| 1 | Detections grouped informally; search is manual |
| 2 | Organized by tactic/technique with consistent naming |
| 3 | Metadata (MITRE tags, severity, status) enables automated filtering |
| 4 | Full-featured detection management platform with analytics |

**Your score:** ___

**Notes / Evidence:**

```
SOC Lab library structure:
  detections/{tactic}/{rule}.{spl,kql}   — SIEM-specific queries
  detections/sigma/*.yml                  — Portable Sigma rules
  Consistent MITRE tagging across all files
  README.md in each directory

  Lab score recommendation: 3
```

---

### 5.3 Portability (Multi-SIEM Support)

**Question:** Can your detections be deployed across multiple SIEM platforms?

| Score | Criteria |
|-------|---------|
| 0 | Detections are platform-specific and cannot be ported |
| 1 | Manual translation between platforms is occasionally done |
| 2 | Detections documented in both SPL and KQL |
| 3 | Sigma rules enable automated compilation to any supported backend |
| 4 | Automated multi-platform deployment with parity validation |

**Your score:** ___

**Notes / Evidence:**

```
SOC Lab portability:
  ✓ All detections written in both SPL (Splunk) and KQL (Elasticsearch/Sentinel)
  ✓ Sigma rules enable compilation to 30+ SIEM backends
  ✗ Automated parity testing between platforms

  Lab score recommendation: 3
```

---

## Scoring Summary

Complete the table after scoring each section:

| Section | Area | Your Score | Max |
|---------|------|-----------|-----|
| 1.1 | ATT&CK Coverage | | 4 |
| 1.2 | Data Source Coverage | | 4 |
| 2.1 | False Positive Rate | | 4 |
| 2.2 | Detection Logic Validation | | 4 |
| 2.3 | Severity Calibration | | 4 |
| 3.1 | Detection Development Lifecycle | | 4 |
| 3.2 | Threat Intelligence Integration | | 4 |
| 3.3 | Coverage Gap Analysis | | 4 |
| 4.1 | Playbook Coverage | | 4 |
| 4.2 | Mean Time to Detect | | 4 |
| 4.3 | Alert Triage Workflow | | 4 |
| 5.1 | Detection-as-Code | | 4 |
| 5.2 | Detection Library Management | | 4 |
| 5.3 | Portability | | 4 |
| **Total** | | **___ / 56** | **56** |
| **Average** | | **___ / 4.0** | **4.0** |

### Overall Maturity Level

| Score Range | Maturity Level |
|------------|----------------|
| 0.0 – 1.0 | **Initial** — Begin with fundamentals: log collection and a few high-confidence rules |
| 1.1 – 2.0 | **Developing** — Systematize: document your library, establish a development lifecycle |
| 2.1 – 3.0 | **Defined** — Measure: track FP rates, MTTD, and ATT&CK coverage percentages |
| 3.1 – 4.0 | **Managed** — Optimize: automate deployment, integrate TI, run red team exercises |

---

## SOC Lab Benchmark

Using the lab documentation as the evidence base, here is an estimated score
for the SOC Lab Docker project in its Phase 4 state:

| Section | Score | Rationale |
|---------|-------|-----------|
| 1.1 ATT&CK Coverage | 2 | 30+ technique IDs mapped, but no formal gap analysis vs. full matrix |
| 1.2 Data Source Coverage | 2 | All major ECS categories covered; no cloud/email telemetry |
| 2.1 False Positive Rate | 2 | Tuning guidance documented; not yet measured against live traffic |
| 2.2 Logic Validation | 2 | Attack simulations validate events; no automated rule unit tests |
| 2.3 Severity Calibration | 2 | Published rubric applied consistently across Sigma rules |
| 3.1 Dev Lifecycle | 2 | CI pipeline validates stack; no detection-specific CI checks |
| 3.2 Threat Intel | 1 | MITRE coverage but no live TI feed integration |
| 3.3 Gap Analysis | 1 | No automated gap analysis tooling yet |
| 4.1 Playbook Coverage | 2 | 5 documented playbooks matching active alert rules |
| 4.2 MTTD | 3 | 60s poll interval gives ~6 min MTTD in lab context |
| 4.3 Triage Workflow | 1 | Alert notifier fires; triage is manual |
| 5.1 Detection-as-Code | 2 | Git + CI; no detection query validation in CI |
| 5.2 Library Management | 3 | Tactic-organized, consistently tagged |
| 5.3 Portability | 3 | SPL + KQL + Sigma across all rules |
| **Total** | **28 / 56** | **Average: 2.0 — Defined** |

**This is a healthy score for a training lab.** The Defined level means the
foundations are solid and the next step is adding measurement (FP tracking,
coverage metrics) to move toward Managed.

---

## Improvement Roadmap

### To reach Level 3 (Managed) in each area

| Priority | Action | Effort |
|----------|--------|--------|
| High | Add ATT&CK Navigator heatmap showing lab detection coverage | Low |
| High | Add CI step to validate detection query syntax (sigma check) | Low |
| High | Build FP rate tracking: log each alert to a file, review monthly | Medium |
| Medium | Integrate a free TI feed (AbuseIPDB, Abuse.ch) for IOC enrichment | Medium |
| Medium | Automate ATT&CK coverage report from Sigma rule tags | Medium |
| Medium | Add triage enrichment to alert_notifier.sh (user context, asset lookup) | High |
| Low | Tabletop exercise using ATTACK_SCENARIOS.md as the scenario input | Low |
| Low | Publish detection library to SigmaHQ community repo | Low |

---

## References

- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — visualize coverage
- [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT) — ATT&CK data source and detection maturity scoring
- [Detection Maturity Model (L1CFC)](https://github.com/center-for-threat-informed-defense/sensor-mappings-to-attack) — CTID coverage model
- [Palantir ADS Framework](https://github.com/palantir/alerting-detection-strategy-framework) — detection strategy templates
- [SANS Detection Engineering course](https://www.sans.org/cyber-security-courses/detection-engineering/) — formal training
