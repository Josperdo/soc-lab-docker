# Detection Queries & Examples

**Purpose:** Query templates and detection rules for learning blue team tradecraft

## Overview

This directory contains example detection queries, rules, and best practices for identifying security events across different query languages and platforms.

## Directory Structure

Queries are organized by attack category:

```
detections/
├── authentication/
│   ├── README.md
│   ├── brute_force_detection.spl        (Splunk Query Language)
│   ├── brute_force_detection.kql        (Kusto Query Language / Azure Sentinel)
│   ├── brute_force_detection.promql     (Prometheus)
│   └── notes.md                         (Tuning, baseline, annotations)
│
├── lateral_movement/
│   ├── README.md
│   ├── psexec_detection.spl
│   ├── psexec_detection.kql
│   └── notes.md
│
├── exfiltration/
│   ├── README.md
│   ├── large_data_transfer.spl
│   ├── dns_exfiltration.spl
│   └── notes.md
│
├── privilege_escalation/
│   └── (similar structure)
│
└── templates/
    ├── alert_template.spl              (Template for writing new SPL queries)
    ├── baseline_detection.spl          (Template for baseline comparison)
    └── correlation_template.spl        (Template for multi-source correlation)
```

## Capabilities

✅ **Multi-format query examples**

- **SPL** (Splunk Query Language)
- **KQL** (Kusto Query Language / Azure Sentinel)
- **PromQL** (Prometheus / time-series metrics)
- **Lambda** (AWS CloudWatch Logs Insights)
- **BigQuery SQL** (Google Cloud)

✅ **Complete documentation**

- Purpose and detection logic
- Field requirements and assumptions
- Tuning guidance (thresholds, time windows)
- Expected false-positive rates
- MITRE ATT&CK mapping

✅ **Testability**

- Each query is runnable against the mock lab data
- Validation notes (what events should trigger)
- Known limitations and edge cases

✅ **Best practices**

- Baseline methodology
- Avoiding false positives
- Correlation techniques
- Incident response integration

## Example Query (Brute Force Detection)

### SPL (Splunk)

```spl
# Detect failed login spike (Brute Force Attack)
sourcetype=authentication
  action=failure
  user!=system
| stats count by user, src_ip, _time
| where count > 5
| table user, src_ip, count
```

### KQL (Azure Sentinel)

```kusto
Authentication
| where ResultType == "Failure"
| summarize FailureCount = count() by User, ClientIP, bin(TimeGenerated, 5m)
| where FailureCount > 5
```

### Notes

- **Threshold:** 5 failed attempts in 5-minute window
- **Baseline:** Adjust based on your environment (help desk, service accounts, etc.)
- **False positives:** Users with incorrect password, service account misconfigurations
- **MITRE ATT&CK:** [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/)

## Learning Path

1. **Start here:** Read each category's `README.md`
2. **Run a query:** Copy a query from `detections/authentication/brute_force_detection.spl`
3. **Test it:** Paste into your lab UI; run against mock data
4. **Trigger it:** Use attack simulation script (e.g., `./scripts/brute_force_simulation.sh`)
5. **Adjust it:** Tune thresholds, add additional conditions
6. **Document it:** Add notes on what worked and why

## Query Writing Guidelines

### Structure

A good detection query should have:

1. **Event selection** – Filter to relevant event type(s)
2. **Filtering** – Remove noise and irrelevant events
3. **Aggregation** – Group by relevant fields (user, host, IP)
4. **Threshold** – Apply statistical or counting logic
5. **Enrichment** – Add context (user role, threat intel)
6. **Output** – Return actionable fields for investigation

### Example Template

```spl
# [1] Event selection
sourcetype=authentication

# [2] Filtering
  action=failure
  user!=system
  user!=*admin*

# [3] Aggregation
| stats count as failure_count by user, src_ip

# [4] Threshold
| where failure_count > 5

# [5] Enrichment
| lookup user_roles user OUTPUT role
| lookup threat_intel src_ip OUTPUT reputation

# [6] Output
| table user, src_ip, failure_count, role, reputation
```

## Multi-Format Support

For each detection query category, we provide:

- **Primary query** (SPL or KQL) – Most common platform
- **Alternative versions** – Same detection in other languages
- **Conversion guide** – How to adapt from one language to another

This teaches platform-independent detection thinking.

## Baseline Methodology

Detection effectiveness requires establishing a baseline:

```
1. Collect "normal" data for 7–14 days
2. Calculate statistics: mean, std dev, percentiles
3. Define threshold as baseline + sensitivity factor
4. Monitor for deviations from baseline
5. Iterate and refine thresholds based on false positives
```

Example:

```spl
# 7-day baseline
earliest=-7d@d latest=@d
sourcetype=web_traffic
| stats count by dst_port
| rename count as baseline_count

# Compare to current activity
| append [search earliest=-24h sourcetype=web_traffic | stats count by dst_port | rename count as current_count]
| stats avg(baseline_count) as avg_baseline stdev(baseline_count) as stdev_baseline by dst_port
| where current_count > avg_baseline + (3 * stdev_baseline)  # 3 standard deviations
```

## Validation & Testing

Before deploying a detection in production:

1. **Functional test:** Run query, verify no errors
2. **Positive test:** Trigger the attack scenario; verify detection fires
3. **Negative test:** Verify detection does NOT fire on normal activity
4. **Tunability test:** Adjust thresholds; understand false-positive trade-offs

## Next Steps

For additional detection techniques and advanced correlation methods, see [docs/roadmap.md](../docs/roadmap.md).

## External Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/) – Threat techniques and tactics
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Search-commands)
- [Kusto Query Language (KQL) Reference](https://learn.microsoft.com/en-us/kusto/query/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma) – Community detection rules
- [Threat Hunting Fieldbook](https://www.ebook.threathunting.net/) – Threat hunting philosophy
