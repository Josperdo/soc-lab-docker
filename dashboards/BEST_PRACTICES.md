# Dashboard Best Practices

**Purpose:** Guidelines for building effective, performant security dashboards in Kibana

---

## Table of Contents

1. [Time Range & Refresh](#time-range--refresh)
2. [Visual Hierarchy](#visual-hierarchy)
3. [Aggregation Sizing](#aggregation-sizing)
4. [Threshold Visualisations](#threshold-visualisations)
5. [Colour Conventions](#colour-conventions)
6. [Performance Tips](#performance-tips)
7. [Exporting & Sharing](#exporting--sharing)

---

## Time Range & Refresh

### Default Time Range

Set a sensible default that matches the dashboard's purpose:

| Dashboard Type | Recommended Default | Rationale |
|---|---|---|
| Operational (live monitoring) | Last 1 hour | Tight focus on current activity |
| Baseline comparison | Last 24 hours | Enough history for pattern recognition |
| Investigation / IR | Last 2 hours | Scoped to incident window |
| Weekly reporting | Last 7 days | Full week view |

> **Warning:** Avoid setting "All time" as a default on dashboards backed by large indices. It causes expensive full-index scans and will degrade Elasticsearch performance.

### Refresh Intervals

- **Live monitoring:** 30 seconds (`"value": 30000`)
- **Incident response:** Pause auto-refresh (`"pause": true`) — you want a stable view while investigating
- **Reporting:** No auto-refresh needed

### Adjusting Time Range During Investigation

Use Kibana's time picker to narrow to the incident window:
1. Click the time range in the top-right corner
2. Enter absolute start/end times (e.g., `2026-02-27 03:00` to `2026-02-27 05:00`)
3. Use "Refresh" to capture new data without losing your time window

---

## Visual Hierarchy

Structure each dashboard to guide the analyst from overview to detail:

```
Level 1 – Summary metrics (top row)
  ├── Total event count
  ├── Failure count
  └── Unique IPs / hosts

Level 2 – Trend / timeline (full width)
  └── Events over time by category (stacked bar, auto interval)

Level 3 – Distribution / breakdown (middle row)
  ├── Event category pie or donut chart
  └── Auth failures vs successes bar chart

Level 4 – Detail tables (bottom rows)
  ├── Top source IPs table
  ├── Top usernames table
  └── Process activity table
```

**Principle:** A viewer should understand the overall situation from the top row alone, then drill down for specifics.

---

## Aggregation Sizing

Keep `terms` bucket sizes reasonable to maintain readability and performance:

| Visualisation Type | Recommended `size` |
|---|---|
| Pie / donut chart | 5–8 (more slices = unreadable) |
| Bar chart grouping | 5–10 |
| Table (investigation) | 15–20 |
| Table (overview) | 10 |

**High-cardinality fields** like `source.ip`, `user.name`, and `process.command_line` are expensive to aggregate with large sizes. Keep to ≤ 20 for `terms` on these fields.

**Avoid** using `*` (wildcard) or very high sizes (100+) in interactive dashboards — reserve large aggregations for ES|QL queries in Discover or Dev Tools.

---

## Threshold Visualisations

Use metric visualisations with colour zones to create visual alert signals:

### Example: Auth Failure Rate (metric with colour zones)

```json
"colorsRange": [
  {"from": 0,   "to": 50},
  {"from": 50,  "to": 200},
  {"from": 200, "to": 99999}
]
```

- **Green (0–50):** Normal range
- **Yellow/Orange (50–200):** Elevated — warrants attention
- **Red (200+):** Threshold exceeded — investigate immediately

Adjust these ranges based on your environment's baseline. Run each metric query over a 7-day quiet period to determine normal ranges before setting thresholds.

---

## Colour Conventions

Apply consistent colour semantics across all dashboards so analysts build visual intuition:

| Colour | Semantic Meaning | Use For |
|---|---|---|
| Green | Normal / expected | Success events, within-threshold metrics |
| Blue | Informational | Neutral counts, process events |
| Orange | Warning / elevated | Authentication failures, unusual activity |
| Red | Critical / anomalous | Above threshold, attack simulation events |
| Grey | Unknown / missing | Null values, uncategorised events |

In Kibana's aggregation-based visualisations, control colours via the legend by clicking a series label and selecting a colour.

---

## Performance Tips

### 1. Filter Early

Apply filters at the `searchSourceJSON` level (in the visualisation's search source) rather than via `WHERE` in displayed data. This reduces the data scanned at the Elasticsearch level.

Good: Use `event.category: "authentication"` in the saved search source of auth-focused panels.
Avoid: Using a global unfiltered search source and expecting aggregations to handle filtering.

### 2. Avoid High-Cardinality Date Splits

**Do not** split date_histogram by high-cardinality fields like `source.ip` or `user.name`. It creates one time series per unique value and will overwhelm the visualisation and Elasticsearch.

Safe splits: `event.category` (5 values), `event.outcome` (2 values), `network.transport` (< 10 values).

### 3. Use Auto Interval for Trend Charts

For trend / histogram charts, use `"interval": "auto"` rather than hardcoding `5m` or `1h`. Kibana will select an appropriate interval based on the visible time range, keeping data points manageable at any zoom level.

### 4. Increase Heap for Heavy Queries

If visualisations show circuit-breaker errors, increase Elasticsearch heap in `.env`:

```bash
ELASTICSEARCH_HEAP_SIZE=2g   # bump from 1g for heavy aggregation workloads
```

Then restart: `docker compose restart elasticsearch`

### 5. Use Kibana's Inspect Tool

Every Kibana visualisation has an **Inspect** button (three-dot menu → Inspect) that shows the raw Elasticsearch query and response time. Use this to identify slow queries before they become a production problem.

---

## Exporting & Sharing

### Exporting Dashboards for Version Control

Always export with related objects included:

1. **Kibana → Stack Management → Saved Objects**
2. Check the dashboard checkbox
3. Click **Export** → enable **Include related objects**
4. Save the `.ndjson` file to `dashboards/templates/`

This ensures the index-pattern, visualisations, and dashboard object are all in one file and can be imported into a fresh Kibana instance without dependencies.

### Importing on a New Instance

1. **Kibana → Stack Management → Saved Objects → Import**
2. Select the `.ndjson` file
3. If prompted about conflicts, choose **Overwrite** to use the latest version
4. Navigate to **Analytics → Dashboards** and confirm the dashboard appears

### Sharing with the Team

For read-only sharing, use Kibana's **Share** button (top-right of any dashboard) to generate a permanent link or PDF export.

---

## Anti-Patterns to Avoid

| Anti-Pattern | Problem | Alternative |
|---|---|---|
| "All time" default range | Full-index scan, slow load | Use `now-24h` to `now` |
| Terms size > 50 on IP fields | Memory pressure, slow render | Keep ≤ 20 |
| Splitting date_histogram by `source.ip` | Thousands of series, browser crash | Use a table instead |
| No dashboard description | New users can't understand intent | Always write a description |
| Hardcoded index name | Breaks on re-deploy | Reference via index-pattern object |

---

*See [SETUP.md](../docs/SETUP.md) for Elasticsearch performance tuning, and [detections/README.md](../detections/README.md) for query writing guidelines.*
