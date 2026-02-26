# Dashboards & Visualizations

**Purpose:** Sample dashboards and visualization templates for the SOC Lab

## Overview

This directory contains pre-built dashboard definitions, visualization examples, and templates for learning data visualization and alert design in a security operations context.

## Directory Structure

```
dashboards/
├── README.md (this file)
│
├── templates/
│   ├── event_overview.json           # Dashboard template (Kibana, Grafana, etc.)
│   ├── authentication_analytics.json
│   └── alerts_and_detections.json
│
├── queries/
│   ├── event_counts.spl              # Query backing each visualization
│   ├── failure_trends.spl
│   └── top_sources.spl
│
└── samples/
    ├── exported_dashboard_example.json   # Example of exported dashboard
    └── dashboard_import_guide.md         # How to import dashboards
```

## Sample Dashboards

### 1. Event Overview Dashboard

**Purpose:** High-level view of all lab events

**Panels:**

- Total Events (number card)
- Events over time (line chart, last 24 hours)
- Event type distribution (pie chart)
- Top source IPs (table)
- Top users (table)
- Top destinations (table)

**Use case:** Daily standup, lab health check

### 2. Authentication Analytics

**Purpose:** Focused view of authentication events

**Panels:**

- Successful logins (line chart)
- Failed login attempts (line chart with threshold line)
- Failed logins by user (bar chart)
- Failed logins by source IP (map visualization)
- Unusual login times (table)
- Privilege elevation events (timeline)

**Use case:** Detecting brute force, unusual access patterns, privilege escalation

### 3. Alerts & Detections

**Purpose:** Detections fired and alert status

**Panels:**

- Alerts fired (real-time gauge)
- Detection rule hit rate (stacked bar chart)
- Alert severity distribution (pie chart)
- Alert drill-down (searchable table with drill-down to log details)
- Top firing rules (top 10 rules)
- Alert response status (pending, in-progress, resolved)

**Use case:** Alert triage, detection tuning, incident tracking

## Dashboard Features

✅ **Interactive Dashboards**

- Click through to underlying data
- Filter by time range, user, host, etc.
- Drill-down from summary to detail

✅ **Real-time Updates**

- Auto-refresh configured (5-second, 30-second options)
- Suitable for SOC wall displays

✅ **Exportable**

- Export as JSON (for version control and sharing)
- Export visualizations as images
- Share dashboard links with team

✅ **Template Customization**

- Available as JSON files for easy modification
- Re-usable panels for other dashboards
- Documentation on customization

## Using Dashboard Templates

### Step 1: Export Template

```bash
# Dashboard is provided as JSON file
cat dashboards/templates/event_overview.json
```

### Step 2: Import into Dashboard UI

For **Kibana** (Elasticsearch):

1. Open Kibana: `http://localhost:5601`
2. Go to **Management** → **Saved Objects** → **Dashboards**
3. Click **Import**
4. Select the JSON file
5. Click **Import**

For **Grafana** (Prometheus/time-series):

1. Open Grafana: `http://localhost:3000`
2. Go to **Dashboards** → **Import**
3. Paste JSON or upload file
4. Select datasource
5. Click **Import**

### Step 3: Customize

Once imported:

- Adjust time ranges, thresholds, colors
- Add/remove panels
- Modify queries underlying visualizations
- Save your customized version

## Best Practices

### Visual Design

- **5-second rule:** Key insights should be obvious within 5 seconds
- **Signal over noise:** Remove redundant or static panels
- **Color coding:** Red for alerts, green for normal, yellow for warning

### Data Density

- **Avoid clutter:** Not all data belongs on all dashboards
- **Progressive disclosure:** Link to detail views for drill-down
- **Consistent visualizations:** Use same chart types for same metrics

### Query Performance

- **Avoid heavy aggregations:** Pre-compute summaries if possible
- **Time-bound queries:** Always specify time range
- **Index optimization:** Ensure proper field indexes for fast queries

## Exporting & Version Control

### Export a Dashboard

```bash
# Kibana: Use UI (Dashboard → Share → Export)
# Or via API:
curl -X GET "localhost:9200/_kibana/dashboards/my-dashboard" > dashboards/exported/my-dashboard.json
```

### Version Control

```bash
# Dashboards are committed as JSON
git add dashboards/templates/event_overview.json
git commit -m "Update event overview dashboard with new alert panel"
```

### Sharing

```bash
# Share dashboard link
# Kibana: http://localhost:5601/app/kibana#/dashboard/event-overview
# Grafana: http://localhost:3000/d/abc123/event-overview

# Or export team-friendly HTML/PDF
```

## Learning Path

1. **View templates:** Review dashboard JSON files
2. **Import a dashboard:** Follow import steps in your platform
3. **Explore data:** Run queries, interact with visualizations
4. **Customize:** Modify a panel (change color, add filter, etc.)
5. **Create:** Build your first custom dashboard from scratch

## Troubleshooting

### Dashboard is blank

- **Cause:** No data in time range or index
- **Solution:** Check log generator is running; verify data in index

### Query times out

- **Cause:** Too much data or expensive aggregation
- **Solution:** Narrow time range; add filters; optimize query

### Visualizations don't match query results

- **Cause:** Transformation or formatting issue
- **Solution:** Re-check query syntax; verify field types

## Learning Resources

For more advanced dashboarding techniques and planned enhancements, see [docs/roadmap.md](../docs/roadmap.md).
