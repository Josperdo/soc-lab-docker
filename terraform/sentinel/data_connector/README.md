# Data Connector – Filebeat → Azure Monitor

This directory contains configuration for forwarding SOC Lab events from the local Docker stack to an Azure Log Analytics Workspace, making them available in Microsoft Sentinel.

---

## Why This Step Is Needed

The local lab stack writes events to Elasticsearch (port 9200). Azure Sentinel reads from Log Analytics. To run the Terraform analytics rules against real lab data, you need to bridge the two: ship events from the lab's Filebeat instance to the Log Analytics Workspace using the Azure Monitor Data Collector API.

Without this step, the analytics rules exist in Sentinel but have no data to query against (the `soc_lab_CL` table will be empty).

---

## Getting Your Workspace Credentials

After running `terraform apply` in `terraform/sentinel/`:

```bash
# Workspace ID (called "Customer ID" internally)
terraform output workspace_customer_id

# Primary shared key (sensitive — handle as a secret)
terraform output -raw primary_shared_key
```

---

## Forwarding Options

### Option A – Logstash (Recommended)

The `logstash-output-azure-loganalytics` plugin handles the HMAC-SHA256 request signing required by the Data Collector API automatically.

1. Add the plugin to your Logstash installation:

   ```bash
   logstash-plugin install logstash-output-azure-loganalytics
   ```

2. Configure a Logstash output pipeline:

   ```ruby
   output {
     azure_loganalytics {
       workspace_id          => "YOUR_WORKSPACE_ID"
       workspace_key         => "YOUR_PRIMARY_SHARED_KEY"
       custom_log_table_name => "soc_lab"
     }
   }
   ```

3. Point the existing Filebeat configuration at the new Logstash pipeline instead of (or in addition to) Elasticsearch.

### Option B – Direct HTTP (filebeat-azure-monitor.yml)

The `filebeat-azure-monitor.yml` file in this directory shows the Filebeat HTTP output configuration. This option requires you to compute the `Authorization` header using HMAC-SHA256 on each request (the Azure Monitor Data Collector API requires signed requests).

For a working signing implementation, see the [Azure Monitor Data Collector API reference](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api).

### Option C – Azure Monitor Agent (AMA)

For production scenarios, consider the [Azure Monitor Agent](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-overview) with a Data Collection Rule (DCR). This is the current Microsoft-recommended approach but requires the log source host to be Azure-enrolled or Arc-connected.

---

## ECS → Log Analytics Field Mapping

Azure Monitor appends type suffixes to all custom log fields. The analytics rules in `analytics_rules.tf` use these column names:

| ECS Field | Log Analytics Column |
|---|---|
| `event.category` | `event_category_s` |
| `event.action` | `event_action_s` |
| `event.outcome` | `event_outcome_s` |
| `source.ip` | `source_ip_s` |
| `destination.ip` | `destination_ip_s` |
| `destination.port` | `destination_port_d` |
| `network.transport` | `network_transport_s` |
| `user.name` | `user_name_s` |
| `host.name` | `host_name_s` |
| `authentication.service` | `authentication_service_s` |
| `process.name` | `process_name_s` |
| `process.parent.name` | `process_parent_name_s` |
| `process.command_line` | `process_command_line_s` |
| `process.integrity_level` | `process_integrity_level_s` |
| `@timestamp` | `TimeGenerated` (auto-mapped) |

---

## Verifying Data in Sentinel

After configuring the connector and sending some lab events:

1. Open the Azure portal → **Microsoft Sentinel** → your workspace
2. Go to **Logs**
3. Run:

   ```kql
   soc_lab_CL
   | take 10
   ```

   If rows appear, the data pipeline is working. The analytics rules will start firing on the next evaluation cycle.
