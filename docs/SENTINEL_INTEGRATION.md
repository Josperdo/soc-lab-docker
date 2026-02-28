# Azure Sentinel Integration

This guide covers deploying SOC Lab Docker's detection library to Microsoft Sentinel — converting the lab's KQL queries into production-grade analytics rules, automating response with Logic App playbooks, and forwarding lab events for an end-to-end pipeline experience.

No live Azure subscription is required to study or customize the templates. A free Azure account is sufficient to deploy the full stack.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SOC Lab Docker (Local)                      │
│                                                                 │
│  ┌───────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │ Mock Log      │───►│   Filebeat   │───►│  Elasticsearch   │  │
│  │ Generator     │    │              │    │  (localhost:9200) │  │
│  └───────────────┘    └──────┬───────┘    └──────────────────┘  │
│                              │                                  │
└──────────────────────────────┼──────────────────────────────────┘
                               │ Azure Monitor Data Collector API
                               │ (HTTPS, HMAC-SHA256 signed)
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Microsoft Azure                            │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │           Log Analytics Workspace (soc_lab_CL)          │    │
│  └───────────────────────────┬─────────────────────────────┘    │
│                              │                                  │
│  ┌───────────────────────────▼─────────────────────────────┐    │
│  │              Microsoft Sentinel                         │    │
│  │                                                         │    │
│  │  ┌─────────────────┐   ┌──────────────────────────────┐ │    │
│  │  │ Analytics Rules │──►│     Incidents / Alerts       │ │    │
│  │  │ (8 lab rules)   │   └──────────────┬───────────────┘ │    │
│  │  └─────────────────┘                  │                 │    │
│  │                                       │ Automation Rule  │    │
│  │  ┌────────────────────────────────────▼───────────────┐ │    │
│  │  │         SOAR Playbooks (Logic Apps)                │ │    │
│  │  │  notify_slack │ create_ticket │ isolate_host       │ │    │
│  │  └────────────────────────────────────────────────────┘ │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

**Data flow:** Lab events → Filebeat → Azure Monitor Data Collector API → `soc_lab_CL` table → Sentinel analytics rules evaluate every 5–15 minutes → alerts fire → Logic App playbooks automate response actions.

---

## Prerequisites

### Tools

| Tool | Version | Install |
|---|---|---|
| Terraform CLI | >= 1.3.0 | https://developer.hashicorp.com/terraform/install |
| Azure CLI | Latest | https://learn.microsoft.com/en-us/cli/azure/install-azure-cli |
| Docker & Docker Compose | v20+ | (already installed for the lab) |

### Azure Account

A free Azure account includes:
- 5 GB/day Log Analytics ingestion (free for 31 days, then billable — lab generates ~1 MB/day)
- Microsoft Sentinel (first 10 GB/day free)
- Logic Apps (pay-per-execution — idle playbooks cost nothing)

Create a free account at: https://azure.microsoft.com/free/

---

## Deployment Walkthrough

### Step 1 – Clone and enter the Terraform directory

```bash
git clone https://github.com/Josperdo/soc-lab-docker.git
cd soc-lab-docker/terraform/sentinel
```

### Step 2 – Authenticate to Azure

```bash
az login
# Follow the browser prompt to complete authentication
```

Verify the correct subscription is selected:

```bash
az account show --query "{name:name, id:id}" -o table
```

To switch subscriptions:

```bash
az account set --subscription "YOUR-SUBSCRIPTION-ID"
```

### Step 3 – Create terraform.tfvars

```bash
cat > terraform.tfvars << 'EOF'
subscription_id     = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
resource_group_name = "soc-lab-sentinel-rg"
location            = "eastus"
workspace_name      = "soc-lab-sentinel-workspace"
retention_in_days   = 90
EOF
```

Replace `subscription_id` with your actual subscription ID from `az account show`.

### Step 4 – Initialize Terraform

```bash
terraform init
```

Expected output:
```
Initializing the backend...
Initializing provider plugins...
- Finding hashicorp/azurerm versions matching "~> 3.0"...
- Installing hashicorp/azurerm v3.x.x...
Terraform has been successfully initialized!
```

### Step 5 – Review the plan

```bash
terraform plan -var-file="terraform.tfvars"
```

The plan will show:
- 1 resource group
- 1 Log Analytics Workspace
- 1 Sentinel onboarding
- 8 scheduled analytics rules

### Step 6 – Apply

```bash
terraform apply -var-file="terraform.tfvars"
```

Type `yes` when prompted. Provisioning takes 2–5 minutes.

### Step 7 – Note the outputs

```bash
terraform output workspace_customer_id   # Workspace ID for data connector
terraform output -raw primary_shared_key # Primary key for data connector
```

Store these securely — you need them in the next step.

---

## Navigating Analytics Rules in the Sentinel UI

After `terraform apply` completes:

1. Open the [Azure portal](https://portal.azure.com)
2. Search for **Microsoft Sentinel** and open it
3. Select your workspace (`soc-lab-sentinel-workspace`)
4. Navigate to **Configuration** → **Analytics**

You should see all 8 rules listed as "Active":

```
┌──────────────────────────────────────────────────────────────────┐
│ Analytics rules                                         Active: 8│
├──────────────────────────────────────────────────────────────────┤
│ ✓ SOC Lab – Brute Force SSH Authentication      High   5m/1h     │
│ ✓ SOC Lab – Account Lockout Spike               Medium 15m/1h    │
│ ✓ SOC Lab – RDP Lateral Movement                High   5m/1h     │
│ ✓ SOC Lab – PsExec Remote Execution Detected    High   5m/1h     │
│ ✓ SOC Lab – WMI Remote Code Execution           High   5m/1h     │
│ ✓ SOC Lab – Local Privilege Escalation to SYSTEM High  5m/1h     │
│ ✓ SOC Lab – Scheduled Task / Cron Persistence   Medium 15m/24h   │
│ ✓ SOC Lab – Suspicious Outbound Data Transfer   High   15m/1h    │
└──────────────────────────────────────────────────────────────────┘
```

Click any rule to view its query, entity mappings, and MITRE technique tags.

---

## Enabling and Linking Playbooks to Analytics Rules

### Step 1 – Deploy a playbook

```bash
az deployment group create \
  --resource-group soc-lab-sentinel-rg \
  --template-file playbooks/notify_slack/azuredeploy.json \
  --parameters @playbooks/notify_slack/parameters.json
```

Edit `playbooks/notify_slack/parameters.json` first to substitute your Slack webhook URL.

### Step 2 – Create an automation rule

1. In Sentinel → **Automation** → **Automation rules** → **Create**
2. **Name:** `Alert - Notify Slack`
3. **Trigger:** When alert is created
4. **Conditions:** (optional) Filter by rule name or severity
5. **Actions:** Run playbook → select `soc-lab-notify-slack`
6. **Save**

The playbook now fires automatically for every new Sentinel alert.

See [playbooks/README.md](../terraform/sentinel/playbooks/README.md) for deployment instructions for all three playbooks.

---

## Data Connector Setup (Event Forwarding)

To forward live lab events to Sentinel, configure the Filebeat → Azure Monitor output.

See [terraform/sentinel/data_connector/README.md](../terraform/sentinel/data_connector/README.md) for the full setup guide including field mapping notes and Logstash vs. direct HTTP options.

Quick summary:

```bash
# Get credentials from Terraform outputs
WORKSPACE_ID=$(terraform output -raw workspace_customer_id)
PRIMARY_KEY=$(terraform output -raw primary_shared_key)

# Substitute into filebeat-azure-monitor.yml and restart Filebeat
# See data_connector/README.md for signing details
```

Verify in Sentinel → **Logs**:

```kql
soc_lab_CL
| take 10
```

---

## Cost Guidance

| Resource | Free Tier | Lab Usage | Expected Cost |
|---|---|---|---|
| Log Analytics ingestion | 5 GB/day free (30 days) | ~1 MB/day | $0 |
| Microsoft Sentinel | 10 GB/day free | <1 MB/day | $0 |
| Logic Apps | ~4,000 runs/month free | Idle/low | $0 |
| Storage (workspace) | Included | Minimal | $0 |

The lab generates approximately 1 MB of log data per day under normal operation. This is well within the free tier limits for both Log Analytics and Sentinel.

After the 31-day free trial, Log Analytics ingestion is billed at approximately $2.76/GB. At 1 MB/day, monthly cost remains under $0.10.

---

## Cleanup

To remove all Sentinel resources:

```bash
terraform destroy -var-file="terraform.tfvars"
```

Type `yes` when prompted. This deletes the resource group, workspace, Sentinel instance, and all analytics rules.

To also remove playbook Logic Apps (deployed separately via `az deployment group create`):

```bash
az logicapp delete \
  --resource-group soc-lab-sentinel-rg \
  --name soc-lab-notify-slack

az logicapp delete \
  --resource-group soc-lab-sentinel-rg \
  --name soc-lab-create-ticket

az logicapp delete \
  --resource-group soc-lab-sentinel-rg \
  --name soc-lab-isolate-host
```

---

## Further Reading

- [Microsoft Sentinel documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
- [AzureRM Sentinel provider](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sentinel_alert_rule_scheduled)
- [Azure Monitor Data Collector API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api)
- [Logic Apps documentation](https://learn.microsoft.com/en-us/azure/logic-apps/)
- [MITRE ATT&CK](https://attack.mitre.org/)
