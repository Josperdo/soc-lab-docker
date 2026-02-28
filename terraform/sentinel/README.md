# terraform/sentinel

Terraform module that provisions an Azure Sentinel workspace and deploys all SOC Lab detection rules as scheduled analytics rules.

---

## Directory Structure

```
terraform/sentinel/
├── providers.tf          # AzureRM provider (~> 3.0)
├── variables.tf          # Input variables
├── main.tf               # Resource group, Log Analytics workspace, Sentinel onboarding
├── outputs.tf            # Workspace ID, customer ID, primary shared key
├── analytics_rules.tf    # All 8 detection rules as Sentinel scheduled alert rules
├── playbooks/            # SOAR Logic App ARM templates
│   ├── README.md
│   ├── notify_slack/
│   ├── create_ticket/
│   └── isolate_host/
└── data_connector/       # Filebeat → Azure Monitor output config
    └── README.md
```

---

## Prerequisites

- [Terraform CLI](https://developer.hashicorp.com/terraform/install) >= 1.3.0
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) for interactive auth
- An Azure subscription (a free account works — see cost note below)

---

## Quick Start

### 1. Authenticate

```bash
az login
```

Or set service principal environment variables:

```bash
export ARM_SUBSCRIPTION_ID="<your-subscription-id>"
export ARM_TENANT_ID="<your-tenant-id>"
export ARM_CLIENT_ID="<your-client-id>"
export ARM_CLIENT_SECRET="<your-client-secret>"
```

### 2. Create a `terraform.tfvars` file

```hcl
subscription_id     = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
resource_group_name = "soc-lab-sentinel-rg"
location            = "eastus"
workspace_name      = "soc-lab-sentinel-workspace"
retention_in_days   = 90
```

### 3. Initialize and apply

```bash
cd terraform/sentinel
terraform init
terraform plan -var-file="terraform.tfvars"
terraform apply -var-file="terraform.tfvars"
```

### 4. Note the outputs

```bash
terraform output workspace_customer_id   # Workspace ID for Filebeat config
terraform output -raw primary_shared_key # Primary key for Filebeat config
```

---

## Resources Created

| Resource | Type | Purpose |
|---|---|---|
| `soc-lab-sentinel-rg` | Resource Group | Container for all resources |
| `soc-lab-sentinel-workspace` | Log Analytics Workspace | Data store for Sentinel |
| Sentinel onboarding | Sentinel | Enables Microsoft Sentinel on the workspace |
| 8 × Alert Rules | Scheduled Analytics Rules | Lab detections as production-grade rules |

---

## Analytics Rules

All 8 lab detections are deployed as `azurerm_sentinel_alert_rule_scheduled` resources:

| Rule | MITRE | Severity | Frequency | Lookback |
|---|---|---|---|---|
| Brute Force SSH | T1110.001 | High | 5m | 1h |
| Account Lockout Spike | T1110.001/003 | Medium | 15m | 1h |
| RDP Lateral Movement | T1021.001 | High | 5m | 1h |
| PsExec Detection | T1021.002 | High | 5m | 1h |
| WMI Execution | T1047 | High | 5m | 1h |
| Local Privilege Escalation | T1068/T1134 | High | 5m | 1h |
| Scheduled Task Creation | T1053.005 | Medium | 15m | 24h |
| Large Data Transfer | T1041/T1048 | High | 15m | 1h |

---

## Cost Expectations (Azure Free Tier)

- **Log Analytics Workspace:** First 5 GB/day ingested free. The lab generates ~1 MB/day under normal load — well within the free tier.
- **Microsoft Sentinel:** First 10 GB/day free (in conjunction with Log Analytics).
- **Logic Apps (Playbooks):** Pay-per-execution. Idle playbooks cost nothing.

For a lab workload, the expected monthly cost is **$0** on the Azure free tier.

---

## Cleanup

To remove all resources:

```bash
terraform destroy -var-file="terraform.tfvars"
```

This deletes the resource group, workspace, Sentinel instance, and all analytics rules.
