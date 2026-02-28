# SOAR Playbooks

ARM template Logic Apps for automating response actions when Sentinel analytics rules fire.

Each playbook is parameterized and deployable independently via the Azure CLI.

---

## Playbooks

| Playbook | Trigger | Action |
|---|---|---|
| `notify_slack` | Sentinel alert | Format alert → POST to Slack webhook |
| `create_ticket` | Sentinel alert | Extract alert details → POST to ticketing API (ServiceNow/JIRA) |
| `isolate_host` | Sentinel alert | Extract Host entity → POST isolation request to EDR API |

---

## Deploying a Playbook

### Prerequisites

- Azure CLI installed and authenticated (`az login`)
- An existing Resource Group (created by the Terraform module, or manually)

### Deploy Command

```bash
az deployment group create \
  --resource-group soc-lab-sentinel-rg \
  --template-file notify_slack/azuredeploy.json \
  --parameters @notify_slack/parameters.json
```

Replace `notify_slack` with `create_ticket` or `isolate_host` as needed.

---

## Parameter Substitution

Before deploying, edit the `parameters.json` file for each playbook and replace all `REPLACE_WITH_*` placeholder values with real credentials:

### notify_slack

```json
"slackWebhookUrl": {
  "value": "https://hooks.slack.com/services/YOUR/REAL/WEBHOOK"
}
```

Get a webhook URL at: https://api.slack.com/messaging/webhooks

### create_ticket

```json
"ticketingApiUrl": {
  "value": "https://YOURINSTANCE.service-now.com/api/now/table/incident"
},
"ticketingApiUsername": { "value": "your_api_user" },
"ticketingApiPassword": { "value": "your_api_token" }
```

For JIRA, the URL pattern is: `https://YOURORG.atlassian.net/rest/api/2/issue/`

### isolate_host

```json
"edrApiBaseUrl": {
  "value": "https://api.securitycenter.microsoft.com/api/machines"
},
"edrApiToken": { "value": "your_bearer_token" }
```

For Defender for Endpoint, obtain a token via the [MDE OAuth2 client credentials flow](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exposed-apis-create-app-webapp).

---

## Linking a Playbook to a Sentinel Analytics Rule

After deployment:

1. Open **Microsoft Sentinel** in the Azure portal
2. Navigate to **Automation** → **Automation rules**
3. Click **Create** → **Automation rule**
4. Set **Trigger** to "When alert is created"
5. Under **Actions**, choose **Run playbook**
6. Select the deployed Logic App from the list
7. Save the automation rule

The playbook now runs automatically whenever the linked analytics rule fires an alert.

---

## Notes

- These playbooks are reference implementations demonstrating the SOAR automation pattern.
- In production, store secrets in Azure Key Vault and reference them via Key Vault references rather than inline parameter values.
- Logic App execution logs are visible in the Azure portal under the Logic App resource → **Runs history**.
