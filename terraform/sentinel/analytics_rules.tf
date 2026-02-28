# ============================================================================
# SOC Lab Docker – Azure Sentinel Analytics Rules
# ============================================================================
# All 8 lab detection queries converted to azurerm_sentinel_alert_rule_scheduled
# resources. Each rule includes MITRE tactics/techniques, entity mappings,
# and tunable frequency/lookback settings.
#
# Table name: soc_lab_CL
# This is the custom log table created when lab events are forwarded via the
# Filebeat → Azure Monitor data connector (see data_connector/).
#
# Field naming convention (Log Analytics custom log suffix):
#   _s  = string
#   _d  = double/number
#   _b  = boolean
#   _t  = datetime
# ============================================================================

locals {
  workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.sentinel.workspace_id
}

# ----------------------------------------------------------------------------
# 1. Brute Force SSH
# MITRE: T1110.001 – Brute Force: Password Guessing
# Severity: High | Frequency: 5m | Lookback: 1h
# ----------------------------------------------------------------------------
resource "azurerm_sentinel_alert_rule_scheduled" "brute_force_ssh" {
  name                       = "soc-lab-brute-force-ssh"
  log_analytics_workspace_id = local.workspace_id
  display_name               = "SOC Lab – Brute Force SSH Authentication"
  severity                   = "High"
  enabled                    = true

  query = <<-KQL
    let threshold = 10;
    soc_lab_CL
    | where TimeGenerated > ago(1h)
    | where event_category_s == "authentication"
    | where event_outcome_s == "failure"
    | where authentication_service_s == "sshd"
    | summarize
        FailureCount  = count(),
        UniqueUsers   = dcount(user_name_s),
        TargetedUsers = make_set(user_name_s, 20),
        TargetedHosts = make_set(host_name_s, 10)
      by SourceIP = source_ip_s, bin(TimeGenerated, 5m)
    | where FailureCount >= threshold
    | extend AttackType = iff(UniqueUsers > 3, "SSH Password Spray", "SSH Brute Force")
    | project TimeGenerated, SourceIP, AttackType, FailureCount, UniqueUsers, TargetedUsers, TargetedHosts
    | order by FailureCount desc
  KQL

  query_frequency = "PT5M"
  query_period    = "PT1H"

  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["CredentialAccess"]
  techniques = ["T1110", "T1110.001"]

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "SourceIP"
    }
  }
}

# ----------------------------------------------------------------------------
# 2. Account Lockout Spike (Password Spray)
# MITRE: T1110.001/T1110.003 – Brute Force / Password Spraying
# Severity: Medium | Frequency: 15m | Lookback: 1h
# ----------------------------------------------------------------------------
resource "azurerm_sentinel_alert_rule_scheduled" "account_lockout_spike" {
  name                       = "soc-lab-account-lockout-spike"
  log_analytics_workspace_id = local.workspace_id
  display_name               = "SOC Lab – Account Lockout Spike (Password Spray)"
  severity                   = "Medium"
  enabled                    = true

  query = <<-KQL
    soc_lab_CL
    | where TimeGenerated > ago(1h)
    | where event_category_s == "authentication"
    | where event_outcome_s == "failure"
    | summarize
        failure_count = count(),
        unique_users  = dcount(user_name_s),
        target_users  = make_set(user_name_s, 20),
        target_hosts  = make_set(host_name_s, 10)
      by SourceIP = source_ip_s, bin(TimeGenerated, 5m)
    | where failure_count > 5
    | extend attack_type = iff(unique_users > 3, "password_spray", "brute_force")
    | project TimeGenerated, SourceIP, attack_type, failure_count, unique_users, target_users, target_hosts
    | sort by failure_count desc
  KQL

  query_frequency = "PT15M"
  query_period    = "PT1H"

  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["CredentialAccess"]
  techniques = ["T1110", "T1110.001", "T1110.003"]

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "SourceIP"
    }
  }
}

# ----------------------------------------------------------------------------
# 3. RDP Lateral Movement
# MITRE: T1021.001 – Remote Services: Remote Desktop Protocol
# Severity: High | Frequency: 5m | Lookback: 1h
# ----------------------------------------------------------------------------
resource "azurerm_sentinel_alert_rule_scheduled" "rdp_lateral_movement" {
  name                       = "soc-lab-rdp-lateral-movement"
  log_analytics_workspace_id = local.workspace_id
  display_name               = "SOC Lab – RDP Lateral Movement"
  severity                   = "High"
  enabled                    = true

  query = <<-KQL
    soc_lab_CL
    | where TimeGenerated > ago(1h)
    | where event_category_s == "network"
    | where destination_port_d == 3389
    | where network_transport_s == "tcp"
    | where event_outcome_s == "success"
    | summarize
        connection_count = count(),
        unique_sources   = dcount(source_ip_s),
        source_ips       = make_set(source_ip_s, 10)
      by TargetHost = host_name_s, bin(TimeGenerated, 5m)
    | where connection_count >= 3
    | project TimeGenerated, TargetHost, connection_count, unique_sources, source_ips
    | sort by connection_count desc
  KQL

  query_frequency = "PT5M"
  query_period    = "PT1H"

  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["LateralMovement"]
  techniques = ["T1021", "T1021.001"]

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "TargetHost"
    }
  }
}

# ----------------------------------------------------------------------------
# 4. PsExec Remote Execution
# MITRE: T1021.002 – Remote Services: SMB/Windows Admin Shares
# Severity: High | Frequency: 5m | Lookback: 1h
# ----------------------------------------------------------------------------
resource "azurerm_sentinel_alert_rule_scheduled" "psexec_detection" {
  name                       = "soc-lab-psexec-detection"
  log_analytics_workspace_id = local.workspace_id
  display_name               = "SOC Lab – PsExec Remote Execution Detected"
  severity                   = "High"
  enabled                    = true

  query = <<-KQL
    soc_lab_CL
    | where TimeGenerated > ago(1h)
    | where event_category_s == "process"
    | where process_name_s == "PSEXESVC.exe"
        or (process_name_s == "cmd.exe" and process_parent_name_s == "PSEXESVC.exe")
    | summarize
        event_count   = count(),
        unique_users  = dcount(user_name_s),
        seen_commands = make_set(process_command_line_s, 10)
      by TargetHost = host_name_s, UserName = user_name_s, process_name_s
    | project TimeGenerated = now(), TargetHost, UserName, process_name_s, event_count, unique_users, seen_commands
    | sort by event_count desc
  KQL

  query_frequency = "PT5M"
  query_period    = "PT1H"

  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["LateralMovement", "Execution"]
  techniques = ["T1021", "T1021.002", "T1570"]

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "TargetHost"
    }
  }

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "UserName"
    }
  }
}

# ----------------------------------------------------------------------------
# 5. WMI Remote Execution
# MITRE: T1047 – Windows Management Instrumentation
# Severity: High | Frequency: 5m | Lookback: 1h
# ----------------------------------------------------------------------------
resource "azurerm_sentinel_alert_rule_scheduled" "wmi_execution" {
  name                       = "soc-lab-wmi-execution"
  log_analytics_workspace_id = local.workspace_id
  display_name               = "SOC Lab – WMI Remote Code Execution"
  severity                   = "High"
  enabled                    = true

  query = <<-KQL
    soc_lab_CL
    | where TimeGenerated > ago(1h)
    | where event_category_s == "process"
    | where process_parent_name_s == "WmiPrvSE.exe"
    | where process_name_s in ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe")
    | summarize
        spawn_count  = count(),
        unique_users = dcount(user_name_s),
        commands     = make_set(process_command_line_s, 10)
      by TargetHost = host_name_s, SpawnedProcess = process_name_s
    | project TimeGenerated = now(), TargetHost, SpawnedProcess, spawn_count, unique_users, commands
    | sort by spawn_count desc
  KQL

  query_frequency = "PT5M"
  query_period    = "PT1H"

  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["LateralMovement", "Execution"]
  techniques = ["T1047", "T1059.001", "T1059.003"]

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "TargetHost"
    }
  }
}

# ----------------------------------------------------------------------------
# 6. Local Privilege Escalation
# MITRE: T1068/T1134 – Exploitation for Privilege Escalation / Token Manipulation
# Severity: Critical | Frequency: 5m | Lookback: 1h
# ----------------------------------------------------------------------------
resource "azurerm_sentinel_alert_rule_scheduled" "local_privilege_escalation" {
  name                       = "soc-lab-local-privilege-escalation"
  log_analytics_workspace_id = local.workspace_id
  display_name               = "SOC Lab – Local Privilege Escalation to SYSTEM"
  severity                   = "High"
  enabled                    = true

  query = <<-KQL
    soc_lab_CL
    | where TimeGenerated > ago(1h)
    | where event_category_s == "process"
    | where process_integrity_level_s == "System"
    | where process_parent_name_s !in ("services.exe", "winlogon.exe", "lsass.exe", "")
    | summarize
        occurrence_count = count(),
        unique_hosts     = dcount(host_name_s),
        seen_commands    = make_set(process_command_line_s, 10)
      by ParentProcess = process_parent_name_s, ChildProcess = process_name_s, UserName = user_name_s
    | project TimeGenerated = now(), ParentProcess, ChildProcess, UserName, occurrence_count, unique_hosts, seen_commands
    | sort by occurrence_count desc
  KQL

  query_frequency = "PT5M"
  query_period    = "PT1H"

  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["PrivilegeEscalation"]
  techniques = ["T1068", "T1134"]

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "UserName"
    }
  }
}

# ----------------------------------------------------------------------------
# 7. Scheduled Task Creation (Persistence)
# MITRE: T1053.005 – Scheduled Task/Job: Scheduled Task
# Severity: Medium | Frequency: 15m | Lookback: 24h
# ----------------------------------------------------------------------------
resource "azurerm_sentinel_alert_rule_scheduled" "scheduled_task_creation" {
  name                       = "soc-lab-scheduled-task-creation"
  log_analytics_workspace_id = local.workspace_id
  display_name               = "SOC Lab – Scheduled Task / Cron Persistence"
  severity                   = "Medium"
  enabled                    = true

  query = <<-KQL
    soc_lab_CL
    | where TimeGenerated > ago(24h)
    | where event_category_s == "process"
    | where process_name_s in ("schtasks.exe", "at.exe", "crontab")
    | where process_command_line_s has_any ("/create", "-e", "-r", "/sc", "/tr")
    | summarize
        creation_count = count(),
        unique_hosts   = dcount(host_name_s),
        commands       = make_set(process_command_line_s, 10)
      by UserName = user_name_s, TaskTool = process_name_s, TargetHost = host_name_s
    | project TimeGenerated = now(), UserName, TaskTool, TargetHost, creation_count, unique_hosts, commands
    | sort by creation_count desc
  KQL

  query_frequency = "PT15M"
  query_period    = "P1D"

  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["Persistence", "Execution"]
  techniques = ["T1053", "T1053.005"]

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "UserName"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "TargetHost"
    }
  }
}

# ----------------------------------------------------------------------------
# 8. Large Data Transfer / Exfiltration
# MITRE: T1041/T1048 – Exfiltration Over C2 / Alternative Protocol
# Severity: High | Frequency: 15m | Lookback: 1h
# ----------------------------------------------------------------------------
resource "azurerm_sentinel_alert_rule_scheduled" "large_data_transfer" {
  name                       = "soc-lab-large-data-transfer"
  log_analytics_workspace_id = local.workspace_id
  display_name               = "SOC Lab – Suspicious Outbound Data Transfer"
  severity                   = "High"
  enabled                    = true

  query = <<-KQL
    soc_lab_CL
    | where TimeGenerated > ago(1h)
    | where event_category_s == "network"
    | where event_outcome_s == "success"
    | where network_transport_s == "tcp"
    | where destination_port_d !in (80, 443, 53, 22, 25, 143, 465, 587, 993)
    | summarize
        connection_count = count(),
        unique_hosts     = dcount(host_name_s),
        source_hosts     = make_set(host_name_s, 10)
      by DestPort = destination_port_d, DestIP = destination_ip_s
    | where connection_count >= 3
    | project TimeGenerated = now(), DestPort, DestIP, connection_count, unique_hosts, source_hosts
    | sort by connection_count desc
  KQL

  query_frequency = "PT15M"
  query_period    = "PT1H"

  trigger_operator  = "GreaterThan"
  trigger_threshold = 0

  tactics    = ["Exfiltration", "CommandAndControl"]
  techniques = ["T1041", "T1048"]

  entity_mapping {
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "DestIP"
    }
  }
}
