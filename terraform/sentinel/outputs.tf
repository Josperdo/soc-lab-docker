output "workspace_id" {
  description = "Log Analytics Workspace resource ID. Used when configuring data connectors and other Sentinel resources."
  value       = azurerm_log_analytics_workspace.sentinel.id
}

output "workspace_customer_id" {
  description = "Log Analytics Workspace Customer ID (also called Workspace ID in the portal UI). Used in the Filebeat azure_monitor output configuration."
  value       = azurerm_log_analytics_workspace.sentinel.workspace_id
}

output "primary_shared_key" {
  description = "Primary shared key for the Log Analytics Workspace. Used by Filebeat and other agents to authenticate when shipping logs."
  value       = azurerm_log_analytics_workspace.sentinel.primary_shared_key
  sensitive   = true
}

output "resource_group_name" {
  description = "Name of the resource group containing all Sentinel resources."
  value       = azurerm_resource_group.sentinel.name
}

output "location" {
  description = "Azure region where resources were deployed."
  value       = azurerm_resource_group.sentinel.location
}
