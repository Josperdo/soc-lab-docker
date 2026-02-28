variable "subscription_id" {
  description = "Azure Subscription ID where resources will be deployed."
  type        = string
}

variable "resource_group_name" {
  description = "Name of the Azure Resource Group to create."
  type        = string
  default     = "soc-lab-sentinel-rg"
}

variable "location" {
  description = "Azure region for all resources."
  type        = string
  default     = "eastus"
}

variable "workspace_name" {
  description = "Name of the Log Analytics Workspace (used as the Sentinel workspace)."
  type        = string
  default     = "soc-lab-sentinel-workspace"
}

variable "retention_in_days" {
  description = "Data retention period in days for the Log Analytics Workspace. Minimum 30, maximum 730."
  type        = number
  default     = 90

  validation {
    condition     = var.retention_in_days >= 30 && var.retention_in_days <= 730
    error_message = "Retention must be between 30 and 730 days."
  }
}

variable "tags" {
  description = "Tags to apply to all resources."
  type        = map(string)
  default = {
    project     = "soc-lab-docker"
    environment = "lab"
    managed_by  = "terraform"
  }
}
