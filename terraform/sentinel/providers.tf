terraform {
  required_version = ">= 1.3.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}

  # Credentials are read from environment variables:
  #   ARM_SUBSCRIPTION_ID
  #   ARM_TENANT_ID
  #   ARM_CLIENT_ID
  #   ARM_CLIENT_SECRET
  #
  # Or use `az login` for interactive authentication.
  # See: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/guides/service_principal_client_secret
}
