# Subscription and tenant come from the environment (ARM_SUBSCRIPTION_ID, ARM_TENANT_ID) or
# Azure CLI login — never from committed files.
provider "azurerm" {
  features {}
}
