# Subscription and tenant come from the environment (ARM_SUBSCRIPTION_ID, ARM_TENANT_ID) or
# Azure CLI login — never from committed files.
provider "azurerm" {
  features {}

  # The audit storage account has shared_access_key_enabled = false (Entra auth only, by design
  # -- ARCHITECTURE §4's "no client secrets anywhere in the product" applies to Terraform's own
  # data-plane calls too, not just the application's). Without this, the provider's own
  # readiness poll after creating the account defaults to key-based auth and fails outright
  # against a key-disabled account ("Key based authentication is not permitted on this storage
  # account"), even though every actual resource declaration is already key-auth-free.
  storage_use_azuread = true
}
