terraform {
  required_version = ">= 1.9.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    # M4-29 item 3: the Mina.Node / Mina.Node.<region> app-role definitions and assignments.
    # First use of this provider anywhere in the repo -- see entra-node-roles.tf's header.
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Remote state lives in access-controlled Azure Storage (threat N6). Values are supplied at
  # init time: terraform init -backend-config=backend.hcl (see backend.hcl.example and
  # scripts/bootstrap-tfstate.sh).
  backend "azurerm" {}
}
