terraform {
  required_version = ">= 1.9.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }

  # Remote state lives in access-controlled Azure Storage (threat N6). Values are supplied at
  # init time: terraform init -backend-config=backend.hcl (see backend.hcl.example and
  # scripts/bootstrap-tfstate.sh).
  backend "azurerm" {}
}
