terraform {
  required_version = ">= 1.9.0"

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "~> 0.111.1"
    }
  }

  # State lives in the same access-controlled Azure Storage as the Azure environments (threat N6),
  # under its own key. Separate state from `dev` on purpose: this applies against a different API
  # with different credentials, and a Proxmox failure should not block an Azure apply or vice versa.
  backend "azurerm" {}
}
