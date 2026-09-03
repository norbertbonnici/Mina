terraform {
  required_version = ">= 1.9.0"

  required_providers {
    proxmox = {
      source = "bpg/proxmox"
      # Pinned to the minor: this provider is pre-1.0 and its schema moves. Matches the sibling
      # control-plane-onprem module's pin so both stay on the same provider release.
      version = "~> 0.111.1"
    }
  }
}
