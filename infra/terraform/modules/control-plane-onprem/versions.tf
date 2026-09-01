terraform {
  required_version = ">= 1.9.0"

  required_providers {
    proxmox = {
      source = "bpg/proxmox"
      # Pinned to the minor: this provider is pre-1.0 and its schema moves. network_device, for
      # instance, is a list attribute here and a block in older releases, so a loose constraint
      # would silently break the configuration on a provider upgrade.
      version = "~> 0.111.1"
    }
  }
}
