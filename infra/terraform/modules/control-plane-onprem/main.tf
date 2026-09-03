# The publishing edge of Mina's on-premises control plane since ADR-0006: a Linux/nginx reverse
# proxy in the FIAU DMZ VLAN that terminates the node-facing listener and forwards to the
# application host, and nothing else. It has no vhost for the management port, so a mistake in its
# configuration cannot expose the portal: there is nothing there to expose.
#
# This module used to also own the application host, as a second Linux VM. It moved out (see
# app-onprem-windows) once SQL Server's Entra managed-identity auth (D-17) put a Windows,
# Arc-connected host in the DMZ anyway -- the app host followed so it could get its own Arc
# identity and authenticate to SQL with no stored credential, which a plain Ubuntu host has no way
# to do. This module keeps `app_address` purely to tell the proxy's nginx config where to forward
# to; it no longer creates that host.
#
# The proxy/app split itself is unchanged and still structural rather than configurational: the
# proxy's host firewall admits the node port from the tunnel connector only, the app host's
# firewall admits the node port only from this proxy and the management port only from corporate
# ranges, and the in-process listener split (Mina.ControlPlane.Hosting) enforces the same boundary
# a third way. All three are deliberately redundant -- no single one is a point of failure for the
# property that the management surface is not on the internet.

locals {
  app_ip   = split("/", var.app_address)[0]
  proxy_ip = split("/", var.proxy_address)[0]
}

resource "proxmox_download_file" "ubuntu" {
  content_type       = "import"
  datastore_id       = var.snippet_datastore_id
  node_name          = var.proxmox_node
  url                = var.cloud_image_url
  checksum           = var.cloud_image_sha256
  checksum_algorithm = "sha256"
  # Ubuntu publishes this as .img, but the file is actually QCOW2 internally (long-standing
  # naming quirk). Proxmox's import validation checks the destination extension against known
  # disk formats and rejects .img; .qcow2 is both accepted and accurate.
  file_name           = "${var.prefix}-ubuntu-24.04.qcow2"
  overwrite_unmanaged = true
}

# --- cloud-init snippets -----------------------------------------------------------------------

resource "proxmox_virtual_environment_file" "proxy_init" {
  content_type = "snippets"
  datastore_id = var.snippet_datastore_id
  node_name    = var.proxmox_node

  source_raw {
    file_name = "${var.prefix}-cp-proxy.yaml"
    data = templatefile("${path.module}/templates/proxy.cloud-init.yaml.tftpl", {
      ssh_keys              = var.ssh_public_keys
      public_hostname       = var.public_hostname
      app_ip                = local.app_ip
      node_port             = var.node_listener_port
      corp_cidrs            = var.corp_management_cidrs
      tunnel_connector_cidr = var.tunnel_connector_cidr
    })
  }
}

# --- virtual machines --------------------------------------------------------------------------

resource "proxmox_virtual_environment_vm" "proxy" {
  name        = "${var.prefix}-cp-proxy"
  node_name   = var.proxmox_node
  description = "Mina control plane: publishes the node-facing listener (ADR-0006)."
  tags        = concat(var.tags, ["dmz", "published"])
  on_boot     = true

  cpu {
    cores = 2
    type  = "host"
  }

  memory {
    dedicated = 2048
  }

  disk {
    datastore_id = var.datastore_id
    import_from  = proxmox_download_file.ubuntu.id
    interface    = "scsi0"
    size         = 20
    discard      = "on"
  }

  # A list attribute rather than a block in this provider version, and a strict object type: every
  # field must be present, so the ones the provider defaults are passed as null explicitly.
  network_device = [{
    bridge       = var.dmz_bridge
    vlan_id      = var.dmz_vlan_tagged ? var.dmz_vlan_id : null
    model        = "virtio"
    enabled      = true
    disconnected = false
    # Host nftables is the control here (see the cloud-init templates); the Proxmox firewall would
    # be a second layer but needs datacenter-level rules that are not in this module's scope.
    firewall    = false
    mac_address = null
    mtu         = null
    queues      = null
    rate_limit  = null
    trunks      = null
  }]

  agent {
    enabled = true
  }

  initialization {
    datastore_id      = var.datastore_id
    user_data_file_id = proxmox_virtual_environment_file.proxy_init.id

    ip_config {
      ipv4 {
        address = var.proxy_address
        gateway = var.dmz_gateway
      }
    }

    dns {
      servers = var.dns_servers
    }
  }
}
