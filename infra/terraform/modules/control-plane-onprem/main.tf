# The on-premises half of Mina since ADR-0006: the control-plane API, the management portal and
# SQL Server, on the FIAU Proxmox cluster in a dedicated DMZ VLAN.
#
# Three hosts, because the security argument depends on the separation being structural rather than
# configurational:
#
#   proxy  — publishes the node-facing listener to the internet, and nothing else. It has no vhost
#            for the management port, so a mistake in its configuration cannot expose the portal:
#            there is nothing there to expose.
#   app    — the API and the portal, binding the two listeners of ADR-0006 constraint 1. Its host
#            firewall admits the node port only from the proxy, and the management port only from
#            corporate ranges.
#   sql    — the database, reachable only from the app host.
#
# The in-process listener split (Mina.ControlPlane.Hosting) and these firewall rules are deliberately
# redundant. Either alone would be a single point of failure for the property that the management
# surface is not on the internet.

locals {
  app_ip   = split("/", var.app_address)[0]
  proxy_ip = split("/", var.proxy_address)[0]
  sql_ip   = split("/", var.sql_address)[0]
}

resource "proxmox_download_file" "ubuntu" {
  content_type        = "import"
  datastore_id        = var.snippet_datastore_id
  node_name           = var.proxmox_node
  url                 = var.cloud_image_url
  checksum            = var.cloud_image_sha256
  checksum_algorithm  = "sha256"
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
      ssh_keys             = var.ssh_public_keys
      public_hostname      = var.public_hostname
      app_ip               = local.app_ip
      node_port            = var.node_listener_port
      corp_cidrs           = var.corp_management_cidrs
      tunnel_connector_cidr = var.tunnel_connector_cidr
    })
  }
}

resource "proxmox_virtual_environment_file" "app_init" {
  content_type = "snippets"
  datastore_id = var.snippet_datastore_id
  node_name    = var.proxmox_node

  source_raw {
    file_name = "${var.prefix}-cp-app.yaml"
    data = templatefile("${path.module}/templates/app.cloud-init.yaml.tftpl", {
      ssh_keys        = var.ssh_public_keys
      proxy_ip        = local.proxy_ip
      node_port       = var.node_listener_port
      management_port = var.management_listener_port
      corp_cidrs      = var.corp_management_cidrs
    })
  }
}

resource "proxmox_virtual_environment_file" "sql_init" {
  content_type = "snippets"
  datastore_id = var.snippet_datastore_id
  node_name    = var.proxmox_node

  source_raw {
    file_name = "${var.prefix}-cp-sql.yaml"
    data = templatefile("${path.module}/templates/sql.cloud-init.yaml.tftpl", {
      ssh_keys   = var.ssh_public_keys
      app_ip     = local.app_ip
      corp_cidrs = var.corp_management_cidrs
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

resource "proxmox_virtual_environment_vm" "app" {
  name        = "${var.prefix}-cp-app"
  node_name   = var.proxmox_node
  description = "Mina control plane: API and management portal (ADR-0006)."
  tags        = concat(var.tags, ["dmz", "app"])
  on_boot     = true

  cpu {
    cores = var.app_cores
    type  = "host"
  }

  memory {
    dedicated = var.app_memory_mb
  }

  disk {
    datastore_id = var.datastore_id
    import_from  = proxmox_download_file.ubuntu.id
    interface    = "scsi0"
    size         = 40
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
    user_data_file_id = proxmox_virtual_environment_file.app_init.id

    ip_config {
      ipv4 {
        address = var.app_address
        gateway = var.dmz_gateway
      }
    }

    dns {
      servers = var.dns_servers
    }
  }
}

resource "proxmox_virtual_environment_vm" "sql" {
  name        = "${var.prefix}-cp-sql"
  node_name   = var.proxmox_node
  description = "Mina control plane: SQL Server, reachable only from the app host (ADR-0006)."
  tags        = concat(var.tags, ["dmz", "data"])
  on_boot     = true

  cpu {
    cores = var.sql_cores
    type  = "host"
  }

  memory {
    dedicated = var.sql_memory_mb
  }

  disk {
    datastore_id = var.datastore_id
    import_from  = proxmox_download_file.ubuntu.id
    interface    = "scsi0"
    size         = 80
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
    user_data_file_id = proxmox_virtual_environment_file.sql_init.id

    ip_config {
      ipv4 {
        address = var.sql_address
        gateway = var.dmz_gateway
      }
    }

    dns {
      servers = var.dns_servers
    }
  }
}
