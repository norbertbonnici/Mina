# SQL Server for the Mina control plane (D-17), on Windows rather than the Linux hosts the rest
# of ADR-0006's control plane runs on. That split is deliberate, not an inconsistency:
#
# D-17 wants the control plane to Entra-authenticate to SQL Server with no stored credential. The
# GA path to that -- SQL Server's own managed-identity feature -- is Windows + SQL Server 2025
# only. The Linux equivalent ("SQL Server enabled by Azure Arc", the extension that would enable
# Entra auth on a Linux-hosted instance at all) is still Preview in Microsoft's own current release
# notes, and its documented supported-OS list doesn't include the Ubuntu release this environment
# already standardized on for the other two hosts. Rather than build on a Preview component with a
# real OS-support gap, SQL Server runs on Windows here -- which also matches how the organisation runs SQL
# Server for real, so this isn't a lab-only detour from the eventual production shape.
#
# Provisioning clones a pre-built, sysprepped Windows Server template (see template_vm_id's
# description) and sizes/networks the VM. It does not install SQL Server, join Azure Arc, or
# configure Entra authentication -- that's a separate, scripted step, the same boundary the Linux
# hosts draw between "the host exists" and "the application is deployed" (see scripts/).
#
# No cloud-init here: Windows doesn't consume it the way the Linux hosts do. The clone boots with
# whatever networking the template had (DHCP), and post-clone configuration -- static IP, hostname,
# firewall, everything else -- goes through the QEMU guest agent's exec capability instead, proven
# during this environment's own template build to work as SYSTEM with no RDP/WinRM required.

resource "proxmox_virtual_environment_vm" "sql" {
  name        = "${var.prefix}-cp-sql"
  node_name   = var.proxmox_node
  description = "Mina control plane: SQL Server on Windows (D-17), reachable only from the app host."
  tags        = concat(var.tags, ["dmz", "data", "windows"])
  on_boot     = true

  clone {
    vm_id        = var.template_vm_id
    full         = true
    datastore_id = var.datastore_id
  }

  cpu {
    cores = var.sql_cores
    type  = "host"
  }

  memory {
    dedicated = var.sql_memory_mb
  }

  # A list attribute rather than a block in this provider version, and a strict object type: every
  # field must be present, so the ones the provider defaults are passed as null explicitly. Matches
  # the sibling control-plane-onprem module's network_device convention.
  network_device = [{
    bridge       = var.dmz_bridge
    vlan_id      = var.dmz_vlan_tagged ? var.dmz_vlan_id : null
    model        = "virtio"
    enabled      = true
    disconnected = false
    # Windows Firewall is the control here, configured by the post-clone provisioning script --
    # the same role nftables plays on the Linux hosts. The Proxmox firewall would be a second
    # layer but needs datacenter-level rules that are not in this module's scope.
    firewall    = false
    mac_address = null
    mtu         = null
    queues      = null
    rate_limit  = null
    trunks      = null
  }]

  agent {
    enabled = true
    # Windows takes longer than the Linux hosts to reach a state where the agent inside actually
    # responds -- OOBE/first-boot processing runs before it does, even though sysprep -oobe was
    # used specifically so a clone doesn't stop at an interactive OOBE screen waiting for nobody.
    timeout = "5m"
  }
}
