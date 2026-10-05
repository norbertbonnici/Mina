# The Mina control-plane application host, on Windows under IIS rather than Linux under systemd.
# That's a deliberate pivot, not the original design (see control-plane-onprem's header for the
# shape this replaced) -- once SQL Server's Entra managed-identity auth (D-17) put a Windows,
# Arc-connected host in the DMZ anyway, the app host followed it there so it can get its own
# Arc-issued managed identity and authenticate to SQL with Authentication=Active Directory Default
# and no stored credential. Authentication=Active Directory Default resolves through a *local*
# Arc/IMDS-style endpoint, which only exists on a machine that is itself Arc-connected -- a plain
# Ubuntu app host has no way to acquire that token, which is the reason this host moved rather
# than staying Linux while only SQL did.
#
# IIS matters here beyond "Windows needs a web server": ADR-0006 constraint 1's listener
# separation (Mina.ControlPlane.Hosting.MinaListeners) keys off the TCP-local-port the connection
# was accepted on, specifically because that can't be spoofed by a misconfigured proxy in front of
# it. Classic IIS reverse-proxy-to-Kestrel ("out-of-process") hosting would reintroduce exactly
# that proxy-misconfiguration risk. In-process hosting (IIS's own HTTP.sys serving the app inside
# the worker process -- .NET's default when publishing to IIS) preserves it, because the local-port
# IIS reports per request is the real socket data, not something a proxy hop rewrote. The
# provisioning script that follows this module configures two IIS site bindings (the node and
# management ports) against one in-process app, and deployment verification checks that a
# management-only endpoint 404s on the node port before calling this done.
#
# No cloud-init here, matching sql-onprem-windows: the clone boots with whatever networking the
# template had (DHCP), and post-clone configuration -- static IP, hostname, Windows Firewall, IIS,
# Arc onboarding, the application itself -- goes through the QEMU guest agent's exec capability,
# the same channel proven during this environment's template build to work as SYSTEM with no
# RDP/WinRM required.

resource "proxmox_virtual_environment_vm" "app" {
  name        = "${var.prefix}-cp-app"
  node_name   = var.proxmox_node
  description = "Mina control plane: API under IIS on Windows (ADR-0006), reachable from the proxy on the node port and from corporate ranges on the management port."
  tags        = concat(var.tags, ["dmz", "app", "windows"])
  on_boot     = true

  clone {
    vm_id        = var.template_vm_id
    full         = true
    datastore_id = var.datastore_id
  }

  cpu {
    cores = var.app_cores
    type  = "host"
  }

  memory {
    dedicated = var.app_memory_mb
  }

  # A list attribute rather than a block in this provider version, and a strict object type: every
  # field must be present, so the ones the provider defaults are passed as null explicitly. Matches
  # the sibling modules' network_device convention.
  network_device = [{
    bridge       = var.dmz_bridge
    vlan_id      = var.dmz_vlan_tagged ? var.dmz_vlan_id : null
    model        = "virtio"
    enabled      = true
    disconnected = false
    # Windows Firewall is the control here, configured by the post-clone provisioning script --
    # the same role nftables plays on the proxy host. The Proxmox firewall would be a second layer
    # but needs datacenter-level rules that are not in this module's scope.
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
