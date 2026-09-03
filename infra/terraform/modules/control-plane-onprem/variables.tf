# Everything here that describes the FIAU site has no default. These are facts about your
# infrastructure, not preferences, and a wrong guess would either fail late or -- worse -- succeed
# against the wrong network.

variable "prefix" {
  description = "Name prefix, e.g. mina-dev."
  type        = string
}

variable "proxmox_node" {
  description = "Proxmox node the control-plane VMs are created on."
  type        = string
}

variable "datastore_id" {
  description = "Proxmox datastore for VM disks, e.g. local-lvm."
  type        = string
}

variable "snippet_datastore_id" {
  description = <<-EOT
    Datastore holding cloud-init snippets. Must have the "snippets" content type enabled in
    Proxmox (Datacenter > Storage > Edit > Content), which is off by default and is the usual
    first-run failure.
  EOT
  type        = string
}

variable "dmz_bridge" {
  description = "Linux bridge carrying the DMZ VLAN, e.g. vmbr1."
  type        = string
}

variable "dmz_vlan_id" {
  description = <<-EOT
    VLAN id of the DMZ segment. ADR-0006 constraint 2: the control plane sits in a dedicated DMZ
    VLAN, not on the corporate LAN, because one of its listeners is published to the internet and
    the segment must be firewalled from corp accordingly.
  EOT
  type        = number
}

variable "dmz_vlan_tagged" {
  description = <<-EOT
    Whether the guest NIC should 802.1Q-tag traffic with dmz_vlan_id. Proxmox's VLAN-aware bridges
    tag unconditionally when a vlan_id is set, which only matches a trunk port configured to expect
    that tag. Set false when the switch port instead carries dmz_vlan_id as its native/untagged
    VLAN -- tagging it anyway double-tags and the traffic goes nowhere, which looks identical to a
    dead link from the guest's side (boots fine, no DNS/apt/SSH, because nothing arrives at all).
  EOT
  type        = bool
  default     = true
}

variable "dmz_gateway" {
  description = "Default gateway on the DMZ VLAN."
  type        = string
}

variable "dns_servers" {
  description = "DNS servers for the control-plane VMs."
  type        = list(string)
}

variable "app_address" {
  description = <<-EOT
    DMZ address of the control-plane application host, in CIDR form (e.g. 10.20.30.11/24). This
    module no longer creates that host (see app-onprem-windows) -- it only uses this to tell the
    proxy's nginx config where to forward the node-facing listener.
  EOT
  type        = string
}

variable "proxy_address" {
  description = "DMZ address of the publishing reverse proxy, in CIDR form."
  type        = string
}

variable "corp_management_cidrs" {
  description = <<-EOT
    Corporate ranges permitted to reach the management listener and to administer these hosts.
    ADR-0006 constraint 1 keeps the portal, audit read and administrative endpoints off the
    published listener; this keeps them off the DMZ interface for everyone else as well.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.corp_management_cidrs) > 0
    error_message = "At least one corporate range is required, or the portal is unreachable by anyone."
  }
}

variable "public_hostname" {
  description = "Public DNS name the egress nodes reach the node-facing listener at."
  type        = string
}

variable "tunnel_connector_cidr" {
  description = <<-EOT
    Address (as a /32, or a range) of the reverse-tunnel connector -- e.g. a Cloudflare Tunnel
    connector -- that is the only thing allowed to reach the proxy's node-facing listener.
    Public TLS terminates at that connector's far end, not on this VM (ADR-0006 constraint 3 is
    still met; the certificate just isn't installed here). If you're terminating TLS on the proxy
    VM itself instead, this should be the internet at large ("0.0.0.0/0") and the proxy cloud-init
    template's nginx site needs its own certificate configuration to match.
  EOT
  type        = string
}

variable "node_listener_port" {
  description = "Port the control-plane API binds for the node-facing listener (Mina:Hosting:Listeners:NodePort)."
  type        = number
  default     = 8443
}

variable "management_listener_port" {
  description = "Port the control-plane API binds for the corporate listener (…:ManagementPort)."
  type        = number
  default     = 8444

  validation {
    condition     = var.management_listener_port != var.node_listener_port
    error_message = "The two listeners must bind different ports; one port would publish the management surface."
  }
}

variable "ssh_public_keys" {
  description = "Administrator SSH public keys for the control-plane VMs."
  type        = list(string)
}

variable "cloud_image_url" {
  description = <<-EOT
    Ubuntu 24.04 cloud image URL, pinned to a dated release rather than a moving one. AC-018 applies
    to the on-premises plane too since ADR-0006, so "current" is not an acceptable source.
    Example: https://cloud-images.ubuntu.com/releases/24.04/release-20250801/ubuntu-24.04-server-cloudimg-amd64.img
  EOT
  type        = string
}

variable "cloud_image_sha256" {
  description = "SHA-256 of the cloud image, from the SHA256SUMS file beside it in the release directory."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.cloud_image_sha256))
    error_message = "cloud_image_sha256 must be a 64-character lowercase hex digest."
  }
}

variable "tags" {
  description = "Tags applied to every VM."
  type        = list(string)
  default     = ["mina", "control-plane"]
}
