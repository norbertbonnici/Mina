# Everything here that describes the deployment site has no default. These are facts about your
# infrastructure, not preferences, and a wrong guess would either fail late or -- worse -- succeed
# against the wrong network. Matches the sibling sql-onprem-windows module's convention.

variable "prefix" {
  description = "Name prefix, e.g. mina-dev."
  type        = string
}

variable "proxmox_node" {
  description = "Proxmox node the application VM is created on."
  type        = string
}

variable "datastore_id" {
  description = "Proxmox datastore for the cloned VM's disks, e.g. local-lvm."
  type        = string
}

variable "template_vm_id" {
  description = <<-EOT
    ID of the sysprepped, generalized Windows Server template to clone from -- the same template
    the sql-onprem-windows module clones for the SQL host. Must already be marked as a Proxmox
    template (the "template" flag, not just a stopped VM) -- Terraform does not build this
    template, it only clones it. Provisioning creates the host; it does not install IIS, join
    Arc, or deploy the application -- that is a separate, deliberate step (see scripts/), the
    same boundary the SQL module draws around its own post-clone configuration.
  EOT
  type        = number
}

variable "dmz_bridge" {
  description = "Linux bridge carrying the DMZ VLAN, e.g. vmbr1."
  type        = string
}

variable "dmz_vlan_id" {
  description = "VLAN id of the DMZ segment (ADR-0006 constraint 2). See the module variable of the same name in control-plane-onprem for the full reasoning."
  type        = number
}

variable "dmz_vlan_tagged" {
  description = <<-EOT
    Whether the guest NIC should 802.1Q-tag traffic with dmz_vlan_id. See the identically-named
    variable in the sibling control-plane-onprem module for the full reasoning -- set false when
    the switch port carries dmz_vlan_id as its native/untagged VLAN instead of a trunk tag.
  EOT
  type        = bool
  default     = true
}

variable "dmz_gateway" {
  description = "Default gateway on the DMZ VLAN."
  type        = string
}

variable "dns_servers" {
  description = "DNS servers for the application VM."
  type        = list(string)
}

variable "app_address" {
  description = <<-EOT
    DMZ address of the application host, in CIDR form. Not applied via cloud-init (Windows
    doesn't use it the way the Linux proxy host does) -- the clone boots with whatever addressing
    the template had (DHCP), and a post-clone provisioning step sets this as a static address via
    the QEMU guest agent, matching how the SQL host and the template itself were provisioned.
  EOT
  type        = string
}

variable "proxy_address" {
  description = "DMZ address of the publishing reverse proxy -- the only address this host's Windows Firewall admits on the node-facing port."
  type        = string
}

variable "corp_management_cidrs" {
  description = "Corporate ranges permitted to reach the management listener and to administer this host (RDP/WinRM), matching the sibling modules' identically-named variable."
  type        = list(string)

  validation {
    condition     = length(var.corp_management_cidrs) > 0
    error_message = "At least one corporate range is required, or the host is unreachable by anyone."
  }
}

variable "app_cores" {
  description = "vCPUs for the application host."
  type        = number
  default     = 2
}

variable "app_memory_mb" {
  description = "Memory for the application host."
  type        = number
  default     = 4096
}

variable "tags" {
  description = "Tags applied to the VM."
  type        = list(string)
  default     = ["mina", "control-plane"]
}
