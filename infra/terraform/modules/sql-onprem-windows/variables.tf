# Everything here that describes the FIAU site has no default. These are facts about your
# infrastructure, not preferences, and a wrong guess would either fail late or -- worse -- succeed
# against the wrong network. Matches the sibling control-plane-onprem module's convention.

variable "prefix" {
  description = "Name prefix, e.g. mina-dev."
  type        = string
}

variable "proxmox_node" {
  description = "Proxmox node the SQL Server VM is created on."
  type        = string
}

variable "datastore_id" {
  description = "Proxmox datastore for the cloned VM's disks, e.g. local-lvm."
  type        = string
}

variable "template_vm_id" {
  description = <<-EOT
    ID of the sysprepped, generalized Windows Server template to clone from. Must already be
    marked as a Proxmox template (the "template" flag, not just a stopped VM) -- Terraform does
    not build this template, it only clones it. Provisioning creates the host; it does not
    install SQL Server, join Arc, or configure Entra authentication -- that is a separate,
    deliberate step (see scripts/), the same boundary the Linux hosts draw around app deployment.
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
  description = "DNS servers for the SQL Server VM."
  type        = list(string)
}

variable "sql_address" {
  description = <<-EOT
    DMZ address of the SQL Server host, in CIDR form. Not applied via cloud-init (Windows doesn't
    use it the way the Linux hosts do) -- the clone boots with whatever addressing the template
    had (DHCP), and a post-clone provisioning step sets this as a static address via the QEMU
    guest agent, which is also how the template itself was proven remotely scriptable without
    RDP.
  EOT
  type        = string
}

variable "app_address" {
  description = "DMZ address of the control-plane application host, in CIDR form -- the only address the SQL host's firewall admits on 1433."
  type        = string
}

variable "corp_management_cidrs" {
  description = "Corporate ranges permitted to administer this host (RDP/WinRM), matching the sibling module's identically-named variable."
  type        = list(string)

  validation {
    condition     = length(var.corp_management_cidrs) > 0
    error_message = "At least one corporate range is required, or the host is unreachable by anyone."
  }
}

variable "sql_cores" {
  description = "vCPUs for the SQL Server host."
  type        = number
  default     = 4
}

variable "sql_memory_mb" {
  description = "Memory for the SQL Server host. SQL Server wants considerably more than the app."
  type        = number
  default     = 8192
}

variable "tags" {
  description = "Tags applied to the VM."
  type        = list(string)
  default     = ["mina", "control-plane"]
}
