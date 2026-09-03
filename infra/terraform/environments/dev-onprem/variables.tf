variable "proxmox_node" {
  description = "Proxmox node the control-plane VMs are created on."
  type        = string
}

variable "datastore_id" {
  description = "Datastore for VM disks, e.g. local-lvm."
  type        = string
}

variable "snippet_datastore_id" {
  description = "Datastore for cloud-init snippets; needs the 'snippets' content type enabled."
  type        = string
}

variable "dmz_bridge" {
  description = "Linux bridge carrying the DMZ VLAN, e.g. vmbr1."
  type        = string
}

variable "dmz_vlan_id" {
  description = "VLAN id of the DMZ segment."
  type        = number
}

variable "dmz_vlan_tagged" {
  description = <<-EOT
    Whether the guest NIC should 802.1Q-tag traffic with dmz_vlan_id. Set false when the switch
    port instead carries dmz_vlan_id as its native/untagged VLAN -- tagging it anyway double-tags
    and the traffic goes nowhere (see the module variable of the same name for the full story).
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

variable "proxy_address" {
  description = "DMZ address of the publishing reverse proxy, in CIDR form."
  type        = string
}

variable "app_address" {
  description = "DMZ address of the application host, in CIDR form."
  type        = string
}

variable "sql_address" {
  description = "DMZ address of the SQL Server host, in CIDR form."
  type        = string
}

variable "corp_management_cidrs" {
  description = "Corporate ranges permitted to reach the management listener and administer the hosts."
  type        = list(string)
}

variable "public_hostname" {
  description = "Public DNS name the egress nodes reach the node-facing listener at."
  type        = string
}

variable "ssh_public_keys" {
  description = "Administrator SSH public keys."
  type        = list(string)
}

variable "cloud_image_url" {
  description = "Pinned Ubuntu 24.04 cloud image URL (a dated release, not a moving one)."
  type        = string
}

variable "cloud_image_sha256" {
  description = "SHA-256 of the cloud image from the release's SHA256SUMS."
  type        = string
}
