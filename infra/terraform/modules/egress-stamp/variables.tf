variable "environment" {
  description = "Deployment environment (dev/test/prod)."
  type        = string
}

variable "region" {
  description = "Azure region for this egress stamp (must be on the approved list, D-08)."
  type        = string
}

variable "region_short" {
  description = "Short code for the region, used in resource names."
  type        = string
}

variable "prefix" {
  description = "Name prefix from the naming module (e.g. mina-dev)."
  type        = string
}

variable "tags" {
  description = "Base tags; the module adds mina:plane and mina:region."
  type        = map(string)
}

variable "vnet_cidr" {
  description = "Address space for the stamp VNet."
  type        = string
  default     = "10.80.0.0/24"
}

variable "ingress_port" {
  description = "Public port the load balancer accepts tunnel connections on."
  type        = number
  default     = 443
}

variable "health_port" {
  description = <<-EOT
    Plaintext port Envoy's health listener answers on. The load balancer probes this rather than
    the tunnel port: since M4-11 a node admits no tunnel without a healthy sidecar, and a TCP
    probe on the tunnel port would keep such a node in rotation refusing every session. 200 here
    means the admission cluster is healthy (envoy-bootstrap.yaml, listener "health").
  EOT
  type        = number
  default     = 8081
}

variable "backend_port" {
  description = "Port Envoy listens on inside the nodes."
  type        = number
  default     = 8443
}

variable "ingress_allowed_cidrs" {
  description = <<-EOT
    Source CIDRs allowed to reach the tunnel ingress (D-07: corporate egress CIDRs at MVP).
    Required with no default so exposure is always an explicit, reviewed choice.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.ingress_allowed_cidrs) > 0
    error_message = "ingress_allowed_cidrs must list at least one CIDR; use [\"0.0.0.0/0\"] only by explicit decision."
  }
}

variable "denied_egress_cidrs" {
  description = <<-EOT
    Destinations egress nodes must never reach (SR-001 / AC-017). Defaults cover private and
    CGNAT space; corp_public_cidrs are appended. Traffic to the Azure platform address
    168.63.129.16 and to IMDS (169.254.169.254) is host-local and unaffected by NSGs.
  EOT
  type        = list(string)
  default     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"]
}

variable "corp_public_cidrs" {
  description = "The organisation's public CIDRs, also denied as egress destinations (AC-017)."
  type        = list(string)
  default     = []
}

variable "instance_count" {
  description = "Envoy node count (2+ for production stamps, 1 acceptable for dev PoC)."
  type        = number
  default     = 2
}

variable "vm_sku" {
  description = "VM size for egress nodes."
  type        = string
  default     = "Standard_D2as_v5"
}

variable "admin_username" {
  description = "Admin username on egress nodes (SSH key auth only; no passwords, SR-005)."
  type        = string
  default     = "minaadmin"
}

variable "admin_ssh_public_key" {
  description = "SSH public key for node administration."
  type        = string
}

variable "nat_ip_prefix_length" {
  description = "Public IP prefix length for egress NAT (30 = 4 addresses, rotation headroom)."
  type        = number
  default     = 30
}

variable "zones" {
  description = "Availability zones for the VMSS (empty for dev)."
  type        = list(string)
  default     = []
}

variable "custom_data" {
  description = "Cloud-init for the nodes (base64 handled by the module); carries the Envoy bootstrap."
  type        = string
  default     = null
}

variable "node_image_version" {
  description = <<-EOT
    Exact Ubuntu 24.04 image version, e.g. "24.04.202508190". Deliberately has no default: "latest"
    makes the same configuration produce different nodes on different days, which is what AC-018
    exists to prevent. List the available versions with

      az vm image list --publisher Canonical --offer ubuntu-24_04-lts --sku server --all -o table
  EOT
  type        = string

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.node_image_version))
    error_message = "node_image_version must be an explicit version such as 24.04.202508190, never 'latest'."
  }
}
