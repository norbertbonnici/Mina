variable "egress_region" {
  description = "Region for the dev PoC egress stamp (from the D-08 candidate list)."
  type        = string
  default     = "westeurope"
}

variable "ingress_allowed_cidrs" {
  description = "Source CIDRs allowed to reach dev tunnel ingress (D-07 interim: admin/corp egress IPs)."
  type        = list(string)
}

variable "corp_public_cidrs" {
  description = "Organisation public CIDRs that egress nodes must never reach (AC-017)."
  type        = list(string)
  default     = []
}

variable "admin_ssh_public_key" {
  description = "SSH public key for dev egress-node administration."
  type        = string
}

variable "tenant_id" {
  description = "Entra tenant id that owns the control-plane Key Vault."
  type        = string
}

variable "control_plane_egress_cidrs" {
  description = <<-EOT
    Public source addresses the on-premises control plane reaches Azure from — the FIAU DMZ's
    egress addresses. The Key Vault and the audit storage account deny by default and admit only
    these. After ADR-0006 the control plane is not in Azure, so a private endpoint is not available.
  EOT
  type        = list(string)
}

variable "node_image_version" {
  description = "Exact Ubuntu 24.04 image version for the egress nodes (never \"latest\"; see the module variable)."
  type        = string
}

variable "envoy_version" {
  description = "Envoy release to install on the nodes, without the leading v."
  type        = string
  default     = "1.39.1"
}

variable "envoy_sha256" {
  description = <<-EOT
    SHA-256 of envoy-<version>-linux-x86_64 from the GitHub release. The node refuses to install a
    binary that does not match, so this pin is the supply-chain control for the process that
    terminates every analyst's research traffic (threat N7). Verify a new value against the release
    before changing it; do not copy it from anywhere but the release itself.
  EOT
  type        = string
  default     = "002c6e1c69ed0fa0ea381887247cadadfaec9481375fa8d8d2b1731eeabf40b8"

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.envoy_sha256))
    error_message = "envoy_sha256 must be a 64-character lowercase hex SHA-256 digest."
  }
}
