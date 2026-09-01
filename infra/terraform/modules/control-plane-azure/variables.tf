variable "prefix" {
  description = "Name prefix from the naming module, e.g. mina-dev."
  type        = string
}

variable "location" {
  description = "Azure region for the control-plane support resources."
  type        = string
}

variable "tenant_id" {
  description = "Entra tenant id that owns the Key Vault."
  type        = string
}

variable "tags" {
  description = "Base tags to merge into every resource."
  type        = map(string)
}

variable "control_plane_egress_cidrs" {
  description = <<-EOT
    Public source addresses the on-premises control plane reaches Azure from — the FIAU DMZ's
    egress addresses. Both the vault and the storage account deny by default and admit only these.
    After ADR-0006 the control plane is not in Azure, so there is no VNet to put a private endpoint
    in and source addresses are the available control.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.control_plane_egress_cidrs) > 0
    error_message = "At least one source address is required; an empty list would deny the control plane itself."
  }
}

variable "key_vault_sku" {
  description = <<-EOT
    'standard' or 'premium'. Premium is HSM-backed and is what the CA signing key warrants in
    production; standard is software-protected and acceptable for a dev PoC.
  EOT
  type        = string
  default     = "standard"

  validation {
    condition     = contains(["standard", "premium"], var.key_vault_sku)
    error_message = "key_vault_sku must be 'standard' or 'premium'."
  }
}

variable "soft_delete_retention_days" {
  description = "Key Vault soft-delete retention window."
  type        = number
  default     = 90
}

variable "audit_retention_days" {
  description = <<-EOT
    Days an audit export anchor cannot be modified or deleted. Distinct from the C1/C2 retention
    period in LOGGING_AND_PRIVACY §7 (5 years, and awaiting DPO ratification): this is the
    immutability window on the anchor blobs, and a dev environment has no reason to carry the
    production figure.
  EOT
  type        = number
  default     = 7
}

variable "audit_immutability_state" {
  description = <<-EOT
    'Unlocked' or 'Locked'.

    Unlocked can be removed by the same administrator who would be tampering with the audit chain,
    so it provides NO tamper evidence — it exists so a dev environment remains destroyable. Locked
    is irreversible for the retention period and is the only state in which the anchoring design
    actually holds. Production must be Locked; that is a production-gate item, not a default this
    module should pick.
  EOT
  type        = string
  default     = "Unlocked"

  validation {
    condition     = contains(["Unlocked", "Locked"], var.audit_immutability_state)
    error_message = "audit_immutability_state must be 'Unlocked' or 'Locked'."
  }
}
