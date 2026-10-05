variable "prefix" {
  description = "Name prefix from the naming module, e.g. mina-dev."
  type        = string
}

variable "location" {
  description = "Azure region for the control-plane support resources."
  type        = string
}

variable "region_short" {
  description = <<-EOT
    Short region code (module.naming.region_short) appended to the Key Vault name. Key Vault
    names are globally unique across all of Azure, and a deleted vault's name stays reserved for
    its soft-delete retention period (up to 90 days) even with purge protection off -- with it
    on (the default here), the name is unavailable for the full retention window, no early purge
    possible. This module's own region can and did move during dev/PoC troubleshooting
    (2026-09-04), which hit exactly that collision. Region-qualifying the name makes a future
    region move safe instead of a 90-day name squat.
  EOT
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
    Public source addresses the on-premises control plane reaches Azure from — the on-premises DMZ's
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

variable "diagnostics_retention_days" {
  description = <<-EOT
    Retention for the diagnostics workspace. These records are evidence about the audit trail —
    who read an anchor, who tried to delete one, who used the CA key — so they are not ordinary
    operational logs. The dev default is short; the production figure belongs with the C1/C2
    decision in LOGGING_AND_PRIVACY §7, which is still awaiting DPO ratification (D-09).
  EOT
  type        = number
  default     = 30
}

variable "diagnostics_daily_quota_gb" {
  description = <<-EOT
    Daily ingestion cap, or null for none. Deliberately null by default: a quota protects the bill
    by DROPPING data once it is hit, and the data being dropped here would be the record of who
    touched the audit anchors. Set it only with that trade understood.
  EOT
  type        = number
  default     = null
}

variable "alert_email_receivers" {
  description = <<-EOT
    Addresses notified when anything happens to the CA vault or the audit-anchor store. Empty
    disables the alert rules entirely — and an empty list is the honest default, because an alert
    with no receiver is worse than none: it looks like coverage in a plan and reaches nobody.

    Expect these to fire on your own Terraform applies. That is intended: a change to the vault
    holding the CA signing key should be something a human sees, including when it is you.
  EOT
  type        = list(string)
  default     = []
}

variable "alert_webhook_uri" {
  description = "Optional webhook for the same alerts, for example a SIEM or chat integration."
  type        = string
  default     = null
}

variable "control_plane_principal_id" {
  description = <<-EOT
    Object id of the on-premises control plane's own identity — its Azure Arc system-assigned
    managed identity (D-17/D-18). Granted the two data-plane roles the internal CA needs: Key Vault
    Crypto User to sign with the CA key, and Key Vault Secrets User to read the CA certificate
    stored beside it (M2-2c).

    Empty until the control-plane hosts are Arc-onboarded (BACKLOG M4-18); with no principal there
    is nothing to grant, and the API cannot use the Key Vault CA until there is. The bootstrap tool
    and an operator's own `az login` are unaffected — those are covered by the deployer role
    assignments this module makes.
  EOT
  type        = string
  default     = ""
}
