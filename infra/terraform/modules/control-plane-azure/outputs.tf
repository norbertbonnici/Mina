output "key_vault_uri" {
  description = "Vault URI the on-premises control plane signs with (Mina:Pki:KeyVaultUri)."
  value       = azurerm_key_vault.cp.vault_uri
}

output "ca_key_id" {
  description = "Versionless id of the internal CA signing key."
  value       = azurerm_key_vault_key.ca_signing.versionless_id
}

output "audit_export_container_uri" {
  description = "Container the audit exporter anchors to (Mina:Audit:ExportContainerUri)."
  value       = "${azurerm_storage_account.audit.primary_blob_endpoint}${azurerm_storage_container.audit_exports.name}"
}

output "audit_immutability_state" {
  description = "Whether the anchors are actually immutable. 'Unlocked' means they are not."
  value       = var.audit_immutability_state
}

output "diagnostics_workspace_id" {
  description = "Log Analytics workspace carrying CA key use and audit-anchor access."
  value       = azurerm_log_analytics_workspace.cp.id
}

output "alerting_enabled" {
  description = "False when no receiver was configured, in which case nothing is alerting (M4-27)."
  value       = length(var.alert_email_receivers) > 0 || var.alert_webhook_uri != null
}

output "ca_signing_key_name" {
  description = "Signing key name (Mina:Pki:SigningKeyName; the API defaults to this value)."
  value       = azurerm_key_vault_key.ca_signing.name
}

output "control_plane_key_vault_access_granted" {
  description = <<-EOT
    Whether the control plane's own identity can actually use the CA. False means no principal was
    supplied (M4-18 not done), so the Key Vault CA is reachable by an operator but not by the API.
  EOT
  value       = var.control_plane_principal_id != ""
}

output "control_plane_audit_storage_access_granted" {
  description = <<-EOT
    Whether the control plane's own identity can write and read audit exports. False means no
    principal was supplied (M4-18 not done), so the API falls back to the filesystem sink (or
    refuses to start outside Development).
  EOT
  value       = var.control_plane_principal_id != ""
}
