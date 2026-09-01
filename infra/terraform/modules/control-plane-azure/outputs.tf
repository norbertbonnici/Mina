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
