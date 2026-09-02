output "ingress_public_ip" {
  description = "Dev tunnel ingress IP (agents connect here)."
  value       = module.egress_stamp.ingress_public_ip
}

output "egress_ip_prefix" {
  description = "Dev egress IP prefix (what research targets observe, AC-003)."
  value       = module.egress_stamp.egress_ip_prefix
}

output "key_vault_uri" {
  description = "Set as Mina:Pki:KeyVaultUri on the on-premises control plane."
  value       = module.control_plane_azure.key_vault_uri
}

output "audit_export_container_uri" {
  description = "Set as Mina:Audit:ExportContainerUri on the on-premises control plane."
  value       = module.control_plane_azure.audit_export_container_uri
}

output "audit_anchors_are_immutable" {
  description = "False in dev: the immutability policy is Unlocked, so anchors are not tamper-evident."
  value       = module.control_plane_azure.audit_immutability_state == "Locked"
}

output "activity_log_exported" {
  description = "Whether ARM operations against this subscription are being recorded (M6-13)."
  value       = module.activity_log.enabled
}
