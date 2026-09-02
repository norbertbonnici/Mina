output "resource_group_name" {
  description = "Stamp resource group."
  value       = azurerm_resource_group.stamp.name
}

output "ingress_public_ip" {
  description = "Public IP analysts' agents connect to (tunnel ingress)."
  value       = azurerm_public_ip.ingress.ip_address
}

output "egress_ip_prefix" {
  description = "Static public IP prefix research traffic egresses from (the approved addresses)."
  value       = azurerm_public_ip_prefix.egress.ip_prefix
}

output "vmss_principal_id" {
  description = "Managed-identity principal of the node scale set (for scoped control-plane RBAC)."
  value       = azurerm_linux_virtual_machine_scale_set.nodes.identity[0].principal_id
}
