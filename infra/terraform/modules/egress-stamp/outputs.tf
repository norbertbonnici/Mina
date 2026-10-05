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

output "nodes_nsg_name" {
  description = <<-EOT
    The nodes' network security group, so an environment that places a private endpoint in this
    subnet can permit the nodes to reach it. The outbound RFC1918 denies here are deliberate
    (SR-004) and deny a private endpoint's address along with everything else, so any such endpoint
    needs an explicit, narrow allow above them or the nodes resolve it and then cannot connect.
  EOT
  value       = azurerm_network_security_group.nodes.name
}

output "vnet_id" {
  description = "Stamp virtual network, for linking a private DNS zone the nodes must resolve."
  value       = azurerm_virtual_network.stamp.id
}

output "nodes_subnet_id" {
  description = <<-EOT
    The single subnet the nodes sit in, for placing a private endpoint the nodes reach an Azure
    service through. Exposed for Private Link specifically: enabling a service endpoint on this
    subnet instead would override routing for a whole service tag and take analyst traffic off the
    NAT gateway's approved egress prefix.
  EOT
  value       = azurerm_subnet.nodes.id
}
