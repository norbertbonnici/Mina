output "node_endpoint" {
  description = "Set as the egress sidecar's ControlPlaneBaseUrl (backlog M4-17)."
  value       = module.control_plane.node_endpoint
}

output "proxy_ip" {
  description = "Point the public DNS record for the node endpoint at this address."
  value       = module.control_plane.proxy_ip
}

output "app_ip" {
  description = "Application host. Not applied automatically -- see module.app_server's own output description."
  value       = module.app_server.app_ip
}

output "app_vm_id" {
  description = "Proxmox VM ID of the application host, for targeting the post-clone provisioning step."
  value       = module.app_server.vm_id
}

output "sql_ip" {
  description = "SQL Server host. Not applied automatically -- see module.sql_server's own output description."
  value       = module.sql_server.sql_ip
}

output "sql_vm_id" {
  description = "Proxmox VM ID of the SQL Server host, for targeting the post-clone provisioning step."
  value       = module.sql_server.vm_id
}

output "listener_ports" {
  description = "Ports the application must bind (Mina:Hosting:Listeners:*)."
  value       = module.control_plane.listener_ports
}
