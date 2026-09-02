output "node_endpoint" {
  description = "Set as the egress sidecar's ControlPlaneBaseUrl (backlog M4-17)."
  value       = module.control_plane.node_endpoint
}

output "proxy_ip" {
  description = "Point the public DNS record for the node endpoint at this address."
  value       = module.control_plane.proxy_ip
}

output "app_ip" {
  description = "Application host; the portal is reached here from corporate ranges."
  value       = module.control_plane.app_ip
}

output "sql_ip" {
  description = "SQL Server host."
  value       = module.control_plane.sql_ip
}

output "listener_ports" {
  description = "Ports the application must bind (Mina:Hosting:Listeners:*)."
  value       = module.control_plane.listener_ports
}
