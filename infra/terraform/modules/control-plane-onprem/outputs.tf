output "app_ip" {
  description = "DMZ address of the control-plane application host."
  value       = local.app_ip
}

output "proxy_ip" {
  description = "DMZ address of the publishing reverse proxy. Point the public DNS record here."
  value       = local.proxy_ip
}

output "sql_ip" {
  description = "DMZ address of the SQL Server host."
  value       = local.sql_ip
}

output "node_endpoint" {
  description = "What the egress nodes are configured with (SidecarOptions.ControlPlaneBaseUrl)."
  value       = "https://${var.public_hostname}"
}

output "listener_ports" {
  description = "Ports the application must bind (Mina:Hosting:Listeners:*)."
  value = {
    node       = var.node_listener_port
    management = var.management_listener_port
  }
}
