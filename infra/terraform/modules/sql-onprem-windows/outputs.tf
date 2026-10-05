output "sql_ip" {
  description = "DMZ address of the SQL Server host. Not applied automatically -- set by the post-clone provisioning script, not by this module."
  value       = split("/", var.sql_address)[0]
}

output "vm_id" {
  description = "Proxmox VM ID of the cloned SQL Server host, for targeting the post-clone provisioning step."
  value       = proxmox_virtual_environment_vm.sql.vm_id
}
