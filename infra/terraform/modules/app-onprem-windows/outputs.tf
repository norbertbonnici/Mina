output "app_ip" {
  description = "DMZ address of the application host. Not applied automatically -- set by the post-clone provisioning script, not by this module."
  value       = split("/", var.app_address)[0]
}

output "vm_id" {
  description = "Proxmox VM ID of the cloned application host, for targeting the post-clone provisioning step."
  value       = proxmox_virtual_environment_vm.app.vm_id
}
