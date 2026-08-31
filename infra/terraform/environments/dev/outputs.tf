output "ingress_public_ip" {
  description = "Dev tunnel ingress IP (agents connect here)."
  value       = module.egress_stamp.ingress_public_ip
}

output "egress_ip_prefix" {
  description = "Dev egress IP prefix (what research targets observe, AC-003)."
  value       = module.egress_stamp.egress_ip_prefix
}
