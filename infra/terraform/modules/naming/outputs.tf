output "prefix" {
  description = "Name prefix, e.g. mina-dev."
  value       = local.prefix
}

output "tags" {
  description = "Base tags to merge into every resource."
  value       = local.base_tags
}

output "region_short" {
  description = "Map of approved-candidate Azure region name to short code."
  value       = local.region_short
}
