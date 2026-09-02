output "enabled" {
  description = "Whether the Activity Log export was created."
  value       = var.enabled
}

output "subscription_id" {
  description = "Subscription the export covers, if enabled."
  value       = data.azurerm_subscription.current.id
}
