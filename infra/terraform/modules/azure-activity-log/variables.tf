variable "enabled" {
  description = <<-EOT
    Whether to create the subscription-scoped Activity Log export. Off by default: it is
    subscription-wide rather than Mina-scoped, needs rights at the subscription rather than the
    resource group, and an organisation may already export the Activity Log centrally — in which
    case a second setting is duplication rather than defence.
  EOT
  type        = bool
  default     = false
}

variable "log_analytics_workspace_id" {
  description = "Workspace the Activity Log is sent to."
  type        = string
}

variable "categories" {
  description = <<-EOT
    Activity Log categories to export.

    `Administrative` is the one this exists for: every ARM create, update and delete, including the
    operations that would remove tamper evidence. `Security` and `Policy` are cheap and relevant.

    The operational categories — ServiceHealth, ResourceHealth, Autoscale, Recommendation — are
    excluded by default. They are the bulk of the volume and none of them records anybody doing
    anything to the audit anchors, which is what this export is for.
  EOT
  type        = list(string)
  default     = ["Administrative", "Security", "Policy"]

  validation {
    condition     = contains(var.categories, "Administrative")
    error_message = "Administrative must be included; without it the export does not record ARM operations, which is the entire purpose."
  }
}
