# Subscription-scoped Azure Activity Log export (M6-13).
#
# M6-11 records who *used* the CA signing key and the audit anchors. This records what was done
# *to* them. The distinction is the whole point: deleting the storage account, removing the
# immutability policy, purging the vault or granting oneself a role are ARM operations. They never
# appear in data-plane diagnostics, and they are what removing tamper evidence actually looks like.
#
# Two limitations are inherent to this shape and are stated rather than glossed:
#
#   1. The workspace lives in the subscription it is watching, so it shares a blast radius with the
#      thing it watches. An attacker with enough rights to remove the immutability policy can also
#      delete the resource group holding the evidence of having done so. The fix is a workspace in a
#      different subscription (or tenant), which needs a second subscription this project does not
#      have — recorded as a production-gate item, not silently accepted.
#   2. Export is not detection. Records in a workspace nobody queries prove things after the fact
#      but stop nothing at the time; alerting on the destructive operations is M6-14.
#
# This is subscription-wide, not Mina-scoped: the Activity Log is a property of the subscription, so
# enabling it captures every workload in it. That is usually what an organisation wants, but it is
# the operator's call, which is why it can be switched off.

data "azurerm_subscription" "current" {}

resource "azurerm_monitor_diagnostic_setting" "activity" {
  count = var.enabled ? 1 : 0

  name                       = "mina-activity-log"
  target_resource_id         = data.azurerm_subscription.current.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  dynamic "enabled_log" {
    for_each = toset(var.categories)

    content {
      category = enabled_log.value
    }
  }
}
