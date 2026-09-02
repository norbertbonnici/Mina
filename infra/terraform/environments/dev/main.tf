module "naming" {
  source      = "../../modules/naming"
  environment = "dev"
}

# After ADR-0006 the control plane runs on the FIAU Proxmox cluster, so the API, the portal, SQL and
# the service logs are NOT Azure resources. What remains here is the two things a general-purpose VM
# cannot provide (D-18): the CA signing key, and storage that can refuse to overwrite an anchor.
module "control_plane_azure" {
  source = "../../modules/control-plane-azure"

  prefix    = module.naming.prefix
  location  = var.egress_region
  tenant_id = var.tenant_id
  tags      = module.naming.tags

  control_plane_egress_cidrs = var.control_plane_egress_cidrs

  # Dev deliberately differs from production on both of these, and the difference is the point:
  # a software-protected key and an unlocked immutability policy are fine for a PoC and provide
  # none of the guarantees the design depends on. Production is premium + Locked (M4-19, M2-2c).
  key_vault_sku            = "standard"
  audit_immutability_state = "Unlocked"
  audit_retention_days     = 7

  # Who hears about it when something happens to the CA vault or the audit anchors (M4-27). Empty
  # means no alert rules are created at all — see the variable for why that is the honest default.
  alert_email_receivers = var.alert_email_receivers
}

# Dev PoC stamp: single node, burstable SKU (docs/COST_MODEL.md §3), one region (D-04).
module "egress_stamp" {
  source = "../../modules/egress-stamp"

  environment           = "dev"
  region                = var.egress_region
  region_short          = module.naming.region_short[var.egress_region]
  prefix                = module.naming.prefix
  tags                  = module.naming.tags
  instance_count        = 1
  vm_sku                = "Standard_B2s"
  ingress_allowed_cidrs = var.ingress_allowed_cidrs
  corp_public_cidrs     = var.corp_public_cidrs
  admin_ssh_public_key  = var.admin_ssh_public_key
  node_image_version    = var.node_image_version

  # The committed Envoy configuration is injected here, so what is in git is what the node runs.
  # The module accepted custom_data all along and nothing ever passed it, which meant the VMSS
  # booted stock Ubuntu with no Mina software on it at all.
  custom_data = templatefile("${path.module}/../../../../egress-node/cloud-init.yaml.tftpl", {
    envoy_config      = file("${path.module}/../../../../egress-node/envoy/envoy-bootstrap.yaml")
    envoy_version     = var.envoy_version
    envoy_sha256      = var.envoy_sha256
    sidecar_region    = var.egress_region
    control_plane_url = var.control_plane_node_url
  })
}

# ARM operations against the subscription — including anything that would remove the audit anchors
# or the immutability policy protecting them (M4-26). Off unless enabled: it is subscription-wide,
# needs subscription-level rights, and many organisations already export the Activity Log centrally.
module "activity_log" {
  source = "../../modules/azure-activity-log"

  enabled                    = var.export_activity_log
  log_analytics_workspace_id = module.control_plane_azure.diagnostics_workspace_id
}
