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
  # BLOCKED (2026-09-04): every mainstream VM family (B-series, D-series -- confirmed via the
  # Microsoft.Compute/skus API for Standard_B2s, Standard_B2ms and Standard_D2s_v5, in both
  # northeurope and germanywestcentral) reports "reasonCode: NotAvailableForSubscription" for
  # this subscription. Only exotic/expensive families (confidential-compute DC-series,
  # huge-memory M-series, HPC, GPU) come back unrestricted. Core quota itself is fine (0/4 vCPUs
  # used in the standard families) -- this is Azure's restricted-VM-SKU-access gate that some
  # subscription offer types (free trial / sponsorship credit) apply to abuse-prone cheap
  # families, not a capacity or quota problem, and not something a different SKU or region works
  # around. Unblocking it needs a support-ticket "Quota increase" request in the Azure Portal for
  # this subscription requesting access to a standard VM series (e.g. Bsv2 or Dsv5) -- see the
  # 2026-09-04 decision log. Left as Standard_B2ms (still blocked) rather than switched to an
  # available-but-wrong-class SKU, so the very next `terraform apply` after the ticket is granted
  # is the real, cost-appropriate test.
  vm_sku                = "Standard_B2ms"
  ingress_allowed_cidrs = var.ingress_allowed_cidrs
  corp_public_cidrs     = var.corp_public_cidrs
  admin_ssh_public_key  = var.admin_ssh_public_key
  node_image_version    = var.node_image_version

  # This subscription's hard quota in northeurope is 3 Standard IPv4 public IPs total (confirmed
  # via `az network list-usages`); the ingress LB's own public IP already claims 1 of those. The
  # module default (/30, 4 addresses, for production rotation headroom) would push the total to
  # 5. /31 is the smallest size Azure's Public IP Prefix accepts, landing exactly on the
  # remaining quota. Dev deliberately forgoes NAT rotation headroom here -- a PoC constraint on a
  # free-tier-shaped subscription, not a design change.
  nat_ip_prefix_length = 31

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
