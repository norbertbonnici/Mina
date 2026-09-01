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
  # none of the guarantees the design depends on. Production is premium + Locked (M6-6, M2-2c).
  key_vault_sku            = "standard"
  audit_immutability_state = "Unlocked"
  audit_retention_days     = 7
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
}
