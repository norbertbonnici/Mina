module "naming" {
  source      = "../../modules/naming"
  environment = "dev"
}

# Control-plane resources land here from M2-2 onward (App Service, SQL, Key Vault, …).
resource "azurerm_resource_group" "core" {
  name     = "rg-${module.naming.prefix}-core"
  location = var.egress_region
  tags     = merge(module.naming.tags, { "mina:plane" = "control" })
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
