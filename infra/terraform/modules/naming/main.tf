# Naming and tagging convention shared by every Mina Terraform configuration.
# Tag keys follow docs/COST_MODEL.md §5.

locals {
  prefix = "${var.workload}-${var.environment}"

  base_tags = {
    "mina:workload"   = var.workload
    "mina:env"        = var.environment
    "mina:managed-by" = "terraform"
  }

  # Short codes for the launch-candidate EU regions (docs/PHASE0_DECISIONS.md D-08).
  region_short = {
    westeurope         = "weu"
    northeurope        = "neu"
    germanywestcentral = "gwc"
    francecentral      = "frc"
    swedencentral      = "sdc"
    spaincentral       = "spc" # dev/PoC-only, D-08a
  }
}
