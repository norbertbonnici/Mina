# M4-29 item 3: the Mina.Node / Mina.Node.<region> app-role assignment procedure for the egress
# VMSS's managed identity -- the last of the three things M4-11's Envoy config needs before any
# node can actually admit a tunnel (items 1 and 2 are done; see BACKLOG.md).
#
# Genuinely new ground for this repo: no Terraform anywhere manages the "Mina" Entra app
# registration itself (created out-of-band during M2-1, appId supplied via var.mina_app_client_id
# -- see that variable). Everything below is deliberately additive rather than an import of the
# whole application under Terraform management: a plain azuread_application resource enforces its
# *entire* app_role list as one block, so bringing the existing application under it here would
# mean either replicating M2-1's sign-in configuration, redirect URIs and federated identity
# credential exactly (real risk of a mistake breaking production sign-in) or accepting that this
# apply could silently remove the three roles M2-1 already created. azuread_application_app_role
# and azuread_app_role_assignment are both standalone resources for exactly this reason: this
# environment touches only what M4-29 actually owns -- the node roles -- and nothing else about
# the application.
#
# ADR-0006 constraint 4 / SECURITY_REVIEW_2026-09-01 finding 7: "a bare node role is entitled to
# nothing." Confirmed in the control-plane code, not just the docs: NodeEndpoints.NodePolicy
# (control-plane/src/Mina.ControlPlane.Api/Sessions/NodeEndpoints.cs) requires the literal
# Mina.Node role via ASP.NET Core's RequireRole (exact string match) just to enter the
# /api/nodes route group at all; NodeRegionGrant
# (control-plane/src/Mina.ControlPlane.Application/Telemetry/NodeRegionGrant.cs) separately
# requires a Mina.Node.<region> role, checked per request inside each handler, before it returns
# anything for that region. Both checks are real and independent -- a node needs both roles
# assigned, not one or the other.

data "azuread_application" "mina" {
  client_id = var.mina_app_client_id
}

data "azuread_service_principal" "mina" {
  client_id = var.mina_app_client_id
}

locals {
  # D-08's four production-candidate regions plus D-08a's dev/PoC-only addition
  # (docs/PHASE0_DECISIONS.md) -- the same list environments/dev/variables.tf's egress_region
  # validation enforces. Role DEFINITIONS are pre-declared for the full set regardless of which
  # regions have an active stamp today: an app role with no assignment grants nothing, so this is
  # cheap and avoids a second Entra-mutating apply every time a new region's stamp goes live. Role
  # ASSIGNMENT (below) is scoped to var.egress_region only -- least privilege for what this
  # environment's actual node needs, not the full catalog.
  node_regions = ["westeurope", "northeurope", "germanywestcentral", "francecentral", "spaincentral"]
}

# Entra app roles are identified by an arbitrary UUID chosen once at creation, not derived from
# the role name -- random_uuid generates it and Terraform state keeps it stable across applies.
# Changing role_id later forces replacement (a new role with a new identity, per the provider's
# own schema), which would silently invalidate every previously-issued token claiming the old one
# -- do not taint or regenerate these once real tokens exist that carry them.
resource "random_uuid" "node_role" {}

resource "random_uuid" "node_region_role" {
  for_each = toset(local.node_regions)
}

resource "azuread_application_app_role" "node" {
  application_id       = data.azuread_application.mina.id
  role_id              = random_uuid.node_role.result
  allowed_member_types = ["Application"]
  display_name         = "Mina Node"
  description          = "Egress node identity. Grants entry to /api/nodes; grants no region on its own (see NodeRegionGrant)."
  value                = "Mina.Node"
}

resource "azuread_application_app_role" "node_region" {
  for_each = toset(local.node_regions)

  application_id       = data.azuread_application.mina.id
  role_id              = random_uuid.node_region_role[each.key].result
  allowed_member_types = ["Application"]
  display_name         = "Mina Node - ${each.key}"
  description          = "Region grant for egress nodes in ${each.key} (NodeRegionGrant). Meaningless without the Mina.Node role too."
  value                = "Mina.Node.${each.key}"
}

# The VMSS's own system-assigned identity: one shared principal for the whole scale set
# regardless of instance count (Uniform orchestration mode, the only mode
# azurerm_linux_virtual_machine_scale_set supports) -- every instance presents this same identity
# to IMDS, so one assignment covers the whole stamp, not one per instance.
resource "azuread_app_role_assignment" "node" {
  app_role_id         = azuread_application_app_role.node.role_id
  principal_object_id = module.egress_stamp.vmss_principal_id
  resource_object_id  = data.azuread_service_principal.mina.object_id
}

resource "azuread_app_role_assignment" "node_region" {
  app_role_id         = azuread_application_app_role.node_region[var.egress_region].role_id
  principal_object_id = module.egress_stamp.vmss_principal_id
  resource_object_id  = data.azuread_service_principal.mina.object_id
}
