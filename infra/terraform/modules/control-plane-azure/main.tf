# The only Azure resources the control plane still uses after ADR-0006.
#
# Four Trivy findings stand against this file, all below the HIGH/CRITICAL gate CI enforces. They
# are recorded here rather than suppressed, because "below the gate" is not the same as "considered
# and accepted", and this is the store that holds a regulator's audit anchors:
#
#   AZU-0014 (key expiration)  Not set, deliberately. The CA signing key has no rollover procedure
#                              yet (M4-2), so an expiry date would be a scheduled outage of session
#                              issuance rather than a control. It belongs with the rollover, not
#                              before it.
#   AZU-0057 (storage logging) A real gap, raised as M6-11. Reads of and write attempts against the
#                              audit anchors should themselves be logged. The check looks for the
#                              classic queue-service logging block, which does not fit a blob-only
#                              account, but its intent is right and currently unmet — and where the
#                              logs should go is a live question now that Wazuh is on premises.
#   AZU-0058 (geo-redundancy)  ZRS today. Moving to GRS replicates C1 audit data to the paired
#                              region, which is a data-residency decision for the owner (D-08
#                              approved specific regions) and not one this module should take.
#   AZU-0060 (customer-managed A defensible hardening step, since the vault is right here — but it
#             keys)            makes the audit store unreadable whenever the vault is unavailable,
#                              and adds a key whose own rotation then matters. Raised as M6-12 to be
#                              decided alongside M4-2 rather than adopted by default.
#
# Everything else — API, portal, SQL, service logs — runs on the FIAU Proxmox cluster. These two
# stay in Azure because they are the guarantees a general-purpose VM cannot provide (D-18): a
# signing key that never leaves a managed vault, and storage that can refuse to overwrite an audit
# anchor. The on-premises hosts reach both outbound with their Arc-enabled managed identity, so no
# credential is stored on premises either.

resource "azurerm_resource_group" "control" {
  name     = "rg-${var.prefix}-cp"
  location = var.location
  tags     = merge(var.tags, { "mina:plane" = "control" })
}

# ---------------------------------------------------------------------------------------------
# Key Vault: the internal CA signing key (SR-005, M2-2c)
# ---------------------------------------------------------------------------------------------

resource "azurerm_key_vault" "cp" {
  name                = "kv-${var.prefix}-cp"
  resource_group_name = azurerm_resource_group.control.name
  location            = azurerm_resource_group.control.location
  tenant_id           = var.tenant_id
  sku_name            = var.key_vault_sku

  # RBAC, not access policies: role assignments are auditable in the same place as every other
  # Azure permission, and the platform grants only the two roles it needs.
  rbac_authorization_enabled = true

  # The CA key is the root of trust for every session certificate. Losing it to a soft-delete purge
  # would invalidate every live session and every certificate ever issued.
  purge_protection_enabled   = true
  soft_delete_retention_days = var.soft_delete_retention_days

  public_network_access_enabled = true

  network_acls {
    # Deny by default; the on-premises control plane is admitted by source address. It reaches this
    # vault over the internet rather than a private endpoint, because after ADR-0006 it is not in
    # Azure and has no VNet to place one in.
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = var.control_plane_egress_cidrs
  }

  tags = merge(var.tags, { "mina:plane" = "control" })
}

# Created in the vault, so the private material is generated there and never exists in Terraform
# state or on any operator's machine. P-256 matches the curve the PKI issues with
# (Mina.ControlPlane.Pki uses ECDsa nistP256).
resource "azurerm_key_vault_key" "ca_signing" {
  name         = "mina-internal-ca"
  key_vault_id = azurerm_key_vault.cp.id
  key_type     = "EC"
  curve        = "P-256"
  key_opts     = ["sign", "verify"]

  tags = merge(var.tags, { "mina:purpose" = "internal-ca-signing" })
}

# ---------------------------------------------------------------------------------------------
# Immutable blob storage: audit export anchors (AC-013, D-18)
# ---------------------------------------------------------------------------------------------

resource "azurerm_storage_account" "audit" {
  name                = replace("st${var.prefix}audit", "-", "")
  resource_group_name = azurerm_resource_group.control.name
  location            = azurerm_resource_group.control.location

  account_tier             = "Standard"
  account_replication_type = "ZRS"
  account_kind             = "StorageV2"
  min_tls_version          = "TLS1_2"

  # A second, independent encryption pass at the infrastructure layer. Cheap, and it can only be set
  # when the account is created — enabling it later means recreating the account, which for a store
  # holding immutable audit anchors is exactly the operation you do not want to discover you need.
  infrastructure_encryption_enabled = true

  # Audit anchors have no reason to leave the tenant that owns them.
  cross_tenant_replication_enabled = false

  # Entra authentication only. A shared key would be a stored credential, which is the property
  # ARCHITECTURE §4 claims the platform does not have anywhere.
  shared_access_key_enabled       = false
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = true

  blob_properties {
    versioning_enabled = true
  }

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
    ip_rules       = var.control_plane_egress_cidrs
  }

  # WORM. `immutability_period_since_creation_in_days` is what makes an anchor an anchor: within
  # the window the blob cannot be overwritten or deleted by anyone, including the subscription
  # owner.
  #
  # `state` is the part that decides whether this is evidence or decoration. Unlocked can be
  # removed by the same administrator who would be tampering, so it proves nothing — it exists so a
  # dev environment can be torn down. Locked is irreversible and is what production requires; see
  # the variable's description and docs/adr/0006.
  immutability_policy {
    allow_protected_append_writes = false
    state                         = var.audit_immutability_state
    period_since_creation_in_days = var.audit_retention_days
  }

  tags = merge(var.tags, { "mina:plane" = "control", "mina:data-class" = "c1-audit" })
}

resource "azurerm_storage_container" "audit_exports" {
  name                  = "audit-exports"
  storage_account_id    = azurerm_storage_account.audit.id
  container_access_type = "private"
}
