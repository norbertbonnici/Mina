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
#   AZU-0057 (storage logging) Closed by the diagnostic settings below. The check looks for the
#                              classic queue-service logging block, which does not fit a blob-only
#                              account, so it still reports — but its intent is met: reads, writes
#                              and deletes against the anchors now land in Log Analytics.
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

# ---------------------------------------------------------------------------------------------
# Diagnostics (M6-11)
# ---------------------------------------------------------------------------------------------
#
# Two resources hold the only things the platform keeps in Azure, and until now neither recorded
# who touched them. That matters more here than the usual "enable logging" hygiene:
#
#   - The Key Vault holds the CA signing key. Every session certificate the platform issues is a
#     signature by that key, and an attacker who can sign with it can mint a session certificate
#     for any analyst. AuditEvent is the only place that use is visible; without it, an unexpected
#     signature leaves no trace anywhere.
#   - The storage account holds the audit anchors, which exist to make tampering with the chain
#     detectable. A delete attempt refused by the immutability policy is precisely the signal the
#     anchoring design is built to produce, and it was being discarded.
#
# ARCHITECTURE §11 already required a Log Analytics workspace for "Entra/Azure activity export for
# break-glass alerting", and COST_MODEL carries it. It survives ADR-0006 because these two
# resources did.

resource "azurerm_log_analytics_workspace" "cp" {
  name                = "log-${var.prefix}-cp"
  resource_group_name = azurerm_resource_group.control.name
  location            = azurerm_resource_group.control.location
  sku                 = "PerGB2018"
  retention_in_days   = var.diagnostics_retention_days

  # Entra authentication only, consistent with the storage account: a workspace key would be a
  # stored credential.
  local_authentication_enabled = false

  # These logs are evidence about the audit trail, so the cap that protects the bill must not
  # silently drop them. Left unset deliberately — see the variable.
  daily_quota_gb = var.diagnostics_daily_quota_gb

  tags = merge(var.tags, { "mina:plane" = "control", "mina:data-class" = "c1-audit" })
}

resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  name                       = "mina-ca-key-audit"
  target_resource_id         = azurerm_key_vault.cp.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.cp.id

  # Every access to the CA signing key, including the signatures the control plane itself makes.
  enabled_log {
    category_group = "audit"
  }
}

resource "azurerm_monitor_diagnostic_setting" "audit_blobs" {
  name = "mina-audit-anchor-access"

  # The blob service, not the account: StorageRead/Write/Delete are emitted per service.
  target_resource_id         = "${azurerm_storage_account.audit.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.cp.id

  enabled_log {
    category = "StorageRead"
  }

  enabled_log {
    category = "StorageWrite"
  }

  # The one that matters most. A delete refused by the immutability policy is what an attempt to
  # remove tamper evidence looks like from the outside.
  enabled_log {
    category = "StorageDelete"
  }
}
