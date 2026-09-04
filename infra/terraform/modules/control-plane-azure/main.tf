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
#                              and adds a key whose own rotation then matters. Raised as M4-25 to be
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

locals {
  # Key Vault's network_acls.ip_rules accepts a /32 CIDR directly. Storage Account's
  # network_rules.ip_rules does not -- Azure rejects /31 and /32 there specifically ("must start
  # with IPV4 address and/or slash, number of bits (0-30) as prefix"), wanting a bare address for
  # a single host instead. Same input, two resource types, two accepted shapes -- strip only the
  # /32 suffix (a genuine range like /24 is untouched) so one variable serves both correctly.
  storage_safe_control_plane_egress_cidrs = [
    for cidr in var.control_plane_egress_cidrs : trimsuffix(cidr, "/32")
  ]
}

# ---------------------------------------------------------------------------------------------
# Key Vault: the internal CA signing key (SR-005, M2-2c)
# ---------------------------------------------------------------------------------------------

resource "azurerm_key_vault" "cp" {
  # Region-qualified: see the region_short variable for why (globally-unique name, soft-delete
  # reserves it for up to 90 days after any teardown, purge protection makes early reuse
  # impossible even for an empty dev vault).
  name                = "kv-${var.prefix}-${var.region_short}-cp"
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

data "azurerm_client_config" "current" {}

# RBAC mode means the vault starts with no data-plane access at all, including for whoever is
# about to create a key in it -- unlike access-policy mode, there's no implicit "creator gets
# rights" behavior. Grants the identity running Terraform itself the role needed to create/manage
# keys; it does not grant the on-premises control plane's own Arc identity anything, because that
# consumer-side access is M2-2c's own scope (the Key-Vault-backed CA), not this apply's.
resource "azurerm_role_assignment" "deployer_crypto_officer" {
  scope                = azurerm_key_vault.cp.id
  role_definition_name = "Key Vault Crypto Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# The CA certificate lives beside the key as a secret, because Key Vault's own certificate objects
# are always end-entity (basic constraints cA=false) and so cannot be a CA certificate. Writing it
# is `mina-ca bootstrap`, run once by an operator with this identity — not by the control plane,
# which is deliberately given no way to mint itself a new root of trust.
resource "azurerm_role_assignment" "deployer_secrets_officer" {
  scope                = azurerm_key_vault.cp.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# The running control plane's own two roles: sign with the CA key, read the CA certificate. Neither
# lets it export the key (no role does — the key is not exportable) and neither lets it write the
# certificate, so re-rooting the platform stays an operator action. Created only once the hosts have
# an Arc identity to grant them to (M4-18).
resource "azurerm_role_assignment" "control_plane_crypto_user" {
  count = var.control_plane_principal_id == "" ? 0 : 1

  scope                = azurerm_key_vault.cp.id
  role_definition_name = "Key Vault Crypto User"
  principal_id         = var.control_plane_principal_id
}

resource "azurerm_role_assignment" "control_plane_secrets_user" {
  count = var.control_plane_principal_id == "" ? 0 : 1

  scope                = azurerm_key_vault.cp.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = var.control_plane_principal_id
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

  # RBAC role assignments take a short but real time to propagate; without this Terraform can
  # (and did, once) try to create the key before the grant above is actually enforceable yet.
  depends_on = [azurerm_role_assignment.deployer_crypto_officer]

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
    ip_rules       = local.storage_safe_control_plane_egress_cidrs
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

# The deployer's own access, same reasoning as deployer_secrets_officer above: Owner/Contributor at
# the subscription grants no data-plane access to blob content on its own (confirmed live,
# `az storage blob list --auth-mode login` against this account refuses without it) -- data actions
# need an explicit data-plane role, deliberately, since that separation is what shared_access_key_enabled
# = false is for. An operator inspecting or troubleshooting exports needs this the same way
# `mina-ca bootstrap` needs Secrets Officer.
resource "azurerm_role_assignment" "deployer_storage_blob_contributor" {
  scope                = azurerm_storage_container.audit_exports.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

# The running control plane's own access to the container: write new exports, read them back for
# anchor verification (AuditAnchorVerifier, M4-19). Scoped to the container rather than the whole
# storage account -- least privilege, same reasoning as the Key Vault role assignments above. This
# role does not grant delete; the immutability policy is what actually refuses that, for anyone,
# which is the point. Created only once the hosts have an Arc identity to grant it to (M4-18).
resource "azurerm_role_assignment" "control_plane_audit_writer" {
  count = var.control_plane_principal_id == "" ? 0 : 1

  scope                = azurerm_storage_container.audit_exports.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = var.control_plane_principal_id
}

# ---------------------------------------------------------------------------------------------
# Diagnostics (M4-24)
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

# ---------------------------------------------------------------------------------------------
# Alerting on destructive operations (M4-27)
# ---------------------------------------------------------------------------------------------
#
# Export is not detection. M4-26 puts ARM operations in a workspace; these raise a human when the
# operations are against the two resources that hold the platform's roots of trust.
#
# The criteria deliberately do NOT enumerate operation names. Naming
# Microsoft.KeyVault/vaults/delete and friends looks precise and creates a silent gap: any operation
# not on the list passes unnoticed, and a rule that never fires is indistinguishable from one with
# nothing to report. Instead each rule matches ANY Administrative operation on its resource. That is
# viable because these resources are supposed to be inert — Terraform creates them and nothing
# touches them again — so the alert is low-volume and high-signal, and it catches the operations
# nobody thought to enumerate.
#
# The corollary is that a Terraform apply against this module will raise these alerts. That is
# correct behaviour, not noise: a change to the vault holding the CA key or the store holding the
# audit anchors should be something a human sees, including when it is you.
#
# No status filter, on purpose. A *failed* delete against the audit anchors is the more interesting
# event of the two: it is what the immutability policy refusing an attempt looks like.

locals {
  alerting_enabled = length(var.alert_email_receivers) > 0 || var.alert_webhook_uri != null
}

resource "azurerm_monitor_action_group" "cp" {
  count = local.alerting_enabled ? 1 : 0

  name                = "ag-${var.prefix}-cp"
  resource_group_name = azurerm_resource_group.control.name
  short_name          = "minacp"

  dynamic "email_receiver" {
    for_each = { for idx, address in var.alert_email_receivers : idx => address }

    content {
      name                    = "email-${email_receiver.key}"
      email_address           = email_receiver.value
      use_common_alert_schema = true
    }
  }

  dynamic "webhook_receiver" {
    for_each = var.alert_webhook_uri == null ? [] : [var.alert_webhook_uri]

    content {
      name                    = "webhook"
      service_uri             = webhook_receiver.value
      use_common_alert_schema = true
    }
  }

  tags = merge(var.tags, { "mina:plane" = "control" })
}

resource "azurerm_monitor_activity_log_alert" "ca_key_vault" {
  count = local.alerting_enabled ? 1 : 0

  name                = "alert-${var.prefix}-ca-vault"
  resource_group_name = azurerm_resource_group.control.name
  location            = "global"
  scopes              = [azurerm_key_vault.cp.id]
  description         = "Any ARM operation against the vault holding the internal CA signing key."

  criteria {
    category    = "Administrative"
    resource_id = azurerm_key_vault.cp.id
  }

  action {
    action_group_id = azurerm_monitor_action_group.cp[0].id
  }

  tags = merge(var.tags, { "mina:plane" = "control" })
}

resource "azurerm_monitor_activity_log_alert" "audit_store" {
  count = local.alerting_enabled ? 1 : 0

  name                = "alert-${var.prefix}-audit-store"
  resource_group_name = azurerm_resource_group.control.name
  location            = "global"
  scopes              = [azurerm_storage_account.audit.id]
  description         = "Any ARM operation against the audit-anchor store, including refused deletes."

  criteria {
    category    = "Administrative"
    resource_id = azurerm_storage_account.audit.id
  }

  action {
    action_group_id = azurerm_monitor_action_group.cp[0].id
  }

  tags = merge(var.tags, { "mina:plane" = "control" })
}

# Privilege escalation is the step before the other two. Someone who cannot delete the audit store
# today grants themselves the role that lets them, and that grant is itself an ARM operation.
resource "azurerm_monitor_activity_log_alert" "role_assignments" {
  count = local.alerting_enabled ? 1 : 0

  name                = "alert-${var.prefix}-cp-role-changes"
  resource_group_name = azurerm_resource_group.control.name
  location            = "global"
  scopes              = [azurerm_resource_group.control.id]
  description         = "Role assignment changes in the control-plane resource group."

  criteria {
    category          = "Administrative"
    resource_group    = azurerm_resource_group.control.name
    resource_provider = "Microsoft.Authorization"
  }

  action {
    action_group_id = azurerm_monitor_action_group.cp[0].id
  }

  tags = merge(var.tags, { "mina:plane" = "control" })
}
