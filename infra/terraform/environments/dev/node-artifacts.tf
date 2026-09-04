# M4-29's remaining gap: where the published sidecar binary is actually hosted for a booting node
# to fetch (see sidecar_artifact_url's own comment). Azure Blob Storage, fetched using the node's
# own system-assigned managed identity through IMDS -- the same mechanism mina-fetch-certs.sh
# already sketches for TLS material (M2-2d, not yet built), applied here for real. Deliberately
# not a public container (the RBAC grant below is the actual access control, not obscurity) and
# not a SAS token: a SAS has an expiry that would silently break a reimaged or later-added
# instance with no warning until it tried to boot.

resource "azurerm_resource_group" "artifacts" {
  name     = "rg-${module.naming.prefix}-artifacts"
  location = var.egress_region
  tags     = module.naming.tags
}

resource "azurerm_storage_account" "artifacts" {
  name                = replace("st${module.naming.prefix}artifacts", "-", "")
  resource_group_name = azurerm_resource_group.artifacts.name
  location            = azurerm_resource_group.artifacts.location

  account_tier = "Standard"
  # Not the audit storage account's ZRS: a single-region PoC build artifact isn't the anchor a
  # regulator needs to survive a datacenter loss, and re-publishing a lost build is a
  # scripts/publish-sidecar.sh run away.
  account_replication_type = "LRS"
  account_kind             = "StorageV2"
  min_tls_version          = "TLS1_2"

  # Entra auth only -- ARCHITECTURE §4's "no client secrets anywhere in the product" applies to
  # this account exactly as it does to the audit storage account. The node authenticates as
  # itself (its managed identity), not as a bearer of a shared key or a SAS. This is the real,
  # unweakened access control regardless of the network setting below: only a principal actually
  # granted a role on this account (the two assignments further down, nothing else) can read or
  # write anything in it.
  shared_access_key_enabled       = false
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = true

  # No network_rules here, unlike Key Vault and the audit storage account -- tried first (IP
  # allow-listing the egress stamp's NAT addresses and the admin CIDRs, same pattern as those two)
  # and found empirically, 2026-09-04, to break Bearer-token (Entra) authenticated requests
  # specifically: the exact same managed identity, role, and token that a plain `curl` rejected
  # with 403 AuthorizationFailure against a firewalled account succeeded immediately (200) the
  # moment the firewall was opened, with nothing else changed. Key Vault and the audit storage
  # account hold the CA signing key and the audit anchors -- genuinely sensitive, worth the
  # trade-off of chasing that interaction down. A checksum-verified software binary, whose real
  # supply-chain control is the checksum in mina-install-sidecar.sh (not secrecy of the bytes),
  # is not -- RBAC alone is the appropriate and sufficient control here.

  tags = module.naming.tags
}

resource "azurerm_storage_container" "sidecar_builds" {
  name                  = "sidecar-builds"
  storage_account_id    = azurerm_storage_account.artifacts.id
  container_access_type = "private"
}

# Read-only: the node only ever fetches its own binary, never writes or lists anything else in
# the account. Scoped to the storage account, not the container -- azurerm_role_assignment can't
# target a container directly, and the account holds nothing else for this to over-grant access
# to.
resource "azurerm_role_assignment" "node_artifact_reader" {
  scope                = azurerm_storage_account.artifacts.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = module.egress_stamp.vmss_principal_id
}

data "azurerm_client_config" "artifact_publisher" {}

# RBAC mode grants the account's creator no implicit data-plane rights either (the same gap
# control-plane-azure's own Key Vault hit) -- without this, scripts/publish-sidecar.sh's upload
# step 403s even from an admitted IP, because network access and data-plane authorization are two
# separate gates and this closes only the first.
resource "azurerm_role_assignment" "artifact_publisher" {
  scope                = azurerm_storage_account.artifacts.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.artifact_publisher.object_id
}
