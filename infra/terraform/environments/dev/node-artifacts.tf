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
  # Not the audit storage account's ZRS: a single-region PoC build artifact isn't the anchor an
  # organisation needs to survive a datacenter loss, and re-publishing a lost build is a
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

  # Left enabled so the operator running scripts/publish-sidecar.sh from the organisation's network can still
  # upload; the firewall below is what makes that the *only* public path in. The node does not use
  # the public endpoint at all — it comes in over the private endpoint further down.
  public_network_access_enabled = true

  # This account was open to any network until 2026-09-06 (Trivy AZU-0012, CRITICAL). The comment
  # that stood here justified it with an empirical result from 2026-09-04 — IP allow-listing was
  # tried, the node got 403 AuthorizationFailure with the firewall on and 200 the moment it was
  # opened, and that was read as "storage network rules break Bearer-token (Entra) auth
  # specifically". That reading was wrong, and the correction is worth recording because the
  # observation itself was sound:
  #
  #   * 403 AuthorizationFailure is Microsoft's documented code for a request refused by the
  #     storage *firewall*. Its four documented causes are all network conditions. The RBAC failure
  #     is a different code, AuthorizationPermissionMismatch. So the 403 was the firewall working
  #     exactly as configured, and said nothing about the token.
  #   * The audit storage account in control-plane-azure disproves the theory on its own: it runs
  #     Entra-only (shared_access_key_enabled = false) behind default_action = "Deny" and works.
  #   * The real reason IP rules could not admit the node: storage IP network rules have no effect
  #     on requests originating in the same region as the account, and this account is created in
  #     var.egress_region — the same region as the VMSS reading from it. Same-region traffic never
  #     presents the NAT gateway's public address, so allow-listing it could not have worked no
  #     matter which addresses were used. (Secondary: ip_rules also rejects the /31 the dev NAT
  #     prefix uses, per the note in control-plane-azure/main.tf.)
  #
  # So the node is admitted by a private endpoint rather than an address, and the IP rule is left
  # to carry only the on-premises publisher, which is genuinely off-Azure and unaffected by the
  # same-region caveat — the same reason the audit account's IP rules work.
  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
    ip_rules       = local.artifact_publisher_ip_rules
  }

  tags = module.naming.tags
}

locals {
  # publish-sidecar.sh is run by an operator on the organisation's network, which is the same public egress
  # the on-premises control plane uses — so this reuses that value rather than adding a second copy
  # of one address that could drift out of step with it. trimsuffix for the same reason
  # control-plane-azure/main.tf does it: storage ip_rules rejects /32 and wants a bare address,
  # while other resource types want the CIDR.
  artifact_publisher_ip_rules = [for cidr in var.control_plane_egress_cidrs : trimsuffix(cidr, "/32")]
}

# How the node gets in now that the account denies the public internet. Private-endpoint traffic is
# exempt from storage network rules entirely — it arrives on the VNet's own address space, so there
# is no address to allow-list and the same-region caveat above does not apply.
#
# Deliberately NOT a Microsoft.Storage service endpoint on the stamp's subnet, which is the more
# obvious way to write a "VNet rule" and was the first thing considered. A service endpoint's route
# override applies to the entire Azure Storage service tag for the region and its pair — not just
# this account — and Microsoft documents that it switches the subnet's source addresses from public
# to private for all of it. Every analyst request to any Azure Storage endpoint would then leave
# over the Azure backbone instead of the NAT gateway, so those destinations would no longer see the
# approved egress prefix. That is the guarantee this whole platform exists to provide, so it is not
# a side effect worth accepting to satisfy a scanner. Private Link is scoped to this one account and
# leaves every other destination on the NAT path; Microsoft recommends it over service endpoints for
# this reason.
resource "azurerm_private_endpoint" "artifacts" {
  name                = "pe-${module.naming.prefix}-artifacts"
  resource_group_name = azurerm_resource_group.artifacts.name
  location            = azurerm_resource_group.artifacts.location

  # The stamp has a single subnet spanning its whole VNet CIDR, so there is no separate subnet to
  # put this in without re-addressing a live network. A private endpoint may share a subnet with
  # virtual machines; azurerm defaults private_endpoint_network_policies to Disabled, which is what
  # lets it work alongside the NSG already on this subnet.
  subnet_id = module.egress_stamp.nodes_subnet_id

  private_service_connection {
    name                           = "psc-artifacts-blob"
    private_connection_resource_id = azurerm_storage_account.artifacts.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "blob"
    private_dns_zone_ids = [azurerm_private_dns_zone.blob.id]
  }

  tags = module.naming.tags
}

# The private endpoint is inside the VNet, and the stamp's NSG denies all egress to RFC1918 at
# priority 110-113 (SR-004: research egress is for the public internet, and nothing in corporate
# address space is reachable from a node). That deny is correct and stays; it simply also covers the
# one private address the node now legitimately needs.
#
# Found the hard way on 2026-09-07, which is why this is written as narrowly as it is: applying the
# private endpoint without this rule took the dev node down. It resolved the account to 10.80.0.5
# exactly as intended, then could not connect, so `mina-install-sidecar.sh` failed its fetch
# (`curl: (28) ... after 135637 ms`), left no binary at /opt/mina, and mina-sidecar.service gave up
# after four restarts. Envoy stayed up and — correctly — refused every tunnel, because admission had
# nothing to ask. The node fails closed rather than open, but it is still a node that does nothing.
#
# One host, one port, above the denies and nothing else: not a hole in the RFC1918 rule but a single
# named exception to it, for an address that only exists because this configuration created it.
resource "azurerm_network_security_rule" "nodes_to_artifact_endpoint" {
  name                        = "allow-egress-artifact-private-endpoint"
  priority                    = 105
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "*"
  destination_address_prefix  = "${azurerm_private_endpoint.artifacts.private_service_connection[0].private_ip_address}/32"
  resource_group_name         = module.egress_stamp.resource_group_name
  network_security_group_name = module.egress_stamp.nodes_nsg_name
}

# Without this, the node would resolve the account's public name to its public address and be
# refused by the firewall. With it, <account>.blob.core.windows.net CNAMEs into this zone and
# resolves to the endpoint's private address for anything in the linked VNet.
#
# Only this account has a record here, so every other storage account still resolves publicly and
# analyst traffic to them is untouched. One useful consequence for the tunnel: an analyst who aims a
# CONNECT at this account's hostname now resolves it to private space, which the M4-10 nftables rule
# rejects — so the artifact store is unreachable through the research path by construction.
# These two carry no tags, unlike every other resource here, and the omission is deliberate. Azure
# accepts tags on a private DNS zone and its virtual network link, reports the update as succeeded,
# and stores nothing: both read back `tags: {}` immediately after an apply that Terraform recorded
# as having changed them. Measured 2026-09-07, and not an RG-wide policy — the private endpoint in
# this same resource group, created by the same apply, kept all three tags.
#
# Left in place they produced a perpetual diff: `terraform plan` proposed adding the tags on every
# run, for ever. That is worse than missing tags. A plan that is never clean cannot be used to
# detect drift, and the value of drift detection here is noticing an NSG rule or a storage firewall
# edited by hand — which is exactly the class of change this environment must not accumulate
# silently. Declaring what the platform demonstrably discards also claims an attribution that does
# not exist.
resource "azurerm_private_dns_zone" "blob" {
  name                = "privatelink.blob.core.windows.net"
  resource_group_name = azurerm_resource_group.artifacts.name
}

resource "azurerm_private_dns_zone_virtual_network_link" "blob" {
  name                  = "link-${module.naming.prefix}-egress"
  resource_group_name   = azurerm_resource_group.artifacts.name
  private_dns_zone_name = azurerm_private_dns_zone.blob.name
  virtual_network_id    = module.egress_stamp.vnet_id
  registration_enabled  = false
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
