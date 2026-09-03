module "naming" {
  source      = "../../modules/naming"
  environment = "dev"
}

# The on-premises control plane (ADR-0006): API, portal and SQL Server on the Proxmox cluster, in a
# dedicated DMZ VLAN, with the node-facing listener published by a proxy that has no configuration
# for anything else.
module "control_plane" {
  source = "../../modules/control-plane-onprem"

  prefix               = module.naming.prefix
  proxmox_node         = var.proxmox_node
  datastore_id         = var.datastore_id
  snippet_datastore_id = var.snippet_datastore_id

  dmz_bridge      = var.dmz_bridge
  dmz_vlan_id     = var.dmz_vlan_id
  dmz_vlan_tagged = var.dmz_vlan_tagged
  dmz_gateway     = var.dmz_gateway
  dns_servers     = var.dns_servers

  proxy_address = var.proxy_address
  app_address   = var.app_address
  sql_address   = var.sql_address

  corp_management_cidrs = var.corp_management_cidrs
  public_hostname       = var.public_hostname
  tunnel_connector_cidr = var.tunnel_connector_cidr
  ssh_public_keys       = var.ssh_public_keys

  cloud_image_url    = var.cloud_image_url
  cloud_image_sha256 = var.cloud_image_sha256
}
