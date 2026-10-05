module "naming" {
  source      = "../../modules/naming"
  environment = "dev"
}

# The on-premises control plane (ADR-0006): API and portal on the Proxmox cluster, in a dedicated
# DMZ VLAN, with the node-facing listener published by a proxy that has no configuration for
# anything else. SQL Server is a separate module (sql_server, below) -- Windows-hosted, not
# cloud-init-provisioned like these two; see that module's own header for why.
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

  corp_management_cidrs = var.corp_management_cidrs
  public_hostname       = var.public_hostname
  tunnel_connector_cidr = var.tunnel_connector_cidr
  ssh_public_keys       = var.ssh_public_keys

  cloud_image_url    = var.cloud_image_url
  cloud_image_sha256 = var.cloud_image_sha256

  # M4-14. Rate-limit sizing and the collector pin stay at the module defaults here.
  node_source_cidrs         = var.node_source_cidrs
  enforce_node_source_cidrs = var.enforce_node_source_cidrs
  otlp_endpoint             = var.otlp_endpoint
}

module "sql_server" {
  source = "../../modules/sql-onprem-windows"

  prefix         = module.naming.prefix
  proxmox_node   = var.proxmox_node
  datastore_id   = var.datastore_id
  template_vm_id = var.windows_template_vm_id

  dmz_bridge      = var.dmz_bridge
  dmz_vlan_id     = var.dmz_vlan_id
  dmz_vlan_tagged = var.dmz_vlan_tagged
  dmz_gateway     = var.dmz_gateway
  dns_servers     = var.dns_servers

  sql_address = var.sql_address
  app_address = var.app_address

  corp_management_cidrs = var.corp_management_cidrs
}

# The application host: Windows under IIS, not Linux under systemd (see app-onprem-windows's own
# header for why this moved off the control_plane module above). Cloned from the same template as
# sql_server.
module "app_server" {
  source = "../../modules/app-onprem-windows"

  prefix         = module.naming.prefix
  proxmox_node   = var.proxmox_node
  datastore_id   = var.datastore_id
  template_vm_id = var.windows_template_vm_id

  dmz_bridge      = var.dmz_bridge
  dmz_vlan_id     = var.dmz_vlan_id
  dmz_vlan_tagged = var.dmz_vlan_tagged
  dmz_gateway     = var.dmz_gateway
  dns_servers     = var.dns_servers

  app_address   = var.app_address
  proxy_address = var.proxy_address

  corp_management_cidrs = var.corp_management_cidrs
}
