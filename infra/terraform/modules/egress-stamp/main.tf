# Egress stamp — one per approved region (ARCHITECTURE §3.3, §8).
# Ingress: public Standard LB (:443) → Envoy VMSS. Egress: NAT Gateway with a static public
# IP prefix, deliberately distinct from the ingress IP. Network invariants (ARCHITECTURE §11):
# no unauthenticated listener beyond 443 (Envoy itself enforces mTLS, M1-2), no route to
# corporate/private space, all exposure choices explicit inputs.

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

locals {
  stamp_name = "${var.prefix}-egress-${var.region_short}"

  tags = merge(var.tags, {
    "mina:plane"  = "egress"
    "mina:region" = var.region
  })

  # cidr => priority offset, stable ordering for NSG deny rules.
  denied_cidrs = { for i, cidr in concat(var.denied_egress_cidrs, var.corp_public_cidrs) : cidr => i }
}

resource "azurerm_resource_group" "stamp" {
  name     = "rg-${local.stamp_name}"
  location = var.region
  tags     = local.tags
}

# --- Network -------------------------------------------------------------------------------

resource "azurerm_virtual_network" "stamp" {
  name                = "vnet-${local.stamp_name}"
  location            = azurerm_resource_group.stamp.location
  resource_group_name = azurerm_resource_group.stamp.name
  address_space       = [var.vnet_cidr]
  tags                = local.tags
}

resource "azurerm_subnet" "nodes" {
  name                 = "snet-nodes"
  resource_group_name  = azurerm_resource_group.stamp.name
  virtual_network_name = azurerm_virtual_network.stamp.name
  address_prefixes     = [var.vnet_cidr]
}

resource "azurerm_network_security_group" "nodes" {
  name                = "nsg-${local.stamp_name}"
  location            = azurerm_resource_group.stamp.location
  resource_group_name = azurerm_resource_group.stamp.name
  tags                = local.tags
}

resource "azurerm_subnet_network_security_group_association" "nodes" {
  subnet_id                 = azurerm_subnet.nodes.id
  network_security_group_id = azurerm_network_security_group.nodes.id
}

# Inbound: tunnel ingress from approved sources plus Azure LB health probes; nothing else.
resource "azurerm_network_security_rule" "in_allow_ingress" {
  name                        = "allow-tunnel-ingress"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = tostring(var.backend_port)
  source_address_prefixes     = var.ingress_allowed_cidrs
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.stamp.name
  network_security_group_name = azurerm_network_security_group.nodes.name
}

resource "azurerm_network_security_rule" "in_allow_azure_lb" {
  name                        = "allow-azure-lb-probes"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "AzureLoadBalancer"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.stamp.name
  network_security_group_name = azurerm_network_security_group.nodes.name
}

resource "azurerm_network_security_rule" "in_deny_all" {
  name                        = "deny-all-inbound"
  priority                    = 4000
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.stamp.name
  network_security_group_name = azurerm_network_security_group.nodes.name
}

# Outbound: deny corporate/private space first (SR-001, AC-017), then allow the narrow set
# research egress and node upkeep need, then deny everything else.
resource "azurerm_network_security_rule" "out_deny_corp" {
  for_each = local.denied_cidrs

  name                        = "deny-egress-${replace(replace(each.key, "/", "-"), ".", "-")}"
  priority                    = 110 + each.value
  direction                   = "Outbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = each.key
  resource_group_name         = azurerm_resource_group.stamp.name
  network_security_group_name = azurerm_network_security_group.nodes.name
}

resource "azurerm_network_security_rule" "out_allow_web" {
  name                        = "allow-web-egress"
  priority                    = 900
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["80", "443"]
  source_address_prefix       = "*"
  destination_address_prefix  = "Internet"
  resource_group_name         = azurerm_resource_group.stamp.name
  network_security_group_name = azurerm_network_security_group.nodes.name
}

resource "azurerm_network_security_rule" "out_allow_dns" {
  name                        = "allow-dns-egress"
  priority                    = 910
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "53"
  source_address_prefix       = "*"
  destination_address_prefix  = "Internet"
  resource_group_name         = azurerm_resource_group.stamp.name
  network_security_group_name = azurerm_network_security_group.nodes.name
}

resource "azurerm_network_security_rule" "out_allow_ntp" {
  name                        = "allow-ntp-egress"
  priority                    = 920
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Udp"
  source_port_range           = "*"
  destination_port_range      = "123"
  source_address_prefix       = "*"
  destination_address_prefix  = "Internet"
  resource_group_name         = azurerm_resource_group.stamp.name
  network_security_group_name = azurerm_network_security_group.nodes.name
}

resource "azurerm_network_security_rule" "out_deny_all" {
  name                        = "deny-all-outbound"
  priority                    = 4000
  direction                   = "Outbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.stamp.name
  network_security_group_name = azurerm_network_security_group.nodes.name
}

# --- Egress identity: NAT Gateway with static public prefix -------------------------------

resource "azurerm_public_ip_prefix" "egress" {
  name                = "ippre-${local.stamp_name}"
  location            = azurerm_resource_group.stamp.location
  resource_group_name = azurerm_resource_group.stamp.name
  prefix_length       = var.nat_ip_prefix_length
  ip_version          = "IPv4"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_nat_gateway" "egress" {
  name                    = "natgw-${local.stamp_name}"
  location                = azurerm_resource_group.stamp.location
  resource_group_name     = azurerm_resource_group.stamp.name
  sku_name                = "Standard"
  idle_timeout_in_minutes = 4
  tags                    = local.tags
}

resource "azurerm_nat_gateway_public_ip_prefix_association" "egress" {
  nat_gateway_id      = azurerm_nat_gateway.egress.id
  public_ip_prefix_id = azurerm_public_ip_prefix.egress.id
}

resource "azurerm_subnet_nat_gateway_association" "nodes" {
  subnet_id      = azurerm_subnet.nodes.id
  nat_gateway_id = azurerm_nat_gateway.egress.id
}

# --- Ingress: public Standard LB ----------------------------------------------------------

resource "azurerm_public_ip" "ingress" {
  name                = "pip-${local.stamp_name}-ingress"
  location            = azurerm_resource_group.stamp.location
  resource_group_name = azurerm_resource_group.stamp.name
  allocation_method   = "Static"
  sku                 = "Standard"
  ip_version          = "IPv4"
  tags                = local.tags
}

resource "azurerm_lb" "ingress" {
  name                = "lb-${local.stamp_name}"
  location            = azurerm_resource_group.stamp.location
  resource_group_name = azurerm_resource_group.stamp.name
  sku                 = "Standard"
  tags                = local.tags

  frontend_ip_configuration {
    name                 = "ingress"
    public_ip_address_id = azurerm_public_ip.ingress.id
  }
}

resource "azurerm_lb_backend_address_pool" "nodes" {
  name            = "envoy-nodes"
  loadbalancer_id = azurerm_lb.ingress.id
}

resource "azurerm_lb_probe" "envoy" {
  name            = "envoy-tcp"
  loadbalancer_id = azurerm_lb.ingress.id
  protocol        = "Tcp"
  port            = var.backend_port
}

resource "azurerm_lb_rule" "tunnel" {
  name                           = "tunnel-ingress"
  loadbalancer_id                = azurerm_lb.ingress.id
  protocol                       = "Tcp"
  frontend_port                  = var.ingress_port
  backend_port                   = var.backend_port
  frontend_ip_configuration_name = "ingress"
  backend_address_pool_ids       = [azurerm_lb_backend_address_pool.nodes.id]
  probe_id                       = azurerm_lb_probe.envoy.id
  disable_outbound_snat          = true # egress goes via NAT Gateway only
}

# --- Envoy nodes --------------------------------------------------------------------------

resource "azurerm_linux_virtual_machine_scale_set" "nodes" {
  name                            = "vmss-${local.stamp_name}"
  location                        = azurerm_resource_group.stamp.location
  resource_group_name             = azurerm_resource_group.stamp.name
  sku                             = var.vm_sku
  instances                       = var.instance_count
  admin_username                  = var.admin_username
  disable_password_authentication = true
  upgrade_mode                    = "Manual"
  zones                           = var.zones
  custom_data                     = var.custom_data == null ? null : base64encode(var.custom_data)
  tags                            = local.tags

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.admin_ssh_public_key
  }

  # Hardened image + Envoy bootstrap arrive with M1-2; until then a stock LTS base boots and
  # fails the LB probe, which is the correct fail-closed default.
  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  network_interface {
    name    = "nic-primary"
    primary = true

    ip_configuration {
      name                                   = "primary"
      primary                                = true
      subnet_id                              = azurerm_subnet.nodes.id
      load_balancer_backend_address_pool_ids = [azurerm_lb_backend_address_pool.nodes.id]
    }
  }

  # Managed identity for the node sidecar: scoped API access only (ARCHITECTURE §3.3).
  identity {
    type = "SystemAssigned"
  }

  boot_diagnostics {} # managed storage account
}
