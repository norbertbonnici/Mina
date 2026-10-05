# Everything here that describes the deployment site has no default. These are facts about your
# infrastructure, not preferences, and a wrong guess would either fail late or -- worse -- succeed
# against the wrong network.

variable "prefix" {
  description = "Name prefix, e.g. mina-dev."
  type        = string
}

variable "proxmox_node" {
  description = "Proxmox node the control-plane VMs are created on."
  type        = string
}

variable "datastore_id" {
  description = "Proxmox datastore for VM disks, e.g. local-lvm."
  type        = string
}

variable "snippet_datastore_id" {
  description = <<-EOT
    Datastore holding cloud-init snippets. Must have the "snippets" content type enabled in
    Proxmox (Datacenter > Storage > Edit > Content), which is off by default and is the usual
    first-run failure.
  EOT
  type        = string
}

variable "dmz_bridge" {
  description = "Linux bridge carrying the DMZ VLAN, e.g. vmbr1."
  type        = string
}

variable "dmz_vlan_id" {
  description = <<-EOT
    VLAN id of the DMZ segment. ADR-0006 constraint 2: the control plane sits in a dedicated DMZ
    VLAN, not on the corporate LAN, because one of its listeners is published to the internet and
    the segment must be firewalled from corp accordingly.
  EOT
  type        = number
}

variable "dmz_vlan_tagged" {
  description = <<-EOT
    Whether the guest NIC should 802.1Q-tag traffic with dmz_vlan_id. Proxmox's VLAN-aware bridges
    tag unconditionally when a vlan_id is set, which only matches a trunk port configured to expect
    that tag. Set false when the switch port instead carries dmz_vlan_id as its native/untagged
    VLAN -- tagging it anyway double-tags and the traffic goes nowhere, which looks identical to a
    dead link from the guest's side (boots fine, no DNS/apt/SSH, because nothing arrives at all).
  EOT
  type        = bool
  default     = true
}

variable "dmz_gateway" {
  description = "Default gateway on the DMZ VLAN."
  type        = string
}

variable "dns_servers" {
  description = "DNS servers for the control-plane VMs."
  type        = list(string)
}

variable "app_address" {
  description = <<-EOT
    DMZ address of the control-plane application host, in CIDR form (e.g. 10.20.30.11/24). This
    module no longer creates that host (see app-onprem-windows) -- it only uses this to tell the
    proxy's nginx config where to forward the node-facing listener.
  EOT
  type        = string
}

variable "proxy_address" {
  description = "DMZ address of the publishing reverse proxy, in CIDR form."
  type        = string
}

variable "corp_management_cidrs" {
  description = <<-EOT
    Corporate ranges permitted to reach the management listener and to administer these hosts.
    ADR-0006 constraint 1 keeps the portal, audit read and administrative endpoints off the
    published listener; this keeps them off the DMZ interface for everyone else as well.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.corp_management_cidrs) > 0
    error_message = "At least one corporate range is required, or the portal is unreachable by anyone."
  }
}

variable "public_hostname" {
  description = "Public DNS name the egress nodes reach the node-facing listener at."
  type        = string
}

variable "tunnel_connector_cidr" {
  description = <<-EOT
    Address (as a /32, or a range) of the reverse-tunnel connector -- e.g. a Cloudflare Tunnel
    connector -- that is the only thing allowed to reach the proxy's node-facing listener.
    Public TLS terminates at that connector's far end, not on this VM (ADR-0006 constraint 3 is
    still met; the certificate just isn't installed here). If you're terminating TLS on the proxy
    VM itself instead, this should be the internet at large ("0.0.0.0/0") and the proxy cloud-init
    template's nginx site needs its own certificate configuration to match.
  EOT
  type        = string
}

variable "node_listener_port" {
  description = "Port the control-plane API binds for the node-facing listener (Mina:Hosting:Listeners:NodePort)."
  type        = number
  default     = 8443
}

variable "management_listener_port" {
  description = "Port the control-plane API binds for the corporate listener (…:ManagementPort)."
  type        = number
  default     = 8444

  validation {
    condition     = var.management_listener_port != var.node_listener_port
    error_message = "The two listeners must bind different ports; one port would publish the management surface."
  }
}

variable "ssh_public_keys" {
  description = "Administrator SSH public keys for the control-plane VMs."
  type        = list(string)
}

variable "cloud_image_url" {
  description = <<-EOT
    Ubuntu 24.04 cloud image URL, pinned to a dated release rather than a moving one. AC-018 applies
    to the on-premises plane too since ADR-0006, so "current" is not an acceptable source.
    Example: https://cloud-images.ubuntu.com/releases/24.04/release-20250801/ubuntu-24.04-server-cloudimg-amd64.img
  EOT
  type        = string
}

variable "cloud_image_sha256" {
  description = "SHA-256 of the cloud image, from the SHA256SUMS file beside it in the release directory."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.cloud_image_sha256))
    error_message = "cloud_image_sha256 must be a 64-character lowercase hex digest."
  }
}

variable "tags" {
  description = "Tags applied to every VM."
  type        = list(string)
  default     = ["mina", "control-plane"]
}

# --- M4-14: rate limiting, source policy and monitoring on the published listener -------------

variable "real_ip_header" {
  description = <<-EOT
    Header the TLS-terminating front end (tunnel_connector_cidr) puts the original client address
    in. nginx trusts it from that address only (set_real_ip_from) and keys every rate limit, the
    source-prefix check and the access log on the recovered address -- otherwise every node in
    every region would share one limit bucket, the connector's own address. Cloudflare Tunnel sets
    CF-Connecting-IP; a self-run reverse proxy typically sets X-Real-IP or X-Forwarded-For.
  EOT
  type        = string
  default     = "CF-Connecting-IP"
}

variable "node_source_cidrs" {
  description = <<-EOT
    The egress stamps' NAT public prefixes (modules/egress-stamp output), i.e. the only addresses a
    genuine node request can come from. These are static and already known to the platform (D-07
    keeps them as reviewed tfvars). Every request is tagged known/unknown against this list in the
    access log, which is what the "source outside the stamps' NAT prefixes" alert reads. Empty
    disables the tagging (logged as "unconfigured", so the alert cannot fire falsely) and means
    enforce_node_source_cidrs cannot be true.
  EOT
  type        = list(string)
  default     = []
}

variable "enforce_node_source_cidrs" {
  description = <<-EOT
    When true, a request from outside node_source_cidrs is answered 403 by the proxy before it
    reaches the application. Off by default: the application already refuses anything without a
    valid node token, so this is defence in depth, and turning it on before every stamp's prefix is
    listed would take a region's nodes off the air. Turn it on once node_source_cidrs is complete
    and the access log has shown no unknown-source traffic for a while.
  EOT
  type        = bool
  default     = false

  validation {
    condition     = !var.enforce_node_source_cidrs || length(var.node_source_cidrs) > 0
    error_message = "enforce_node_source_cidrs requires a non-empty node_source_cidrs; enforcing an empty list would refuse every node."
  }
}

variable "node_rate_limit" {
  description = <<-EOT
    nginx limit_req/limit_conn sizing for the node-facing listener, answered 429 when exceeded.
    Keyed on the recovered client address (see real_ip_header). Every node in a stamp leaves
    through that stamp's NAT prefix, so one address is a whole stamp's worth of nodes, not one
    node. Steady state per node is about 0.2 requests/s (allowlist every 15 s, telemetry every
    10 s); the defaults allow a 16-node stamp with headroom and a burst large enough for a whole
    stamp re-imaging at once (certificate, first allowlist, refresh-on-miss) without a single 429.
    requests_per_second_total bounds the listener as a whole regardless of how many sources.
  EOT
  type = object({
    requests_per_second_per_source = optional(number, 10)
    burst_per_source               = optional(number, 50)
    requests_per_second_total      = optional(number, 50)
    burst_total                    = optional(number, 200)
    connections_per_source         = optional(number, 100)
  })
  default = {}

  validation {
    condition = alltrue([
      var.node_rate_limit.requests_per_second_per_source >= 1,
      var.node_rate_limit.burst_per_source >= 0,
      var.node_rate_limit.requests_per_second_total >= var.node_rate_limit.requests_per_second_per_source,
      var.node_rate_limit.burst_total >= var.node_rate_limit.burst_per_source,
      var.node_rate_limit.connections_per_source >= 1,
    ])
    error_message = "node_rate_limit: rates must be >= 1/s, bursts >= 0, and the total limits must be at least the per-source limits."
  }
}

variable "otlp_endpoint" {
  description = <<-EOT
    OTLP/gRPC endpoint of the SigNoz collector the proxy's own telemetry goes to, e.g.
    http://signoz-collector.internal:4317 (the same value the application uses for
    Mina:Observability:OtlpEndpoint). When set, a pinned OpenTelemetry Collector (contrib) is
    installed on the proxy host and ships nginx's stub_status metrics plus the node-listener access
    and error logs. null installs nothing and leaves the host's monitoring at "logs on disk" --
    a deliberate, visible gap, not a default to ship with.
  EOT
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.otlp_endpoint == null || can(regex("^https?://[^/]+:[0-9]+$", var.otlp_endpoint))
    error_message = "otlp_endpoint must be http(s)://host:port with no path, or null."
  }
}

variable "otelcol_version" {
  description = "OpenTelemetry Collector (contrib) release installed on the proxy when otlp_endpoint is set. Pinned; bump together with otelcol_sha256."
  type        = string
  default     = "0.162.0"
}

variable "otelcol_sha256" {
  description = <<-EOT
    SHA-256 of otelcol-contrib_<otelcol_version>_linux_amd64.deb, from the .deb.sha256 asset on
    the GitHub release. The download at first boot is refused if the digest does not match, the
    same discipline the egress node applies to its Envoy download.
  EOT
  type        = string
  default     = "0b2b37eeb83db8e19a5f9dfc60894d058c739384a226ac085e674561befaad44"

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.otelcol_sha256))
    error_message = "otelcol_sha256 must be a 64-character lowercase hex digest."
  }
}
