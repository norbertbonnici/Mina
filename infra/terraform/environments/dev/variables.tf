variable "egress_region" {
  description = "Region for the dev PoC egress stamp (from the D-08 candidate list)."
  type        = string
  default     = "westeurope"

  validation {
    # D-08's approved EU launch regions, plus D-08a's dev/PoC-only addition -- nothing else
    # enforces this. Getting the region wrong is exactly the kind of thing CLAUDE.md requires a
    # human decision for ("changing the approved production region/public-IP strategy"), so a
    # typo or a copy-pasted unapproved region fails the plan instead of silently standing up a
    # stamp somewhere unapproved. spaincentral is dev/PoC-only, not a production candidate.
    condition = contains(
      ["westeurope", "northeurope", "germanywestcentral", "francecentral", "spaincentral"],
      var.egress_region
    )
    error_message = "egress_region must be one of D-08's approved launch regions (westeurope, northeurope, germanywestcentral, francecentral) or D-08a's dev/PoC-only spaincentral."
  }
}

variable "ingress_allowed_cidrs" {
  description = "Source CIDRs allowed to reach dev tunnel ingress (D-07 interim: admin/corp egress IPs)."
  type        = list(string)
}

variable "corp_public_cidrs" {
  description = "Organisation public CIDRs that egress nodes must never reach (AC-017)."
  type        = list(string)
  default     = []
}

variable "admin_ssh_public_key" {
  description = "SSH public key for dev egress-node administration."
  type        = string
}

variable "tenant_id" {
  description = "Entra tenant id that owns the control-plane Key Vault."
  type        = string
}

variable "control_plane_egress_cidrs" {
  description = <<-EOT
    Public source addresses the on-premises control plane reaches Azure from — the FIAU DMZ's
    egress addresses. The Key Vault and the audit storage account deny by default and admit only
    these. After ADR-0006 the control plane is not in Azure, so a private endpoint is not available.
  EOT
  type        = list(string)
}

variable "node_image_version" {
  description = "Exact Ubuntu 24.04 image version for the egress nodes (never \"latest\"; see the module variable)."
  type        = string
}

variable "envoy_version" {
  description = "Envoy release to install on the nodes, without the leading v."
  type        = string
  default     = "1.39.1"
}

variable "envoy_sha256" {
  description = <<-EOT
    SHA-256 of envoy-<version>-linux-x86_64 from the GitHub release. The node refuses to install a
    binary that does not match, so this pin is the supply-chain control for the process that
    terminates every analyst's research traffic (threat N7). Verify a new value against the release
    before changing it; do not copy it from anywhere but the release itself.
  EOT
  type        = string
  default     = "002c6e1c69ed0fa0ea381887247cadadfaec9481375fa8d8d2b1731eeabf40b8"

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.envoy_sha256))
    error_message = "envoy_sha256 must be a 64-character lowercase hex SHA-256 digest."
  }
}

variable "sidecar_version" {
  description = <<-EOT
    Opaque build identifier for the published Mina.EgressNode.Sidecar binary installed on the
    nodes -- e.g. a git short SHA. Never "latest"; same AC-018 discipline as node_image_version.
    Only used in the install script's log line -- sidecar_artifact_url and sidecar_sha256 are
    what actually pin the binary. Empty is valid (see sidecar_artifact_url) and means "not set".
  EOT
  type        = string
  default     = ""
}

variable "sidecar_sha256" {
  description = <<-EOT
    SHA-256 of the published Mina.EgressNode.Sidecar binary at sidecar_artifact_url. The node
    refuses to install a binary that does not match -- the same supply-chain control as
    envoy_sha256 (threat N7), for the process that decides which sessions get to tunnel at all
    (M4-11). Produced by scripts/publish-sidecar.sh, which prints it next to the binary it
    builds; verify against that output, not from anywhere else. Empty is valid and means "not
    set" -- see sidecar_artifact_url.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.sidecar_sha256 == "" || can(regex("^[0-9a-f]{64}$", var.sidecar_sha256))
    error_message = "sidecar_sha256 must be empty (not set) or a 64-character lowercase hex SHA-256 digest."
  }
}

variable "sidecar_artifact_url" {
  description = <<-EOT
    HTTPS URL the node downloads the published sidecar binary from. Unlike Envoy (a public,
    third-party GitHub release with a stable URL pattern to template a version into), this is
    Mina's own build output from scripts/publish-sidecar.sh, and where that output actually gets
    hosted for a booting node to reach is not decided yet (M4-29 items 2/3 -- managed-identity
    auth for the node -- are the natural place that decision lands, since the same IMDS-token
    mechanism could authenticate the artifact fetch too). Defaults to "" (not set): the install
    script treats an empty URL as "no publish pipeline wired up for this environment yet" and
    skips cleanly rather than failing the whole boot, the same way an empty node-token below
    makes the sidecar itself refuse to start rather than block Envoy from coming up.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.sidecar_artifact_url == "" || can(regex("^https://", var.sidecar_artifact_url))
    error_message = "sidecar_artifact_url must be empty (not set) or an https:// URL."
  }
}

variable "export_activity_log" {
  description = <<-EOT
    Export the subscription's Activity Log to the diagnostics workspace (M4-26). Needs rights at the
    subscription, not just the resource group.

    Leave false if the organisation already exports the Activity Log centrally — a central export to
    a workspace outside this subscription is strictly better than this one, because it does not
    share a blast radius with the resources it watches.
  EOT
  type        = bool
  default     = false
}

variable "alert_email_receivers" {
  description = <<-EOT
    Addresses notified when anything happens to the CA vault or the audit-anchor store. Leaving this
    empty creates no alert rules — deliberately, because an alert with no receiver looks like
    coverage and reaches nobody.

    These fire on your own Terraform applies too. That is intended.
  EOT
  type        = list(string)
  default     = []
}

variable "control_plane_node_url" {
  description = <<-EOT
    The node-facing control-plane endpoint the sidecar calls — the address ADR-0006 publishes from
    the FIAU DMZ, as an https:// URL. Required with no default (M4-17): since M4-11 the sidecar is
    what admits every tunnel, so a node that cannot reach this refuses all research browsing.
  EOT
  type        = string

  validation {
    condition     = can(regex("^https://", var.control_plane_node_url))
    error_message = "control_plane_node_url must be an https:// URL."
  }
}
