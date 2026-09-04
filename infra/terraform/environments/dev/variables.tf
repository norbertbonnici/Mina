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

variable "mina_app_client_id" {
  description = <<-EOT
    Client (application) id of the single "Mina" Entra app registration the whole platform
    validates against (ARCHITECTURE §4) -- created out-of-band during M2-1, not by Terraform.
    Used only to look up that existing application/service principal (data sources) so
    entra-node-roles.tf can add the node app roles to it; this environment never creates or owns
    the application itself, and nothing here can accidentally modify its sign-in configuration,
    federated credential, or the three roles M2-1 already defined.
  EOT
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
    Mina's own build output from scripts/publish-sidecar.sh -- hosted in this environment's own
    private Azure Storage container (node-artifacts.tf's sidecar_builds container), fetched by
    the node's managed identity through IMDS, the same mechanism mina-fetch-certs.sh sketches for
    Key Vault. Not a SAS token or a public container on purpose: a SAS has an expiry that would
    silently break a reimaged or later-added instance, and this is a real binary a node's own
    supply chain depends on (THREAT_MODEL N7), not something to leave unauthenticated.

    Defaults to "" (not set): the install script treats an empty URL as "no artifact published
    for this environment yet" and skips cleanly rather than failing the whole boot, the same way
    an empty node-token below makes the sidecar itself refuse to start rather than block Envoy
    from coming up. Publishing a new build means: run scripts/publish-sidecar.sh, upload the
    result to the sidecar_builds container (`az storage blob upload --auth-mode login`, requires
    the Storage Blob Data Contributor role node-artifacts.tf grants the deploying principal), and
    update this variable together with sidecar_version/sidecar_sha256 to match -- the URL itself
    is a stable, overwritten-in-place blob path, so only the checksum actually changes per build.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.sidecar_artifact_url == "" || can(regex("^https://", var.sidecar_artifact_url))
    error_message = "sidecar_artifact_url must be empty (not set) or an https:// URL."
  }
}

variable "sidecar_managed_identity_scope" {
  description = <<-EOT
    The Entra scope the sidecar requests a token for using the VMSS's own system-assigned managed
    identity (M4-29 item 2), since the platform validates every caller (analysts and nodes alike)
    against one app registration's audience (ARCHITECTURE §4). Defaults to "" (not set): with no
    scope configured the sidecar falls back to a fixed development token instead, and that
    fallback itself refuses to start outside Development unless explicitly allowed -- there is no
    silent path to an unauthenticated node.

    Shape: "<mina_app_client_id>/.default", the bare client id -- NOT "api://<client id>/.default".
    Checked directly against this tenant (2026-09-04): the "Mina" app registration's
    identifierUris is empty, no custom Application ID URI was ever set, so an "api://" scope has
    nothing to resolve to. A bare client id is always a valid implicit identifier for an app's own
    app-only permissions regardless of whether identifierUris is populated, and
    Microsoft.Identity.Web's default audience validation (what the control plane uses) accepts a
    token whose `aud` is the bare client id -- this is the verified, not assumed, correct form for
    this specific tenant.

    Even with this set, the node still needs the Mina.Node and Mina.Node.<region> app roles
    actually assigned to its managed identity's service principal (M4-29 item 3, done 2026-09-04
    -- entra-node-roles.tf) -- and this variable alone is still not sufficient for a real token
    round trip: it has not been verified end to end against the live node, which has no SSH/Bastion
    path in to check from.
  EOT
  type        = string
  default     = ""
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
