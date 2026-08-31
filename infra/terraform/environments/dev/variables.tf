variable "egress_region" {
  description = "Region for the dev PoC egress stamp (from the D-08 candidate list)."
  type        = string
  default     = "westeurope"
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
