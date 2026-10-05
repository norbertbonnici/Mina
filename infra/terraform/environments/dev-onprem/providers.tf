# Deliberately empty. The provider reads PROXMOX_VE_ENDPOINT and PROXMOX_VE_API_TOKEN from the
# environment, verified against this provider version rather than assumed, so the API token never
# enters a variable, a tfvars file, or Terraform state. Putting it in a variable would place it in
# state even when marked sensitive.
#
#   export PROXMOX_VE_ENDPOINT="https://pve.example.internal:8006/"
#   export PROXMOX_VE_API_TOKEN="terraform@pve!mina=<uuid>"
#
# The "snippets" content type has no upload API, so the provider writes it over SFTP directly to
# the node instead. That needs its own SSH username -- verified empirically that it does NOT fall
# back to PROXMOX_VE_USERNAME the way ssh.username's schema description implies when api_token
# auth is in use, so it's set here explicitly rather than guessed at again via another env var.
# Not a secret: the key that makes this authenticate is PROXMOX_VE_SSH_PRIVATE_KEY (env var only).
provider "proxmox" {
  ssh {
    username = "root"
  }
}
