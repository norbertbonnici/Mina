# Deliberately empty. The provider reads PROXMOX_VE_ENDPOINT and PROXMOX_VE_API_TOKEN from the
# environment, verified against this provider version rather than assumed, so the API token never
# enters a variable, a tfvars file, or Terraform state. Putting it in a variable would place it in
# state even when marked sensitive.
#
#   export PROXMOX_VE_ENDPOINT="https://pve.fiau.local:8006/"
#   export PROXMOX_VE_API_TOKEN="terraform@pve!mina=<uuid>"
provider "proxmox" {}
