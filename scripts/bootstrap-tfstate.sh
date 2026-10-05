#!/usr/bin/env bash
# One-time per subscription: create the access-controlled storage for Terraform remote state
# (threat N6: versioned, Entra-auth, no shared-key access). Requires: az login + subscription set.
set -euo pipefail

# On Git Bash/MSYS, leading-slash args (e.g. --scope /subscriptions/...) get silently rewritten
# into a Windows path (C:/Program Files/Git/subscriptions/...) before az ever sees them, which
# turns the role assignment call below into a 404. No-op on Linux/macOS.
export MSYS_NO_PATHCONV=1

LOCATION="${LOCATION:-westeurope}"
RG="${RG:-rg-mina-tfstate}"
# Storage account names are 3-24 chars, lowercase alphanumeric, globally unique.
SA="${SA:-stminatfstate$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 8 || true)}"
CONTAINER="tfstate"

az group create --name "$RG" --location "$LOCATION" --tags mina:workload=mina mina:plane=tfstate -o none
az storage account create \
  --name "$SA" --resource-group "$RG" --location "$LOCATION" \
  --sku Standard_ZRS --kind StorageV2 \
  --min-tls-version TLS1_2 \
  --allow-blob-public-access false \
  --allow-shared-key-access false \
  -o none
az storage account blob-service-properties update \
  --account-name "$SA" --resource-group "$RG" \
  --enable-versioning true -o none
az storage container create \
  --name "$CONTAINER" --account-name "$SA" --auth-mode login -o none

ME="$(az ad signed-in-user show --query id -o tsv)"
SCOPE="$(az storage account show --name "$SA" --resource-group "$RG" --query id -o tsv)"
az role assignment create --assignee "$ME" --role "Storage Blob Data Contributor" --scope "$SCOPE" -o none

cat <<EOF

State storage ready. backend.hcl values:

resource_group_name  = "$RG"
storage_account_name = "$SA"
container_name       = "$CONTAINER"
key                  = "<env>.terraform.tfstate"
use_azuread_auth     = true
EOF
