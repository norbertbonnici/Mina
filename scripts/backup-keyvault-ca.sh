#!/usr/bin/env bash
# Backs up the internal CA's material from Key Vault (RUNBOOKS.md, backup and restore summary).
#
# The CA signing key never leaves the vault; Key Vault's `key backup` returns an encrypted blob that
# only a vault in the same Azure subscription and geography can restore, which is the point: this
# is protection against the vault (or its key) being deleted past soft-delete/purge-protection
# recovery, not a copy of the key anyone can use. The CA certificate is a secret alongside it
# (mina-ca stores it; D-20). Both are backed up; neither is readable from the output.
#
# Usage: backup-keyvault-ca.sh <key-vault-uri> <output-dir> [key-name] [certificate-secret-name]
# Needs: az login as a principal with Key Vault Crypto Officer (key backup) and Secrets Officer
#        (secret backup) on the vault -- the same roles the deployer holds (environments/dev).
set -euo pipefail

vault_uri="${1:?key vault uri, e.g. https://mina-dev-cp-kv.vault.azure.net/}"
out_dir="${2:?output directory}"
key_name="${3:-mina-internal-ca}"
secret_name="${4:-mina-internal-ca-certificate}"

vault_name="$(printf '%s' "$vault_uri" | sed -E 's#^https?://([^./]+)\..*#\1#')"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out_dir"

key_out="$out_dir/$vault_name-$key_name-$stamp.keybackup"
secret_out="$out_dir/$vault_name-$secret_name-$stamp.secretbackup"

echo "==> key backup: $key_name from $vault_name"
az keyvault key backup --vault-name "$vault_name" --name "$key_name" --file "$key_out" --only-show-errors
echo "==> secret backup: $secret_name from $vault_name"
az keyvault secret backup --vault-name "$vault_name" --name "$secret_name" --file "$secret_out" --only-show-errors

chmod 0600 "$key_out" "$secret_out"
sha256sum "$key_out" "$secret_out" | tee -a "$out_dir/SHA256SUMS"
echo "==> done. Restore with: az keyvault key restore --vault-name <vault> --file $key_out ; az keyvault secret restore --vault-name <vault> --file $secret_out"
echo "    Restoring into a different vault needs the same subscription and geography; then point Mina:Pki:KeyVaultUri at it."
