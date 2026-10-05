#!/usr/bin/env bash
# Stamp rebuild drill (RUNBOOKS.md, drills; AC-018): recreate an egress stamp's node scale set from
# IaC in a NON-PRODUCTION environment and prove the result still demands a client certificate.
#
# Destructive by design -- it replaces every node in the stamp -- so it plans first, prints the
# plan, and applies only when the operator types the exact confirmation phrase. It never runs
# against an environment whose directory name contains "prod".
#
# Usage: drill-stamp-rebuild.sh <environment-dir> [module-address]
#   environment-dir  e.g. infra/terraform/environments/dev
#   module-address   default module.egress_stamp
# Needs: terraform, openssl, an authenticated az CLI for the backend and provider.
set -euo pipefail

env_dir="${1:?environment directory, e.g. infra/terraform/environments/dev}"
module_address="${2:-module.egress_stamp}"
vmss_address="$module_address.azurerm_linux_virtual_machine_scale_set.nodes"

case "$env_dir" in
  *prod*) echo "refusing: '$env_dir' looks like production. Drills run in dev/test only." >&2; exit 2 ;;
esac

cd "$env_dir"
echo "==> terraform plan -replace=$vmss_address"
terraform plan -input=false -replace="$vmss_address" -out=drill.tfplan
echo
read -r -p "Type 'rebuild the stamp' to apply this plan (anything else aborts): " answer
if [ "$answer" != "rebuild the stamp" ]; then
  echo "aborted; drill.tfplan left for inspection"; exit 1
fi

started="$(date -u +%s)"
terraform apply -input=false drill.tfplan
rm -f drill.tfplan

ingress_ip="$(terraform output -raw ingress_public_ip)"
echo "==> waiting for the rebuilt stamp to answer at $ingress_ip:443"
deadline=$(( $(date -u +%s) + 900 ))
while :; do
  # A TLS handshake with no client certificate must FAIL (AC-016: the node demands one). The probe
  # therefore succeeds when openssl reports a handshake alert, and keeps waiting while nothing is
  # listening at all.
  if out="$(echo | timeout 10 openssl s_client -connect "$ingress_ip:443" -servername egress.mina 2>&1)"; then
    :
  fi
  if printf '%s' "$out" | grep -qiE "certificate required|handshake failure|alert"; then
    echo "==> node answered and refused an uncertificated client (expected)"; break
  fi
  if [ "$(date -u +%s)" -ge "$deadline" ]; then
    echo "FAILED: no refusing node at $ingress_ip:443 within 15 minutes" >&2; exit 1
  fi
  sleep 15
done

elapsed=$(( $(date -u +%s) - started ))
echo
echo "Stamp rebuilt in ${elapsed}s. Finish the drill by hand (RUNBOOKS.md, drills):"
echo "  1. a lab endpoint starts a session in this region and browsing works;"
echo "  2. the control plane records that session's telemetry (mina_telemetry_items_total{outcome=\"recorded\"});"
echo "  3. an echo canary shows an address inside: $(terraform output -raw egress_ip_prefix)"
echo "File the elapsed time and these three results with the release evidence (AC-019)."
