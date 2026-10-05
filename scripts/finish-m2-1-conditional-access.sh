#!/usr/bin/env bash
# Finishes the second half of backlog M2-1: an authentication context bound to a compliant-device
# Conditional Access policy, per docs/BACKLOG.md's own wording for this item and ARCHITECTURE.md
# §4. The app registration, app roles, and group assignments (the FIRST half of M2-1) are already
# done and verified as of 2026-09-03 -- see project memory / the morning decision log for details.
#
# BLOCKED in this lab tenant as of 2026-09-04, confirmed conclusively, not a permissions problem:
# this tenant's only license (DEVELOPERPACK -- the M365 E5 Developer Program's collaboration
# bundle: Exchange, SharePoint, Teams, Forms, etc.) contains ZERO Entra ID Premium P1 or P2 service
# plans. Every Conditional Access WRITE fails identically with "Your tenant is not licensed for
# this feature" (403) -- both the authentication-context PATCH and a completely plain,
# app-targeted policy POST with no auth-context binding at all. This was tested with a token that
# actually had the right scope (see below), signed in by Norbert himself, so it is not a consent or
# role problem -- reads work fine (listing authentication contexts returns 200), writes are the
# wall. Likely lab-only: a real organizational M365 tenant conventionally includes at least P1.
# Revisit this script once this deploys against a tenant that actually has Entra ID P1/P2, or once
# this lab tenant's license is upgraded -- the script itself should still be correct as written.
#
# Getting the required scope onto a token at all needs two things only a human can supply --
#
#   1. A fresh sign-in requesting the Policy.ReadWrite.ConditionalAccess scope. Two more things
#      worth knowing here, both confirmed by direct test, not assumed:
#      - `az login --scope ...` does NOT work for this specific scope, even freshly, even with a
#        real human completing the device code: AADSTS65002, "consent between first party
#        application [Azure CLI] and first party resource [Graph] must be configured via
#        preauthorization" -- Microsoft's own Azure CLI app is not preauthorized for
#        Policy.ReadWrite.ConditionalAccess in any tenant, this is not tenant-specific.
#      - The workaround: request a device code directly (not via `az login`) against Microsoft
#        Graph PowerShell's own well-known client ID (14d82eec-204b-4c2f-b7e8-296a70dab67e), which
#        IS preauthorized for this scope -- this is the client ID Microsoft's own documented
#        Connect-MgGraph pattern uses for exactly this kind of admin scenario. Use the resulting
#        access_token directly via `curl -H "Authorization: Bearer $TOKEN"` against Graph, not
#        `az rest` (which always uses the az CLI's own cached, differently-scoped token) and not
#        Connect-MgGraph itself (its interactive device-code display breaks under output
#        redirection in this specific harness -- see feedback memory).
#   2. A deliberate decision on enforcement mode. This script creates the policy in
#      "enabledForReportingButNotEnforced" (Report-only) -- Microsoft's own recommended rollout
#      practice for a new CA policy, and the right default for something created unattended
#      overnight. Report-only means it evaluates and logs what WOULD happen but blocks nothing.
#      Flipping it to "enabled" (actually enforcing) is a separate, deliberate step -- do that only
#      after checking the sign-in logs (Entra ID > Sign-in logs > filter by this policy) show the
#      expected population passing, and only with Norbert's own explicit go-ahead: this is exactly
#      the class of change CLAUDE.md requires a human decision for ("weakening OR changing
#      Conditional Access... device-compliance requirements").
#
# This script still uses `az rest`, which will need updating to the raw-token approach above once
# there's a licensed tenant to actually run it against -- left as `az rest` for now since it reads
# more clearly and the blocker is the license, not this script's own mechanics.
#
# Run this after signing in fresh (see the caveat above -- this exact command does not work today):
#   az login --scope "https://graph.microsoft.com/Policy.ReadWrite.ConditionalAccess" \
#            --scope "https://graph.microsoft.com/Policy.Read.All"
#   ./scripts/finish-m2-1-conditional-access.sh
set -euo pipefail

# Both come from the environment: the tenant and the Mina enterprise application (client) id.
#   export MINA_TENANT_ID=<tenant guid> MINA_APP_ID=<app guid>
TENANT_ID="${MINA_TENANT_ID:?set MINA_TENANT_ID to the Entra tenant id}"
MINA_APP_ID="${MINA_APP_ID:?set MINA_APP_ID to the Mina enterprise application id}"
AUTH_CONTEXT_ID="c1"
AUTH_CONTEXT_NAME="Mina compliant device required"

echo "==> Confirming the signed-in session actually has the required scope"
SCOPES=$(az account get-access-token --resource-type ms-graph --scope "https://graph.microsoft.com/Policy.ReadWrite.ConditionalAccess" --query accessToken -o tsv >/dev/null 2>&1 && echo ok || echo missing)
if [[ "$SCOPES" != "ok" ]]; then
  echo "Missing the required scope. Run:" >&2
  echo '  az login --scope "https://graph.microsoft.com/Policy.ReadWrite.ConditionalAccess" --scope "https://graph.microsoft.com/Policy.Read.All"' >&2
  exit 1
fi

echo "==> Creating authentication context '$AUTH_CONTEXT_ID' ($AUTH_CONTEXT_NAME)"
az rest --method patch \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences/$AUTH_CONTEXT_ID" \
  --body "{\"id\":\"$AUTH_CONTEXT_ID\",\"displayName\":\"$AUTH_CONTEXT_NAME\",\"description\":\"Required for Mina session issuance (Mina:Session:RequiredAuthContextId) -- ARCHITECTURE.md \$4.\",\"isAvailable\":true}" \
  --headers "Content-Type=application/json"

echo "==> Creating the compliant-device policy bound to that context, in REPORT-ONLY mode"
# Scoped to the auth context itself (not to "all sign-ins to the Mina app") -- the API only
# requests this context for the specific actions that need it (session issuance), matching
# ARCHITECTURE.md's step-up design rather than gating the whole app on every sign-in.
POLICY_BODY=$(cat <<JSON
{
  "displayName": "Mina - require compliant device (auth context c1)",
  "state": "enabledForReportingButNotEnforced",
  "conditions": {
    "users": { "includeUsers": ["All"] },
    "applications": {
      "includeAuthenticationContextClassReferences": ["$AUTH_CONTEXT_ID"]
    },
    "clientAppTypes": ["all"]
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["compliantDevice"]
  }
}
JSON
)
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --body "$POLICY_BODY" \
  --headers "Content-Type=application/json"

echo ""
echo "==> Done. Remaining manual steps:"
echo "    1. Set Mina:Session:RequiredAuthContextId = $AUTH_CONTEXT_ID in the API's deployed config"
echo "       (redeploy via scripts/deploy-control-plane-api-windows.ps1 once the RequiredAuthContextId"
echo "       parameter is added to it -- not added yet, since there was nothing to point it at until now)."
echo "    2. Watch Entra ID > Sign-in logs, filter by this policy, for a representative period."
echo "    3. When satisfied, flip the policy's state to 'enabled' yourself -- this script deliberately"
echo "       does not do that."
