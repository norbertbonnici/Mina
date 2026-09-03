#!/usr/bin/env bash
# Finishes the second half of backlog M2-1: an authentication context bound to a compliant-device
# Conditional Access policy, per docs/BACKLOG.md's own wording for this item and ARCHITECTURE.md
# §4. The app registration, app roles, and group assignments (the FIRST half of M2-1) are already
# done and verified as of 2026-09-03 -- see project memory / the morning decision log for details.
#
# NOT run automatically overnight, on purpose: this needs two things only a human can supply --
#
#   1. A fresh az CLI sign-in requesting the Policy.ReadWrite.ConditionalAccess scope. The
#      existing cached session (from this session's earlier device-code sign-ins) does not carry
#      this scope and Entra refuses to mint it silently (AADSTS65002 -- "consent... must be
#      configured via preauthorization"), confirmed by direct test.
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
# Run this after signing in fresh:
#   az login --scope "https://graph.microsoft.com/Policy.ReadWrite.ConditionalAccess" \
#            --scope "https://graph.microsoft.com/Policy.Read.All"
#   ./scripts/finish-m2-1-conditional-access.sh
set -euo pipefail

TENANT_ID="f5283c99-d8e0-4bf2-a2bf-42acb11846ee"
MINA_APP_ID="a7b459cd-032b-4adf-b52b-4c771a37b467"
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
