#!/usr/bin/env bash
# Publishes Mina.ControlPlane.Api and (re)deploys it to a target host over SSH, under a hardened
# systemd unit. Framework-dependent, matching the only other publish precedent in this repo (the
# egress-node sidecar's Dockerfile) -- the target needs the ASP.NET Core runtime, installed here
# if missing.
#
# No production CA exists in code yet (backlog M2-2c) -- Mina:AllowDevelopmentFallbacks=true is
# not a convenience default here, it is the only way this process starts at all right now. That
# flag bypasses TWO things, not one: every session certificate comes from a CA that regenerates
# on every restart, AND -- unless SQL_CONNECTION_STRING is supplied below -- session, approval,
# telemetry and audit state is in-memory only and is wiped on every restart this script performs.
# ADR-0006 ("Configuration delivery becomes a security control") built the startup guard this
# flag opts out of specifically to stop a mistyped setting from silently producing exactly that
# shape of "production" control plane; this script does it deliberately, not by accident, and
# only because M4-18 (SQL Server + Arc onboarding) hasn't landed yet. Once it has, pass
# SQL_CONNECTION_STRING and re-run.
#
# The Mina.ManagementUi portal is deliberately NOT covered here: outside ASPNETCORE_ENVIRONMENT=
# Development it hard-refuses its dev sign-in bypass and requires a real Entra app registration
# (backlog M2-1, not done yet). Deploying it needs that decision made first, not a script default.
set -euo pipefail

TARGET_HOST="${TARGET_HOST:?Set TARGET_HOST, e.g. 10.20.40.91}"
TARGET_USER="${TARGET_USER:-mina-admin}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
NODE_PORT="${NODE_PORT:-8443}"
MANAGEMENT_PORT="${MANAGEMENT_PORT:-8444}"
SQL_CONNECTION_STRING="${SQL_CONNECTION_STRING:-}"

# NODE_PORT, MANAGEMENT_PORT and TARGET_USER are spliced into remote shell command strings below,
# and NODE_PORT/MANAGEMENT_PORT also into an unquoted heredoc; an unvalidated value in either spot
# is a remote-code-execution path into a sudo-capable account, not just a correctness footgun --
# found by adversarial review before this ever ran twice. Reject anything that isn't the plain
# shape each is supposed to be before it reaches either place.
[[ "$NODE_PORT" =~ ^[0-9]+$ ]] || { echo "NODE_PORT must be a plain integer, got: $NODE_PORT" >&2; exit 1; }
[[ "$MANAGEMENT_PORT" =~ ^[0-9]+$ ]] || { echo "MANAGEMENT_PORT must be a plain integer, got: $MANAGEMENT_PORT" >&2; exit 1; }
[[ "$TARGET_USER" =~ ^[a-zA-Z0-9_-]+$ ]] || { echo "TARGET_USER contains disallowed characters: $TARGET_USER" >&2; exit 1; }
[[ "$TARGET_HOST" =~ ^[a-zA-Z0-9.:-]+$ ]] || { echo "TARGET_HOST contains disallowed characters: $TARGET_HOST" >&2; exit 1; }
[[ "$SQL_CONNECTION_STRING" != *$'\n'* ]] || { echo "SQL_CONNECTION_STRING must not contain a newline" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBLISH_DIR="$(mktemp -d)"
trap 'rm -rf "$PUBLISH_DIR"' EXIT

ssh_cmd=(ssh -o BatchMode=yes -i "$SSH_KEY" "$TARGET_USER@$TARGET_HOST")
scp_cmd=(scp -o BatchMode=yes -i "$SSH_KEY" -q)

echo "==> Publishing Mina.ControlPlane.Api (linux-x64, framework-dependent)"
dotnet publish "$REPO_ROOT/control-plane/src/Mina.ControlPlane.Api/Mina.ControlPlane.Api.csproj" \
  -c Release -r linux-x64 --no-self-contained -o "$PUBLISH_DIR"

echo "==> Ensuring the ASP.NET Core runtime is installed on $TARGET_HOST"
"${ssh_cmd[@]}" 'command -v dotnet >/dev/null 2>&1 && dotnet --list-runtimes | grep -q "Microsoft.AspNetCore.App 10\."' || \
"${ssh_cmd[@]}" '
  set -e
  curl -sSL https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb -o /tmp/packages-microsoft-prod.deb
  sudo dpkg -i /tmp/packages-microsoft-prod.deb
  sudo apt-get update -qq
  sudo apt-get install -y aspnetcore-runtime-10.0
'

# Stop before touching any state, not after: this is also what makes the later "enable --now" a
# real start rather than a no-op on redeploy -- systemd's "start" on an already-running unit does
# nothing, the same trap that left the proxy VM silently serving nginx's stock config until this
# session tracked it down.
echo "==> Stopping mina-api (if running)"
"${ssh_cmd[@]}" 'sudo systemctl stop mina-api 2>/dev/null || true'

# Rebuild the directory from scratch rather than chown-then-overwrite: a non-recursive chown
# followed by an unprivileged scp only works the FIRST time -- on redeploy, files already owned
# by mina:mina (from the previous run's final chown -R below) can't be overwritten by the
# unprivileged scp user, aborting the script under set -e with the service already stopped. This
# also means a file removed from a later build never gets cleaned up between deploys otherwise.
echo "==> Rebuilding /opt/mina/api from a clean slate"
"${ssh_cmd[@]}" "sudo rm -rf /opt/mina/api && sudo mkdir -p /opt/mina/api && sudo chown $TARGET_USER:$TARGET_USER /opt/mina/api"
"${scp_cmd[@]}" -r "$PUBLISH_DIR"/. "$TARGET_USER@$TARGET_HOST:/opt/mina/api/"
"${ssh_cmd[@]}" 'sudo chown -R mina:mina /opt/mina/api && sudo chmod -R o-rwx /opt/mina/api'

echo "==> Ensuring the audit export directory exists (nothing else creates it yet)"
"${ssh_cmd[@]}" 'sudo install -d -m 0750 -o mina -g mina /var/lib/mina/audit-exports'

echo "==> Writing /etc/mina/api.env and the mina-api systemd unit"
CONNECTION_STRING_LINE=""
if [[ -n "$SQL_CONNECTION_STRING" ]]; then
  CONNECTION_STRING_LINE="ConnectionStrings__MinaDb=$SQL_CONNECTION_STRING"
fi
# tee, chown and chmod run as one remote command so the file is never left world-readable between
# separate SSH round-trips.
"${ssh_cmd[@]}" "sudo tee /etc/mina/api.env > /dev/null && sudo chown root:mina /etc/mina/api.env && sudo chmod 640 /etc/mina/api.env" <<ENVFILE
ASPNETCORE_ENVIRONMENT=Production
Mina__AllowDevelopmentFallbacks=true
Mina__Hosting__Listeners__NodePort=$NODE_PORT
Mina__Hosting__Listeners__ManagementPort=$MANAGEMENT_PORT
Mina__Hosting__DataProtectionKeyPath=/var/lib/mina/dataprotection-keys
Mina__Hosting__ForwardedProxyCount=1
Mina__Audit__ExportPath=/var/lib/mina/audit-exports
$CONNECTION_STRING_LINE
ENVFILE

"${ssh_cmd[@]}" "sudo tee /etc/systemd/system/mina-api.service > /dev/null" <<'UNIT'
[Unit]
Description=Mina control-plane API (dev-fallback mode -- no production CA exists yet, M2-2c)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/mina/api
ExecStart=/usr/bin/dotnet /opt/mina/api/Mina.ControlPlane.Api.dll
EnvironmentFile=/etc/mina/api.env
Restart=always
RestartSec=2
User=mina
Group=mina
UMask=0007
RuntimeDirectory=mina-api
RuntimeDirectoryMode=0750
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/mina

[Install]
WantedBy=multi-user.target
UNIT

echo "==> Starting mina-api"
"${ssh_cmd[@]}" 'sudo systemctl daemon-reload && sudo systemctl enable --now mina-api'

echo "==> Waiting for the node listener to come up"
for _ in $(seq 1 10); do
  if "${ssh_cmd[@]}" "curl -sf -o /dev/null http://localhost:$NODE_PORT/healthz"; then
    echo "mina-api is healthy on port $NODE_PORT"
    exit 0
  fi
  sleep 2
done
echo "mina-api did not become healthy within 20s -- check:" >&2
echo "  ssh -i $SSH_KEY $TARGET_USER@$TARGET_HOST sudo journalctl -u mina-api -n 50" >&2
exit 1
