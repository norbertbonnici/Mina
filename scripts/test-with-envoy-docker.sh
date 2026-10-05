#!/usr/bin/env bash
# Run the real-Envoy tests (skipped without MINA_ENVOY) inside a Linux container that has the
# pinned Envoy release alongside the .NET SDK. This is the same Envoy build the node runs, so what
# passes here is what the node does; a macOS Envoy from a third-party build would not be.
#
# Usage: scripts/test-with-envoy-docker.sh [dotnet test args...]
# Default test target: tests/integration/Mina.Transport.Tests
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENVOY_VERSION="${ENVOY_VERSION:-$(sed -n 's/.*default *= *"\([0-9.]*\)".*/\1/p' "$ROOT/infra/terraform/environments/dev/variables.tf" | head -1)}"
IMAGE="mina-envoy-test:${ENVOY_VERSION}"

# Build (cached) an image: .NET SDK + the pinned Envoy binary copied from the official image.
docker build -q -t "$IMAGE" - <<DOCKERFILE >/dev/null
FROM envoyproxy/envoy:v${ENVOY_VERSION} AS envoy
FROM mcr.microsoft.com/dotnet/sdk:10.0
COPY --from=envoy /usr/local/bin/envoy /usr/local/bin/envoy
DOCKERFILE

# The repo is mounted read-only and copied inside the container, minus build output, so the Linux
# build never touches the host's bin/obj and the host's never confuses it. The NuGet cache lives in
# a named volume so only the first run pays for the restore.
exec docker run --rm \
  -v "$ROOT:/mnt/src:ro" \
  -v mina-nuget-cache:/root/.nuget/packages \
  -e MINA_ENVOY=/usr/local/bin/envoy \
  -e DOTNET_CLI_TELEMETRY_OPTOUT=1 \
  -e DOTNET_NOLOGO=1 \
  "$IMAGE" \
  bash -c 'mkdir -p /src && tar -C /mnt/src --exclude=./.git --exclude=bin --exclude=obj --exclude=.docker-out -cf - . | tar -C /src -xf - && cd /src && dotnet test "$@" --nologo -v q --logger "console;verbosity=normal"' _ "${@:-tests/integration/Mina.Transport.Tests}"
