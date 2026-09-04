#!/usr/bin/env bash
# Build the egress-node sidecar exactly the way the nodes run it: self-contained, single-file,
# linux-x64 (M4-29 item 1). No demo shortcuts — Dockerfile.sidecar publishes framework-dependent
# for the test stack, but a real node has no .NET runtime installed and no package manager to get
# one from, matching Envoy's own single-static-binary footprint and this project's minimal-image
# posture (M4-10, AC-018).
#
# Usage: scripts/publish-sidecar.sh <version> [output-dir]
#   <version>     Opaque build identifier, e.g. a git short SHA or a date-based tag. Never
#                 "latest" -- same AC-018 discipline as node_image_version. Stamped into the
#                 output only for the summary this script prints; nothing embeds it in the binary.
#   [output-dir]  Defaults to dist/sidecar/<version>.
#
# Prints the published binary's path and SHA-256 at the end -- copy that digest into
# infra/terraform/environments/dev/variables.tf's sidecar_sha256 (or the equivalent prod var) by
# hand, the same "verify against the artifact itself" discipline envoy_sha256 already documents.
# This script does not publish the artifact anywhere reachable by a booting node -- see
# egress-node/cloud-init.yaml.tftpl's mina-install-sidecar.sh and the sidecar_artifact_url
# variable for what still needs a real hosting decision (M4-29 items 2/3 are close neighbours of
# that decision, not yet made).
#
# Restoring for -r linux-x64 would otherwise rewrite packages.lock.json for this project AND
# for any other project restored transitively in the same pass (seen with
# integrations/signoz/src/Mina.Observability, shared with the Windows endpoint agent) -- a
# single-RID restore replaces a project's existing RID section rather than adding one
# alongside it. The solution is restored RID-agnostically (CI runs `dotnet restore Mina.slnx
# --locked-mode`), so a stray net10.0/linux-x64 section breaks it with NU1004. The publish
# below therefore disables lock files: RestorePackagesWithLockFile=false on its own is refused
# with NU1005 while a lock file exists on disk, so NuGetLockFilePath additionally points the
# lock-file lookup at a path that does not exist. Nothing is read from or written to it, and
# every package version is pinned, so resolution is unchanged.
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: $0 <version> [output-dir]" >&2
  exit 1
fi

version="$1"
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
project="$repo_root/egress-node/src/Mina.EgressNode.Sidecar/Mina.EgressNode.Sidecar.csproj"
out="${2:-$repo_root/dist/sidecar/$version}"
expected_binary="Mina.EgressNode.Sidecar"

rm -rf "$out"
mkdir -p "$out"

LOCK_REDIRECT="$(mktemp -u)"
dotnet publish "$project" \
  -c Release \
  -r linux-x64 \
  -p:RestorePackagesWithLockFile=false -p:NuGetLockFilePath="$LOCK_REDIRECT" \
  --self-contained true \
  -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true \
  -o "$out"

binary="$out/$expected_binary"

# The publish target/RID above is exactly what makes this filename appear with no extension --
# the systemd unit's ExecStartPre/ExecStart (egress-node/cloud-init.yaml.tftpl) hard-codes this
# path, so a rename here breaks the node silently until the unit fails. Checking existence only,
# not the execute bit: a Linux ELF cross-published from a Windows build host has no meaningful
# exec bit until it actually lands on Linux, where mina-install-sidecar.sh's `install -m 0755`
# sets it explicitly regardless of whatever this build host produced.
if [ ! -f "$binary" ]; then
  echo "publish did not produce $expected_binary in $out" >&2
  exit 1
fi

# A framework-dependent publish or a bad RID silently produces a binary too small to actually be
# self-contained (the apphost stub alone is a few hundred KB; a real self-contained single-file
# .NET 10 ASP.NET Core app is tens of MB). Catches "looked like it worked" long before a node does.
size_bytes="$(stat -c%s "$binary" 2>/dev/null || stat -f%z "$binary")"
min_bytes=$((10 * 1024 * 1024))
if [ "$size_bytes" -lt "$min_bytes" ]; then
  echo "published binary is only $size_bytes bytes -- too small for a self-contained publish, check the RID/flags" >&2
  exit 1
fi

sha256="$(sha256sum "$binary" | cut -d' ' -f1)"

echo "== sidecar publish =="
echo "version:  $version"
echo "binary:   $binary"
echo "size:     $size_bytes bytes"
echo "sha256:   $sha256"
