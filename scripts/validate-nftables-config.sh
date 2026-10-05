#!/usr/bin/env bash
# Validate the egress node's nftables ruleset with a real nft binary.
# Extracts /etc/nftables.conf out of the cloud-init template's write_files block and runs
# `nft --check` on it. Requires: nft (the nftables package), and root — see below.
#
# Why this exists. Nothing else in this repository has ever evaluated this ruleset: cloud-init
# writes the file and `systemctl enable --now nftables` loads it, so until now the first thing to
# parse it was a booting production node. That matters more than a normal syntax check, because nft
# applies a file atomically and this ruleset opens with `flush ruleset`: one error anywhere in it
# leaves the node with NO rules loaded rather than a partial ruleset. The M4-10 containment on
# research traffic would be silently absent instead of failing closed — the node would come up,
# serve tunnels, and enforce nothing.
#
# Root is required for two reasons, neither avoidable: `nft --check` still hands the batch to the
# kernel to validate (it just never commits it), which needs CAP_NET_ADMIN; and the ruleset matches
# `skuid "mina-envoy"`, which nft resolves through getpwnam while parsing, so the account has to
# exist on the checking host or a rule that is perfectly valid on a real node fails here.
set -euo pipefail

NFT="${NFT:-nft}"
TEMPLATE="$(cd "$(dirname "$0")/.." && pwd)/egress-node/cloud-init.yaml.tftpl"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ "$(id -u)" -ne 0 ]; then
  echo "Must run as root (try: sudo $0)." >&2
  echo "nft --check needs CAP_NET_ADMIN, and resolving skuid \"mina-envoy\" needs the account." >&2
  exit 1
fi

# Pull the `content: |` block that follows `- path: /etc/nftables.conf`, stripping the six-space
# YAML block indent. The block ends at the first non-blank line indented less than that.
awk '
  /^  - path: \/etc\/nftables\.conf$/ { found = 1; next }
  found && /^    content: \|$/        { body  = 1; next }
  body {
    if ($0 == "")        { print ""; next }
    if ($0 ~ /^      /)  { sub(/^      /, ""); print; next }
    exit
  }
' "$TEMPLATE" > "$WORK/nftables.conf"

if [ ! -s "$WORK/nftables.conf" ]; then
  echo "Could not extract /etc/nftables.conf from $TEMPLATE — has the write_files block moved?" >&2
  exit 1
fi

# The extraction must have caught the whole ruleset, not a prefix of it. A truncated extract is
# still valid nft: it would check clean and prove nothing about the rules that were cut off, which
# is the one way this script could pass while telling you nothing.
for required in 'flush ruleset' 'table inet mina' 'chain output' 'meta skuid "mina-envoy"' 'ip6 daddr'; do
  if ! grep -qF "$required" "$WORK/nftables.conf"; then
    echo "Extracted ruleset is missing '$required' — the extraction is wrong, not the ruleset." >&2
    echo "--- what was extracted ---" >&2
    cat "$WORK/nftables.conf" >&2
    exit 1
  fi
done

if ! id -u mina-envoy >/dev/null 2>&1; then
  echo "Creating a throwaway mina-envoy account so nft can resolve skuid by name."
  useradd -r -s /usr/sbin/nologin mina-envoy
fi

echo "Checking $(wc -l < "$WORK/nftables.conf") lines with $("$NFT" --version)"
"$NFT" --check --file "$WORK/nftables.conf"
echo "OK: the ruleset parses and the kernel accepts every rule."
