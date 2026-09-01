#!/usr/bin/env bash
# Validate the egress Envoy bootstrap with a real Envoy binary, against throwaway certs.
# Generates a dev CA + server cert in a temp dir, rewrites the /etc/mina/tls paths to point at
# them, and runs `envoy --mode validate`. Requires: envoy on PATH (or $ENVOY), openssl.
set -euo pipefail

ENVOY="${ENVOY:-envoy}"
CONFIG="$(cd "$(dirname "$0")/.." && pwd)/egress-node/envoy/envoy-bootstrap.yaml"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Dev CA + server cert (SAN egress.local + loopback). Throwaway — never leaves the temp dir.
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/ca.key" 2>/dev/null
openssl req -x509 -new -key "$WORK/ca.key" -sha256 -days 1 -subj "/CN=Mina Dev CA" -out "$WORK/ca.crt" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/server.key" 2>/dev/null
openssl req -new -key "$WORK/server.key" -subj "/CN=egress.local" -out "$WORK/server.csr" 2>/dev/null
openssl x509 -req -in "$WORK/server.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" -CAcreateserial \
  -days 1 -sha256 -extfile <(printf "subjectAltName=DNS:egress.local,IP:127.0.0.1") \
  -out "$WORK/server.crt" 2>/dev/null

# Redirect the TLS material, the access log and the admin socket into the temp dir, so validation
# touches nothing outside it.
sed -e "s#/etc/mina/tls#$WORK#g" \
    -e "s#/var/log/mina/envoy-access.log#$WORK/envoy-access.log#g" \
    -e "s#/run/mina/envoy-admin.sock#$WORK/envoy-admin.sock#g" \
    "$CONFIG" > "$WORK/envoy.yaml"

echo "Validating $CONFIG with $("$ENVOY" --version 2>/dev/null | tr -d '\n')"
"$ENVOY" --mode validate -c "$WORK/envoy.yaml"
