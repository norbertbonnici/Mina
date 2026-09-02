#!/usr/bin/env bash
# Throwaway dev CA + server certificate for the stack's Envoy container. Same shape as
# scripts/validate-envoy-config.sh and tests/support/Mina.TestSupport/EnvoyProcess.cs: ECDSA P-256,
# server SAN covering the name curl will connect as. Never committed; regenerated on each run.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)/certs"
rm -rf "$DIR"
mkdir -p "$DIR"

openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/ca.key" 2>/dev/null
openssl req -x509 -new -key "$DIR/ca.key" -sha256 -days 30 -subj "/CN=Mina Dev Stack CA" -out "$DIR/ca.crt" 2>/dev/null

openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/server.key" 2>/dev/null
openssl req -new -key "$DIR/server.key" -subj "/CN=egress.local" -out "$DIR/server.csr" 2>/dev/null
openssl x509 -req -in "$DIR/server.csr" -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" -CAcreateserial \
  -days 30 -sha256 -extfile <(printf "subjectAltName=DNS:egress.local,IP:127.0.0.1") \
  -out "$DIR/server.crt" 2>/dev/null
rm -f "$DIR/server.csr" "$DIR/ca.srl"

chmod 644 "$DIR"/*.crt "$DIR"/*.key
echo "Certs written to $DIR"
