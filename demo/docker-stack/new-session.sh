#!/usr/bin/env bash
# Issues a client certificate for a fresh session id and prints the curl commands to use it.
# Does NOT register the session with the node-api stub — that is the interesting step to run
# separately (see README): the tunnel is refused until you admit it.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS="$DIR/certs"
SESSION_ID="${1:-$(python3 -c 'import uuid; print(uuid.uuid4())' 2>/dev/null || uuidgen | tr '[:upper:]' '[:lower:]')}"
OUT="$CERTS/session-$SESSION_ID"

if [ ! -f "$CERTS/ca.key" ]; then
  echo "No CA found — run ./generate-certs.sh first." >&2
  exit 1
fi

openssl ecparam -name prime256v1 -genkey -noout -out "$OUT.key" 2>/dev/null
openssl req -new -key "$OUT.key" -subj "/CN=mina-session-demo" -out "$OUT.csr" 2>/dev/null
openssl x509 -req -in "$OUT.csr" -CA "$CERTS/ca.crt" -CAkey "$CERTS/ca.key" -CAcreateserial \
  -days 1 -sha256 -extfile <(printf "subjectAltName=URI:mina:session:%s" "$SESSION_ID") \
  -out "$OUT.crt" 2>/dev/null
rm -f "$OUT.csr" "$CERTS/ca.srl"

cat <<MSG

Session id:  $SESSION_ID
Certificate: $OUT.crt / $OUT.key

Admit it with the stub (the tunnel is refused until you do this):

  curl -s -X POST http://127.0.0.1:8090/admin/sessions \\
    -H 'Content-Type: application/json' \\
    -d '{"sessionId":"$SESSION_ID","leaseMinutes":60}'

Then curl through the tunnel:

  curl --proxy-cacert "$CERTS/ca.crt" --proxy-cert "$OUT.crt" --proxy-key "$OUT.key" \\
    --resolve egress.local:8443:127.0.0.1 -x https://egress.local:8443 \\
    https://example.com -sS -o /dev/null -w '%{http_code}\n'

Revoke it and watch the same curl start refusing within the refresh interval (~5s in this stack):

  curl -s -X DELETE http://127.0.0.1:8090/admin/sessions/$SESSION_ID
MSG
