#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
./generate-certs.sh
docker compose up --build "$@"
