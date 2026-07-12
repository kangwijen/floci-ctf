#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"
if [[ -z "${AWS_ENDPOINT_URL:-}${FLOCI_ENDPOINT:-}" ]]; then
  echo "Set AWS_ENDPOINT_URL (or FLOCI_ENDPOINT) to a CTF Compose instance." >&2
  exit 1
fi
./mvnw install -DskipTests -q
./mvnw -f tools/fuzz/pom.xml test -Pfuzz-operator "$@"
