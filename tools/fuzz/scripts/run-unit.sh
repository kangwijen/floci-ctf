#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"
./mvnw install -DskipTests -q
./mvnw -f tools/fuzz/pom.xml test "$@"
