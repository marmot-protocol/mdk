#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
project="mdk-fips-cli-${UID:-0}-$$"
compose=(
  docker compose
  --project-name "$project"
  --file "$repo_root/testing/fips-native/compose.remote.yml"
  --profile mdk
)

cleanup() {
  if [[ ${KEEP_FIPS_E2E:-0} == 1 ]]; then
    printf 'keeping Docker Compose project %s for inspection\n' "$project" >&2
    return
  fi
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

"${compose[@]}" build discovery client-fips
"${compose[@]}" build mdk-e2e
"${compose[@]}" up --no-build --abort-on-container-exit --exit-code-from mdk-e2e mdk-e2e
