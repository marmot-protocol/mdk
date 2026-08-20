#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
project="mdk-fips-remote-${UID:-0}-$$"
compose=(
  docker compose
  --project-name "$project"
  --file "$repo_root/testing/fips-native/compose.remote.yml"
)

cleanup() {
  if [[ ${KEEP_FIPS_E2E:-0} == 1 ]]; then
    printf 'keeping Docker Compose project %s for inspection\n' "$project" >&2
    return
  fi
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

"${compose[@]}" up --build --abort-on-container-exit --exit-code-from smoke smoke
