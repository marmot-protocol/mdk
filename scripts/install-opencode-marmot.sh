#!/usr/bin/env bash
set -euo pipefail

export MARMOT_TERMINAL_HARNESS=opencode
script_source="${BASH_SOURCE[0]:-}"
if [ -z "$script_source" ] || [ ! -f "$script_source" ]; then
    echo "error: this repository wrapper must be run from a checkout; use the release installer only after verifying its published .sha256 companion" >&2
    exit 64
fi
script_dir="$(cd "$(dirname "$script_source")" && pwd)"
exec "$script_dir/install-terminal-harness-marmot.sh" "$@"
