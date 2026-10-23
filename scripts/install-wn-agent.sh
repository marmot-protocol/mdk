#!/usr/bin/env bash
set -euo pipefail

# Connector-only install for custom agent-control clients: wn-agent and its
# same-user service, without a harness or gateway plugin.
export MARMOT_TERMINAL_HARNESS=none
script_source="${BASH_SOURCE[0]:-}"
if [ -z "$script_source" ] || [ ! -f "$script_source" ]; then
    echo "error: this repository wrapper must be run from a checkout; use the release installer only after verifying its published .sha256 companion" >&2
    exit 64
fi
script_dir="$(cd "$(dirname "$script_source")" && pwd)"
exec "$script_dir/install-terminal-harness-marmot.sh" "$@"
