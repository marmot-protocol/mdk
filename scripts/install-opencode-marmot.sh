#!/usr/bin/env bash
set -euo pipefail

export MARMOT_TERMINAL_HARNESS=opencode
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$script_dir/install-terminal-harness-marmot.sh" "$@"
