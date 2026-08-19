#!/usr/bin/env bash
set -euo pipefail

export MARMOT_TERMINAL_HARNESS=codex
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/install-terminal-harness-marmot.sh" "$@"
