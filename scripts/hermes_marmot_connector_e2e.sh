#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: scripts/hermes_marmot_connector_e2e.sh [options]

Runs a deterministic Hermes/Marmot E2E against a real dm-agent process started
with debug controls. No model, real Marmot account, group, or relay is required.

Options:
  --root PATH      Dev root (default: ${HERMES_MARMOT_DEV_ROOT:-${TMPDIR:-/tmp}/hermes-marmot-test})
  -h, --help       Show this help
USAGE
}

default_tmp="${TMPDIR:-/tmp}"
dev_root="${HERMES_MARMOT_DEV_ROOT:-${default_tmp%/}/hermes-marmot-test}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --root)
            dev_root="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ ! -f "$dev_root/env.sh" ]; then
    echo "error: $dev_root/env.sh not found. Run scripts/hermes_marmot_dev_setup.sh first." >&2
    exit 1
fi

source "$dev_root/env.sh"

if [ ! -x "$HERMES_AGENT_REPO/.venv/bin/python" ]; then
    echo "error: Hermes venv python not found at $HERMES_AGENT_REPO/.venv/bin/python" >&2
    echo "       Rerun setup without --skip-hermes-install." >&2
    exit 1
fi

cd "$HERMES_AGENT_REPO"
export PYTHONDONTWRITEBYTECODE=1
exec "$HERMES_AGENT_REPO/.venv/bin/python" \
    "$DARKMATTER_REPO/integrations/hermes/marmot/tests/e2e_connector.py"
