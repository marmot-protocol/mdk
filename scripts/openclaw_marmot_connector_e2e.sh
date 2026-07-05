#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: scripts/openclaw_marmot_connector_e2e.sh [options]

Runs a deterministic OpenClaw/Marmot E2E against a real wn-agent process started
with debug controls. No model, real Marmot account, group, relay, or OpenClaw
gateway is required.

Options:
  --root PATH      Dev root (default: ${OPENCLAW_MARMOT_DEV_ROOT:-${TMPDIR:-/tmp}/openclaw-marmot-test})
  -h, --help       Show this help
USAGE
}

default_tmp="${TMPDIR:-/tmp}"
dev_root="${OPENCLAW_MARMOT_DEV_ROOT:-${default_tmp%/}/openclaw-marmot-test}"

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
    echo "error: $dev_root/env.sh not found. Run scripts/openclaw_marmot_dev_setup.sh first." >&2
    exit 1
fi

source "$dev_root/env.sh"

cd "$OPENCLAW_PLUGIN_SRC"
exec env MARMOT_OPENCLAW_CONNECTOR_E2E=1 pnpm exec vitest run test/e2e-connector.test.ts
