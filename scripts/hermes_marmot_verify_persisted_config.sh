#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: scripts/hermes_marmot_verify_persisted_config.sh [options]

Configure Marmot in an isolated Hermes home, then verify Hermes loads the
Marmot adapter from persisted platforms.marmot.extra in a fresh subprocess with
all MARMOT_* environment variables removed.

This exercises Hermes plugin discovery, load_gateway_config(), and
platform_registry.create_adapter(). It does not start ``hermes gateway run``.

Options:
  --root PATH      Dev root (default: ${HERMES_MARMOT_DEV_ROOT:-${TMPDIR:-/tmp}/hermes-marmot-test})
  --account-id-hex HEX  Account id written into persisted config (default: 11..11)
  -h, --help       Show this help
USAGE
}

default_tmp="${TMPDIR:-/tmp}"
dev_root="${HERMES_MARMOT_DEV_ROOT:-${default_tmp%/}/hermes-marmot-test}"
account_id_hex="$(printf '11%.0s' {1..32})"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --root)
            dev_root="$2"
            shift 2
            ;;
        --account-id-hex)
            account_id_hex="$2"
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

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -f "$dev_root/env.sh" ]; then
    echo "error: $dev_root/env.sh not found. Run scripts/hermes_marmot_dev_setup.sh first." >&2
    exit 1
fi

# shellcheck disable=SC1091
source "$dev_root/env.sh"

if [ ! -x "$HERMES_AGENT_REPO/.venv/bin/python" ]; then
    echo "error: Hermes venv python not found at $HERMES_AGENT_REPO/.venv/bin/python" >&2
    echo "       Rerun setup without --skip-hermes-install." >&2
    exit 1
fi

socket_path="$MARMOT_HOME/dev/wn-agent.sock"
python3 - "$socket_path" <<'PY' &
import socket
import sys
from pathlib import Path

socket_path = Path(sys.argv[1])
socket_path.parent.mkdir(parents=True, exist_ok=True)
try:
    socket_path.unlink()
except FileNotFoundError:
    pass
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
    server.bind(str(socket_path))
    server.listen(1)
    connection, _ = server.accept()
    connection.close()
PY
socket_server_pid=$!
cleanup() {
    kill "$socket_server_pid" 2>/dev/null || true
    wait "$socket_server_pid" 2>/dev/null || true
}
trap cleanup EXIT
for _ in {1..50}; do
    [ -S "$socket_path" ] && break
    sleep 0.1
done
if [ ! -S "$socket_path" ]; then
    echo "error: test wn-agent socket did not become ready: $socket_path" >&2
    exit 1
fi

python3 "$repo_root/scripts/hermes_marmot_configure_gateway.py" \
    --home "$HERMES_HOME" \
    --agent-home "$MARMOT_HOME" \
    --socket-path "$socket_path" \
    --account-id-hex "$account_id_hex" \
    --streaming 0 \
    --transport off \
    --tool-progress off \
    --interim-messages 0 \
    --long-running-notifications 0 \
    --busy-ack-detail 0

(
    export HERMES_HOME
    cd "$HERMES_AGENT_REPO"
    .venv/bin/hermes plugins enable marmot
)

cd "$HERMES_AGENT_REPO"
env -i \
    HOME="$HOME" \
    HERMES_HOME="$HERMES_HOME" \
    HERMES_MARMOT_EXPECTED_SOCKET="$socket_path" \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="$HERMES_AGENT_REPO/.venv/bin:$PATH" \
    "$HERMES_AGENT_REPO/.venv/bin/python" \
    "$MDK_REPO/integrations/hermes/marmot/tests/real_hermes_persisted_config.py"
wait "$socket_server_pid"
