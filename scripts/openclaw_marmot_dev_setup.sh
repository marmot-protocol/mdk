#!/usr/bin/env bash
# Repeatable, throwaway dev setup for the OpenClaw Marmot channel plugin without
# touching your normal OpenClaw home. Mirrors scripts/hermes_marmot_dev_setup.sh.
#
# It builds the plugin, prepares an isolated dev root + env, and generates helper
# scripts to run dm-agent and the OpenClaw gateway against it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PLUGIN_SRC="$REPO_ROOT/integrations/openclaw/marmot"

ROOT="${OPENCLAW_MARMOT_DEV_ROOT:-${TMPDIR:-/tmp}/openclaw-marmot-test}"
PRINT_ENV=0
RELAYS=()
QUIC_CANDIDATES=()
AUTH_TOKEN_FILE=""
SOCKET_DIR_MODE=""
SOCKET_MODE=""

usage() {
    cat <<'USAGE'
Usage: openclaw_marmot_dev_setup.sh [options]

Options:
  --root DIR              Dev root (default: ${TMPDIR:-/tmp}/openclaw-marmot-test)
  --relay URL             Public relay URL (repeatable)
  --quic-candidate URL    quic:// preview broker candidate (repeatable)
  --auth-token-file PATH  Use a token-gated control socket
  --socket-dir-mode MODE  Octal parent-dir mode for the control socket (e.g. 0770)
  --socket-mode MODE      Octal socket mode (e.g. 0660)
  --print-env             Print the path to the generated env.sh on success
  -h, --help              Show this help
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --root) ROOT="$2"; shift 2;;
        --relay) RELAYS+=("$2"); shift 2;;
        --quic-candidate) QUIC_CANDIDATES+=("$2"); shift 2;;
        --auth-token-file) AUTH_TOKEN_FILE="$2"; shift 2;;
        --socket-dir-mode) SOCKET_DIR_MODE="$2"; shift 2;;
        --socket-mode) SOCKET_MODE="$2"; shift 2;;
        --print-env) PRINT_ENV=1; shift;;
        -h|--help) usage; exit 0;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2;;
    esac
done

MARMOT_HOME="$ROOT/marmot-agent-home"
OPENCLAW_HOME="$ROOT/openclaw-home"
LOGS_DIR="$ROOT/logs"
mkdir -p "$MARMOT_HOME" "$OPENCLAW_HOME" "$LOGS_DIR"

echo "openclaw-marmot dev setup: building plugin in $PLUGIN_SRC"
( cd "$PLUGIN_SRC" && pnpm install && pnpm typecheck && pnpm test )

# Default relays/candidates match the public pilot set.
if [ "${#RELAYS[@]}" -eq 0 ]; then
    RELAYS=(wss://relay.eu.whitenoise.chat wss://relay.us.whitenoise.chat)
fi
RELAY_ARGS=()
for relay in "${RELAYS[@]}"; do RELAY_ARGS+=(--relay "$relay"); done
QUIC_CSV="$(IFS=,; echo "${QUIC_CANDIDATES[*]:-}")"

SOCKET_PATH="$MARMOT_HOME/dev/dm-agent.sock"
DM_AGENT_EXTRA=()
[ -n "$AUTH_TOKEN_FILE" ] && DM_AGENT_EXTRA+=(--auth-token-file "$AUTH_TOKEN_FILE")
[ -n "$SOCKET_DIR_MODE" ] && DM_AGENT_EXTRA+=(--socket-dir-mode "$SOCKET_DIR_MODE")
[ -n "$SOCKET_MODE" ] && DM_AGENT_EXTRA+=(--socket-mode "$SOCKET_MODE")

cat > "$ROOT/env.sh" <<ENV
# Source this to configure the OpenClaw Marmot dev environment.
export OPENCLAW_MARMOT_DEV_ROOT="$ROOT"
export OPENCLAW_HOME="$OPENCLAW_HOME"
export MARMOT_HOME="$MARMOT_HOME"
export MARMOT_AGENT_SOCKET="$SOCKET_PATH"
export MARMOT_QUIC_CANDIDATES="$QUIC_CSV"
${AUTH_TOKEN_FILE:+export MARMOT_AGENT_AUTH_TOKEN_FILE="$AUTH_TOKEN_FILE"}
ENV

cat > "$ROOT/run-dm-agent.sh" <<RUN
#!/usr/bin/env bash
set -euo pipefail
exec cargo run -p agent-connector --bin dm-agent -- \\
  --home "$MARMOT_HOME" \\
  ${RELAY_ARGS[*]} \\
  ${DM_AGENT_EXTRA[*]:-}
RUN
chmod +x "$ROOT/run-dm-agent.sh"

cat > "$ROOT/run-openclaw-gateway.sh" <<RUN
#!/usr/bin/env bash
set -euo pipefail
source "$ROOT/env.sh"
# Install the local plugin into the isolated OpenClaw home, then run the gateway.
# Adjust the run subcommand to match your OpenClaw version if needed.
openclaw plugins install "$PLUGIN_SRC"
exec openclaw gateway run
RUN
chmod +x "$ROOT/run-openclaw-gateway.sh"

cat > "$ROOT/smoke-plugin.sh" <<RUN
#!/usr/bin/env bash
set -euo pipefail
cd "$PLUGIN_SRC"
pnpm typecheck && pnpm test
RUN
chmod +x "$ROOT/smoke-plugin.sh"

echo "openclaw-marmot dev setup ready under: $ROOT"
echo "  1. start dm-agent:        $ROOT/run-dm-agent.sh"
echo "  2. bootstrap the account: cargo run -p agent-connector --bin dm-agent -- bootstrap --home '$MARMOT_HOME' --qr"
echo "  3. run the gateway:       $ROOT/run-openclaw-gateway.sh"
if [ "$PRINT_ENV" -eq 1 ]; then
    echo "$ROOT/env.sh"
fi
