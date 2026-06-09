#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

: "${MARMOT_HOME:=/data/marmot-agent}"
: "${HERMES_HOME:=/data/hermes-home}"
: "${MARMOT_AGENT_SOCKET:=/run/marmot-agent/dm-agent.sock}"
: "${MARMOT_AGENT_AUTH_TOKEN_FILE:=$MARMOT_HOME/control.token}"
: "${MARMOT_AGENT_SOCKET_DIR_MODE:=0770}"
: "${MARMOT_AGENT_SOCKET_MODE:=0660}"
: "${MARMOT_RELAYS:=${MARMOT_RELAY:-wss://relay.eu.whiteniose.chat,wss://relay.us.whitenoise.chat}}"
: "${MARMOT_QUIC_CANDIDATES:=quic://quic-broker.ipf.dev:4450}"
: "${HERMES_MARMOT_AUTO_BOOTSTRAP:=1}"
: "${HERMES_MARMOT_START_GATEWAY:=1}"
: "${HERMES_MARMOT_STREAMING:=1}"
: "${HERMES_MARMOT_STREAMING_TRANSPORT:=auto}"
: "${HERMES_MARMOT_TOOL_PROGRESS:=off}"
: "${HERMES_MARMOT_INTERIM_MESSAGES:=0}"
: "${HERMES_MARMOT_LONG_RUNNING_NOTIFICATIONS:=0}"
: "${HERMES_MARMOT_BUSY_ACK_DETAIL:=0}"
: "${MARMOT_PROFILE_NAME_ONBOARDING:=1}"

export MARMOT_HOME
export HERMES_HOME
export MARMOT_AGENT_SOCKET
export MARMOT_AGENT_AUTH_TOKEN_FILE
export MARMOT_AGENT_SOCKET_DIR_MODE
export MARMOT_AGENT_SOCKET_MODE
export MARMOT_RELAYS
export MARMOT_QUIC_CANDIDATES
export MARMOT_PROFILE_NAME_ONBOARDING
export PATH="/opt/hermes-agent/.venv/bin:$PATH"

mkdir -p "$MARMOT_HOME" "$HERMES_HOME/plugins" "$(dirname "$MARMOT_AGENT_SOCKET")"
chmod 0700 "$MARMOT_HOME" "$HERMES_HOME" || true

if [ ! -f "$MARMOT_AGENT_AUTH_TOKEN_FILE" ]; then
    token_parent="$(dirname "$MARMOT_AGENT_AUTH_TOKEN_FILE")"
    mkdir -p "$token_parent"
    umask 077
    python3 - <<'PY' >"$MARMOT_AGENT_AUTH_TOKEN_FILE"
import secrets
print(secrets.token_hex(32))
PY
fi
chmod 0600 "$MARMOT_AGENT_AUTH_TOKEN_FILE"

ln -sfn /work/darkmatter/integrations/hermes/marmot "$HERMES_HOME/plugins/marmot"

dm_agent_args=(
    --home "$MARMOT_HOME"
    --socket "$MARMOT_AGENT_SOCKET"
    --auth-token-file "$MARMOT_AGENT_AUTH_TOKEN_FILE"
    --socket-dir-mode "$MARMOT_AGENT_SOCKET_DIR_MODE"
    --socket-mode "$MARMOT_AGENT_SOCKET_MODE"
)

IFS=',' read -r -a configured_relays <<<"$MARMOT_RELAYS"
for relay in "${configured_relays[@]}"; do
    relay="${relay#"${relay%%[![:space:]]*}"}"
    relay="${relay%"${relay##*[![:space:]]}"}"
    [ -z "$relay" ] || dm_agent_args+=(--relay "$relay")
done

case "${MARMOT_AGENT_ALLOW_ANY:-1}" in
    1|true|TRUE|yes|YES)
        dm_agent_args+=(--allow-any)
        ;;
esac

dm-agent "${dm_agent_args[@]}" &
dm_agent_pid="$!"

cleanup() {
    kill "$dm_agent_pid" 2>/dev/null || true
    if [ -n "${hermes_pid:-}" ]; then
        kill "$hermes_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

if [ "$HERMES_MARMOT_AUTO_BOOTSTRAP" != "0" ]; then
    bootstrap_json="$(marmot-agent-bootstrap --json)"
    printf '%s\n' "$bootstrap_json" >"$MARMOT_HOME/bootstrap.json"
    MARMOT_ACCOUNT_ID_HEX="$(
        printf '%s\n' "$bootstrap_json" |
            python3 -c 'import json, sys; print(json.load(sys.stdin)["account_id_hex"])'
    )"
    export MARMOT_ACCOUNT_ID_HEX
    echo "Marmot agent account: $MARMOT_ACCOUNT_ID_HEX"
    echo "Bootstrap details: $MARMOT_HOME/bootstrap.json"
fi

if command -v hermes >/dev/null 2>&1; then
    hermes plugins enable marmot || true
else
    echo "error: hermes launcher not found on PATH" >&2
    exit 1
fi

marmot-configure-hermes-gateway \
    --home "$HERMES_HOME" \
    --streaming "$HERMES_MARMOT_STREAMING" \
    --transport "$HERMES_MARMOT_STREAMING_TRANSPORT" \
    --tool-progress "$HERMES_MARMOT_TOOL_PROGRESS" \
    --interim-messages "$HERMES_MARMOT_INTERIM_MESSAGES" \
    --long-running-notifications "$HERMES_MARMOT_LONG_RUNNING_NOTIFICATIONS" \
    --busy-ack-detail "$HERMES_MARMOT_BUSY_ACK_DETAIL"

if [ "$HERMES_MARMOT_START_GATEWAY" = "0" ]; then
    echo "Hermes gateway disabled; dm-agent is running."
    wait "$dm_agent_pid"
fi

hermes gateway run &
hermes_pid="$!"

wait -n "$dm_agent_pid" "$hermes_pid"
