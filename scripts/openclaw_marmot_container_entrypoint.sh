#!/usr/bin/env bash
# Container entrypoint for the OpenClaw Marmot phone test: start dm-agent, bootstrap
# the agent account, install + enable the Marmot channel plugin, run the gateway.
# Mirrors scripts/hermes_marmot_container_entrypoint.sh.
set -euo pipefail

socket_dir="$(dirname "$MARMOT_AGENT_SOCKET")"
install -d -m "${MARMOT_AGENT_SOCKET_DIR_MODE:-0770}" "$socket_dir"
install -d -m 0700 "$MARMOT_HOME" "$OPENCLAW_HOME"

if [ ! -f "$MARMOT_AGENT_AUTH_TOKEN_FILE" ]; then
    ( umask 0177; head -c 32 /dev/urandom | xxd -p -c 64 > "$MARMOT_AGENT_AUTH_TOKEN_FILE" )
fi

relay_args=()
IFS=',' read -ra relays <<< "${MARMOT_RELAYS:-}"
for relay in "${relays[@]}"; do
    [ -n "$relay" ] && relay_args+=(--relay "$relay")
done

extra_args=()
if [ "${MARMOT_AGENT_ALLOW_ANY:-0}" = "1" ]; then
    extra_args+=(--allow-any)
fi
if [ "${MARMOT_AGENT_DEBUG_CONTROLS:-0}" = "1" ]; then
    extra_args+=(--debug-controls)
fi

# Surface dm-agent's privacy-safe connector tracing in the container logs so the
# phone test can see welcome/group/inbound activity (override with RUST_LOG).
export RUST_LOG="${RUST_LOG:-info}"

dm-agent \
    --home "$MARMOT_HOME" \
    --socket "$MARMOT_AGENT_SOCKET" \
    --auth-token-file "$MARMOT_AGENT_AUTH_TOKEN_FILE" \
    --socket-dir-mode "${MARMOT_AGENT_SOCKET_DIR_MODE:-0770}" \
    --socket-mode "${MARMOT_AGENT_SOCKET_MODE:-0660}" \
    "${relay_args[@]}" \
    "${extra_args[@]}" &

# Wait for the control socket before bootstrapping.
for _ in $(seq 1 30); do
    [ -S "$MARMOT_AGENT_SOCKET" ] && break
    sleep 1
done

if [ ! -S "$MARMOT_AGENT_SOCKET" ]; then
    echo "error: dm-agent control socket not available at $MARMOT_AGENT_SOCKET" >&2
    exit 1
fi

dm-agent bootstrap \
    --home "$MARMOT_HOME" \
    --socket "$MARMOT_AGENT_SOCKET" \
    --auth-token-file "$MARMOT_AGENT_AUTH_TOKEN_FILE" \
    --label "${MARMOT_AGENT_LABEL:-openclaw-agent}" \
    --qr || true

# OpenClaw refuses to start the gateway unless the config has been onboarded
# (gateway.mode=local); `openclaw plugins ...` alone leaves it unset, which is
# what trips the "missing gateway.mode / clobbered config" guard. Onboard once,
# non-interactively, in local mode, picking up whichever model API key is set.
openclaw_config="$OPENCLAW_HOME/.openclaw/openclaw.json"
if ! node -e 'process.exit(require(process.argv[1]).gateway?.mode==="local"?0:1)' "$openclaw_config" 2>/dev/null; then
    onboard_args=(
        --non-interactive --accept-risk --mode local --flow quickstart
        --suppress-gateway-token-output
        --no-install-daemon --skip-channels --skip-skills --skip-ui
        --skip-search --skip-hooks --skip-health --skip-bootstrap
    )
    if [ -n "${OPENAI_API_KEY:-}" ]; then
        onboard_args+=(--auth-choice openai-api-key --openai-api-key "$OPENAI_API_KEY")
    elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then
        onboard_args+=(--auth-choice anthropic-api-key --anthropic-api-key "$ANTHROPIC_API_KEY")
    elif [ -n "${OPENROUTER_API_KEY:-}" ]; then
        onboard_args+=(--auth-choice openrouter-api-key --openrouter-api-key "$OPENROUTER_API_KEY")
    elif [ -n "${GEMINI_API_KEY:-}" ]; then
        onboard_args+=(--auth-choice gemini-api-key --gemini-api-key "$GEMINI_API_KEY")
    elif [ -n "${GOOGLE_API_KEY:-}" ]; then
        onboard_args+=(--auth-choice gemini-api-key --gemini-api-key "$GOOGLE_API_KEY")
    else
        echo "warning: no model API key set (OPENAI_API_KEY/ANTHROPIC_API_KEY/OPENROUTER_API_KEY/GEMINI_API_KEY/GOOGLE_API_KEY); the gateway will start but agent turns fail until one is provided" >&2
        onboard_args+=(--auth-choice skip)
    fi
    openclaw onboard "${onboard_args[@]}"
fi

# --force overwrites an already-installed copy. OPENCLAW_HOME lives on a
# persisted volume, so without --force a rebuilt image's updated plugin dist is
# ignored in favor of the stale copy left in the volume from a prior run.
openclaw plugins install --force /work/darkmatter/integrations/openclaw/marmot || true
openclaw plugins enable marmot || true

# Enabling the plugin loads its code but does not start a channel: OpenClaw only
# starts channels configured under channels.<id>. `openclaw channels add
# --channel marmot` insists on installing @darkmatter/openclaw-marmot from npm
# (this is a local, unpublished plugin), so write the channel entry directly.
# Every marmot channel field is optional and resolved from MARMOT_* env, so an
# enabled entry is sufficient. Idempotent, so it also re-asserts on restart.
if [ -f "$openclaw_config" ]; then
    node -e '
const fs = require("fs");
const p = process.argv[1];
const cfg = JSON.parse(fs.readFileSync(p, "utf8"));
cfg.channels = cfg.channels || {};
const streamMode = process.env.MARMOT_STREAM_MODE || "block";
if (!["off", "partial", "block", "progress"].includes(streamMode)) {
  throw new Error(`invalid MARMOT_STREAM_MODE: ${streamMode}`);
}
// Enable the channel + live QUIC previews. streaming.mode gates our preview and
// streaming.block.enabled + agents.defaults.blockStreamingDefault make OpenClaw
// emit the progressive block deliveries the preview is built from.
cfg.channels.marmot = {
  ...(cfg.channels.marmot || {}),
  enabled: true,
  streaming: {
    ...(cfg.channels.marmot || {}).streaming,
    mode: streamMode,
    block: { ...((cfg.channels.marmot || {}).streaming || {}).block, enabled: true },
  },
};
cfg.agents = cfg.agents || {};
cfg.agents.defaults = { ...(cfg.agents.defaults || {}), blockStreamingDefault: "on" };
fs.writeFileSync(p, JSON.stringify(cfg, null, 2) + "\n");
' "$openclaw_config" && echo "marmot: enabled channels.marmot (streaming.mode=${MARMOT_STREAM_MODE:-block}) in OpenClaw config"
fi

exec openclaw gateway run
