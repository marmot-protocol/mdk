#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
tmp_parent="$(mktemp -d)"
trap 'rm -rf "$tmp_parent"' EXIT

dev_root="$tmp_parent/nested/openclaw-marmot-test"
account_id="$(printf '11%.0s' {1..32})"
group_id="$(printf '22%.0s' {1..32})"

"$repo_root/scripts/openclaw_marmot_dev_setup.sh" \
    --root "$dev_root" \
    --account-id-hex "$account_id" \
    --group-id-hex "$group_id" \
    --auth-token "script-token" \
    --socket-dir-mode "0770" \
    --socket-mode "0660" \
    --relay "wss://relay.example" \
    --quic-candidate "quic://127.0.0.1:4433" \
    --print-env

[ -f "$dev_root/env.sh" ]
[ -x "$dev_root/run-wn-agent.sh" ]
[ -x "$dev_root/run-openclaw-gateway.sh" ]
[ -x "$dev_root/start-wn-agent.sh" ]
[ -x "$dev_root/start-openclaw-gateway.sh" ]
[ -x "$dev_root/stop-dev-processes.sh" ]
[ -x "$dev_root/smoke-plugin.sh" ]
[ -x "$dev_root/control-smoketest.sh" ]
[ -x "$dev_root/e2e-connector.sh" ]
[ -x "$dev_root/bootstrap-agent.sh" ]

for helper in \
    "$dev_root/run-wn-agent.sh" \
    "$dev_root/run-openclaw-gateway.sh" \
    "$dev_root/start-wn-agent.sh" \
    "$dev_root/start-openclaw-gateway.sh" \
    "$dev_root/stop-dev-processes.sh" \
    "$dev_root/smoke-plugin.sh" \
    "$dev_root/control-smoketest.sh" \
    "$dev_root/e2e-connector.sh" \
    "$dev_root/bootstrap-agent.sh"; do
    bash -n "$helper"
done

stop_marker="$tmp_parent/stop-marker"
cat > "$dev_root/stop-dev-processes.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
: "${OPENCLAW_STOP_MARKER:?}"
printf 'stopped\n' > "$OPENCLAW_STOP_MARKER"
SCRIPT
chmod +x "$dev_root/stop-dev-processes.sh"

# shellcheck disable=SC1091
source "$dev_root/env.sh"

[ "$OPENCLAW_MARMOT_DEV_ROOT" = "$dev_root" ]
[ "$MDK_REPO" = "$repo_root" ]
[ "$OPENCLAW_PLUGIN_SRC" = "$repo_root/integrations/openclaw/marmot" ]
[ "$OPENCLAW_HOME" = "$dev_root/openclaw-home" ]
[ "$MARMOT_HOME" = "$dev_root/marmot-agent-home" ]
[ "$MARMOT_AGENT_SOCKET" = "$dev_root/marmot-agent-home/dev/wn-agent.sock" ]
[ "$MARMOT_AGENT_AUTH_TOKEN_FILE" = "$dev_root/control.token" ]
[ "$MARMOT_AGENT_SOCKET_DIR_MODE" = "0770" ]
[ "$MARMOT_AGENT_SOCKET_MODE" = "0660" ]
[ "$MARMOT_ACCOUNT_ID_HEX" = "$account_id" ]
[ "$MARMOT_GROUP_ID_HEX" = "$group_id" ]
[ "$MARMOT_RELAYS" = "wss://relay.example" ]
[ "$MARMOT_QUIC_CANDIDATES" = "quic://127.0.0.1:4433" ]
[ "$(cat "$MARMOT_AGENT_AUTH_TOKEN_FILE")" = "script-token" ]
[ "${wn_agent_relay_args[0]}" = "--relay" ]
[ "${wn_agent_relay_args[1]}" = "wss://relay.example" ]
[ "${wn_agent_quic_args[0]}" = "--quic-candidate" ]
[ "${wn_agent_quic_args[1]}" = "quic://127.0.0.1:4433" ]

OPENCLAW_STOP_MARKER="$stop_marker" "$repo_root/scripts/openclaw_marmot_dev_teardown.sh" --root "$dev_root" --dry-run
[ "$(cat "$stop_marker")" = "stopped" ]
[ -d "$dev_root" ]
rm "$stop_marker"
OPENCLAW_STOP_MARKER="$stop_marker" "$repo_root/scripts/openclaw_marmot_dev_teardown.sh" --root "$dev_root" --force
[ "$(cat "$stop_marker")" = "stopped" ]
[ ! -e "$dev_root" ]

default_root="$tmp_parent/defaults/openclaw-marmot-test"
"$repo_root/scripts/openclaw_marmot_dev_setup.sh" \
    --root "$default_root"

# shellcheck disable=SC1091
source "$default_root/env.sh"

[ "$MARMOT_ACCOUNT_ID_HEX" = "" ]
[ "$MARMOT_GROUP_ID_HEX" = "" ]
[ "$MARMOT_QUIC_CANDIDATES" = "" ]
[ "$MARMOT_AGENT_AUTH_TOKEN_FILE" = "" ]
[ "$MARMOT_AGENT_SOCKET_DIR_MODE" = "0700" ]
[ "$MARMOT_AGENT_SOCKET_MODE" = "0600" ]
[ "$MARMOT_RELAYS" = "wss://relay.eu.whitenoise.chat,wss://relay.us.whitenoise.chat" ]
[ "${#wn_agent_relay_args[@]}" -eq 4 ]
[ "${#wn_agent_quic_args[@]}" -eq 0 ]
"$repo_root/scripts/openclaw_marmot_dev_teardown.sh" --root "$default_root" --force
[ ! -e "$default_root" ]

[ -x "$repo_root/scripts/install-openclaw-marmot.sh" ]
installer_dry_run="$(
    env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
        WN_AGENT_SHA="9.9.9" \
        MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
    "$repo_root/scripts/install-openclaw-marmot.sh" --dry-run --yes
)"
installer_stdin_dry_run="$(
    env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
        WN_AGENT_SHA="9.9.9" \
        MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
    bash -s -- --dry-run --yes < "$repo_root/scripts/install-openclaw-marmot.sh"
)"
installer_bad_welcomer_status=0
env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
    WN_AGENT_SHA="9.9.9" \
    MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
    "$repo_root/scripts/install-openclaw-marmot.sh" --dry-run --yes --allow-welcomer not-a-key \
    >/dev/null 2>&1 || installer_bad_welcomer_status=$?
[ "$installer_bad_welcomer_status" -ne 0 ]
case "$installer_dry_run" in
    *"wn-agent-"*"9.9.9.tar.gz"* ) ;;
    *) echo "OpenClaw installer dry-run did not use WN_AGENT_SHA asset suffix" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"openclaw-marmot-plugin-9.9.9.tgz"* ) ;;
    *) echo "OpenClaw installer dry-run did not use expected plugin asset" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"wn-agent-v9.9.9-test"* ) ;;
    *) echo "OpenClaw installer dry-run did not use requested release tag" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"Marmot home: $HOME/.marmot-agents/openclaw"* ) ;;
    *) echo "OpenClaw installer dry-run did not use isolated default Marmot home" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"Marmot socket: $HOME/.marmot-agents/openclaw/dev/wn-agent.sock"* ) ;;
    *) echo "OpenClaw installer dry-run did not derive the socket from the isolated home" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"--label openclaw-agent"* ) ;;
    *) echo "OpenClaw installer dry-run did not pass the OpenClaw bootstrap label" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"wn-agent-openclaw.service"* | *"org.marmot.wn-agent.openclaw.plist"* ) ;;
    *) echo "OpenClaw installer dry-run did not use the OpenClaw-specific service identity" >&2; exit 1;;
esac
case "$installer_stdin_dry_run" in
    *"openclaw-marmot-plugin-9.9.9.tgz"* ) ;;
    *) echo "OpenClaw installer stdin dry-run did not use expected plugin asset" >&2; exit 1;;
esac
case "$installer_stdin_dry_run" in
    *"wn-agent-"*"9.9.9.tar.gz"* ) ;;
    *) echo "OpenClaw installer stdin dry-run did not use WN_AGENT_SHA asset suffix" >&2; exit 1;;
esac
case "$installer_stdin_dry_run" in
    *"wn-agent-v9.9.9-test"* ) ;;
    *) echo "OpenClaw installer stdin dry-run did not use requested release tag" >&2; exit 1;;
esac
case "$installer_stdin_dry_run" in
    *"Marmot home: $HOME/.marmot-agents/openclaw"* ) ;;
    *) echo "OpenClaw installer stdin dry-run did not use isolated default Marmot home" >&2; exit 1;;
esac
case "$installer_stdin_dry_run" in
    *"--label openclaw-agent"* ) ;;
    *) echo "OpenClaw installer stdin dry-run did not pass the OpenClaw bootstrap label" >&2; exit 1;;
esac

echo "OpenClaw dev script test passed"
