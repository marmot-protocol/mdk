#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
tmp_parent="$(mktemp -d)"
trap 'rm -rf "$tmp_parent"' EXIT

dev_root="$tmp_parent/nested/hermes-marmot-test"
account_id="$(printf '11%.0s' {1..32})"
group_id="$(printf '22%.0s' {1..32})"

"$repo_root/scripts/hermes_marmot_dev_setup.sh" \
    --root "$dev_root" \
    --skip-hermes-install \
    --account-id-hex "$account_id" \
    --group-id-hex "$group_id" \
    --auth-token "script-token" \
    --socket-dir-mode "0770" \
    --socket-mode "0660" \
    --relay "wss://relay.example" \
    --quic-candidate "quic://127.0.0.1:4433" \
    --print-env

[ -f "$dev_root/env.sh" ]
[ -x "$dev_root/run-dm-agent.sh" ]
[ -x "$dev_root/run-hermes-gateway.sh" ]
[ -x "$dev_root/start-dm-agent.sh" ]
[ -x "$dev_root/start-hermes-gateway.sh" ]
[ -x "$dev_root/stop-dev-processes.sh" ]
[ -x "$dev_root/smoke-plugin.sh" ]
[ -x "$dev_root/e2e-deterministic.sh" ]
[ -x "$dev_root/e2e-connector.sh" ]
[ -x "$dev_root/bootstrap-agent.sh" ]
[ -L "$dev_root/hermes-home/plugins/marmot" ]

# shellcheck disable=SC1091
source "$dev_root/env.sh"

[ "$HERMES_HOME" = "$dev_root/hermes-home" ]
[ "$MARMOT_HOME" = "$dev_root/marmot-agent-home" ]
[ "$MARMOT_AGENT_SOCKET" = "$dev_root/marmot-agent-home/dev/dm-agent.sock" ]
[ "$MARMOT_AGENT_AUTH_TOKEN_FILE" = "$dev_root/control.token" ]
[ "$MARMOT_AGENT_SOCKET_DIR_MODE" = "0770" ]
[ "$MARMOT_AGENT_SOCKET_MODE" = "0660" ]
[ "$MARMOT_ACCOUNT_ID_HEX" = "$account_id" ]
[ "$MARMOT_GROUP_ID_HEX" = "$group_id" ]
[ "$MARMOT_RELAYS" = "wss://relay.example" ]
[ "$MARMOT_QUIC_CANDIDATES" = "quic://127.0.0.1:4433" ]
[ "$(cat "$MARMOT_AGENT_AUTH_TOKEN_FILE")" = "script-token" ]
[ "${dm_agent_relay_args[0]}" = "--relay" ]
[ "${dm_agent_relay_args[1]}" = "wss://relay.example" ]

"$repo_root/scripts/hermes_marmot_dev_teardown.sh" --root "$dev_root" --dry-run
[ -d "$dev_root" ]
"$repo_root/scripts/hermes_marmot_dev_teardown.sh" --root "$dev_root" --force
[ ! -e "$dev_root" ]

unset MARMOT_AGENT_AUTH_TOKEN
unset MARMOT_AGENT_AUTH_TOKEN_FILE
unset MARMOT_AGENT_SOCKET_DIR_MODE
unset MARMOT_AGENT_SOCKET_MODE
default_root="$tmp_parent/defaults/hermes-marmot-test"
"$repo_root/scripts/hermes_marmot_dev_setup.sh" \
    --root "$default_root" \
    --skip-hermes-install

# shellcheck disable=SC1091
source "$default_root/env.sh"

[ "$MARMOT_QUIC_CANDIDATES" = "" ]
[ "$MARMOT_AGENT_AUTH_TOKEN_FILE" = "" ]
[ "$MARMOT_AGENT_SOCKET_DIR_MODE" = "0700" ]
[ "$MARMOT_AGENT_SOCKET_MODE" = "0600" ]
[ "$MARMOT_RELAYS" = "" ]
[ "${#dm_agent_relay_args[@]}" -eq 0 ]
"$repo_root/scripts/hermes_marmot_dev_teardown.sh" --root "$default_root" --force
[ ! -e "$default_root" ]

[ -x "$repo_root/scripts/install-hermes-marmot.sh" ]
"$repo_root/scripts/install-hermes-marmot.sh" --dry-run >/dev/null

echo "dev script test passed"
