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
[ -x "$dev_root/run-wn-agent.sh" ]
[ -x "$dev_root/run-hermes-gateway.sh" ]
[ -x "$dev_root/start-wn-agent.sh" ]
[ -x "$dev_root/start-hermes-gateway.sh" ]
[ -x "$dev_root/stop-dev-processes.sh" ]
[ -x "$dev_root/smoke-plugin.sh" ]
[ -x "$dev_root/e2e-deterministic.sh" ]
[ -x "$dev_root/e2e-connector.sh" ]
[ -x "$dev_root/bootstrap-agent.sh" ]
[ -L "$dev_root/hermes-home/plugins/marmot" ]

for helper in \
    "$dev_root/run-wn-agent.sh" \
    "$dev_root/run-hermes-gateway.sh" \
    "$dev_root/start-wn-agent.sh" \
    "$dev_root/start-hermes-gateway.sh" \
    "$dev_root/stop-dev-processes.sh" \
    "$dev_root/smoke-plugin.sh" \
    "$dev_root/e2e-deterministic.sh" \
    "$dev_root/e2e-connector.sh" \
    "$dev_root/bootstrap-agent.sh"; do
    bash -n "$helper"
done

# shellcheck disable=SC1091
source "$dev_root/env.sh"

[ "$HERMES_HOME" = "$dev_root/hermes-home" ]
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
[ "${#wn_agent_relay_args[@]}" -eq 0 ]
[ "${#wn_agent_quic_args[@]}" -eq 0 ]
"$repo_root/scripts/hermes_marmot_dev_teardown.sh" --root "$default_root" --force
[ ! -e "$default_root" ]

[ -x "$repo_root/scripts/install-hermes-marmot.sh" ]
installer_dry_run="$(
    WN_AGENT_SHA="9.9.9" \
    MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
    "$repo_root/scripts/install-hermes-marmot.sh" --dry-run --yes
)"
installer_stdin_dry_run="$(
    WN_AGENT_SHA="9.9.9" \
    MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
    bash -s -- --dry-run --yes < "$repo_root/scripts/install-hermes-marmot.sh"
)"
installer_bad_welcomer_status=0
WN_AGENT_SHA="9.9.9" \
    MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
    "$repo_root/scripts/install-hermes-marmot.sh" --dry-run --yes --allow-welcomer not-a-key \
    >/dev/null 2>&1 || installer_bad_welcomer_status=$?
[ "$installer_bad_welcomer_status" -ne 0 ]
case "$installer_dry_run" in
    *"wn-agent-"*"9.9.9.tar.gz"* ) ;;
    *) echo "Hermes installer dry-run did not use WN_AGENT_SHA asset suffix" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"hermes-marmot-plugin-9.9.9.tar.gz"* ) ;;
    *) echo "Hermes installer dry-run did not use expected plugin asset" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"wn-agent-v9.9.9-test"* ) ;;
    *) echo "Hermes installer dry-run did not use requested release tag" >&2; exit 1;;
esac
case "$installer_stdin_dry_run" in
    *"wn-agent-"*"9.9.9.tar.gz"* ) ;;
    *) echo "Hermes installer stdin dry-run did not use WN_AGENT_SHA asset suffix" >&2; exit 1;;
esac
case "$installer_stdin_dry_run" in
    *"hermes-marmot-plugin-9.9.9.tar.gz"* ) ;;
    *) echo "Hermes installer stdin dry-run did not use expected plugin asset" >&2; exit 1;;
esac
case "$installer_stdin_dry_run" in
    *"wn-agent-v9.9.9-test"* ) ;;
    *) echo "Hermes installer stdin dry-run did not use requested release tag" >&2; exit 1;;
esac

echo "dev script test passed"
