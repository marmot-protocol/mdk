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
[ -L "$dev_root/hermes-home/plugins/marmot" ]

# shellcheck disable=SC1091
source "$dev_root/env.sh"

[ "$HERMES_HOME" = "$dev_root/hermes-home" ]
[ "$MARMOT_HOME" = "$dev_root/marmot-agent-home" ]
[ "$MARMOT_AGENT_SOCKET" = "$dev_root/marmot-agent-home/dev/dm-agent.sock" ]
[ "$MARMOT_ACCOUNT_ID_HEX" = "$account_id" ]
[ "$MARMOT_GROUP_ID_HEX" = "$group_id" ]
[ "$MARMOT_QUIC_CANDIDATES" = "quic://127.0.0.1:4433" ]
[ "${dm_agent_relay_args[0]}" = "--relay" ]
[ "${dm_agent_relay_args[1]}" = "wss://relay.example" ]

"$repo_root/scripts/hermes_marmot_dev_teardown.sh" --root "$dev_root" --dry-run
[ -d "$dev_root" ]
"$repo_root/scripts/hermes_marmot_dev_teardown.sh" --root "$dev_root" --force
[ ! -e "$dev_root" ]

default_root="$tmp_parent/defaults/hermes-marmot-test"
"$repo_root/scripts/hermes_marmot_dev_setup.sh" \
    --root "$default_root" \
    --skip-hermes-install

# shellcheck disable=SC1091
source "$default_root/env.sh"

[ "$MARMOT_QUIC_CANDIDATES" = "" ]
[ "${#dm_agent_relay_args[@]}" -eq 0 ]
"$repo_root/scripts/hermes_marmot_dev_teardown.sh" --root "$default_root" --force
[ ! -e "$default_root" ]

echo "dev script test passed"
