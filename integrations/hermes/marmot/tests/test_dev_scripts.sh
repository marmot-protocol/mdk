#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
tmp_parent="$(mktemp -d)"
trap 'rm -rf "$tmp_parent"' EXIT

dev_root="$tmp_parent/nested/hermes-marmot-test"
account_id="$(printf '11%.0s' {1..32})"
group_id="$(printf '22%.0s' {1..32})"

# Exercise GitHub smart-HTTP authentication without network access. The fake
# git verifies the scoped config environment on both clone and fetch; fake uv
# lets the setup finish without constructing a real Hermes environment.
auth_fake_bin="$tmp_parent/auth-fake-bin"
auth_capture="$tmp_parent/github-auth-capture"
mkdir -p "$auth_fake_bin"
cat >"$auth_fake_bin/git" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

capture_auth() {
    printf 'count=%s\nkey=%s\nvalue=%s\n' \
        "${GIT_CONFIG_COUNT:-}" \
        "${GIT_CONFIG_KEY_0:-}" \
        "${GIT_CONFIG_VALUE_0:-}" >>"$AUTH_CAPTURE"
}

case " $* " in
    *" clone "*)
        capture_auth
        dest="${@: -1}"
        mkdir -p "$dest/.git"
        ;;
    *" fetch "*)
        capture_auth
        ;;
esac
SCRIPT
cat >"$auth_fake_bin/uv" <<'SCRIPT'
#!/usr/bin/env bash
if [ -n "${UV_CAPTURE:-}" ]; then
    printf '%s\n' "$*" >>"$UV_CAPTURE"
fi
exit 0
SCRIPT
chmod +x "$auth_fake_bin/git" "$auth_fake_bin/uv"

auth_dev_root="$tmp_parent/github-auth"
env \
    PATH="$auth_fake_bin:$PATH" \
    GITHUB_TOKEN="test-actions-token" \
    AUTH_CAPTURE="$auth_capture" \
    "$repo_root/scripts/hermes_marmot_dev_setup.sh" \
        --root "$auth_dev_root" \
        --hermes-ref "test-ref" \
        --no-enable-plugin
expected_basic="$(printf 'x-access-token:%s' 'test-actions-token' | base64 | tr -d '\r\n')"
[ "$(grep -Fxc 'count=1' "$auth_capture")" -eq 2 ]
[ "$(grep -Fxc 'key=http.https://github.com/.extraheader' "$auth_capture")" -eq 2 ]
[ "$(grep -Fxc "value=AUTHORIZATION: basic $expected_basic" "$auth_capture")" -eq 2 ]
if grep -F 'test-actions-token' "$auth_capture" >/dev/null; then
    echo "raw GitHub token leaked into git configuration" >&2
    exit 1
fi

# The required CI path installs the released, hash-pinned wheel and must not
# contact GitHub for a source checkout.
wheel_dev_root="$tmp_parent/pinned-wheel"
wheel_capture="$tmp_parent/pinned-wheel-uv-capture"
env \
    PATH="$auth_fake_bin:$PATH" \
    UV_CAPTURE="$wheel_capture" \
    "$repo_root/scripts/hermes_marmot_dev_setup.sh" \
        --root "$wheel_dev_root" \
        --install-pinned-wheel \
        --no-enable-plugin
[ -d "$wheel_dev_root/hermes-agent" ]
[ ! -e "$wheel_dev_root/hermes-agent/.git" ]
grep -F 'venv .venv --python 3.11' "$wheel_capture" >/dev/null
grep -F 'hermes-agent[all,dev] @ https://files.pythonhosted.org/' "$wheel_capture" >/dev/null
grep -F '#sha256=' "$wheel_capture" >/dev/null
if grep -F 'pip install -e ' "$wheel_capture" >/dev/null; then
    echo "pinned wheel install unexpectedly used editable mode" >&2
    exit 1
fi

# Pinned-wheel installs must not silently ignore an explicit source ref.
ref_conflict_stderr="$tmp_parent/pinned-wheel-ref-conflict.stderr"
if env \
    PATH="$auth_fake_bin:$PATH" \
    HERMES_AGENT_REF="test-ref" \
    "$repo_root/scripts/hermes_marmot_dev_setup.sh" \
        --root "$tmp_parent/pinned-wheel-ref-conflict" \
        --install-pinned-wheel \
        --no-enable-plugin 2>"$ref_conflict_stderr"; then
    echo "pinned wheel install accepted an explicit Hermes ref" >&2
    exit 1
fi
grep -F -- '--install-pinned-wheel cannot be combined with an explicit Hermes ref' \
    "$ref_conflict_stderr" >/dev/null

# A stale wheel URL must fail before CI can validate a different Hermes version
# than the source-oriented lock fields describe.
drift_repo="$tmp_parent/wheel-version-drift-repo"
mkdir -p "$drift_repo/scripts" "$drift_repo/integrations/hermes/marmot"
cp "$repo_root/scripts/hermes_marmot_dev_setup.sh" "$drift_repo/scripts/"
cp "$repo_root/integrations/hermes/marmot/hermes-agent.lock" \
    "$drift_repo/integrations/hermes/marmot/hermes-agent.lock"
sed 's/^HERMES_AGENT_VERSION=.*/HERMES_AGENT_VERSION=version-drift-test/' \
    "$drift_repo/integrations/hermes/marmot/hermes-agent.lock" \
    >"$drift_repo/integrations/hermes/marmot/hermes-agent.lock.tmp"
mv "$drift_repo/integrations/hermes/marmot/hermes-agent.lock.tmp" \
    "$drift_repo/integrations/hermes/marmot/hermes-agent.lock"
drift_stderr="$tmp_parent/wheel-version-drift.stderr"
if env \
    PATH="$auth_fake_bin:$PATH" \
    "$drift_repo/scripts/hermes_marmot_dev_setup.sh" \
        --root "$tmp_parent/wheel-version-drift" \
        --install-pinned-wheel \
        --no-enable-plugin 2>"$drift_stderr"; then
    echo "pinned wheel install accepted a URL for the wrong Hermes version" >&2
    exit 1
fi
grep -F 'pinned Hermes wheel URL does not match HERMES_AGENT_VERSION' \
    "$drift_stderr" >/dev/null

# A pinned commit already present in a successful full clone must be checked
# out locally instead of making a redundant fetch. This keeps the CI setup from
# failing when GitHub rate-limits a second request immediately after the clone.
local_ref_capture="$tmp_parent/github-local-ref-capture"
local_ref_root="$tmp_parent/github-local-ref"
env \
    PATH="$auth_fake_bin:$PATH" \
    GITHUB_TOKEN="test-actions-token" \
    AUTH_CAPTURE="$local_ref_capture" \
    "$repo_root/scripts/hermes_marmot_dev_setup.sh" \
        --root "$local_ref_root" \
        --hermes-ref "$(printf 'ab%.0s' {1..20})" \
        --no-enable-plugin
[ "$(grep -c '^count=' "$local_ref_capture")" -eq 1 ]
[ "$(grep -Fxc 'count=1' "$local_ref_capture")" -eq 1 ]
[ "$(grep -Fxc 'key=http.https://github.com/.extraheader' "$local_ref_capture")" -eq 1 ]
[ "$(grep -Fxc "value=AUTHORIZATION: basic $expected_basic" "$local_ref_capture")" -eq 1 ]

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
[ -x "$dev_root/verify-persisted-config.sh" ]
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
    "$dev_root/verify-persisted-config.sh" \
    "$dev_root/bootstrap-agent.sh"; do
    bash -n "$helper"
done
grep -F 'hermes_marmot_verify_persisted_config.sh" "$@" --root "$dev_root"' \
    "$dev_root/verify-persisted-config.sh" >/dev/null

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
allowed_sender_hex="$(printf 'aa%.0s' {1..32})"
installer_hermes_home="$tmp_parent/hermes-install-home"
mkdir -p "$installer_hermes_home"

run_installer_scrubbed() {
    python3 - "$@" <<'PY'
import os
import subprocess
import sys

extra = {}
args = sys.argv[1:]
while args and args[0] == "--env":
    args.pop(0)
    key, value = args.pop(0).split("=", 1)
    extra[key] = value

env = {key: value for key, value in os.environ.items() if not key.startswith("MARMOT_")}
env.update(extra)
completed = subprocess.run(args, env=env, capture_output=True, text=True)
sys.stdout.write(completed.stdout)
sys.stderr.write(completed.stderr)
raise SystemExit(completed.returncode)
PY
}

"$repo_root/integrations/test_installer_systemd_service.sh" hermes
installer_dry_run="$(
    run_installer_scrubbed \
        --env "WN_AGENT_SHA=9.9.9" \
        --env "MARMOT_RELEASE_TAG=wn-agent-v9.9.9-test" \
        --env "HERMES_HOME=$installer_hermes_home" \
        "$repo_root/scripts/install-hermes-marmot.sh" --dry-run --yes --allow-user "$allowed_sender_hex"
)"
installer_stdin_dry_run="$(
    python3 - "$repo_root/scripts/install-hermes-marmot.sh" "$allowed_sender_hex" "$installer_hermes_home" <<'PY'
import os
import subprocess
import sys
from pathlib import Path

installer = Path(sys.argv[1])
allowed_sender_hex = sys.argv[2]
installer_hermes_home = sys.argv[3]
env = {key: value for key, value in os.environ.items() if not key.startswith("MARMOT_")}
env.update(
    {
        "WN_AGENT_SHA": "9.9.9",
        "MARMOT_RELEASE_TAG": "wn-agent-v9.9.9-test",
        "HERMES_HOME": installer_hermes_home,
    }
)
completed = subprocess.run(
    [
        "bash",
        "-s",
        "--",
        "--dry-run",
        "--yes",
        "--allow-user",
        allowed_sender_hex,
    ],
    input=installer.read_text(encoding="utf-8"),
    capture_output=True,
    text=True,
    env=env,
)
sys.stdout.write(completed.stdout)
sys.stderr.write(completed.stderr)
raise SystemExit(completed.returncode)
PY
)"
identity_secret="nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99"
identity_file="$tmp_parent/hermes-agent.nsec"
printf '%s\n' "$identity_secret" > "$identity_file"
chmod 0600 "$identity_file"
expected_identity="$(printf '11%.0s' {1..32})"
installer_existing_identity_dry_run="$(
    run_installer_scrubbed \
        --env "WN_AGENT_SHA=9.9.9" \
        --env "MARMOT_RELEASE_TAG=wn-agent-v9.9.9-test" \
        --env "HERMES_HOME=$installer_hermes_home" \
    "$repo_root/scripts/install-hermes-marmot.sh" --dry-run --yes \
        --existing-identity-file "$identity_file" \
        --expected-npub "$expected_identity" \
        --allow-user "$allowed_sender_hex"
)"
installer_generated_identity_dry_run="$(
    run_installer_scrubbed \
        --env "WN_AGENT_SHA=9.9.9" \
        --env "MARMOT_RELEASE_TAG=wn-agent-v9.9.9-test" \
        --env "HERMES_HOME=$installer_hermes_home" \
        "$repo_root/scripts/install-hermes-marmot.sh" --dry-run --yes \
        --generate-identity --allow-user "$allowed_sender_hex"
)"
installer_bad_welcomer_status=0
run_installer_scrubbed \
    --env "WN_AGENT_SHA=9.9.9" \
    --env "MARMOT_RELEASE_TAG=wn-agent-v9.9.9-test" \
    --env "HERMES_HOME=$installer_hermes_home" \
    "$repo_root/scripts/install-hermes-marmot.sh" --dry-run --yes --allow-welcomer not-a-key \
    >/dev/null 2>&1 || installer_bad_welcomer_status=$?
installer_missing_sender_status=0
run_installer_scrubbed \
    --env "WN_AGENT_SHA=9.9.9" \
    --env "MARMOT_RELEASE_TAG=wn-agent-v9.9.9-test" \
    --env "HERMES_HOME=$installer_hermes_home" \
    "$repo_root/scripts/install-hermes-marmot.sh" --dry-run --yes \
    >/dev/null 2>&1 || installer_missing_sender_status=$?
[ "$installer_bad_welcomer_status" -ne 0 ]
installer_identity_conflict_status=0
run_installer_scrubbed \
    --env "WN_AGENT_SHA=9.9.9" \
    --env "MARMOT_RELEASE_TAG=wn-agent-v9.9.9-test" \
    --env "HERMES_HOME=$installer_hermes_home" \
    "$repo_root/scripts/install-hermes-marmot.sh" --dry-run --yes --generate-identity \
    --existing-identity-file "$identity_file" --allow-user "$allowed_sender_hex" \
    >/dev/null 2>&1 || installer_identity_conflict_status=$?
[ "$installer_identity_conflict_status" -ne 0 ]
installer_expected_without_source_status=0
run_installer_scrubbed \
    --env "WN_AGENT_SHA=9.9.9" \
    --env "MARMOT_RELEASE_TAG=wn-agent-v9.9.9-test" \
    --env "HERMES_HOME=$installer_hermes_home" \
    "$repo_root/scripts/install-hermes-marmot.sh" --dry-run --yes \
    --expected-npub "$expected_identity" --allow-user "$allowed_sender_hex" \
    >/dev/null 2>&1 || installer_expected_without_source_status=$?
[ "$installer_expected_without_source_status" -ne 0 ]
[ "$installer_missing_sender_status" -ne 0 ]
case "$installer_dry_run" in
    *"would configure Marmot message-sender authorization"* ) ;;
    *) echo "Hermes installer dry-run did not describe sender authorization" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"$allowed_sender_hex"* )
        echo "Hermes installer dry-run leaked sender identity" >&2
        exit 1
        ;;
esac
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
case "$installer_dry_run" in
    *"Marmot home: $HOME/.marmot-agents/hermes"* ) ;;
    *) echo "Hermes installer dry-run did not use isolated default Marmot home" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"Marmot socket: $HOME/.marmot-agents/hermes/dev/wn-agent.sock"* ) ;;
    *) echo "Hermes installer dry-run did not derive the socket from the isolated home" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"--label hermes-agent"* ) ;;
    *) echo "Hermes installer dry-run did not pass the Hermes bootstrap label" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"wn-agent-hermes.service"* | *"org.marmot.wn-agent.hermes.plist"* ) ;;
    *) echo "Hermes installer dry-run did not use the Hermes-specific service identity" >&2; exit 1;;
esac
if [ "$(uname -s)" = Linux ]; then
    case "$installer_dry_run" in
        *"would enable/start, or restart if already active, systemd user service: wn-agent-hermes.service"* ) ;;
        *) echo "Hermes installer dry-run did not describe active-service upgrade behavior" >&2; exit 1;;
    esac
fi
case "$installer_dry_run" in
    *"hermes gateway restart"* ) ;;
    *) echo "Hermes installer dry-run did not print gateway restart guidance" >&2; exit 1;;
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
case "$installer_stdin_dry_run" in
    *"Marmot home: $HOME/.marmot-agents/hermes"* ) ;;
    *) echo "Hermes installer stdin dry-run did not use isolated default Marmot home" >&2; exit 1;;
esac
case "$installer_stdin_dry_run" in
    *"--label hermes-agent"* ) ;;
    *) echo "Hermes installer stdin dry-run did not pass the Hermes bootstrap label" >&2; exit 1;;
esac
case "$installer_existing_identity_dry_run" in
    *"import-identity"*"--identity-file"*"$identity_file"*"--expected-identity"*"$expected_identity"* ) ;;
    *) echo "Hermes installer did not use the shared secure identity-import command" >&2; exit 1;;
esac
case "$installer_existing_identity_dry_run" in
    *"bootstrap"*"--no-create"*"--account-id-hex"* ) ;;
    *) echo "Hermes installer did not bootstrap the imported account with creation disabled" >&2; exit 1;;
esac
case "$installer_existing_identity_dry_run" in
    *"$identity_secret"* ) echo "Hermes installer output exposed identity secret material" >&2; exit 1;;
    *) ;;
esac
case "$installer_generated_identity_dry_run" in
    *"import-identity"* | *"--no-create"* ) echo "Hermes generated-identity path used existing-identity flags" >&2; exit 1;;
    *) ;;
esac

bash "$repo_root/integrations/hermes/marmot/tests/test_installer_env.sh"

echo "dev script test passed"
