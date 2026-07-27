#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
installer="$repo_root/scripts/install-hermes-marmot.sh"
configure_gateway="$repo_root/scripts/hermes_marmot_configure_gateway.py"
integration_plugin="$repo_root/integrations/hermes/marmot"
e2e_gateway_auth="$repo_root/integrations/hermes/marmot/tests/e2e_gateway_auth.py"
user_a="$(printf '11%.0s' {1..32})"
user_b="$(printf '22%.0s' {1..32})"
user_c="$(printf '33%.0s' {1..32})"
user_unknown="$(printf '44%.0s' {1..32})"

[ -f "$installer" ]
[ -f "$configure_gateway" ]
bash -n "$installer"

fixture_root="$(mktemp -d)"
trap 'rm -rf "$fixture_root"' EXIT
mock_bin="$fixture_root/mock-bin"
mkdir -p "$mock_bin"
curl_log="$fixture_root/curl.log"
: >"$curl_log"

cat >"$mock_bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
destination=""
url=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) destination="$2"; shift 2 ;;
        http*) url="$1"; shift ;;
        *) shift ;;
    esac
done
printf '%s\n' "$url" >>"${CURL_LOG:?}"
if [[ "$url" == *.sha256 ]]; then
    printf '%s\n' fixture-hash >"$destination"
else
    : >"$destination"
fi
EOF

cat >"$mock_bin/shasum" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' fixture-hash
EOF

cat >"$mock_bin/tar" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
archive=""
destination=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -xzf) archive="$2"; shift 2 ;;
        -C) destination="$2"; shift 2 ;;
        *) shift ;;
    esac
done
archive_name="$(basename "$archive")"
case "$archive_name" in
    wn-agent-*)
        platform="${archive_name#wn-agent-}"
        platform="${platform%-9.9.9.tar.gz}"
        output_dir="$destination/wn-agent-$platform"
        mkdir -p "$output_dir"
        cat >"$output_dir/wn-agent" <<'SCRIPT'
#!/usr/bin/env bash
if [ "${1:-}" = bootstrap ]; then
    printf '%s\n' '{"account_id_hex":"aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4","welcomer_account_ids_hex":["bb"]}'
fi
SCRIPT
        chmod +x "$output_dir/wn-agent"
        ;;
    hermes-marmot-plugin-*)
        plugin_dir="$destination/hermes-marmot-plugin"
        mkdir -p "$plugin_dir"
        cp "$INTEGRATION_PLUGIN_SOURCE/__init__.py" \
            "$INTEGRATION_PLUGIN_SOURCE/adapter.py" \
            "$INTEGRATION_PLUGIN_SOURCE/plugin.yaml" \
            "$plugin_dir/"
        cp "$CONFIGURE_GATEWAY_SOURCE" "$plugin_dir/configure_gateway.py"
        ;;
    *)
        echo "unexpected archive: $archive_name" >&2
        exit 1
        ;;
esac
EOF

cat >"$mock_bin/hermes" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat >"$mock_bin/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$mock_bin"/*

scrub_marmot_env_python() {
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
subprocess.run(args, env=env, check=True)
PY
}

run_installer() {
    local case_root="$1"
    shift
    mkdir -p "$case_root"
    : >"$case_root/systemctl.log"
    : >"$curl_log"
    scrub_marmot_env_python \
        --env "CURL_LOG=$curl_log" \
        --env "SYSTEMCTL_LOG=$case_root/systemctl.log" \
        --env "CONFIGURE_GATEWAY_SOURCE=$configure_gateway" \
        --env "INTEGRATION_PLUGIN_SOURCE=$integration_plugin" \
        --env "HOME=$case_root/home" \
        --env "HERMES_HOME=$case_root/hermes-home" \
        --env "MARMOT_HOME=$case_root/marmot-home" \
        --env "MARMOT_INSTALL_PREFIX=$case_root/install" \
        --env "PATH=$mock_bin:/usr/bin:/bin" \
        --env "WN_AGENT_SHA=9.9.9" \
        --env "MARMOT_RELEASE_TAG=wn-agent-v9.9.9-test" \
        "$installer" --yes --no-service "$@"
}

run_streamed_installer() {
    local case_root="$1"
    shift
    mkdir -p "$case_root"
    : >"$case_root/systemctl.log"
    : >"$curl_log"
    CURL_LOG="$curl_log" python3 - "$installer" "$case_root" "$configure_gateway" "$integration_plugin" "$mock_bin" "$@" <<'PY'
import os
import subprocess
import sys
from pathlib import Path

installer = Path(sys.argv[1])
case_root = sys.argv[2]
configure_gateway = sys.argv[3]
integration_plugin = sys.argv[4]
mock_bin = sys.argv[5]
extra_args = sys.argv[6:]

env = {key: value for key, value in os.environ.items() if not key.startswith("MARMOT_")}
env.update(
    {
        "CURL_LOG": os.environ["CURL_LOG"],
        "SYSTEMCTL_LOG": f"{case_root}/systemctl.log",
        "CONFIGURE_GATEWAY_SOURCE": configure_gateway,
        "INTEGRATION_PLUGIN_SOURCE": integration_plugin,
        "HOME": f"{case_root}/home",
        "HERMES_HOME": f"{case_root}/hermes-home",
        "MARMOT_HOME": f"{case_root}/marmot-home",
        "MARMOT_INSTALL_PREFIX": f"{case_root}/install",
        "PATH": f"{mock_bin}:/usr/bin:/bin",
        "WN_AGENT_SHA": "9.9.9",
        "MARMOT_RELEASE_TAG": "wn-agent-v9.9.9-test",
    }
)
completed = subprocess.run(
    ["bash", "-s", "--", "--yes", "--no-service", *extra_args],
    input=installer.read_text(encoding="utf-8"),
    env=env,
    text=True,
)
raise SystemExit(completed.returncode)
PY
}

assert_env_contains() {
    local env_file="$1"
    local expected="$2"
    if ! grep -Fq "$expected" "$env_file"; then
        echo "missing expected managed env assignment: $expected" >&2
        if ! grep -Eq '^(export[[:space:]]+)?MARMOT_(ALLOWED_USERS|ALLOW_ALL_USERS)=' "$env_file"; then
            echo "no managed Marmot authorization keys present" >&2
        fi
        return 1
    fi
}

assert_curl_not_called() {
    if [ -s "$curl_log" ]; then
        echo "expected installer to fail before download, but curl was invoked" >&2
        return 1
    fi
}

case_root="$fixture_root/fresh-install"
run_installer "$case_root" --allow-user "$user_a"
env_file="$case_root/hermes-home/.env"
[ -f "$env_file" ]
assert_env_contains "$env_file" "MARMOT_ALLOWED_USERS=$user_a"
assert_env_contains "$env_file" "MARMOT_ALLOW_ALL_USERS=false"

case_root="$fixture_root/reinstall-union"
run_installer "$case_root" --allow-user "$user_a"
env_file="$case_root/hermes-home/.env"
printf '%s\n' \
    "# unrelated" \
    "OPENAI_API_KEY=secret" \
    >"$case_root/hermes-home/.env.prelude"
cat "$env_file" >>"$case_root/hermes-home/.env.prelude"
mv "$case_root/hermes-home/.env.prelude" "$env_file"
run_installer "$case_root" --allow-user "$user_b"
assert_env_contains "$env_file" "MARMOT_ALLOWED_USERS=$user_a,$user_b"
assert_env_contains "$env_file" "OPENAI_API_KEY=secret"
assert_env_contains "$env_file" "MARMOT_ALLOW_ALL_USERS=false"

case_root="$fixture_root/reinstall-idempotent"
run_installer "$case_root" --allow-user "$user_a"
env_file="$case_root/hermes-home/.env"
before="$(cat "$env_file")"
run_installer "$case_root" --allow-user "$user_a"
after="$(cat "$env_file")"
[ "$before" = "$after" ]

case_root="$fixture_root/reinstall-preserve-without-args"
run_installer "$case_root" --allow-user "$user_a"
env_file="$case_root/hermes-home/.env"
before="$(cat "$env_file")"
run_installer "$case_root"
after="$(cat "$env_file")"
[ "$before" = "$after" ]

case_root="$fixture_root/ambient-env-ignored"
run_installer "$case_root" --allow-user "$user_a"
env_file="$case_root/hermes-home/.env"
scrub_marmot_env_python \
    --env "MARMOT_ALLOWED_USERS=$user_b" \
    --env "MARMOT_ALLOW_ALL_USERS=true" \
    --env "CURL_LOG=$curl_log" \
    --env "SYSTEMCTL_LOG=$case_root/systemctl.log" \
    --env "CONFIGURE_GATEWAY_SOURCE=$configure_gateway" \
    --env "INTEGRATION_PLUGIN_SOURCE=$integration_plugin" \
    --env "HOME=$case_root/home" \
    --env "HERMES_HOME=$case_root/hermes-home" \
    --env "MARMOT_HOME=$case_root/marmot-home" \
    --env "MARMOT_INSTALL_PREFIX=$case_root/install" \
    --env "PATH=$mock_bin:/usr/bin:/bin" \
    --env "WN_AGENT_SHA=9.9.9" \
    --env "MARMOT_RELEASE_TAG=wn-agent-v9.9.9-test" \
    "$installer" --yes --no-service --allow-user "$user_c" >/dev/null
assert_env_contains "$env_file" "MARMOT_ALLOWED_USERS=$user_a,$user_c"
assert_env_contains "$env_file" "MARMOT_ALLOW_ALL_USERS=false"

case_root="$fixture_root/malformed-existing"
mkdir -p "$case_root/hermes-home"
printf '%s\n' "MARMOT_ALLOWED_USERS=not-a-valid-user" >"$case_root/hermes-home/.env"
malformed_status=0
run_installer "$case_root" --allow-user "$user_a" >/dev/null 2>&1 || malformed_status=$?
[ "$malformed_status" -ne 0 ]
[ "$(cat "$case_root/hermes-home/.env")" = "MARMOT_ALLOWED_USERS=not-a-valid-user" ]

case_root="$fixture_root/malformed-explicit"
malformed_explicit_status=0
run_installer "$case_root" --allow-user "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" >/dev/null 2>&1 || malformed_explicit_status=$?
[ "$malformed_explicit_status" -ne 0 ]
[ ! -f "$case_root/hermes-home/.env" ]

case_root="$fixture_root/streamed-malformed-npub"
streamed_bad_status=0
run_streamed_installer "$case_root" --allow-user "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" >/dev/null 2>&1 || streamed_bad_status=$?
[ "$streamed_bad_status" -ne 0 ]
assert_curl_not_called
[ ! -f "$case_root/hermes-home/.env" ]
[ ! -d "$case_root/hermes-home/plugins/marmot" ]

case_root="$fixture_root/streamed-blank-allow-user"
streamed_blank_status=0
run_streamed_installer "$case_root" --allow-user "   " >/dev/null 2>&1 || streamed_blank_status=$?
[ "$streamed_blank_status" -ne 0 ]
assert_curl_not_called
[ ! -f "$case_root/hermes-home/.env" ]

case_root="$fixture_root/guided-no-continues"
mkdir -p "$case_root"
guided_log="$case_root/guided.log"
if command -v script >/dev/null 2>&1 \
    && command -v timeout >/dev/null 2>&1 \
    && script --version 2>&1 | grep -qi 'util-linux'; then
    guided_status=0
    printf '\n\n\nn\nn\n%s\n\n' "$user_a" | timeout 10s script -qefc \
        "env -i HOME='$case_root/home' HERMES_HOME='$case_root/hermes-home' PATH=/usr/bin:/bin WN_AGENT_SHA=9.9.9 MARMOT_RELEASE_TAG=wn-agent-v9.9.9-test bash '$installer' --dry-run --hermes-home '$case_root/hermes-home' --allow-welcomer '$user_a'" \
        /dev/null >"$guided_log" 2>&1 || guided_status=$?
    if [ "$guided_status" -ne 0 ]; then
        echo "guided prompt integration failed with status $guided_status; captured log:" >&2
        cat "$guided_log" >&2
        exit 1
    fi
    if ! grep -Fq "Allow Marmot messages from any sender?" "$guided_log"; then
        echo "guided prompt output missing; captured log:" >&2
        cat "$guided_log" >&2
        exit 1
    fi
else
    echo "skip: guided prompt integration (util-linux script(1) and timeout required)"
fi

case_root="$fixture_root/allow-all-users"
run_installer "$case_root" --allow-all-users
env_file="$case_root/hermes-home/.env"
[ -f "$env_file" ]
assert_env_contains "$env_file" "MARMOT_ALLOW_ALL_USERS=true"

case_root="$fixture_root/streamed-reinstall-preserves-existing-auth"
mkdir -p "$case_root/hermes-home"
env_file="$case_root/hermes-home/.env"
printf '%s\n' \
    "MARMOT_ALLOWED_USERS=$user_a" \
    "MARMOT_ALLOW_ALL_USERS=false" \
    >"$env_file"
before="$(cat "$env_file")"
run_streamed_installer "$case_root" --force
after_first="$(cat "$env_file")"
run_streamed_installer "$case_root" --force
after_second="$(cat "$env_file")"
[ "$before" = "$after_first" ]
[ "$before" = "$after_second" ]

case_root="$fixture_root/fresh-streamed-fail-early"
fresh_status=0
run_streamed_installer "$case_root" >/dev/null 2>&1 || fresh_status=$?
[ "$fresh_status" -ne 0 ]
assert_curl_not_called

case_root="$fixture_root/upgrade-legacy-helper"
mkdir -p "$case_root/hermes-home/plugins/marmot"
cat >"$case_root/hermes-home/plugins/marmot/configure_gateway.py" <<'PY'
#!/usr/bin/env python3
import sys
if "--configure-env" in sys.argv:
    print("error: unrecognized arguments: --configure-env", file=sys.stderr)
    raise SystemExit(2)
raise SystemExit(0)
PY
chmod +x "$case_root/hermes-home/plugins/marmot/configure_gateway.py"
run_streamed_installer "$case_root" --allow-user "$user_a" --force
env_file="$case_root/hermes-home/.env"
[ -f "$env_file" ]
assert_env_contains "$env_file" "MARMOT_ALLOWED_USERS=$user_a"
python3 "$case_root/hermes-home/plugins/marmot/configure_gateway.py" \
    --configure-env --env-dry-run --home "$case_root/hermes-home" --quiet --allow-user "$user_a"

hermes_repo="${HERMES_AGENT_REPO:-}"
if [ -n "$hermes_repo" ] && [ -x "$hermes_repo/.venv/bin/hermes" ] && [ -x "$hermes_repo/.venv/bin/python" ]; then
    case_root="$fixture_root/real-hermes-gateway-auth"
    run_installer "$case_root" --allow-user "$user_a"
    env_file="$case_root/hermes-home/.env"
    [ -f "$env_file" ]
    env -i \
        HOME="$case_root/home" \
        HERMES_HOME="$case_root/hermes-home" \
        PATH="$hermes_repo/.venv/bin:/usr/bin:/bin" \
        "$hermes_repo/.venv/bin/hermes" plugins enable marmot >/dev/null
    auth_output="$(
        cd "$hermes_repo"
        env -i \
            HOME="$case_root/home" \
            HERMES_HOME="$case_root/hermes-home" \
            PATH="/usr/bin:/bin" \
            MARMOT_TEST_ALLOWED_USER_HEX="$user_a" \
            MARMOT_TEST_UNKNOWN_USER_HEX="$user_unknown" \
        "$hermes_repo/.venv/bin/python" "$e2e_gateway_auth"
    )"
    case "$auth_output" in
        *"allowed=true"*"unknown=false"*) echo "real Hermes gateway auth: $auth_output" ;;
        *)
            echo "unexpected real Hermes gateway auth output: $auth_output" >&2
            exit 1
            ;;
    esac
else
    echo "skip: real Hermes gateway authorization E2E (set HERMES_AGENT_REPO to an isolated checkout with .venv/bin/hermes)"
fi

echo "installer env test passed"
