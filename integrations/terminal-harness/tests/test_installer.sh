#!/usr/bin/env bash
set -euo pipefail

kind="${1:?usage: test_installer.sh codex|pi|opencode}"
case "$kind" in
    codex)
        env_prefix="WN_CODEX"
        display_name="Codex"
        default_home="$HOME/.marmot-agents/codex"
        agent_service="wn-agent-codex.service"
        agent_launchd="org.marmot.wn-agent.codex"
        agent_label="codex-harness-agent"
        ;;
    pi)
        env_prefix="WN_PI"
        display_name="Pi"
        default_home="$HOME/.marmot-agents/pi"
        agent_service="wn-agent-pi.service"
        agent_launchd="org.marmot.wn-agent.pi"
        agent_label="pi-harness-agent"
        ;;
    opencode)
        env_prefix="WN_OPENCODE"
        display_name="OpenCode"
        default_home="$HOME/.marmot-agents/harnesses"
        agent_service="wn-agent-harnesses.service"
        agent_launchd="org.marmot.wn-agent.harnesses"
        agent_label="terminal-harness-agent"
        ;;
    *) echo "unsupported harness: $kind" >&2; exit 64 ;;
esac
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
installer="$repo_root/scripts/install-$kind-marmot.sh"
shared_installer="$repo_root/scripts/install-terminal-harness-marmot.sh"
harness_binary="wn-$kind"
harness_service="$harness_binary.service"
bin_env="${env_prefix}_BIN"
allowed_env="${env_prefix}_ALLOWED_SENDERS_HEX"
timeout_env="${env_prefix}_TIMEOUT_SECS"
idle_timeout_env="${env_prefix}_IDLE_TIMEOUT_SECS"
request_timeout_env="${env_prefix}_REQUEST_TIMEOUT_SECS"
max_reply_env="${env_prefix}_MAX_REPLY_BYTES"
max_pending_env="${env_prefix}_MAX_PENDING_PER_GROUP"
profile_env="MARMOT_HARNESS_EXECUTION_PROFILE"
export "$bin_env=/bin/echo"
allow_hex="$(printf '11%.0s' {1..32})"
fixture_version="9.9.9"
export FIXTURE_VERSION="$fixture_version"

[ -x "$installer" ]
bash -n "$installer"
bash -n "$shared_installer"

assert_log_contains() {
    local log_file="$1"
    local expected="$2"
    local line
    while IFS= read -r line; do
        [ "$line" != "$expected" ] || return 0
    done <"$log_file"
    echo "missing systemctl call: $expected" >&2
    return 1
}

assert_log_excludes() {
    local log_file="$1"
    local unexpected="$2"
    local line
    while IFS= read -r line; do
        if [ "$line" = "$unexpected" ]; then
            echo "unexpected systemctl call: $unexpected" >&2
            return 1
        fi
    done <"$log_file"
}

stat_mode() {
    if stat -f %Lp "$1" >/dev/null 2>&1; then
        stat -f %Lp "$1"
    else
        stat -c %a "$1"
    fi
}

run_linux_service_case() {
    local fixture_root="$1"
    local active="$2"
    local log_file="$3"
    local mock_bin="$fixture_root/mock-bin"
    local output_file="$fixture_root/installer-output.log"
    shift 3

    : >"$log_file"
    SYSTEMCTL_ACTIVE="$active" \
    SYSTEMCTL_LOG="$log_file" \
    TEST_LEGACY_BOOTSTRAP="${TEST_LEGACY_BOOTSTRAP:-0}" \
    TEST_HARNESS_BINARY="$harness_binary" \
    HOME="$fixture_root/home" \
    MARMOT_HOME="$fixture_root/marmot-home" \
    MARMOT_INSTALL_PREFIX="$fixture_root/install" \
    PATH="$mock_bin:/usr/bin:/bin" \
    WN_AGENT_SHA="$fixture_version" \
    MARMOT_RELEASE_TAG="wn-agent-v$fixture_version-test" \
        "$installer" --yes --allow-welcomer "$allow_hex" "$@" >"$output_file" 2>&1 || {
        echo "installer failed for systemd scenario (log: $log_file)" >&2
        cat "$output_file" >&2
        return 1
    }
}

fixture_parent="$(mktemp -d)"
fixture_root="$fixture_parent/fixture root"
mkdir -p "$fixture_root"
trap 'rm -rf "$fixture_parent"' EXIT
mock_bin="$fixture_root/mock-bin"
mkdir -p "$mock_bin"

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
mode=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -xzf | -tzf) mode="$1"; archive="$2"; shift 2 ;;
        -C) destination="$2"; shift 2 ;;
        *) shift ;;
    esac
done
archive_name="$(basename "$archive")"
case "$archive_name" in
    wn-agent-*) binary=wn-agent ;;
    "$TEST_HARNESS_BINARY"-*) binary="$TEST_HARNESS_BINARY" ;;
    *) exit 1 ;;
esac
platform="${archive_name#"$binary-"}"
platform="${platform%-$FIXTURE_VERSION.tar.gz}"
if [ "$mode" = -tzf ]; then
    printf '%s\n' "$binary-$platform/$binary"
    if [ "${TEST_UNSAFE_ARCHIVE:-0}" = 1 ]; then
        printf '%s\n' '../escape'
    fi
    exit 0
fi
mkdir -p "$destination/$binary-$platform"
cat >"$destination/$binary-$platform/$binary" <<'SCRIPT'
#!/usr/bin/env bash
if [ "${1:-}" = bootstrap ]; then
    printf '%s\n' '{"account_id_hex":"aa","welcomer_account_ids_hex":["bb"],"npub":"npub-test","nprofile":"nprofile-test"}'
fi
SCRIPT
chmod +x "$destination/$binary-$platform/$binary"
EOF

cat >"$mock_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$SYSTEMCTL_LOG"
if [ "${1:-}" = --user ] && [ "${2:-}" = is-active ]; then
    [ "$SYSTEMCTL_ACTIVE" = 1 ]
fi
EOF

cat >"$mock_bin/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$mock_bin/uname" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
    -s) printf '%s\n' Linux ;;
    -m) printf '%s\n' x86_64 ;;
    *) printf '%s\n' Linux ;;
esac
EOF
cat >"$mock_bin/python3" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
code="${2:-}"
cat >/dev/null
case "$code" in
    *account_id_hex*) printf '%s\n' aa ;;
    *welcomer_account_ids_hex*) printf '%s\n' bb ;;
    *'json.load(sys.stdin).get("npub", "")'*)
        [ "${TEST_LEGACY_BOOTSTRAP:-0}" = 1 ] || printf '%s\n' npub-test
        ;;
    *'json.load(sys.stdin).get("nprofile", "")'*)
        [ "${TEST_LEGACY_BOOTSTRAP:-0}" = 1 ] || printf '%s\n' nprofile-test
        ;;
    *) exit 1 ;;
esac
EOF
chmod +x "$mock_bin"/*

fresh_log="$fixture_root/systemctl-fresh.log"
run_linux_service_case "$fixture_root" 0 "$fresh_log"
installer_output="$fixture_root/installer-output.log"
grep -F "npub: npub-test" "$installer_output" >/dev/null
grep -F "nprofile: nprofile-test" "$installer_output" >/dev/null
grep -F "Services were installed and started for the current user." "$installer_output" >/dev/null
if grep -Fq "To run it manually:" "$installer_output"; then
    echo "$kind installer printed manual-start steps after starting services" >&2
    exit 1
fi

legacy_log="$fixture_root/systemctl-legacy.log"
TEST_LEGACY_BOOTSTRAP=1 run_linux_service_case "$fixture_root" 1 "$legacy_log" --no-service
legacy_output="$fixture_root/installer-output.log"
grep -F "White Noise agent identity was not returned by this wn-agent release." "$legacy_output" >/dev/null
grep -F "Inspect the bootstrap response at: $fixture_root/marmot-home/bootstrap.json" "$legacy_output" >/dev/null
assert_log_contains "$fresh_log" "--user enable --now $agent_service"
assert_log_contains "$fresh_log" "--user enable --now $harness_service"
assert_log_excludes "$fresh_log" "--user restart $agent_service"
assert_log_excludes "$fresh_log" "--user restart $harness_service"
unit_dir="$fixture_root/home/.config/systemd/user"
[ "$(stat_mode "$unit_dir/$agent_service")" = 600 ]
[ "$(stat_mode "$unit_dir/$harness_service")" = 600 ]
[ "$(stat_mode "$fixture_root/marmot-home")" = 700 ]
[ "$(stat_mode "$fixture_root/marmot-home/bootstrap.json")" = 600 ]
[ "$(stat_mode "$fixture_root/marmot-home/dev/$harness_binary.env")" = 600 ]
grep -F "Environment=\"$timeout_env=3600\"" "$unit_dir/$harness_service" >/dev/null
grep -F "Environment=\"$request_timeout_env=30\"" "$unit_dir/$harness_service" >/dev/null
grep -F "Environment=\"$profile_env=inherit\"" "$unit_dir/$harness_service" >/dev/null
grep -F "$profile_env=inherit" \
    "$fixture_root/marmot-home/dev/$harness_binary.env" >/dev/null

for profile in autonomous unrestricted; do
    profile_log="$fixture_root/systemctl-profile-$profile.log"
    profile_args=(--execution-profile "$profile")
    if [ "$profile" = unrestricted ]; then
        profile_args+=(--acknowledge-unrestricted)
    fi
    run_linux_service_case "$fixture_root" 1 "$profile_log" "${profile_args[@]}"
    grep -F "Environment=\"$profile_env=$profile\"" \
        "$unit_dir/$harness_service" >/dev/null
    grep -F "$profile_env=$profile" \
        "$fixture_root/marmot-home/dev/$harness_binary.env" >/dev/null
done

upgrade_log="$fixture_root/systemctl-upgrade.log"
run_linux_service_case "$fixture_root" 1 "$upgrade_log"
assert_log_contains "$upgrade_log" "--user enable $agent_service"
assert_log_contains "$upgrade_log" "--user restart $agent_service"
assert_log_contains "$upgrade_log" "--user enable $harness_service"
assert_log_contains "$upgrade_log" "--user restart $harness_service"
assert_log_excludes "$upgrade_log" "--user enable --now $agent_service"
assert_log_excludes "$upgrade_log" "--user enable --now $harness_service"

no_start_log="$fixture_root/systemctl-no-start.log"
run_linux_service_case "$fixture_root" 1 "$no_start_log" "--no-start-$harness_binary"
assert_log_contains "$no_start_log" "--user restart $agent_service"
assert_log_excludes "$no_start_log" "--user is-active --quiet $harness_service"
assert_log_contains "$no_start_log" "--user enable $harness_service"
assert_log_excludes "$no_start_log" "--user enable --now $harness_service"
assert_log_excludes "$no_start_log" "--user restart $harness_service"
[ -f "$unit_dir/$harness_service" ]

no_start_agent_log="$fixture_root/systemctl-no-start-agent.log"
run_linux_service_case "$fixture_root" 1 "$no_start_agent_log" "--no-start-wn-agent"
assert_log_excludes "$no_start_agent_log" "--user is-active --quiet $agent_service"
assert_log_contains "$no_start_agent_log" "--user enable $agent_service"
assert_log_excludes "$no_start_agent_log" "--user enable --now $agent_service"
assert_log_excludes "$no_start_agent_log" "--user restart $agent_service"
assert_log_excludes "$no_start_agent_log" "--user is-active --quiet $harness_service"
assert_log_contains "$no_start_agent_log" "--user enable $harness_service"
assert_log_excludes "$no_start_agent_log" "--user enable --now $harness_service"
assert_log_excludes "$no_start_agent_log" "--user restart $harness_service"
[ -f "$unit_dir/$agent_service" ]
[ -f "$unit_dir/$harness_service" ]

custom_log="$fixture_root/systemctl-custom.log"
MARMOT_HARNESS_SERVICE_NAME="custom-$kind" \
    run_linux_service_case "$fixture_root" 0 "$custom_log"
assert_log_contains "$custom_log" "--user enable --now custom-$kind.service"
[ -f "$unit_dir/custom-$kind.service" ]

ln -s /bin/echo "$fixture_root/relative-$kind"
relative_log="$fixture_root/systemctl-relative.log"
(
    cd "$fixture_root"
    export "$bin_env=./relative-$kind"
    run_linux_service_case "$fixture_root" 0 "$relative_log"
)
grep -F "Environment=\"$bin_env=$fixture_root/relative-$kind\"" \
    "$unit_dir/$harness_service" >/dev/null

unsafe_status=0
TEST_UNSAFE_ARCHIVE=1 \
    run_linux_service_case "$fixture_root" 0 "$fixture_root/systemctl-unsafe.log" \
    >/dev/null 2>&1 \
    || unsafe_status=$?
[ "$unsafe_status" -ne 0 ]

installer_dry_run="$(
    env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
        WN_AGENT_SHA="$fixture_version" \
        MARMOT_RELEASE_TAG="wn-agent-v$fixture_version-test" \
    "$installer" --dry-run --yes --no-service --allow-welcomer "$allow_hex"
)"

installer_service_dry_run="$(
    env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
        WN_AGENT_SHA="$fixture_version" \
        MARMOT_RELEASE_TAG="wn-agent-v$fixture_version-test" \
    "$installer" --dry-run --yes --allow-welcomer "$allow_hex"
)"

installer_no_start_dry_run="$(
    env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
        WN_AGENT_SHA="$fixture_version" \
        MARMOT_RELEASE_TAG="wn-agent-v$fixture_version-test" \
    "$installer" --dry-run --yes "--no-start-$harness_binary" --allow-welcomer "$allow_hex"
)"

installer_stdin_dry_run="$(
    env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
        WN_AGENT_SHA="$fixture_version" \
        MARMOT_RELEASE_TAG="wn-agent-v$fixture_version-test" \
    MARMOT_TERMINAL_HARNESS="$kind" \
    bash -s -- --dry-run --yes --no-service --allow-welcomer "$allow_hex" < "$shared_installer"
)"

for profile in inherit autonomous unrestricted; do
    profile_args=(--execution-profile "$profile")
    if [ "$profile" = unrestricted ]; then
        profile_args+=(--acknowledge-unrestricted)
    fi
    profile_dry_run="$(
        env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
            WN_AGENT_SHA="$fixture_version" \
            MARMOT_RELEASE_TAG="wn-agent-v$fixture_version-test" \
        "$installer" --dry-run --yes --no-service --allow-welcomer "$allow_hex" \
            "${profile_args[@]}"
    )"
    case "$profile_dry_run" in
        *"$profile_env=$profile"*) ;;
        *) echo "$kind installer dry-run omitted execution profile $profile" >&2; exit 1 ;;
    esac
done

unacknowledged_status=0
unacknowledged_stderr="$fixture_root/unacknowledged-unrestricted.err"
env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
    WN_AGENT_SHA="$fixture_version" \
    MARMOT_RELEASE_TAG="wn-agent-v$fixture_version-test" \
    "$installer" --dry-run --yes --no-service --allow-welcomer "$allow_hex" \
        --execution-profile unrestricted >/dev/null 2>"$unacknowledged_stderr" \
    || unacknowledged_status=$?
[ "$unacknowledged_status" -ne 0 ]
grep -F -- "--acknowledge-unrestricted is required" "$unacknowledged_stderr" >/dev/null

custom_root="$fixture_parent/custom"
installer_custom_socket_dry_run="$(
    env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
        WN_AGENT_SHA="$fixture_version" \
        MARMOT_RELEASE_TAG="wn-agent-v$fixture_version-test" \
    "$installer" --dry-run --yes --no-service \
        --socket "$custom_root/wn-agent.sock" \
        --home "$custom_root/marmot-home" \
        --allow-welcomer "$allow_hex"
)"

prompt_sender_hex="$(printf '22%.0s' {1..32})"
configured_sender_dry_run="$(
    env "$allowed_env=$prompt_sender_hex" \
        WN_AGENT_SHA="$fixture_version" \
        MARMOT_RELEASE_TAG="wn-agent-v$fixture_version-test" \
        "$installer" --dry-run --yes --no-service --allow-welcomer "$allow_hex"
)"
bootstrap_line="$(printf '%s\n' "$configured_sender_dry_run" | grep '\[dry-run\] wn-agent bootstrap')"
case "$bootstrap_line" in
    *"$prompt_sender_hex"*) echo "$kind installer promoted prompt sender to welcomer" >&2; exit 1 ;;
    *"$allow_hex"*) ;;
    *) echo "$kind installer omitted explicit welcomer" >&2; exit 1 ;;
esac

missing_allowlist_status=0
missing_allowlist_stderr="$fixture_root/missing-allowlist.err"
env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
    WN_AGENT_SHA="$fixture_version" \
    MARMOT_RELEASE_TAG="wn-agent-v$fixture_version-test" \
    "$installer" --dry-run --yes --no-service >/dev/null 2>"$missing_allowlist_stderr" || missing_allowlist_status=$?
[ "$missing_allowlist_status" -ne 0 ]
grep -F "at least one --allow-welcomer/--allow-sender value is required" \
    "$missing_allowlist_stderr" >/dev/null

bad_allowlist_status=0
bad_allowlist_stderr="$fixture_root/bad-allowlist.err"
env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
    WN_AGENT_SHA="$fixture_version" \
    MARMOT_RELEASE_TAG="wn-agent-v$fixture_version-test" \
    "$installer" --dry-run --yes --no-service --allow-welcomer not-a-key \
    >/dev/null 2>"$bad_allowlist_stderr" || bad_allowlist_status=$?
[ "$bad_allowlist_status" -ne 0 ]
grep -F "invalid allowlist value:" "$bad_allowlist_stderr" >/dev/null

unresolved_version_status=0
unresolved_version_stderr="$fixture_root/unresolved-version.err"
env -u MARMOT_RELEASE_TAG -u MARMOT_RELEASE_TAG_DEFAULT \
    -u WN_AGENT_SHA -u WN_AGENT_VERSION -u WN_AGENT_VERSION_DEFAULT \
    MARMOT_TERMINAL_HARNESS="$kind" \
    bash -s -- --dry-run --yes --no-service --allow-welcomer "$allow_hex" \
    <"$shared_installer" >/dev/null 2>"$unresolved_version_stderr" \
    || unresolved_version_status=$?
[ "$unresolved_version_status" -ne 0 ]
grep -F "could not resolve a release version" "$unresolved_version_stderr" >/dev/null

case "$installer_dry_run" in
    *"wn-agent-"*"$fixture_version.tar.gz"* ) ;;
    *) echo "$kind installer dry-run did not use WN_AGENT_SHA asset suffix for wn-agent" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"$harness_binary-"*"$fixture_version.tar.gz"* ) ;;
    *) echo "$kind installer dry-run did not use expected $harness_binary asset" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"wn-agent-v$fixture_version-test"* ) ;;
    *) echo "$kind installer dry-run did not use requested release tag" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"bootstrap"*"--allow-welcomer"* ) ;;
    *) echo "$kind installer dry-run did not bootstrap with allowlist" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"Terminal harness agent:"*"home: $default_home"* ) ;;
    *) echo "$kind installer dry-run did not use terminal harness Marmot home" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"Dry run complete. No services were installed or started."* ) ;;
    *) echo "$kind installer dry-run claimed that services were started" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"--socket $default_home/dev/wn-agent.sock"* ) ;;
    *) echo "$kind installer dry-run did not derive the terminal harness socket" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"--label $agent_label"* ) ;;
    *) echo "$kind installer dry-run did not pass the terminal harness bootstrap label" >&2; exit 1;;
esac
case "$installer_stdin_dry_run" in
    *"$harness_binary-"*"$fixture_version.tar.gz"* ) ;;
    *) echo "$kind installer stdin dry-run did not use expected $harness_binary asset" >&2; exit 1;;
esac
case "$installer_stdin_dry_run" in
    *"home: $default_home"* ) ;;
    *) echo "$kind installer stdin dry-run did not use terminal harness Marmot home" >&2; exit 1;;
esac
case "$installer_custom_socket_dry_run" in
    *"--socket $custom_root/wn-agent.sock"* ) ;;
    *) echo "$kind installer dry-run did not preserve explicit socket after --home" >&2; exit 1;;
esac
case "$installer_custom_socket_dry_run" in
    *"$custom_root/marmot-home/dev/wn-agent.sock"* )
        echo "$kind installer dry-run overwrote explicit socket when --home followed --socket" >&2
        exit 1
        ;;
esac
case "$installer_service_dry_run" in
    *"would write private env file"* ) ;;
    *) echo "$kind installer service dry-run did not write env file" >&2; exit 1;;
esac
case "$installer_service_dry_run" in
    *"would require $display_name binary: /bin/echo"* ) ;;
    *) echo "$kind installer service dry-run did not validate $display_name binary" >&2; exit 1;;
esac
case "$installer_service_dry_run" in
    *"$timeout_env=3600"* ) ;;
    *) echo "$kind installer service dry-run did not set 3600s total timeout" >&2; exit 1;;
esac
case "$installer_service_dry_run" in
    *"$idle_timeout_env=120"* ) ;;
    *) echo "$kind installer service dry-run did not set 120s idle timeout" >&2; exit 1;;
esac
for assignment in \
    "$request_timeout_env=30" \
    "$max_reply_env=30000" \
    "$max_pending_env=4"
do
    case "$installer_service_dry_run" in
        *"$assignment"*) ;;
        *) echo "$kind installer dry-run omitted $assignment" >&2; exit 1 ;;
    esac
done
case "$(uname -s)" in
    Darwin)
        case "$installer_service_dry_run" in
            *"would install LaunchAgent"*"$agent_launchd.plist"* ) ;;
            *) echo "$kind installer service dry-run did not plan terminal harness wn-agent LaunchAgent" >&2; exit 1;;
        esac
        case "$installer_service_dry_run" in
            *"would install LaunchAgent"*"org.marmot.$harness_binary.plist"* ) ;;
            *) echo "$kind installer service dry-run did not plan $harness_binary LaunchAgent" >&2; exit 1;;
        esac
        ;;
    Linux)
        case "$installer_service_dry_run" in
            *"would install systemd user unit"*"$agent_service"* ) ;;
            *) echo "$kind installer service dry-run did not plan terminal harness wn-agent systemd unit" >&2; exit 1;;
        esac
        case "$installer_service_dry_run" in
            *"would install systemd user unit"*"$harness_service"* ) ;;
            *) echo "$kind installer service dry-run did not plan $harness_binary systemd unit" >&2; exit 1;;
        esac
        case "$installer_service_dry_run" in
            *"would restart $agent_service when active; otherwise enable --now"* ) ;;
            *) echo "$kind installer did not plan active wn-agent restart" >&2; exit 1;;
        esac
        case "$installer_service_dry_run" in
            *"would restart $harness_service when active; otherwise enable --now"* ) ;;
            *) echo "$kind installer did not plan active $harness_binary restart" >&2; exit 1;;
        esac
        ;;
esac
case "$installer_no_start_dry_run" in
    *"without starting it: $harness_service"* | *"without starting it: org.marmot.$harness_binary"* ) ;;
    *) echo "$kind installer no-start dry-run did not preserve service installation" >&2; exit 1;;
esac

# This is a literal source assertion.
# shellcheck disable=SC2016
grep -F 'if systemctl --user is-active --quiet "$unit"; then' "$shared_installer" >/dev/null || {
    echo "$kind installer does not distinguish active service upgrades" >&2
    exit 1
}
# This is a literal source assertion.
# shellcheck disable=SC2016
grep -F 'run systemctl --user restart "$unit"' "$shared_installer" >/dev/null || {
    echo "$kind installer does not restart active services" >&2
    exit 1
}

echo "$kind installer test passed"
