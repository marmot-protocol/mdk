#!/usr/bin/env bash
set -euo pipefail

# Connector-only mode of the shared installer (scripts/install-wn-agent.sh):
# wn-agent, a private home and its same-user service, with no harness. Service
# cases run against mocked systemd (Linux) and launchd (macOS) on any host.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
installer="$repo_root/scripts/install-wn-agent.sh"
shared_installer="$repo_root/scripts/install-terminal-harness-marmot.sh"
fixture_version="9.9.9"
release_tag="wn-agent-v$fixture_version-test"
welcomer_hex="$(printf '11%.0s' {1..32})"
bootstrap_account="$(printf 'aa%.0s' {1..32})"
imported_account="$(printf 'cc%.0s' {1..32})"
expected_npub="npub1$(printf 'q%.0s' {1..58})"
default_relay_args='"--relay" "wss://relay.eu.whitenoise.chat" "--relay" "wss://relay.us.whitenoise.chat"'

# Cases set these per run; do not inherit an operator's connector settings.
unset MARMOT_HOME MARMOT_AGENT_SOCKET MARMOT_AGENT_LABEL MARMOT_RELAYS MARMOT_WELCOMER_ALLOWLIST \
    MARMOT_AGENT_SERVICE_NAME MARMOT_AGENT_LAUNCHD_LABEL

[ -x "$installer" ]
bash -n "$installer"
bash -n "$shared_installer"

fail() {
    echo "connector-only installer test: $*" >&2
    exit 1
}

stat_mode() {
    if stat -f %Lp "$1" >/dev/null 2>&1; then
        stat -f %Lp "$1"
    else
        stat -c %a "$1"
    fi
}

assert_mode() {
    [ -e "$1" ] || fail "missing $1"
    [ "$(stat_mode "$1")" = "$2" ] || fail "$1 has mode $(stat_mode "$1"), expected $2"
}

assert_contains() {
    grep -F -- "$2" "$1" >/dev/null || {
        cat "$1" >&2
        fail "$1 does not contain: $2"
    }
}

assert_excludes() {
    if grep -F -- "$2" "$1" >/dev/null; then
        cat "$1" >&2
        fail "$1 unexpectedly contains: $2"
    fi
}

assert_line() {
    grep -Fx -- "$2" "$1" >/dev/null || {
        cat "$1" >&2
        fail "$1 has no line: $2"
    }
}

# Line number of the first line in $1 that starts with $2; 0 when absent.
line_of() {
    local number=0 line
    while IFS= read -r line; do
        number=$((number + 1))
        case "$line" in
            "$2"*) printf '%s\n' "$number"; return 0 ;;
        esac
    done <"$1"
    printf '0\n'
}

fixture_parent="$(mktemp -d)"
trap 'rm -rf "$fixture_parent"' EXIT
fixtures="$fixture_parent/fixture root"
mock_bin="$fixtures/mock-bin"
mkdir -p "$mock_bin"

# Every mock appends to one event log so cases can assert call order.
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
printf 'curl %s\n' "$url" >>"$TEST_LOG"
if [[ "$url" == *.sha256 ]]; then
    printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >"$destination"
else
    : >"$destination"
fi
EOF

cat >"$mock_bin/shasum" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
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
    wn-agent-*) ;;
    *) echo "unexpected archive: $archive_name" >&2; exit 1 ;;
esac
platform="${archive_name#wn-agent-}"
platform="${platform%-$FIXTURE_VERSION.tar.gz}"
if [ "$mode" = -tzf ]; then
    printf '%s\n' "wn-agent-$platform/wn-agent"
    exit 0
fi
mkdir -p "$destination/wn-agent-$platform"
cat >"$destination/wn-agent-$platform/wn-agent" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
printf 'wn-agent %s\n' "$*" >>"$TEST_LOG"
case "${1:-}" in
    bootstrap)
        account="$TEST_BOOTSTRAP_ACCOUNT"
        while [ "$#" -gt 0 ]; do
            if [ "$1" = --account-id-hex ]; then
                account="$2"
            fi
            shift
        done
        printf '{"account_id_hex":"%s","welcomer_account_ids_hex":[],"npub":"npub-test","nprofile":"nprofile-test"}\n' "$account"
        ;;
    import-identity)
        printf '{"account_id_hex":"%s","label":"standalone-agent","local_signing":true}\n' "$TEST_IMPORTED_ACCOUNT"
        ;;
esac
SCRIPT
chmod +x "$destination/wn-agent-$platform/wn-agent"
EOF

cat >"$mock_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'systemctl %s\n' "$*" >>"$TEST_LOG"
if [ "${1:-}" = --user ] && [ "${2:-}" = is-active ]; then
    [ "$SYSTEMCTL_ACTIVE" = 1 ]
fi
EOF

cat >"$mock_bin/launchctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'launchctl %s\n' "$*" >>"$TEST_LOG"
EOF

cat >"$mock_bin/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat >"$mock_bin/uname" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
    -m) [ "$TEST_UNAME_S" = Darwin ] && printf '%s\n' arm64 || printf '%s\n' x86_64 ;;
    *) printf '%s\n' "$TEST_UNAME_S" ;;
esac
EOF

# Reads the JSON field each installer one-liner selects.
cat >"$mock_bin/python3" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
code="${2:-}"
input="$(cat)"
field() {
    printf '%s\n' "$input" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"
}
case "$code" in
    *'["account_id_hex"]'*) field account_id_hex ;;
    *welcomer_account_ids_hex*) printf '\n' ;;
    *'.get("npub", "")'*) field npub ;;
    *'.get("nprofile", "")'*) field nprofile ;;
    *) exit 1 ;;
esac
EOF
chmod +x "$mock_bin"/*

# run_case NAME OS ACTIVE [installer args...]: run the installer in a fresh
# fixture; sets case_root, case_home, case_output and case_log.
run_case() {
    local name="$1" os="$2" active="$3"
    shift 3
    case_root="$fixtures/$name"
    case_home="$case_root/home/.marmot-agents/standalone"
    case_output="$case_root/output.log"
    case_log="$case_root/events.log"
    mkdir -p "$case_root/home"
    : >"$case_log"
    local status=0
    env TEST_LOG="$case_log" \
        TEST_UNAME_S="$os" \
        TEST_BOOTSTRAP_ACCOUNT="$bootstrap_account" \
        TEST_IMPORTED_ACCOUNT="$imported_account" \
        SYSTEMCTL_ACTIVE="$active" \
        FIXTURE_VERSION="$fixture_version" \
        HOME="$case_root/home" \
        MARMOT_INSTALL_PREFIX="$case_root/install" \
        PATH="$mock_bin:/usr/bin:/bin" \
        WN_AGENT_SHA="$fixture_version" \
        MARMOT_RELEASE_TAG="$release_tag" \
        "$installer" "$@" >"$case_output" 2>&1 || status=$?
    case_status="$status"
}

expect_success() {
    if [ "$case_status" -ne 0 ]; then
        cat "$case_output" >&2
        fail "installer exited $case_status for $(basename "$case_root")"
    fi
}

expect_failure() {
    local message="$1"
    if [ "$case_status" -eq 0 ]; then
        cat "$case_output" >&2
        fail "installer accepted invalid input in $(basename "$case_root")"
    fi
    assert_contains "$case_output" "$message"
    # Input errors stop before any download or service change.
    [ ! -s "$case_log" ] || fail "rejected input still ran commands in $(basename "$case_root")"
}

assert_only_wn_agent_downloaded() {
    local platform="$1"
    assert_line "$case_log" "curl https://github.com/marmot-protocol/mdk/releases/download/$release_tag/wn-agent-$platform-$fixture_version.tar.gz"
    assert_line "$case_log" "curl https://github.com/marmot-protocol/mdk/releases/download/$release_tag/wn-agent-$platform-$fixture_version.tar.gz.sha256"
    [ "$(grep -c '^curl ' "$case_log")" = 2 ] || fail "downloaded more than the wn-agent bundle"
    [ -x "$case_root/install/bin/wn-agent" ] || fail "wn-agent was not installed"
    [ "$(find "$case_root/install/bin" -type f | wc -l | tr -d ' ')" = 1 ] || fail "installed more than wn-agent"
}

unit_dir() {
    printf '%s\n' "$case_root/home/.config/systemd/user"
}

plist_path() {
    printf '%s\n' "$case_root/home/Library/LaunchAgents/org.marmot.wn-agent.standalone.plist"
}

# Linux, systemd: fresh install with no identity step.
run_case linux-fresh Linux 0 --yes
expect_success
assert_only_wn_agent_downloaded linux-x86_64
assert_mode "$case_home" 700
unit="$(unit_dir)/wn-agent-standalone.service"
assert_mode "$unit" 600
[ "$(find "$(unit_dir)" -type f | wc -l | tr -d ' ')" = 1 ] || fail "installed more than the wn-agent unit"
assert_contains "$unit" "ExecStart=\"$case_root/install/bin/wn-agent\" \"--home\" \"$case_home\" \"--socket\" \"$case_home/dev/wn-agent.sock\" $default_relay_args"
assert_contains "$unit" "Restart=always"
assert_line "$case_log" "systemctl --user daemon-reload"
assert_line "$case_log" "systemctl --user enable --now wn-agent-standalone.service"
assert_excludes "$case_log" "restart"
[ "$(line_of "$case_log" "wn-agent ")" = 0 ] || fail "installer ran wn-agent without an identity step"
[ ! -e "$case_home/bootstrap.json" ] || fail "bootstrap ran without --bootstrap"
[ ! -e "$case_home/dev" ] || fail "connector-only install wrote harness files"
assert_contains "$case_output" "No agent identity was created or imported."
assert_contains "$case_output" "wn-agent bootstrap --home"
assert_contains "$case_output" "--label standalone-agent"
assert_contains "$case_output" "wn-agent is running as a same-user service."
assert_contains "$case_output" "export MARMOT_AGENT_SOCKET="
assert_contains "$case_output" "integrations/custom-client.md"
assert_excludes "$case_output" "account_id_hex:"
assert_excludes "$case_output" "Terminal harness agent:"

# Linux, systemd: upgrade of an active service, with bootstrap and an allowlist.
run_case linux-bootstrap Linux 1 --bootstrap --allow-welcomer "$welcomer_hex"
expect_success
assert_line "$case_log" "systemctl --user enable wn-agent-standalone.service"
assert_line "$case_log" "systemctl --user restart wn-agent-standalone.service"
assert_excludes "$case_log" "enable --now"
assert_line "$case_log" "wn-agent bootstrap --json --home $case_home --socket $case_home/dev/wn-agent.sock --label standalone-agent --no-quic --relay wss://relay.eu.whitenoise.chat --relay wss://relay.us.whitenoise.chat --allow-welcomer $welcomer_hex"
assert_excludes "$case_log" "import-identity"
[ "$(line_of "$case_log" "wn-agent --home")" = 0 ] || fail "started a temporary wn-agent beside the service"
[ "$(line_of "$case_log" "systemctl --user restart")" -lt "$(line_of "$case_log" "wn-agent bootstrap")" ] ||
    fail "bootstrap ran before the service restarted"
assert_mode "$case_home/bootstrap.json" 600
assert_contains "$case_home/bootstrap.json" "$bootstrap_account"
assert_contains "$case_output" "account_id_hex: $bootstrap_account"
assert_contains "$case_output" "npub: npub-test"
assert_contains "$case_output" "nprofile: nprofile-test"
assert_contains "$case_output" "This identity belongs to this connector alone."
assert_contains "$case_output" "export MARMOT_ACCOUNT_ID_HEX=$bootstrap_account"
assert_excludes "$case_output" "No agent identity was created"

# Linux, systemd: import an existing identity before the service starts, then
# bootstrap exactly that account.
run_case linux-import Linux 0 --import-identity --expected-identity "$expected_npub"
expect_success
assert_line "$case_log" "wn-agent import-identity --json --home $case_home --label standalone-agent --prompt --expected-identity $expected_npub"
assert_contains "$case_log" "wn-agent bootstrap --json --home $case_home --socket $case_home/dev/wn-agent.sock --label standalone-agent --no-quic --no-create --account-id-hex $imported_account"
import_line="$(line_of "$case_log" "wn-agent import-identity")"
start_line="$(line_of "$case_log" "systemctl --user enable --now")"
bootstrap_line="$(line_of "$case_log" "wn-agent bootstrap")"
[ "$import_line" -lt "$start_line" ] && [ "$start_line" -lt "$bootstrap_line" ] ||
    fail "expected import, then service start, then bootstrap"
assert_contains "$case_output" "account_id_hex: $imported_account"

# Linux, --no-service with bootstrap: a temporary daemon serves bootstrap only.
run_case linux-no-service-bootstrap Linux 0 --no-service --bootstrap --relay wss://relay.example.test
expect_success
assert_only_wn_agent_downloaded linux-x86_64
assert_excludes "$case_log" "systemctl"
[ ! -e "$(unit_dir)" ] || fail "--no-service wrote a systemd unit"
assert_line "$case_log" "wn-agent --home $case_home --socket $case_home/dev/wn-agent.sock --relay wss://relay.example.test"
assert_contains "$case_log" "wn-agent bootstrap --json"
assert_excludes "$case_log" "relay.eu.whitenoise.chat"
assert_mode "$case_home" 700
assert_contains "$case_output" "The temporary wn-agent used for bootstrap stops when this installer exits."
assert_contains "$case_output" "wn-agent is not supervised."
assert_contains "$case_output" "--relay wss://relay.example.test"

# Linux, --no-service without an identity step runs nothing after the install,
# and still tightens an existing home.
mkdir -p "$fixtures/linux-no-service/home/.marmot-agents/standalone"
chmod 755 "$fixtures/linux-no-service/home/.marmot-agents/standalone"
run_case linux-no-service Linux 0 --no-service
expect_success
assert_only_wn_agent_downloaded linux-x86_64
[ "$(wc -l <"$case_log" | tr -d ' ')" = 2 ] || fail "--no-service ran commands beyond the download"
assert_mode "$case_home" 700
assert_contains "$case_output" "wn-agent is not supervised."
assert_excludes "$case_output" "temporary wn-agent"

# Linux, --no-start-wn-agent enables the unit without starting it.
MARMOT_AGENT_SERVICE_NAME=custom-agent run_case linux-no-start Linux 1 --no-start-wn-agent
expect_success
assert_line "$case_log" "systemctl --user enable custom-agent.service"
assert_excludes "$case_log" "is-active"
assert_excludes "$case_log" "--now"
assert_excludes "$case_log" "restart"
assert_mode "$(unit_dir)/custom-agent.service" 600
assert_contains "$case_output" "The wn-agent service is installed but was not started."
assert_contains "$case_output" "systemctl --user start custom-agent.service"

# macOS, LaunchAgent: fresh install with bootstrap.
run_case darwin-bootstrap Darwin 0 --bootstrap
expect_success
assert_only_wn_agent_downloaded darwin-aarch64
assert_mode "$case_home" 700
plist="$(plist_path)"
assert_mode "$plist" 600
for value in "$case_root/install/bin/wn-agent" --home "$case_home" --socket "$case_home/dev/wn-agent.sock" \
    --relay wss://relay.eu.whitenoise.chat wss://relay.us.whitenoise.chat "$case_home/logs/wn-agent.err.log"; do
    assert_contains "$plist" "<string>$value</string>"
done
assert_contains "$plist" "<key>KeepAlive</key>"
[ "$(find "$case_root/home/Library/LaunchAgents" -type f | wc -l | tr -d ' ')" = 1 ] ||
    fail "installed more than the wn-agent LaunchAgent"
assert_line "$case_log" "launchctl bootstrap gui/$UID $plist"
assert_excludes "$case_log" "systemctl"
[ "$(line_of "$case_log" "wn-agent --home")" = 0 ] || fail "started a temporary wn-agent beside the LaunchAgent"
[ "$(line_of "$case_log" "launchctl bootstrap")" -lt "$(line_of "$case_log" "wn-agent bootstrap")" ] ||
    fail "bootstrap ran before the LaunchAgent loaded"
assert_contains "$case_output" "wn-agent is running as a same-user service."
assert_contains "$case_output" "account_id_hex: $bootstrap_account"

# macOS, --no-service writes no LaunchAgent.
run_case darwin-no-service Darwin 0 --no-service
expect_success
assert_only_wn_agent_downloaded darwin-aarch64
[ ! -e "$(plist_path)" ] || fail "--no-service wrote a LaunchAgent"
assert_excludes "$case_log" "launchctl"
assert_contains "$case_output" "wn-agent is not supervised."

# macOS, --no-start-wn-agent writes the LaunchAgent without loading it.
run_case darwin-no-start Darwin 0 --no-start-wn-agent
expect_success
assert_mode "$(plist_path)" 600
assert_excludes "$case_log" "launchctl"
assert_contains "$case_output" "launchctl bootstrap gui/$UID $(plist_path)"

# Dry runs plan the same layout on both service managers without side effects.
run_case linux-dry-run Linux 0 --dry-run
expect_success
[ ! -s "$case_log" ] || fail "dry run ran commands"
[ ! -e "$case_root/home/.marmot-agents" ] || fail "dry run created the home"
assert_contains "$case_output" "wn-agent-linux-x86_64-$fixture_version.tar.gz"
assert_contains "$case_output" "would create private home $case_home (mode 0700)"
assert_contains "$case_output" "[dry-run] service command: wn-agent --home"
assert_contains "$case_output" "--relay wss://relay.eu.whitenoise.chat --relay wss://relay.us.whitenoise.chat"
assert_contains "$case_output" "would install systemd user unit $case_root/home/.config/systemd/user/wn-agent-standalone.service"
assert_contains "$case_output" "would restart wn-agent-standalone.service when active; otherwise enable --now"
assert_contains "$case_output" "Dry run complete. Nothing was installed or started"
assert_excludes "$case_output" "bootstrap --json"
assert_excludes "$case_output" "wn-claude"

run_case linux-dry-run-no-service Linux 0 --dry-run --no-service
expect_success
assert_excludes "$case_output" "systemd"
assert_excludes "$case_output" "service command"

run_case darwin-dry-run Darwin 0 --dry-run --import-identity --expected-identity "$expected_npub"
expect_success
[ ! -s "$case_log" ] || fail "dry run ran commands"
assert_contains "$case_output" "wn-agent-darwin-aarch64-$fixture_version.tar.gz"
assert_contains "$case_output" "would install LaunchAgent $(plist_path)"
assert_contains "$case_output" "[dry-run] wn-agent import-identity --json --home"
assert_contains "$case_output" "--prompt --expected-identity $expected_npub"
assert_contains "$case_output" "--no-create --account-id-hex"
[ "$(line_of "$case_output" "[dry-run] wn-agent import-identity")" -lt \
    "$(line_of "$case_output" "install-wn-agent: would install LaunchAgent")" ] ||
    fail "dry run planned the service before the identity import"

run_case darwin-dry-run-no-service Darwin 0 --dry-run --no-service
expect_success
assert_excludes "$case_output" "LaunchAgent"

# Invalid combinations fail before any download.
run_case reject-welcomer-without-identity Linux 0 --allow-welcomer "$welcomer_hex"
expect_failure "need --bootstrap or --import-identity"
MARMOT_WELCOMER_ALLOWLIST="$welcomer_hex" run_case reject-env-welcomer-without-identity Linux 0
expect_failure "need --bootstrap or --import-identity"
run_case reject-bad-welcomer Linux 0 --bootstrap --allow-welcomer not-a-key
expect_failure "invalid allowlist value"
run_case reject-expected-without-import Linux 0 --bootstrap --expected-identity "$expected_npub"
expect_failure "--expected-identity needs --import-identity"
run_case reject-secret-expected-identity Linux 0 --import-identity --expected-identity nsec1notapublickey
expect_failure "--expected-identity must be an npub or 64-character hex public key"
assert_excludes "$case_output" "nsec1notapublickey"
run_case reject-bootstrap-without-start Linux 0 --bootstrap --no-start-wn-agent
expect_failure "need a running wn-agent"
run_case reject-harness-option Linux 0 --execution-profile inherit
expect_failure "unknown option: --execution-profile"
run_case reject-harness-bin Linux 0 --none-bin /bin/echo
expect_failure "unknown option: --none-bin"
MARMOT_RELAYS="," run_case reject-empty-relays Linux 0
expect_failure "at least one --relay or MARMOT_RELAYS entry is required"

# The release asset is the shared installer with the mode exported, run as a file
# or from stdin; it still needs a resolvable release.
stdin_output="$(
    env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
        WN_AGENT_SHA="$fixture_version" MARMOT_RELEASE_TAG="$release_tag" \
        MARMOT_TERMINAL_HARNESS=none \
        bash -s -- --dry-run --yes --bootstrap <"$shared_installer"
)"
case "$stdin_output" in
    *"install-wn-agent: platform="*"home: $HOME/.marmot-agents/standalone"*"Dry run complete."*) ;;
    *) printf '%s\n' "$stdin_output" >&2; fail "stdin dry run did not use connector-only defaults" ;;
esac
unresolved_status=0
env -u MARMOT_RELEASE_TAG -u MARMOT_RELEASE_TAG_DEFAULT \
    -u WN_AGENT_SHA -u WN_AGENT_VERSION -u WN_AGENT_VERSION_DEFAULT \
    MARMOT_TERMINAL_HARNESS=none \
    bash -s -- --dry-run <"$shared_installer" >"$fixtures/unresolved.out" 2>&1 || unresolved_status=$?
[ "$unresolved_status" -ne 0 ] || fail "stdin install without a release version succeeded"
assert_contains "$fixtures/unresolved.out" "could not resolve a release version"

help_output="$fixtures/help.out"
"$installer" --help >"$help_output"
assert_contains "$help_output" "Usage: install-wn-agent.sh [options]"
assert_contains "$help_output" "installer_script=install-wn-agent.sh"
assert_contains "$help_output" "--import-identity"
assert_excludes "$help_output" "--execution-profile"
assert_excludes "$help_output" "MARMOT_HARNESS"

echo "connector-only installer test passed"
