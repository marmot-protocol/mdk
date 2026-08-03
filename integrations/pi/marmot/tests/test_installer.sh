#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
installer="$repo_root/scripts/install-pi-marmot.sh"
allow_hex="$(printf '11%.0s' {1..32})"

[ -x "$installer" ]
bash -n "$installer"

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

run_linux_service_case() {
    local fixture_root="$1"
    local active="$2"
    local log_file="$3"
    local mock_bin="$fixture_root/mock-bin"
    shift 3

    : >"$log_file"
    SYSTEMCTL_ACTIVE="$active" \
    SYSTEMCTL_LOG="$log_file" \
    HOME="$fixture_root/home" \
    MARMOT_HOME="$fixture_root/marmot-home" \
    MARMOT_INSTALL_PREFIX="$fixture_root/install" \
    PATH="$mock_bin:/usr/bin:/bin" \
    WN_AGENT_SHA="9.9.9" \
    MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
    WN_PI_BIN="/bin/echo" \
        "$installer" --yes --allow-welcomer "$allow_hex" "$@" >/dev/null 2>&1 || {
        echo "installer failed for systemd scenario (log: $log_file)" >&2
        return 1
    }
}

if [ "$(uname -s)" = Linux ]; then
    fixture_root="$(mktemp -d)"
    trap 'rm -rf "$fixture_root"' EXIT
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
while [ "$#" -gt 0 ]; do
    case "$1" in
        -xzf) archive="$2"; shift 2 ;;
        -C) destination="$2"; shift 2 ;;
        *) shift ;;
    esac
done
archive_name="$(basename "$archive")"
case "$archive_name" in
    wn-agent-*) binary=wn-agent ;;
    wn-pi-*) binary=wn-pi ;;
    *) exit 1 ;;
esac
platform="${archive_name#"$binary-"}"
platform="${platform%-9.9.9.tar.gz}"
mkdir -p "$destination/$binary-$platform"
cat >"$destination/$binary-$platform/$binary" <<'SCRIPT'
#!/usr/bin/env bash
if [ "${1:-}" = bootstrap ]; then
    printf '%s\n' '{"account_id_hex":"aa","welcomer_account_ids_hex":["bb"]}'
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
    chmod +x "$mock_bin"/*

    fresh_log="$fixture_root/systemctl-fresh.log"
    run_linux_service_case "$fixture_root" 0 "$fresh_log"
    assert_log_contains "$fresh_log" "--user enable --now wn-agent-pi.service"
    assert_log_contains "$fresh_log" "--user enable --now wn-pi.service"
    assert_log_excludes "$fresh_log" "--user restart wn-agent-pi.service"
    assert_log_excludes "$fresh_log" "--user restart wn-pi.service"

    upgrade_log="$fixture_root/systemctl-upgrade.log"
    run_linux_service_case "$fixture_root" 1 "$upgrade_log"
    assert_log_contains "$upgrade_log" "--user enable wn-agent-pi.service"
    assert_log_contains "$upgrade_log" "--user restart wn-agent-pi.service"
    assert_log_contains "$upgrade_log" "--user enable wn-pi.service"
    assert_log_contains "$upgrade_log" "--user restart wn-pi.service"
    assert_log_excludes "$upgrade_log" "--user enable --now wn-agent-pi.service"
    assert_log_excludes "$upgrade_log" "--user enable --now wn-pi.service"

    no_start_pi_log="$fixture_root/systemctl-no-start-pi.log"
    run_linux_service_case "$fixture_root" 1 "$no_start_pi_log" --no-start-wn-pi
    assert_log_contains "$no_start_pi_log" "--user restart wn-agent-pi.service"
    assert_log_excludes "$no_start_pi_log" "--user is-active --quiet wn-pi.service"
    assert_log_excludes "$no_start_pi_log" "--user enable wn-pi.service"
    assert_log_excludes "$no_start_pi_log" "--user enable --now wn-pi.service"
    assert_log_excludes "$no_start_pi_log" "--user restart wn-pi.service"
fi

installer_dry_run="$(
    env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
        WN_AGENT_SHA="9.9.9" \
        MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
        WN_PI_BIN="/bin/echo" \
    "$installer" --dry-run --yes --no-service --allow-welcomer "$allow_hex"
)"

installer_service_dry_run="$(
    env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
        WN_AGENT_SHA="9.9.9" \
        MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
        WN_PI_BIN="/bin/echo" \
    "$installer" --dry-run --yes --allow-welcomer "$allow_hex"
)"

installer_no_start_dry_run="$(
    env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
        WN_AGENT_SHA="9.9.9" \
        MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
        WN_PI_BIN="/bin/echo" \
    "$installer" --dry-run --yes --no-start-wn-pi --allow-welcomer "$allow_hex"
)"

installer_stdin_dry_run="$(
    env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
        WN_AGENT_SHA="9.9.9" \
        MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
        WN_PI_BIN="/bin/echo" \
    bash -s -- --dry-run --yes --no-service --allow-welcomer "$allow_hex" < "$installer"
)"

installer_custom_socket_dry_run="$(
    WN_AGENT_SHA="9.9.9" \
    MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
    WN_PI_BIN="/bin/echo" \
    "$installer" --dry-run --yes --no-service --socket /tmp/custom-wn-agent.sock --home /tmp/custom-marmot-home --allow-welcomer "$allow_hex"
)"

missing_allowlist_status=0
env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
    WN_AGENT_SHA="9.9.9" \
    MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
    WN_PI_BIN="/bin/echo" \
    "$installer" --dry-run --yes --no-service >/dev/null 2>&1 || missing_allowlist_status=$?
[ "$missing_allowlist_status" -ne 0 ]

bad_allowlist_status=0
env -u MARMOT_HOME -u MARMOT_AGENT_SOCKET \
    WN_AGENT_SHA="9.9.9" \
    MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
    WN_PI_BIN="/bin/echo" \
    "$installer" --dry-run --yes --no-service --allow-welcomer not-a-key \
    >/dev/null 2>&1 || bad_allowlist_status=$?
[ "$bad_allowlist_status" -ne 0 ]

case "$installer_dry_run" in
    *"wn-agent-"*"9.9.9.tar.gz"* ) ;;
    *) echo "pi installer dry-run did not use WN_AGENT_SHA asset suffix for wn-agent" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"wn-pi-"*"9.9.9.tar.gz"* ) ;;
    *) echo "pi installer dry-run did not use expected wn-pi asset" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"wn-agent-v9.9.9-test"* ) ;;
    *) echo "pi installer dry-run did not use requested release tag" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"bootstrap"*"--allow-welcomer"* ) ;;
    *) echo "pi installer dry-run did not bootstrap with allowlist" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"Terminal harness agent:"*"home: $HOME/.marmot-agents/pi"* ) ;;
    *) echo "pi installer dry-run did not use terminal harness Marmot home" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"--socket $HOME/.marmot-agents/pi/dev/wn-agent.sock"* ) ;;
    *) echo "pi installer dry-run did not derive the terminal harness socket" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"--label pi-harness-agent"* ) ;;
    *) echo "pi installer dry-run did not pass the terminal harness bootstrap label" >&2; exit 1;;
esac
case "$installer_stdin_dry_run" in
    *"wn-pi-"*"9.9.9.tar.gz"* ) ;;
    *) echo "pi installer stdin dry-run did not use expected wn-pi asset" >&2; exit 1;;
esac
case "$installer_stdin_dry_run" in
    *"home: $HOME/.marmot-agents/pi"* ) ;;
    *) echo "pi installer stdin dry-run did not use terminal harness Marmot home" >&2; exit 1;;
esac
case "$installer_custom_socket_dry_run" in
    *"--socket /tmp/custom-wn-agent.sock"* ) ;;
    *) echo "pi installer dry-run did not preserve explicit socket after --home" >&2; exit 1;;
esac
case "$installer_custom_socket_dry_run" in
    *"/tmp/custom-marmot-home/dev/wn-agent.sock"* )
        echo "pi installer dry-run overwrote explicit socket when --home followed --socket" >&2
        exit 1
        ;;
esac
case "$installer_service_dry_run" in
    *"would write private env file"* ) ;;
    *) echo "pi installer service dry-run did not write env file" >&2; exit 1;;
esac
case "$installer_service_dry_run" in
    *"would require Pi binary: /bin/echo"* ) ;;
    *) echo "pi installer service dry-run did not validate Pi binary" >&2; exit 1;;
esac
case "$installer_service_dry_run" in
    *"WN_PI_TIMEOUT_SECS"*3600* ) ;;
    *) echo "pi installer service dry-run did not set 3600s total timeout" >&2; exit 1;;
esac
case "$installer_service_dry_run" in
    *"WN_PI_IDLE_TIMEOUT_SECS"*120* ) ;;
    *) echo "pi installer service dry-run did not set 120s idle timeout" >&2; exit 1;;
esac
case "$(uname -s)" in
    Darwin)
        case "$installer_service_dry_run" in
            *"would install LaunchAgent"*"org.marmot.wn-agent.pi.plist"* ) ;;
            *) echo "pi installer service dry-run did not plan terminal harness wn-agent LaunchAgent" >&2; exit 1;;
        esac
        case "$installer_service_dry_run" in
            *"would install LaunchAgent"*"org.marmot.wn-pi.plist"* ) ;;
            *) echo "pi installer service dry-run did not plan wn-pi LaunchAgent" >&2; exit 1;;
        esac
        ;;
    Linux)
        case "$installer_service_dry_run" in
            *"would install systemd user unit"*"wn-agent-pi.service"* ) ;;
            *) echo "pi installer service dry-run did not plan terminal harness wn-agent systemd unit" >&2; exit 1;;
        esac
        case "$installer_service_dry_run" in
            *"would install systemd user unit"*"wn-pi.service"* ) ;;
            *) echo "pi installer service dry-run did not plan wn-pi systemd unit" >&2; exit 1;;
        esac
        case "$installer_service_dry_run" in
            *"would restart wn-agent-pi.service when active; otherwise enable --now"* ) ;;
            *) echo "pi installer did not plan active wn-agent restart" >&2; exit 1;;
        esac
        case "$installer_service_dry_run" in
            *"would restart wn-pi.service when active; otherwise enable --now"* ) ;;
            *) echo "pi installer did not plan active wn-pi restart" >&2; exit 1;;
        esac
        ;;
esac
case "$installer_no_start_dry_run" in
    *"not starting wn-pi because --no-start-wn-pi was passed"* ) ;;
    *) echo "pi installer no-start dry-run did not skip wn-pi start" >&2; exit 1;;
esac

grep -F 'if systemctl --user is-active --quiet "$unit"; then' "$installer" >/dev/null || {
    echo "pi installer does not distinguish active service upgrades" >&2
    exit 1
}
grep -F 'run systemctl --user restart "$unit"' "$installer" >/dev/null || {
    echo "pi installer does not restart active services" >&2
    exit 1
}

echo "pi installer test passed"
