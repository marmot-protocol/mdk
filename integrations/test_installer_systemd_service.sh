#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
flavor="${1:?usage: test_installer_systemd_service.sh <hermes|openclaw>}"
allow_hex="$(printf '11%.0s' {1..32})"

case "$flavor" in
    hermes)
        installer="$repo_root/scripts/install-hermes-marmot.sh"
        service="wn-agent-hermes.service"
        host_command="hermes"
        configure_flag="--no-configure-hermes"
        ;;
    openclaw)
        installer="$repo_root/scripts/install-openclaw-marmot.sh"
        service="wn-agent-openclaw.service"
        host_command="openclaw"
        configure_flag="--no-configure-openclaw"
        ;;
    *)
        echo "unknown installer flavor: $flavor" >&2
        exit 2
        ;;
esac

[ -x "$installer" ]
bash -n "$installer"

if [ "$(uname -s)" != Linux ]; then
    exit 0
fi

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
    wn-agent-*)
        platform="${archive_name#wn-agent-}"
        platform="${platform%-9.9.9.tar.gz}"
        output_dir="$destination/wn-agent-$platform"
        mkdir -p "$output_dir"
        cat >"$output_dir/wn-agent" <<'SCRIPT'
#!/usr/bin/env bash
if [ "${1:-}" = bootstrap ]; then
    printf '%s\n' '{"account_id_hex":"aa","welcomer_account_ids_hex":["bb"]}'
fi
SCRIPT
        chmod +x "$output_dir/wn-agent"
        ;;
    hermes-marmot-plugin-*)
        mkdir -p "$destination/hermes-marmot-plugin"
        ;;
    *)
        echo "unexpected archive: $archive_name" >&2
        exit 1
        ;;
esac
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

cat >"$mock_bin/$host_command" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$mock_bin"/*

run_case() {
    local name="$1"
    local active="$2"
    local log_file="$3"
    shift 3
    local case_root="$fixture_root/$name"

    mkdir -p "$case_root"
    : >"$log_file"
    SYSTEMCTL_ACTIVE="$active" \
    SYSTEMCTL_LOG="$log_file" \
    HOME="$case_root/home" \
    HERMES_HOME="$case_root/hermes-home" \
    OPENCLAW_HOME="$case_root/openclaw-home" \
    MARMOT_HOME="$case_root/marmot-home" \
    MARMOT_INSTALL_PREFIX="$case_root/install" \
    PATH="$mock_bin:/usr/bin:/bin" \
    WN_AGENT_SHA="9.9.9" \
    MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
        "$installer" --yes "$configure_flag" --allow-welcomer "$allow_hex" "$@" >/dev/null 2>&1
}

assert_log_equals() {
    local log_file="$1"
    local expected="$2"
    local actual
    actual="$(cat "$log_file")"
    if [ "$actual" != "$expected" ]; then
        printf 'unexpected systemctl calls for %s installer\nexpected:\n%s\nactual:\n%s\n' \
            "$flavor" "$expected" "$actual" >&2
        return 1
    fi
}

fresh_log="$fixture_root/systemctl-fresh.log"
run_case fresh 0 "$fresh_log"
assert_log_equals "$fresh_log" "--user daemon-reload
--user is-active --quiet $service
--user enable --now $service"

upgrade_log="$fixture_root/systemctl-upgrade.log"
run_case upgrade 1 "$upgrade_log"
assert_log_equals "$upgrade_log" "--user daemon-reload
--user is-active --quiet $service
--user enable $service
--user restart $service"

no_start_log="$fixture_root/systemctl-no-start.log"
run_case no-start 1 "$no_start_log" --no-start-wn-agent
assert_log_equals "$no_start_log" ""

no_service_log="$fixture_root/systemctl-no-service.log"
run_case no-service 1 "$no_service_log" --no-service
assert_log_equals "$no_service_log" ""
