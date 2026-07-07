#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
installer="$repo_root/scripts/install-opencode-marmot.sh"
allow_hex="$(printf '11%.0s' {1..32})"

[ -x "$installer" ]
bash -n "$installer"

installer_dry_run="$(
    WN_AGENT_SHA="9.9.9" \
    MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
    WN_OPENCODE_BIN="/bin/echo" \
    "$installer" --dry-run --yes --no-service --allow-welcomer "$allow_hex"
)"

installer_service_dry_run="$(
    WN_AGENT_SHA="9.9.9" \
    MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
    WN_OPENCODE_BIN="/bin/echo" \
    "$installer" --dry-run --yes --allow-welcomer "$allow_hex"
)"

installer_no_start_dry_run="$(
    WN_AGENT_SHA="9.9.9" \
    MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
    WN_OPENCODE_BIN="/bin/echo" \
    "$installer" --dry-run --yes --no-start-wn-opencode --allow-welcomer "$allow_hex"
)"

installer_stdin_dry_run="$(
    WN_AGENT_SHA="9.9.9" \
    MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
    WN_OPENCODE_BIN="/bin/echo" \
    bash -s -- --dry-run --yes --no-service --allow-welcomer "$allow_hex" < "$installer"
)"

installer_custom_socket_dry_run="$(
    WN_AGENT_SHA="9.9.9" \
    MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
    WN_OPENCODE_BIN="/bin/echo" \
    "$installer" --dry-run --yes --no-service --socket /tmp/custom-wn-agent.sock --home /tmp/custom-marmot-home --allow-welcomer "$allow_hex"
)"

missing_allowlist_status=0
WN_AGENT_SHA="9.9.9" \
    MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
    WN_OPENCODE_BIN="/bin/echo" \
    "$installer" --dry-run --yes --no-service >/dev/null 2>&1 || missing_allowlist_status=$?
[ "$missing_allowlist_status" -ne 0 ]

bad_allowlist_status=0
WN_AGENT_SHA="9.9.9" \
    MARMOT_RELEASE_TAG="wn-agent-v9.9.9-test" \
    WN_OPENCODE_BIN="/bin/echo" \
    "$installer" --dry-run --yes --no-service --allow-welcomer not-a-key \
    >/dev/null 2>&1 || bad_allowlist_status=$?
[ "$bad_allowlist_status" -ne 0 ]

case "$installer_dry_run" in
    *"wn-agent-"*"9.9.9.tar.gz"* ) ;;
    *) echo "opencode installer dry-run did not use WN_AGENT_SHA asset suffix for wn-agent" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"wn-opencode-"*"9.9.9.tar.gz"* ) ;;
    *) echo "opencode installer dry-run did not use expected wn-opencode asset" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"wn-agent-v9.9.9-test"* ) ;;
    *) echo "opencode installer dry-run did not use requested release tag" >&2; exit 1;;
esac
case "$installer_dry_run" in
    *"bootstrap"*"--allow-welcomer"* ) ;;
    *) echo "opencode installer dry-run did not bootstrap with allowlist" >&2; exit 1;;
esac
case "$installer_stdin_dry_run" in
    *"wn-opencode-"*"9.9.9.tar.gz"* ) ;;
    *) echo "opencode installer stdin dry-run did not use expected wn-opencode asset" >&2; exit 1;;
esac
case "$installer_custom_socket_dry_run" in
    *"--socket /tmp/custom-wn-agent.sock"* ) ;;
    *) echo "opencode installer dry-run did not preserve explicit socket after --home" >&2; exit 1;;
esac
case "$installer_custom_socket_dry_run" in
    *"/tmp/custom-marmot-home/dev/wn-agent.sock"* )
        echo "opencode installer dry-run overwrote explicit socket when --home followed --socket" >&2
        exit 1
        ;;
esac
case "$installer_service_dry_run" in
    *"would write private env file"* ) ;;
    *) echo "opencode installer service dry-run did not write env file" >&2; exit 1;;
esac
case "$installer_service_dry_run" in
    *"would require opencode binary: /bin/echo"* ) ;;
    *) echo "opencode installer service dry-run did not validate opencode binary" >&2; exit 1;;
esac
case "$(uname -s)" in
    Darwin)
        case "$installer_service_dry_run" in
            *"would install LaunchAgent"*"org.marmot.wn-agent.plist"* ) ;;
            *) echo "opencode installer service dry-run did not plan wn-agent LaunchAgent" >&2; exit 1;;
        esac
        case "$installer_service_dry_run" in
            *"would install LaunchAgent"*"org.marmot.wn-opencode.plist"* ) ;;
            *) echo "opencode installer service dry-run did not plan wn-opencode LaunchAgent" >&2; exit 1;;
        esac
        ;;
    Linux)
        case "$installer_service_dry_run" in
            *"would install systemd user unit"*"wn-agent.service"* ) ;;
            *) echo "opencode installer service dry-run did not plan wn-agent systemd unit" >&2; exit 1;;
        esac
        case "$installer_service_dry_run" in
            *"would install systemd user unit"*"wn-opencode.service"* ) ;;
            *) echo "opencode installer service dry-run did not plan wn-opencode systemd unit" >&2; exit 1;;
        esac
        ;;
esac
case "$installer_no_start_dry_run" in
    *"not starting wn-opencode because --no-start-wn-opencode was passed"* ) ;;
    *) echo "opencode installer no-start dry-run did not skip wn-opencode start" >&2; exit 1;;
esac

echo "opencode installer test passed"
