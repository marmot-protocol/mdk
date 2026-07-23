#!/usr/bin/env bash
set -euo pipefail

# NOTE: requires a published wn-agent-v* release. Releases from before the rename
# ship differently-named assets and cannot be installed by this script.

SCRIPT_SOURCE="${BASH_SOURCE[0]:-}"
SCRIPT_DIR=""
if [ -n "$SCRIPT_SOURCE" ] && [ -f "$SCRIPT_SOURCE" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_SOURCE")" && pwd)"
fi
workspace_version_default="latest"
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/../Cargo.toml" ]; then
    workspace_version_default="$(
        sed -n 's/^version = "\(.*\)"/\1/p' "$SCRIPT_DIR/../Cargo.toml" 2>/dev/null |
            head -n 1 || true
    )"
    workspace_version_default="${workspace_version_default:-latest}"
fi

MARMOT_RELEASE_REPO="${MARMOT_RELEASE_REPO:-marmot-protocol/mdk}"
WN_AGENT_VERSION_DEFAULT="${WN_AGENT_VERSION_DEFAULT:-$workspace_version_default}"
WN_AGENT_VERSION="${WN_AGENT_VERSION:-${WN_AGENT_SHA:-$WN_AGENT_VERSION_DEFAULT}}"
MARMOT_RELEASE_TAG_DEFAULT="${MARMOT_RELEASE_TAG_DEFAULT:-wn-agent-v${WN_AGENT_VERSION}}"
MARMOT_RELEASE_TAG="${MARMOT_RELEASE_TAG:-$MARMOT_RELEASE_TAG_DEFAULT}"
MARMOT_INSTALL_PREFIX="${MARMOT_INSTALL_PREFIX:-${HOME}/.local}"
HERMES_HOME="${HERMES_HOME:-${HOME}/.hermes}"
MARMOT_PLUGIN_DIR_OVERRIDE="${MARMOT_PLUGIN_DIR:-}"
MARMOT_HOME="${MARMOT_HOME:-${HOME}/.marmot-agents/hermes}"
MARMOT_AGENT_SOCKET_OVERRIDE="${MARMOT_AGENT_SOCKET:-}"
MARMOT_OUTBOUND_MEDIA_DIR_OVERRIDE="${MARMOT_OUTBOUND_MEDIA_DIR:-}"
MARMOT_AGENT_LABEL="${MARMOT_AGENT_LABEL:-hermes-agent}"
MARMOT_AGENT_SERVICE_NAME="${MARMOT_AGENT_SERVICE_NAME:-wn-agent-hermes}"
MARMOT_AGENT_LAUNCHD_LABEL="${MARMOT_AGENT_LAUNCHD_LABEL:-org.marmot.wn-agent.hermes}"
MARMOT_RELAYS="${MARMOT_RELAYS:-wss://relay.eu.whitenoise.chat,wss://relay.us.whitenoise.chat}"

ASSUME_YES=0
CONFIGURE_HERMES=1
DRY_RUN=0
ENABLE_STREAMING=0
FORCE=0
INSTALL_SERVICE=1
INTERACTIVE=0
NO_START_WN_AGENT=0
SYSTEM_INSTALL=0
CLI_RELAYS=0
BOOTSTRAP_ACCOUNT_ID_HEX=""
BOOTSTRAP_JSON_PATH=""
WN_AGENT_TEMP_PID=""

RELAYS=()
ALLOW_WELCOMERS=()
QUIC_CANDIDATES=()

usage() {
    cat <<'USAGE'
Usage: install-hermes-marmot.sh [options]

Install wn-agent and the Hermes Marmot plugin from a WN Agent GitHub release.
Hermes itself must already be installed.

Options:
  --bootstrap              Compatibility alias; guided bootstrap is the default
  --yes, --non-interactive Use defaults and do not prompt
  --home PATH              Marmot agent home (default: ~/.marmot-agents/hermes)
  --hermes-home PATH       Hermes home (default: $HERMES_HOME or ~/.hermes)
  --allow-welcomer VALUE   Allow invites from this npub or hex pubkey; may repeat
  --relay URL              Relay URL for wn-agent/bootstrap; may repeat
  --enable-streaming       Configure Marmot live preview streaming
  --quic-candidate URI     QUIC preview candidate used with --enable-streaming
  --no-service             Do not install/start a LaunchAgent or systemd user unit
  --no-start-wn-agent      Do not start wn-agent before bootstrap
  --no-configure-hermes    Install assets but do not patch Hermes config.yaml
  --system                 Install wn-agent to /usr/local/bin instead of ~/.local/bin
  --force                  Replace the existing Marmot plugin instead of backing it up
  --dry-run                Print actions without installing
  -h, --help               Show this help

Environment:
  MARMOT_RELEASE_REPO      GitHub repo (default: marmot-protocol/mdk)
  MARMOT_RELEASE_TAG       Release tag (release assets default to their own tag)
  WN_AGENT_VERSION         Asset version suffix (release assets default to their own version)
  WN_AGENT_SHA             Legacy alias for WN_AGENT_VERSION
  MARMOT_INSTALL_PREFIX    Install root for wn-agent (default: ~/.local)
  HERMES_HOME              Hermes home (default: ~/.hermes)
  MARMOT_PLUGIN_DIR        Hermes plugin path (default: $HERMES_HOME/plugins/marmot)
  MARMOT_HOME              wn-agent home (default: ~/.marmot-agents/hermes)
  MARMOT_AGENT_SOCKET      wn-agent socket (default: $MARMOT_HOME/dev/wn-agent.sock)
  MARMOT_AGENT_LABEL       Account label used by bootstrap (default: hermes-agent)
  MARMOT_AGENT_SERVICE_NAME Linux systemd user service name (default: wn-agent-hermes)
  MARMOT_AGENT_LAUNCHD_LABEL macOS LaunchAgent label (default: org.marmot.wn-agent.hermes)
  MARMOT_RELAYS            Relay CSV used by wn-agent and bootstrap
  MARMOT_WELCOMER_ALLOWLIST Comma-separated npub or hex allowlist values

Example:
  curl -fsSL https://github.com/marmot-protocol/mdk/releases/download/wn-agent-latest/install-hermes-marmot.sh | bash

  curl -fsSL .../install-hermes-marmot.sh | bash -s -- --yes --allow-welcomer npub1...
USAGE
}

log() {
    printf 'install-hermes-marmot: %s\n' "$*"
}

warn() {
    printf 'install-hermes-marmot: warning: %s\n' "$*" >&2
}

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] '
        printf '%q ' "$@"
        printf '\n'
        return 0
    fi
    "$@"
}

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: required command not found: $1" >&2
        exit 1
    fi
}

append_csv() {
    local value="$1"
    local item
    local -a _items
    IFS=',' read -r -a _items <<<"$value"
    for item in "${_items[@]}"; do
        item="${item#"${item%%[![:space:]]*}"}"
        item="${item%"${item##*[![:space:]]}"}"
        [ -z "$item" ] || printf '%s\n' "$item"
    done
}

have_tty() {
    [ -r /dev/tty ] && [ -w /dev/tty ]
}

prompt_value() {
    local prompt="$1"
    local default_value="$2"
    local reply=""
    if [ "$INTERACTIVE" -ne 1 ]; then
        printf '%s\n' "$default_value"
        return 0
    fi
    if [ -n "$default_value" ]; then
        printf '%s [%s]: ' "$prompt" "$default_value" >/dev/tty
    else
        printf '%s: ' "$prompt" >/dev/tty
    fi
    IFS= read -r reply </dev/tty || reply=""
    if [ -z "$reply" ]; then
        printf '%s\n' "$default_value"
    else
        printf '%s\n' "$reply"
    fi
}

prompt_yes_no() {
    local prompt="$1"
    local default_value="$2"
    local suffix reply normalized
    if [ "$INTERACTIVE" -ne 1 ]; then
        [ "$default_value" = "yes" ]
        return $?
    fi
    if [ "$default_value" = "yes" ]; then
        suffix="Y/n"
    else
        suffix="y/N"
    fi
    while true; do
        printf '%s [%s]: ' "$prompt" "$suffix" >/dev/tty
        IFS= read -r reply </dev/tty || reply=""
        reply="${reply:-$default_value}"
        normalized="$(printf '%s' "$reply" | tr '[:upper:]' '[:lower:]')"
        case "$normalized" in
            y | yes) return 0 ;;
            n | no) return 1 ;;
            *) printf 'Please answer yes or no.\n' >/dev/tty ;;
        esac
    done
}

is_welcomer_ref_syntax() {
    local value normalized
    value="${1#"${1%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    normalized="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
    case "$normalized" in
        npub1*)
            [[ "$normalized" =~ ^npub1[023456789acdefghjklmnpqrstuvwxyz]+$ ]]
            ;;
        *)
            [[ "$normalized" =~ ^[0-9a-f]{64}$ ]]
            ;;
    esac
}

validate_welcomer_inputs() {
    local welcomer
    if [ "${#ALLOW_WELCOMERS[@]}" -eq 0 ]; then
        return 0
    fi
    for welcomer in "${ALLOW_WELCOMERS[@]}"; do
        if ! is_welcomer_ref_syntax "$welcomer"; then
            echo "error: invalid welcomer allowlist value: $welcomer" >&2
            echo "expected a Nostr npub or 64-character hex account id" >&2
            exit 1
        fi
    done
}

detect_platform() {
    local os arch
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"
    case "$os-$arch" in
        linux-x86_64 | linux-amd64) echo "linux-x86_64" ;;
        linux-aarch64 | linux-arm64) echo "linux-aarch64" ;;
        darwin-arm64 | darwin-aarch64) echo "darwin-aarch64" ;;
        darwin-x86_64) echo "darwin-x86_64" ;;
        *)
            echo "error: unsupported platform: $os/$arch (supported: linux/x86_64, linux/arm64, darwin/arm64, darwin/x86_64)" >&2
            exit 1
            ;;
    esac
}

release_base_url() {
    printf 'https://github.com/%s/releases/download/%s' "$MARMOT_RELEASE_REPO" "$MARMOT_RELEASE_TAG"
}

download_asset() {
    local name="$1"
    local dest="$2"
    local url
    url="$(release_base_url)/$name"
    log "downloading $name"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "url: $url"
        return 0
    fi
    curl -fsSL "$url" -o "$dest"
}

verify_sha256() {
    local asset="$1"
    local checksum_file="$2"
    if [ "$DRY_RUN" -eq 1 ]; then
        return 0
    fi
    local expected actual
    expected="$(awk '{print $1}' "$checksum_file")"
    if command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$asset" | awk '{print $1}')"
    elif command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$asset" | awk '{print $1}')"
    else
        echo "error: need shasum or sha256sum to verify downloads" >&2
        exit 1
    fi
    if [ "$expected" != "$actual" ]; then
        echo "error: checksum mismatch for $(basename "$asset")" >&2
        exit 1
    fi
}

install_dir() {
    if [ "$SYSTEM_INSTALL" -eq 1 ]; then
        printf '/usr/local/bin\n'
    else
        printf '%s/bin\n' "$MARMOT_INSTALL_PREFIX"
    fi
}

wn_agent_path() {
    printf '%s/wn-agent\n' "$(install_dir)"
}

install_wn_agent() {
    local platform="$1"
    local tmpdir="$2"
    local suffix="$WN_AGENT_VERSION"
    local archive="$tmpdir/wn-agent-$platform-$suffix.tar.gz"
    local checksum="$tmpdir/wn-agent-$platform-$suffix.tar.gz.sha256"
    local extract_dir="$tmpdir/wn-agent-extract"
    local target_dir
    target_dir="$(install_dir)"

    download_asset "wn-agent-$platform-$suffix.tar.gz" "$archive"
    download_asset "wn-agent-$platform-$suffix.tar.gz.sha256" "$checksum"
    verify_sha256 "$archive" "$checksum"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "would install wn-agent to $target_dir/wn-agent"
        return 0
    fi

    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"
    tar -xzf "$archive" -C "$extract_dir"
    run mkdir -p "$target_dir"
    run install -m 0755 "$extract_dir/wn-agent-$platform/wn-agent" "$target_dir/wn-agent"
    log "installed wn-agent -> $target_dir/wn-agent"
}

install_plugin() {
    local tmpdir="$1"
    local suffix="$WN_AGENT_VERSION"
    local archive="$tmpdir/hermes-marmot-plugin-$suffix.tar.gz"
    local checksum="$tmpdir/hermes-marmot-plugin-$suffix.tar.gz.sha256"
    local extract_dir="$tmpdir/plugin-extract"
    local backup_dir

    download_asset "hermes-marmot-plugin-$suffix.tar.gz" "$archive"
    download_asset "hermes-marmot-plugin-$suffix.tar.gz.sha256" "$checksum"
    verify_sha256 "$archive" "$checksum"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "would install plugin to $MARMOT_PLUGIN_DIR"
        return 0
    fi

    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"
    tar -xzf "$archive" -C "$extract_dir"

    if [ -e "$MARMOT_PLUGIN_DIR" ]; then
        if [ "$FORCE" -eq 1 ]; then
            run rm -rf "$MARMOT_PLUGIN_DIR"
        else
            backup_dir="${MARMOT_PLUGIN_DIR}.backup.$(date -u +%Y%m%dT%H%M%SZ)"
            run mv "$MARMOT_PLUGIN_DIR" "$backup_dir"
            log "backed up existing Marmot plugin -> $backup_dir"
        fi
    fi

    run mkdir -p "$(dirname "$MARMOT_PLUGIN_DIR")"
    run cp -R "$extract_dir/hermes-marmot-plugin" "$MARMOT_PLUGIN_DIR"
    log "installed Hermes plugin -> $MARMOT_PLUGIN_DIR"
}

enable_hermes_plugin() {
    if [ "$DRY_RUN" -eq 1 ]; then
        log "would run: hermes plugins enable marmot"
        return 0
    fi
    if run hermes plugins enable marmot; then
        log "enabled Hermes plugin: marmot"
    else
        warn "could not auto-enable; run 'hermes plugins enable marmot'"
    fi
}

ensure_path() {
    local bindir
    bindir="$(install_dir)"
    case ":$PATH:" in
        *":$bindir:"*) ;;
        *)
            log "adding $bindir to PATH for this installer run"
            export PATH="$bindir:$PATH"
            ;;
    esac
}

relay_args() {
    local relay
    for relay in "${RELAYS[@]}"; do
        printf '%s\n' "--relay"
        printf '%s\n' "$relay"
    done
}

quic_args() {
    local candidate
    if [ "$ENABLE_STREAMING" -ne 1 ]; then
        printf '%s\n' "--no-quic"
        return 0
    fi
    for candidate in "${QUIC_CANDIDATES[@]}"; do
        printf '%s\n' "--quic-candidate"
        printf '%s\n' "$candidate"
    done
}

allow_welcomer_args() {
    local welcomer
    if [ "${#ALLOW_WELCOMERS[@]}" -gt 0 ]; then
        for welcomer in "${ALLOW_WELCOMERS[@]}"; do
            printf '%s\n' "--allow-welcomer"
            printf '%s\n' "$welcomer"
        done
    fi
}

wait_for_socket() {
    local waited=0
    while [ "$waited" -lt 15 ]; do
        [ -S "$MARMOT_AGENT_SOCKET" ] && return 0
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

plist_string() {
    local value="$1"
    value="${value//&/&amp;}"
    value="${value//</&lt;}"
    value="${value//>/&gt;}"
    value="${value//\"/&quot;}"
    printf '    <string>%s</string>\n' "$value"
}

install_macos_service() {
    local plist_dir plist label program logs_dir relay
    label="$MARMOT_AGENT_LAUNCHD_LABEL"
    plist_dir="$HOME/Library/LaunchAgents"
    plist="$plist_dir/$label.plist"
    program="$(wn_agent_path)"
    logs_dir="$MARMOT_HOME/logs"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "would install LaunchAgent $plist"
        log "would run: launchctl bootstrap gui/$UID $plist"
        return 0
    fi

    run mkdir -p "$plist_dir" "$logs_dir" "$MARMOT_OUTBOUND_MEDIA_DIR" || return 1
    run chmod 0700 "$MARMOT_OUTBOUND_MEDIA_DIR" || return 1
    {
        printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>'
        printf '%s\n' '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">'
        printf '%s\n' '<plist version="1.0">'
        printf '%s\n' '<dict>'
        printf '%s\n' '  <key>Label</key>'
        plist_string "$label"
        printf '%s\n' '  <key>ProgramArguments</key>'
        printf '%s\n' '  <array>'
        plist_string "$program"
        plist_string "--home"
        plist_string "$MARMOT_HOME"
        plist_string "--socket"
        plist_string "$MARMOT_AGENT_SOCKET"
        plist_string "--media-allowed-root"
        plist_string "$MARMOT_OUTBOUND_MEDIA_DIR"
        for relay in "${RELAYS[@]}"; do
            plist_string "--relay"
            plist_string "$relay"
        done
        printf '%s\n' '  </array>'
        printf '%s\n' '  <key>RunAtLoad</key>'
        printf '%s\n' '  <true/>'
        printf '%s\n' '  <key>KeepAlive</key>'
        printf '%s\n' '  <true/>'
        printf '%s\n' '  <key>StandardOutPath</key>'
        plist_string "$logs_dir/wn-agent.out.log"
        printf '%s\n' '  <key>StandardErrorPath</key>'
        plist_string "$logs_dir/wn-agent.err.log"
        printf '%s\n' '</dict>'
        printf '%s\n' '</plist>'
    } >"$plist" || return 1

    launchctl bootout "gui/$UID" "$plist" >/dev/null 2>&1 || true
    if ! run launchctl bootstrap "gui/$UID" "$plist"; then
        warn "launchctl bootstrap failed for $label; falling back to a temporary wn-agent process"
        return 1
    fi
    launchctl kickstart -k "gui/$UID/$label" >/dev/null 2>&1 || true
    log "installed and started LaunchAgent: $label"
}

enable_or_restart_systemd_user_service() {
    local service="$1"
    if systemctl --user is-active --quiet "$service"; then
        run systemctl --user enable "$service" || return 1
        run systemctl --user restart "$service" || return 1
    else
        run systemctl --user enable --now "$service" || return 1
    fi
}

install_linux_user_service() {
    local service_dir service program relay
    if ! command -v systemctl >/dev/null 2>&1; then
        return 1
    fi
    service_dir="$HOME/.config/systemd/user"
    service="$service_dir/$MARMOT_AGENT_SERVICE_NAME.service"
    program="$(wn_agent_path)"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "would install systemd user unit $service"
        log "would enable/start, or restart if already active, systemd user service: $MARMOT_AGENT_SERVICE_NAME.service"
        return 0
    fi

    run mkdir -p "$service_dir" "$MARMOT_HOME/logs" "$MARMOT_OUTBOUND_MEDIA_DIR" || return 1
    run chmod 0700 "$MARMOT_OUTBOUND_MEDIA_DIR" || return 1
    {
        printf '%s\n' '[Unit]'
        printf '%s\n' 'Description=Marmot wn-agent connector'
        printf '%s\n' 'After=network-online.target'
        printf '\n'
        printf '%s\n' '[Service]'
        printf 'ExecStart=%q --home %q --socket %q --media-allowed-root %q' "$program" "$MARMOT_HOME" "$MARMOT_AGENT_SOCKET" "$MARMOT_OUTBOUND_MEDIA_DIR"
        for relay in "${RELAYS[@]}"; do
            printf ' --relay %q' "$relay"
        done
        printf '\n'
        printf '%s\n' 'Restart=always'
        printf '%s\n' 'RestartSec=2'
        printf '\n'
        printf '%s\n' '[Install]'
        printf '%s\n' 'WantedBy=default.target'
    } >"$service" || return 1

    if ! run systemctl --user daemon-reload; then
        warn "systemctl --user daemon-reload failed; falling back to a temporary wn-agent process"
        return 1
    fi
    if ! enable_or_restart_systemd_user_service "$MARMOT_AGENT_SERVICE_NAME.service"; then
        warn "could not enable/start systemd user service $MARMOT_AGENT_SERVICE_NAME.service; falling back to a temporary wn-agent process"
        return 1
    fi
    log "installed and started systemd user service: $MARMOT_AGENT_SERVICE_NAME.service"
}

install_user_service() {
    case "$(uname -s)" in
        Darwin)
            install_macos_service
            ;;
        Linux)
            if ! install_linux_user_service; then
                warn "systemd user service not available; wn-agent will not be installed as a service"
                return 1
            fi
            ;;
        *)
            warn "no supported same-user service manager for $(uname -s)"
            return 1
            ;;
    esac
}

start_temp_agent() {
    if [ "$NO_START_WN_AGENT" -eq 1 ]; then
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] wn-agent --home %q --socket %q --media-allowed-root %q' "$MARMOT_HOME" "$MARMOT_AGENT_SOCKET" "$MARMOT_OUTBOUND_MEDIA_DIR"
        local relay
        for relay in "${RELAYS[@]}"; do
            printf ' --relay %q' "$relay"
        done
        printf '\n'
        return 0
    fi
    if [ -S "$MARMOT_AGENT_SOCKET" ]; then
        log "found existing wn-agent socket: $MARMOT_AGENT_SOCKET"
        return 0
    fi
    run mkdir -p "$MARMOT_HOME" "$MARMOT_OUTBOUND_MEDIA_DIR"
    run chmod 0700 "$MARMOT_OUTBOUND_MEDIA_DIR"
    local -a args=(--home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET" --media-allowed-root "$MARMOT_OUTBOUND_MEDIA_DIR")
    local relay
    for relay in "${RELAYS[@]}"; do
        args+=(--relay "$relay")
    done
    log "starting temporary wn-agent for bootstrap"
    wn-agent "${args[@]}" &
    WN_AGENT_TEMP_PID="$!"
    log "temporary wn-agent pid: $WN_AGENT_TEMP_PID"
}

bootstrap_agent() {
    ensure_path
    if [ "$DRY_RUN" -eq 0 ]; then
        need_cmd wn-agent
    fi

    if [ "$INSTALL_SERVICE" -eq 1 ] && [ "$NO_START_WN_AGENT" -ne 1 ]; then
        install_user_service || start_temp_agent
    else
        start_temp_agent
    fi

    if [ "$DRY_RUN" -eq 0 ] && ! wait_for_socket; then
        warn "wn-agent socket did not appear before bootstrap wait; bootstrap will keep waiting briefly"
    fi

    local -a args=(
        bootstrap
        --json
        --home "$MARMOT_HOME"
        --socket "$MARMOT_AGENT_SOCKET"
        --label "$MARMOT_AGENT_LABEL"
    )
    local relay
    for relay in "${RELAYS[@]}"; do
        args+=(--relay "$relay")
    done
    if [ "$ENABLE_STREAMING" -eq 1 ]; then
        local candidate
        for candidate in "${QUIC_CANDIDATES[@]}"; do
            args+=(--quic-candidate "$candidate")
        done
    else
        args+=(--no-quic)
    fi
    local welcomer
    if [ "${#ALLOW_WELCOMERS[@]}" -gt 0 ]; then
        for welcomer in "${ALLOW_WELCOMERS[@]}"; do
            args+=(--allow-welcomer "$welcomer")
        done
    fi

    log "running wn-agent bootstrap"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] wn-agent'
        printf ' %q' "${args[@]}"
        printf '\n'
        BOOTSTRAP_ACCOUNT_ID_HEX="<account-id-from-bootstrap>"
        BOOTSTRAP_JSON_PATH="$MARMOT_HOME/bootstrap.json"
        return 0
    fi

    run mkdir -p "$MARMOT_HOME"
    local bootstrap_json
    bootstrap_json="$(wn-agent "${args[@]}")"
    BOOTSTRAP_JSON_PATH="$MARMOT_HOME/bootstrap.json"
    printf '%s\n' "$bootstrap_json" >"$BOOTSTRAP_JSON_PATH"
    BOOTSTRAP_ACCOUNT_ID_HEX="$(
        printf '%s\n' "$bootstrap_json" |
            python3 -c 'import json, sys; print(json.load(sys.stdin)["account_id_hex"])'
    )"
    log "bootstrap details -> $BOOTSTRAP_JSON_PATH"
}

configure_hermes_gateway() {
    if [ "$CONFIGURE_HERMES" -ne 1 ]; then
        return 0
    fi
    local helper="$MARMOT_PLUGIN_DIR/configure_gateway.py"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "would patch Hermes config: $HERMES_HOME/config.yaml"
        log "would preserve other Hermes connectors and only update platforms.marmot/display.platforms.marmot"
        return 0
    fi
    if [ ! -f "$helper" ]; then
        echo "error: Hermes config helper not found in plugin: $helper" >&2
        exit 1
    fi

    local -a args=(
        "$helper"
        --home "$HERMES_HOME"
        --agent-home "$MARMOT_HOME"
        --socket-path "$MARMOT_AGENT_SOCKET"
        --account-id-hex "$BOOTSTRAP_ACCOUNT_ID_HEX"
        --tool-progress off
        --interim-messages 0
        --long-running-notifications 0
        --busy-ack-detail 0
    )
    if [ "$ENABLE_STREAMING" -eq 1 ]; then
        args+=(--streaming 1 --transport auto --configure-global-streaming)
    else
        args+=(--streaming 0 --transport off)
    fi
    if [ "${#ALLOW_WELCOMERS[@]}" -gt 0 ]; then
        local welcomer
        for welcomer in "${ALLOW_WELCOMERS[@]}"; do
            args+=(--welcomer-allowlist "$welcomer")
        done
    fi
    run python3 "${args[@]}"
}

print_next_steps() {
    cat <<EOF

Install complete.

Marmot agent:
  label: $MARMOT_AGENT_LABEL
  home: $MARMOT_HOME
  socket: $MARMOT_AGENT_SOCKET
  service: $MARMOT_AGENT_SERVICE_NAME.service (Linux) / $MARMOT_AGENT_LAUNCHD_LABEL (macOS)
  account: $BOOTSTRAP_ACCOUNT_ID_HEX
  bootstrap JSON: $BOOTSTRAP_JSON_PATH
EOF
    if [ -n "${WN_AGENT_TEMP_PID:-}" ]; then
        cat <<EOF
  temporary process: pid $WN_AGENT_TEMP_PID (stop with: kill $WN_AGENT_TEMP_PID)
EOF
    fi
    cat <<EOF

Hermes:
  home: $HERMES_HOME
  plugin: $MARMOT_PLUGIN_DIR

Restart your existing Hermes gateway when you are ready for it to load the Marmot plugin/config:
  hermes gateway run

Existing Hermes connectors were not removed or disabled. The installer only updated the Marmot plugin and Marmot-specific config entries.

Build: ${MARMOT_RELEASE_REPO}@${MARMOT_RELEASE_TAG} (${WN_AGENT_VERSION})
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --bootstrap)
            shift
            ;;
        --yes | --non-interactive)
            ASSUME_YES=1
            shift
            ;;
        --home)
            MARMOT_HOME="${2:?missing value for --home}"
            MARMOT_AGENT_SOCKET_OVERRIDE=""
            shift 2
            ;;
        --hermes-home)
            HERMES_HOME="${2:?missing value for --hermes-home}"
            shift 2
            ;;
        --allow-welcomer)
            ALLOW_WELCOMERS+=("${2:?missing value for --allow-welcomer}")
            shift 2
            ;;
        --relay)
            CLI_RELAYS=1
            RELAYS+=("${2:?missing value for --relay}")
            shift 2
            ;;
        --enable-streaming)
            ENABLE_STREAMING=1
            shift
            ;;
        --quic-candidate)
            QUIC_CANDIDATES+=("${2:?missing value for --quic-candidate}")
            shift 2
            ;;
        --no-service)
            INSTALL_SERVICE=0
            shift
            ;;
        --no-start-wn-agent)
            NO_START_WN_AGENT=1
            shift
            ;;
        --no-configure-hermes)
            CONFIGURE_HERMES=0
            shift
            ;;
        --system)
            SYSTEM_INSTALL=1
            shift
            ;;
        --force)
            FORCE=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [ "$ASSUME_YES" -ne 1 ] && have_tty; then
    INTERACTIVE=1
fi
if [ "$ASSUME_YES" -eq 1 ]; then
    INTERACTIVE=0
fi

MARMOT_PLUGIN_DIR="${MARMOT_PLUGIN_DIR_OVERRIDE:-$HERMES_HOME/plugins/marmot}"
MARMOT_AGENT_SOCKET="${MARMOT_AGENT_SOCKET_OVERRIDE:-$MARMOT_HOME/dev/wn-agent.sock}"

if [ "$CLI_RELAYS" -eq 0 ]; then
    while IFS= read -r relay; do
        RELAYS+=("$relay")
    done < <(append_csv "$MARMOT_RELAYS")
fi
if [ "${#RELAYS[@]}" -eq 0 ]; then
    RELAYS+=("wss://relay.eu.whitenoise.chat" "wss://relay.us.whitenoise.chat")
fi
if [ -n "${MARMOT_WELCOMER_ALLOWLIST:-}" ]; then
    while IFS= read -r welcomer; do
        ALLOW_WELCOMERS+=("$welcomer")
    done < <(append_csv "$MARMOT_WELCOMER_ALLOWLIST")
fi
if [ "${#QUIC_CANDIDATES[@]}" -eq 0 ]; then
    QUIC_CANDIDATES+=("quic://quic-broker.ipf.dev:4450")
fi

if [ "$INTERACTIVE" -eq 1 ]; then
    log "guided setup will prompt on /dev/tty; press Enter to accept defaults"
    HERMES_HOME="$(prompt_value "Hermes home" "$HERMES_HOME")"
    MARMOT_HOME="$(prompt_value "Marmot agent home" "$MARMOT_HOME")"
    MARMOT_PLUGIN_DIR="${MARMOT_PLUGIN_DIR_OVERRIDE:-$HERMES_HOME/plugins/marmot}"
    MARMOT_AGENT_SOCKET="${MARMOT_AGENT_SOCKET_OVERRIDE:-$MARMOT_HOME/dev/wn-agent.sock}"
    if [ -e "$MARMOT_HOME" ]; then
        log "existing Marmot agent home detected; bootstrap will reuse or repair it: $MARMOT_HOME"
    fi
    if [ "${#ALLOW_WELCOMERS[@]}" -eq 0 ]; then
        while true; do
            welcomer_reply="$(prompt_value "Allowed inviter/welcomer npub or hex (blank to skip)" "")"
            if [ -n "$welcomer_reply" ]; then
                ALLOW_WELCOMERS+=("$welcomer_reply")
                break
            fi
            if prompt_yes_no "Skip the welcomer allowlist for now? Invites will not auto-accept." "no"; then
                break
            fi
        done
    fi
fi

MARMOT_OUTBOUND_MEDIA_DIR="${MARMOT_OUTBOUND_MEDIA_DIR_OVERRIDE:-$MARMOT_HOME/dev/outbound-media}"

validate_welcomer_inputs

need_cmd curl
need_cmd tar
if [ "$DRY_RUN" -eq 0 ]; then
    need_cmd hermes
    if [ "$CONFIGURE_HERMES" -eq 1 ]; then
        need_cmd python3
    fi
else
    log "would require hermes on PATH"
fi

platform="$(detect_platform)"
tmpdir="$(mktemp -d)"
cleanup() {
    local status=$?
    rm -rf "$tmpdir"
    if [ "$status" -ne 0 ] && [ -n "${WN_AGENT_TEMP_PID:-}" ]; then
        kill "$WN_AGENT_TEMP_PID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

log "platform=$platform repo=$MARMOT_RELEASE_REPO tag=$MARMOT_RELEASE_TAG version=$WN_AGENT_VERSION"
log "Hermes home: $HERMES_HOME"
log "Marmot home: $MARMOT_HOME"
log "Marmot socket: $MARMOT_AGENT_SOCKET"
log "Marmot agent label: $MARMOT_AGENT_LABEL"
install_wn_agent "$platform" "$tmpdir"
install_plugin "$tmpdir"
enable_hermes_plugin
bootstrap_agent
configure_hermes_gateway
print_next_steps
