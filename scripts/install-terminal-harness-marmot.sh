#!/usr/bin/env bash
set -euo pipefail

# Shared installer implementation for Marmot terminal harnesses.
# MARMOT_TERMINAL_HARNESS must be `codex`, `pi`, or `opencode`.

SCRIPT_SOURCE="${BASH_SOURCE[0]:-}"
SCRIPT_DIR=""
if [ -n "$SCRIPT_SOURCE" ] && [ -f "$SCRIPT_SOURCE" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_SOURCE")" && pwd)"
fi

HARNESS_KIND="${MARMOT_TERMINAL_HARNESS:-}"
case "$HARNESS_KIND" in
    codex)
        HARNESS_DISPLAY_NAME="Codex"
        HARNESS_ENV_PREFIX="WN_CODEX"
        HARNESS_DEFAULT_BIN="codex"
        HARNESS_FALLBACK_BIN_DIR="$HOME/.local/bin"
        HARNESS_DEFAULT_HOME="$HOME/.marmot-agents/codex"
        HARNESS_DEFAULT_AGENT_LABEL="codex-harness-agent"
        HARNESS_DEFAULT_AGENT_SERVICE="wn-agent-codex"
        HARNESS_DEFAULT_AGENT_LAUNCHD="org.marmot.wn-agent.codex"
        ;;
    pi)
        HARNESS_DISPLAY_NAME="Pi"
        HARNESS_ENV_PREFIX="WN_PI"
        HARNESS_DEFAULT_BIN="pi"
        HARNESS_FALLBACK_BIN_DIR="$HOME/.pi/bin"
        HARNESS_DEFAULT_HOME="$HOME/.marmot-agents/pi"
        HARNESS_DEFAULT_AGENT_LABEL="pi-harness-agent"
        HARNESS_DEFAULT_AGENT_SERVICE="wn-agent-pi"
        HARNESS_DEFAULT_AGENT_LAUNCHD="org.marmot.wn-agent.pi"
        ;;
    opencode)
        HARNESS_DISPLAY_NAME="OpenCode"
        HARNESS_ENV_PREFIX="WN_OPENCODE"
        HARNESS_DEFAULT_BIN="opencode"
        HARNESS_FALLBACK_BIN_DIR="$HOME/.opencode/bin"
        HARNESS_DEFAULT_HOME="$HOME/.marmot-agents/harnesses"
        HARNESS_DEFAULT_AGENT_LABEL="terminal-harness-agent"
        HARNESS_DEFAULT_AGENT_SERVICE="wn-agent-harnesses"
        HARNESS_DEFAULT_AGENT_LAUNCHD="org.marmot.wn-agent.harnesses"
        ;;
    *)
        echo "error: MARMOT_TERMINAL_HARNESS must be codex, pi, or opencode" >&2
        exit 64
        ;;
esac
HARNESS_BINARY="wn-$HARNESS_KIND"
HARNESS_BIN_ENV="${HARNESS_ENV_PREFIX}_BIN"
HARNESS_ALLOWED_SENDERS_ENV="${HARNESS_ENV_PREFIX}_ALLOWED_SENDERS_HEX"
HARNESS_ACCOUNT_ID_ENV="${HARNESS_ENV_PREFIX}_ACCOUNT_ID_HEX"
HARNESS_TIMEOUT_ENV="${HARNESS_ENV_PREFIX}_TIMEOUT_SECS"
HARNESS_IDLE_TIMEOUT_ENV="${HARNESS_ENV_PREFIX}_IDLE_TIMEOUT_SECS"
HARNESS_REQUEST_TIMEOUT_ENV="${HARNESS_ENV_PREFIX}_REQUEST_TIMEOUT_SECS"
HARNESS_MAX_REPLY_ENV="${HARNESS_ENV_PREFIX}_MAX_REPLY_BYTES"
HARNESS_MAX_PENDING_ENV="${HARNESS_ENV_PREFIX}_MAX_PENDING_PER_GROUP"
HARNESS_EXECUTION_PROFILE_ENV="MARMOT_HARNESS_EXECUTION_PROFILE"

env_or_default() {
    local name="$1" default_value="$2"
    printf '%s' "${!name:-$default_value}"
}
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
MARMOT_HOME="${MARMOT_HOME:-$HARNESS_DEFAULT_HOME}"
MARMOT_AGENT_SOCKET_OVERRIDE="${MARMOT_AGENT_SOCKET:-}"
MARMOT_AGENT_SOCKET="${MARMOT_AGENT_SOCKET_OVERRIDE:-$MARMOT_HOME/dev/wn-agent.sock}"
MARMOT_AGENT_LABEL="${MARMOT_AGENT_LABEL:-$HARNESS_DEFAULT_AGENT_LABEL}"
MARMOT_AGENT_SERVICE_NAME="${MARMOT_AGENT_SERVICE_NAME:-$HARNESS_DEFAULT_AGENT_SERVICE}"
MARMOT_AGENT_LAUNCHD_LABEL="${MARMOT_AGENT_LAUNCHD_LABEL:-$HARNESS_DEFAULT_AGENT_LAUNCHD}"
MARMOT_HARNESS_SERVICE_NAME="${MARMOT_HARNESS_SERVICE_NAME:-$HARNESS_BINARY}"
MARMOT_HARNESS_LAUNCHD_LABEL="${MARMOT_HARNESS_LAUNCHD_LABEL:-org.marmot.$HARNESS_BINARY}"
MARMOT_RELAYS="${MARMOT_RELAYS:-wss://relay.eu.whitenoise.chat,wss://relay.us.whitenoise.chat}"
HARNESS_BIN="$(env_or_default "$HARNESS_BIN_ENV" "$HARNESS_DEFAULT_BIN")"
HARNESS_TIMEOUT_SECS="$(env_or_default "$HARNESS_TIMEOUT_ENV" 3600)"
HARNESS_IDLE_TIMEOUT_SECS="$(env_or_default "$HARNESS_IDLE_TIMEOUT_ENV" 120)"
HARNESS_REQUEST_TIMEOUT_SECS="$(env_or_default "$HARNESS_REQUEST_TIMEOUT_ENV" 30)"
HARNESS_MAX_REPLY_BYTES="$(env_or_default "$HARNESS_MAX_REPLY_ENV" 30000)"
HARNESS_MAX_PENDING_PER_GROUP="$(env_or_default "$HARNESS_MAX_PENDING_ENV" 4)"
HARNESS_EXECUTION_PROFILE="$(env_or_default "$HARNESS_EXECUTION_PROFILE_ENV" inherit)"
HARNESS_CONFIGURED_SENDERS_HEX="$(env_or_default "$HARNESS_ALLOWED_SENDERS_ENV" "")"

ASSUME_YES=0
DRY_RUN=0
INSTALL_SERVICE=1
INTERACTIVE=0
NO_START_WN_AGENT=0
NO_START_HARNESS=0
SYSTEM_INSTALL=0
ACKNOWLEDGE_UNRESTRICTED=0
WN_AGENT_TEMP_PID=""
BOOTSTRAP_ACCOUNT_ID_HEX=""
BOOTSTRAP_ALLOWED_SENDERS_HEX=""
BOOTSTRAP_NPUB=""
BOOTSTRAP_NPROFILE=""
MARMOT_AGENT_SOCKET_SET=0
if [ -n "$MARMOT_AGENT_SOCKET_OVERRIDE" ]; then
    MARMOT_AGENT_SOCKET_SET=1
fi

RELAYS=()
ALLOW_WELCOMERS=()

usage() {
    cat <<USAGE
Usage: install-$HARNESS_KIND-marmot.sh [options]

Install wn-agent and $HARNESS_BINARY from a WN Agent GitHub release. $HARNESS_DISPLAY_NAME
itself must already be installed.

Options:
  --bootstrap              Compatibility alias; guided bootstrap is the default
  --yes, --non-interactive Use defaults and do not prompt
  --home PATH              Marmot terminal harness agent home (default: $HARNESS_DEFAULT_HOME)
  --socket PATH            wn-agent socket (default: \$MARMOT_HOME/dev/wn-agent.sock)
  --allow-welcomer VALUE   Allow invites/prompts from this npub or hex pubkey; may repeat
  --allow-sender VALUE     Alias for --allow-welcomer
  --relay URL              Relay URL for wn-agent/bootstrap; may repeat
  --$HARNESS_KIND-bin PATH      $HARNESS_DISPLAY_NAME binary or command name (default: $HARNESS_DEFAULT_BIN)
  --execution-profile PROFILE  inherit, autonomous, or unrestricted (default: inherit)
  --acknowledge-unrestricted   Confirm that unrestricted requires external isolation
  --no-service             Do not install/start LaunchAgents or systemd user units
  --no-start-wn-agent      Install services but do not start wn-agent or the harness
  --no-start-$HARNESS_BINARY   Install the service but do not activate it
  --system                 Install binaries to /usr/local/bin instead of ~/.local/bin
  --dry-run                Print actions without installing
  -h, --help               Show this help

Environment:
  MARMOT_RELEASE_REPO      GitHub repo (default: marmot-protocol/mdk)
  MARMOT_RELEASE_TAG       Release tag (release assets default to their own tag)
  WN_AGENT_VERSION         Asset version suffix (release assets default to their own version)
  WN_AGENT_SHA             Legacy alias for WN_AGENT_VERSION
  MARMOT_INSTALL_PREFIX    Install root for binaries (default: ~/.local)
  MARMOT_HOME              wn-agent home (default: $HARNESS_DEFAULT_HOME)
  MARMOT_AGENT_SOCKET      wn-agent socket (default: \$MARMOT_HOME/dev/wn-agent.sock)
  MARMOT_AGENT_LABEL       Account label used by bootstrap (default: $HARNESS_DEFAULT_AGENT_LABEL)
  MARMOT_AGENT_SERVICE_NAME Linux wn-agent systemd user service name
  MARMOT_AGENT_LAUNCHD_LABEL macOS wn-agent LaunchAgent label
  MARMOT_HARNESS_SERVICE_NAME Linux harness service name (default: $HARNESS_BINARY)
  MARMOT_HARNESS_LAUNCHD_LABEL macOS harness LaunchAgent label (default: org.marmot.$HARNESS_BINARY)
  MARMOT_RELAYS            Relay CSV used by wn-agent and bootstrap
  MARMOT_WELCOMER_ALLOWLIST Comma-separated npub or hex allowlist values
  $HARNESS_ALLOWED_SENDERS_ENV Comma-separated hex values for prompt senders
  $HARNESS_BIN_ENV          $HARNESS_DISPLAY_NAME binary or command name
  MARMOT_HARNESS_EXECUTION_PROFILE Shared execution profile (default: inherit)

Example:
  curl -fsSL https://github.com/marmot-protocol/mdk/releases/download/$MARMOT_RELEASE_TAG/install-$HARNESS_KIND-marmot.sh | bash

  curl -fsSL .../install-$HARNESS_KIND-marmot.sh | bash -s -- --yes --allow-welcomer npub1...
USAGE
}

log() {
    printf 'install-%s-marmot: %s\n' "$HARNESS_KIND" "$*"
}

warn() {
    printf 'install-%s-marmot: warning: %s\n' "$HARNESS_KIND" "$*" >&2
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
    for item in ${_items[@]+"${_items[@]}"}; do
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

is_welcomer_ref_syntax() {
    local value normalized
    value="${1#"${1%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    normalized="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
    case "$normalized" in
        npub1*)
            [[ "$normalized" =~ ^npub1[023456789acdefghjklmnpqrstuvwxyz]{58}$ ]]
            ;;
        *)
            [[ "$normalized" =~ ^[0-9a-f]{64}$ ]]
            ;;
    esac
}

validate_welcomer_inputs() {
    local welcomer
    if [ "${#ALLOW_WELCOMERS[@]}" -eq 0 ]; then
        echo "error: at least one --allow-welcomer/--allow-sender value is required" >&2
        exit 1
    fi
    for welcomer in ${ALLOW_WELCOMERS[@]+"${ALLOW_WELCOMERS[@]}"}; do
        if ! is_welcomer_ref_syntax "$welcomer"; then
            echo "error: invalid allowlist value: $welcomer" >&2
            echo "expected a Nostr npub or 64-character hex account id" >&2
            exit 1
        fi
    done
}

validate_prompt_senders() {
    local sender normalized
    [ -n "$HARNESS_CONFIGURED_SENDERS_HEX" ] || return 0
    while IFS= read -r sender; do
        normalized="$(printf '%s' "$sender" | tr '[:upper:]' '[:lower:]')"
        if [[ ! "$normalized" =~ ^[0-9a-f]{64}$ ]]; then
            echo "error: $HARNESS_ALLOWED_SENDERS_ENV entries must be 64-character hex ids" >&2
            exit 1
        fi
    done < <(append_csv "$HARNESS_CONFIGURED_SENDERS_HEX")
}

validate_execution_profile() {
    case "$HARNESS_EXECUTION_PROFILE" in
        inherit | autonomous) ;;
        unrestricted)
            if [ "$ACKNOWLEDGE_UNRESTRICTED" -ne 1 ]; then
                echo "error: --acknowledge-unrestricted is required before writing the unrestricted execution profile" >&2
                exit 1
            fi
            ;;
        *)
            echo "error: --execution-profile must be inherit, autonomous, or unrestricted" >&2
            exit 1
            ;;
    esac
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
    curl -fsSL --connect-timeout 10 --max-time 120 "$url" -o "$dest"
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

harness_path() {
    printf '%s/%s\n' "$(install_dir)" "$HARNESS_BINARY"
}

install_binary_bundle() {
    local binary="$1"
    local platform="$2"
    local tmpdir="$3"
    local suffix="$WN_AGENT_VERSION"
    local archive="$tmpdir/$binary-$platform-$suffix.tar.gz"
    local checksum="$tmpdir/$binary-$platform-$suffix.tar.gz.sha256"
    local extract_dir="$tmpdir/$binary-extract"
    local target_dir
    target_dir="$(install_dir)"

    download_asset "$binary-$platform-$suffix.tar.gz" "$archive"
    download_asset "$binary-$platform-$suffix.tar.gz.sha256" "$checksum"
    verify_sha256 "$archive" "$checksum"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "would install $binary to $target_dir/$binary"
        return 0
    fi

    local archive_members member expected_member
    archive_members="$(tar -tzf "$archive")"
    while IFS= read -r member; do
        case "$member" in
            /* | .. | ../* | */../* | */..) echo "error: unsafe archive member: $member" >&2; exit 1 ;;
        esac
    done <<<"$archive_members"
    expected_member="$binary-$platform/$binary"
    if ! grep -Fx "$expected_member" <<<"$archive_members" >/dev/null; then
        echo "error: archive did not contain $expected_member" >&2
        exit 1
    fi
    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"
    tar -xzf "$archive" -C "$extract_dir" --no-same-owner "$expected_member"
    run mkdir -p "$target_dir"
    run install -m 0755 "$extract_dir/$binary-$platform/$binary" "$target_dir/$binary"
    log "installed $binary -> $target_dir/$binary"
}

resolve_harness_bin() {
    if [ "$DRY_RUN" -eq 1 ]; then
        log "would require $HARNESS_DISPLAY_NAME binary: $HARNESS_BIN"
        return 0
    fi
    if [[ "$HARNESS_BIN" == */* ]]; then
        if [ ! -x "$HARNESS_BIN" ]; then
            echo "error: $HARNESS_BIN_ENV is not executable: $HARNESS_BIN" >&2
            exit 1
        fi
        HARNESS_BIN="$(cd "$(dirname "$HARNESS_BIN")" && pwd)/$(basename "$HARNESS_BIN")"
        return 0
    fi
    if command -v "$HARNESS_BIN" >/dev/null 2>&1; then
        HARNESS_BIN="$(command -v "$HARNESS_BIN")"
        return 0
    fi
    local fallback_bin="$HARNESS_FALLBACK_BIN_DIR/$HARNESS_BIN"
    if [ ! -x "$fallback_bin" ]; then
        echo "error: $HARNESS_DISPLAY_NAME binary not found: $HARNESS_BIN" >&2
        echo "install $HARNESS_DISPLAY_NAME first or set $HARNESS_BIN_ENV/--$HARNESS_KIND-bin" >&2
        exit 1
    fi
    HARNESS_BIN="$fallback_bin"
    log "found $HARNESS_DISPLAY_NAME binary: $HARNESS_BIN"
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

plist_env_entry() {
    local key="$1"
    local value="$2"
    printf '    <key>%s</key>\n' "$key"
    plist_string "$value"
}

install_macos_wn_agent_service() {
    local plist_dir plist label program logs_dir relay
    label="$MARMOT_AGENT_LAUNCHD_LABEL"
    plist_dir="$HOME/Library/LaunchAgents"
    plist="$plist_dir/$label.plist"
    program="$(wn_agent_path)"
    logs_dir="$MARMOT_HOME/logs"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "would install LaunchAgent $plist"
        if [ "$NO_START_WN_AGENT" -eq 1 ]; then
            log "would install LaunchAgent without starting it: $label"
        else
            log "would run: launchctl bootstrap gui/$UID $plist"
        fi
        return 0
    fi

    run mkdir -p "$plist_dir" "$logs_dir" || return 1
    (
        umask 077
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
        for relay in ${RELAYS[@]+"${RELAYS[@]}"}; do
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
        } >"$plist"
    ) || return 1
    chmod 600 "$plist" || return 1

    if [ "$NO_START_WN_AGENT" -eq 1 ]; then
        log "installed LaunchAgent without starting it: $label"
        return 0
    fi
    launchctl bootout "gui/$UID" "$plist" >/dev/null 2>&1 || true
    run launchctl bootstrap "gui/$UID" "$plist" || return 1
    launchctl kickstart -k "gui/$UID/$label" >/dev/null 2>&1 || true
    log "installed and started LaunchAgent: $label"
}

install_macos_harness_service() {
    local plist_dir plist label program logs_dir
    label="$MARMOT_HARNESS_LAUNCHD_LABEL"
    plist_dir="$HOME/Library/LaunchAgents"
    plist="$plist_dir/$label.plist"
    program="$(harness_path)"
    logs_dir="$MARMOT_HOME/logs"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "would install LaunchAgent $plist"
        if [ "$NO_START_HARNESS" -eq 1 ] || [ "$NO_START_WN_AGENT" -eq 1 ]; then
            log "would install LaunchAgent without starting it: $label"
        else
            log "would run: launchctl bootstrap gui/$UID $plist"
        fi
        log "env: $HARNESS_EXECUTION_PROFILE_ENV=$HARNESS_EXECUTION_PROFILE $HARNESS_TIMEOUT_ENV=$HARNESS_TIMEOUT_SECS $HARNESS_IDLE_TIMEOUT_ENV=$HARNESS_IDLE_TIMEOUT_SECS $HARNESS_REQUEST_TIMEOUT_ENV=$HARNESS_REQUEST_TIMEOUT_SECS $HARNESS_MAX_REPLY_ENV=$HARNESS_MAX_REPLY_BYTES $HARNESS_MAX_PENDING_ENV=$HARNESS_MAX_PENDING_PER_GROUP"
        return 0
    fi

    run mkdir -p "$plist_dir" "$logs_dir" || return 1
    (
        umask 077
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
        printf '%s\n' '  </array>'
        printf '%s\n' '  <key>EnvironmentVariables</key>'
        printf '%s\n' '  <dict>'
        plist_env_entry "MARMOT_HOME" "$MARMOT_HOME"
        plist_env_entry "MARMOT_AGENT_SOCKET" "$MARMOT_AGENT_SOCKET"
        plist_env_entry "$HARNESS_ACCOUNT_ID_ENV" "$BOOTSTRAP_ACCOUNT_ID_HEX"
        plist_env_entry "$HARNESS_ALLOWED_SENDERS_ENV" "$BOOTSTRAP_ALLOWED_SENDERS_HEX"
        plist_env_entry "$HARNESS_BIN_ENV" "$HARNESS_BIN"
        plist_env_entry "$HARNESS_EXECUTION_PROFILE_ENV" "$HARNESS_EXECUTION_PROFILE"
        plist_env_entry "$HARNESS_TIMEOUT_ENV" "$HARNESS_TIMEOUT_SECS"
        plist_env_entry "$HARNESS_IDLE_TIMEOUT_ENV" "$HARNESS_IDLE_TIMEOUT_SECS"
        plist_env_entry "$HARNESS_REQUEST_TIMEOUT_ENV" "$HARNESS_REQUEST_TIMEOUT_SECS"
        plist_env_entry "$HARNESS_MAX_REPLY_ENV" "$HARNESS_MAX_REPLY_BYTES"
        plist_env_entry "$HARNESS_MAX_PENDING_ENV" "$HARNESS_MAX_PENDING_PER_GROUP"
        printf '%s\n' '  </dict>'
        printf '%s\n' '  <key>RunAtLoad</key>'
        printf '%s\n' '  <true/>'
        printf '%s\n' '  <key>KeepAlive</key>'
        printf '%s\n' '  <true/>'
        printf '%s\n' '  <key>StandardOutPath</key>'
        plist_string "$logs_dir/$HARNESS_BINARY.out.log"
        printf '%s\n' '  <key>StandardErrorPath</key>'
        plist_string "$logs_dir/$HARNESS_BINARY.err.log"
        printf '%s\n' '</dict>'
        printf '%s\n' '</plist>'
        } >"$plist"
    ) || return 1
    chmod 600 "$plist" || return 1

    if [ "$NO_START_HARNESS" -eq 1 ] || [ "$NO_START_WN_AGENT" -eq 1 ]; then
        log "installed LaunchAgent without starting it: $label"
        return 0
    fi
    launchctl bootout "gui/$UID" "$plist" >/dev/null 2>&1 || true
    run launchctl bootstrap "gui/$UID" "$plist" || return 1
    launchctl kickstart -k "gui/$UID/$label" >/dev/null 2>&1 || true
    log "installed and started LaunchAgent: $label"
}

systemd_quote() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//\$/\$\$}"
    value="${value//%/%%}"
    printf '"%s"' "$value"
}

activate_systemd_user_service() {
    local unit="$1"
    if systemctl --user is-active --quiet "$unit"; then
        run systemctl --user enable "$unit" || return 1
        run systemctl --user restart "$unit" || return 1
    else
        run systemctl --user enable --now "$unit" || return 1
    fi
}

install_linux_wn_agent_service() {
    local service_dir service program relay
    service_dir="$HOME/.config/systemd/user"
    service="$service_dir/$MARMOT_AGENT_SERVICE_NAME.service"
    program="$(wn_agent_path)"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "would install systemd user unit $service"
        if [ "$NO_START_WN_AGENT" -eq 1 ]; then
            log "would install systemd user service without starting it: $MARMOT_AGENT_SERVICE_NAME.service"
        else
            log "would restart $MARMOT_AGENT_SERVICE_NAME.service when active; otherwise enable --now"
        fi
        return 0
    fi

    if ! command -v systemctl >/dev/null 2>&1; then
        return 1
    fi

    run mkdir -p "$service_dir" "$MARMOT_HOME/logs" || return 1
    (
        umask 077
        {
        printf '%s\n' '[Unit]'
        printf '%s\n' 'Description=Marmot wn-agent connector'
        printf '%s\n' 'After=network-online.target'
        printf '\n'
        printf '%s\n' '[Service]'
        printf 'ExecStart=%s %s %s %s %s' \
            "$(systemd_quote "$program")" \
            "$(systemd_quote --home)" \
            "$(systemd_quote "$MARMOT_HOME")" \
            "$(systemd_quote --socket)" \
            "$(systemd_quote "$MARMOT_AGENT_SOCKET")"
        for relay in ${RELAYS[@]+"${RELAYS[@]}"}; do
            printf ' %s %s' "$(systemd_quote --relay)" "$(systemd_quote "$relay")"
        done
        printf '\n'
        printf '%s\n' 'Restart=always'
        printf '%s\n' 'RestartSec=2'
        printf '\n'
        printf '%s\n' '[Install]'
        printf '%s\n' 'WantedBy=default.target'
        } >"$service"
    ) || return 1
    chmod 600 "$service" || return 1

    run systemctl --user daemon-reload || return 1
    if [ "$NO_START_WN_AGENT" -eq 1 ]; then
        run systemctl --user enable "$MARMOT_AGENT_SERVICE_NAME.service" || return 1
        log "installed and enabled systemd user service without starting it: $MARMOT_AGENT_SERVICE_NAME.service"
        return 0
    fi
    activate_systemd_user_service "$MARMOT_AGENT_SERVICE_NAME.service" || return 1
    log "installed and started systemd user service: $MARMOT_AGENT_SERVICE_NAME.service"
}

install_linux_harness_service() {
    local service_dir service program
    service_dir="$HOME/.config/systemd/user"
    service="$service_dir/$MARMOT_HARNESS_SERVICE_NAME.service"
    program="$(harness_path)"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "would install systemd user unit $service"
        if [ "$NO_START_HARNESS" -eq 1 ] || [ "$NO_START_WN_AGENT" -eq 1 ]; then
            log "would install systemd user service without starting it: $MARMOT_HARNESS_SERVICE_NAME.service"
        else
            log "would restart $MARMOT_HARNESS_SERVICE_NAME.service when active; otherwise enable --now"
        fi
        log "env: $HARNESS_EXECUTION_PROFILE_ENV=$HARNESS_EXECUTION_PROFILE $HARNESS_TIMEOUT_ENV=$HARNESS_TIMEOUT_SECS $HARNESS_IDLE_TIMEOUT_ENV=$HARNESS_IDLE_TIMEOUT_SECS $HARNESS_REQUEST_TIMEOUT_ENV=$HARNESS_REQUEST_TIMEOUT_SECS $HARNESS_MAX_REPLY_ENV=$HARNESS_MAX_REPLY_BYTES $HARNESS_MAX_PENDING_ENV=$HARNESS_MAX_PENDING_PER_GROUP"
        return 0
    fi

    if ! command -v systemctl >/dev/null 2>&1; then
        return 1
    fi

    run mkdir -p "$service_dir" "$MARMOT_HOME/logs" || return 1
    (
        umask 077
        {
        printf '%s\n' '[Unit]'
        printf 'Description=Marmot %s harness\n' "$HARNESS_BINARY"
        printf '%s\n' "After=$MARMOT_AGENT_SERVICE_NAME.service"
        printf '%s\n' "Requires=$MARMOT_AGENT_SERVICE_NAME.service"
        printf '\n'
        printf '%s\n' '[Service]'
        printf 'Environment=%s\n' "$(systemd_quote "MARMOT_HOME=$MARMOT_HOME")"
        printf 'Environment=%s\n' "$(systemd_quote "MARMOT_AGENT_SOCKET=$MARMOT_AGENT_SOCKET")"
        printf 'Environment=%s\n' "$(systemd_quote "$HARNESS_ACCOUNT_ID_ENV=$BOOTSTRAP_ACCOUNT_ID_HEX")"
        printf 'Environment=%s\n' "$(systemd_quote "$HARNESS_ALLOWED_SENDERS_ENV=$BOOTSTRAP_ALLOWED_SENDERS_HEX")"
        printf 'Environment=%s\n' "$(systemd_quote "$HARNESS_BIN_ENV=$HARNESS_BIN")"
        printf 'Environment=%s\n' "$(systemd_quote "$HARNESS_EXECUTION_PROFILE_ENV=$HARNESS_EXECUTION_PROFILE")"
        printf 'Environment=%s\n' "$(systemd_quote "$HARNESS_TIMEOUT_ENV=$HARNESS_TIMEOUT_SECS")"
        printf 'Environment=%s\n' "$(systemd_quote "$HARNESS_IDLE_TIMEOUT_ENV=$HARNESS_IDLE_TIMEOUT_SECS")"
        printf 'Environment=%s\n' "$(systemd_quote "$HARNESS_REQUEST_TIMEOUT_ENV=$HARNESS_REQUEST_TIMEOUT_SECS")"
        printf 'Environment=%s\n' "$(systemd_quote "$HARNESS_MAX_REPLY_ENV=$HARNESS_MAX_REPLY_BYTES")"
        printf 'Environment=%s\n' "$(systemd_quote "$HARNESS_MAX_PENDING_ENV=$HARNESS_MAX_PENDING_PER_GROUP")"
        printf 'ExecStart=%s\n' "$(systemd_quote "$program")"
        printf '%s\n' 'Restart=always'
        printf '%s\n' 'RestartSec=2'
        printf '\n'
        printf '%s\n' '[Install]'
        printf '%s\n' 'WantedBy=default.target'
        } >"$service"
    ) || return 1
    chmod 600 "$service" || return 1

    run systemctl --user daemon-reload || return 1
    if [ "$NO_START_HARNESS" -eq 1 ] || [ "$NO_START_WN_AGENT" -eq 1 ]; then
        run systemctl --user enable "$MARMOT_HARNESS_SERVICE_NAME.service" || return 1
        log "installed and enabled systemd user service without starting it: $MARMOT_HARNESS_SERVICE_NAME.service"
        return 0
    fi
    activate_systemd_user_service "$MARMOT_HARNESS_SERVICE_NAME.service" || return 1
    log "installed and started systemd user service: $MARMOT_HARNESS_SERVICE_NAME.service"
}

install_wn_agent_service() {
    case "$(uname -s)" in
        Darwin) install_macos_wn_agent_service ;;
        Linux) install_linux_wn_agent_service ;;
        *) return 1 ;;
    esac
}

install_harness_service() {
    case "$(uname -s)" in
        Darwin) install_macos_harness_service ;;
        Linux) install_linux_harness_service ;;
        *) return 1 ;;
    esac
}

start_temp_agent() {
    if [ "$NO_START_WN_AGENT" -eq 1 ]; then
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] wn-agent --home %q --socket %q' "$MARMOT_HOME" "$MARMOT_AGENT_SOCKET"
        local relay
        for relay in ${RELAYS[@]+"${RELAYS[@]}"}; do
            printf ' --relay %q' "$relay"
        done
        printf '\n'
        return 0
    fi
    if [ -S "$MARMOT_AGENT_SOCKET" ]; then
        log "found existing wn-agent socket: $MARMOT_AGENT_SOCKET"
        return 0
    fi
    run mkdir -p "$MARMOT_HOME"
    local -a args=(--home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET")
    local relay
    for relay in ${RELAYS[@]+"${RELAYS[@]}"}; do
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

    if [ "$INSTALL_SERVICE" -eq 1 ]; then
        install_wn_agent_service || start_temp_agent
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
        --no-quic
    )
    local relay
    for relay in ${RELAYS[@]+"${RELAYS[@]}"}; do
        args+=(--relay "$relay")
    done
    local welcomer
    for welcomer in ${ALLOW_WELCOMERS[@]+"${ALLOW_WELCOMERS[@]}"}; do
        args+=(--allow-welcomer "$welcomer")
    done

    log "running wn-agent bootstrap"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] wn-agent'
        printf ' %q' "${args[@]}"
        printf '\n'
        BOOTSTRAP_ACCOUNT_ID_HEX="<account-id-from-bootstrap>"
        BOOTSTRAP_ALLOWED_SENDERS_HEX="${HARNESS_CONFIGURED_SENDERS_HEX:-<allowlist-from-bootstrap>}"
        BOOTSTRAP_NPUB="<agent-npub-from-bootstrap>"
        BOOTSTRAP_NPROFILE="<agent-nprofile-from-bootstrap>"
        return 0
    fi

    run mkdir -p "$MARMOT_HOME"
    run chmod 700 "$MARMOT_HOME"
    local bootstrap_json
    bootstrap_json="$(wn-agent "${args[@]}")"
    (
        umask 077
        printf '%s\n' "$bootstrap_json" >"$MARMOT_HOME/bootstrap.json"
    )
    BOOTSTRAP_ACCOUNT_ID_HEX="$(
        printf '%s\n' "$bootstrap_json" |
            python3 -c 'import json, sys; print(json.load(sys.stdin)["account_id_hex"])'
    )"
    local bootstrap_welcomers_hex
    bootstrap_welcomers_hex="$(
        printf '%s\n' "$bootstrap_json" |
            python3 -c 'import json, sys; print(",".join(json.load(sys.stdin).get("welcomer_account_ids_hex", [])))'
    )"
    BOOTSTRAP_ALLOWED_SENDERS_HEX="${HARNESS_CONFIGURED_SENDERS_HEX:-$bootstrap_welcomers_hex}"
    BOOTSTRAP_NPUB="$(
        printf '%s\n' "$bootstrap_json" |
            python3 -c 'import json, sys; print(json.load(sys.stdin)["npub"])'
    )"
    BOOTSTRAP_NPROFILE="$(
        printf '%s\n' "$bootstrap_json" |
            python3 -c 'import json, sys; print(json.load(sys.stdin)["nprofile"])'
    )"
    if [ -z "$BOOTSTRAP_ACCOUNT_ID_HEX" ]; then
        echo "error: bootstrap did not return an account id" >&2
        exit 1
    fi
    if [ -z "$BOOTSTRAP_ALLOWED_SENDERS_HEX" ]; then
        echo "error: bootstrap did not return any allowlisted sender hex ids" >&2
        exit 1
    fi
    log "bootstrap details -> $MARMOT_HOME/bootstrap.json"
}

print_phone_invite() {
    cat <<EOF

White Noise agent identity:
  npub: $BOOTSTRAP_NPUB
  nprofile: $BOOTSTRAP_NPROFILE
EOF
    if [ "$DRY_RUN" -eq 0 ] && [ -t 1 ] && command -v qrencode >/dev/null 2>&1; then
        printf '%s' "$BOOTSTRAP_NPROFILE" | qrencode -t ANSIUTF8
    fi
}

write_harness_env() {
    local env_file="$MARMOT_HOME/dev/$HARNESS_BINARY.env"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "would write private env file $env_file"
        log "env: $HARNESS_EXECUTION_PROFILE_ENV=$HARNESS_EXECUTION_PROFILE $HARNESS_TIMEOUT_ENV=$HARNESS_TIMEOUT_SECS $HARNESS_IDLE_TIMEOUT_ENV=$HARNESS_IDLE_TIMEOUT_SECS $HARNESS_REQUEST_TIMEOUT_ENV=$HARNESS_REQUEST_TIMEOUT_SECS $HARNESS_MAX_REPLY_ENV=$HARNESS_MAX_REPLY_BYTES $HARNESS_MAX_PENDING_ENV=$HARNESS_MAX_PENDING_PER_GROUP"
        return 0
    fi
    run mkdir -p "$MARMOT_HOME/dev"
    (
        umask 077
        {
            printf 'MARMOT_HOME=%q\n' "$MARMOT_HOME"
            printf 'MARMOT_AGENT_SOCKET=%q\n' "$MARMOT_AGENT_SOCKET"
            printf '%s=%q\n' "$HARNESS_ACCOUNT_ID_ENV" "$BOOTSTRAP_ACCOUNT_ID_HEX"
            printf '%s=%q\n' "$HARNESS_ALLOWED_SENDERS_ENV" "$BOOTSTRAP_ALLOWED_SENDERS_HEX"
            printf '%s=%q\n' "$HARNESS_BIN_ENV" "$HARNESS_BIN"
            printf '%s=%q\n' "$HARNESS_EXECUTION_PROFILE_ENV" "$HARNESS_EXECUTION_PROFILE"
            printf '%s=%q\n' "$HARNESS_TIMEOUT_ENV" "$HARNESS_TIMEOUT_SECS"
            printf '%s=%q\n' "$HARNESS_IDLE_TIMEOUT_ENV" "$HARNESS_IDLE_TIMEOUT_SECS"
            printf '%s=%q\n' "$HARNESS_REQUEST_TIMEOUT_ENV" "$HARNESS_REQUEST_TIMEOUT_SECS"
            printf '%s=%q\n' "$HARNESS_MAX_REPLY_ENV" "$HARNESS_MAX_REPLY_BYTES"
            printf '%s=%q\n' "$HARNESS_MAX_PENDING_ENV" "$HARNESS_MAX_PENDING_PER_GROUP"
        } >"$env_file"
    )
    log "wrote $HARNESS_BINARY env -> $env_file"
}

print_next_steps() {
    print_phone_invite
    cat <<EOF

Install complete.

Terminal harness agent:
  label: $MARMOT_AGENT_LABEL
  home: $MARMOT_HOME
  socket: $MARMOT_AGENT_SOCKET
  service: $MARMOT_AGENT_SERVICE_NAME.service (Linux) / $MARMOT_AGENT_LAUNCHD_LABEL (macOS)

EOF
    if [ "$DRY_RUN" -eq 1 ]; then
        cat <<EOF
Dry run complete. No services were installed or started.
EOF
    elif [ "$INSTALL_SERVICE" -eq 1 ] && [ "$NO_START_WN_AGENT" -eq 0 ] && [ "$NO_START_HARNESS" -eq 0 ]; then
        cat <<EOF
Services were installed and started for the current user.

Next steps:
  1. Add the agent identity above in White Noise.
  2. Invite it from an authorized account.
  3. Send a test message. Use /<path> first to select a working directory.
EOF
    else
        cat <<EOF
The connector or harness was left stopped by the selected install options.

To run it manually:
  1. Ensure binaries are on your PATH ($(install_dir)).
  2. Start wn-agent:
     wn-agent --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET"
  3. In another shell, load the harness environment and start $HARNESS_BINARY:
     . "$MARMOT_HOME/dev/$HARNESS_BINARY.env"
     $HARNESS_BINARY
  4. Add the agent identity above in White Noise, invite it, and send a test message.
EOF
    fi
    cat <<EOF

Build: ${MARMOT_RELEASE_REPO}@${MARMOT_RELEASE_TAG} (${WN_AGENT_VERSION})
EOF
}

cleanup() {
    if [ -n "$WN_AGENT_TEMP_PID" ] && [ "$DRY_RUN" -eq 0 ]; then
        kill "$WN_AGENT_TEMP_PID" >/dev/null 2>&1 || true
    fi
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
            if [ "$MARMOT_AGENT_SOCKET_SET" -eq 0 ]; then
                MARMOT_AGENT_SOCKET="$MARMOT_HOME/dev/wn-agent.sock"
            fi
            shift 2
            ;;
        --socket)
            MARMOT_AGENT_SOCKET="${2:?missing value for --socket}"
            MARMOT_AGENT_SOCKET_SET=1
            shift 2
            ;;
        --allow-welcomer | --allow-sender)
            ALLOW_WELCOMERS+=("${2:?missing value for $1}")
            shift 2
            ;;
        --relay)
            RELAYS+=("${2:?missing value for --relay}")
            shift 2
            ;;
        --"$HARNESS_KIND"-bin)
            HARNESS_BIN="${2:?missing value for --$HARNESS_KIND-bin}"
            shift 2
            ;;
        --execution-profile)
            HARNESS_EXECUTION_PROFILE="${2:?missing value for --execution-profile}"
            shift 2
            ;;
        --acknowledge-unrestricted)
            ACKNOWLEDGE_UNRESTRICTED=1
            shift
            ;;
        --no-service)
            INSTALL_SERVICE=0
            shift
            ;;
        --no-start-wn-agent)
            NO_START_WN_AGENT=1
            shift
            ;;
        --no-start-"$HARNESS_BINARY")
            NO_START_HARNESS=1
            shift
            ;;
        --system)
            SYSTEM_INSTALL=1
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

if [ "$MARMOT_RELEASE_TAG" = "wn-agent-vlatest" ]; then
    echo "error: could not resolve a release version; set MARMOT_RELEASE_TAG or WN_AGENT_VERSION" >&2
    exit 1
fi

if [ "${#RELAYS[@]}" -eq 0 ]; then
    while IFS= read -r relay; do
        RELAYS+=("$relay")
    done < <(append_csv "$MARMOT_RELAYS")
fi
if [ -n "${MARMOT_WELCOMER_ALLOWLIST:-}" ]; then
    while IFS= read -r welcomer; do
        ALLOW_WELCOMERS+=("$welcomer")
    done < <(append_csv "$MARMOT_WELCOMER_ALLOWLIST")
fi
if [ "$ASSUME_YES" -eq 0 ] && have_tty && [ "${#ALLOW_WELCOMERS[@]}" -eq 0 ]; then
    INTERACTIVE=1
    prompt_attempts=0
    while [ "${#ALLOW_WELCOMERS[@]}" -eq 0 ] && [ "$prompt_attempts" -lt 5 ]; do
        prompt_attempts=$((prompt_attempts + 1))
        welcomer_reply="$(prompt_value "Allowed inviter npub or hex" "")"
        [ -n "$welcomer_reply" ] && ALLOW_WELCOMERS+=("$welcomer_reply")
    done
    if [ "${#ALLOW_WELCOMERS[@]}" -eq 0 ]; then
        echo "error: no allowlist value received after $prompt_attempts attempts" >&2
        exit 1
    fi
fi

validate_welcomer_inputs
validate_prompt_senders
validate_execution_profile
need_cmd curl
need_cmd tar
if [ "$DRY_RUN" -eq 0 ]; then
    need_cmd python3
fi
resolve_harness_bin

platform="$(detect_platform)"
tmpdir="$(mktemp -d)"
trap 'cleanup; rm -rf "$tmpdir"' EXIT

log "platform=$platform repo=$MARMOT_RELEASE_REPO tag=$MARMOT_RELEASE_TAG version=$WN_AGENT_VERSION"
install_binary_bundle "wn-agent" "$platform" "$tmpdir"
install_binary_bundle "$HARNESS_BINARY" "$platform" "$tmpdir"
bootstrap_agent
write_harness_env

if [ "$INSTALL_SERVICE" -eq 1 ]; then
    install_harness_service || warn "$HARNESS_BINARY service was not installed; run it manually with $MARMOT_HOME/dev/$HARNESS_BINARY.env"
fi

print_next_steps
