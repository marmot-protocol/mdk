#!/usr/bin/env bash
set -euo pipefail

# Install wn-agent and the wn-opencode harness from a WN Agent GitHub release.
# OpenCode itself must already be installed.

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
MARMOT_HOME="${MARMOT_HOME:-${HOME}/.marmot-agents/harnesses}"
MARMOT_AGENT_SOCKET_OVERRIDE="${MARMOT_AGENT_SOCKET:-}"
MARMOT_AGENT_SOCKET="${MARMOT_AGENT_SOCKET_OVERRIDE:-$MARMOT_HOME/dev/wn-agent.sock}"
MARMOT_AGENT_LABEL="${MARMOT_AGENT_LABEL:-terminal-harness-agent}"
MARMOT_AGENT_SERVICE_NAME="${MARMOT_AGENT_SERVICE_NAME:-wn-agent-harnesses}"
MARMOT_AGENT_LAUNCHD_LABEL="${MARMOT_AGENT_LAUNCHD_LABEL:-org.marmot.wn-agent.harnesses}"
MARMOT_RELAYS="${MARMOT_RELAYS:-wss://relay.eu.whitenoise.chat,wss://relay.us.whitenoise.chat}"
WN_OPENCODE_BIN="${WN_OPENCODE_BIN:-opencode}"
WN_OPENCODE_TIMEOUT_SECS="${WN_OPENCODE_TIMEOUT_SECS:-3600}"
WN_OPENCODE_IDLE_TIMEOUT_SECS="${WN_OPENCODE_IDLE_TIMEOUT_SECS:-120}"
WN_OPENCODE_REQUEST_TIMEOUT_SECS="${WN_OPENCODE_REQUEST_TIMEOUT_SECS:-30}"
WN_OPENCODE_MAX_REPLY_BYTES="${WN_OPENCODE_MAX_REPLY_BYTES:-30000}"
WN_OPENCODE_MAX_PENDING_PER_GROUP="${WN_OPENCODE_MAX_PENDING_PER_GROUP:-4}"

ASSUME_YES=0
DRY_RUN=0
INSTALL_SERVICE=1
INTERACTIVE=0
NO_START_WN_AGENT=0
NO_START_WN_OPENCODE=0
SYSTEM_INSTALL=0
WN_AGENT_TEMP_PID=""
BOOTSTRAP_ACCOUNT_ID_HEX=""
BOOTSTRAP_ALLOWED_SENDERS_HEX=""
MARMOT_AGENT_SOCKET_SET=0
if [ -n "$MARMOT_AGENT_SOCKET_OVERRIDE" ]; then
    MARMOT_AGENT_SOCKET_SET=1
fi

RELAYS=()
ALLOW_WELCOMERS=()

usage() {
    cat <<'USAGE'
Usage: install-opencode-marmot.sh [options]

Install wn-agent and wn-opencode from a WN Agent GitHub release. OpenCode
itself must already be installed.

Options:
  --bootstrap              Compatibility alias; guided bootstrap is the default
  --yes, --non-interactive Use defaults and do not prompt
  --home PATH              Marmot terminal harness agent home (default: ~/.marmot-agents/harnesses)
  --socket PATH            wn-agent socket (default: $MARMOT_HOME/dev/wn-agent.sock)
  --allow-welcomer VALUE   Allow invites/prompts from this npub or hex pubkey; may repeat
  --allow-sender VALUE     Alias for --allow-welcomer
  --relay URL              Relay URL for wn-agent/bootstrap; may repeat
  --opencode-bin PATH      OpenCode binary or command name (default: opencode)
  --no-service             Do not install/start LaunchAgents or systemd user units
  --no-start-wn-agent      Do not start wn-agent before bootstrap
  --no-start-wn-opencode   Install but do not start wn-opencode
  --system                 Install binaries to /usr/local/bin instead of ~/.local/bin
  --dry-run                Print actions without installing
  -h, --help               Show this help

Environment:
  MARMOT_RELEASE_REPO      GitHub repo (default: marmot-protocol/mdk)
  MARMOT_RELEASE_TAG       Release tag (release assets default to their own tag)
  WN_AGENT_VERSION         Asset version suffix (release assets default to their own version)
  WN_AGENT_SHA             Legacy alias for WN_AGENT_VERSION
  MARMOT_INSTALL_PREFIX    Install root for binaries (default: ~/.local)
  MARMOT_HOME              wn-agent home (default: ~/.marmot-agents/harnesses)
  MARMOT_AGENT_SOCKET      wn-agent socket (default: $MARMOT_HOME/dev/wn-agent.sock)
  MARMOT_AGENT_LABEL       Account label used by bootstrap (default: terminal-harness-agent)
  MARMOT_AGENT_SERVICE_NAME Linux systemd user service name (default: wn-agent-harnesses)
  MARMOT_AGENT_LAUNCHD_LABEL macOS LaunchAgent label (default: org.marmot.wn-agent.harnesses)
  MARMOT_RELAYS            Relay CSV used by wn-agent and bootstrap
  MARMOT_WELCOMER_ALLOWLIST Comma-separated npub or hex allowlist values
  WN_OPENCODE_ALLOWED_SENDERS_HEX Comma-separated hex values for prompt senders
  WN_OPENCODE_BIN          OpenCode binary or command name

Example:
  curl -fsSL https://github.com/marmot-protocol/mdk/releases/download/wn-agent-latest/install-opencode-marmot.sh | bash

  curl -fsSL .../install-opencode-marmot.sh | bash -s -- --yes --allow-welcomer npub1...
USAGE
}

log() {
    printf 'install-opencode-marmot: %s\n' "$*"
}

warn() {
    printf 'install-opencode-marmot: warning: %s\n' "$*" >&2
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
        echo "error: at least one --allow-welcomer/--allow-sender value is required" >&2
        exit 1
    fi
    for welcomer in "${ALLOW_WELCOMERS[@]}"; do
        if ! is_welcomer_ref_syntax "$welcomer"; then
            echo "error: invalid allowlist value: $welcomer" >&2
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

wn_opencode_path() {
    printf '%s/wn-opencode\n' "$(install_dir)"
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

    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"
    tar -xzf "$archive" -C "$extract_dir"
    run mkdir -p "$target_dir"
    run install -m 0755 "$extract_dir/$binary-$platform/$binary" "$target_dir/$binary"
    log "installed $binary -> $target_dir/$binary"
}

resolve_opencode_bin() {
    if [ "$DRY_RUN" -eq 1 ]; then
        log "would require OpenCode binary: $WN_OPENCODE_BIN"
        return 0
    fi
    if [[ "$WN_OPENCODE_BIN" == */* ]]; then
        if [ ! -x "$WN_OPENCODE_BIN" ]; then
            echo "error: WN_OPENCODE_BIN is not executable: $WN_OPENCODE_BIN" >&2
            exit 1
        fi
        return 0
    fi
    if command -v "$WN_OPENCODE_BIN" >/dev/null 2>&1; then
        WN_OPENCODE_BIN="$(command -v "$WN_OPENCODE_BIN")"
        return 0
    fi
    local opencode_home_bin="$HOME/.opencode/bin/$WN_OPENCODE_BIN"
    if [ ! -x "$opencode_home_bin" ]; then
        echo "error: OpenCode binary not found: $WN_OPENCODE_BIN" >&2
        echo "install OpenCode first or set WN_OPENCODE_BIN/--opencode-bin" >&2
        exit 1
    fi
    WN_OPENCODE_BIN="$opencode_home_bin"
    log "found OpenCode binary: $WN_OPENCODE_BIN"
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
        log "would run: launchctl bootstrap gui/$UID $plist"
        return 0
    fi

    run mkdir -p "$plist_dir" "$logs_dir" || return 1
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
    chmod 600 "$plist" || return 1

    launchctl bootout "gui/$UID" "$plist" >/dev/null 2>&1 || true
    run launchctl bootstrap "gui/$UID" "$plist" || return 1
    launchctl kickstart -k "gui/$UID/$label" >/dev/null 2>&1 || true
    log "installed and started LaunchAgent: $label"
}

install_macos_opencode_service() {
    local plist_dir plist label program logs_dir
    label="org.marmot.wn-opencode"
    plist_dir="$HOME/Library/LaunchAgents"
    plist="$plist_dir/$label.plist"
    program="$(wn_opencode_path)"
    logs_dir="$MARMOT_HOME/logs"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "would install LaunchAgent $plist"
        log "would run: launchctl bootstrap gui/$UID $plist"
        log "env: WN_OPENCODE_TIMEOUT_SECS=$WN_OPENCODE_TIMEOUT_SECS WN_OPENCODE_IDLE_TIMEOUT_SECS=$WN_OPENCODE_IDLE_TIMEOUT_SECS"
        return 0
    fi

    run mkdir -p "$plist_dir" "$logs_dir" || return 1
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
        plist_env_entry "WN_OPENCODE_ACCOUNT_ID_HEX" "$BOOTSTRAP_ACCOUNT_ID_HEX"
        plist_env_entry "WN_OPENCODE_ALLOWED_SENDERS_HEX" "$BOOTSTRAP_ALLOWED_SENDERS_HEX"
        plist_env_entry "WN_OPENCODE_BIN" "$WN_OPENCODE_BIN"
        plist_env_entry "WN_OPENCODE_TIMEOUT_SECS" "$WN_OPENCODE_TIMEOUT_SECS"
        plist_env_entry "WN_OPENCODE_IDLE_TIMEOUT_SECS" "$WN_OPENCODE_IDLE_TIMEOUT_SECS"
        plist_env_entry "WN_OPENCODE_REQUEST_TIMEOUT_SECS" "$WN_OPENCODE_REQUEST_TIMEOUT_SECS"
        plist_env_entry "WN_OPENCODE_MAX_REPLY_BYTES" "$WN_OPENCODE_MAX_REPLY_BYTES"
        plist_env_entry "WN_OPENCODE_MAX_PENDING_PER_GROUP" "$WN_OPENCODE_MAX_PENDING_PER_GROUP"
        printf '%s\n' '  </dict>'
        printf '%s\n' '  <key>RunAtLoad</key>'
        printf '%s\n' '  <true/>'
        printf '%s\n' '  <key>KeepAlive</key>'
        printf '%s\n' '  <true/>'
        printf '%s\n' '  <key>StandardOutPath</key>'
        plist_string "$logs_dir/wn-opencode.out.log"
        printf '%s\n' '  <key>StandardErrorPath</key>'
        plist_string "$logs_dir/wn-opencode.err.log"
        printf '%s\n' '</dict>'
        printf '%s\n' '</plist>'
    } >"$plist" || return 1
    chmod 600 "$plist" || return 1

    launchctl bootout "gui/$UID" "$plist" >/dev/null 2>&1 || true
    run launchctl bootstrap "gui/$UID" "$plist" || return 1
    launchctl kickstart -k "gui/$UID/$label" >/dev/null 2>&1 || true
    log "installed and started LaunchAgent: $label"
}

systemd_quote() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '"%s"' "$value"
}

install_linux_wn_agent_service() {
    local service_dir service program relay
    service_dir="$HOME/.config/systemd/user"
    service="$service_dir/$MARMOT_AGENT_SERVICE_NAME.service"
    program="$(wn_agent_path)"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "would install systemd user unit $service"
        log "would run: systemctl --user enable --now $MARMOT_AGENT_SERVICE_NAME.service"
        return 0
    fi

    if ! command -v systemctl >/dev/null 2>&1; then
        return 1
    fi

    run mkdir -p "$service_dir" "$MARMOT_HOME/logs" || return 1
    {
        printf '%s\n' '[Unit]'
        printf '%s\n' 'Description=Marmot wn-agent connector'
        printf '%s\n' 'After=network-online.target'
        printf '\n'
        printf '%s\n' '[Service]'
        printf 'ExecStart=%q --home %q --socket %q' "$program" "$MARMOT_HOME" "$MARMOT_AGENT_SOCKET"
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
    chmod 600 "$service" || return 1

    run systemctl --user daemon-reload || return 1
    run systemctl --user enable --now "$MARMOT_AGENT_SERVICE_NAME.service" || return 1
    log "installed and started systemd user service: $MARMOT_AGENT_SERVICE_NAME.service"
}

install_linux_opencode_service() {
    local service_dir service program
    service_dir="$HOME/.config/systemd/user"
    service="$service_dir/wn-opencode.service"
    program="$(wn_opencode_path)"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "would install systemd user unit $service"
        log "would run: systemctl --user enable --now wn-opencode.service"
        log "env: WN_OPENCODE_TIMEOUT_SECS=$WN_OPENCODE_TIMEOUT_SECS WN_OPENCODE_IDLE_TIMEOUT_SECS=$WN_OPENCODE_IDLE_TIMEOUT_SECS"
        return 0
    fi

    if ! command -v systemctl >/dev/null 2>&1; then
        return 1
    fi

    run mkdir -p "$service_dir" "$MARMOT_HOME/logs" || return 1
    {
        printf '%s\n' '[Unit]'
        printf '%s\n' 'Description=Marmot wn-opencode harness'
        printf '%s\n' "After=$MARMOT_AGENT_SERVICE_NAME.service"
        printf '%s\n' "Requires=$MARMOT_AGENT_SERVICE_NAME.service"
        printf '\n'
        printf '%s\n' '[Service]'
        printf 'Environment=%s\n' "$(systemd_quote "MARMOT_HOME=$MARMOT_HOME")"
        printf 'Environment=%s\n' "$(systemd_quote "MARMOT_AGENT_SOCKET=$MARMOT_AGENT_SOCKET")"
        printf 'Environment=%s\n' "$(systemd_quote "WN_OPENCODE_ACCOUNT_ID_HEX=$BOOTSTRAP_ACCOUNT_ID_HEX")"
        printf 'Environment=%s\n' "$(systemd_quote "WN_OPENCODE_ALLOWED_SENDERS_HEX=$BOOTSTRAP_ALLOWED_SENDERS_HEX")"
        printf 'Environment=%s\n' "$(systemd_quote "WN_OPENCODE_BIN=$WN_OPENCODE_BIN")"
        printf 'Environment=%s\n' "$(systemd_quote "WN_OPENCODE_TIMEOUT_SECS=$WN_OPENCODE_TIMEOUT_SECS")"
        printf 'Environment=%s\n' "$(systemd_quote "WN_OPENCODE_IDLE_TIMEOUT_SECS=$WN_OPENCODE_IDLE_TIMEOUT_SECS")"
        printf 'Environment=%s\n' "$(systemd_quote "WN_OPENCODE_REQUEST_TIMEOUT_SECS=$WN_OPENCODE_REQUEST_TIMEOUT_SECS")"
        printf 'Environment=%s\n' "$(systemd_quote "WN_OPENCODE_MAX_REPLY_BYTES=$WN_OPENCODE_MAX_REPLY_BYTES")"
        printf 'Environment=%s\n' "$(systemd_quote "WN_OPENCODE_MAX_PENDING_PER_GROUP=$WN_OPENCODE_MAX_PENDING_PER_GROUP")"
        printf 'ExecStart=%q\n' "$program"
        printf '%s\n' 'Restart=always'
        printf '%s\n' 'RestartSec=2'
        printf '\n'
        printf '%s\n' '[Install]'
        printf '%s\n' 'WantedBy=default.target'
    } >"$service" || return 1
    chmod 600 "$service" || return 1

    run systemctl --user daemon-reload || return 1
    run systemctl --user enable --now wn-opencode.service || return 1
    log "installed and started systemd user service: wn-opencode.service"
}

install_wn_agent_service() {
    case "$(uname -s)" in
        Darwin) install_macos_wn_agent_service ;;
        Linux) install_linux_wn_agent_service ;;
        *) return 1 ;;
    esac
}

install_opencode_service() {
    if [ "$NO_START_WN_OPENCODE" -eq 1 ]; then
        log "not starting wn-opencode because --no-start-wn-opencode was passed"
        return 0
    fi
    case "$(uname -s)" in
        Darwin) install_macos_opencode_service ;;
        Linux) install_linux_opencode_service ;;
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
    run mkdir -p "$MARMOT_HOME"
    local -a args=(--home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET")
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
        need_cmd python3
    fi

    if [ "$INSTALL_SERVICE" -eq 1 ] && [ "$NO_START_WN_AGENT" -ne 1 ]; then
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
    for relay in "${RELAYS[@]}"; do
        args+=(--relay "$relay")
    done
    local welcomer
    for welcomer in "${ALLOW_WELCOMERS[@]}"; do
        args+=(--allow-welcomer "$welcomer")
    done

    log "running wn-agent bootstrap"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] wn-agent'
        printf ' %q' "${args[@]}"
        printf '\n'
        BOOTSTRAP_ACCOUNT_ID_HEX="<account-id-from-bootstrap>"
        BOOTSTRAP_ALLOWED_SENDERS_HEX="<allowlist-from-bootstrap>"
        return 0
    fi

    run mkdir -p "$MARMOT_HOME"
    local bootstrap_json
    bootstrap_json="$(wn-agent "${args[@]}")"
    printf '%s\n' "$bootstrap_json" >"$MARMOT_HOME/bootstrap.json"
    BOOTSTRAP_ACCOUNT_ID_HEX="$(
        printf '%s\n' "$bootstrap_json" |
            python3 -c 'import json, sys; print(json.load(sys.stdin)["account_id_hex"])'
    )"
    BOOTSTRAP_ALLOWED_SENDERS_HEX="$(
        printf '%s\n' "$bootstrap_json" |
            python3 -c 'import json, sys; print(",".join(json.load(sys.stdin).get("welcomer_account_ids_hex", [])))'
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

write_opencode_env() {
    local env_file="$MARMOT_HOME/dev/wn-opencode.env"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "would write private env file $env_file"
        log "env: WN_OPENCODE_TIMEOUT_SECS=$WN_OPENCODE_TIMEOUT_SECS WN_OPENCODE_IDLE_TIMEOUT_SECS=$WN_OPENCODE_IDLE_TIMEOUT_SECS"
        return 0
    fi
    run mkdir -p "$MARMOT_HOME/dev"
    (
        umask 077
        {
            printf 'MARMOT_HOME=%q\n' "$MARMOT_HOME"
            printf 'MARMOT_AGENT_SOCKET=%q\n' "$MARMOT_AGENT_SOCKET"
            printf 'WN_OPENCODE_ACCOUNT_ID_HEX=%q\n' "$BOOTSTRAP_ACCOUNT_ID_HEX"
            printf 'WN_OPENCODE_ALLOWED_SENDERS_HEX=%q\n' "$BOOTSTRAP_ALLOWED_SENDERS_HEX"
            printf 'WN_OPENCODE_BIN=%q\n' "$WN_OPENCODE_BIN"
            printf 'WN_OPENCODE_TIMEOUT_SECS=%q\n' "$WN_OPENCODE_TIMEOUT_SECS"
            printf 'WN_OPENCODE_IDLE_TIMEOUT_SECS=%q\n' "$WN_OPENCODE_IDLE_TIMEOUT_SECS"
            printf 'WN_OPENCODE_REQUEST_TIMEOUT_SECS=%q\n' "$WN_OPENCODE_REQUEST_TIMEOUT_SECS"
            printf 'WN_OPENCODE_MAX_REPLY_BYTES=%q\n' "$WN_OPENCODE_MAX_REPLY_BYTES"
            printf 'WN_OPENCODE_MAX_PENDING_PER_GROUP=%q\n' "$WN_OPENCODE_MAX_PENDING_PER_GROUP"
        } >"$env_file"
    )
    log "wrote wn-opencode env -> $env_file"
}

print_next_steps() {
    cat <<EOF

Install complete.

Terminal harness agent:
  label: $MARMOT_AGENT_LABEL
  home: $MARMOT_HOME
  socket: $MARMOT_AGENT_SOCKET
  service: $MARMOT_AGENT_SERVICE_NAME.service (Linux) / $MARMOT_AGENT_LAUNCHD_LABEL (macOS)

Next steps:
  1. Ensure binaries are on your PATH ($(install_dir))
  2. Start wn-agent:
     wn-agent --home "$MARMOT_HOME" --socket "$MARMOT_AGENT_SOCKET"
  3. Load the harness env:
     . "$MARMOT_HOME/dev/wn-opencode.env"
  4. Start wn-opencode:
     wn-opencode

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
        --opencode-bin)
            WN_OPENCODE_BIN="${2:?missing value for --opencode-bin}"
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
        --no-start-wn-opencode)
            NO_START_WN_OPENCODE=1
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
if [ -n "${WN_OPENCODE_ALLOWED_SENDERS_HEX:-}" ]; then
    while IFS= read -r welcomer; do
        ALLOW_WELCOMERS+=("$welcomer")
    done < <(append_csv "$WN_OPENCODE_ALLOWED_SENDERS_HEX")
fi

if [ "$ASSUME_YES" -eq 0 ] && have_tty && [ "${#ALLOW_WELCOMERS[@]}" -eq 0 ]; then
    INTERACTIVE=1
    while [ "${#ALLOW_WELCOMERS[@]}" -eq 0 ]; do
        welcomer_reply="$(prompt_value "Allowed inviter/prompt sender npub or hex" "")"
        [ -n "$welcomer_reply" ] && ALLOW_WELCOMERS+=("$welcomer_reply")
    done
fi

validate_welcomer_inputs
need_cmd curl
need_cmd tar
resolve_opencode_bin

platform="$(detect_platform)"
tmpdir="$(mktemp -d)"
trap 'cleanup; rm -rf "$tmpdir"' EXIT

log "platform=$platform repo=$MARMOT_RELEASE_REPO tag=$MARMOT_RELEASE_TAG version=$WN_AGENT_VERSION"
install_binary_bundle "wn-agent" "$platform" "$tmpdir"
install_binary_bundle "wn-opencode" "$platform" "$tmpdir"
bootstrap_agent
write_opencode_env

if [ "$INSTALL_SERVICE" -eq 1 ]; then
    install_opencode_service || warn "wn-opencode service was not installed; run it manually with $MARMOT_HOME/dev/wn-opencode.env"
fi

print_next_steps
