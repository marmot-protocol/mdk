#!/usr/bin/env bash
set -euo pipefail

# Install wn-agent and the OpenClaw Marmot channel plugin from a WN Agent GitHub
# release. OpenClaw itself must already be installed. Mirrors
# scripts/install-hermes-marmot.sh.
#
# NOTE: requires a published wn-agent-v* release. Releases from before the rename
# ship differently-named assets and cannot be installed by this script;
# cut the first wn-agent-v* release before pointing installs here.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace_version_default="$(sed -n 's/^version = "\(.*\)"/\1/p' "$SCRIPT_DIR/../Cargo.toml" 2>/dev/null | head -n 1)"
workspace_version_default="${workspace_version_default:-latest}"

MARMOT_RELEASE_REPO="${MARMOT_RELEASE_REPO:-marmot-protocol/mdk}"
WN_AGENT_VERSION_DEFAULT="${WN_AGENT_VERSION_DEFAULT:-$workspace_version_default}"
WN_AGENT_VERSION="${WN_AGENT_VERSION:-${WN_AGENT_SHA:-$WN_AGENT_VERSION_DEFAULT}}"
MARMOT_RELEASE_TAG_DEFAULT="${MARMOT_RELEASE_TAG_DEFAULT:-wn-agent-v${WN_AGENT_VERSION}}"
MARMOT_RELEASE_TAG="${MARMOT_RELEASE_TAG:-$MARMOT_RELEASE_TAG_DEFAULT}"
MARMOT_INSTALL_PREFIX="${MARMOT_INSTALL_PREFIX:-${HOME}/.local}"
MARMOT_HOME="${MARMOT_HOME:-${HOME}/.marmot-agent}"
MARMOT_RELAYS="${MARMOT_RELAYS:-wss://relay.eu.whitenoise.chat,wss://relay.us.whitenoise.chat}"
PLUGIN_PACKAGE="${PLUGIN_PACKAGE:-openclaw-marmot-plugin-${WN_AGENT_VERSION}.tgz}"
INSTALL_BOOTSTRAP=0
START_WN_AGENT=1
DRY_RUN=0
FORCE=0
SYSTEM_INSTALL=0

usage() {
    cat <<'USAGE'
Usage: install-openclaw-marmot.sh [options]

Install wn-agent and the OpenClaw Marmot channel plugin from a WN Agent GitHub
release. OpenClaw must already be installed and `openclaw` on PATH.

Options:
  --bootstrap           After install, start wn-agent and run `wn-agent bootstrap --qr`
  --no-start-wn-agent   With --bootstrap, do not start wn-agent automatically
  --system              Install wn-agent to /usr/local/bin instead of ~/.local/bin
  --force               Reinstall the OpenClaw Marmot plugin even if already present
  --dry-run             Print actions without installing
  -h, --help            Show this help

Environment:
  MARMOT_RELEASE_REPO   GitHub repo (default: marmot-protocol/mdk)
  MARMOT_RELEASE_TAG    Release tag (default: wn-agent-v<version>)
  WN_AGENT_VERSION      Asset version suffix
  WN_AGENT_SHA          Legacy alias for WN_AGENT_VERSION
  MARMOT_INSTALL_PREFIX Install root for wn-agent (default: ~/.local)
  MARMOT_HOME           wn-agent home used by bootstrap (default: ~/.marmot-agent)
  MARMOT_RELAYS         Relay CSV used when --bootstrap starts wn-agent
USAGE
}

log() { printf 'install-openclaw-marmot: %s\n' "$*"; }
run() {
    if [ "$DRY_RUN" -eq 1 ]; then printf '[dry-run] '; printf '%q ' "$@"; printf '\n'; return 0; fi
    "$@"
}
need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }

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

install_wn_agent() {
    local platform="$1"
    local tmpdir="$2"
    local suffix="$WN_AGENT_VERSION"
    local archive="$tmpdir/wn-agent-$platform-$suffix.tar.gz"
    local checksum="$tmpdir/wn-agent-$platform-$suffix.tar.gz.sha256"
    local extract_dir="$tmpdir/wn-agent-extract"
    local install_dir

    if [ "$SYSTEM_INSTALL" -eq 1 ]; then
        install_dir="/usr/local/bin"
    else
        install_dir="$MARMOT_INSTALL_PREFIX/bin"
    fi

    download_asset "wn-agent-$platform-$suffix.tar.gz" "$archive"
    download_asset "wn-agent-$platform-$suffix.tar.gz.sha256" "$checksum"
    verify_sha256 "$archive" "$checksum"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "would install wn-agent to $install_dir/wn-agent"
        return 0
    fi

    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"
    tar -xzf "$archive" -C "$extract_dir"
    run mkdir -p "$install_dir"
    run install -m 0755 "$extract_dir/wn-agent-$platform/wn-agent" "$install_dir/wn-agent"
    log "installed wn-agent -> $install_dir/wn-agent"
}

install_plugin() {
    local tmpdir="$1"
    local archive="$tmpdir/$PLUGIN_PACKAGE"
    local checksum="$tmpdir/$PLUGIN_PACKAGE.sha256"

    download_asset "$PLUGIN_PACKAGE" "$archive"
    download_asset "$PLUGIN_PACKAGE.sha256" "$checksum"
    verify_sha256 "$archive" "$checksum"

    log "installing the plugin into OpenClaw"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "would run: openclaw plugins install $archive"
        return 0
    fi
    if [ "$FORCE" -eq 1 ]; then
        run openclaw plugins install --force "$archive" 2>/dev/null \
            || run openclaw plugins install "$archive"
    else
        run openclaw plugins install "$archive"
    fi
}

enable_openclaw_plugin() {
    if [ "$DRY_RUN" -eq 1 ]; then
        log "would run: openclaw plugins enable marmot"
        return 0
    fi
    if run openclaw plugins enable marmot; then
        log "enabled OpenClaw plugin: marmot"
    else
        log "could not auto-enable; run 'openclaw plugins enable marmot'"
    fi
}

ensure_path() {
    local bindir
    if [ "$SYSTEM_INSTALL" -eq 1 ]; then
        bindir="/usr/local/bin"
    else
        bindir="$MARMOT_INSTALL_PREFIX/bin"
    fi
    case ":$PATH:" in
        *":$bindir:"*) ;;
        *)
            log "add $bindir to PATH before running wn-agent"
            export PATH="$bindir:$PATH"
            ;;
    esac
}

run_bootstrap() {
    ensure_path
    if [ "$DRY_RUN" -eq 0 ] && ! command -v wn-agent >/dev/null 2>&1; then
        echo "error: wn-agent not found on PATH after install" >&2
        exit 1
    fi

    local wn_agent_pid=""
    if [ "$START_WN_AGENT" -eq 1 ]; then
        local -a wn_agent_args=(--home "$MARMOT_HOME")
        local relay
        IFS=',' read -r -a relays <<<"$MARMOT_RELAYS"
        for relay in "${relays[@]}"; do
            relay="${relay#"${relay%%[![:space:]]*}"}"
            relay="${relay%"${relay##*[![:space:]]}"}"
            [ -z "$relay" ] || wn_agent_args+=(--relay "$relay")
        done
        log "starting wn-agent"
        if [ "$DRY_RUN" -eq 1 ]; then
            printf '[dry-run] wn-agent'
            printf ' %q' "${wn_agent_args[@]}"
            printf '\n'
        else
            run mkdir -p "$MARMOT_HOME"
            wn-agent "${wn_agent_args[@]}" &
            wn_agent_pid="$!"
            sleep 2
        fi
    fi

    log "running wn-agent bootstrap"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] wn-agent bootstrap --home %q --qr\n' "$MARMOT_HOME"
    else
        run wn-agent bootstrap --home "$MARMOT_HOME" --qr
    fi

    if [ -n "$wn_agent_pid" ] && [ "$DRY_RUN" -eq 0 ]; then
        log "wn-agent running in background (pid $wn_agent_pid)"
    fi
}

print_next_steps() {
    cat <<EOF

Install complete.

Next steps:
  1. Ensure wn-agent is on your PATH ($(
    if [ "$SYSTEM_INSTALL" -eq 1 ]; then echo "/usr/local/bin"; else echo "$MARMOT_INSTALL_PREFIX/bin"; fi
  ))
  2. Start the connector:
     export MARMOT_HOME="$MARMOT_HOME"
     wn-agent --home "\$MARMOT_HOME" --relay wss://relay.eu.whitenoise.chat --relay wss://relay.us.whitenoise.chat
  3. Bootstrap or reuse the agent account:
     wn-agent bootstrap --home "\$MARMOT_HOME" --qr
  4. Start OpenClaw:
     openclaw gateway run

Build: ${MARMOT_RELEASE_REPO}@${MARMOT_RELEASE_TAG} (${WN_AGENT_VERSION})
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --bootstrap) INSTALL_BOOTSTRAP=1; shift;;
        --no-start-wn-agent) START_WN_AGENT=0; shift;;
        --system) SYSTEM_INSTALL=1; shift;;
        --force) FORCE=1; shift;;
        --dry-run) DRY_RUN=1; shift;;
        -h|--help) usage; exit 0;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2;;
    esac
done

need_cmd curl
need_cmd tar
if [ "$DRY_RUN" -ne 1 ]; then
    need_cmd openclaw
fi

platform="$(detect_platform)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

log "platform=$platform repo=$MARMOT_RELEASE_REPO tag=$MARMOT_RELEASE_TAG version=$WN_AGENT_VERSION"
install_wn_agent "$platform" "$tmpdir"
install_plugin "$tmpdir"
enable_openclaw_plugin

if [ "$INSTALL_BOOTSTRAP" -eq 1 ]; then
    run_bootstrap
else
    print_next_steps
fi
