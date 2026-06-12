#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace_version_default="$(sed -n 's/^version = "\(.*\)"/\1/p' "$SCRIPT_DIR/../Cargo.toml" 2>/dev/null | head -n 1)"
workspace_version_default="${workspace_version_default:-latest}"

MARMOT_RELEASE_REPO="${MARMOT_RELEASE_REPO:-marmot-protocol/darkmatter}"
DM_AGENT_VERSION_DEFAULT="${DM_AGENT_VERSION_DEFAULT:-$workspace_version_default}"
DM_AGENT_VERSION="${DM_AGENT_VERSION:-${DM_AGENT_SHA:-$DM_AGENT_VERSION_DEFAULT}}"
MARMOT_RELEASE_TAG_DEFAULT="${MARMOT_RELEASE_TAG_DEFAULT:-dm-agent-v${DM_AGENT_VERSION}}"
MARMOT_RELEASE_TAG="${MARMOT_RELEASE_TAG:-$MARMOT_RELEASE_TAG_DEFAULT}"
MARMOT_INSTALL_PREFIX="${MARMOT_INSTALL_PREFIX:-${HOME}/.local}"
MARMOT_PLUGIN_DIR="${MARMOT_PLUGIN_DIR:-${HOME}/.hermes/plugins/marmot}"
MARMOT_HOME="${MARMOT_HOME:-${HOME}/.marmot-agent}"
MARMOT_RELAYS="${MARMOT_RELAYS:-wss://relay.eu.whitenoise.chat,wss://relay.us.whitenoise.chat}"
INSTALL_BOOTSTRAP=0
START_DM_AGENT=0
DRY_RUN=0
FORCE=0
SYSTEM_INSTALL=0

usage() {
    cat <<'USAGE'
Usage: install-hermes-marmot.sh [options]

Install dm-agent and the Hermes Marmot plugin from a DM Agent GitHub release.
Hermes itself must already be installed.

Options:
  --bootstrap           After install, start dm-agent and run dm-agent bootstrap --qr
  --no-start-dm-agent   With --bootstrap, do not start dm-agent automatically
  --system              Install dm-agent to /usr/local/bin instead of ~/.local/bin
  --force               Replace an existing Hermes plugin directory
  --dry-run             Print actions without installing
  -h, --help            Show this help

Environment:
  MARMOT_RELEASE_REPO   GitHub repo (default: marmot-protocol/darkmatter)
  MARMOT_RELEASE_TAG    Release tag (release assets default to their own tag)
  DM_AGENT_VERSION      Asset version suffix (release assets default to their own version)
  DM_AGENT_SHA          Legacy alias for DM_AGENT_VERSION
  MARMOT_INSTALL_PREFIX Install root for dm-agent (default: ~/.local)
  MARMOT_PLUGIN_DIR     Hermes plugin path (default: ~/.hermes/plugins/marmot)
  MARMOT_HOME           dm-agent home used by bootstrap (default: ~/.marmot-agent)
  MARMOT_RELAYS         Relay CSV used when --bootstrap starts dm-agent

Example:
  curl -fsSL https://github.com/marmot-protocol/darkmatter/releases/download/dm-agent-v0.1.0/install-hermes-marmot.sh | bash

  curl -fsSL .../install-hermes-marmot.sh | bash -s -- --bootstrap
USAGE
}

log() {
    printf 'install-hermes-marmot: %s\n' "$*"
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

detect_platform() {
    local os arch
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"
    case "$os-$arch" in
        linux-x86_64 | linux-amd64) echo "linux-x86_64" ;;
        darwin-arm64 | darwin-aarch64) echo "darwin-aarch64" ;;
        *)
            echo "error: unsupported platform: $os/$arch (supported: linux/x86_64, darwin/arm64)" >&2
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

install_dm_agent() {
    local platform="$1"
    local tmpdir="$2"
    local suffix="$DM_AGENT_VERSION"
    local archive="$tmpdir/dm-agent-$platform-$suffix.tar.gz"
    local checksum="$tmpdir/dm-agent-$platform-$suffix.tar.gz.sha256"
    local extract_dir="$tmpdir/dm-agent-extract"
    local install_dir

    if [ "$SYSTEM_INSTALL" -eq 1 ]; then
        install_dir="/usr/local/bin"
    else
        install_dir="$MARMOT_INSTALL_PREFIX/bin"
    fi

    download_asset "dm-agent-$platform-$suffix.tar.gz" "$archive"
    download_asset "dm-agent-$platform-$suffix.tar.gz.sha256" "$checksum"
    verify_sha256 "$archive" "$checksum"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "would install dm-agent to $install_dir/dm-agent"
        return 0
    fi

    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"
    tar -xzf "$archive" -C "$extract_dir"
    run mkdir -p "$install_dir"
    run install -m 0755 "$extract_dir/dm-agent-$platform/dm-agent" "$install_dir/dm-agent"
    log "installed dm-agent -> $install_dir/dm-agent"
}

install_plugin() {
    local tmpdir="$1"
    local suffix="$DM_AGENT_VERSION"
    local archive="$tmpdir/hermes-marmot-plugin-$suffix.tar.gz"
    local checksum="$tmpdir/hermes-marmot-plugin-$suffix.tar.gz.sha256"
    local extract_dir="$tmpdir/plugin-extract"

    download_asset "hermes-marmot-plugin-$suffix.tar.gz" "$archive"
    download_asset "hermes-marmot-plugin-$suffix.tar.gz.sha256" "$checksum"
    verify_sha256 "$archive" "$checksum"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "would install plugin to $MARMOT_PLUGIN_DIR"
        return 0
    fi

    if [ -e "$MARMOT_PLUGIN_DIR" ] && [ "$FORCE" -ne 1 ]; then
        echo "error: plugin path already exists: $MARMOT_PLUGIN_DIR (pass --force to replace)" >&2
        exit 1
    fi

    rm -rf "$extract_dir"
    mkdir -p "$extract_dir"
    tar -xzf "$archive" -C "$extract_dir"
    run rm -rf "$MARMOT_PLUGIN_DIR"
    run mkdir -p "$(dirname "$MARMOT_PLUGIN_DIR")"
    run cp -R "$extract_dir/hermes-marmot-plugin" "$MARMOT_PLUGIN_DIR"
    log "installed Hermes plugin -> $MARMOT_PLUGIN_DIR"
}

enable_hermes_plugin() {
    if ! command -v hermes >/dev/null 2>&1; then
        log "hermes not found on PATH; skipping 'hermes plugins enable marmot'"
        return 0
    fi
    run hermes plugins enable marmot
    log "enabled Hermes plugin: marmot"
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
            log "add $bindir to PATH before running dm-agent"
            export PATH="$bindir:$PATH"
            ;;
    esac
}

run_bootstrap() {
    ensure_path
    if ! command -v dm-agent >/dev/null 2>&1; then
        echo "error: dm-agent not found on PATH after install" >&2
        exit 1
    fi

    local dm_agent_pid=""
    if [ "$START_DM_AGENT" -eq 1 ]; then
        local -a dm_agent_args=(--home "$MARMOT_HOME")
        local relay
        IFS=',' read -r -a relays <<<"$MARMOT_RELAYS"
        for relay in "${relays[@]}"; do
            relay="${relay#"${relay%%[![:space:]]*}"}"
            relay="${relay%"${relay##*[![:space:]]}"}"
            [ -z "$relay" ] || dm_agent_args+=(--relay "$relay")
        done
        log "starting dm-agent"
        if [ "$DRY_RUN" -eq 1 ]; then
            printf '[dry-run] dm-agent'
            printf ' %q' "${dm_agent_args[@]}"
            printf '\n'
        else
            run mkdir -p "$MARMOT_HOME"
            dm-agent "${dm_agent_args[@]}" &
            dm_agent_pid="$!"
        fi
    fi

    log "running dm-agent bootstrap"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] dm-agent bootstrap --home %q --qr\n' "$MARMOT_HOME"
    else
        run dm-agent bootstrap --home "$MARMOT_HOME" --qr
    fi

    if [ -n "$dm_agent_pid" ] && [ "$DRY_RUN" -eq 0 ]; then
        log "dm-agent running in background (pid $dm_agent_pid)"
    fi
}

print_next_steps() {
    cat <<EOF

Install complete.

Next steps:
  1. Ensure dm-agent is on your PATH ($(
    if [ "$SYSTEM_INSTALL" -eq 1 ]; then echo "/usr/local/bin"; else echo "$MARMOT_INSTALL_PREFIX/bin"; fi
  ))
  2. Start the connector:
     export MARMOT_HOME="$MARMOT_HOME"
     dm-agent --home "\$MARMOT_HOME" --relay wss://relay.eu.whitenoise.chat --relay wss://relay.us.whitenoise.chat
  3. Bootstrap or reuse the agent account:
     dm-agent bootstrap --home "\$MARMOT_HOME" --qr
  4. Start Hermes:
     hermes gateway run

Build: ${MARMOT_RELEASE_REPO}@${MARMOT_RELEASE_TAG} (${DM_AGENT_VERSION})
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --bootstrap)
            INSTALL_BOOTSTRAP=1
            START_DM_AGENT=1
            shift
            ;;
        --no-start-dm-agent)
            START_DM_AGENT=0
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

need_cmd curl
need_cmd tar
platform="$(detect_platform)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

log "platform=$platform repo=$MARMOT_RELEASE_REPO tag=$MARMOT_RELEASE_TAG version=$DM_AGENT_VERSION"
install_dm_agent "$platform" "$tmpdir"
install_plugin "$tmpdir"
enable_hermes_plugin

if [ "$INSTALL_BOOTSTRAP" -eq 1 ]; then
    run_bootstrap
else
    print_next_steps
fi
