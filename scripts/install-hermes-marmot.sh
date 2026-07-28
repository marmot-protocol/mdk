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
MIN_HERMES_VERSION="0.19.0"

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
EXISTING_IDENTITY_FILE=""
EXISTING_IDENTITY_PROMPT=0
GENERATE_IDENTITY_EXPLICIT=0
EXPECTED_IDENTITY=""
IMPORTED_ACCOUNT_ID_HEX=""
WN_AGENT_TEMP_PID=""

RELAYS=()
ALLOW_WELCOMERS=()
ALLOW_USERS=()
QUIC_CANDIDATES=()
EXPLICIT_ALLOW_ALL=0

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
  --existing-identity-file PATH
                           Import an existing nsec/raw-hex identity from an
                           owner-only regular file before bootstrap
  --expected-npub VALUE    Fail unless the imported identity matches this npub
                           or 64-character hex public key; this must be a public
                           key, never an nsec or raw secret key
  --generate-identity      Explicitly use generated-identity onboarding (default)
  --allow-user VALUE       Allow Marmot messages from this npub or hex account id; may repeat
  --allow-all-users        Allow Marmot messages from any sender (explicit opt-in)
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

Welcomer allowlist entries control which accounts may invite the Marmot agent
through wn-agent. Message-sender allowlist entries control which Marmot senders
Hermes accepts after gateway restart via $HERMES_HOME/.env.

Example:
  curl -fsSL https://github.com/marmot-protocol/mdk/releases/download/wn-agent-latest/install-hermes-marmot.sh | bash

  curl -fsSL .../install-hermes-marmot.sh | bash -s -- --yes \
    --existing-identity-file "$HOME/.config/example/hermes-agent.nsec" \
    --allow-welcomer npub1... \
    --expected-npub npub1... \
    --allow-user npub1...

  curl -fsSL .../install-hermes-marmot.sh | bash -s -- --yes \
    --allow-all-users
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

version_at_least() {
    awk -v have="$1" -v need="$2" 'BEGIN {
        split(have, h, "."); split(need, n, ".");
        for (i = 1; i <= 3; i++) {
            hv = (h[i] == "" ? 0 : h[i]) + 0;
            nv = (n[i] == "" ? 0 : n[i]) + 0;
            if (hv > nv) exit 0;
            if (hv < nv) exit 1;
        }
        exit 0;
    }'
}

require_hermes_version() {
    local output version
    output="$(hermes --version 2>&1)" || {
        echo "error: could not determine Hermes version; Hermes $MIN_HERMES_VERSION or newer is required" >&2
        exit 1
    }
    version="$(printf '%s\n' "$output" | awk '
        match($0, /[0-9]+\.[0-9]+\.[0-9]+/) {
            print substr($0, RSTART, RLENGTH)
            exit
        }
    ')"
    if [ -z "$version" ] || ! version_at_least "$version" "$MIN_HERMES_VERSION"; then
        echo "error: Hermes $MIN_HERMES_VERSION or newer is required (found ${version:-unknown}); upgrade Hermes separately, then rerun this installer" >&2
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
    local tty_path
    tty_path="$(prompt_tty_path)"
    [ -r "$tty_path" ] && [ -w "$tty_path" ]
}

prompt_tty_path() {
    if [ -n "${HERMES_INSTALLER_TEST_PROMPT_TTY:-}" ]; then
        case "${HERMES_INSTALLER_TEST_PROMPT_TTY}" in
            /dev/null | /dev/fd/[0-9]*)
                printf '%s\n' "${HERMES_INSTALLER_TEST_PROMPT_TTY}"
                ;;
            *)
                echo "error: HERMES_INSTALLER_TEST_PROMPT_TTY must be /dev/null or an inherited /dev/fd/* handle" >&2
                exit 1
                ;;
        esac
        return 0
    fi
    printf '%s\n' /dev/tty
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
        printf '%s [%s]: ' "$prompt" "$default_value" >"$(prompt_tty_path)"
    else
        printf '%s: ' "$prompt" >"$(prompt_tty_path)"
    fi
    if ! IFS= read -r reply <"$(prompt_tty_path)"; then
        return 1
    fi
    if [ -z "$reply" ]; then
        printf '%s\n' "$default_value"
    else
        printf '%s\n' "$reply"
    fi
    return 0
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
        printf '%s [%s]: ' "$prompt" "$suffix" >"$(prompt_tty_path)"
        if ! IFS= read -r reply <"$(prompt_tty_path)"; then
            return 2
        fi
        reply="${reply:-$default_value}"
        normalized="$(printf '%s' "$reply" | tr '[:upper:]' '[:lower:]')"
        case "$normalized" in
            y | yes) return 0 ;;
            n | no) return 1 ;;
            *) printf 'Please answer yes or no.\n' >"$(prompt_tty_path)" ;;
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

is_user_ref_syntax() {
    is_welcomer_ref_syntax "$1"
}

validate_welcomer_inputs() {
    local welcomer
    if [ "${#ALLOW_WELCOMERS[@]}" -eq 0 ]; then
        return 0
    fi
    for welcomer in "${ALLOW_WELCOMERS[@]}"; do
        if ! is_welcomer_ref_syntax "$welcomer"; then
            echo "error: invalid welcomer allowlist entry" >&2
            echo "expected a Nostr npub or 64-character hex account id" >&2
            exit 1
        fi
    done
}

validate_user_inputs() {
    local user entry remaining
    if [ "${#ALLOW_USERS[@]}" -eq 0 ]; then
        return 0
    fi
    for user in "${ALLOW_USERS[@]}"; do
        remaining="$user,"
        while [[ "$remaining" == *,* ]]; do
            entry="${remaining%%,*}"
            remaining="${remaining#*,}"
            if ! is_user_ref_syntax "$entry"; then
                echo "error: invalid message sender allowlist entry" >&2
                echo "expected a Nostr npub or 64-character hex account id" >&2
                exit 1
            fi
        done
    done
}

configure_gateway_helper_path() {
    if installed_configure_gateway_helper_path; then
        return 0
    fi
    same_version_configure_gateway_helper_path
}

same_version_configure_gateway_helper_path() {
    if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/hermes_marmot_configure_gateway.py" ]; then
        printf '%s\n' "$SCRIPT_DIR/hermes_marmot_configure_gateway.py"
        return 0
    fi
    return 1
}

strict_validate_sender_auth_preflight() {
    need_cmd python3
    local -a args=()
    if [ "${#ALLOW_USERS[@]}" -gt 0 ]; then
        local user
        for user in "${ALLOW_USERS[@]}"; do
            args+=(--allow-user "$user")
        done
    fi
    local helper=""
    if helper="$(same_version_configure_gateway_helper_path 2>/dev/null)"; then
        run_gateway_helper_env_dry_run "$helper"
        return $?
    fi
    INSTALL_SCRIPT_DIR="$SCRIPT_DIR" HERMES_HOME="$HERMES_HOME" \
        python3 - "${args[@]+"${args[@]}"}" <<'PY'
import os
import re
import sys
from pathlib import Path
from typing import Iterable, Optional

# These constants and the identity-parsing functions below intentionally mirror
# scripts/hermes_marmot_configure_gateway.py. A semantic parity test guards this
# streamed-install fallback against drifting from the installed helper.
ACCOUNT_ID_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_VALUES = {character: index for index, character in enumerate(_BECH32_CHARSET)}
MANAGED_ENV_KEYS = ("MARMOT_ALLOWED_USERS", "MARMOT_ALLOW_ALL_USERS")


def _bech32_polymod(values: Iterable[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def _convert_bits(values: Iterable[int], from_bits: int, to_bits: int) -> Optional[bytes]:
    accumulator = 0
    bit_count = 0
    result = bytearray()
    max_value = (1 << to_bits) - 1
    for value in values:
        if value < 0 or value >> from_bits:
            return None
        accumulator = (accumulator << from_bits) | value
        bit_count += from_bits
        while bit_count >= to_bits:
            bit_count -= to_bits
            result.append((accumulator >> bit_count) & max_value)
    if bit_count >= from_bits or ((accumulator << (to_bits - bit_count)) & max_value):
        return None
    return bytes(result)


def _npub_to_hex(value: str) -> Optional[str]:
    if not value or len(value) > 90 or (value.lower() != value and value.upper() != value):
        return None
    normalized = value.lower()
    separator = normalized.rfind("1")
    if separator <= 0 or normalized[:separator] != "npub" or separator + 7 > len(normalized):
        return None
    try:
        data = [_BECH32_VALUES[character] for character in normalized[separator + 1 :]]
    except KeyError:
        return None
    hrp = normalized[:separator]
    expanded_hrp = [ord(character) >> 5 for character in hrp]
    expanded_hrp.extend([0])
    expanded_hrp.extend(ord(character) & 31 for character in hrp)
    if _bech32_polymod([*expanded_hrp, *data]) != 1:
        return None
    decoded = _convert_bits(data[:-6], 5, 8)
    if decoded is None or len(decoded) != 32:
        return None
    return decoded.hex()


def normalize_account_id(entry: str) -> str:
    normalized = str(entry).strip()
    if not normalized:
        return ""
    if normalized.lower().startswith("npub1"):
        return _npub_to_hex(normalized) or ""
    return normalized.lower().removeprefix("0x")


def _validate_account_id(entry: str, *, label: str) -> str:
    normalized = normalize_account_id(entry)
    if not ACCOUNT_ID_HEX_RE.fullmatch(normalized):
        raise ValueError(
            f"invalid {label}: expected a Nostr npub or 64-character hex account id"
        )
    return normalized


def validate_sender_auth_entries(entries: list[str]) -> None:
    for entry in entries:
        if not str(entry).strip():
            raise ValueError("invalid allowed user: empty value is not allowed")
        _validate_account_id(entry, label="allowed user")


def _parse_dotenv_scalar(raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        return ""
    if value[0] in {"'", '"'}:
        quote = value[0]
        end = value.find(quote, 1)
        if end == -1:
            return value[1:]
        return value[1:end]
    value = re.sub(r"\s+#.*$", "", value).strip()
    return value


def _parse_bool(value: str, *, name: str) -> bool:
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean-ish value, got {value!r}")


def _managed_env_key(line: str) -> Optional[str]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if "=" not in stripped:
        return None
    key = stripped.split("=", 1)[0].strip()
    if key.startswith("export "):
        key = key[7:].strip()
    if key in MANAGED_ENV_KEYS:
        return key
    return None


def _parse_allowed_users_value(raw_value: str) -> list[str]:
    parsed = _parse_dotenv_scalar(raw_value)
    if not parsed.strip():
        return []
    users: list[str] = []
    for entry in parsed.split(","):
        normalized = normalize_account_id(entry)
        if not normalized:
            if entry.strip():
                raise ValueError("invalid MARMOT_ALLOWED_USERS entry")
            continue
        if not ACCOUNT_ID_HEX_RE.fullmatch(normalized):
            raise ValueError("invalid MARMOT_ALLOWED_USERS entry")
        users.append(normalized)
    return sorted(dict.fromkeys(users))


def validate_existing_env_auth(env_path: Path) -> None:
    if not env_path.is_file():
        return
    allowed_users: list[str] | None = None
    allow_all_users: bool | None = None
    saw_managed = False
    for line in env_path.read_text(encoding="utf-8").splitlines():
        key = _managed_env_key(line)
        if key is None:
            continue
        saw_managed = True
        _, raw_value = line.split("=", 1)
        if key == "MARMOT_ALLOWED_USERS":
            allowed_users = _parse_allowed_users_value(raw_value)
        elif key == "MARMOT_ALLOW_ALL_USERS":
            allow_all_users = _parse_bool(
                _parse_dotenv_scalar(raw_value),
                name="MARMOT_ALLOW_ALL_USERS",
            )
    if not saw_managed:
        return
    if allowed_users is None:
        allowed_users = []
    if allow_all_users is None:
        allow_all_users = False
    if not allowed_users and not allow_all_users:
        raise ValueError("invalid existing Hermes Marmot sender authorization")


args = sys.argv[1:]
index = 0
allowed_users: list[str] = []
while index < len(args):
    if args[index] == "--allow-user":
        index += 1
        if index >= len(args):
            print("error: missing value for --allow-user", file=sys.stderr)
            raise SystemExit(2)
        allowed_users.extend(args[index].split(","))
    index += 1

try:
    validate_sender_auth_entries(allowed_users)
except ValueError as exc:
    print(f"error: {exc}", file=sys.stderr)
    raise SystemExit(2) from exc

hermes_home = Path(os.environ.get("HERMES_HOME", ""))
if hermes_home:
    try:
        validate_existing_env_auth(hermes_home / ".env")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
PY
}

installed_configure_gateway_helper_path() {
    if [ -f "$MARMOT_PLUGIN_DIR/configure_gateway.py" ]; then
        printf '%s\n' "$MARMOT_PLUGIN_DIR/configure_gateway.py"
        return 0
    fi
    return 1
}

hermes_env_has_managed_sender_auth_keys() {
    local env_file="$HERMES_HOME/.env"
    [ -f "$env_file" ] || return 1
    grep -Eq '^[[:space:]]*(export[[:space:]]+)?MARMOT_ALLOWED_USERS[[:space:]]*=' "$env_file" && return 0
    grep -Eq '^[[:space:]]*(export[[:space:]]+)?MARMOT_ALLOW_ALL_USERS[[:space:]]*=' "$env_file" && return 0
    return 1
}

run_gateway_helper_env_dry_run() {
    local helper="${1:-}"
    if [ -z "$helper" ]; then
        if ! helper="$(configure_gateway_helper_path)"; then
            return 1
        fi
    fi
    local -a args=(
        "$helper"
        --home "$HERMES_HOME"
        --configure-env
        --env-dry-run
        --quiet
    )
    if [ "${#ALLOW_USERS[@]}" -gt 0 ]; then
        local user
        for user in "${ALLOW_USERS[@]}"; do
            args+=(--allow-user "$user")
        done
    fi
    if [ "$EXPLICIT_ALLOW_ALL" -eq 1 ]; then
        args+=(--allow-all-users)
    fi
    python3 "${args[@]}"
}

sender_auth_not_configured_message() {
    echo "error: Hermes Marmot sender authorization is not configured." >&2
    echo "Pass one or more --allow-user npub-or-hex values, opt into --allow-all-users," >&2
    echo "or keep an existing valid allowlist in $HERMES_HOME/.env." >&2
    echo "Use --no-configure-hermes to install assets without patching Hermes." >&2
}

guided_setup_input_failed() {
    echo "error: guided setup input is unavailable; use --yes with explicit flags." >&2
}

log_sender_auth_dry_run_intent() {
    if [ "${#ALLOW_USERS[@]}" -gt 0 ]; then
        log "would configure Marmot message-sender authorization for ${#ALLOW_USERS[@]} allowed sender(s)"
    elif [ -f "$HERMES_HOME/.env" ]; then
        log "would preserve or update existing Marmot message-sender authorization in Hermes env"
    else
        log "would configure Marmot message-sender authorization in Hermes env"
    fi
    if [ "$EXPLICIT_ALLOW_ALL" -eq 1 ]; then
        log "would set MARMOT_ALLOW_ALL_USERS=true"
    else
        log "would keep MARMOT_ALLOW_ALL_USERS=false unless already true in Hermes env"
    fi
}

validate_hermes_sender_auth_pre_install() {
    if [ "$CONFIGURE_HERMES" -ne 1 ]; then
        return 0
    fi

    if ! strict_validate_sender_auth_preflight; then
        echo "error: invalid Hermes Marmot sender authorization inputs" >&2
        exit 1
    fi

    if [ "$DRY_RUN" -eq 0 ] && [ "$ASSUME_YES" -eq 1 ]; then
        if [ "$EXPLICIT_ALLOW_ALL" -eq 0 ] && [ "${#ALLOW_USERS[@]}" -eq 0 ]; then
            if ! hermes_env_has_managed_sender_auth_keys; then
                sender_auth_not_configured_message
                exit 1
            fi
        fi
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        if [ "$EXPLICIT_ALLOW_ALL" -eq 1 ]; then
            return 0
        fi
        if [ "${#ALLOW_USERS[@]}" -gt 0 ]; then
            return 0
        fi
        if hermes_env_has_managed_sender_auth_keys; then
            return 0
        fi
        sender_auth_not_configured_message
        exit 1
    fi

    if [ "$EXPLICIT_ALLOW_ALL" -eq 1 ] || [ "${#ALLOW_USERS[@]}" -gt 0 ] || hermes_env_has_managed_sender_auth_keys; then
        return 0
    fi

    sender_auth_not_configured_message
    exit 1
}

validate_hermes_sender_auth_post_install() {
    if [ "$CONFIGURE_HERMES" -ne 1 ] || [ "$DRY_RUN" -eq 1 ]; then
        return 0
    fi
    local helper
    if ! helper="$(installed_configure_gateway_helper_path)"; then
        echo "error: Hermes config helper not found after plugin install" >&2
        exit 1
    fi
    if ! run_gateway_helper_env_dry_run "$helper"; then
        echo "error: Hermes Marmot sender authorization validation failed after plugin install" >&2
        exit 1
    fi
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

import_existing_identity() {
    if [ -z "$EXISTING_IDENTITY_FILE" ] && [ "$EXISTING_IDENTITY_PROMPT" -ne 1 ]; then
        return 0
    fi
    ensure_path
    if [ "$DRY_RUN" -eq 0 ]; then
        need_cmd wn-agent
        need_cmd python3
    fi

    local -a args=(
        import-identity
        --json
        --home "$MARMOT_HOME"
        --label "$MARMOT_AGENT_LABEL"
    )
    if [ -n "$EXISTING_IDENTITY_FILE" ]; then
        args+=(--identity-file "$EXISTING_IDENTITY_FILE")
    else
        args+=(--prompt)
    fi
    if [ -n "$EXPECTED_IDENTITY" ]; then
        args+=(--expected-identity "$EXPECTED_IDENTITY")
    fi

    log "importing and verifying existing Nostr identity"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] wn-agent'
        printf ' %q' "${args[@]}"
        printf '\n'
        IMPORTED_ACCOUNT_ID_HEX="<account-id-from-identity-import>"
        return 0
    fi

    local imported_json
    imported_json="$(wn-agent "${args[@]}")"
    IMPORTED_ACCOUNT_ID_HEX="$(
        printf '%s\n' "$imported_json" |
            python3 -c 'import json, sys; print(json.load(sys.stdin)["account_id_hex"])'
    )"
    if [ -z "$IMPORTED_ACCOUNT_ID_HEX" ]; then
        echo "error: identity import did not return an account id" >&2
        exit 1
    fi
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
    if [ -n "$IMPORTED_ACCOUNT_ID_HEX" ]; then
        args+=(--no-create --account-id-hex "$IMPORTED_ACCOUNT_ID_HEX")
    fi
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
    local helper
    if ! helper="$(configure_gateway_helper_path)"; then
        if [ "$DRY_RUN" -eq 1 ]; then
            log "would patch Hermes config: $HERMES_HOME/config.yaml"
            log "would preserve other Hermes connectors and only update platforms.marmot/display.platforms.marmot"
            log_sender_auth_dry_run_intent
            return 0
        fi
        echo "error: Hermes config helper not found" >&2
        exit 1
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        log "would patch Hermes config: $HERMES_HOME/config.yaml"
        log "would preserve other Hermes connectors and only update platforms.marmot/display.platforms.marmot"
        log_sender_auth_dry_run_intent
        return 0
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
        --configure-env
    )
    if [ "$ENABLE_STREAMING" -eq 1 ]; then
        args+=(--streaming 1 --transport auto --configure-global-streaming)
    else
        args+=(--streaming 0 --transport off)
    fi
    local welcomer
    if [ "${#ALLOW_WELCOMERS[@]}" -gt 0 ]; then
        for welcomer in "${ALLOW_WELCOMERS[@]}"; do
            args+=(--welcomer-allowlist "$welcomer")
        done
    fi
    if [ "${#ALLOW_USERS[@]}" -gt 0 ]; then
        local user
        for user in "${ALLOW_USERS[@]}"; do
            args+=(--allow-user "$user")
        done
    fi
    if [ "$EXPLICIT_ALLOW_ALL" -eq 1 ]; then
        args+=(--allow-all-users)
    fi
    run python3 "${args[@]}"
}

print_next_steps() {
    # Account ids stay in the bootstrap/config files but are intentionally
    # omitted here to keep installer diagnostics privacy-safe.
    cat <<EOF

Install complete.

Marmot agent:
  label: $MARMOT_AGENT_LABEL
  home: $MARMOT_HOME
  socket: $MARMOT_AGENT_SOCKET
  service: $MARMOT_AGENT_SERVICE_NAME.service (Linux) / $MARMOT_AGENT_LAUNCHD_LABEL (macOS)
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
  hermes gateway restart

Hermes loads sender authorization from $HERMES_HOME/.env at gateway startup.
After changing MARMOT_ALLOWED_USERS or MARMOT_ALLOW_ALL_USERS, restart Hermes
so allowed Marmot senders are accepted.

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
        --existing-identity-file)
            EXISTING_IDENTITY_FILE="${2:?missing value for --existing-identity-file}"
            shift 2
            ;;
        --expected-npub)
            EXPECTED_IDENTITY="${2:?missing value for --expected-npub}"
            shift 2
            ;;
        --generate-identity)
            GENERATE_IDENTITY_EXPLICIT=1
            shift
            ;;
        --allow-welcomer)
            ALLOW_WELCOMERS+=("${2:?missing value for --allow-welcomer}")
            shift 2
            ;;
        --allow-user)
            ALLOW_USERS+=("${2:?missing value for --allow-user}")
            shift 2
            ;;
        --allow-all-users)
            EXPLICIT_ALLOW_ALL=1
            shift
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
    if ! HERMES_HOME="$(prompt_value "Hermes home" "$HERMES_HOME")"; then
        guided_setup_input_failed
        exit 1
    fi
    if ! MARMOT_HOME="$(prompt_value "Marmot agent home" "$MARMOT_HOME")"; then
        guided_setup_input_failed
        exit 1
    fi
    MARMOT_PLUGIN_DIR="${MARMOT_PLUGIN_DIR_OVERRIDE:-$HERMES_HOME/plugins/marmot}"
    MARMOT_AGENT_SOCKET="${MARMOT_AGENT_SOCKET_OVERRIDE:-$MARMOT_HOME/dev/wn-agent.sock}"
    if [ -e "$MARMOT_HOME" ]; then
        log "existing Marmot agent home detected; bootstrap will reuse or repair it: $MARMOT_HOME"
    fi
    if [ "$GENERATE_IDENTITY_EXPLICIT" -ne 1 ] && [ -z "$EXISTING_IDENTITY_FILE" ]; then
        if prompt_yes_no "Import an existing Nostr identity?" "no"; then
            if prompt_yes_no "Read the identity from an owner-only file?" "yes"; then
                EXISTING_IDENTITY_FILE="$(prompt_value "Existing identity file" "")"
                if [ -z "$EXISTING_IDENTITY_FILE" ]; then
                    echo "error: existing identity file path cannot be empty" >&2
                    exit 1
                fi
            else
                EXISTING_IDENTITY_PROMPT=1
            fi
            EXPECTED_IDENTITY="$(prompt_value "Expected npub or hex (blank to skip)" "$EXPECTED_IDENTITY")"
        fi
    fi
    if [ "${#ALLOW_WELCOMERS[@]}" -eq 0 ]; then
        while true; do
            if ! welcomer_reply="$(prompt_value "Allowed inviter/welcomer npub or hex (blank to skip)" "")"; then
                guided_setup_input_failed
                exit 1
            fi
            if [ -n "$welcomer_reply" ]; then
                ALLOW_WELCOMERS+=("$welcomer_reply")
                break
            fi
            if prompt_yes_no "Skip the welcomer allowlist for now? Invites will not auto-accept." "no"; then
                break
            fi
        done
    fi
    if [ "${#ALLOW_USERS[@]}" -eq 0 ] && [ "$EXPLICIT_ALLOW_ALL" -ne 1 ]; then
        prompt_sender_auth=1
        if hermes_env_has_managed_sender_auth_keys; then
            log "existing Marmot message-sender authorization found in Hermes env; preserving unless you add entries"
            if ! prompt_yes_no "Add more allowed Marmot message senders?" "no"; then
                prompt_sender_auth=0
            fi
        fi
        if [ "$prompt_sender_auth" -eq 1 ]; then
            while true; do
                if ! user_reply="$(prompt_value "Allowed Marmot message sender npub or hex (blank to finish)" "")"; then
                    sender_auth_not_configured_message
                    exit 1
                fi
                if [ -n "$user_reply" ]; then
                    ALLOW_USERS+=("$user_reply")
                    continue
                fi
                if [ "${#ALLOW_USERS[@]}" -gt 0 ]; then
                    break
                fi
                if [ "${#ALLOW_WELCOMERS[@]}" -gt 0 ]; then
                    if prompt_yes_no "Also allow configured welcomer identity/identities to message Hermes?" "no"; then
                        ALLOW_USERS+=("${ALLOW_WELCOMERS[@]}")
                    else
                        welcomer_prompt_status=$?
                        if [ "$welcomer_prompt_status" -eq 2 ]; then
                            sender_auth_not_configured_message
                            exit 1
                        fi
                    fi
                fi
                if [ "${#ALLOW_USERS[@]}" -gt 0 ]; then
                    break
                fi
                if prompt_yes_no "Allow Marmot messages from any sender? This sets MARMOT_ALLOW_ALL_USERS=true." "no"; then
                    EXPLICIT_ALLOW_ALL=1
                    break
                else
                    allow_all_prompt_status=$?
                    if [ "$allow_all_prompt_status" -eq 2 ]; then
                        sender_auth_not_configured_message
                        exit 1
                    fi
                fi
                printf 'Add at least one allowed sender or opt into allow-all before continuing.\n' >"$(prompt_tty_path)"
            done
        fi
    fi
fi

MARMOT_OUTBOUND_MEDIA_DIR="${MARMOT_OUTBOUND_MEDIA_DIR_OVERRIDE:-$MARMOT_HOME/dev/outbound-media}"

if [ "$GENERATE_IDENTITY_EXPLICIT" -eq 1 ] && { [ -n "$EXISTING_IDENTITY_FILE" ] || [ "$EXISTING_IDENTITY_PROMPT" -eq 1 ]; }; then
    echo "error: --generate-identity conflicts with existing-identity onboarding" >&2
    exit 1
fi
if [ -n "$EXPECTED_IDENTITY" ] && [ -z "$EXISTING_IDENTITY_FILE" ] && [ "$EXISTING_IDENTITY_PROMPT" -ne 1 ]; then
    echo "error: --expected-npub requires --existing-identity-file" >&2
    exit 1
fi

validate_welcomer_inputs
validate_user_inputs
validate_hermes_sender_auth_pre_install

need_cmd curl
need_cmd tar
if [ "$DRY_RUN" -eq 0 ]; then
    need_cmd hermes
    require_hermes_version
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
import_existing_identity
install_plugin "$tmpdir"
validate_hermes_sender_auth_post_install
enable_hermes_plugin
bootstrap_agent
configure_hermes_gateway
print_next_steps
