#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: scripts/hermes_marmot_dev_teardown.sh [options]

Stops generated background processes, then deletes the isolated Hermes Marmot
development root.

Options:
  --root PATH      Dev root (default: ${TMPDIR:-/tmp}/hermes-marmot-test)
  --dry-run        Print what would be removed
  --force          Do not prompt before deletion
  -h, --help       Show this help
USAGE
}

default_tmp="${TMPDIR:-/tmp}"
dev_root="${HERMES_MARMOT_DEV_ROOT:-${default_tmp%/}/hermes-marmot-test}"
dry_run=0
force=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --root)
            dev_root="$2"
            shift 2
            ;;
        --dry-run)
            dry_run=1
            shift
            ;;
        --force)
            force=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ -z "$dev_root" ]; then
    echo "error: empty dev root" >&2
    exit 1
fi

dev_parent="$(dirname "$dev_root")"
dev_base="$(basename "$dev_root")"
if [ ! -d "$dev_parent" ]; then
    echo "nothing to remove: $dev_root"
    exit 0
fi
dev_root="$(cd "$dev_parent" && pwd)/$dev_base"

same_or_within() {
    local path="${1%/}"
    local root="${2%/}"
    if [ -z "$path" ]; then
        path="/"
    fi
    if [ -z "$root" ]; then
        root="/"
    fi
    if [ "$root" = "/" ]; then
        [ "$path" = "/" ]
        return
    fi
    [ "$path" = "$root" ] || [[ "$path" = "$root/"* ]]
}

within_root() {
    local path="${1%/}"
    local root="${2%/}"
    if [ -z "$path" ]; then
        path="/"
    fi
    if [ -z "$root" ]; then
        root="/"
    fi
    if [ "$root" = "/" ]; then
        [ "$path" != "/" ]
        return
    fi
    [[ "$path" = "$root/"* ]]
}

default_tmp_root="${default_tmp%/}"
if [ -d "$default_tmp_root" ]; then
    default_tmp_root="$(cd "$default_tmp_root" && pwd)"
fi

home_root="${HOME%/}"
home_data_root="$home_root/.local/share"
if same_or_within "$dev_root" "/" \
    || same_or_within "$dev_root" "$PWD" \
    || same_or_within "$dev_root" "/etc" \
    || same_or_within "$dev_root" "/usr" \
    || same_or_within "$dev_root" "/bin" \
    || same_or_within "$dev_root" "/sbin" \
    || same_or_within "$dev_root" "/System" \
    || same_or_within "$dev_root" "/Library"; then
    echo "error: refusing to delete unsafe root: $dev_root" >&2
    exit 1
fi
if same_or_within "$dev_root" "$home_root" && ! within_root "$dev_root" "$home_data_root"; then
    echo "error: refusing to delete unsafe root: $dev_root" >&2
    exit 1
fi
if ! within_root "$dev_root" "/tmp" \
    && ! within_root "$dev_root" "/var/tmp" \
    && ! within_root "$dev_root" "$default_tmp_root" \
    && ! within_root "$dev_root" "$home_data_root"; then
    echo "error: refusing to delete unsafe root: $dev_root" >&2
    exit 1
fi

if [ ! -e "$dev_root" ]; then
    echo "nothing to remove: $dev_root"
    exit 0
fi

if [ -x "$dev_root/stop-dev-processes.sh" ]; then
    "$dev_root/stop-dev-processes.sh" || true
fi

if [ "$dry_run" -eq 1 ]; then
    echo "would remove: $dev_root"
    exit 0
fi

if [ "$force" -ne 1 ]; then
    printf 'Delete %s? [y/N] ' "$dev_root" >&2
    read -r answer
    case "$answer" in
        y|Y|yes|YES)
            ;;
        *)
            echo "aborted"
            exit 1
            ;;
    esac
fi

rm -rf "$dev_root"
echo "removed: $dev_root"
