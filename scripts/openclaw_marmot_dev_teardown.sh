#!/usr/bin/env bash
# Remove the throwaway OpenClaw Marmot dev root created by
# scripts/openclaw_marmot_dev_setup.sh. Mirrors the Hermes teardown.
set -euo pipefail

ROOT="${OPENCLAW_MARMOT_DEV_ROOT:-${TMPDIR:-/tmp}/openclaw-marmot-test}"
FORCE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --root) ROOT="$2"; shift 2;;
        --force) FORCE=1; shift;;
        -h|--help) echo "Usage: openclaw_marmot_dev_teardown.sh [--root DIR] [--force]"; exit 0;;
        *) echo "unknown option: $1" >&2; exit 2;;
    esac
done

if [ ! -d "$ROOT" ]; then
    echo "openclaw-marmot teardown: nothing at $ROOT"
    exit 0
fi

if [ "$FORCE" -ne 1 ]; then
    printf 'Delete dev root %s? [y/N] ' "$ROOT"
    read -r reply
    case "$reply" in y|Y|yes|YES) ;; *) echo "aborted"; exit 1;; esac
fi

case "$ROOT" in
    ""|"/"|"."|"/home"|"/root"|"/usr"|"/opt"|"/etc"|"/var"|"$HOME")
        echo "refusing to delete unsafe root path: '$ROOT'" >&2
        exit 1
        ;;
esac

rm -rf "$ROOT"
echo "openclaw-marmot teardown: removed $ROOT"
