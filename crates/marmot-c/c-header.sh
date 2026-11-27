#!/usr/bin/env bash
set -euo pipefail

required=0.29.4
if [[ "${1:-}" == --print-version ]]; then
    printf '%s\n' "$required"
    exit 0
fi

export PATH="$HOME/.cargo/bin:$PATH"
if ! version="$(cbindgen --version)" || [[ "$version" != "cbindgen $required" ]]; then
    echo "C header generation requires cbindgen $required" >&2
    exit 1
fi

crate_dir="$(cd "$(dirname "$0")" && pwd)"
cd "$crate_dir/../.."
mkdir -p "$crate_dir/include"

# Expand the mirror-generating macros on the stable toolchain.
RUSTC_BOOTSTRAP=1 cbindgen --config "$crate_dir/cbindgen.toml" --crate marmot-c \
    --output "$crate_dir/include/marmot.h" "$crate_dir"
