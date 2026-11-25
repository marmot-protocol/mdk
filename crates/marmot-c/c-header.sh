#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"
crate_dir="$(cd "$(dirname "$0")" && pwd)"
cd "$crate_dir/../.."
mkdir -p "$crate_dir/include"

# Expand the mirror-generating macros on the stable toolchain.
RUSTC_BOOTSTRAP=1 cbindgen --config "$crate_dir/cbindgen.toml" --crate marmot-c \
    --output "$crate_dir/include/marmot.h" "$crate_dir"
