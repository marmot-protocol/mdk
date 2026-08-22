#!/usr/bin/env bash
# Build and stage the marmot-c artifact set.
#
# Outputs (under <crate>/output/):
#   lib/libmarmot_c.so       (cdylib, host target)
#   lib/libmarmot_c.a        (staticlib, host target)
#   include/marmot.h         (checked-in cbindgen header, copied)
#   lib/pkgconfig/marmot-c.pc

set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"

CRATE_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_DIR="$(cd "$CRATE_DIR/../.." && pwd)"
TARGET_DIR="$WORKSPACE_DIR/target"
OUT_DIR="$CRATE_DIR/output"

CRATE_NAME="marmot-c"
LIB_BASENAME="marmot_c"

cd "$WORKSPACE_DIR"

echo "==> Cleaning previous output"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/lib/pkgconfig" "$OUT_DIR/include"

echo "==> Building release cdylib + staticlib"
cargo build --release -p "$CRATE_NAME"

case "$(uname -s)" in
  Darwin) DYLIB_EXT="dylib" ;;
  *) DYLIB_EXT="so" ;;
esac

cp "$TARGET_DIR/release/lib$LIB_BASENAME.$DYLIB_EXT" "$OUT_DIR/lib/"
cp "$TARGET_DIR/release/lib$LIB_BASENAME.a" "$OUT_DIR/lib/"
cp "$CRATE_DIR/include/marmot.h" "$OUT_DIR/include/"

echo "==> Generating pkg-config file"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$WORKSPACE_DIR/Cargo.toml" | head -n 1)"
sed -e "s|@VERSION@|$version|" "$CRATE_DIR/marmot-c.pc.in" > "$OUT_DIR/lib/pkgconfig/marmot-c.pc"

echo "==> Done: $OUT_DIR"
