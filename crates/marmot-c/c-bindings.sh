#!/usr/bin/env bash
# Build and stage the marmot-c artifact set.
#
# Outputs (under <crate>/output/):
#   lib/libmarmot_c.so       (cdylib, host target)
#   lib/libmarmot_c.a        (staticlib, host target)
#   include/marmot.h         (generated from the same checkout)
#   references/*/API-REFERENCE.md
#   lib/pkgconfig/marmot-c.pc

set -euo pipefail

if [[ $# != 0 ]]; then
  echo "usage: $0" >&2
  exit 2
fi

export PATH="$HOME/.cargo/bin:$PATH"

# Avoid Rust/LLVM debug stripping producing a misaligned Mach-O LINKEDIT pool
# rejected by Xcode 27. Match MarmotKit's unstripped Apple artifact policy.
# https://github.com/rust-lang/rust/issues/157750
# Revisit after upgrading the pinned Rust toolchain (fix: rust-lang/rust#158410).
# Remove only after the default optimized shared/static smoke passes without it.
if [[ "$(uname -s)" == "Darwin" ]]; then
    export CARGO_PROFILE_RELEASE_STRIP=none
fi

# pledge forbids mlock/munlock. OpenBSD concealed allocations exclude SQLite
# buffers from core dumps and wipe them on free; realloc preserves concealment.
# These flags affect only SQLCipher, not other C dependencies. Page residency
# is not guaranteed: swap protection follows the host's encryption policy.
if [[ "$(uname -s)" == "OpenBSD" ]]; then
    export LIBSQLITE3_FLAGS="${LIBSQLITE3_FLAGS:+$LIBSQLITE3_FLAGS }-DOMIT_MEMLOCK -Dmalloc=malloc_conceal -Dcalloc=calloc_conceal"
fi

CRATE_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_DIR="$(cd "$CRATE_DIR/../.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$WORKSPACE_DIR/target}"
OUT_DIR="$CRATE_DIR/output"

CRATE_NAME="marmot-c"
LIB_BASENAME="marmot_c"

cd "$WORKSPACE_DIR"

echo "==> Generating C header"
bash "$CRATE_DIR/c-header.sh"
python3 scripts/check_binding_docs.py --with-c

echo "==> Cleaning previous output"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/lib/pkgconfig" "$OUT_DIR/include"

echo "==> Building release cdylib + staticlib"
FEATURE_ARGS=()
if [[ "${OTLP_EXPORT:-0}" == "1" || "${OTLP_EXPORT:-}" == "true" ]]; then
  FEATURE_ARGS+=(--features otlp-export)
fi
if [[ "${PRODUCT_ANALYTICS_EXPORT:-0}" == "1" || "${PRODUCT_ANALYTICS_EXPORT:-}" == "true" ]]; then
  FEATURE_ARGS+=(--features product-analytics-export)
fi
cargo build --release --locked -p "$CRATE_NAME" ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}

# Darwin has no libdl: dlopen lives in libSystem.
case "$(uname -s)" in
  Darwin)
    DYLIB_EXT="dylib"
    LIBS_PRIVATE="-lm -lpthread -framework Security -framework CoreFoundation -liconv"
    ;;
  *) DYLIB_EXT="so"; LIBS_PRIVATE="-lm -lpthread -ldl" ;;
esac

cp "$TARGET_DIR/release/lib$LIB_BASENAME.$DYLIB_EXT" "$OUT_DIR/lib/"
cp "$TARGET_DIR/release/lib$LIB_BASENAME.a" "$OUT_DIR/lib/"
cp "$CRATE_DIR/include/marmot.h" "$OUT_DIR/include/"
mkdir -p "$OUT_DIR/references/marmot-c" "$OUT_DIR/references/marmot-uniffi"
sed 's|^\[Header contract\](include/marmot\.h#L|[Header contract](../../include/marmot.h#L|' \
  "$CRATE_DIR/API-REFERENCE.md" > "$OUT_DIR/references/marmot-c/API-REFERENCE.md"
cp crates/marmot-uniffi/API-REFERENCE.md "$OUT_DIR/references/marmot-uniffi/"

echo "==> Generating pkg-config file"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$WORKSPACE_DIR/Cargo.toml" | head -n 1)"
sed -e "s|@VERSION@|$version|" -e "s|@LIBS_PRIVATE@|$LIBS_PRIVATE|" \
    "$CRATE_DIR/marmot-c.pc.in" > "$OUT_DIR/lib/pkgconfig/marmot-c.pc"

echo "==> Done: $OUT_DIR"
