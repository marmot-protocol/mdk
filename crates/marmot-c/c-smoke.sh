#!/usr/bin/env bash
# Compile and run the C smoke test against the freshly built staticlib.
# Runs under valgrind when available (CI installs it; locally optional).
#
# Usage: ./crates/marmot-c/c-smoke.sh [CC...]
#   CC list defaults to "cc"; CI passes "gcc clang" to cover both.

set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"

CRATE_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_DIR="$(cd "$CRATE_DIR/../.." && pwd)"
TARGET_DIR="$WORKSPACE_DIR/target"
BUILD_DIR="$CRATE_DIR/build"

COMPILERS=("${@:-cc}")

cd "$WORKSPACE_DIR"

echo "==> Building marmot-c staticlib (debug, faster + assert-friendly)"
cargo build -p marmot-c

mkdir -p "$BUILD_DIR"

for compiler in "${COMPILERS[@]}"; do
  if ! command -v "$compiler" >/dev/null 2>&1; then
    echo "==> Skipping $compiler (not installed)"
    continue
  fi
  bin="$BUILD_DIR/smoke-$compiler"
  echo "==> Compiling smoke.c with $compiler"
  "$compiler" -std=c11 -Wall -Wextra -Werror \
    -I "$CRATE_DIR/include" \
    "$CRATE_DIR/examples/smoke.c" \
    "$TARGET_DIR/debug/libmarmot_c.a" \
    -lm -lpthread -ldl \
    -o "$bin"

  smoke_home="$(mktemp -d)"
  trap 'rm -rf "$smoke_home"' EXIT
  ran_under_valgrind=0
  if command -v valgrind >/dev/null 2>&1; then
    # valgrind needs a redirectable ld.so (glibc debuginfo). On hosts that
    # ship a stripped dynamic linker it aborts at startup (exit 1) before
    # running the program; that is an infra gap, not a leak. Probe once and
    # fall back to a direct run so a local box never reports a false failure.
    # `--error-exitcode=42` makes an actual leak/error distinguishable from
    # a clean run (0) or a startup abort (non-0, non-42).
    echo "==> Running smoke test under valgrind ($compiler)"
    set +e
    valgrind --leak-check=full --errors-for-leak-kinds=definite \
      --error-exitcode=42 "$bin" "$smoke_home"
    vg_status=$?
    set -e
    if [[ "$vg_status" == "42" ]]; then
      echo "valgrind reported a definite leak or memory error" >&2
      exit 1
    elif [[ "$vg_status" == "0" ]]; then
      ran_under_valgrind=1
    else
      echo "==> valgrind could not start (exit $vg_status); running directly" >&2
      rm -rf "$smoke_home"
      smoke_home="$(mktemp -d)"
    fi
  fi
  if [[ "$ran_under_valgrind" == "0" ]]; then
    echo "==> Running smoke test ($compiler, direct)"
    "$bin" "$smoke_home"
  fi
  rm -rf "$smoke_home"
  trap - EXIT
done

# Optional cross-language consumers. These prove a non-C, non-cbindgen FFI
# caller (Zig via @cImport, Odin via hand-declared foreign bindings) drives
# the same ABI correctly — exactly the multi-language coverage the issue
# asked for. Each is skipped when its toolchain is absent.
STATIC_LIB="$TARGET_DIR/debug/libmarmot_c.a"

if command -v zig >/dev/null 2>&1; then
  echo "==> Compiling smoke.zig"
  zig_bin="$BUILD_DIR/smoke-zig"
  # -fllvm: standard ELF the loader accepts. -lunwind: the `_Unwind_*`
  # symbols the Rust staticlib needs (gcc/clang link these implicitly).
  zig build-exe "$CRATE_DIR/examples/smoke.zig" \
    -I "$CRATE_DIR/include" -lc -fllvm \
    "$STATIC_LIB" -lm -lpthread -ldl -lunwind \
    -femit-bin="$zig_bin"
  smoke_home="$(mktemp -d)"
  trap 'rm -rf "$smoke_home"' EXIT
  echo "==> Running smoke.zig"
  "$zig_bin" "$smoke_home"
  rm -rf "$smoke_home"
  trap - EXIT
else
  echo "==> Skipping Zig consumer (zig not installed)"
fi

if command -v odin >/dev/null 2>&1; then
  echo "==> Compiling smoke.odin"
  odin_bin="$BUILD_DIR/smoke-odin"
  # Odin links the shared library (complements the static-linked C/Zig
  # tests); the run needs it on the loader path.
  odin build "$CRATE_DIR/examples/smoke.odin" -file -out:"$odin_bin" \
    -extra-linker-flags:"-L$TARGET_DIR/debug -lmarmot_c -lm -lpthread -ldl"
  smoke_home="$(mktemp -d)"
  trap 'rm -rf "$smoke_home"' EXIT
  echo "==> Running smoke.odin"
  LD_LIBRARY_PATH="$TARGET_DIR/debug" "$odin_bin" "$smoke_home"
  rm -rf "$smoke_home"
  trap - EXIT
else
  echo "==> Skipping Odin consumer (odin not installed)"
fi

if command -v nim >/dev/null 2>&1; then
  echo "==> Compiling smoke.nim"
  nim_bin="$BUILD_DIR/smoke-nim"
  nim_cache="$BUILD_DIR/nimcache"
  # -Wno-incompatible-pointer-types: Nim emits `char**` for the relay array
  # where the header declares `const char *const *`; benign FFI const gap
  # that gcc 14+ otherwise errors on.
  nim c -d:release --hints:off --nimcache:"$nim_cache" \
    --passC:"-I$CRATE_DIR/include -Wno-incompatible-pointer-types" \
    --passL:"$STATIC_LIB -lm -lpthread -ldl" \
    -o:"$nim_bin" "$CRATE_DIR/examples/smoke.nim"
  smoke_home="$(mktemp -d)"
  trap 'rm -rf "$smoke_home"' EXIT
  echo "==> Running smoke.nim"
  "$nim_bin" "$smoke_home"
  rm -rf "$smoke_home"
  trap - EXIT
else
  echo "==> Skipping Nim consumer (nim not installed)"
fi

if command -v go >/dev/null 2>&1; then
  echo "==> Building smoke.go (cgo)"
  go_bin="$BUILD_DIR/smoke-go"
  # cgo LDFLAGS in the source link the static archive relative to ${SRCDIR};
  # a plain `go build` of the single file is enough.
  ( cd "$CRATE_DIR/examples" && go build -o "$go_bin" smoke.go )
  smoke_home="$(mktemp -d)"
  trap 'rm -rf "$smoke_home"' EXIT
  echo "==> Running smoke.go"
  "$go_bin" "$smoke_home"
  rm -rf "$smoke_home"
  trap - EXIT
else
  echo "==> Skipping Go consumer (go not installed)"
fi

# Lua via FFI needs LuaJIT (stock Lua has no ffi); it loads the shared lib.
if command -v luajit >/dev/null 2>&1; then
  echo "==> Running smoke.lua (LuaJIT FFI)"
  smoke_home="$(mktemp -d)"
  trap 'rm -rf "$smoke_home"' EXIT
  MARMOT_C_LIB="$TARGET_DIR/debug/libmarmot_c.so" \
    luajit "$CRATE_DIR/examples/smoke.lua" "$smoke_home"
  rm -rf "$smoke_home"
  trap - EXIT
else
  echo "==> Skipping Lua consumer (luajit not installed)"
fi

# PHP via the FFI extension; it loads the shared lib. The extension may be
# built-in but disabled by default, so enable it explicitly and only run when
# a probe confirms the FFI class is reachable.
if command -v php >/dev/null 2>&1 && \
   php -d extension=ffi -r 'exit(class_exists("FFI") ? 0 : 1);' >/dev/null 2>&1; then
  echo "==> Running smoke.php (FFI)"
  smoke_home="$(mktemp -d)"
  trap 'rm -rf "$smoke_home"' EXIT
  MARMOT_C_LIB="$TARGET_DIR/debug/libmarmot_c.so" \
    php -d extension=ffi -d ffi.enable=1 "$CRATE_DIR/examples/smoke.php" "$smoke_home"
  rm -rf "$smoke_home"
  trap - EXIT
else
  echo "==> Skipping PHP consumer (php with FFI not available)"
fi

echo "==> Smoke test passed"
