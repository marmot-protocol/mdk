#!/usr/bin/env bash
# Build marmot-c and run the C smoke example against both linkage models:
# the shared object and the static archive, for each compiler given as an
# argument (default: cc). Runs the shared build under valgrind when
# available. Usage: c-smoke.sh [cc...]

set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"

CRATE_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_DIR="$(cd "$CRATE_DIR/../.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$WORKSPACE_DIR/target}"
COMPILERS=("$@")
[ ${#COMPILERS[@]} -gt 0 ] || COMPILERS=(cc)

cd "$WORKSPACE_DIR"

echo "==> Building marmot-c (release)"
cargo build --release -p marmot-c

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

CFLAGS=(-std=c11 -Wall -Wextra -Werror -I"$CRATE_DIR/include")

# Darwin has no libdl (dlopen lives in libSystem) and looks up shared
# libraries through DYLD_LIBRARY_PATH.
case "$(uname -s)" in
  Darwin)
    STATIC_LIBS=(-lm -pthread -framework Security -framework CoreFoundation -liconv)
    LIB_PATH_VAR="DYLD_LIBRARY_PATH"
    ;;
  *) STATIC_LIBS=(-lm -pthread -ldl); LIB_PATH_VAR="LD_LIBRARY_PATH" ;;
esac

run() {
    local bin="$1"; shift
    local home
    home="$(mktemp -d "$WORK/home.XXXXXX")"
    env "$LIB_PATH_VAR=$TARGET_DIR/release" "$@" "$bin" "$home"
    rm -rf "$home"
}

for cc in "${COMPILERS[@]}"; do
    echo "==> [$cc] Compiling smoke.c against the shared object"
    "$cc" "${CFLAGS[@]}" "$CRATE_DIR/examples/smoke.c" \
        -L"$TARGET_DIR/release" -lmarmot_c -o "$WORK/smoke-shared-$cc"

    echo "==> [$cc] Compiling smoke.c against the static archive"
    "$cc" "${CFLAGS[@]}" "$CRATE_DIR/examples/smoke.c" \
        "$TARGET_DIR/release/libmarmot_c.a" "${STATIC_LIBS[@]}" -o "$WORK/smoke-static-$cc"

    echo "==> [$cc] Running smoke (shared)"
    run "$WORK/smoke-shared-$cc"

    echo "==> [$cc] Running smoke (static)"
    run "$WORK/smoke-static-$cc"

    if command -v valgrind >/dev/null 2>&1; then
        echo "==> [$cc] Running smoke (shared, valgrind)"
        run "$WORK/smoke-shared-$cc" valgrind --error-exitcode=1 --leak-check=full \
            --errors-for-leak-kinds=definite
    else
        echo "==> valgrind not found; skipping leak run"
    fi
done

echo "==> c-smoke: all passed"
