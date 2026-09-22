#!/usr/bin/env bash
# Build the MarmotKit.xcframework for iOS device + simulator.
#
# Outputs:
#   <crate>/output/MarmotKit.xcframework
#   <crate>/output/MarmotKit.swift   (generated Swift bindings, separate from the xcframework)
#   <crate>/output/PrivacyInfo.xcprivacy (feature-selected SDK declaration)
#
# Targets:
#   aarch64-apple-ios       (device, arm64)
#   aarch64-apple-ios-sim   (simulator on Apple Silicon)
#
# Add x86_64-apple-ios + lipo if/when an Intel Mac is on the test matrix.

set -euo pipefail

# Split phases let CI build native slices independently; no arguments retains
# the complete local build used by downstream synchronization scripts.
MODE="${1:-all}"
case "$MODE" in
  all|generate|assemble) [[ $# -le 1 ]] || { echo "usage: $0 [all|generate|assemble|native <aarch64-apple-ios|aarch64-apple-ios-sim>]" >&2; exit 2; } ;;
  native)
    [[ $# -eq 2 ]] || { echo "native requires one iOS target" >&2; exit 2; }
    case "$2" in
      aarch64-apple-ios|aarch64-apple-ios-sim) ;;
      *) echo "unsupported iOS target: $2" >&2; exit 2 ;;
    esac
    ;;
  *) echo "usage: $0 [all|generate|assemble|native <aarch64-apple-ios|aarch64-apple-ios-sim>]" >&2; exit 2 ;;
esac

# Force rustup's cargo to win over any Homebrew-installed cargo, so that
# rust-toolchain.toml is honored and iOS targets are visible.
export PATH="$HOME/.cargo/bin:$PATH"

# Pin the iOS deployment target so the bundled OpenSSL (via rusqlite's
# SQLCipher feature) is built and linked against the same iOS version.
# Without this, the build defaults to a very old iOS minimum and the link
# step fails with missing __chkstk_darwin and friends.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-18.0}"
# Target-scoped rather than RUSTFLAGS: Cargo replaces [build] rustflags when
# RUSTFLAGS is set. Apple rustc defaults to embed-bitcode=yes; that leaves
# __LLVM,__bitcode in static archive members (including compiler_builtins)
# and nearly doubled thin-LTO archive bytes on the exact-head measurement.
export CARGO_TARGET_AARCH64_APPLE_IOS_RUSTFLAGS="${CARGO_TARGET_AARCH64_APPLE_IOS_RUSTFLAGS:+$CARGO_TARGET_AARCH64_APPLE_IOS_RUSTFLAGS }-C embed-bitcode=no"
export CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUSTFLAGS="${CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUSTFLAGS:+$CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUSTFLAGS }-C embed-bitcode=no"

TOOL_DIR="$(cd "$(dirname "$0")" && pwd)"
# Keep production release behavior and debug-symbol policy in one source of truth.
source "$TOOL_DIR/marmotkit-release-profile.env"
WORKSPACE_DIR="${MARMOTKIT_WORKSPACE_DIR:-$(cd "$TOOL_DIR/../.." && pwd)}"
CRATE_DIR="${MARMOTKIT_CRATE_DIR:-$WORKSPACE_DIR/crates/marmot-uniffi}"
TARGET_DIR="${CARGO_TARGET_DIR:-$WORKSPACE_DIR/target}"
if [[ "$TARGET_DIR" != /* ]]; then
  TARGET_DIR="$WORKSPACE_DIR/$TARGET_DIR"
fi
# Scoped to build/ios, not build/, so cleaning this script's scratch space
# cannot take xcframework-macos.sh's build/macos with it.
BUILD_DIR="$CRATE_DIR/build/ios"
OUT_DIR="$CRATE_DIR/output"

# Set public first-party endpoint defaults for values compiled via option_env!.
# Tokens remain host-app runtime configuration.
source "$TOOL_DIR/marmotkit-endpoints.env"

CRATE_NAME="marmot-uniffi"
LIB_BASENAME="marmot_uniffi"
FRAMEWORK_NAME="MarmotKit"

FEATURE_ARGS=()
BINDGEN_FEATURES="cli"
if [[ "${OTLP_EXPORT:-0}" == "1" || "${OTLP_EXPORT:-}" == "true" ]]; then
  FEATURE_ARGS=(--features otlp-export)
  BINDGEN_FEATURES="cli,otlp-export"
fi
if [[ "${PRODUCT_ANALYTICS_EXPORT:-0}" == "1" || "${PRODUCT_ANALYTICS_EXPORT:-}" == "true" ]]; then
  FEATURE_ARGS+=(--features product-analytics-export)
  BINDGEN_FEATURES="${BINDGEN_FEATURES},product-analytics-export"
fi


# Run from the workspace root so cargo resolves the right Cargo.toml no
# matter where this script was invoked from (e.g. the iOS repo's
# sync-bindings.sh).
cd "$WORKSPACE_DIR"

if [[ "$MODE" == native ]]; then
  rustup target add "$2"
  cargo build --locked --release --timings -p "$CRATE_NAME" --target "$2" ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}
  exit 0
fi

if [[ "$MODE" == generate ]]; then
  rm -rf "$BUILD_DIR/swift"
  mkdir -p "$BUILD_DIR/swift"
  echo "==> Building host dylib (used for binding generation)"
  cargo build --locked --release --timings -p "$CRATE_NAME" ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}

  echo "==> Generating Swift bindings"
  cargo run --locked --release --timings -p "$CRATE_NAME" --features "$BINDGEN_FEATURES" --bin uniffi-bindgen -- \
    generate \
    --library "$TARGET_DIR/release/lib${LIB_BASENAME}.dylib" \
    --language swift \
    --out-dir "$BUILD_DIR/swift"

  exit 0
fi

if [[ "$MODE" == all ]]; then
  echo "==> Cleaning previous build artifacts"
  rm -rf "$BUILD_DIR"
  mkdir -p "$BUILD_DIR"
  echo "==> Ensuring iOS targets are installed"
  rustup target add aarch64-apple-ios aarch64-apple-ios-sim

  echo "==> Building host dylib (used for binding generation)"
  cargo build --locked --release --timings -p "$CRATE_NAME" ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}

  echo "==> Building iOS device target (aarch64-apple-ios)"
  cargo build --locked --release --timings -p "$CRATE_NAME" --target aarch64-apple-ios ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}

  echo "==> Building iOS simulator target (aarch64-apple-ios-sim)"
  cargo build --locked --release --timings -p "$CRATE_NAME" --target aarch64-apple-ios-sim ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}

  echo "==> Generating Swift bindings"
  cargo run --locked --release --timings -p "$CRATE_NAME" --features "$BINDGEN_FEATURES" --bin uniffi-bindgen -- \
    generate \
    --library "$TARGET_DIR/release/lib${LIB_BASENAME}.dylib" \
    --language swift \
    --out-dir "$BUILD_DIR/swift"

fi

# Assembly only consumes existing slices and generated bindings. In particular,
# never delete build/*/swift downloaded from the generation job.
for input in "$BUILD_DIR/swift/${LIB_BASENAME}.swift" \
  "$BUILD_DIR/swift/${LIB_BASENAME}FFI.h" \
  "$BUILD_DIR/swift/${LIB_BASENAME}FFI.modulemap" \
  "$TARGET_DIR/aarch64-apple-ios/release/lib${LIB_BASENAME}.a" \
  "$TARGET_DIR/aarch64-apple-ios-sim/release/lib${LIB_BASENAME}.a"; do
  [[ -s "$input" ]] || { echo "error: missing assembly input: $input" >&2; exit 1; }
done
rm -rf "$BUILD_DIR/headers" "$OUT_DIR/$FRAMEWORK_NAME.xcframework" "$OUT_DIR/$FRAMEWORK_NAME.swift" "$OUT_DIR/PrivacyInfo.xcprivacy"
mkdir -p "$BUILD_DIR/headers" "$OUT_DIR"

echo "==> Staging headers + modulemap for XCFramework"
cp "$BUILD_DIR/swift/${LIB_BASENAME}FFI.h" "$BUILD_DIR/headers/"
# XCFramework expects the modulemap to be named module.modulemap
cp "$BUILD_DIR/swift/${LIB_BASENAME}FFI.modulemap" "$BUILD_DIR/headers/module.modulemap"

echo "==> Removing leftover Apple bitcode sections from cargo archives"
# Not a symbol strip: strip=none/debug=0 stay in the published profile.
# Walk every member, including compiler_builtins; do not skip names.
python3 "$TOOL_DIR/release-profile-archive.py" --sanitize \
  "$TARGET_DIR/aarch64-apple-ios/release/lib${LIB_BASENAME}.a"
python3 "$TOOL_DIR/release-profile-archive.py" --sanitize \
  "$TARGET_DIR/aarch64-apple-ios-sim/release/lib${LIB_BASENAME}.a"

echo "==> Creating $FRAMEWORK_NAME.xcframework"
xcodebuild -create-xcframework \
  -library "$TARGET_DIR/aarch64-apple-ios/release/lib${LIB_BASENAME}.a" -headers "$BUILD_DIR/headers" \
  -library "$TARGET_DIR/aarch64-apple-ios-sim/release/lib${LIB_BASENAME}.a" -headers "$BUILD_DIR/headers" \
  -output "$OUT_DIR/$FRAMEWORK_NAME.xcframework"
python3 "$TOOL_DIR/apple-privacy.py" "$OUT_DIR/PrivacyInfo.xcprivacy" \
  --privacy-dir "$CRATE_DIR/apple-privacy" --product-analytics "${PRODUCT_ANALYTICS_EXPORT:-0}"

echo "==> Copying generated Swift binding to output dir"
cp "$BUILD_DIR/swift/${LIB_BASENAME}.swift" "$OUT_DIR/${FRAMEWORK_NAME}.swift"

echo ""
echo "Done."
echo "  SDK privacy:    $OUT_DIR/PrivacyInfo.xcprivacy"
echo "  XCFramework:    $OUT_DIR/$FRAMEWORK_NAME.xcframework"
echo "  Swift binding:  $OUT_DIR/$FRAMEWORK_NAME.swift"
