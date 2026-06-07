#!/usr/bin/env bash
# Build the MarmotKit.xcframework for iOS device + simulator.
#
# Outputs:
#   <crate>/output/MarmotKit.xcframework
#   <crate>/output/MarmotKit.swift   (generated Swift bindings, separate from the xcframework)
#
# Targets:
#   aarch64-apple-ios       (device, arm64)
#   aarch64-apple-ios-sim   (simulator on Apple Silicon)
#
# Add x86_64-apple-ios + lipo if/when an Intel Mac is on the test matrix.

set -euo pipefail

# Force rustup's cargo to win over any Homebrew-installed cargo, so that
# rust-toolchain.toml is honored and iOS targets are visible.
export PATH="$HOME/.cargo/bin:$PATH"

# Pin the iOS deployment target so the bundled OpenSSL (via rusqlite's
# SQLCipher feature) is built and linked against the same iOS version.
# Without this, the build defaults to a very old iOS minimum and the link
# step fails with missing __chkstk_darwin and friends.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-18.0}"

CRATE_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_DIR="$(cd "$CRATE_DIR/../.." && pwd)"
TARGET_DIR="$WORKSPACE_DIR/target"
BUILD_DIR="$CRATE_DIR/build"
OUT_DIR="$CRATE_DIR/output"

CRATE_NAME="marmot-uniffi"
LIB_BASENAME="marmot_uniffi"
FRAMEWORK_NAME="MarmotKit"

FEATURE_ARGS=()
BINDGEN_FEATURES="cli"
if [[ "${OTLP_EXPORT:-0}" == "1" || "${OTLP_EXPORT:-}" == "true" ]]; then
  FEATURE_ARGS=(--features otlp-export)
  BINDGEN_FEATURES="cli,otlp-export"
fi

# Run from the workspace root so cargo resolves the right Cargo.toml no
# matter where this script was invoked from (e.g. the iOS repo's
# sync-bindings.sh).
cd "$WORKSPACE_DIR"

echo "==> Cleaning previous build artifacts"
rm -rf "$BUILD_DIR" "$OUT_DIR/$FRAMEWORK_NAME.xcframework" "$OUT_DIR/$FRAMEWORK_NAME.swift"
mkdir -p "$BUILD_DIR/headers" "$OUT_DIR"

echo "==> Building host dylib (used for binding generation)"
cargo build --release -p "$CRATE_NAME" "${FEATURE_ARGS[@]}"

echo "==> Building iOS device target (aarch64-apple-ios)"
cargo build --release -p "$CRATE_NAME" --target aarch64-apple-ios "${FEATURE_ARGS[@]}"

echo "==> Building iOS simulator target (aarch64-apple-ios-sim)"
cargo build --release -p "$CRATE_NAME" --target aarch64-apple-ios-sim "${FEATURE_ARGS[@]}"

echo "==> Generating Swift bindings"
cargo run --release -p "$CRATE_NAME" --features "$BINDGEN_FEATURES" --bin uniffi-bindgen -- \
  generate \
  --library "$TARGET_DIR/release/lib${LIB_BASENAME}.dylib" \
  --language swift \
  --out-dir "$BUILD_DIR/swift"

echo "==> Staging headers + modulemap for XCFramework"
cp "$BUILD_DIR/swift/${LIB_BASENAME}FFI.h" "$BUILD_DIR/headers/"
# XCFramework expects the modulemap to be named module.modulemap
cp "$BUILD_DIR/swift/${LIB_BASENAME}FFI.modulemap" "$BUILD_DIR/headers/module.modulemap"

echo "==> Creating $FRAMEWORK_NAME.xcframework"
xcodebuild -create-xcframework \
  -library "$TARGET_DIR/aarch64-apple-ios/release/lib${LIB_BASENAME}.a" \
  -headers "$BUILD_DIR/headers" \
  -library "$TARGET_DIR/aarch64-apple-ios-sim/release/lib${LIB_BASENAME}.a" \
  -headers "$BUILD_DIR/headers" \
  -output "$OUT_DIR/$FRAMEWORK_NAME.xcframework"

echo "==> Copying generated Swift binding to output dir"
cp "$BUILD_DIR/swift/${LIB_BASENAME}.swift" "$OUT_DIR/${FRAMEWORK_NAME}.swift"

echo ""
echo "Done."
echo "  XCFramework:    $OUT_DIR/$FRAMEWORK_NAME.xcframework"
echo "  Swift binding:  $OUT_DIR/$FRAMEWORK_NAME.swift"
