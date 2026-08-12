#!/usr/bin/env bash
# Build the MarmotKit.xcframework for macOS (Apple Silicon).
#
# Outputs:
#   <crate>/output/macos/MarmotKit.xcframework
#   <crate>/output/macos/MarmotKit.swift   (generated Swift bindings, separate from the xcframework)
#
# Targets:
#   aarch64-apple-darwin    (macOS, arm64)
#
# Add x86_64-apple-darwin + lipo if/when an Intel Mac is on the test matrix.
#
# The output directory is deliberately distinct from xcframework.sh's so that
# building both in one workspace cannot clobber the iOS artifact.

set -euo pipefail

# Force rustup's cargo to win over any Homebrew-installed cargo, so that
# rust-toolchain.toml is honored and Apple targets are visible.
export PATH="$HOME/.cargo/bin:$PATH"

# Pin the macOS deployment target so the bundled OpenSSL (via rusqlite's
# SQLCipher feature) is built and linked against the same macOS version.
# Without this, the build defaults to a very old macOS minimum and the link
# step fails with missing __chkstk_darwin and friends.
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}"
export CFLAGS_aarch64_apple_darwin="${CFLAGS_aarch64_apple_darwin:--mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET}}"
export CXXFLAGS_aarch64_apple_darwin="${CXXFLAGS_aarch64_apple_darwin:--mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET}}"
# Target-scoped rather than RUSTFLAGS on purpose. Cargo treats a RUSTFLAGS env
# var as replacing `[build] rustflags` from .cargo/config.toml rather than
# merging with it, so a workspace-wide flag added later would be silently
# dropped for this build alone. Scoping also keeps the flag off the host dylib
# build below, whose target/release fingerprint is shared with xcframework.sh.
export CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS="-C link-arg=-mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET}"

TOOL_DIR="$(cd "$(dirname "$0")" && pwd)"
# Keep production release behavior and debug-symbol policy in one source of truth.
source "$TOOL_DIR/marmotkit-release-profile.env"
WORKSPACE_DIR="${MARMOTKIT_WORKSPACE_DIR:-$(cd "$TOOL_DIR/../.." && pwd)}"
CRATE_DIR="${MARMOTKIT_CRATE_DIR:-$WORKSPACE_DIR/crates/marmot-uniffi}"
TARGET_DIR="$WORKSPACE_DIR/target"
BUILD_DIR="$CRATE_DIR/build/macos"
OUT_DIR="$CRATE_DIR/output/macos"

# Set public first-party endpoint defaults for values compiled via option_env!.
# Tokens remain host-app runtime configuration.
source "$TOOL_DIR/marmotkit-endpoints.env"

CRATE_NAME="marmot-uniffi"
LIB_BASENAME="marmot_uniffi"
FRAMEWORK_NAME="MarmotKit"
MACOS_TARGET="aarch64-apple-darwin"

FEATURE_ARGS=()
BINDGEN_FEATURES="cli"
if [[ "${OTLP_EXPORT:-0}" == "1" || "${OTLP_EXPORT:-}" == "true" ]]; then
  FEATURE_ARGS=(--features otlp-export)
  BINDGEN_FEATURES="cli,otlp-export"
fi

# Run from the workspace root so cargo resolves the right Cargo.toml no
# matter where this script was invoked from (e.g. the macOS repo's
# sync-bindings.sh).
cd "$WORKSPACE_DIR"

echo "==> Cleaning previous build artifacts"
rm -rf "$BUILD_DIR" "$OUT_DIR/$FRAMEWORK_NAME.xcframework" "$OUT_DIR/$FRAMEWORK_NAME.swift"
mkdir -p "$BUILD_DIR/headers" "$OUT_DIR"

echo "==> Ensuring $MACOS_TARGET is installed"
rustup target add "$MACOS_TARGET"

echo "==> Building host dylib (used for binding generation)"
cargo build --release -p "$CRATE_NAME" ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}

# On an Apple Silicon host this is nominally the same triple as the host build,
# but passing --target keeps it in its own target dir and makes the
# deployment-target flags apply, so keep it explicit.
echo "==> Building macOS target ($MACOS_TARGET)"
cargo build --release -p "$CRATE_NAME" --target "$MACOS_TARGET" ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}

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

# The static library is packaged exactly as cargo produced it, matching
# xcframework.sh. Do not strip it here: marmotkit-release-profile.env pins
# strip=none and debug=0, and package-macos-artifacts.sh publishes that profile
# as provenance, so a post-link strip would make the manifest describe an
# artifact that is not the one shipped.
echo "==> Creating $FRAMEWORK_NAME.xcframework"
xcodebuild -create-xcframework \
  -library "$TARGET_DIR/$MACOS_TARGET/release/lib${LIB_BASENAME}.a" \
  -headers "$BUILD_DIR/headers" \
  -output "$OUT_DIR/$FRAMEWORK_NAME.xcframework"

echo "==> Copying generated Swift binding to output dir"
cp "$BUILD_DIR/swift/${LIB_BASENAME}.swift" "$OUT_DIR/${FRAMEWORK_NAME}.swift"

echo ""
echo "Done."
echo "  XCFramework:       $OUT_DIR/$FRAMEWORK_NAME.xcframework"
echo "  Swift binding:     $OUT_DIR/$FRAMEWORK_NAME.swift"
echo "  Deployment target: $MACOSX_DEPLOYMENT_TARGET"
