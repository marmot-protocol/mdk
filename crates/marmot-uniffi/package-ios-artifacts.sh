#!/usr/bin/env bash
# Package a built MarmotKit XCFramework as immutable release assets.

set -euo pipefail

# Match xcframework.sh: report the rustup-selected toolchain that built the
# artifact, not an unrelated Homebrew cargo/rustc earlier on PATH.
export PATH="$HOME/.cargo/bin:$PATH"

usage() {
  echo "usage: $0 <release-id> <release-tag> <source-sha> <dist-dir> <builder-sha>" >&2
  exit 2
}

[[ $# -eq 5 ]] || usage

RELEASE_ID="$1"
RELEASE_TAG="$2"
SOURCE_SHA="$3"
DIST_DIR="$4"
BUILDER_SHA="$5"

TOOL_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$TOOL_DIR/marmotkit-release-profile.env"
WORKSPACE_DIR="${MARMOTKIT_WORKSPACE_DIR:-$(cd "$TOOL_DIR/../.." && pwd)}"
CRATE_DIR="${MARMOTKIT_CRATE_DIR:-$WORKSPACE_DIR/crates/marmot-uniffi}"
OUTPUT_DIR="$CRATE_DIR/output"
XCFRAMEWORK="$OUTPUT_DIR/MarmotKit.xcframework"
SWIFT_BINDING="$OUTPUT_DIR/MarmotKit.swift"

if [[ ! "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "error: source SHA must be a full lowercase 40-character Git commit SHA" >&2
  exit 1
fi
if [[ ! "$BUILDER_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "error: builder SHA must be a full lowercase 40-character Git commit SHA" >&2
  exit 1
fi
if [[ ! -d "$XCFRAMEWORK" || ! -f "$SWIFT_BINDING" ]]; then
  echo "error: run crates/marmot-uniffi/xcframework.sh before packaging" >&2
  exit 1
fi

workspace_version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$WORKSPACE_DIR/Cargo.toml" | head -n 1)"
lock_sha="$(shasum -a 256 "$WORKSPACE_DIR/Cargo.lock" | awk '{print $1}')"
rust_version="$(rustc --version)"
cargo_version="$(cargo --version)"
deployment_target="${IPHONEOS_DEPLOYMENT_TARGET:-18.0}"
if [[ "${OTLP_EXPORT:-}" != "1" && "${OTLP_EXPORT:-}" != "true" ]]; then
  echo "error: MarmotKit release artifacts require OTLP_EXPORT=1" >&2
  exit 1
fi

binary_name="MarmotKitFFI-${RELEASE_ID}.xcframework.zip"
swift_name="MarmotKit-${RELEASE_ID}.swift"
manifest_name="marmotkit-ios-${RELEASE_ID}.manifest.json"
bundle_name="marmotkit-ios-${RELEASE_ID}.zip"
checksums_name="marmotkit-ios-${RELEASE_ID}.checksums.txt"

stage_parent="$(mktemp -d)"
trap 'rm -rf "$stage_parent"' EXIT
bundle_dir="$stage_parent/marmotkit-ios-$RELEASE_ID"

mkdir -p "$DIST_DIR" "$bundle_dir"
DIST_DIR="$(cd "$DIST_DIR" && pwd)"
rm -f \
  "$DIST_DIR/$binary_name" \
  "$DIST_DIR/$binary_name.sha256" \
  "$DIST_DIR/$binary_name.swiftpm-checksum" \
  "$DIST_DIR/$swift_name" \
  "$DIST_DIR/$manifest_name" \
  "$DIST_DIR/$bundle_name" \
  "$DIST_DIR/$bundle_name.sha256" \
  "$DIST_DIR/$checksums_name"

# A SwiftPM binary-target archive has the XCFramework at the archive root.
(
  cd "$OUTPUT_DIR"
  COPYFILE_DISABLE=1 zip -qry "$DIST_DIR/$binary_name" MarmotKit.xcframework
)

binary_sha="$(shasum -a 256 "$DIST_DIR/$binary_name" | awk '{print $1}')"
swiftpm_checksum="$(swift package compute-checksum "$DIST_DIR/$binary_name")"
swift_sha="$(shasum -a 256 "$SWIFT_BINDING" | awk '{print $1}')"
plist="$XCFRAMEWORK/Info.plist"
device_artifact=""
simulator_artifact=""
index=0
while identifier="$(/usr/libexec/PlistBuddy -c "Print :AvailableLibraries:$index:LibraryIdentifier" "$plist" 2>/dev/null)"; do
  platform="$(/usr/libexec/PlistBuddy -c "Print :AvailableLibraries:$index:SupportedPlatform" "$plist")"
  variant="$(/usr/libexec/PlistBuddy -c "Print :AvailableLibraries:$index:SupportedPlatformVariant" "$plist" 2>/dev/null || true)"
  binary_path="$(/usr/libexec/PlistBuddy -c "Print :AvailableLibraries:$index:BinaryPath" "$plist")"
  [[ "$platform" == "ios" ]] || { echo "error: unexpected XCFramework platform $platform" >&2; exit 1; }
  artifact="MarmotKit.xcframework/$identifier/$binary_path"
  if [[ "$variant" == "simulator" ]]; then
    [[ -z "$simulator_artifact" ]] || { echo "error: duplicate iOS simulator slice" >&2; exit 1; }
    simulator_artifact="$artifact"
  elif [[ -z "$variant" ]]; then
    [[ -z "$device_artifact" ]] || { echo "error: duplicate iOS device slice" >&2; exit 1; }
    device_artifact="$artifact"
  else
    echo "error: unexpected iOS platform variant $variant" >&2
    exit 1
  fi
  index=$((index + 1))
done
[[ $index -eq 2 && -n "$device_artifact" && -n "$simulator_artifact" ]] || {
  echo "error: expected exactly one iOS device slice and one simulator slice" >&2
  exit 1
}
device_library_sha="$(shasum -a 256 "$XCFRAMEWORK/${device_artifact#MarmotKit.xcframework/}" | awk '{print $1}')"
simulator_library_sha="$(shasum -a 256 "$XCFRAMEWORK/${simulator_artifact#MarmotKit.xcframework/}" | awk '{print $1}')"

cp "$SWIFT_BINDING" "$DIST_DIR/$swift_name"

cat > "$DIST_DIR/$manifest_name" <<EOF
{
  "schema_version": 1,
  "name": "marmotkit-ios",
  "release_identifier": "$RELEASE_ID",
  "release_tag": "$RELEASE_TAG",
  "source_sha": "$SOURCE_SHA",
  "builder_sha": "$BUILDER_SHA",
  "workspace_version": "$workspace_version",
  "cargo_lock_sha256": "$lock_sha",
  "rustc": "$rust_version",
  "cargo": "$cargo_version",
  "features": ["otlp-export"],
  "ios_targets": ["aarch64-apple-ios", "aarch64-apple-ios-sim"],
  "ios_deployment_target": "$deployment_target",
  "rust_release_profile": {
    "opt_level": "$CARGO_PROFILE_RELEASE_OPT_LEVEL",
    "debug": "$CARGO_PROFILE_RELEASE_DEBUG",
    "debug_assertions": false,
    "overflow_checks": false,
    "lto": $CARGO_PROFILE_RELEASE_LTO,
    "codegen_units": $CARGO_PROFILE_RELEASE_CODEGEN_UNITS,
    "panic": "$CARGO_PROFILE_RELEASE_PANIC",
    "strip": "$CARGO_PROFILE_RELEASE_STRIP"
  },
  "artifacts": {
    "$binary_name": {
      "sha256": "$binary_sha",
      "swiftpm_checksum": "$swiftpm_checksum"
    },
    "$swift_name": {
      "sha256": "$swift_sha"
    },
    "$device_artifact": {
      "sha256": "$device_library_sha",
      "architecture": "arm64"
    },
    "$simulator_artifact": {
      "sha256": "$simulator_library_sha",
      "architecture": "arm64"
    }
  },
  "contents": ["MarmotKit.xcframework", "MarmotKit.swift", "manifest.json"]
}
EOF

cp -R "$XCFRAMEWORK" "$bundle_dir/MarmotKit.xcframework"
cp "$SWIFT_BINDING" "$bundle_dir/MarmotKit.swift"
cp "$DIST_DIR/$manifest_name" "$bundle_dir/manifest.json"
(
  cd "$stage_parent"
  COPYFILE_DISABLE=1 zip -qry "$DIST_DIR/$bundle_name" "$(basename "$bundle_dir")"
)

bundle_sha="$(shasum -a 256 "$DIST_DIR/$bundle_name" | awk '{print $1}')"
manifest_sha="$(shasum -a 256 "$DIST_DIR/$manifest_name" | awk '{print $1}')"

cat > "$DIST_DIR/$checksums_name" <<EOF
sha256  $binary_sha  $binary_name
swiftpm $swiftpm_checksum  $binary_name
sha256  $swift_sha  $swift_name
sha256  $manifest_sha  $manifest_name
sha256  $bundle_sha  $bundle_name
EOF

printf '%s\n' "$binary_sha  $binary_name" > "$DIST_DIR/$binary_name.sha256"
printf '%s\n' "$swiftpm_checksum" > "$DIST_DIR/$binary_name.swiftpm-checksum"
printf '%s\n' "$bundle_sha  $bundle_name" > "$DIST_DIR/$bundle_name.sha256"

echo "Packaged immutable MarmotKit iOS assets in $DIST_DIR"
echo "  Binary artifact:  $binary_name"
echo "  SHA-256:          $binary_sha"
echo "  SwiftPM checksum: $swiftpm_checksum"
