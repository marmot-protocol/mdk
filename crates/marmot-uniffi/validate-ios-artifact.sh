#!/usr/bin/env bash
# Validate XCFramework structure, architecture, deployment target, and ZIP layout.

set -euo pipefail

usage() {
  echo "usage: $0 <xcframework-or-zip> [deployment-target]" >&2
  exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || usage

INPUT="$1"
EXPECTED_DEPLOYMENT_TARGET="${2:-18.0}"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

if [[ -f "$INPUT" ]]; then
  case "$INPUT" in
    *.zip)
      root_entries="$(unzip -Z1 "$INPUT" | awk -F/ 'NF {print $1}' | sort -u)"
      if [[ "$root_entries" != "MarmotKit.xcframework" ]]; then
        echo "error: SwiftPM ZIP must contain only MarmotKit.xcframework at its root" >&2
        printf 'found root entries:\n%s\n' "$root_entries" >&2
        exit 1
      fi
      unzip -q "$INPUT" -d "$TEMP_DIR/archive"
      XCFRAMEWORK="$TEMP_DIR/archive/MarmotKit.xcframework"
      ;;
    *)
      usage
      ;;
  esac
elif [[ -d "$INPUT" ]]; then
  XCFRAMEWORK="$INPUT"
else
  echo "error: artifact does not exist: $INPUT" >&2
  exit 1
fi

XCFRAMEWORK="$(cd "$(dirname "$XCFRAMEWORK")" && pwd)/$(basename "$XCFRAMEWORK")"

PLIST="$XCFRAMEWORK/Info.plist"
[[ -f "$PLIST" ]] || { echo "error: missing XCFramework Info.plist" >&2; exit 1; }

found_device=0
found_simulator=0
index=0
while identifier="$(/usr/libexec/PlistBuddy -c "Print :AvailableLibraries:$index:LibraryIdentifier" "$PLIST" 2>/dev/null)"; do
  platform="$(/usr/libexec/PlistBuddy -c "Print :AvailableLibraries:$index:SupportedPlatform" "$PLIST")"
  variant="$(/usr/libexec/PlistBuddy -c "Print :AvailableLibraries:$index:SupportedPlatformVariant" "$PLIST" 2>/dev/null || true)"
  binary_path="$(/usr/libexec/PlistBuddy -c "Print :AvailableLibraries:$index:BinaryPath" "$PLIST")"
  library="$XCFRAMEWORK/$identifier/$binary_path"

  [[ "$platform" == "ios" ]] || { echo "error: unexpected platform $platform" >&2; exit 1; }
  [[ -f "$library" ]] || { echo "error: missing library $library" >&2; exit 1; }
  [[ "$(lipo -archs "$library")" == "arm64" ]] || {
    echo "error: $identifier is not an arm64-only library" >&2
    exit 1
  }

  headers_path="$(/usr/libexec/PlistBuddy -c "Print :AvailableLibraries:$index:HeadersPath" "$PLIST")"
  [[ -f "$XCFRAMEWORK/$identifier/$headers_path/module.modulemap" ]] || {
    echo "error: missing module map for $identifier" >&2
    exit 1
  }
  [[ -f "$XCFRAMEWORK/$identifier/$headers_path/marmot_uniffiFFI.h" ]] || {
    echo "error: missing generated header for $identifier" >&2
    exit 1
  }

  object_dir="$TEMP_DIR/objects-$index"
  mkdir -p "$object_dir"
  (
    cd "$object_dir"
    xcrun ar -x "$library"
  )
  primary_object="$(find "$object_dir" -type f -name 'marmot_uniffi.marmot_uniffi*.o' -print -quit)"
  [[ -n "$primary_object" ]] || { echo "error: no MarmotKit Rust object in $identifier" >&2; exit 1; }
  build_info="$(xcrun vtool -show-build "$primary_object")"
  grep -Eq "minos[[:space:]]+$EXPECTED_DEPLOYMENT_TARGET$" <<< "$build_info" || {
    echo "error: $identifier does not use iOS deployment target $EXPECTED_DEPLOYMENT_TARGET" >&2
    echo "$build_info" >&2
    exit 1
  }

  if [[ "$variant" == "simulator" ]]; then
    grep -Eq 'platform[[:space:]]+IOSSIMULATOR$' <<< "$build_info" || {
      echo "error: $identifier is not an iOS simulator library" >&2
      exit 1
    }
    found_simulator=1
  elif [[ -z "$variant" ]]; then
    grep -Eq 'platform[[:space:]]+IOS$' <<< "$build_info" || {
      echo "error: $identifier is not an iOS device library" >&2
      exit 1
    }
    found_device=1
  else
    echo "error: unexpected iOS platform variant $variant" >&2
    exit 1
  fi
  index=$((index + 1))
done

[[ $index -eq 2 && $found_device -eq 1 && $found_simulator -eq 1 ]] || {
  echo "error: expected exactly one arm64 iOS device slice and one arm64 simulator slice" >&2
  exit 1
}

echo "Validated arm64 iOS device and simulator XCFramework slices at deployment target $EXPECTED_DEPLOYMENT_TARGET"
