#!/usr/bin/env bash
# Validate macOS XCFramework structure, architecture, deployment target, and ZIP layout.
#
# The deployment target passed here must be the same value the artifact was
# built with. Objects compiled under MACOSX_DEPLOYMENT_TARGET report exactly
# that minimum, so validating against a lower number fails.

set -euo pipefail

usage() {
  echo "usage: $0 <xcframework-or-zip> [deployment-target]" >&2
  exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || usage

INPUT="$1"
EXPECTED_DEPLOYMENT_TARGET="${2:-15.0}"
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

index=0
while identifier="$(/usr/libexec/PlistBuddy -c "Print :AvailableLibraries:$index:LibraryIdentifier" "$PLIST" 2>/dev/null)"; do
  platform="$(/usr/libexec/PlistBuddy -c "Print :AvailableLibraries:$index:SupportedPlatform" "$PLIST")"
  variant="$(/usr/libexec/PlistBuddy -c "Print :AvailableLibraries:$index:SupportedPlatformVariant" "$PLIST" 2>/dev/null || true)"
  binary_path="$(/usr/libexec/PlistBuddy -c "Print :AvailableLibraries:$index:BinaryPath" "$PLIST")"
  library="$XCFRAMEWORK/$identifier/$binary_path"

  [[ "$platform" == "macos" ]] || { echo "error: unexpected platform $platform" >&2; exit 1; }
  [[ -z "$variant" ]] || { echo "error: unexpected macOS platform variant $variant" >&2; exit 1; }
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

  # Mach-O LC_BUILD_VERSION platform constant: PLATFORM_MACOS = 1.
  expected_platform=1
  expected_platform_name=MACOS

  # otool walks every member of a static archive, including duplicate member
  # names. Validate every object carrying LC_BUILD_VERSION instead of sampling
  # a single Rust object. An older minimum is compatible; a newer one would
  # silently raise the consuming app's deployment requirement. Rust's prebuilt
  # std objects legitimately report an older minimum than the pinned target.
  build_info="$(xcrun otool -l "$library")"
  awk -v identifier="$identifier" \
      -v expected_platform="$expected_platform" \
      -v expected_platform_name="$expected_platform_name" \
      -v expected_minos="$EXPECTED_DEPLOYMENT_TARGET" '
    function version_gt(left, right, left_parts, right_parts, count, i) {
      split(left, left_parts, ".")
      split(right, right_parts, ".")
      count = 3
      for (i = 1; i <= count; i++) {
        if ((left_parts[i] + 0) > (right_parts[i] + 0)) return 1
        if ((left_parts[i] + 0) < (right_parts[i] + 0)) return 0
      }
      return 0
    }
    /^Archive : / { member = $0 }
    /^.*\([^)]*\):$/ { member = $0 }
    /^[[:space:]]*cmd LC_BUILD_VERSION$/ {
      in_build_version = 1
      platform_seen = 0
      minos_seen = 0
      count++
      next
    }
    in_build_version && /^[[:space:]]*platform / {
      platform_seen = 1
      if (($2 + 0) != expected_platform) {
        printf "error: %s member %s uses platform %s, expected %s (%s)\n", \
          identifier, member, $2, expected_platform, expected_platform_name > "/dev/stderr"
        failed = 1
      }
      next
    }
    in_build_version && /^[[:space:]]*minos / {
      minos_seen = 1
      if (version_gt($2, expected_minos)) {
        printf "error: %s member %s requires macOS %s, newer than supported %s\n", \
          identifier, member, $2, expected_minos > "/dev/stderr"
        failed = 1
      }
      in_build_version = 0
      next
    }
    END {
      if (count == 0) {
        printf "error: %s contains no LC_BUILD_VERSION commands\n", identifier > "/dev/stderr"
        failed = 1
      }
      if (in_build_version && (!platform_seen || !minos_seen)) {
        printf "error: incomplete LC_BUILD_VERSION in %s member %s\n", identifier, member > "/dev/stderr"
        failed = 1
      }
      exit failed
    }
  ' <<< "$build_info"
  index=$((index + 1))
done

[[ $index -eq 1 ]] || {
  echo "error: expected exactly one arm64 macOS slice" >&2
  exit 1
}

echo "Validated every arm64 macOS archive member supports deployment target $EXPECTED_DEPLOYMENT_TARGET"
