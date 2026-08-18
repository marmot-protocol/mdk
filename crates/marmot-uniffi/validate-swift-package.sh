#!/usr/bin/env bash
# Build a minimal SwiftPM consumer against a local or remote MarmotKit binary target.

set -euo pipefail

usage() {
  echo "usage: $0 <xcframework-path-or-https-url> <checksum-or-dash> <MarmotKit.swift> [work-dir]" >&2
  exit 2
}

[[ $# -ge 3 && $# -le 4 ]] || usage

ARTIFACT="$1"
CHECKSUM="$2"
SWIFT_BINDING="$3"
if [[ $# -eq 4 ]]; then
  WORK_DIR="$4"
  if [[ -e "$WORK_DIR" ]]; then
    echo "error: validation work directory already exists: $WORK_DIR" >&2
    exit 1
  fi
else
  WORK_DIR="$(mktemp -d)"
  trap 'rm -rf "$WORK_DIR"' EXIT
fi

[[ -f "$SWIFT_BINDING" ]] || { echo "error: missing Swift binding $SWIFT_BINDING" >&2; exit 1; }
mkdir -p "$WORK_DIR/Sources/MarmotKit" "$WORK_DIR/Sources/MarmotKitConsumer"
cp "$SWIFT_BINDING" "$WORK_DIR/Sources/MarmotKit/MarmotKit.swift"

if [[ "$ARTIFACT" == https://* ]]; then
  [[ "$CHECKSUM" =~ ^[0-9a-f]{64}$ ]] || { echo "error: remote artifact requires a SwiftPM checksum" >&2; exit 1; }
  binary_declaration=".binaryTarget(name: \"MarmotKitFFI\", url: \"$ARTIFACT\", checksum: \"$CHECKSUM\")"
else
  [[ -d "$ARTIFACT" ]] || { echo "error: missing local XCFramework $ARTIFACT" >&2; exit 1; }
  cp -R "$ARTIFACT" "$WORK_DIR/MarmotKit.xcframework"
  binary_declaration='.binaryTarget(name: "MarmotKitFFI", path: "MarmotKit.xcframework")'
fi

cat > "$WORK_DIR/Package.swift" <<EOF
// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "MarmotKitConsumerValidation",
    platforms: [.iOS(.v18)],
    products: [
        .library(name: "MarmotKit", targets: ["MarmotKit"]),
        .library(name: "MarmotKitConsumer", type: .dynamic, targets: ["MarmotKitConsumer"]),
    ],
    targets: [
        $binary_declaration,
        .target(name: "MarmotKit", dependencies: ["MarmotKitFFI"]),
        .target(name: "MarmotKitConsumer", dependencies: ["MarmotKit"]),
    ]
)
EOF

cat > "$WORK_DIR/Sources/MarmotKitConsumer/Consumer.swift" <<'EOF'
import MarmotKit

// Referencing the generated public object proves the source and binary headers
// are the matching UniFFI surface. The dynamic product forces a final link.
public func acceptMarmotForLinkValidation(_ marmot: Marmot) {}

// Compile the combined conversation-loading API, both result projections, and
// the typed MarmotKit error path so generated Swift cannot silently drift from
// the Rust record or async method shape (mdk#1490).
public func loadConversationSnapshot(
    _ marmot: Marmot,
    accountRef: String,
    groupIdHex: String
) async throws -> GroupConversationSnapshotFfi {
    do {
        let snapshot = try await marmot.groupConversationSnapshot(
            accountRef: accountRef,
            groupIdHex: groupIdHex
        )
        _ = snapshot.details.group.groupIdHex
        _ = snapshot.details.members
        _ = snapshot.details.mlsState.epoch
        _ = snapshot.managementState.myAccountIdHex
        _ = snapshot.managementState.memberActions
        return snapshot
    } catch let error as MarmotKitError {
        throw error
    }
}
EOF

(
  cd "$WORK_DIR"
  swift package describe >/dev/null
  # `swift package resolve` performs the remote download and checksum
  # verification. Xcode then consumes that resolved artifact for iOS builds.
  swift package resolve
  xcodebuild \
    -scheme MarmotKitConsumer \
    -configuration Release \
    -destination 'generic/platform=iOS Simulator' \
    -derivedDataPath "$WORK_DIR/DerivedData-simulator" \
    -disableAutomaticPackageResolution \
    ARCHS=arm64 \
    ONLY_ACTIVE_ARCH=YES \
    CODE_SIGNING_ALLOWED=NO \
    -quiet \
    build
  xcodebuild \
    -scheme MarmotKitConsumer \
    -configuration Release \
    -destination 'generic/platform=iOS' \
    -derivedDataPath "$WORK_DIR/DerivedData-device" \
    -disableAutomaticPackageResolution \
    ARCHS=arm64 \
    ONLY_ACTIVE_ARCH=YES \
    CODE_SIGNING_ALLOWED=NO \
    -quiet \
    build
)

echo "Validated SwiftPM MarmotKit source compilation and simulator/device linking"
