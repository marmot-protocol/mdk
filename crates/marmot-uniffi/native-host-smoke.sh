#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

if [[ $# -ne 0 ]]; then
  echo 'Usage: bash crates/marmot-uniffi/native-host-smoke.sh' >&2
  exit 2
fi
for tool in cargo python3 swift swiftc; do
  if ! command -v "$tool" >/dev/null; then
    echo "error: native-host smoke requires $tool on PATH (install Rust, Python 3 and the Swift toolchain)" >&2
    exit 2
  fi
done
case "$(uname -s)" in
  Darwin) library_name=libmarmot_uniffi.dylib ;;
  Linux) library_name=libmarmot_uniffi.so ;;
  *) echo 'error: native-host smoke supports macOS and Linux only' >&2; exit 2 ;;
esac

cargo build -p marmot-uniffi --features cli --locked --lib --bin uniffi-bindgen --example native-host-relay
smoke_target="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug"
smoke_library="$smoke_target/$library_name"
smoke_dir="$(mktemp -d)"
runner_pid=
cleanup() {
  if [[ -n "$runner_pid" ]]; then
    kill -TERM "$runner_pid" 2>/dev/null || true
    wait "$runner_pid" 2>/dev/null || true
  fi
  rm -rf "$smoke_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

mkdir -p "$smoke_dir/generated" "$smoke_dir/Sources/MarmotKit" \
  "$smoke_dir/Sources/marmot_uniffiFFI" "$smoke_dir/Tests/MarmotKitTests"
"$smoke_target/uniffi-bindgen" generate --library "$smoke_library" --language swift --out-dir "$smoke_dir/generated"
cp "$smoke_dir/generated/marmot_uniffi.swift" "$smoke_dir/Sources/MarmotKit/"
cp "$smoke_dir/generated/marmot_uniffiFFI.h" "$smoke_dir/Sources/marmot_uniffiFFI/"
cp "$smoke_dir/generated/marmot_uniffiFFI.modulemap" "$smoke_dir/Sources/marmot_uniffiFFI/module.modulemap"
cp crates/marmot-uniffi/tests/native_host_smoke.swift "$smoke_dir/Tests/MarmotKitTests/"
cat > "$smoke_dir/Package.swift" <<'EOF'
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MarmotKitNativeHostSmoke",
    platforms: [.macOS(.v13)],
    products: [.library(name: "MarmotKit", targets: ["MarmotKit"])],
    targets: [
        .systemLibrary(name: "marmot_uniffiFFI"),
        .target(name: "MarmotKit", dependencies: ["marmot_uniffiFFI"]),
        .testTarget(name: "MarmotKitTests", dependencies: ["MarmotKit"]),
    ],
    swiftLanguageVersions: [.v5]
)
EOF

RUST_MIN_STACK="${RUST_MIN_STACK:-4194304}" \
  TMPDIR="$smoke_dir" \
  DYLD_LIBRARY_PATH="$smoke_target${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
  LD_LIBRARY_PATH="$smoke_target${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  "$smoke_target/examples/native-host-relay" \
  swift test --package-path "$smoke_dir" \
  -Xlinker -L -Xlinker "$smoke_target" -Xlinker -lmarmot_uniffi \
  -Xlinker -rpath -Xlinker "$smoke_target" &
runner_pid=$!
status=0
wait "$runner_pid" || status=$?
runner_pid=
exit "$status"
