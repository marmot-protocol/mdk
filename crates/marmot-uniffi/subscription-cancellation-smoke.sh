#!/usr/bin/env bash
# Host Swift/native cancellation integration; does not package Apple artifacts.
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ $# -gt 1 || "${1:-swift}" != swift ]]; then
  echo 'Usage: subscription-cancellation-smoke.sh [swift]' >&2
  exit 2
fi
command -v swiftc >/dev/null
cargo build -p marmot-uniffi --features cli --locked
smoke_target="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug"
case "$(uname -s)" in
  Darwin) smoke_library="$smoke_target/libmarmot_uniffi.dylib" ;;
  Linux) smoke_library="$smoke_target/libmarmot_uniffi.so" ;;
  *) echo 'Native smoke runner supports macOS and Linux' >&2; exit 2 ;;
esac
smoke_dir="$(mktemp -d)"
trap 'rm -rf "$smoke_dir"' EXIT
"$smoke_target/uniffi-bindgen" generate --library "$smoke_library" --language swift --out-dir "$smoke_dir"
cat "$smoke_dir/marmot_uniffi.swift" \
  crates/marmot-uniffi/swift-support/CancellableSubscriptions.swift \
  crates/marmot-uniffi/tests/subscription_cancellation_smoke.swift > "$smoke_dir/CombinedSmoke.swift"
swiftc -parse-as-library -I "$smoke_dir" -Xcc "-fmodule-map-file=$smoke_dir/marmot_uniffiFFI.modulemap" \
  -L "$smoke_target" -lmarmot_uniffi "$smoke_dir/CombinedSmoke.swift" -o "$smoke_dir/smoke"
# Swift launches outside Cargo, so carry over its native thread-stack contract.
RUST_MIN_STACK="${RUST_MIN_STACK:-4194304}" \
  DYLD_LIBRARY_PATH="$smoke_target" LD_LIBRARY_PATH="$smoke_target" "$smoke_dir/smoke"
