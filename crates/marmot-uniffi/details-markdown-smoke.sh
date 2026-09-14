#!/usr/bin/env bash
# Native Details DTO lift/lower round trips. This does not package Apple/Android artifacts.
set -euo pipefail
cd "$(dirname "$0")/../.."
smoke_language="${1:-swift}"
case "$smoke_language" in
  swift) command -v swiftc >/dev/null ;;
  kotlin)
    command -v kotlinc >/dev/null
    : "${MDK_KOTLIN_CLASSPATH:?Supply JNA with native libraries, Android platform, annotations, and coroutines jars}"
    ;;
  *) echo 'Usage: details-markdown-smoke.sh swift|kotlin' >&2; exit 2 ;;
esac
cargo build -p marmot-uniffi --features cli --locked
smoke_target="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug"
case "$(uname -s)" in
  Darwin) smoke_library="$smoke_target/libmarmot_uniffi.dylib" ;;
  Linux) smoke_library="$smoke_target/libmarmot_uniffi.so" ;;
  *) echo 'Native smoke runner supports macOS and Linux' >&2; exit 2 ;;
esac
smoke_dir="$(mktemp -d)"
trap 'rm -rf "$smoke_dir"' EXIT
"$smoke_target/uniffi-bindgen" generate --library "$smoke_library" --language "$smoke_language" --out-dir "$smoke_dir"
if [[ "$smoke_language" == swift ]]; then
  cat "$smoke_dir/marmot_uniffi.swift" crates/marmot-uniffi/tests/details_markdown_smoke.swift > "$smoke_dir/CombinedSmoke.swift"
  swiftc -parse-as-library -I "$smoke_dir" -Xcc "-fmodule-map-file=$smoke_dir/marmot_uniffiFFI.modulemap" \
    -L "$smoke_target" -lmarmot_uniffi "$smoke_dir/CombinedSmoke.swift" -o "$smoke_dir/smoke"
  DYLD_LIBRARY_PATH="$smoke_target" LD_LIBRARY_PATH="$smoke_target" "$smoke_dir/smoke"
else
  kotlinc "$smoke_dir/dev/ipf/marmotkit/marmot_uniffi.kt" crates/marmot-uniffi/tests/details_markdown_smoke.kt \
    -cp "$MDK_KOTLIN_CLASSPATH" -include-runtime -d "$smoke_dir/smoke.jar"
  java -Djna.library.path="$smoke_target" -cp "$smoke_dir/smoke.jar:$MDK_KOTLIN_CLASSPATH" \
    dev.ipf.marmotkit.Details_markdown_smokeKt
fi
