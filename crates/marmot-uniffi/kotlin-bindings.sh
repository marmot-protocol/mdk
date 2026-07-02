#!/usr/bin/env bash
# Build Kotlin bindings and Android JNI libraries for MarmotKit.
#
# Outputs:
#   <crate>/output/android/kotlin/dev/ipf/marmotkit/marmot_uniffi.kt
#   <crate>/output/android/kotlin/dev/ipf/marmotkit/MarmotAndroid.kt
#   <crate>/output/android/kotlin/io/crates/keyring/Keyring.kt
#   <crate>/output/android/jniLibs/<abi>/libmarmot_uniffi.so
#
# The Kotlin file is generated from the same UniFFI metadata as the Swift
# bindings, so the exported Marmot surface stays in lockstep across platforms.
# The two hand-written helpers under kotlin-support/ are copied alongside it to
# give Android consumers the ndk-context init bridge the keyring store needs
# (see kotlin-support/dev/ipf/marmotkit/MarmotAndroid.kt).

set -euo pipefail

# Force rustup's cargo to win over any Homebrew-installed cargo so Android
# targets installed through rustup are visible.
export PATH="$HOME/.cargo/bin:$PATH"

CRATE_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_DIR="$(cd "$CRATE_DIR/../.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$WORKSPACE_DIR/target}"
if [[ "$TARGET_DIR" != /* ]]; then
  TARGET_DIR="$WORKSPACE_DIR/$TARGET_DIR"
fi
OUT_DIR="$CRATE_DIR/output/android"
KOTLIN_OUT_DIR="$OUT_DIR/kotlin"
JNI_OUT_DIR="$OUT_DIR/jniLibs"

# Set public first-party endpoint defaults for values compiled via option_env!.
# Tokens remain host-app runtime configuration.
source "$CRATE_DIR/marmotkit-endpoints.env"

CRATE_NAME="marmot-uniffi"
LIB_BASENAME="marmot_uniffi"

FEATURE_ARGS=()
BINDGEN_FEATURES="cli"
if [[ "${OTLP_EXPORT:-0}" == "1" || "${OTLP_EXPORT:-}" == "true" ]]; then
  FEATURE_ARGS=(--features otlp-export)
  BINDGEN_FEATURES="cli,otlp-export"
fi

ANDROID_API="${ANDROID_API:-26}"
ANDROID_ABIS="${ANDROID_ABIS:-arm64-v8a armeabi-v7a x86 x86_64}"

SUPPORTED_ANDROID_ABIS="arm64-v8a armeabi-v7a x86 x86_64"

abi_to_target() {
  case "$1" in
    arm64-v8a) echo "aarch64-linux-android" ;;
    armeabi-v7a) echo "armv7-linux-androideabi" ;;
    x86) echo "i686-linux-android" ;;
    x86_64) echo "x86_64-linux-android" ;;
    *) return 1 ;;
  esac
}

target_to_clang_prefix() {
  case "$1" in
    aarch64-linux-android) echo "aarch64-linux-android" ;;
    armv7-linux-androideabi) echo "armv7a-linux-androideabi" ;;
    i686-linux-android) echo "i686-linux-android" ;;
    x86_64-linux-android) echo "x86_64-linux-android" ;;
    *) return 1 ;;
  esac
}

host_dylib_path() {
  case "$(uname -s)" in
    Darwin) echo "$TARGET_DIR/release/lib${LIB_BASENAME}.dylib" ;;
    Linux) echo "$TARGET_DIR/release/lib${LIB_BASENAME}.so" ;;
    MINGW*|MSYS*|CYGWIN*) echo "$TARGET_DIR/release/${LIB_BASENAME}.dll" ;;
    *) echo "unsupported host OS: $(uname -s)" >&2; return 1 ;;
  esac
}

find_android_ndk() {
  local candidate
  for candidate in "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}" "${NDK_HOME:-}"; do
    if [[ -n "$candidate" && -d "$candidate/toolchains/llvm/prebuilt" ]]; then
      echo "$candidate"
      return 0
    fi
  done

  local sdk_root="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
  if [[ -z "$sdk_root" ]]; then
    case "$(uname -s)" in
      Darwin) sdk_root="$HOME/Library/Android/sdk" ;;
      Linux) sdk_root="$HOME/Android/Sdk" ;;
      *) sdk_root="$HOME/Library/Android/sdk" ;;
    esac
  fi
  if [[ -d "$sdk_root/ndk" ]]; then
    local ndk_dir
    ndk_dir="$(find "$sdk_root/ndk" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
    if [[ -n "$ndk_dir" ]]; then
      echo "$ndk_dir"
      return 0
    fi
  fi

  echo "error: Android NDK not found. Set ANDROID_NDK_HOME or ANDROID_NDK_ROOT." >&2
  return 1
}

ndk_host_tag() {
  local ndk="$1"
  local os
  os="$(uname -s)"
  case "$os" in
    Darwin)
      if [[ -d "$ndk/toolchains/llvm/prebuilt/darwin-x86_64" ]]; then
        echo "darwin-x86_64"
      else
        local host_dir
        host_dir="$(find "$ndk/toolchains/llvm/prebuilt" -mindepth 1 -maxdepth 1 -type d -name 'darwin-*' | sort | tail -n 1)"
        if [[ -z "$host_dir" ]]; then
          echo "error: no Darwin Android NDK toolchain found under $ndk" >&2
          return 1
        fi
        basename "$host_dir"
      fi
      ;;
    Linux) echo "linux-x86_64" ;;
    *) echo "unsupported host OS for Android NDK: $os" >&2; return 1 ;;
  esac
}

require_rust_targets() {
  local missing=()
  local abi target
  for abi in $ANDROID_ABIS; do
    if ! target="$(abi_to_target "$abi")"; then
      echo "error: unsupported Android ABI '$abi'" >&2
      echo "supported ABIs: $SUPPORTED_ANDROID_ABIS" >&2
      return 1
    fi
    if ! rustup target list --installed | grep -qx "$target"; then
      missing+=("$target")
    fi
  done

  if (( ${#missing[@]} > 0 )); then
    echo "error: missing Rust Android target(s): ${missing[*]}" >&2
    echo "install them with:" >&2
    echo "  rustup target add ${missing[*]}" >&2
    return 1
  fi
}

configure_android_toolchain() {
  local ndk="$1"
  local host_tag="$2"
  local toolchain_bin="$ndk/toolchains/llvm/prebuilt/$host_tag/bin"
  local target="$3"
  local clang_prefix
  clang_prefix="$(target_to_clang_prefix "$target")"
  local clang="$toolchain_bin/${clang_prefix}${ANDROID_API}-clang"
  local cargo_env cc_env

  if [[ ! -x "$clang" ]]; then
    echo "error: Android clang not found or not executable: $clang" >&2
    return 1
  fi

  cargo_env="$(echo "$target" | tr '[:lower:]-' '[:upper:]_')"
  cc_env="$(echo "$target" | tr '-' '_')"

  export "CARGO_TARGET_${cargo_env}_LINKER=$clang"
  export "CARGO_TARGET_${cargo_env}_AR=$toolchain_bin/llvm-ar"
  export "CC_${cc_env}=$clang"
  export "AR_${cc_env}=$toolchain_bin/llvm-ar"
  export "RANLIB_${cc_env}=$toolchain_bin/llvm-ranlib"
}

cd "$WORKSPACE_DIR"

NDK_DIR="$(find_android_ndk)"
HOST_TAG="$(ndk_host_tag "$NDK_DIR")"
require_rust_targets

echo "==> Cleaning previous Android/Kotlin build artifacts"
rm -rf "$OUT_DIR"
mkdir -p "$KOTLIN_OUT_DIR" "$JNI_OUT_DIR"

echo "==> Building host dylib (used for binding generation)"
cargo build --release -p "$CRATE_NAME" "${FEATURE_ARGS[@]}"

echo "==> Generating Kotlin bindings"
cargo run --release -p "$CRATE_NAME" --features "$BINDGEN_FEATURES" --bin uniffi-bindgen -- \
  generate \
  --library "$(host_dylib_path)" \
  --language kotlin \
  --config "$CRATE_DIR/uniffi.toml" \
  --no-format \
  --out-dir "$KOTLIN_OUT_DIR"

echo "==> Copying hand-written Android Kotlin support (ndk-context init bridge)"
# kotlin-support/ mirrors the Kotlin package layout, so copying its contents into
# the generated output lands MarmotAndroid.kt next to marmot_uniffi.kt and the
# io.crates.keyring.Keyring JNI shim under its required package.
cp -R "$CRATE_DIR/kotlin-support/." "$KOTLIN_OUT_DIR/"

for abi in $ANDROID_ABIS; do
  target="$(abi_to_target "$abi")"
  echo "==> Building Android target $target ($abi)"
  configure_android_toolchain "$NDK_DIR" "$HOST_TAG" "$target"
  cargo build --release -p "$CRATE_NAME" --target "$target" "${FEATURE_ARGS[@]}"
  mkdir -p "$JNI_OUT_DIR/$abi"
  cp "$TARGET_DIR/$target/release/lib${LIB_BASENAME}.so" "$JNI_OUT_DIR/$abi/"
done

echo ""
echo "Done."
echo "  Kotlin binding: $KOTLIN_OUT_DIR/dev/ipf/marmotkit/${LIB_BASENAME}.kt"
echo "  Android init:   $KOTLIN_OUT_DIR/dev/ipf/marmotkit/MarmotAndroid.kt"
echo "  Keyring shim:   $KOTLIN_OUT_DIR/io/crates/keyring/Keyring.kt"
echo "  JNI libraries:  $JNI_OUT_DIR"
