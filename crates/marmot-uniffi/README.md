# marmot-uniffi

UniFFI bindings for the Marmot app runtime.

The Rust API in `src/` is the source of truth for both generated Swift and generated Kotlin. Platform scripts only
package that shared surface:

- `./crates/marmot-uniffi/xcframework.sh` builds `output/MarmotKit.xcframework` plus `output/MarmotKit.swift` for iOS.
- `./crates/marmot-uniffi/kotlin-bindings.sh` builds `output/android/kotlin/.../marmot_uniffi.kt` plus Android
  `jniLibs` shared libraries.

The Kotlin binding is generated from the same release host library metadata as Swift, so it exposes the same `Marmot`
object, subscription objects, records, enums, and error variants.

## Service Endpoint Defaults

`marmotkit-endpoints.env` sets the public build-time defaults consumed by Marmot's compiled endpoint config:

- `MARMOT_AUDIT_LOG_TRACKER_ENDPOINT`
- `MARMOT_RELAY_TELEMETRY_OTLP_ENDPOINT`

These are route URLs only. Host apps still supply audit and telemetry bearer tokens at runtime. Set either environment
variable before invoking a build script to override the default for staging or local testing.

## Kotlin / Android

Prerequisites:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
# macOS Android Studio default:
export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/<version>"
# Linux / common CI default:
# export ANDROID_NDK_HOME="$HOME/Android/Sdk/ndk/<version>"
```

CI jobs can also set `ANDROID_SDK_ROOT` or `ANDROID_HOME`; the build script will discover the newest NDK under
`$ANDROID_SDK_ROOT/ndk` or `$ANDROID_HOME/ndk` when `ANDROID_NDK_HOME` is not set.

Build all Android ABIs:

```sh
./crates/marmot-uniffi/kotlin-bindings.sh
```

To build a subset:

```sh
ANDROID_ABIS="arm64-v8a x86_64" ./crates/marmot-uniffi/kotlin-bindings.sh
```

Generated Kotlin uses package `dev.ipf.marmotkit`, loads `libmarmot_uniffi.so`, and requires the normal
UniFFI Kotlin runtime dependencies used by the generated file: JNA, Kotlin coroutines, and AndroidX annotations.

The output directories are ignored because generated bindings and packaged native libraries are derived artifacts.
Regenerate them from this crate before vendoring into an app repository.
