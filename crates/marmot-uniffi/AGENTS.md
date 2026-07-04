# AGENTS.md - marmot-uniffi

UniFFI bindings for the Marmot app runtime. Read `README.md` first for build scripts and platform setup.

## Scope

- Own the UniFFI export surface over `marmot-app` for Swift (iOS) and Kotlin (Android) consumers.
- Own build/packaging scripts: `xcframework.sh` (Swift + XCFramework) and `kotlin-bindings.sh` (Android JNI libs +
  generated Kotlin).
- Own `marmotkit-endpoints.env` build-time defaults for audit-log tracker and relay-telemetry OTLP route URLs.
- Keep generated bindings out of git; host apps vendor artifacts from `output/` after running the scripts.

## Invariants

- The Rust API in `src/` is the source of truth for both Swift and Kotlin — scripts package, they do not fork types.
- Android consumers must call `MarmotAndroid.initialize(context)` before constructing `Marmot` (Keystore JNI via
  `ndk-context`).
- Endpoint env vars set route URLs only; bearer tokens and runtime secrets stay with the host app.
- Keep binding changes in lockstep with `marmot-app` public API changes; bump the workspace version when UniFFI records,
  enums, object methods, or error variants change.

## Verification

Regenerate and smoke-test bindings after API changes:

```sh
./crates/marmot-uniffi/xcframework.sh
./crates/marmot-uniffi/kotlin-bindings.sh
cargo test -p marmot-uniffi
cargo test -p marmot-app
```

OTLP export builds:

```sh
cargo check -p marmot-uniffi --features otlp-export
```

See [`README.md`](README.md) for Android NDK prerequisites and initialization requirements.
