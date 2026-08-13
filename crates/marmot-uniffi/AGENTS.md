# AGENTS.md - marmot-uniffi

UniFFI bindings for the Marmot app runtime. Read `README.md` first for build scripts and platform setup.

## Scope

- Own the UniFFI export surface over `marmot-app` for Swift (iOS and macOS) and Kotlin (Android) consumers.
- Own build/packaging scripts: `xcframework.sh` (Swift + iOS XCFramework), `xcframework-macos.sh` (Swift + macOS
  XCFramework), `kotlin-bindings.sh` (Android JNI libs + generated Kotlin), `package-ios-artifacts.sh`,
  `package-macos-artifacts.sh`, `validate-ios-artifact.sh`, `validate-macos-artifact.sh`, `validate-swift-package.sh`,
  and `validate-swift-package-macos.sh`.
- Own `marmotkit-release-profile.env`, the canonical Rust release profile for distributable MarmotKit artifacts.
- Own `marmotkit-endpoints.env` build-time defaults for audit-log tracker and relay-telemetry OTLP route URLs.
- Keep generated bindings out of git; host apps vendor artifacts from `output/` after running the scripts.

## Invariants

- The Rust API in `src/` is the source of truth for both Swift and Kotlin — scripts package, they do not fork types.
- Android consumers must call `MarmotAndroid.initialize(context)` before constructing `Marmot` (Keystore JNI via
  `ndk-context`).
- Endpoint env vars set route URLs only; bearer tokens and runtime secrets stay with the host app.
- Build and validate an Apple artifact against the same deployment target. Objects compiled under
  `MACOSX_DEPLOYMENT_TARGET` / `IPHONEOS_DEPLOYMENT_TARGET` report exactly that minimum, and the validators fail on a
  minimum *newer* than expected, so validating against a lower number fails. macOS publishes at `15.0`.
- Package Apple static libraries exactly as cargo produced them. Neither `xcframework.sh` nor `xcframework-macos.sh`
  strips post-link: `marmotkit-release-profile.env` pins `strip=none` and `debug=0`, and the packagers publish that
  profile as provenance, so a post-link strip would make the manifest describe an artifact that was not shipped.
- The generated Swift binding is platform-independent, so releases publish `MarmotKit-<id>.swift` exactly once, from
  the iOS job. `package-macos-artifacts.sh` records its SHA-256 in the macOS manifest but must not emit the file;
  emitting it would collide with the iOS asset name on the shared release. The release job asserts both hashes match.
- Host-supplied `group_id_hex` values are variable-length MLS `GroupId` bytes, not Nostr `nostr_group_id` route handles.
  Accept non-empty opaque MLS group ids, including the 16-byte ids OpenMLS generates for MDK today, and do not validate
  them with the 32-byte route-id/pubkey/message-id rule.
- Keep binding changes in lockstep with `marmot-app` public API changes, but do not bump the workspace version as part
  of feature, fix, binding, or review-feedback work. Workspace versions are bumped only as an explicit, user-directed
  release operation; UniFFI records, enums, object methods, and error variants may change while the current workspace
  version remains unchanged.

## Verification

Regenerate and smoke-test bindings after API changes:

```sh
./crates/marmot-uniffi/xcframework.sh
./crates/marmot-uniffi/xcframework-macos.sh
./crates/marmot-uniffi/kotlin-bindings.sh
cargo test -p marmot-uniffi
cargo test -p marmot-app
```

OTLP export builds:

```sh
cargo check -p marmot-uniffi --features otlp-export
```

Release-artifact checks (after `xcframework.sh`):

```sh
./crates/marmot-uniffi/validate-ios-artifact.sh crates/marmot-uniffi/output/MarmotKit.xcframework 18.0
./crates/marmot-uniffi/validate-swift-package.sh \
  crates/marmot-uniffi/output/MarmotKit.xcframework - crates/marmot-uniffi/output/MarmotKit.swift
```

macOS release-artifact checks (after `xcframework-macos.sh`, which needs `OTLP_EXPORT=1` for packaging):

```sh
./crates/marmot-uniffi/validate-macos-artifact.sh crates/marmot-uniffi/output/macos/MarmotKit.xcframework 15.0
./crates/marmot-uniffi/validate-swift-package-macos.sh \
  crates/marmot-uniffi/output/macos/MarmotKit.xcframework - crates/marmot-uniffi/output/macos/MarmotKit.swift
```

See [`README.md`](README.md) for Android NDK prerequisites and initialization requirements.
