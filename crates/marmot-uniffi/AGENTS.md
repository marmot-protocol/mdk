# AGENTS.md - marmot-uniffi

UniFFI bindings for the Marmot app runtime. Read `README.md` first for build scripts and platform setup.

## Scope

- Own the UniFFI export surface over `marmot-app` for Swift (iOS and macOS) and Kotlin (Android) consumers.
- Own build/packaging scripts: `xcframework.sh` (Swift + iOS XCFramework), `xcframework-macos.sh` (Swift + macOS
  XCFramework), `kotlin-bindings.sh` (Android JNI libs + generated Kotlin), `package-ios-artifacts.sh`,
  `package-macos-artifacts.sh`, `validate-ios-artifact.sh`, `validate-macos-artifact.sh`, `validate-swift-package.sh`,
  and `validate-swift-package-macos.sh`.
- Own `apple-framework.py`, `apple-privacy/`, `validate-apple-privacy.py`, `validate-apple-archive.py`,
  and `test-apple-privacy.py` for SDK declarations and resource delivery into Apple app archives.
- Own `marmotkit-release-profile.env`, the canonical Rust release profile for distributable MarmotKit artifacts.
- Own `chat-projections-smoke.sh`, the host Swift/Kotlin chat-screen DTO round-trip check.
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
  Stage those unchanged archives inside resource-bearing static frameworks; preserve macOS versioned symlinks.
  Validate privacy declarations against the packaged source and build features, then validate resources in a
  consuming app archived from the packaged ZIP. Raw-library `HeadersPath` is no longer the slice layout.
- The generated Swift binding is platform-independent, so releases publish `MarmotKit-<id>.swift` exactly once, from
  the iOS job. `package-macos-artifacts.sh` records its SHA-256 in the macOS manifest but must not emit the file;
  emitting it would collide with the iOS asset name on the shared release. The release job asserts both hashes match.
- Timeline and reply-preview `media` is an ordered `Vec<MediaAttachmentOutcomeFfi>`; a rejected `imeta` attachment
  stays in place as `Rejected { attachment_index, rejection }` with a stable `MediaAttachmentRejectionKindFfi`
  (mdk#1787). Timeline rows and `parse_media_imeta_tag` are the surfaces that carry the typed reason, and they must
  report the same kind and detail for the same tag. `list_media` is the downloadable-only gallery view: it returns
  accepted records only, numbered by tag position so its `attachment_index` matches the timeline outcome, and it
  deliberately does not emit a record for a rejected attachment (a gallery host renders placeholders from the timeline
  row, and mdk#1448 replaces `list_media`). Route all three through `marmot_app::parse_media_attachment` / the shared
  outcome helpers; do not reintroduce a `filter_map(.ok())` that drops the verdict in the timeline projection.
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

Chat-screen DTO changes also use `just uniffi-projections-smoke swift` (requires `swiftc`) and
`just uniffi-projections-smoke kotlin` (requires `kotlinc` and `MDK_KOTLIN_CLASSPATH` containing JNA with native
libraries, Android platform, annotations, and coroutines jars). These host checks do not replace release-artifact or
device validation.

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
