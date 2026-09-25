# AGENTS.md - marmot-uniffi

UniFFI bindings for the Marmot app runtime. Read `README.md` first for integration concepts, API selection and platform setup; then `API-REFERENCE.md` for the complete exported method inventory.

## Scope

- Own the UniFFI export surface over `marmot-app` for Swift (iOS and macOS) and Kotlin (Android) consumers.
- Own build/packaging scripts: `xcframework.sh` (Swift + iOS XCFramework), `xcframework-macos.sh` (Swift + macOS
  XCFramework), `kotlin-bindings.sh` (Android JNI libs + generated Kotlin), `package-ios-artifacts.sh`,
  `package-macos-artifacts.sh`, `validate-ios-artifact.sh`, `validate-macos-artifact.sh`, `validate-swift-package.sh`,
  `validate-swift-package-macos.sh`, and `validate-android-artifact.py`.
- Own `apple-privacy.py`, `apple-privacy/`, `validate-apple-privacy.py`, `validate-apple-archive.py`,
  and `test-apple-privacy.py` for SDK declarations and resource delivery into Apple app archives.
- Own `marmotkit-release-profile.env`, the canonical Rust release profile for distributable MarmotKit artifacts.
- Own `release-profile-json.py`, `release-profile-archive.py`, `test-release-profile.py`, and
  `measure-release-profile.py` for provenance JSON, native-archive bitcode checks, and controlled
  baseline/candidate measurements.
- Keep automatic exact-head packaging in `bindings-profile.yml`; comparative
  measurements belong in the explicit full-SHA `bindings-profile-measurement.yml`
  dispatch and must retain host, Android, Apple, CPU and failure evidence. Changes
  to the release profile, Rust toolchain or measurement methodology must dispatch
  and link completed comparative evidence before merge.
- Build scripts retain complete no-argument builds and expose generation/native/assembly phases for release CI.
  Keep `test-build-phases.py` covering phase isolation, required assembly inputs and deployment/strip behavior.
  Shared Swift generation feeds both Apple assemblers; transfer phase inputs only from the same workflow run.
- Own `chat-projections-smoke.sh`, the host Swift/Kotlin chat-screen DTO round-trip check.
- Own `marmotkit-endpoints.env` build-time defaults for audit-log tracker and relay-telemetry OTLP route URLs.
- Keep generated bindings out of git; host apps vendor artifacts from `output/` after running the scripts.

## Invariants

- The Rust API in `src/` is the source of truth for both Swift and Kotlin — scripts package, they do not fork types.
- Android consumers must call `MarmotAndroid.initialize(context)` before constructing `Marmot` (Keystore JNI via
  `ndk-context`).
- Android `arm64-v8a` and `x86_64` JNI libraries are linked with 16 KB ELF load alignment
  (`-Wl,-z,max-page-size=16384` and `-Wl,-z,common-page-size=16384`) through extra flags on the final
  library `cargo rustc` invocation, so configured Cargo rustflags are left in place. 32-bit ABIs keep the
  NDK default page size.
  `validate-android-artifact.py` checks the packaged bytes; ZIP alignment does not repair a 4 KB `PT_LOAD`.
- Endpoint env vars set route URLs only; bearer tokens and runtime secrets stay with the host app.
- Build and validate an Apple artifact against the same deployment target. Objects compiled under
  `MACOSX_DEPLOYMENT_TARGET` / `IPHONEOS_DEPLOYMENT_TARGET` report exactly that minimum, and the validators fail on a
  minimum *newer* than expected, so validating against a lower number fails. macOS publishes at `15.0`.
- Package Apple static libraries as native objects. Apple Cargo invocations set target-scoped
  `-C embed-bitcode=no` (iOS rustc defaults to embedding bitcode). After cargo writes each `.a`,
  `release-profile-archive.py --sanitize` removes leftover `__LLVM` / `__bitcode` segments and
  MH_OBJECT section-level `__LLVM` leftovers from every member, including toolchain
  `compiler_builtins` objects; it does not skip names or accept raw LLVM bitcode.
  Rust's `llvm-tools-preview` component supplies `llvm-objcopy` to rewrite sections,
  symbols and relocations; do not implement custom Mach-O offset rewriting.
  Archive reconstruction uses Apple `libtool` to regenerate alignment and symbol
  indexes, preserves duplicate object names, and replaces the original only after
  validation. Never copy an old symbol index into a rewritten archive.
  This is not a symbol strip: `marmotkit-release-profile.env` still pins `strip=none`
  and `debug=0`, and the packagers publish that profile as provenance. Package the sanitized native
  archives as raw-library XCFramework slices. Render the feature-selected privacy declaration
  from the packaged source's `apple-privacy/` and publish it separately with a checksum; also include it in the
  existing provenance bundle. Never stage resource-bearing framework wrappers or another complete-package ZIP.
  Consumers must synchronize binary, Swift and privacy inputs and declare the privacy resource in their Swift target.
  Validate the actual released inputs in app/notification-extension archives: privacy delivery, static linking, real
  Rust references, dSYM UUIDs, and no codeless framework stub. Keep Rust debug policy separate from privacy packaging.
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

## Documentation contract

- Every exported constructor, runtime/object method, free function and foreign callback belongs in
  `API-REFERENCE.md`, with its exact Rust signature, purpose and source link. Update it in the same PR
  as API changes; use `just binding-docs-update` to regenerate mechanical signatures/source anchors
  without replacing authored guidance. New scaffolds require prose before they pass; explicitly
  review removed/duplicate entries. `just binding-docs-gate` checks metadata drift and runs its
  companion tests. It does not validate prose, records/enums or generated-language ABI: review those manually.
- Keep the README's recommended/compatibility/lower-level selection table accurate. Do not describe
  a supported primitive as deprecated simply because a chat-screen projection exists. State a
  replacement and its scope for compatibility recommendations; claim formal deprecation only when
  the source actually declares it. Preserve non-chat consumers.
- Keep detailed contracts in `CHAT-LIST-ROWS.md`, `CONVERSATION-WINDOW.md`, `ATTACHMENT-HISTORY.md`, `ATTACHMENT-ACCESS.md`
  and linked architecture docs; make the README the discoverable entry point rather than accumulating
  unindexed release snippets. Source/binary pairing, ownership, cancellation, local/network behavior,
  pagination, localization and privacy must be explicit for new public surfaces.
- Starting with 0.10.2, every release needs `docs/integration/<version>.md` alongside concise
  `docs/release/<version>.md`. Follow `release.md#release-documentation`: compare the prior tag,
  distinguish required migration/default changes from optional adoption and automatic fixes,
  include Swift/Kotlin/C implications and concrete consumer validation. Link both directions and
  update `docs/integration/README.md`. Never move an existing tag for a later documentation supplement.

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
