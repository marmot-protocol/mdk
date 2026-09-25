# MarmotKit Binary Distribution

MarmotKit releases publish generated Swift/Kotlin APIs with matching native libraries as immutable GitHub Release
assets. Apple consumers use a binary-target XCFramework ZIP, generated Swift, and a separate SDK privacy manifest.
Android consumers unpack the Kotlin and JNI bundle into their app build.

## Apple privacy migration

**Migration required for releases built with this change.** Apple XCFrameworks now contain raw static-library slices,
not resource-bearing frameworks. Updating only the binary URL loses SDK privacy delivery. Keep the remote SwiftPM
binary target, but update all three matching release inputs and the wrapper's resource declaration together:

- `MarmotKitFFI-<identifier>.xcframework.zip` for iOS, or `MarmotKitFFI-macos-<identifier>.xcframework.zip` for macOS.
- `MarmotKit-<identifier>.swift`, shared by both platforms.
- `PrivacyInfo-ios-<identifier>.xcprivacy` or `PrivacyInfo-macos-<identifier>.xcprivacy`, for that platform's build.

Download from the same exact release/snapshot tag. Verify the privacy asset with its sibling `.sha256` using
`shasum -a 256 -c <filename>.sha256`, and verify Swift/binary hashes against the platform manifest. SwiftPM also checks
the binary ZIP against its `.swiftpm-checksum`. The platform privacy files are separately named so each build's
feature selection and provenance remain explicit; their contents match when their privacy-relevant features match.

Place the Swift binding and the privacy asset in the existing Swift wrapper target, renaming them to `MarmotKit.swift`
and `PrivacyInfo.xcprivacy`. Preserve the SDK declaration separately from the host application's own privacy manifest.
The wrapper target must declare:

```swift
.target(
    name: "MarmotKit",
    dependencies: ["MarmotKitFFI"],
    resources: [.copy("PrivacyInfo.xcprivacy")],
    linkerSettings: [
        .linkedFramework("Security", .when(platforms: [.macOS])),
        .linkedFramework("SystemConfiguration", .when(platforms: [.macOS]))
    ]
)
```

Assign that wrapper's product to each consuming app and notification extension. Do not add an extra host-compiled copy
of the generated Swift. SwiftPM delivers the target's manifest in a resource bundle; Rust remains statically linked
into each executable. No additional complete-package ZIP or new Rust binary is published. Existing provenance bundle
ZIPs include all three inputs plus `manifest.json`, but are not themselves binary-target archives.

Platform manifests identify this layout with `distribution: static-library-and-privacy-v1` and hash the privacy asset
alongside Swift, the ZIP and each static library. Keep all inputs on one identifier; automate their synchronization.
Consumers of 0.10.0 and earlier retain the old framework layout. No published release is modified. Direct Xcode
consumers must provide and validate an equivalent SDK resource bundle or use the Swift wrapper.

Release CI builds a simulator consumer and archives iOS app/notification-extension and macOS consumers from the
released ZIP, matching Swift and privacy assets. It checks resource content in each consumer, unchanged static
linkage, real Rust references, executable/dSYM UUIDs, and absence of the empty framework stub. The fixture uses a local
binary target after checking the downloaded ZIP's hash; existing remote SwiftPM link checks still exercise the URL and
checksum path. Signed export, Organizer privacy report and App Store Connect upload remain separate host checks.
Rust source-level debug information is unchanged and belongs in the crash-symbol PR.

[Consumer migration tracking](https://github.com/marmot-protocol/mdk/issues/1874) records downstream adoption and host
release evidence. See the [privacy audit and adoption guide](apple-privacy/README.md) for outstanding privacy questions.

## iOS

The iOS binary asset carries no platform token in its name, for backward compatibility with URLs consumers already
pin. macOS assets are explicitly prefixed `-macos-`; an unprefixed `MarmotKitFFI-<identifier>` asset is always iOS.

### Exact URLs

Formal release `marmotkit-v<version>`:

```text
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-v<version>/MarmotKitFFI-<version>.xcframework.zip
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-v<version>/MarmotKit-<version>.swift
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-v<version>/PrivacyInfo-ios-<version>.xcprivacy
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-v<version>/PrivacyInfo-ios-<version>.xcprivacy.sha256
```

Snapshot for a full 40-character commit SHA `<sha>` reachable from `master`:

```text
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-snapshot-<sha>/MarmotKitFFI-snapshot-<sha>.xcframework.zip
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-snapshot-<sha>/MarmotKit-snapshot-<sha>.swift
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-snapshot-<sha>/PrivacyInfo-ios-snapshot-<sha>.xcprivacy
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-snapshot-<sha>/PrivacyInfo-ios-snapshot-<sha>.xcprivacy.sha256
```

These URLs always contain an exact tag or snapshot identifier. Do not use a `latest` URL for SwiftPM artifacts.

### SwiftPM

Follow the [privacy migration](#apple-privacy-migration) as well as this binary declaration; the binary alone does not
carry the SDK privacy resource.

Download the sibling `.swiftpm-checksum` asset or read the `swiftpm` record in
`marmotkit-ios-<identifier>.checksums.txt`, then declare:

```swift
.binaryTarget(
    name: "MarmotKitFFI",
    url: "<exact URL above>",
    checksum: "<contents of .swiftpm-checksum>"
)
```

The consuming Swift package must declare iOS 18.0 or newer. The labeled records in `checksums.txt` are intended for
inspection and provenance; they are not `shasum -c` input. Use the sibling `.sha256` files for ordinary SHA-256
verification.

Add the matching `MarmotKit-<identifier>.swift` file to a Swift source target that depends on `MarmotKitFFI`. Update
the binary URL, checksum, generated Swift source, and platform privacy file together. Mixing source and binary identifiers can compile
against the wrong UniFFI ABI and is unsupported.

For manual verification, compare the ZIP with its `.sha256` asset. The separately published
`marmotkit-ios-<identifier>.manifest.json` records the full MDK source SHA, workspace version, `Cargo.lock` SHA-256,
toolchain versions, enabled features, iOS targets and deployment target, effective Rust release profile, and hashes
of the binary and generated Swift artifacts. `rust_release_profile.lto` follows Cargo's boolean-or-string
representation: JSON `false` for the historical untuned control, and the string `"thin"` for current production.
Codegen units remain an integer. Host and Apple artifacts keep `strip` as `"none"`; Android JNI builds apply
`symbols` only on those target invocations. Apple builders also pass `-C embed-bitcode=no` and sanitize leftover
Mach-O `__LLVM` / `__bitcode` sections so packaged archives stay native; that is not recorded as a `strip`
change. The complete `marmotkit-ios-<identifier>.zip` retains the XCFramework,
matching Swift source, `PrivacyInfo.xcprivacy`, and the same manifest for consumers that prefer a single provenance bundle.

## macOS

macOS artifacts are Apple Silicon only: the XCFramework carries a single `macos-arm64` slice built for
`aarch64-apple-darwin`. There is no Intel or universal build.

### Exact URLs

Formal release `marmotkit-v<version>`:

```text
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-v<version>/MarmotKitFFI-macos-<version>.xcframework.zip
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-v<version>/PrivacyInfo-macos-<version>.xcprivacy
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-v<version>/PrivacyInfo-macos-<version>.xcprivacy.sha256
```

Snapshot for a full 40-character commit SHA `<sha>` reachable from `master`:

```text
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-snapshot-<sha>/MarmotKitFFI-macos-snapshot-<sha>.xcframework.zip
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-snapshot-<sha>/PrivacyInfo-macos-snapshot-<sha>.xcprivacy
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-snapshot-<sha>/PrivacyInfo-macos-snapshot-<sha>.xcprivacy.sha256
```

### SwiftPM

Follow the [privacy migration](#apple-privacy-migration) as well as this binary declaration; the binary alone does not
carry the SDK privacy resource.

Download the sibling `.swiftpm-checksum` asset or read the `swiftpm` record in
`marmotkit-macos-<identifier>.checksums.txt`, then declare:

```swift
.binaryTarget(
    name: "MarmotKitFFI",
    url: "<exact URL above>",
    checksum: "<contents of .swiftpm-checksum>"
)
```

The consuming Swift package must declare macOS 15.0 or newer, and the target that wraps the binary links `Security`
and `SystemConfiguration`.

### Generated Swift is shared with iOS

There is no `MarmotKit-macos-<identifier>.swift` asset, and looking for one is the common mistake. The generated Swift
binding is platform-independent and published exactly once per release, by the iOS job, as
`MarmotKit-<identifier>.swift`. Use that same file for a macOS consumer, from the same release identifier as the macOS
binary. `marmotkit-macos-<identifier>.manifest.json` records its SHA-256 so a macOS consumer can verify it without
consulting the iOS manifest, and publishing fails if the two jobs ever generate different Swift from one source SHA.

For the same reason, `marmotkit-macos-<identifier>.checksums.txt` carries a `sha256` line for
`MarmotKit-<identifier>.swift` even though that file is not a macOS release asset — the line lets a macOS consumer
verify the shared Swift from the macOS checksums file alone. A verifier that walks that file expecting every named
entry to exist among the macOS assets must skip this one.

For manual verification, compare the ZIP with its `.sha256` asset. The separately published
`marmotkit-macos-<identifier>.manifest.json` records the full MDK source SHA, workspace version, `Cargo.lock` SHA-256,
toolchain versions, enabled features, macOS targets and deployment target, effective Rust release profile, and hashes
of the binary and shared generated Swift artifacts. `rust_release_profile.lto` is Cargo's boolean-or-string value
(`false` or `"thin"`); codegen units remain an integer. Apple builders pass `-C embed-bitcode=no` and sanitize leftover
Mach-O `__LLVM` / `__bitcode` sections; that is not a `strip` change. The complete `marmotkit-macos-<identifier>.zip` retains the
XCFramework, matching Swift source, `PrivacyInfo.xcprivacy`, and the same manifest for consumers that prefer a single provenance bundle.

## Android

Android bundles contain generated Kotlin, the required Android initialization helpers, and JNI libraries for
`arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64`.

### Exact URLs

Formal release `marmotkit-v<version>`:

```text
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-v<version>/marmotkit-android-<version>.zip
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-v<version>/marmotkit-android-<version>.zip.sha256
```

Snapshot for a full 40-character commit SHA `<sha>` reachable from `master`:

```text
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-snapshot-<sha>/marmotkit-android-snapshot-<sha>.zip
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-snapshot-<sha>/marmotkit-android-snapshot-<sha>.zip.sha256
```

The archive has a `marmotkit-android-<identifier>` root containing:

- `kotlin/dev/ipf/marmotkit/marmot_uniffi.kt`
- `kotlin/dev/ipf/marmotkit/MarmotAndroid.kt`
- `kotlin/io/crates/keyring/Keyring.kt`
- `jniLibs/<abi>/libmarmot_uniffi.so` for each supported ABI
- `android-elf.json`
- `manifest.json`

`arm64-v8a` and `x86_64` libraries are linked so every ELF `PT_LOAD` segment is aligned to at least 16 KB.
The linker flags are extra arguments on the final library build, so configured Cargo rustflags remain in effect.
`armeabi-v7a` and `x86` stay on the NDK default page size. The four ABIs and the Kotlin API are unchanged.
`android-elf.json` is a schema-1 report of the packaged bytes: each `jniLibs/<abi>/libmarmot_uniffi.so` entry has
the library's lowercase SHA-256, ELF class, machine, and ordered `PT_LOAD` alignments. Compare those hashes with
the files you stage. ZIP alignment of an app bundle does not repair a library whose load segments are still 4 KB.

Verify the archive against its sibling `.sha256` before extracting it. Update the generated Kotlin helpers and all
JNI ABI libraries together; mixing identifiers can cross an incompatible UniFFI ABI. The manifest records both the
exact packaged source SHA and the workflow builder SHA. Its ordered `contents` contract lists the generated UniFFI
Kotlin source and JNI libraries; the two required hand-written initialization helpers remain validated archive
payloads but do not change that existing consumer-facing API contract. `elf_validation` names `android-elf.json`
without adding that report to `contents`. Exact-head candidate packages from the release-profile workflow include
the same report beside `manifest.txt` and the build provenance. Publishing a new formal or snapshot artifact, and
adopting it in an Android app, remains a separate release step.

## Publishing

Pushing a formal `marmotkit-v*` tag publishes iOS, macOS, and Android bindings. To publish an untagged snapshot, run
the `MarmotKit Bindings` workflow with a full SHA on `master`. Its immutable release tag is derived from that SHA.
Snapshots publish the iOS, macOS, and Android bindings from the same source SHA.

Set the dispatch input `build_only=true` to build and validate workflow artifacts
without publishing. This also permits testing the workflow on a development
branch. Publishing retains the `master` workflow/source-ancestry restrictions.
See [parallel builds and rehearsals](../../release.md#parallel-builds-and-build-only-rehearsals)
for phase boundaries, concurrency limits, cache warming and evidence scope.

Publishing first uploads and verifies every asset on a draft, then publishes it under repository-enforced immutable
releases. A retry discards only an incomplete draft. Publishing fails if a public release already exists, and snapshot
publishing also fails if its derived tag already exists. Assets and snapshot tags are never replaced or moved; a
changed build requires a new formal version or a new source SHA.

Each platform manifest records both the packaged source SHA and the workflow builder SHA. Snapshot dispatches must use
the workflow from `master`, so an older reachable source commit cannot substitute its own packaging logic. The
builder SHA also owns the canonical Rust release profile and compiled-in public endpoint defaults. Source-coupled
inputs—including the Cargo workspace, UniFFI configuration, and Kotlin support files—come from the packaged source
SHA so the generated API and JNI libraries remain a matched set.

## Apple privacy resources

Apple exporters publish raw static libraries and the reviewed SDK manifest as separate matching release inputs.
The consuming Swift wrapper owns the privacy resource. See the [privacy audit and adoption guide](apple-privacy/README.md)
for declarations, archive validation and unresolved release questions.
