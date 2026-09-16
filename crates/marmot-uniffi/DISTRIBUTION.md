# MarmotKit Binary Distribution

MarmotKit releases publish the generated Swift and Kotlin APIs with their matching native libraries as immutable
GitHub Release assets. New SwiftPM integrations should use the complete platform Swift package described below.
The existing framework binary-target assets remain available for current/manual integrations; Android consumers
unpack the Kotlin and JNI bundle into their app build.

## Complete Apple SwiftPM packages

Releases built with this packaging change additionally publish:

```text
marmotkit-swiftpm-ios-<identifier>.zip
marmotkit-swiftpm-ios-<identifier>.zip.sha256
marmotkit-swiftpm-macos-<identifier>.zip
marmotkit-swiftpm-macos-<identifier>.zip.sha256
```

Use the same exact release/snapshot tag and identifier as the other assets. These files are **not retroactively
available in 0.10.0 or earlier releases**. A complete package ZIP is not a `.binaryTarget(url:)` archive.
Download it and its sibling `.sha256`, verify them with `shasum -a 256 -c <filename>.sha256`, then extract it.
Add the enclosed `MarmotKit` directory as a **local Swift package**, for example:

```swift
// In the host's Package.swift dependencies:
.package(path: "Vendored/MarmotKit")
// In each app/extension target's dependencies:
.product(name: "MarmotKit", package: "MarmotKit")
```

For Xcode projects, use Add Local Package and assign the MarmotKit product to the app and notification extension.
Replace the old MarmotKit wrapper dependency; do not compile an additional copy of `MarmotKit.swift` in the host.
If retaining an existing package wrapper is necessary, copy **all** the matching package inputs and retain its
`resources: [.copy("PrivacyInfo.xcprivacy")]` declaration and platform linker settings.

The package contains:

```text
MarmotKit/
  Package.swift
  manifest.json
  MarmotKit.xcframework/                 # raw, unchanged static-library slices
  Sources/MarmotKit/MarmotKit.swift
  Sources/MarmotKit/PrivacyInfo.xcprivacy # owned and copied by the Swift target
```

This keeps Rust statically linked into each consuming executable. SwiftPM copies the SDK manifest into its
`MarmotKit_MarmotKit.bundle`, avoiding the codeless framework that Xcode otherwise replaces with an empty dynamic
stub. No privacy declaration is removed or changed. The generated Swift and archive bytes match the corresponding
framework distribution; Rust release/debug settings are unchanged. Crash source maps are separate work.

The package's `manifest.json` retains source/builder SHA, feature selection, toolchain and profile provenance, and
adds hashes of every payload file and the original static archives. The platform release manifest records the package
ZIP SHA-256 under `swiftpm_package`; its checksums file also lists that ZIP. macOS embeds the same generated Swift
source in this complete package, while the standalone `.swift` release asset remains owned by the iOS job.

A complete package is the unit of integration. A raw library cannot carry resources by itself; copying only its
XCFramework loses the privacy resource. Keep the host's own privacy manifest and declarations too. The framework
assets documented below retain their current formats and manifests for compatibility, but their codeless resource
framework can still trigger a missing-dSYM warning on Xcode 27. Adopting this new package is required to avoid that
stub; updating only an old binary URL is not the migration.

Release CI archives the complete package on both Apple platforms. iOS checks the app and notification extension;
macOS checks the app and its ad-hoc signature. The checks require correct SDK resources, unchanged static linkage,
actual Rust function references, matching consumer dSYM UUIDs, and no embedded Marmot framework stub. They do not
claim source-line debug coverage or App Store acceptance. Signed distribution export, Organizer privacy-report
verification and a real staging upload remain host release checks.

Each release carries a separate iOS and macOS XCFramework under distinct asset names, and a single shared
`MarmotKit-<identifier>.swift`. The generated Swift is platform-independent, so both platforms consume the same file:
there is no macOS-specific Swift asset to look for.

## iOS

The iOS binary asset carries no platform token in its name, for backward compatibility with URLs consumers already
pin. macOS assets are explicitly prefixed `-macos-`; an unprefixed `MarmotKitFFI-<identifier>` asset is always iOS.

### Exact URLs

Formal release `marmotkit-v<version>`:

```text
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-v<version>/MarmotKitFFI-<version>.xcframework.zip
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-v<version>/MarmotKit-<version>.swift
```

Snapshot for a full 40-character commit SHA `<sha>` reachable from `master`:

```text
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-snapshot-<sha>/MarmotKitFFI-snapshot-<sha>.xcframework.zip
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-snapshot-<sha>/MarmotKit-snapshot-<sha>.swift
```

These URLs always contain an exact tag or snapshot identifier. Do not use a `latest` URL for SwiftPM artifacts.

### SwiftPM

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
the binary URL, checksum, and generated Swift source together. Mixing source and binary identifiers can compile
against the wrong UniFFI ABI and is unsupported.

For manual verification, compare the ZIP with its `.sha256` asset. The separately published
`marmotkit-ios-<identifier>.manifest.json` records the full MDK source SHA, workspace version, `Cargo.lock` SHA-256,
toolchain versions, enabled features, iOS targets and deployment target, effective Rust release profile, and hashes
of the binary and generated Swift artifacts. The complete `marmotkit-ios-<identifier>.zip` retains the XCFramework,
matching Swift source, and the same manifest for consumers that prefer a single provenance bundle.

## macOS

macOS artifacts are Apple Silicon only: the XCFramework carries a single `macos-arm64` slice built for
`aarch64-apple-darwin`. There is no Intel or universal build.

### Exact URLs

Formal release `marmotkit-v<version>`:

```text
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-v<version>/MarmotKitFFI-macos-<version>.xcframework.zip
```

Snapshot for a full 40-character commit SHA `<sha>` reachable from `master`:

```text
https://github.com/marmot-protocol/mdk/releases/download/marmotkit-snapshot-<sha>/MarmotKitFFI-macos-snapshot-<sha>.xcframework.zip
```

### SwiftPM

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
of the binary and shared generated Swift artifacts. The complete `marmotkit-macos-<identifier>.zip` retains the
XCFramework, matching Swift source, and the same manifest for consumers that prefer a single provenance bundle.

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
- `manifest.json`

Verify the archive against its sibling `.sha256` before extracting it. Update the generated Kotlin helpers and all
JNI ABI libraries together; mixing identifiers can cross an incompatible UniFFI ABI. The manifest records both the
exact packaged source SHA and the workflow builder SHA. Its ordered `contents` contract lists the generated UniFFI
Kotlin source and JNI libraries; the two required hand-written initialization helpers remain validated archive
payloads but do not change that existing consumer-facing API contract.

## Publishing

Pushing a formal `marmotkit-v*` tag publishes iOS, macOS, and Android bindings. To publish an untagged snapshot, run
the `MarmotKit Bindings` workflow with a full SHA on `master`. Its immutable release tag is derived from that SHA.
Snapshots publish the iOS, macOS, and Android bindings from the same source SHA.

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

Apple exporters retain resource-bearing static framework slices and additionally package a complete SwiftPM
distribution with target-owned privacy resources. See the
[privacy audit and adoption guide](apple-privacy/README.md) for declarations,
archive validation, host integration changes, and unresolved release questions.
