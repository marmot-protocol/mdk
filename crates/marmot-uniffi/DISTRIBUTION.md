# MarmotKit Apple Binary Distribution

MarmotKit releases publish the generated Swift API and its matching XCFrameworks as immutable GitHub Release
assets. Consumers keep `MarmotKit.swift` in a Swift source target and declare the XCFramework as a remote binary
target; neither the expanded XCFramework nor its static libraries need to be committed to the app repository.

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

## Publishing

Pushing a formal `marmotkit-v*` tag publishes iOS, macOS, and Android bindings. To publish an untagged snapshot, run
the `MarmotKit Bindings` workflow with a full SHA on `master`. Its immutable release tag is derived from that SHA.
Snapshots publish the iOS and macOS bindings; Android bindings are published only for formal tags.

Publishing first uploads and verifies every asset on a draft, then publishes it under repository-enforced immutable
releases. A retry discards only an incomplete draft. Publishing fails if a public release already exists, and snapshot
publishing also fails if its derived tag already exists. Assets and snapshot tags are never replaced or moved; a
changed build requires a new formal version or a new source SHA.

The iOS and macOS manifests each record both the packaged source SHA and the workflow builder SHA. Snapshot dispatches
must use the workflow from `master`, so an older reachable source commit cannot substitute its own packaging logic.
