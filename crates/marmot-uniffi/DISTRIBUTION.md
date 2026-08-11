# MarmotKit iOS Binary Distribution

MarmotKit iOS releases publish the generated Swift API and its matching XCFramework as immutable GitHub Release
assets. Consumers keep `MarmotKit.swift` in a Swift source target and declare the XCFramework as a remote binary
target; neither the expanded XCFramework nor its static libraries need to be committed to the app repository.

## Exact URLs

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

## SwiftPM

Download the sibling `.swiftpm-checksum` asset or read `marmotkit-ios-<identifier>.checksums.txt`, then declare:

```swift
.binaryTarget(
    name: "MarmotKitFFI",
    url: "<exact URL above>",
    checksum: "<contents of .swiftpm-checksum>"
)
```

Add the matching `MarmotKit-<identifier>.swift` file to a Swift source target that depends on `MarmotKitFFI`. Update
the binary URL, checksum, and generated Swift source together. Mixing source and binary identifiers can compile
against the wrong UniFFI ABI and is unsupported.

For manual verification, compare the ZIP with its `.sha256` asset. The separately published
`marmotkit-ios-<identifier>.manifest.json` records the full MDK source SHA, workspace version, `Cargo.lock` SHA-256,
toolchain versions, enabled features, iOS targets and deployment target, effective Rust release profile, and hashes
of the binary and generated Swift artifacts. The complete `marmotkit-ios-<identifier>.zip` retains the XCFramework,
matching Swift source, and the same manifest for consumers that prefer a single provenance bundle.

## Publishing

Pushing a formal `marmotkit-v*` tag publishes iOS and Android bindings. To publish an untagged TestFlight snapshot,
run the `MarmotKit Bindings` workflow with a full SHA on `master`. Its immutable release tag is derived from that SHA.

Publishing fails if the release already exists. Snapshot publishing also fails if its derived tag already exists.
Assets and snapshot tags are never replaced, moved, or uploaded with `--clobber`; a changed build requires a new
formal version or a new source SHA.
