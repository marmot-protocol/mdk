# Local validation receipt — 2026-09-15

These are **local review artifacts**, built from Rust source at
`b7dc47b12c640a99ed352ef451e0d3430d8d34be` with the accompanying uncommitted
packaging/privacy changes. They are not a published release or a claim that
that commit already contains the new manifests. An eventual immutable release
must rebuild from the reviewed commit using the normal provenance workflow.

Environment: Rust 1.97.1, Xcode 27.0 (27A266a), Apple Silicon. Both Apple
exporters used `OTLP_EXPORT=1 PRODUCT_ANALYTICS_EXPORT=1`.

| Boundary | Result |
| --- | --- |
| Historical artifact | Fresh 0.9.21 iOS and macOS downloads matched their published SHA-256 values; neither ZIP contained a privacy manifest. Both release provenance manifests identify source `fdd398a80f1626f1713787cebe416f7890b5b204`. |
| Syntax / values | `plutil` accepts the manifests. The privacy validator checks Boolean types, reviewed data types/purposes and C617.1, then compares complete declarations. |
| Resource regressions | `just apple-privacy-gate`: 5 tests passed. Missing slice resources, feature differences across slices, invalid values, archive resource loss and accidentally embedded static archives are rejected. The old raw-library package is rejected. |
| Repository source gates | `just fast-ci` passed. The new privacy gate also passed separately after its addition to the recipe. |
| Rust crate tests | `cargo test -p marmot-uniffi`: 190 passed, 1 ignored, 0 failed across unit, integration and audit suites; doc tests passed (0 tests). |
| Native artifacts | Finalized iOS and macOS exporters succeeded. Validators walked every archive member for arm64 and maximum deployment targets iOS 18.0 / macOS 15.0. |
| ZIP resources | Both local binary-only ZIPs passed the platform validators after extraction, including macOS versioned framework links. |
| Binary/source preservation | All three staged native libraries equal their Cargo-produced archives byte-for-byte. iOS and macOS generated Swift files are byte-identical. |
| SwiftPM linking | Existing iOS consumer validation passed both arm64 simulator and device compilation/linking. |
| Consuming app archives | Both Xcode app archives passed. The generated SwiftPM consumers have no host manifest and no custom resource-copy build phase. Xcode embedded the SDK resource and omitted the static archive binary. |
| Native API residual | Both final app executables still reference stat/fstat/lstat/fstatat/statfs/fstatfs. SQLite's statfs/fstatfs object references are independently attributable in the SDK archive. A final app symbol alone does not attribute all other calls to MDK. No boot-time declaration was inferred from Rust timers. |
| Xcode privacy report | User supplied the iOS Organizer PDF on 2026-09-15. All 12 collection categories, their purposes, Tracking NO and Linked YES match the archived SDK manifest. Every entry is attributed to `marmot_uniffiFFI.framework/PrivacyInfo.xcprivacy`. No missing or unexpected collection entry was found. macOS report remains uninspected. |
| App Store | No signing/distribution upload, App Store validation, or review was attempted. No release or consumer repository was modified. |

The initial long-running exporters read scripts while they were being edited
and stopped with shell-read errors after compilation. Both were rerun from the
finalized scripts successfully. The results above refer to those successful runs.
The minimal app fixtures emitted ordinary launch/orientation/category warnings;
they are archive resource/link tests, not submission-ready applications.

## Retained local evidence

Paths are relative to the worktree root:

* iOS: `crates/marmot-uniffi/output/MarmotKit.xcframework`
* macOS: `crates/marmot-uniffi/output/macos/MarmotKit.xcframework`
* iOS archive: `target/privacy-ios-consumer/PrivacyConsumer.xcarchive`
* macOS archive: `target/privacy-macos-consumer/PrivacyConsumer.xcarchive`
* Local ZIPs: `target/privacy-review-zips/`
* Build/check logs: `/tmp/mdk-privacy-audit/`

The actual archived resources are:

```text
iOS: Products/Applications/PrivacyConsumer.app/Frameworks/marmot_uniffiFFI.framework/PrivacyInfo.xcprivacy
macOS: Products/Applications/PrivacyConsumer.app/Contents/Frameworks/marmot_uniffiFFI.framework/Versions/A/Resources/PrivacyInfo.xcprivacy
```

| Local input/output | SHA-256 |
| --- | --- |
| Shared generated Swift | `4dc96f8f90c62105a517c4d954cd21cccab44aedfa2eea5af5c2b0e55e199c49` |
| Merged privacy resource | `3759ff2493741386342599b39673989a461f491ad1fb207a7133a2b0035140f7` |
| iOS device native archive | `0c4f3ece33d53ddec630f207a4199db991903b4dd6941929d441040c0d90a06f` |
| iOS simulator native archive | `8eebde78a16e44b796362c2320ad8ebbf15e36c30c93f4dc5722deba39ddeaa8` |
| macOS native archive | `22f650a5dcf0ae0fbc347160ee27348e74d4579cb799f20d9e559543bb10faab` |
| Local iOS ZIP | `dc4b85a7a8f0099b3e014ad85b72b42b5e5fde814d5ce32d881e32fd17b54428` |
| Local macOS ZIP | `78d7817e6f29f25d9ee9ffae19a27f761bb72b9979f6aefd9bb4e472046e8702` |

See [the audit](README.md) for the declaration evidence and unresolved purposes,
collector assumptions, SDK signing, and White Noise adoption instructions.

## User-supplied Xcode report

`PrivacyConsumer-PrivacyReport 2026-09-15 17-38-55.pdf` (one page), SHA-256
`c1da696a70ba6d4930ca52c19d05eacf064c6745c16d4d1302605d976b9e67ff`.
The complete page was extracted and visually inspected. This closes the iOS
Xcode collection-report check; the PDF does not contain required-reason API
entries and does not validate API purposes, actual collection behavior, SDK
signing, or App Store acceptance. The PDF remains in the user's Downloads;
it was not modified or committed to the repository.
