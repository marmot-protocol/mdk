# MarmotKit Apple privacy audit

Audit baseline: MDK `b7dc47b12c640a99ed352ef451e0d3430d8d34be`, Cargo.lock,
Rust 1.97.1, Xcode 27.0 (27A266a), 2026-09-15. This change is for review;
**it is not an App Store acceptance or release-readiness assertion.**

## Findings and declarations

The SDK manifest covers behavior available in the binary, including optional
host-triggered uploads. Disabling a runtime setting does not remove a declaration.
`product-analytics.plist` is merged only when `PRODUCT_ANALYTICS_EXPORT=1` (or
`true`), matching the Rust feature. OTLP adds no new data categories beyond the
always-built forensic uploader, so both OTLP feature variants use the base file.
All declared collection is non-tracking. There is no advertising/broker use in
the audited SDK. Collector URLs are not tracking domains merely because they
receive diagnostics.

| Declaration | Code/dependency behavior | Purpose and linkage |
| --- | --- | --- |
| FileTimestamp / C617.1 | `fs-private/src/lib.rs` and `marmot-account/src/io.rs` inspect file type, size and permissions; `storage-sqlite` uses SQLCipher VFS metadata; `marmot-app/src/audit_log.rs::audit_log_files` and `AuditUploadSnapshot::capture` read modification time for local enumeration/checkpoints. | App/app-group container storage. Hosts must keep SDK roots, temporary storage and imported local paths inside those containers. Arbitrary macOS paths need a separate purpose review. |
| UserID | `audit_log.rs::audit_account_ref_hex` derives a stable account hash; forensic rows include it. `directory/methods.rs` publishes signed public profile and follow-list records. | AppFunctionality, linked. Hashing a public account key does not make it anonymous. |
| DeviceID | `audit_log.rs::audit_device_id_hex` persists a per-account-device random ID; `AuditSourceContext` uploads it. OTLP `resource_attributes` sends `service.instance.id`. | AppFunctionality, linked; opt-in does not eliminate disclosure. Analytics purpose added for the product pipeline's documented daily activity grouping. |
| PerformanceData | Audit event durations in `marmot-forensics/src/audit.rs`; OTLP `relay_telemetry_export.rs` exports startup, operation and relay latency histograms. | AppFunctionality, linked through account/device or service-instance metadata. Product export adds Analytics for duration buckets. |
| OtherDiagnosticData | V4 forensic state/transport evidence, relay URLs and identifiers, errors, counts, hardware model/platform/app version; OTLP counters and resource attributes. | AppFunctionality, linked; product export adds Analytics for outcome buckets and system metadata. No crash-log collector was found; do not relabel these records CrashData. |
| ProductInteraction | V4 `AuditHumanActionContext` accompanies diagnostic records. With product export, `product_analytics/mod.rs::enqueue` exports approved journey events and bucketed feature activity with temporary session IDs. | AppFunctionality for forensic diagnosis; Analytics added for product export. Linked because the base audit stream carries account/device identifiers; the manifest reports the union of uses for this data type. |
| Name, PhotosorVideos, OtherUserContent, OtherUserContactInfo | `directory/records.rs::UserProfileMetadata` / `profile_content_json`: name/display name, picture/banner, about/extra fields, NIP-05/Lightning contact addresses. `runtime/mod.rs::upload_profile_image` uploads a public image to Blossom. | AppFunctionality, linked to the signed public account identity. These are SDK publication APIs, not diagnostic uploads. No email or phone collection is inferred from an address-shaped NIP-05/Lightning identifier. |
| EmailsOrTextMessages | Forensic `OutboundMessage`, `RecipientExpectation` and `ConvergenceAppWitness` carry message references and salted sender/recipient references in uploaded evidence. | AppFunctionality, linked to audit account/device. This covers communication metadata, not a claim that the SDK uploads message plaintext. Apple includes sender/recipient information in this data type. |
| Contacts | `directory/methods.rs::publish_account_follow_list` publishes the user's public social graph (kind 3). | AppFunctionality, linked. No address-book permission/API is involved. |
| CoarseLocation (product feature only) | `product_analytics/mod.rs::USAGE_DIAGNOSTICS_DISCLOSURE` explicitly describes Aptabase IP/user-agent daily grouping and country/region enrichment. | Analytics. Linked is conservative for the documented device/day grouping, not a claim of GPS access. The host/operator must verify the receiving deployment's enrichment, retention and anti-linkage policy before release. |

Paths above are relative to `crates/`. All base collection entries use
`NSPrivacyCollectedDataTypeLinked=true`, `NSPrivacyCollectedDataTypeTracking=false`.
No UserDefaults, ActiveKeyboards or DiskSpace declaration is fabricated.

## Native API investigation and unresolved release questions

* Both freshly downloaded 0.9.21 iOS and macOS binary ZIPs passed their published
  SHA-256 checks and contain **zero** `.xcprivacy` files. Their provenance records
  identify `fdd398a80f1626f1713787cebe416f7890b5b204`, with both exporters enabled.
  The current tree also had no manifest/resource path. The older local
  `dcb3c1c3772ab52187b92932382019231188c814` build was not used as current evidence.
* The locked SQLCipher amalgamation is `libsqlite3-sys` 0.38.1 from rusqlite
  revision `5ae7fdf83085c595fd54f977b3a56ccacabaf16b`. In `sqlite3.c`,
  `autolockIoFinderImpl` uses `statfs` for filesystem type/read-only status;
  `unixOpen` uses `fstatfs` for msdos/exfat flags and proxy-lock decisions;
  `proxyTransformUnixFile` checks read-only status when a conch file is missing.
  `proxyTakeConch` uses file modification times to detect a stale lock.
  None of these paths checks free capacity or provides low-space UX.
  **DiskSpace is unresolved:** Apple's listed APIs include statfs/fstatfs, but
  the published reasons do not describe this locking/flags use. Do not select
  E174.1. Obtain an approved reason/clarification from Apple or implement a
  separately reviewed dependency solution before claiming complete required-
  reason compliance. Do not disable locking or interpose fake filesystem data.
* `stat`, `fstat`, `lstat`, and (where present) `fstatat` are leads, not proof of
  timestamp collection. Rust filesystem code and SQLCipher inspect metadata.
  OpenSSL also contains file/config/certificate metadata paths; its command-line
  tools are not SDK entry points. Check final linked executables as well as the
  full static archive: dead-stripping and the selected entry points matter.
  OpenSSL automatic configuration loading and random-device file checks may
  touch paths outside app containers. C617.1 is not blanket coverage for those
  paths: confirm their reachability/default configuration in the shipping app
  before claiming complete file-metadata purpose coverage.
* No `mach_absolute_time`/`systemUptime` reference was found in the inspected
  0.9.21 iOS archive or current iOS device archive. Rust timers alone are not
  evidence of Apple's SystemBootTime API. There is no boot-time declaration.
* OpenSSL **is on Apple's current SDK list**, and Cargo.lock bundles OpenSSL
  3.6.2 via `openssl-src` 300.6.0+3.6.2 for SQLCipher. MarmotKit is not named on
  that list. Apple's rule also addresses repackaged listed SDKs. Resolve
  release XCFramework signing with the release owner; these local unsigned
  artifacts and Git commit signatures do not establish SDK signature compliance.
* SDK profile `extra` fields are extensible. Hosts that solicit specific sensitive
  fields must review those data types; OtherUserContent does not cover every
  possible host-designed form. Host bot/agent integrations or recipients that
  can read private messages also need their own collection assessment. Encrypted
  message/media relay storage is not asserted here to be readable diagnostic
  collection. The host must assess its messaging/privacy label, including
  recipients and services, under Apple's guidance for private messaging.
* No live collector was inspected. Default route strings and successful HTTP
  requests cannot prove server retention, enrichment, or whether operators
  combine records. Hosts remain responsible for their configured collectors,
  disclosure/consent, App Store privacy answers and native APIs outside MDK.
  Local audit files alone are not collection; uploading them is.

## Packaging contract

Raw `.a` slices cannot carry resources. Each exporter now stages a static
`marmot_uniffiFFI.framework` around the **byte-identical Cargo archive**, with
the generated header and a framework-form module map preserving the C module
name. It does not regenerate or edit Swift API declarations. `xcodebuild
-create-xcframework -framework` packages these resource-bearing slices:

* iOS/device and simulator: framework root `PrivacyInfo.xcprivacy`.
* macOS: `Versions/A/Resources/PrivacyInfo.xcprivacy`, with versioned framework
  symlinks.

Privacy inputs come from the **packaged source checkout** (`MARMOTKIT_CRATE_DIR`),
not the workflow builder's newer declarations. Building an older snapshot that
lacks these inputs fails rather than attaching current claims to an old binary.
ZIP checksums cover the resources as well as code. No generated files or binaries
are committed, no version is bumped, and no existing release is modified.

Xcode 15+ supports linking and embedding static frameworks while omitting the
static binary from the embedded resource bundle. A standalone `.a`, copied ZIP,
or a successful SwiftPM library link is not archive evidence.

## Validation and host adoption

Run the resource-loss tests and both platform validators. For full artifact and
app-archive checks (XcodeGen is required; local validation used 2.44.1):

```sh
python3 crates/marmot-uniffi/test-apple-privacy.py
OTLP_EXPORT=1 PRODUCT_ANALYTICS_EXPORT=1 ./crates/marmot-uniffi/xcframework.sh
OTLP_EXPORT=1 PRODUCT_ANALYTICS_EXPORT=1 ./crates/marmot-uniffi/xcframework-macos.sh
./crates/marmot-uniffi/validate-ios-artifact.sh crates/marmot-uniffi/output/MarmotKit.xcframework 18.0
./crates/marmot-uniffi/validate-macos-artifact.sh crates/marmot-uniffi/output/macos/MarmotKit.xcframework 15.0
python3 crates/marmot-uniffi/validate-apple-archive.py ios crates/marmot-uniffi/output/MarmotKit.xcframework crates/marmot-uniffi/output/MarmotKit.swift /tmp/mdk-ios-privacy-consumer
python3 crates/marmot-uniffi/validate-apple-archive.py macos crates/marmot-uniffi/output/macos/MarmotKit.xcframework crates/marmot-uniffi/output/macos/MarmotKit.swift /tmp/mdk-macos-privacy-consumer
```

The archive validator also accepts the packaged `.xcframework.zip` in place of
the XCFramework directory; use that ZIP for release validation. Pass
`--privacy-dir <packaged-source>/crates/marmot-uniffi/apple-privacy` when the
source differs from the builder, and `--product-analytics 1` (or `0`) to require
the declarations for the built feature. The shell artifact validators honor
`MARMOTKIT_CRATE_DIR` and, when supplied, `PRODUCT_ANALYTICS_EXPORT`.

Each archive work directory must be new. The generated test app has no host
privacy manifest or custom resource-copy phase. CI builds the consumer from the packaged SwiftPM ZIP before
uploading Apple artifacts. macOS uses ad-hoc signing and strict signature
verification. The device iOS fixture is unsigned because development signing
requires a certificate/profile; a signed host archive remains a release check. The checker inspects only `Products/Applications`
in the archive and compares the embedded SDK manifest to the artifact's manifest.
It fails if resources exist only in the input XCFramework or DerivedData.

After resolving the release questions above and publishing a **new immutable**
release, White Noise should:

1. Update its existing binding synchronization flow to pin the new exact tag,
   verify ZIP SHA-256/SwiftPM checksums and source/builder provenance, and update
   Swift source and platform binary together. Do not reuse a 0.9.21 URL/checksum.
2. Preserve the complete XCFramework and its versioned macOS symlinks. Do not
   extract just the archive or copy a manifest beside the library.
3. For direct Xcode integration, link and **Embed & Sign** the static framework
   using Xcode 15+. For SwiftPM, validate the final app archive; do not assume
   the source target's successful link proves resource propagation. Update any
   consumer scripts that assume `HeadersPath` or a `.a` slice layout.
4. Keep the host's manifest and review its app/app-group file access, app-owned
   collection and extensions separately. Keep MDK's root in an app/app-group
   container. Verify each app/extension that links the SDK contains the resource.
   **The SDK manifest does not declare DiskSpace:** SQLCipher's `statfs`/`fstatfs`
   purpose remains unresolved. Resolve that before App Store submission; a green
   resource check does not close it. Adding a host declaration is valid only if
   its approved reason actually covers those native calls. Do not substitute a
   host low-disk-space feature for SQLCipher's unrelated locking/filesystem use.
5. Run `validate-apple-privacy.py <new.xcframework> --archive <host.xcarchive>`.
   In Organizer choose **Generate Privacy Report** and compare its aggregated
   collection to consent screens, policy, configured services and App Store
   privacy answers. A local archive/report does not validate an App Store upload.

## Official sources verified 2026-09-15

* [Manifest placement and static-library migration](https://developer.apple.com/documentation/bundleresources/adding-a-privacy-manifest-to-your-app-or-third-party-sdk)
* [Static framework embedding](https://developer.apple.com/documentation/xcode/creating-a-static-framework)
* [Required-reason policy](https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api)
* [API categories and approved reasons](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacyaccessedapitypes/nsprivacyaccessedapitype)
* [Data types](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacycollecteddatatypes/nsprivacycollecteddatatype) and [purposes](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacycollecteddatatypes/nsprivacycollecteddatatypepurposes)
* [SDK list and repackaging rule](https://developer.apple.com/support/third-party-SDK-requirements/)
* [Collection, linkage, opt-in and private messaging guidance](https://developer.apple.com/app-store/app-privacy-details/)
* [Xcode privacy report](https://developer.apple.com/documentation/bundleresources/describing-data-use-in-privacy-manifests)
