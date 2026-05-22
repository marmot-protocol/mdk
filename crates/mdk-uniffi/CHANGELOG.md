# Changelog

<!-- All notable changes to this project will be documented in this file. -->

<!-- The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), -->
<!-- and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). -->

<!-- Template

## Unreleased

### Breaking changes

- **MIP-04 media records now include optional audio display metadata.** `EncryptedMediaUploadResult` and `MediaReferenceRecord` both add `duration_ms: Option<u64>` and `waveform: Option<Vec<u8>>`, allowing binding consumers to pass and receive typed audio duration and waveform metadata through IMETA tag creation/parsing. Callers constructing these records directly must provide the new fields. ([#300](https://github.com/marmot-protocol/mdk/pull/300))

### Changed

### Added

### Fixed

### Removed

### Deprecated

-->

## Unreleased

### Breaking changes

- **`Mdk::create_key_package_for_event_with_options` signature changed**: the third parameter is now `options: KeyPackageOptions` (a new UniFFI record) instead of `protected: bool`. The record carries both the existing `protected` flag and a new `existing_d_tag: Option<String>` field for `d` tag reuse during KeyPackage rotation. Binding consumers must update their call sites — replace e.g. `mdk.createKeyPackageForEventWithOptions(pubkey, relays, true)` with `mdk.createKeyPackageForEventWithOptions(pubkey, relays, KeyPackageOptions(protected = true, existingDTag = null))` (Kotlin) / equivalent in Swift / Python. Malformed `existing_d_tag` (non-empty / non-hex / wrong length) surfaces as `MdkUniffiError.InvalidInput` at the FFI boundary, matching how other parameter parsers in the binding report errors. `create_key_package_for_event` (the no-options variant) is unchanged. ([#303](https://github.com/marmot-protocol/mdk/pull/303))
- **`Mdk::create_group` gained a `disappearing_message_secs: Option<UInt64>` parameter** (after `admins`). `None` = disabled; `Some(n)` = expire `n` seconds after creation. `Some(0)` is rejected as `MdkUniffiError::InvalidInput`. Binding consumers must update their call sites. Part 2 of #253. ([#306](https://github.com/marmot-protocol/mdk/pull/306))
- **`GroupDataUpdate` gained `disappearing_message_secs: Option<Option<UInt64>>`**. Outer `None` = leave unchanged; `Some(None)` = disable; `Some(Some(n))` = set to `n` seconds. Binding consumers constructing `GroupDataUpdate` literals must include the new field. Part 2 of #253. ([#306](https://github.com/marmot-protocol/mdk/pull/306))

### Changed

- The `Group` UniFFI record now exposes `disappearing_message_secs: Option<UInt64>`, mirroring the new field on the core `Group` struct. Part 2 of #253. ([#306](https://github.com/marmot-protocol/mdk/pull/306))

### Added

- Added UniFFI bindings for group capability inspection and upgrades: `group_member_capabilities`, `group_capability_upgrade_status`, and `upgrade_group_capabilities`, plus binding-safe records and enums for member capability snapshots and upgrade readiness. ([#301](https://github.com/marmot-protocol/mdk/pull/301))
- Added the `KeyPackageOptions` UniFFI record (fields: `protected: Boolean`, `existing_d_tag: Option<String>`). Pass a previously stored `d_tag` (the value returned in `KeyPackageResult.d_tag`) via `existing_d_tag` to rotate a KeyPackage while keeping the NIP-33 addressable slot stable — no more post-editing the tag list before signing. The value is validated at the FFI boundary (exactly 64 ASCII hex characters per MIP-00) so callers see `MdkUniffiError.InvalidInput` directly on malformed input. ([#303](https://github.com/marmot-protocol/mdk/pull/303))
- Added UniFFI bindings for `delete_message`, `delete_messages_before_timestamp`, and `delete_processed_messages_for_group`, exposing the new granular deletion APIs to Kotlin and Swift consumers for disappearing-message cleanup. Part 3 of #253. ([#315](https://github.com/marmot-protocol/mdk/pull/315))

### Fixed

- Swift packaging now rebuilds C dependencies on every push by setting `cache-targets: false` on the `Swatinem/rust-cache` step in `package-swift`. Without this, the previous runner pin (#312) silently re-published byte-identical `libmdk_uniffi.a` archives, because the rust-cache key (`Darwin-arm64` + Cargo.lock hash + Rust version) stayed stable across the runner bump and restored the pre-existing macos-15 `target/` directory, including the already-compiled `libsqlite3-sys` / `secp256k1-sys` object files still tagged `sdk=18.5`. Registry / crate-source caching is unaffected. ([marmot-protocol/mdk-swift#1](https://github.com/marmot-protocol/mdk-swift/issues/1))
- Suppressed R8 minify warnings about missing `java.awt.*` classes referenced by JNA's `Native$AWT` helper. Added `-dontwarn java.awt.**` to the Kotlin consumer ProGuard rules so downstream Android apps with minification enabled no longer fail with `Missing class java.awt.Component` errors. ([#313](https://github.com/marmot-protocol/mdk/pull/313))
- Swift bindings now build on `macos-26` (Xcode 26) so the published xcframework's iOS Simulator slice is compiled against the iOS 26 SDK end-to-end. Previously the runner defaulted to `macos-15-arm64` + Xcode 16.4 (iPhoneSimulator 18.5 SDK), and the resulting archive mixed `sdk=18.5` and `sdk=26.x` objects — which Xcode 26's stricter linker rejected with a misleading "iOS Simulator-arm64 but ... iOS-arm64" platform-mismatch error when consumers built for an iOS 26 simulator target. ([`#312`](https://github.com/marmot-protocol/mdk/pull/312))
- Hardened the Kotlin bindings publishing workflow. The version-tag step now runs only on `v*` tag pushes, refuses to overwrite an existing remote tag (no more `git push --force`), and routes secrets through step `env:` blocks instead of inline expression substitution. Downstream JitPack consumers can now trust that a pinned Kotlin version maps to immutable artifact content. ([#292](https://github.com/marmot-protocol/mdk/pull/292))

### Removed

### Deprecated

## [0.8.0] - 2026-05-04

### Breaking changes

- **`KeyPackageResult` now includes `d_tag` and `tags_legacy`**: The `KeyPackageResult` struct returned by `create_key_package_for_event` and `create_key_package_for_event_with_options` now includes a `d_tag: String` field containing the 32-byte hex identifier for the KeyPackage slot. This enables callers to reuse the same `d` value when rotating KeyPackages so that relays automatically replace the old event. It also includes `tags_legacy`, which provides the tags without the `d` tag. Callers MUST dual-publish both `kind:30443` (using `tags`) and `kind:443` (using `tags_legacy`) through May 31, 2026 so that legacy clients can still discover new key packages. All test event builders updated to use `kind:30443`. ([#233](https://github.com/marmot-protocol/mdk/pull/233))
- `new_mdk_unencrypted()` is now gated behind the `test-utils` feature flag. Downstream consumers must enable the `test-utils` feature to access this function. ([#245](https://github.com/marmot-protocol/mdk/pull/245))
- `create_message` now takes an additional `event_tags` parameter (`Option<Vec<Vec<String>>>`) for appending allow-listed tags (e.g. NIP-40 `expiration`) to the outer kind:445 wrapper event. Pass `None` to preserve existing behavior. ([#248](https://github.com/marmot-protocol/mdk/pull/248))

### Changed

- Extracted `update_group_result_to_uniffi()` and `mdk_from_storage()` helpers to eliminate duplicated serialization and constructor logic across multiple exported functions. ([#239](https://github.com/marmot-protocol/mdk/pull/239))
- Simplified iterator collection patterns to use `.collect::<Result<_, _>>()` instead of two-step collect-then-unwrap. ([#239](https://github.com/marmot-protocol/mdk/pull/239))

### Added

- `new_mdk()` now auto-initializes the platform-native keyring-core credential store on first call (`OnceLock`-guarded). Callers no longer need to call `keyring_core::set_default_store()` manually. Platform stores: iOS (protected), macOS ARM (protected), macOS x86 (keychain), Android, Windows, Linux desktop via Secret Service; mock store in test builds. Headless/server Linux environments should configure a durable store explicitly or use `new_mdk_with_key()`. ([#252](https://github.com/marmot-protocol/mdk/pull/252))
- Exported `init_keyring_store()` via UniFFI for consumers who need early keyring initialization before constructing an MDK instance. ([#252](https://github.com/marmot-protocol/mdk/pull/252))
- Added UniFFI bindings for `group_required_proposals` and a mirror enum `MdkProposalType` covering `SelfRemove` and a forward-compat `Unknown` catch-all. Lets mobile consumers branch UI on per-group capability state (e.g. whether `SelfRemove` is available) without taking a direct `openmls` dependency on the binding side. Result order is deterministic (`Vec<MdkProposalType>` built from the underlying `BTreeSet`). The `From<ProposalType>` mapping enumerates every openmls variant explicitly — no wildcard arm — so an openmls bump that adds a proposal type fails to compile rather than silently collapsing to `Unknown`. ([#265](https://github.com/marmot-protocol/mdk/pull/265))
- Added UniFFI bindings for `delete_messages_for_group` and `delete_group` for local "clear chat" and "delete chat" operations. ([#250](https://github.com/marmot-protocol/mdk/pull/250))
- Added UniFFI bindings for 10 previously unbound methods: `delete_key_package_from_storage`, `delete_key_package_from_storage_by_hash_ref`, `get_ratchet_tree_info`, `group_leaf_map`, `own_leaf_index`, `pending_added_members_pubkeys`, `pending_member_changes`, `pending_removed_members_pubkeys`, `prepare_group_image_for_upload_with_options`, and `process_message_with_context`. ([#249](https://github.com/marmot-protocol/mdk/pull/249))
- Added optional `thumbhash` fields alongside the existing `blurhash` UniFFI records for group-image and encrypted-media uploads, plus a `generate_thumbhash` option in `MediaProcessingOptionsInput`. ([#244](https://github.com/marmot-protocol/mdk/pull/244))
- Moved binary size optimizations (`opt-level = "z"`, thin LTO, single codegen unit, `panic = "abort"`, symbol stripping) into `[profile.release]` directly. Android builds override to fat LTO via `CARGO_PROFILE_RELEASE_LTO=fat` for maximum `.so` reduction; iOS uses thin LTO to avoid `.a` archive bloat. ([#221](https://github.com/marmot-protocol/mdk/pull/221), [#232](https://github.com/marmot-protocol/mdk/pull/232))

### Fixed

- Allowed failed platform keyring auto-initialization attempts to be retried, so a transient keyring failure does not permanently block `new_mdk()` in the current process. ([#252](https://github.com/marmot-protocol/mdk/pull/252))
- Removed the Swift package's explicit system `sqlite3` link and linked the native frameworks required by the bundled SQLCipher provider instead. ([#252](https://github.com/marmot-protocol/mdk/pull/252))
- Removed redundant `cargo build` steps from Swift, Python, and Ruby binding CI jobs that duplicated work already done by `_build-uniffi`. ([#232](https://github.com/marmot-protocol/mdk/pull/232))
- Fixed stale `release-size` artifact paths in Kotlin and Swift binding generation recipes. ([#232](https://github.com/marmot-protocol/mdk/pull/232))
- Unbroke binding builds on Linux: switched `[profile.release].strip` from `true` to `"debuginfo"` so `uniffi-bindgen --library` can still read `UNIFFI_META_*` symbols from the cdylib's `.symtab` (GNU strip's `--strip-all` was removing them, which silently produced empty Kotlin/Ruby/Python binding output). DWARF debug info is still stripped, so the binary-size cost is small. ([#267](https://github.com/marmot-protocol/mdk/pull/267))
- Switched iOS bindings to fat LTO (`CARGO_PROFILE_RELEASE_LTO=fat`, mirroring Android) so the static `.a` archives no longer embed per-module thin-LTO bitcode. This shrinks `libmdk_uniffi.a` back below GitHub's 100 MB push limit. The Swift package workflow also configures `git lfs track "*.a"` as a defensive safety net. ([#267](https://github.com/marmot-protocol/mdk/pull/267))
- **Security**: `scripts/build-openssl-android.sh` now verifies the upstream OpenSSL release tarball against a pinned SHA-256 before extraction, and aborts when no hash is recorded for the requested version. Without this check, a tampered tarball (poisoned CDN, MITM, or compromised GitHub release) would have been linked into the `mdk-uniffi` Android shared library. ([#290](https://github.com/marmot-protocol/mdk/pull/290))

### Removed

### Deprecated

## [0.7.1] - 2026-03-05

## [0.7.0] - 2026-03-04

### Breaking changes

### Changed

- `MdkConfig` now includes a `max_past_epochs: Option<u32>` field (defaults to `5` when `None`) that controls how many past MLS epoch message secrets are retained for late message decryption. ([#207](https://github.com/marmot-protocol/mdk/pull/207))

### Added

- `max_past_epochs` field to the `MdkConfig` UniFFI record, allowing callers to configure past-epoch message decryption tolerance. ([#207](https://github.com/marmot-protocol/mdk/pull/207))
- MIP-04 encrypted media support: five new methods on `Mdk` — `encrypt_media_for_upload`, `encrypt_media_for_upload_with_options`, `decrypt_media_from_download`, `create_media_imeta_tag`, and `parse_media_imeta_tag` — plus three new UniFFI records: `EncryptedMediaUploadResult`, `MediaReferenceRecord`, and `MediaProcessingOptionsInput`. The `mip04` feature is now always active in the UniFFI crate. ([#215](https://github.com/marmot-protocol/mdk/pull/215))

### Fixed

### Removed

### Deprecated

## [0.6.0] - 2026-02-18

### Breaking changes

- **Self-update tracking field change**: The `Group` record's `needs_self_update: bool` and `last_self_update_at: Option<u64>` fields have been replaced with a single `self_update_state: String` field. Values are `"required"` (post-join obligation) or `"completed_at:<unix_timestamp>"` (last rotation time). ([#184](https://github.com/marmot-protocol/mdk/pull/184))
- **`KeyPackageResult` now includes `hash_ref`**: The `KeyPackageResult` struct returned by `create_key_package_for_event` and `create_key_package_for_event_with_options` now includes a `hash_ref: Vec<u8>` field containing the serialized hash reference of the key package. This enables callers to track key packages for lifecycle management without re-parsing. ([#178](https://github.com/marmot-protocol/mdk/pull/178))
- **`create_key_package_for_event` No Longer Adds Protected Tag**: The `create_key_package_for_event()` function no longer adds the NIP-70 protected tag by default. This is a behavioral change - existing code that relied on the protected tag being present will now produce key packages without it. Key packages can now be republished by third parties to any relay. For users who need the protected tag, use the new `create_key_package_for_event_with_options()` function with `protected: true`. ([#173](https://github.com/marmot-protocol/mdk/pull/173), related: [#168](https://github.com/marmot-protocol/mdk/issues/168))
- **Security (Audit Issue M)**: Changed `get_message()` to require both `mls_group_id` and `event_id` parameters. This prevents messages from different groups from overwriting each other by scoping lookups to a specific group. ([#124](https://github.com/marmot-protocol/mdk/pull/124))
- Renamed `Message.processed_at` to `Message.created_at` for semantic accuracy. The field represents when a message was created, not when it was processed by the system. ([#163](https://github.com/marmot-protocol/mdk/pull/163))

### Changed

- Upgraded `nostr` dependency from 0.43 to 0.44, replacing deprecated `Timestamp::as_u64()` calls with `Timestamp::as_secs()` ([#162](https://github.com/marmot-protocol/mdk/pull/162))
- Changed `get_messages()` to accept optional `limit` and `offset` parameters for pagination control. Existing calls must be updated to pass `None, None` for default behavior (limit: 1000, offset: 0), or specify values for custom pagination. ([#111](https://github.com/marmot-protocol/mdk/pull/111))
- Changed `get_pending_welcomes()` to accept optional `limit` and `offset` parameters for pagination control. Existing calls must be updated to pass `None, None` for default behavior (limit: 1000, offset: 0), or specify values for custom pagination. ([#119](https://github.com/marmot-protocol/mdk/pull/119))
- Changed `new_mdk()`, `new_mdk_with_key()`, and `new_mdk_unencrypted()` to accept an optional `MdkConfig` parameter for customizing MDK behavior. Existing calls must be updated to pass `None` for default behavior. ([#155](https://github.com/marmot-protocol/mdk/pull/155))

### Added

- **`clear_pending_commit` method**: Added `clear_pending_commit(group_id)` to allow callers to roll back an uncommitted pending MLS commit. ([#196](https://github.com/marmot-protocol/mdk/pull/196))
- **`groups_needing_self_update()` method**: Returns hex-encoded group IDs of active groups that need a self-update (post-join obligation or stale rotation), given a threshold in seconds. ([#184](https://github.com/marmot-protocol/mdk/pull/184))
- **Custom Message Sort Order**: `get_messages()` now accepts an optional `sort_order` parameter (`"created_at_first"` or `"processed_at_first"`) to control message ordering. Defaults to `"created_at_first"` when omitted. ([#171](https://github.com/marmot-protocol/mdk/pull/171))
- **Last Message by Sort Order**: Added `get_last_message(mls_group_id, sort_order)` method to retrieve the most recent message under a given sort order, so clients using `"processed_at_first"` can get a "last message" consistent with their `get_messages()` ordering. ([#171](https://github.com/marmot-protocol/mdk/pull/171))
- **`create_key_package_for_event_with_options`**: New function that allows specifying whether to include the NIP-70 protected tag. Use this if you need to publish to relays that accept protected events. ([#173](https://github.com/marmot-protocol/mdk/pull/173), related: [#168](https://github.com/marmot-protocol/mdk/issues/168))
- **Group `last_message_processed_at` Field**: The `Group` record now includes an optional `last_message_processed_at: u64` field (Unix timestamp) indicating when the last message was received/processed by this client. This complements `last_message_at` (sender's timestamp) and ensures `last_message_id` is consistent with the first message returned by `get_messages()`. ([#166](https://github.com/marmot-protocol/mdk/pull/166))
- **Message `processed_at` Field**: The `Message` record now includes a `processed_at: u64` field (Unix timestamp) indicating when this client received/processed the message. This complements the existing `created_at` field (sender's timestamp) and helps clients handle clock skew between devices - messages can now be displayed in reception order if desired. ([#166](https://github.com/marmot-protocol/mdk/pull/166))
- **`PreviouslyFailed` Result Variant**: Added `ProcessMessageResult.PreviouslyFailed` enum variant to handle cases where a previously failed message arrives again but the MLS group ID cannot be extracted. This prevents crashes in client applications (fixes [#153](https://github.com/marmot-protocol/mdk/issues/153)) by returning a result instead of throwing an exception. ([#165](https://github.com/marmot-protocol/mdk/pull/165), fixes [#154](https://github.com/marmot-protocol/mdk/issues/154), [#159](https://github.com/marmot-protocol/mdk/issues/159))
- Added `MdkConfig` record for configuring MDK behavior, including `out_of_order_tolerance` and `maximum_forward_distance` settings for MLS sender ratchet configuration. All fields are optional and default to sensible values. ([#155](https://github.com/marmot-protocol/mdk/pull/155))
- Exposed pagination control for `get_messages()` to foreign language bindings via optional `limit` and `offset` parameters. ([#111](https://github.com/marmot-protocol/mdk/pull/111))
- Exposed pagination control for `get_pending_welcomes()` to foreign language bindings via optional `limit` and `offset` parameters. ([#119](https://github.com/marmot-protocol/mdk/pull/119))

### Fixed

- **Security**: Secret values in bindings now use `Secret<T>` wrapper for automatic memory zeroization, preventing sensitive cryptographic material from persisting in memory ([#109](https://github.com/marmot-protocol/mdk/pull/109))
- **Build**: Improved Android cross-compilation by requiring `ANDROID_OPENSSL_DIR` environment variable pointing to prebuilt OpenSSL libraries, with clear error messages explaining the required directory structure ([#140](https://github.com/marmot-protocol/mdk/pull/140))
- **Build**: Added `RANLIB` configuration for Android NDK toolchain to fix OpenSSL library installation ([#140](https://github.com/marmot-protocol/mdk/pull/140))
- **Build**: Added Rust target installation checks for both Android and iOS builds with helpful error messages showing how to install missing targets ([#140](https://github.com/marmot-protocol/mdk/pull/140))
- **Build**: Fixed Windows CI builds for Python and Ruby bindings by installing OpenSSL via vcpkg, resolving `libsqlite3-sys` build failures caused by missing `OPENSSL_DIR` ([#144](https://github.com/marmot-protocol/mdk/pull/144))
- **Build**: Fixed Windows linker errors for Python and Ruby bindings by adding missing `crypt32` and `user32` system library links required by statically-linked OpenSSL ([#172](https://github.com/marmot-protocol/mdk/pull/172))

## [0.5.3] - 2025-12-09

First bindings release ([commit](https://github.com/marmot-protocol/mdk/commit/8d05c9b499564277bdd1d1fe27fcc702eadf4d54))
