# Changelog

<!-- All notable changes to this project will be documented in this file. -->

<!-- The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), -->
<!-- and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). -->

<!-- Template

## Unreleased

### Breaking changes

### Changed

### Added

### Fixed

### Removed

### Deprecated

-->

## Unreleased

### Breaking changes

- **Secret Type Wrapper**: Secret values now use `Secret<T>` wrapper for automatic zeroization ([#109](https://github.com/marmot-protocol/mdk/pull/109))
  - `Group.image_key` changed from `Option<[u8; 32]>` to `Option<Secret<[u8; 32]>>`
  - `Group.image_nonce` changed from `Option<[u8; 12]>` to `Option<Secret<[u8; 12]>>`
  - `GroupExporterSecret.secret` changed from `[u8; 32]` to `Secret<[u8; 32]>`
  - `Welcome.group_image_key` changed from `Option<[u8; 32]>` to `Option<Secret<[u8; 32]>>`
  - `Welcome.group_image_nonce` changed from `Option<[u8; 12]>` to `Option<Secret<[u8; 12]>>`
  - Code accessing these fields must use `Secret::new()` to wrap values or dereference/clone to access inner values ([#109](https://github.com/marmot-protocol/mdk/pull/109))
- **BREAKING**: Changed `WelcomeStorage::pending_welcomes()` to accept `Option<Pagination>` parameter instead of having separate `pending_welcomes()` and `pending_welcomes_paginated()` methods ([#110](https://github.com/marmot-protocol/mdk/pull/110))
- **BREAKING**: Removed `MAX_PENDING_WELCOMES_OFFSET` constant - offset validation removed to allow legitimate large-scale use cases ([#110](https://github.com/marmot-protocol/mdk/pull/110))
- Changed `GroupStorage::messages()` to accept `Option<Pagination>` parameter instead of having separate `messages()` and `messages_paginated()` methods ([#111](https://github.com/marmot-protocol/mdk/pull/111))

### Changed

### Added

- **Secret Type and Zeroization**: Added `Secret<T>` wrapper type that automatically zeroizes memory on drop ([#109](https://github.com/marmot-protocol/mdk/pull/109))
  - Implements `Zeroize` trait for `[u8; 32]`, `[u8; 12]`, and `Vec<u8>`
  - Provides `Deref` and `DerefMut` for transparent access to wrapped values
  - Includes serde serialization support
  - Debug formatting hides secret values to prevent leaks
  - Comprehensive test suite including memory zeroization verification ([#109](https://github.com/marmot-protocol/mdk/pull/109))
- Added `Pagination` struct with `limit` and `offset` fields for cleaner pagination API - now part of public API for external consumers ([#110](https://github.com/marmot-protocol/mdk/pull/110), [#111](https://github.com/marmot-protocol/mdk/pull/111))
- Added `DEFAULT_MESSAGE_LIMIT` (1000) and `MAX_MESSAGE_LIMIT` (10,000) constants for pagination validation ([#111](https://github.com/marmot-protocol/mdk/pull/111))
- Added `DEFAULT_PENDING_WELCOMES_LIMIT` (1000) and `MAX_PENDING_WELCOMES_LIMIT` (10,000) constants for pagination validation ([#110](https://github.com/marmot-protocol/mdk/pull/110))
- Add tests for `admins()`, `messages()`, and `group_relays()` error cases when group not found ([#104](https://github.com/marmot-protocol/mdk/pull/104))

### Fixed

- **Security (Audit Issue Y)**: Secret values (encryption keys, nonces, exporter secrets) are now automatically zeroized when dropped, preventing memory leaks of sensitive cryptographic material ([#109](https://github.com/marmot-protocol/mdk/pull/109))
- **Security (Audit Issue Z)**: Added pagination to prevent memory exhaustion from unbounded loading of group messages ([#111](https://github.com/marmot-protocol/mdk/pull/111))
- **Security (Audit Issue AA)**: Added pagination to prevent memory exhaustion from unbounded loading of pending welcomes ([#110](https://github.com/marmot-protocol/mdk/pull/110))

### Removed

### Deprecated

## [0.5.1] - 2025-10-01

### Changed

- Update MSRV to 1.90.0 (required by openmls 0.7.1)
- Update openmls to 0.7.1

## [0.5.0] - 2025-09-10

**Note**: This is the first release as an independent library. Previously, this code was part of the `rust-nostr` project.

### Breaking changes

- Library split from rust-nostr into independent MDK (Marmot Development Kit) project
- Wrapped `GroupId` type to avoid leaking OpenMLS types
- Remove group type from groups
- Remove `save_group_relay` method ([#1056](https://github.com/rust-nostr/nostr/pull/1056))
- `image_hash` instead of `image_url` ([#1059](https://github.com/rust-nostr/nostr/pull/1059))

### Changed

- Upgrade openmls to v0.7.0

### Added

- Added `replace_group_relays` to make relay replace for groups an atomic operation ([#1056](https://github.com/rust-nostr/nostr/pull/1056))
- Comprehensive consistency testing framework for testing all mdk-storage-traits implementations for correctness and consistency ([#1056](https://github.com/rust-nostr/nostr/pull/1056))
- Added Serde support for GroupId

## v0.43.0 - 2025/07/28

No notable changes in this release.

## v0.42.0 - 2025/05/20

First release ([#836](https://github.com/rust-nostr/nostr/pull/836))
