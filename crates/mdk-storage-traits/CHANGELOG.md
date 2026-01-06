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

- **BREAKING**: Changed `WelcomeStorage::pending_welcomes()` to accept `Option<Pagination>` parameter for pagination control ([#110](https://github.com/marmot-protocol/mdk/pull/110))

### Changed

### Added

- Added `Pagination` struct with `limit` and `offset` fields for cleaner pagination API - now part of public API for external consumers ([#110](https://github.com/marmot-protocol/mdk/pull/110))
- Added `DEFAULT_PENDING_WELCOMES_LIMIT` (1000) and `MAX_PENDING_WELCOMES_LIMIT` (10,000) constants for pagination validation ([#110](https://github.com/marmot-protocol/mdk/pull/110))
- Add tests for `admins()`, `messages()`, and `group_relays()` error cases when group not found ([#104](https://github.com/marmot-protocol/mdk/pull/104))

### Fixed

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
