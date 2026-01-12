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

- Updated `messages()` implementation to accept `Option<Pagination>` parameter ([#111](https://github.com/marmot-protocol/mdk/pull/111))
- Updated `pending_welcomes()` implementation to accept `Option<Pagination>` parameter ([#110](https://github.com/marmot-protocol/mdk/pull/110))

### Changed

- **Storage Security**: Updated to use `Secret<T>` wrapper for secret values from storage traits, ensuring automatic memory zeroization ([#109](https://github.com/marmot-protocol/mdk/pull/109))
- Simplified validation logic to use range contains pattern for better readability ([#111](https://github.com/marmot-protocol/mdk/pull/111))
- Simplified validation logic to use range contains pattern for better readability ([#110](https://github.com/marmot-protocol/mdk/pull/110))

### Added

- Implemented pagination support using `Pagination` struct for group messages ([#111](https://github.com/marmot-protocol/mdk/pull/111))
- Implemented pagination support using `Pagination` struct for pending welcomes ([#110](https://github.com/marmot-protocol/mdk/pull/110))

### Fixed

- **Security (Audit Issue 6/Suggestion 6)**: Improved `save_message` performance from O(n) to expected/amortized O(1) by replacing `Vec<Message>` with `HashMap<EventId, Message>` for the messages-by-group cache. This addresses potential DoS risk from high message counts per group (threat model T.10.2 and T.10.4). Fixes [#92](https://github.com/marmot-protocol/mdk/issues/92) ([#134](https://github.com/marmot-protocol/mdk/pull/134))
- **Security (Audit Issue Y)**: Secret values stored in memory are now wrapped in `Secret<T>` type, ensuring automatic memory zeroization and preventing sensitive cryptographic material from persisting in memory ([#109](https://github.com/marmot-protocol/mdk/pull/109))
- **Security (Audit Issue Z)**: Added pagination to prevent memory exhaustion from unbounded loading of group messages ([#111](https://github.com/marmot-protocol/mdk/pull/111))
- **Security (Audit Issue AA)**: Added pagination to prevent memory exhaustion from unbounded loading of pending welcomes ([#110](https://github.com/marmot-protocol/mdk/pull/110))
- **Security (Audit Issue AN)**: Fixed security issue where `save_message` would accept messages for non-existent groups, allowing cache pollution. Now verifies group existence before inserting messages into the cache. ([#113](https://github.com/marmot-protocol/mdk/pull/113))
- **Security (Audit Issue AO)**: Removed MLS group identifiers from error messages to prevent metadata leakage in logs and telemetry. Error messages now use generic "Group not found" instead of including the sensitive 32-byte MLS group ID. ([#112](https://github.com/marmot-protocol/mdk/pull/112))
- Fix `admins()` to return `InvalidParameters` error when group not found, instead of incorrectly returning `NoAdmins` ([#104](https://github.com/marmot-protocol/mdk/pull/104))
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
- Remove group type from groups
- Replaced `save_group_relay` with `replace_group_relays` trait method ([#1056](https://github.com/rust-nostr/nostr/pull/1056))
- `image_hash` instead of `image_url` ([#1059](https://github.com/rust-nostr/nostr/pull/1059))

### Changed

- Upgrade openmls to v0.7.0

## v0.43.0 - 2025/07/28

### Changed

- Bump lru from 0.14 to 0.16

## v0.42.0 - 2025/05/20

- First release ([#839](https://github.com/rust-nostr/nostr/pull/839))
