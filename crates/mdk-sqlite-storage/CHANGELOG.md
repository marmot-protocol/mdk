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

- **Security (Audit Issue M)**: Changed `MessageStorage::find_message_by_event_id()` to require both `mls_group_id` and `event_id` parameters. This prevents messages from different groups from overwriting each other. Database migration V105 changes the messages table primary key from `id` to `(mls_group_id, id)`. ([#124](https://github.com/marmot-protocol/mdk/pull/124))
- Updated `messages()` implementation to accept `Option<Pagination>` parameter ([#111](https://github.com/marmot-protocol/mdk/pull/111))
- Updated `pending_welcomes()` implementation to accept `Option<Pagination>` parameter ([#110](https://github.com/marmot-protocol/mdk/pull/110))

### Changed

- Upgraded `refinery` from 0.8 to 0.9 to align with OpenMLS dependencies ([#142](https://github.com/marmot-protocol/mdk/pull/142))
- **Storage Security**: Updated storage operations to use `Secret<T>` wrapper for secret values, ensuring automatic memory zeroization when values are dropped ([#109](https://github.com/marmot-protocol/mdk/pull/109))
- SQLite is now built with SQLCipher support (`bundled-sqlcipher`) instead of plain SQLite (`bundled`), enabling transparent AES-256 encryption at rest ([#102](https://github.com/marmot-protocol/mdk/pull/102))
- Simplified validation logic to use range contains pattern for better readability ([#111](https://github.com/marmot-protocol/mdk/pull/111))

### Added

- Input validation for storage operations to prevent unbounded writes ([#94](https://github.com/marmot-protocol/mdk/pull/94))
  - Message content limited to 1MB
  - Group names limited to 255 bytes
  - Group descriptions limited to 2000 bytes
  - JSON fields limited to 50-100KB
  - New `Validation` error variant for validation failures
- Automatic key management with `keyring-core`: `new()` constructor handles encryption key generation and secure storage automatically using the platform's native credential store (Keychain, Keystore, etc.) ([#102](https://github.com/marmot-protocol/mdk/pull/102))
- New `keyring` module with `get_or_create_db_key()` and `delete_db_key()` utilities ([#102](https://github.com/marmot-protocol/mdk/pull/102))
- New `encryption` module with `EncryptionConfig` struct and SQLCipher utilities ([#102](https://github.com/marmot-protocol/mdk/pull/102))
- New encryption-related error variants: `InvalidKeyLength`, `WrongEncryptionKey`, `UnencryptedDatabaseWithEncryption`, `KeyGeneration`, `FilePermission`, `Keyring`, `KeyringNotInitialized`, `KeyringEntryMissingForExistingDatabase` ([#102](https://github.com/marmot-protocol/mdk/pull/102))
- File permission hardening on Unix: database directories (0700) and files (0600) are created with owner-only access ([#102](https://github.com/marmot-protocol/mdk/pull/102))
- Implemented pagination support using `Pagination` struct for group messages ([#111](https://github.com/marmot-protocol/mdk/pull/111))
- Implemented pagination support using `Pagination` struct for pending welcomes ([#110](https://github.com/marmot-protocol/mdk/pull/110))

### Fixed

- **Security (Audit Issue M)**: Fixed messages being overwritten across groups due to non-scoped primary key. Changed messages table primary key from `id` to `(mls_group_id, id)` and updated `save_message()` to use `INSERT ... ON CONFLICT(mls_group_id, id) DO UPDATE` instead of `INSERT OR REPLACE`. This prevents an attacker or faulty relay from causing message loss and misattribution across groups by reusing deterministic rumor IDs. ([#124](https://github.com/marmot-protocol/mdk/pull/124))
- **Security (Audit Issue Y)**: Secret values stored in SQLite are now wrapped in `Secret<T>` type, ensuring automatic memory zeroization and preventing sensitive cryptographic material from persisting in memory ([#109](https://github.com/marmot-protocol/mdk/pull/109))
- **Security (Audit Issue Z)**: Added pagination to prevent memory exhaustion from unbounded loading of group messages ([#111](https://github.com/marmot-protocol/mdk/pull/111))
- **Security (Audit Issue AO)**: Removed MLS group identifiers from error messages to prevent metadata leakage in logs and telemetry. Error messages now use generic "Group not found" instead of including the sensitive 32-byte MLS group ID. ([#112](https://github.com/marmot-protocol/mdk/pull/112))
- **Security (Audit Issue AA)**: Added pagination to prevent memory exhaustion from unbounded loading of pending welcomes ([#110](https://github.com/marmot-protocol/mdk/pull/110))
- **Security (Audit Issue AB)**: Added size limits to prevent disk and CPU exhaustion from unbounded user input ([#94](https://github.com/marmot-protocol/mdk/pull/94))
- **Security (Audit Issue AG)**: `all_groups` now skips corrupted rows instead of failing on the first deserialization error, improving availability when database contains malformed data ([#115](https://github.com/marmot-protocol/mdk/pull/115))
- **Security (Audit Issue AO)**: Removed MLS group identifiers from error messages to prevent metadata leakage in logs and telemetry. Error messages now use generic "Group not found" instead of including the sensitive 32-byte MLS group ID. ([#112](https://github.com/marmot-protocol/mdk/pull/112))
- Propagate `last_message_id` parse errors in `row_to_group` instead of silently converting to `None` ([#105](https://github.com/marmot-protocol/mdk/pull/105))

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

No notable changes in this release.

## v0.42.0 - 2025/05/20

First release ([#842](https://github.com/rust-nostr/nostr/pull/842))
