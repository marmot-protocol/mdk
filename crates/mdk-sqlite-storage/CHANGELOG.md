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

- **BREAKING**: Updated `pending_welcomes()` implementation to accept `Option<Pagination>` parameter ([#110](https://github.com/marmot-protocol/mdk/pull/110))

### Changed

- Simplified validation logic to use range contains pattern for better readability ([#110](https://github.com/marmot-protocol/mdk/pull/110))
- SQLite is now built with SQLCipher support (`bundled-sqlcipher`) instead of plain SQLite
  (`bundled`). This enables transparent AES-256 encryption of the database at rest. Encryption is now always enabled (no feature flag required). SQLCipher dependencies are
  always included. ([#102](https://github.com/marmot-protocol/mdk/pull/102))

### Added

- Input validation for storage operations to prevent unbounded writes ([#94](https://github.com/marmot-protocol/mdk/pull/94))
  - Message content limited to 1MB
  - Group names limited to 255 bytes
  - Group descriptions limited to 2000 bytes
  - JSON fields limited to 50-100KB
  - New `Validation` error variant for validation failures
- Implemented pagination support using `Pagination` struct for pending welcomes ([#110](https://github.com/marmot-protocol/mdk/pull/110))
- **Automatic key management with `keyring-core`**: The primary constructor `new()` now handles
  encryption key generation and secure storage automatically. Keys are stored in the platform's
  native credential store. ([#102](https://github.com/marmot-protocol/mdk/pull/102))
- New `keyring` module with secure key storage utilities: ([#102](https://github.com/marmot-protocol/mdk/pull/102))
  - `get_or_create_db_key()` - Retrieve or generate encryption key from keyring
  - `delete_db_key()` - Remove key from keyring (for re-keying or cleanup)
- **SQLCipher encryption support**: All databases are encrypted using SQLCipher with AES-256. ([#102](https://github.com/marmot-protocol/mdk/pull/102))
- New `EncryptionConfig` struct for direct key management: ([#102](https://github.com/marmot-protocol/mdk/pull/102))
  - `EncryptionConfig::new(key)` - Create config from a 32-byte key
  - `EncryptionConfig::from_slice(key)` - Create config from a byte slice
  - `EncryptionConfig::generate()` - Generate a random key
- New `encryption` module with SQLCipher utilities: ([#102](https://github.com/marmot-protocol/mdk/pull/102))
  - `apply_encryption()` - Apply encryption to a connection
  - `is_database_encrypted()` - Check if a database file is encrypted
- New error variants: ([#102](https://github.com/marmot-protocol/mdk/pull/102))
  - `Error::InvalidKeyLength` - Key is not 32 bytes
  - `Error::WrongEncryptionKey` - Database cannot be decrypted with the provided key
  - `Error::EncryptedDatabaseRequiresKey` - Encrypted database opened without a key
  - `Error::UnencryptedDatabaseWithEncryption` - Unencrypted database opened with a key
  - `Error::KeyGeneration` - Failed to generate random key
  - `Error::FilePermission` - File permission error
  - `Error::Keyring` - Keyring operation failed
  - `Error::KeyringNotInitialized` - No keyring store has been set up
- File permission hardening on Unix platforms: ([#102](https://github.com/marmot-protocol/mdk/pull/102))
  - Database directories are created with mode 0700 (owner-only access)
  - Database files are set to mode 0600 (owner read/write only)
  - SQLite sidecar files (-wal, -shm, -journal) also receive secure permissions

### Fixed

- **Security (Audit Issue AA)**: Added pagination to prevent memory exhaustion from unbounded loading of pending welcomes ([#110](https://github.com/marmot-protocol/mdk/pull/110))
- **Security (Audit Issue AB)**: Added size limits to prevent disk and CPU exhaustion from unbounded user input ([#94](https://github.com/marmot-protocol/mdk/pull/94))
- **Security (Audit Issue AG)**: `all_groups` now skips corrupted rows instead of failing on the first deserialization error, improving availability when database contains malformed data ([#115](https://github.com/marmot-protocol/mdk/pull/115))
- **Security (Audit Issue AO)**: Removed MLS group identifiers from error messages to prevent metadata leakage in logs and telemetry. Error messages now use generic "Group not found" instead of including the sensitive 32-byte MLS group ID. ([#112](https://github.com/marmot-protocol/mdk/pull/112))
  - Propagate `last_message_id` parse errors in `row_to_group` instead of silently converting to `None` ([#105](https://github.com/marmot-protocol/mdk/pull/105))
  - Added size limits to prevent disk and CPU exhaustion from unbounded user input ([#94](https://github.com/marmot-protocol/mdk/pull/94))

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
