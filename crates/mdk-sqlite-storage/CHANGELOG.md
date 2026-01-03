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

### Changed

### Added

- Input validation for storage operations to prevent unbounded writes ([#94](https://github.com/marmot-protocol/mdk/pull/94))
  - Message content limited to 1MB
  - Group names limited to 255 bytes
  - Group descriptions limited to 2000 bytes
  - JSON fields limited to 50-100KB
  - New `Validation` error variant for validation failures

### Fixed

- **Security (Audit Issue AO)**: Removed MLS group identifiers from error messages to prevent metadata leakage in logs and telemetry. Error messages now use generic "Group not found" instead of including the sensitive 32-byte MLS group ID. ([#112](https://github.com/marmot-protocol/mdk/pull/112))
- **Security (Audit Issue AB)**: Added size limits to prevent disk and CPU exhaustion from unbounded user input ([#94](https://github.com/marmot-protocol/mdk/pull/94))
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
