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

- **Security (Audit Issue M)**: Changed `get_message()` to require both `mls_group_id` and `event_id` parameters. This prevents messages from different groups from overwriting each other by scoping lookups to a specific group. ([#124](https://github.com/marmot-protocol/mdk/pull/124))
- Renamed `Message.processed_at` to `Message.created_at` for semantic accuracy. The field represents when a message was created, not when it was processed by the system. ([`#163`](https://github.com/marmot-protocol/mdk/pull/163))

### Changed

- Upgraded `nostr` dependency from 0.43 to 0.44, replacing deprecated `Timestamp::as_u64()` calls with `Timestamp::as_secs()` ([#162](https://github.com/marmot-protocol/mdk/pull/162))
- Changed `get_messages()` to accept optional `limit` and `offset` parameters for pagination control. Existing calls must be updated to pass `None, None` for default behavior (limit: 1000, offset: 0), or specify values for custom pagination. ([#111](https://github.com/marmot-protocol/mdk/pull/111))
- Changed `get_pending_welcomes()` to accept optional `limit` and `offset` parameters for pagination control. Existing calls must be updated to pass `None, None` for default behavior (limit: 1000, offset: 0), or specify values for custom pagination. ([#119](https://github.com/marmot-protocol/mdk/pull/119))
- Changed `new_mdk()`, `new_mdk_with_key()`, and `new_mdk_unencrypted()` to accept an optional `MdkConfig` parameter for customizing MDK behavior. Existing calls must be updated to pass `None` for default behavior. ([`#155`](https://github.com/marmot-protocol/mdk/pull/155))

### Changed

### Added

- Added `MdkConfig` record for configuring MDK behavior, including `out_of_order_tolerance` and `maximum_forward_distance` settings for MLS sender ratchet configuration. All fields are optional and default to sensible values. ([`#155`](https://github.com/marmot-protocol/mdk/pull/155))
- Exposed pagination control for `get_messages()` to foreign language bindings via optional `limit` and `offset` parameters. ([#111](https://github.com/marmot-protocol/mdk/pull/111))
- Exposed pagination control for `get_pending_welcomes()` to foreign language bindings via optional `limit` and `offset` parameters. ([#119](https://github.com/marmot-protocol/mdk/pull/119))

### Fixed

- **Security**: Secret values in bindings now use `Secret<T>` wrapper for automatic memory zeroization, preventing sensitive cryptographic material from persisting in memory ([#109](https://github.com/marmot-protocol/mdk/pull/109))
- **Build**: Improved Android cross-compilation by requiring `ANDROID_OPENSSL_DIR` environment variable pointing to prebuilt OpenSSL libraries, with clear error messages explaining the required directory structure ([#140](https://github.com/marmot-protocol/mdk/pull/140))
- **Build**: Added `RANLIB` configuration for Android NDK toolchain to fix OpenSSL library installation ([#140](https://github.com/marmot-protocol/mdk/pull/140))
- **Build**: Added Rust target installation checks for both Android and iOS builds with helpful error messages showing how to install missing targets ([#140](https://github.com/marmot-protocol/mdk/pull/140))
- **Build**: Fixed Windows CI builds for Python and Ruby bindings by installing OpenSSL via vcpkg, resolving `libsqlite3-sys` build failures caused by missing `OPENSSL_DIR` ([#144](https://github.com/marmot-protocol/mdk/pull/144))

### Removed

### Deprecated

## [0.5.3] - 2025-12-09

First bindings release ([commit](https://github.com/marmot-protocol/mdk/commit/8d05c9b499564277bdd1d1fe27fcc702eadf4d54))
