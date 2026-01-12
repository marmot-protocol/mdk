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

- Changed `get_messages()` to accept optional `limit` and `offset` parameters for pagination control. Existing calls must be updated to pass `None, None` for default behavior (limit: 1000, offset: 0), or specify values for custom pagination. ([#111](https://github.com/marmot-protocol/mdk/pull/111))
- Changed `get_pending_welcomes()` to accept optional `limit` and `offset` parameters for pagination control. Existing calls must be updated to pass `None, None` for default behavior (limit: 1000, offset: 0), or specify values for custom pagination. ([#119](https://github.com/marmot-protocol/mdk/pull/119))

### Changed

### Added

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