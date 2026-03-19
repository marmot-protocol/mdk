# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Breaking changes

### Changed

### Added

- Initial C ABI bindings for mdk-core with SQLite storage ([#205](https://github.com/marmot-protocol/mdk/pull/205))
- 33-function API surface mirroring mdk-uniffi exactly ([#205](https://github.com/marmot-protocol/mdk/pull/205))
- Opaque `MdkHandle` with mutex-based thread safety ([#205](https://github.com/marmot-protocol/mdk/pull/205))
- JSON serialization for complex types across FFI boundary ([#205](https://github.com/marmot-protocol/mdk/pull/205))
- Thread-local error message storage with `mdk_last_error_message()` ([#205](https://github.com/marmot-protocol/mdk/pull/205))
- Panic safety via `catch_unwind` on all extern "C" functions ([#205](https://github.com/marmot-protocol/mdk/pull/205))
- Null pointer guards on all pointer parameters ([#205](https://github.com/marmot-protocol/mdk/pull/205))
- `mdk_string_free` and `mdk_bytes_free` for memory management ([#205](https://github.com/marmot-protocol/mdk/pull/205))
- cbindgen-based header generation (`include/mdk.h`) ([#205](https://github.com/marmot-protocol/mdk/pull/205))

### Fixed

### Removed

- Removed JavaScript bindings (`mdk-js` crate and `publish-js` CI job); JS is no longer a supported binding target ([#205](https://github.com/marmot-protocol/mdk/pull/205))

### Deprecated
