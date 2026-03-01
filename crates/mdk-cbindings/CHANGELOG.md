# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Added

- Initial C ABI bindings for mdk-core with SQLite storage
- 33-function API surface mirroring mdk-uniffi exactly
- Opaque `MdkHandle` with mutex-based thread safety
- JSON serialization for complex types across FFI boundary
- Thread-local error message storage with `mdk_last_error_message()`
- Panic safety via `catch_unwind` on all extern "C" functions
- Null pointer guards on all pointer parameters
- `mdk_string_free` and `mdk_bytes_free` for memory management
- cbindgen-based header generation (`include/mdk.h`)
