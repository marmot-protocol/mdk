# Changelog

All notable changes to `marmot-c` are tracked here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This crate uses semantic
versioning through the workspace version in the root `Cargo.toml`.

## [0.9.3] - 2026-07-08

### Added

- Added `marmot-c`, a stable C ABI over the Marmot app runtime for consumers that cannot pull in a UniFFI runtime
  (C/C++, and raw-FFI callers such as Zig, Nim, Go, Odin, Lua, and PHP). The crate builds a `cdylib` and a `staticlib`,
  ships a cbindgen-generated, checked-in `include/marmot.h`, and mirrors the full `marmot-uniffi` surface: account and
  session lifecycle, group operations, messaging, media, timeline, notifications, push, audit, relay health, agent text
  streams, and Markdown parsing.
- Every runtime record/enum has a `#[repr(C)]` mirror built from the `marmot-uniffi` `…Ffi` types, so the C shape can
  never drift from the Swift/Kotlin surface. Complex values cross the ABI as owned pointers freed only by their matching
  `marmot_*_free`; inputs are borrowed and never retained. Async runtime work runs on an embedded tokio runtime via
  blocking calls, and subscriptions expose both blocking `*_next` reads and callback registration.
- Added memory-safety scaffolding: an `alloc-audit` test feature that proves deep-free completeness, `catch_unwind` at
  every ABI boundary so panics never unwind into C, and a typed `MarmotStatus` code per `MarmotKitError` variant with a
  thread-local last-error detail channel.
- Added `marmot_download_group_blossom_image` (fetch + verify + decrypt the group's encrypted Blossom image to an owned
  byte buffer freed with `marmot_bytes_free`), completing the group-image surface alongside `image_hash_hex`. External
  signer accounts remain a documented gap pending a C callback-vtable design.
- Added packaging and cross-language verification: `c-bindings.sh` (staged libraries + header + pkg-config),
  `c-smoke.sh`, and seven worked example consumers (`examples/smoke.{c,zig,nim,go,odin,lua,php}`) exercised in CI, plus a
  `marmotc-v*` release track titled `v<version> - Marmot C`.

Closes [#328](https://github.com/marmot-protocol/mdk/issues/328)
