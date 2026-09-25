# Changelog

## Unreleased

### Fixed

- Fetched kind:0 `about` text keeps normalized line breaks. Other known profile strings
  stay single-line, and unsafe controls are still removed. (#1973)

- Package Android `arm64-v8a` and `x86_64` MarmotKit libraries with 16 KB ELF load-segment alignment, and reject a release or exact-head candidate whose packaged libraries do not meet that alignment. The page-size flags are appended on the final library link so configured Cargo rustflags stay in effect.

### Breaking changes

- `HostPerformanceOperationFfi` gains 28 shared and nine Linux-specific stages.
  Regenerate Swift/Kotlin bindings with the matching native library and update
  exhaustive operation switches. `AppPerformanceSnapshotFfi` keeps its existing
  record fields; read every new stage through `runtime_operations`.

### Added

- Add bounded encrypted NIP-88 poll creation and replacement-vote methods. Timeline rows expose deterministic poll
  counts, participants, local selection and deadline state. Poll creation follows canonical group-conversation
  classification; an accepted open poll remains votable after reclassification. Regenerate Swift/Kotlin
  bindings with the matching library.

## 0.10.4 - 2026-09-20

### Fixed

- Classify host-managed configuration and signed-out permission errors separately from media errors; document opt-in retry budgets and revocation-safe publication. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

### Breaking changes

- `MarmotOptions` gains an optional acquisition mode and transfer state gains three terminal variants. `MarmotKitError` adds attachment configuration/account variants. Regenerate Kotlin/Swift bindings with the matching library and update exhaustive state handling. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

### Added

- Token-aware text, reply, draft and media-send methods return durable local acceptance and expose local submission
  status; timeline rows carry the opaque caller token. Existing send methods remain supported. ([#1943](https://github.com/marmot-protocol/mdk/pull/1943))

- `ChatListMessagePreviewFfi` exposes optional per-message retention duration and expiry so hosts can hide expired previews before pruning. Regenerate Swift/Kotlin bindings with the matching native library. ([#1942](https://github.com/marmot-protocol/mdk/pull/1942))

- Expose host-managed acquisition mode, generation-fenced permission updates and atomic automatic requests to Kotlin/Swift. Add terminal history/budget outcomes; regenerate bindings with matching native libraries. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))
