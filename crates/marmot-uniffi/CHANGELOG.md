# Changelog

## Unreleased

### Changed

- Explicit catch-up ingests live input, then runs the account's recovery comparison in
  place. It no longer re-subscribes relays once the session is active; a route change
  still refreshes them.
- Generated identities and later relay-list or profile edits schedule
  best-effort copies of kind 10002, kind 10050, and kind 0 to the built-in
  public directory indexers. Development accounts using loopback relays skip
  these writes while retaining public indexer reads for existing identities.

### Fixed

- Keep native conversation-window paging usable during content-only refreshes.
  An older visible-anchor quote whose row has left the retained window now
  reports a stale window so hosts can reassess the visible row. (#2052)

- Keep native chat-list-window paging usable while account activity refreshes
  the window. An older visible-anchor quote whose row has left the retained
  window reports a stale window so hosts can reassess the visible row.

- Fetched kind:0 `about` text keeps normalized line breaks. Other known profile strings
  stay single-line, and unsafe controls are still removed. (#1973)

- Package Android `arm64-v8a` and `x86_64` MarmotKit libraries with 16 KB ELF load-segment alignment, and reject a release or exact-head candidate whose packaged libraries do not meet that alignment. The page-size flags are appended on the final library link so configured Cargo rustflags stay in effect.

### Breaking changes

- `HostPerformanceOperationFfi` gains 28 shared and nine Linux-specific stages.
  Regenerate Swift/Kotlin bindings with the matching native library and update
  exhaustive operation switches. `AppPerformanceSnapshotFfi` keeps its existing
  record fields; read every new stage through `runtime_operations`.
- `MarmotEventFfi` gains `HistoryNoticesChanged { account_id_hex, account_label }`; update
  exhaustive event switches. `GroupRecoveryStatusFfi` gains `history_may_be_incomplete` and
  `history_notice_ids`, with binding defaults for host-constructed records. Regenerate
  Swift/Kotlin bindings with the matching native library.

### Added

- Add bounded encrypted NIP-88 poll creation and replacement-vote methods. Timeline rows expose deterministic poll
  counts, participants, local selection and deadline state. Poll creation follows canonical group-conversation
  classification; an accepted open poll remains votable after reclassification. Regenerate Swift/Kotlin
  bindings with the matching library.
- Add `history_notices` and `dismiss_history_notice` with `HistoryNoticeFfi` and
  `HistoryNoticeCauseFfi`. Each notice is one parked recovery occurrence to show as "history may
  be incomplete"; dismissal is durable, is recorded as its own outcome rather than recovered
  history, and returns false for a stale id. Group-scoped occurrences also appear in
  `group_recovery_status`. See the README section "History may be incomplete notices". (#2068)

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
