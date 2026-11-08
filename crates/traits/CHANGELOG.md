# Changelog

## Unreleased

- `SendIntent` gains `StepDownAndLeave { group_id }` and `SendResult` gains `LeaveRequested { request }` (mdk#3014):
  an admin's Leave that records the leave request first and leaves the step-down and SelfRemove to the engine.
  Exhaustive matches need them. Neither is persisted in a queued intent; no schema or wire change.

- `LeaveRequest` gains `blocked: Option<LeaveBlockReason>` (`#[serde(default)]`; one reason, `LastActiveAdmin`), and
  `EngineError` gains `LeaveNotBlocked { group_id }` (kind `leave_not_blocked`) for a Cancel asked of a leave that is
  not blocked (mdk#3014). Struct literals and exhaustive matches need them. Stored requests without the field read as
  not blocked; no schema change.

- Add `TooLarge` endpoint rejection, coarse `EventSizeClass`, and optional size evidence on endpoint and aggregate
  publish failures. Rust struct literals and exhaustive matches must adopt the new fields/case. Old retained JSON
  remains readable with unknown evidence; older readers may reject newly written rejection variants. No schema or wire change.

### Breaking changes

- Add `SiblingAddRefusal::AlreadyPresent` for selected-tree sibling presence. Experimental Rust callers with exhaustive
  matches must handle the new variant; another KeyPackage cannot resolve it. No stored or wire encoding changes.

- Remove D90-only authenticated device-group source types and `MessageStorage` observation/content-association
  methods; ordinary processed-wrapper markers remain. `PublicationObservation` retains only immutable actual
  acceptance time, with the retired serialized order ignored on read (D100).

- `GroupStorage` now requires `invitation_admission` and `put_invitation_admission` for native transactional
  admission metadata (mdk#2628 D96). `InvitationAdmission` binds the original generation to founding origin or its
  exact successful local Welcome output; no transport id is used as the shared generation seed.

- Remove `AnnouncedKeyPackage`, `AnnouncedKeyPackageStorage`, its retention
  and per-slot limits, and `StorageProvider::announced_key_package_storage`
  (mdk#2863, D81). The unused announcement history has no replacement.
