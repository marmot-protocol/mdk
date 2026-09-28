# Changelog

## Unreleased

### Changed

- A recovery scope may admit relays it does not require. Completion checks only the
  required relays, each of which must be admitted and covered. Checkpoints may name any
  required or admitted relay, and joining comparison debt replaces its required relays
  instead of accumulating them. (#2068)
- `StoredNostrRoute` gains `replaced_at`, when the device saw the route replaced as its
  group's current route, which anchors the retained route's relay history floor. It is an
  optional field inside the existing route JSON (`account_groups` and the local-deletion
  frontier), so there is no migration; routes stored before it read as `None` until
  `stamp_unrecorded_prior_route_switches` stamps them. Retaining a frontier route keeps its
  earliest known switch. (#2070)

### Added

- Report recovery demand transitions for the owner's audit rows.
  `synchronize_account_delivery_loss` now returns one `RecoveryLossImport` per loss cause it
  changed (its obligation, a `RecoveryDemandTransition` and the newly charged count) instead
  of `()`; callers that ignored the unit result compile unchanged.
  `request_recovery_observed` and `mark_account_delivery_recovery_observed` report the same
  transition for a request and for the worker's overflow observation, and
  `recovery_obligation_status` reads one obligation's revision, cause, state and
  eligibility. None of these changes demand.

- Add `stamp_unrecorded_prior_route_switches(now_secs)`, which stamps each retained route in
  `account_groups` that has no `replaced_at` with `now_secs` and persists the stamp in one
  transaction, so a route stored before switch times were kept gets one fixed floor
  anchor. It returns how many routes it stamped, and leaves the local-deletion frontier
  alone. (#2070)

- Add `checkpoint_recovery_comparison`, which takes each compared scope's
  `RecoveryPassProgress` and keeps that scope's quiet streak in its checkpoint payload for its
  goal: progress restarts it and an unserved comparison leaves it alone. A retryable obligation
  parks, in the same transaction, once every scope it still cannot certify has
  `RECOVERY_PARK_AFTER_QUIET_PASSES` quiet comparisons in a row, so a pass that compares a slice
  of routes cannot park the rest. `StoredRecoveryScope::quiet_passes` reports the streak. (#2068)

- Add schema 0098 for "history may be incomplete" notices. `parked_recovery_obligations` and
  `parked_group_recovery_obligations` list each pending obligation parked for deep repair as a
  `ParkedRecoveryObligation` (ticket, cause, optional group and new `parked_at_ms`, which parking
  now records). `retire_parked_recovery_obligation(id, revision, now_ms)` is the explicit,
  user-authorized ending: in one transaction, and only for that exact parked revision, it records
  `state = 2` with a documented `incomplete_reason`, never coverage. For queue or notification loss
  it retires every evidence generation of that cause at its imported count (new `retired_count`)
  and refuses while newer evidence is unimported; for incremental history it settles the comparison
  slot that served only that debt, and records the routes and required relays it could not
  certify (new `dismissed_scopes`); parking again on none but those retires it again silently.
  Retired watermarks no longer bound loss goals or legacy
  restoration, and a delayed duplicate observation cannot reopen them. New loss above a watermark,
  a new generation, a higher epoch, a comparison join or a new known-event, incremental or explicit
  request reopens the row as fresh pending debt. (#2068)

- Add schema 0097 `bound_state` and `bound_seconds` on `account_delivery_loss_evidence`: a
  running minimum of the wire `created_at` charged to each loss generation, which becomes
  unknown for good after any charge without one. Rows written before 0097 are unknown.
  `record_account_recovery_loss_bounded` and the other `*_bounded` writers maintain it, and
  `recovery_loss_goal_floor` reads it. (#2068)

- Add schema 0096 `account_delivery_spill`, the durable overflow tail of the in-memory account
  delivery queue, with `spill_account_deliveries`, `spilled_account_deliveries` and
  `remove_spilled_account_delivery`. Spilling skips deliveries already recorded in
  `seen_events` unless their receipt was released for redelivery. (#1947)

- Add qualified recovery scope checkpoints, independent completion predicates, exact loss
  acknowledgment guards and atomic inventory invalidation. Schema 0093 preserves existing
  demand/retry evidence and bounds serialized explicit-history callers to one row. This
  storage slice remains gated on coordinated runtime owner integration. (#1946)

- Add schema 0092 recovery-ledger groundwork: migrate overflow and epoch demand, preserve
  release/maintenance/inventory evidence, and provide restart-safe attempt reservations.
  Legacy storage APIs use the new ledger. Runtime owner integration is still required. (#1946)

## 0.10.4 - 2026-09-20

### Fixed

- Clear permission pause on terminal failure, share MIME permission classification, and avoid idle permission-resume write transactions and redundant demand updates. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

- Initialize upgrade budgets at zero, preserve paused deadlines and partial ciphertext, and retain size-policy diagnostics when budgets are exhausted. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))

### Added

- Migrations 88–89 add a blob-free draft attachment-descriptor index and durable token-correlated local submissions.
  Locally accepted sends survive restart and transfer ownership atomically to the engine queue. ([#1943](https://github.com/marmot-protocol/mdk/pull/1943))

- Chat-list previews expose the selected message's pinned retention duration and expiry directly from its source record, including decisions finalized after local admission. No database migration is required. ([#1942](https://github.com/marmot-protocol/mdk/pull/1942))

- Migration 87 preserves acquired-but-unavailable history and persists completed receipts and opt-in budgets of four
  acquisitions and 64 network attempts. Upgrade preserves native retry behavior and existing work. Automatic demand
  atomically preserves suppression, deadlines and outcomes. ([#1939](https://github.com/marmot-protocol/mdk/pull/1939))
