# Changelog

## Unreleased

### Breaking changes

- Migration 0113 advances account storage to schema 113 on first open. Older
  binaries reject the upgraded database; downgrade is unsupported. It rebuilds
  `media_files` to allow a `staged` state (an outgoing body its upload owns,
  not yet referenced) and adds `outgoing_attachment_uploads.file_id`. A media
  file now lives while a slot references it or an upload owns it, so an
  upload shared by several messages keeps its promoted file for the ones still
  waiting. Deleting an upload, or pointing it at another file, deletes a
  still-staged file's key, and a promoted one no slot references (mdk#2314
  step 3).
- `promote_attachment_uploads` skips uploads that have a media store file;
  promote those through `MediaStore::promote` with an
  `AttachmentUploadPromotion`.
- Migration 0111 advances account storage to schema 111 on first open. Older
  binaries reject the upgraded database; downgrade is unsupported. It adds
  `cgka_messages.openmls_content` and `openmls_epoch`, which every write
  derives from the payload (the OpenMLS content type and MLS epoch it
  carries), plus a covering `(group_id, state, openmls_content,
  openmls_epoch)` index and a partial index of rows not derived yet. Existing
  rows take `-1` without a table rewrite (mdk#2330).
- Migration 0110 advances account storage to schema 110 on first open. Older
  binaries reject the upgraded database; downgrade is unsupported. It adds
  `media_files` (per-file keys and states for the encrypted media store,
  mdk#2314) and `media_file_refs` (attachment slot to ready file), with triggers
  that delete a file's key with its last reference and on a store reset.
- Migration 0112 advances account storage to schema 112 on first open. Older
  binaries reject the upgraded database; downgrade is unsupported. It discards
  existing download checkpoints (the next attempt starts its body over) and adds
  `attachment_partial.wire_file_id` and `progress_floor`: checkpoint
  ciphertext now lives in a media store `.wire` file and the row keeps only
  its metadata (mdk#2314). Checkpoints no longer reserve retained budget
  (`attachment_partial_usage.reserved_bytes` stays zero).
- Download checkpoints are metadata only, written through the media store.
  `attachment_checkpoint` and `attachment_checkpoint_matching` return an
  `AttachmentCheckpoint`, the job's `media_store::CheckpointTarget`; save,
  restore and clear a checkpoint with `MediaStore::checkpoint_append`,
  `checkpoint_restore` and `checkpoint_clear`. `load_attachment_partial` returns
  `AttachmentPartial { identity, received, wire_file }` instead of the bytes.
  `clear_attachment_partial`, `checkpoint_attachment_partial`,
  `load_attachment_partial_to_writer` and `attachment_acquisition_fits_budget`
  are no longer public.
- `readmit_storage_blocked_attachments` takes a `ReadmitAdmission` (the
  recorded-checkpoint threshold the caller's admission rule implies) in place
  of the transfer limit, so readmission and worker admission decide the same
  way. It filters by it before limiting its page, so rows admission refuses
  cannot hide later ones that pass.
- `read_retained_attachment` returns an error for a body stored as a media file
  (mdk#2314). Use `retained_attachment_read`, which returns legacy database bytes or
  the media file id to read through the media store.
- Migration 0108 advances account storage to schema 108 with account-wide attachment seek/expiry indexes and invalidation counters. Older binaries reject the upgraded database; downgrade is unsupported.
- Migration 0109 advances account storage to schema 109 on first open. Older
  binaries reject the upgraded database; downgrade is unsupported. It adds
  `attachment_acquisition.storage_blocked_headroom` and `storage_park_count`,
  a partial index for parked rows, and keeps ciphertext checkpoints for jobs
  parked on disk space.
- `AttachmentTransferState` adds `StorageBlocked`; update exhaustive matches.

### Added

- File-backed outgoing uploads on the media store (mdk#2314 step 3):
  `reserve_attachment_upload` reserves an upload row before its body is staged,
  `attachment_upload_stage` returns its `AttachmentUploadStage`
  (`media_store::StageTarget`), `attachment_upload_promotion` returns an
  `AttachmentUploadPromotion` (`media_store::PromoteTarget`) for a published
  message, and `attachment_upload_file` locates the staged file for the upload.
  `SqliteMediaCatalog` implements the new `staged_file` and
  `abandon_unowned_staged` catalog methods.

- `MessageStorage::list_openmls_messages_in_states` leaves out, in SQL, the rows
  an `OpenMlsContentFilter` excludes (delivered applications at or below an
  epoch, everything but commits, or everything but one epoch's applications);
  rows not derived yet or unclassified are always returned (mdk#2330).
- `SqliteMediaCatalog` and `SlotPublication` implement the `media-store` crate's
  `MediaCatalog` and `PublishTarget` traits on the account database;
  `release_media_reference` removes a slot's reference and reports released files.
- `AttachmentPublication` publishes a claimed download into the media store with the
  job's fences and no retained-byte budget; `retained_attachment_read` locates a
  retained body (legacy bytes or a media file id).

- Bounded account-wide attachment pages with group/sender selections, inclusive date bounds and account/query-bound continuation cursors.
- `SqliteAccountStorage::block_attachment_storage` parks a live attempt whose
  publication disk reserve the device cannot cover. It records the free space
  the next attempt needs beyond the reserve, refreshes the checkpoint's idle
  expiry, refunds the automatic-history claim and the claim streak, withdraws
  a completed-body receipt that publication could not use, and advances a park
  streak (a permission-owned park does not). `readmit_storage_blocked_attachments`
  requeues up to 64 parked jobs whose target fits the supplied free space less
  `STORAGE_READMIT_MARGIN_BYTES` once worker admission (`disk_reserve + 2 *
  transfer_limit`, less the job's checkpoint and never less than one limit)
  would pass, delays a repeated park by its streak, and skips
  automatic rows while automatic acquisition is disabled; its probe is
  read-only until a row fits. Explicit retry, readmission, completion and
  cancellation clear the parked marker; both explicit retry APIs refresh a
  parked prefix's idle expiry. `prune_attachment_partials` keeps a parked
  prefix for at most `STORAGE_PARKED_PREFIX_MAX_AGE_SECONDS` (seven days) after
  the latest park, then prunes it. `attachment_partial_extent` reports a
  checkpoint's total and saved bytes. The new `test-support` feature exposes
  `limit_database_pages_for_test` and `attachment_partial_bytes_for_test` to
  dependents' tests (mdk#2239).
- `SqliteAccountStorage::epoch_gap_recovery_open_since` reports when an unresolved epoch-gap obligation (pending, parked or retired by the user) covering a group's local epoch was first armed.

### Fixed

- `list_messages_in_states` and `visit_messages_in_states` take row ids from
  the `(group_id, state, epoch)` index and read rows by id. Ordering by
  `insert_order` alone let SQLite walk every row of the group, so listing a
  rare state cost the group's whole history (mdk#2330).
- `promote_legacy_message_rows` also derives the OpenMLS content columns of
  rows written before migration 0111, writing only those columns.
- `complete_attachment_acquisition` publishes a body larger than one 64 KiB
  staging chunk as a completed chunked file, the layout the file sink's import
  already produces, so no SQLite value holds more than one chunk of it and the
  insert trigger never rewrites a body-sized row. Migration 0104 appends `byte_len`
  after `bytes`, and SQLite expands a `zeroblob` that is not the record's last
  field, so a pre-sized array row would still materialize the body. A body of
  at most one chunk stays one array row (mdk#2241).
- `load_attachment_partial` sizes the restored prefix for the complete
  representation with a fallible reservation: a refused allocation is a
  storage error that keeps the checkpoint, not a process abort (mdk#2241).

## 0.13.0 - 2026-10-12

Account storage advances from migration 101 through 107 on first open; downgrade
is unsupported.

### Breaking changes

- `PresentedChatRow` adds `draft_version: Option<ChatListDraftVersion>`; struct
  literals must set it.

- Migration 0102 advances account storage to schema 102 on first open and
  invalidates attachment-history versions when source emoji tags change.
  Downgrade is unsupported. The public `AttachmentHistoryEntry` adds the required
  `emoji_tags` field; update Rust struct literals. Selected entries read these
  canonical source tags in the page snapshot without a history backfill.
- Migrations 0103 through 0107 advance account storage to schema 107 on first
  open. Older binaries reject the upgraded database; downgrade is unsupported.

### Added

- `SqliteAccountStorage::open_encrypted_observed` reports fixed open phases and
  migration numbers (`StorageOpenPhase`, `StorageOpenProgress`) without paths,
  SQL or keys. Migrations 0104/0105 validate and account metadata on mutation;
  affected foreign keys are verified transactionally and enforcement is restored
  on failure or unwind. Already-upgraded physical schemas remain supported.
- `chat_list_selection_snapshot`, `chat_list_selection_count`,
  `chat_list_selection_page` and `revalidate_chat_list_selection` capture every
  eligible chat id for a fixed chat-list view in one read transaction
  (`ChatListSelectionSnapshot`, `ChatListSelectionError`), so batch actions are
  not limited to the loaded display window.

- Migration 0107 adds the account-private `moderation_report_outbox` with
  `SqliteAccountStorage` methods to stage, retry, deduplicate, rate-count,
  prune and purge signed moderation-report wraps. Rows never hold the reported
  key or explanation in the clear, and a published row drops its wrap.

- Test-only `test-migrated-template` feature adds
  `SqliteAccountStorage::in_memory_from_migrated_template`, which copies one
  migrated in-memory database per process instead of replaying every migration
  for each open. Harnesses that open thousands of databases use it.
- `SqliteAccountStorage::stage_attachment_upload_files` stages
  `AttachmentUploadSource` readers and
  `complete_attachment_acquisition_from_reader` publishes authenticated
  plaintext readers. Both reserve the complete quota, verify length and digest,
  and write protected `ATTACHMENT_STAGING_CHUNK_BYTES` (64 KiB) chunks with
  nonce-bound reservations and short transactions, releasing the account lock
  during caller I/O. Failed or cancelled imports release their reservations.
  Migration 0106 lets outgoing file promotion share immutable chunks with retained
  sources; legacy staged arrays use bounded incremental BLOB copies. File bodies
  use `MAX_RETAINED_FILE_ATTACHMENT_BYTES` (900 MiB); legacy arrays retain
  `MAX_RETAINED_ATTACHMENT_BYTES` (512 MiB). Migrations 0104/0105 preserve
  retained bodies and ciphertext checkpoints while widening file-backed
  representation bounds, without increasing user quotas. (#2175)

### Fixed

- Outgoing promotion defers file bodies bound after its verification snapshot
  without quarantining them or hiding a verified same-slot sibling. Source
  expiry admission includes time spent verifying and waiting for storage.
- File-backed checkpoint restore rechecks lease, source expiry and checkpoint
  expiry after caller writes, including time spent copying the prefix.
- Canonical push-token reconciliation removes absent account/device-leaf pairs
  atomically with departed-account tombstones. A surviving sibling retains its
  destinations and anti-resurrection tombstones; other groups are untouched.
  Roster membership is materialized once per deletion statement instead of
  rescanning the JSON roster for every stored destination.

## 0.12.0 - 2026-10-02

Account storage advances from migration 98 through 101 on first open; downgrade
is unsupported.

### Added

- Migration 0100 keeps a tapped attachment's explicit priority when its
  history row is reprojected, and migration 0101
  adds bounded outgoing-upload staging records, written after the blob upload
  and before publication; confirmed sends later promote them to retained
  attachment bytes.
  (#2142)

- `SqliteAccountStorage::poll_votes` pages each voter's effective selection for
  one visible poll (1..=100 per page, `(voted_at, voter)` cursor). The timeline
  tally and this read share one resolver, so the per-voter pages always sum to
  `PollProjection`'s counts and `participants`. (#2091)
- `SqliteAccountStorage::defer_attachment_preparation` counts consecutive
  missing-key deferrals (migration 0099, `preparation_deferrals`) with backoff
  and fails the acquisition after the sixth.

### Changed

- Kind-7 reactions with encrypted-media `imeta` (NIP-30 custom emoji images)
  now reference their media epoch secret like kind-9 chats, so the image stays
  decryptable after the group advances.

### Fixed

- Certifying incremental-history debt through a full-history repair now settles the
  pending recovery comparison, so a comparison with no work left is no longer selected
  ahead of other recovery causes. (#2100)
- `checkpoint_recovery_comparison` counts each scope's unserved comparisons in a
  row (stored in the scope payload, no migration). A scope with six, on passes
  that could retry, counts toward parking like one with three quiet comparisons.
  The caller counts only requests answered by at least one required relay;
  offline and deadline-cut scopes are omitted.
  Progress resets both counts, a quiet comparison resets the unserved count, and
  a goal or required-relay change starts both over. (#2110)

## 0.11.0 - 2026-09-29

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
  changed (its obligation, a `RecoveryDemandTransition`, the newly charged count and the
  goal floor read in the same transaction) instead
  of `()`; callers that ignored the unit result compile unchanged.
  `request_recovery_observed` and `mark_account_delivery_recovery_observed` report the same
  transition for a request and for the worker's overflow observation, and
  `recovery_obligation_status` reads one obligation's revision, cause, state and
  eligibility, and `recovery_parking_streak` the shortest quiet streak among the scopes that
  still decide parking. None of these changes demand.

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
