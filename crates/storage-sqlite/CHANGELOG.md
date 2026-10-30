# Changelog

## Unreleased

### Breaking changes

- Migration 0134 advances account storage to schema 134 (mdk#2660 phase 4).
  It adds `recheck_revision` to `account_recovery_units`, which existing rows
  start at 0. Every request that makes a re-check pass due bumps it
  (`make_recovery_recheck_due`, `rearm_all_recovery_units`, and a cooldown
  longer than `RecoveryUnitPolicy::recheck_after_cooldown_seconds` ending),
  and `RecoveryRecheckPass::revision` reports it. `record_recovery_recheck`
  takes the revision its quantum began on, records nothing once it moved, and
  returns whether it recorded. Ending a long cooldown, by an answer or by
  `record_recovery_relay_reconnected` (which now takes the policy and the
  time), makes every re-check on the relay due in the same transaction.
- Migration 0133 advances account storage to schema 133 (mdk#2628 item 3.3b).
  It adds `device_links`, one row per device this device approved adding to
  the account's device group, written before the approving commit, with the
  added KeyPackage's event id (which names the link's Welcome) and its leaf's
  signature key, its outcome (`pending`, `linked` or `failed`), and whether a
  failed link's Welcome is withdrawn. It also adds `device_group_joins`, the
  device groups this device joined through a link whose first commit there has
  not landed yet. `SqliteAppStorage` gains `record_device_link` (taking a
  `LinkedKeyPackage`), `mark_device_link_welcome_withdrawn`, `device_link`,
  `device_links`, `decide_device_link`, `record_device_group_join`,
  `device_group_joins` and `delete_device_group_join`. A local forget removes
  the group's rows. No rows are seeded.
- Migration 0132 advances account storage to schema 132 (mdk#2660 phase 4).
  It adds `import_revision` to `account_delivery_loss_evidence`: the loss
  revision the import that last charged a generation left. Existing imported
  rows take the current loss revision; rows no import charged stay NULL. It
  also adds `acknowledged_import_revision` to `account_recovery_state`: the
  highest `import_revision` an acknowledgment deleted, starting at the current
  loss revision. `recovery_loss_reach` and `recovery_loss_reach_after` return
  a `RecoveryLossReach`: where unresolved loss of one cause, or loss imported
  after a loss revision, may have lost events, by route.
  `recovery_loss_reach_after` returns `None` below the acknowledged revision.
- Migration 0131 advances account storage to schema 131 (mdk#2628 item 3.2).
  It adds `account_sign_ins`, one row per KeyPackage slot of the account that
  this device found and does not recognize: whether this device's first check
  returned its slot, its client name, when it appeared and last published, its newest
  KeyPackage, whether it is still signed in, and this device's answer, with
  whether the device group's roster records a rejection yet.
  `account_sign_in_baseline` holds when the first check ran, and
  `account_sign_in_baseline_slots` every slot its read returned.
  `SqliteAppStorage` gains `record_sign_in_check`, `sign_ins`, `sign_in`,
  `answer_sign_in`, `settle_sign_in_rejection`,
  `rearm_sign_in_rejections` and `sign_in_baseline`.
- Migration 0130 advances account storage to schema 130 (mdk#2660 phase 4).
  It adds `account_recovery_coverage_remainders`, each route's parked
  remainder, and `settled_below_seconds` to
  `account_recovery_coverage_goals` (an existing goal starts settled at its
  own floor, where the earlier prune left it).
  `prune_recovery_coverage` takes the current routes with their certifying
  relays, parks what they still owe between each route's settled floor and
  the retention floor, then settles every route at the retention floor; loss
  lowers a route's settled floor to the loss floor.
  `recovery_coverage_remainders` reads the remainders.
  `dismiss_recovery_route_park` clears a route's remainder too, and accepts
  the newest revision among its broken units and its remainder, which
  `parked_recovery_routes` now reports. A released receipt (or a discarded
  staged event) below the retention window no longer changes the ledger.
- Migration 0129 advances account storage to schema 129 (mdk#2628 item 3.3b).
  It adds `cgka_device_group_welcome_expectations`, one row per device group a
  confirmed link waits to join: the sender leaf's signature key and the end of
  the wait. `SqliteAccountStorage` implements the new
  `DeviceGroupWelcomeStorage` trait over it. The engine consumes a row with
  the join it admits, and the app deletes it when a link is withdrawn or its
  wait ends. No rows are seeded.
- Migration 0128 advances account storage to schema 128 (mdk#2660 phase 4).
  It adds `route_state` to `account_delivery_loss_evidence`, which existing
  rows leave 0, and `account_delivery_loss_evidence_routes`: the routes a loss
  generation lost deliveries on, each with the earliest `created_at` lost
  there. `record_account_recovery_loss_routed` records them; a generation with
  every charge routed, and at most `MAX_LOSS_ROUTES` routes, un-covers only
  those routes at import, and a legacy clear un-covers each generation it
  restores the same way. A worker observation past the durable count makes its
  generation account-wide. `RecoveryLossImport` gains `every_route`, and an
  import that un-covered every route is reported even when its obligation did
  not change.
- Migration 0127 advances account storage to schema 127 (mdk#2660 phase 4).
  It adds the recovery runner's retry state, which nothing in production
  writes yet: `account_recovery_units` (per route and relay: active, broken
  or retired, backoff, park and probe), `account_recovery_unit_spans` (parked
  and retired spans, never coverage), `account_recovery_relays` (health and
  NIP-11 caps), `account_recovery_budget` (a rolling-hour account budget),
  `account_recovery_park_revision` and `account_recovery_staged` (a proven
  slice's unseen events, written with its coverage). `SqliteAppStorage` gains
  `begin_recovery_unit_attempt`, `settle_recovery_unit`, the re-arm,
  dismissal, relay and re-check writers, `stage_recovery_slice` and the
  matching reads; `RecoveryUnitPolicy` carries the caller's policy values.
  The retention prune trims parked and retired spans at its floor.
- Migration 0126 advances account storage to schema 126 (mdk#2660 phase 4).
  It adds the coverage ledger's un-cover log
  (`account_recovery_coverage_uncovers`,
  `account_recovery_coverage_uncover_state`) and
  `account_recovery_coverage_released`, the seconds released for replay that
  live boundaries leave out. Loss imports and receipt releases append what
  they un-cover; `recovery_coverage_mark` and `record_recovery_coverage_since`
  let a fetch subtract everything un-covered since it started, and replace
  `record_recovery_coverage_at_loss_revision`.
- Migration 0125 advances account storage to schema 125 (mdk#2628 item 3.1).
  It adds `device_groups`, one row per device group this device knows of, with
  how it came to know it: `creating`, `created`, `awaiting_welcome`, `linked`
  or `untrusted`. `SqliteAppStorage` gains `device_group`, `device_groups`,
  `insert_device_group`, `set_device_group_trust` and `delete_device_group`.
  At most one row claims the account's device group. A local forget removes
  the group's row. No rows are seeded.
- Migration 0121 advances account storage to schema 121 (mdk#2628). It drops
  `cgka_member_capabilities`, the engine's per-account capability cache: with
  several devices per account, one device's capabilities stood in for all of
  them, so a capability could be offered as an upgrade while a device lacked
  it. The engine now reads each current leaf's capabilities from the MLS tree,
  and every member computes the same answer, a Welcome joiner included.
  `CapabilityStorage` loses `save_member_capabilities` and
  `member_capabilities`. Snapshots and checkpoints keep their v2 layout: the
  retired list is written empty, and rows in older snapshots are skipped.
- Migration 0120 advances account storage to schema 120 (mdk#2628).
  `account_groups.member_count` now counts member accounts, so an account
  with several devices in a group counts once and a chat between two
  accounts is `Direct`. The migration rewrites rows whose engine record lists
  an account more than once, with the peer index and presentation members
  their accounts make; every other row already counted accounts.
- Migration 0117 advances account storage to schema 117 on first open; older
  binaries reject the upgraded database. It queues the current push
  registration once for every joined group while native push is on, so
  members who joined before this release receive this device's token
  (mdk#2604).
- Migration 0118 advances account storage to schema 118 (mdk#2611). It adds
  `token_fingerprint` and `owner_sig` to push tombstones, which existing
  tombstones leave NULL, and an empty `group_push_gossip_state` table.
- Migration 0119 advances account storage to schema 119 (mdk#2611). It adds
  `snapshot_owed_after_epoch` to `group_push_gossip_state`, which existing
  rows leave NULL, and a partial index over the rows that owe one.
  `AccountGroupPushGossipState` gains the matching field.
- Migration 0122 advances account storage to schema 122 (mdk#2611). It adds
  `joining_since_ms` to `group_push_gossip_state`, which existing rows leave
  NULL, with a partial index over the rows that have it,
  `join_window_counted_ms`, which they leave 0, and `announce_owed_at_ms`,
  which they leave NULL, with a partial index over the rows that have it.
  `AccountGroupPushGossipState` gains the matching fields.
- Migration 0124 advances account storage to schema 124 (mdk#2660). It adds
  `recovery_attempts` and `recovery_admitted_high` to
  `account_recovery_obligations`, which existing rows leave 0, and a trigger
  that clears both when an obligation leaves the pending state.
  `count_recovery_attempt` and `park_capped_recovery_obligation` count and cap
  reserved attempts per obligation; `RECOVERY_PARK_AFTER_ATTEMPTS` is the cap. Progress resets the count; for a native goal that means more of its
  sources admitted at once than ever before (`recovery_admitted_high`). A
  native goal's re-arm, retired native windows and route-policy changes keep a
  goal the cap parked.
- `apply_group_push_token_tombstone` takes an `AccountGroupPushTokenTombstone`
  instead of eight arguments, and stores its optional removal proof.

### Added

- `settle_recovery_recheck` applies one re-check quantum's outcome to its
  relay and the account's rolling-hour budget, never to its unit's retry
  state (mdk#2660 phase 4). `staged_recovery_items` lists the ids and times a
  route has staged in a range, from every relay. `make_recovery_recheck_due`
  keeps what a due or running pass would check below an epoch gap's bound.
- `OpenMlsContentFilter::CommitsAndProposalsBetween` lists only the commits and
  proposals whose MLS epoch falls in a range, plus the rows SQLite cannot
  classify (mdk#2684). A failed convergence batch checks its horizon through it
  on every load, reading neither the group's applications nor its older
  history.
- `queue_current_push_registration_share_for_group` queues the stored
  registration for one joined group again, including a revision whose share
  already completed. It does nothing while native push is off or without a
  registration.
- `group_push_token_tombstones` lists a group's tombstones. One with an
  `AccountPushTokenRemovalProof` can be relayed as the owner's signed removal;
  one without, written before migration 0118, stays local-only until the same
  removal is applied again with its proof.
- `group_push_gossip_state`, `record_group_push_gossip_join` and
  `record_group_push_gossip_announce` keep when this device's join became final
  and when it last announced, for its current membership. Writes need a joined group; the row goes when the device leaves
  or is removed, and with the group.
- `record_group_push_snapshot_owed`, `owed_group_push_snapshots` and
  `replace_group_push_snapshot_owed` keep the push snapshot this device owes a
  group after a Commit of its own adds leaves: the latest source epoch wins,
  and replacing or settling it needs the epoch it still holds.
- Saving the projection opens this device's push join window in a group when a
  Welcome installs or replaces its copy there: `joining_since_ms` records the
  time, and an earlier join time and its counted window time are dropped. A
  group this device created has no window. `joining_group_push_gossip_states`
  lists the open windows, `count_push_join_window_time` adds time to every one
  whose join has completed, and `record_group_push_gossip_announce` closes one.
- `record_group_push_announce_owed` and `owed_group_push_announce_states` keep
  the other announces this device owes a group. Each new debt raises the
  stored value past the last, even if the clock went back, and returns it.
  `record_group_push_gossip_announce` now also takes the owed value the
  published announce was built under, and settles the debt only while it
  still holds that value; a new Welcome drops it.

## 0.14.0 - 2026-10-23

Account storage advances from migration 107 through 116 on first open; downgrade
is unsupported. marmot-app also rekeys its databases once to raw SQLCipher keys
(`SqlCipherKey::raw`); older binaries cannot open them.

### Breaking changes

- Migrations 0108 through 0116 advance account storage from schema 107 to 116
  on first open. Older binaries reject the upgraded database; downgrade is
  unsupported. None of them rewrites message rows:
  - 0108 adds account-wide attachment seek and expiry indexes and invalidation
    counters, filling `attachment_history.retention_expires_at` once.
  - 0109 adds `attachment_acquisition.storage_blocked_headroom` and
    `storage_park_count` and keeps the checkpoints of jobs parked on disk space.
  - 0110 adds `media_files` (per-file keys and states for the encrypted media
    store, mdk#2314) and `media_file_refs` (attachment slot to ready file),
    with triggers that delete a file's key with its last reference and on a
    store reset. Both start empty.
  - 0111 adds `cgka_messages.openmls_content` and `openmls_epoch`, which every
    write derives from the payload, with a covering `(group_id, state,
    openmls_content, openmls_epoch)` index and a partial index of rows not
    derived yet. Existing rows take `-1` without a table rewrite (mdk#2330).
  - 0112 discards existing download checkpoints (the next attempt starts its
    body over) and adds `attachment_partial.wire_file_id` and
    `progress_floor`: checkpoint ciphertext lives in a media store `.wire` file
    and no longer reserves retained budget.
  - 0113 rebuilds `media_files` to allow a `staged` state and adds
    `outgoing_attachment_uploads.file_id`. A media file lives while a slot
    references it or an upload owns it; deleting an upload, or pointing it at
    another file, deletes a still-staged file's key and a promoted one no slot
    references (mdk#2314 step 3).
  - 0114 rebuilds `avatar_assets` so an image can be file-backed (new
    `byte_len`, `bytes` optional when present) and adds `avatar_file_refs`. It
    copies at most 32 MiB of database-held images, smallest first; owners
    beyond that are dropped as if evicted (with their recency, fetch and
    identity-demand rows) and fetched again when shown. On a full 128 MiB
    cache this costs about 1.1 s and 166 MiB of extra disk on a desktop (debug
    build), against 1.8 s and 265 MiB for copying everything.
  - 0115 rebuilds `account_recovery_obligations` to admit subscription-replay
    obligations, keeping existing obligations, scope windows and retry state.
  - 0116 adds the "Keep media" setting (`attachment_keep_media`),
    `attachment_removal_suppression.reason` and
    `attachment_acquisition.keep_from`. Existing suppressions read as removed
    by you, and the setting starts as Forever.
- `SqlCipherKey::new` rejects SQLCipher's raw-key syntax (`x'…'` with 64, 96
  or 160 hex digits), so a passphrase cannot skip SQLCipher's key derivation.
  The new `SqlCipherKey::raw` presents an already-derived 32-byte key as
  `x'<64 hex digits>'`; cipher hardening and operational defaults are
  unchanged (mdk#1791).
- `AttachmentTransferState` adds `StorageBlocked` (free disk cannot cover the
  body's publication reserve) and `CleanedBySetting` (the account's "Keep
  media" setting removed the body, mdk#2314 step 10). Update exhaustive
  matches.
- `record_reconciliation_items` replaces
  `record_transport_reconciliation_item`. It accepts a cloneable iterator of
  borrowed route/item pairs and commits the advisory inventory batch atomically,
  retaining the existing per-route floor, cap and recovery-fence rules.
- App storage has its own handle, `SqliteAppStorage`.
  `SqliteAccountStorage::app_storage()` returns one over the same connection:
  it opens nothing, closes with the account storage, and fails the same way
  once closed. Every app and transport method (account projection, timeline,
  chat list, drafts, attachments, avatars, media catalog, recovery ledger,
  local submissions, transport state) moves from `SqliteAccountStorage` to it,
  so callers write `storage.app_storage().method(..)`. `SqliteAccountStorage`
  keeps the protocol traits, open and close, `delete_local_group_data` and
  `set_message_draft_commit_observer`. `SqliteMediaCatalog::new` and
  `SlotPublication::new` take a `SqliteAppStorage`, and
  `SqliteMediaCatalog::storage` returns one. No schema or behaviour change.
- `promote_attachment_uploads` skips uploads that have a media store file;
  promote those through `MediaStore::promote` with an
  `AttachmentUploadPromotion`.
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
- `AvatarAssetRead` gains `file` (`AvatarStoredFile`): a file-backed image
  comes back there, with `image` empty, for the caller to read through the
  media store. `AttachmentStorageUsage` gains `cache_bytes`.

### Added

- The opt-in "Keep media" setting (mdk#2314 step 10, migration 0116):
  `AttachmentKeepMedia` (Forever by default, one year, six months, 30 days),
  `attachment_keep_media` / `set_attachment_keep_media`, and
  `clean_attachments_past_keep_window`, a bounded batch that removes retained
  attachments past the window, and unfinished automatic downloads the user
  never requested, as explicit `Remove` does but records them as cleaned by
  the setting. Age is the later of the message's received time and
  the last explicit request for the body (`keep_from`, set by explicit
  requests, retries and download-again). `request_automatic_acquisition` is
  `request_attachment_acquisition` for automatic demand: a slot already past
  the window and not yet requested is recorded as cleaned instead of fetched.
  An explicit `Remove` of a cleaned slot records it as removed by you.

- Moving avatars onto the media store (mdk#2314 step 9b):
  `AvatarPublication::for_acquisition` publishes a claimed fetch's image and
  settles the attempt in the same commit (`settle_avatar_acquisition` settles
  a refused one), and `AvatarPublication::for_migration` moves a
  database-held image into a file without changing its content revision or
  recency. `database_held_avatars` (smallest first), `database_avatar_body`,
  `drop_corrupt_database_avatar` and `database_avatar_bytes` are the
  migration's database side, and
  `ready_media_file` finds the file a publication would reuse, so the move
  can verify it before giving up the database copy.

- Avatars and group images in the media store's cache category (mdk#2314
  step 9): `AvatarPublication` is the `media_store::PublishTarget` for one
  source generation (`AvatarFileImage` describes the image), fenced on the
  content revision like `publish_avatar`. Identical images share one file;
  the 128 MiB budget counts each file once, and eviction reports the files it
  released for an immediate unlink. `discard_avatar_file` reports a missing or
  corrupt file: it is marked lost, and every owner sharing it is cleared and
  refetched. `AttachmentStorageUsage::cache_bytes` totals the cache in both
  layouts.

- New account databases are created with `auto_vacuum=INCREMENTAL`, so
  freed pages return to the filesystem without the one-time compaction
  older databases need (mdk#2314 step 6). Existing databases keep their mode
  until compacted.
- Database compaction (mdk#2314 step 6): `database_space` reports the account
  database's pages (`DatabaseSpace`: size, free pages, live bytes, whether it
  is incremental), `compact_database` switches it to
  `auto_vacuum=INCREMENTAL` with one `VACUUM` between WAL checkpoints (an
  interrupted one changes nothing; closing the storage stops one still
  building its copy, which polls the close latch, but its final write-back
  cannot be interrupted, so callers keep the live database small), and
  `reclaim_free_pages` returns freed
  pages in bounded steps afterwards (`PageReclaim`). Both truncate the WAL
  without waiting on readers and report whether they did;
  `wal_truncate_pending` says one a reader on another connection blocked is
  still owed (recorded with the connection locked), and `truncate_wal`
  retries it.
  `DatabaseCloser::begin_close` (and `CloseableConnection::begin_close`)
  latches a database closed without waiting, which also stops a
  compaction still building its copy, so an owner can free work blocked
  behind it before closing. `AttachmentMigrationState` adds
  `Compacting`.

- Moving legacy attachment bodies into the media store (mdk#2314 step 6):
  `legacy_attachment_bodies` lists completed legacy database bodies smallest
  first, `legacy_attachment_reader` streams one (`LegacyBodyReader`, which
  reports a body malformed as stored), `legacy_attachment_publication` is its
  `media_store::PublishTarget` (fenced on the legacy row), and
  `drop_migrated_legacy_body` / `drop_corrupt_legacy_body` delete its rows.
  `AttachmentStorageUsage` gains `migration` (`AttachmentMigrationState`);
  storage reports `NotNeeded` or `Running { remaining_bytes }`. Broken or
  missing chunks of a completed legacy body now read as
  `StorageError::InvalidAttachmentBody` instead of `Backend`.

- `SqliteAppStorage::retention_expiry_scan` reports the three facts the
  retention sweep prunes on for one group (mdk#2425). The unread leg shares
  the chat-list projection's one read-cursor clause, so the sweep and the
  projection can no longer disagree: same five-column canonical key, same
  `(timeline_at, message_id_hex)` fallback for legacy markers. New
  `RetentionExpiryScan` result type. Every leg reads the pinned
  `retention_expires_at` the prune deletes on, so a policy change since a
  row's source epoch cannot hide a due unread row from the sweep.
- Manage storage queries (mdk#2314 step 5) on `SqliteAppStorage`:
  `attachment_storage_usage` (media-store bytes counted once, legacy database
  bytes, retained attachment count, database size and free pages),
  `attachment_storage_by_chat` and `largest_retained_attachments` (paged,
  largest first, with `ChatUsageCursor` / `RetainedSizeCursor`), and
  `remove_retained_attachments`, a bounded batch of explicit `Remove` by chat
  and/or received time that reports released media files.
  `remove_attachment_reference_releasing` is `remove_attachment_reference`
  returning the media files it released, for an immediate unlink.

- `retained_attachment_descriptor` returns a source slot's `imeta` tag and
  source epoch, for naming a local copy of a retained body (mdk#2314 step 4).

- File-backed outgoing uploads on the media store (mdk#2314 step 3):
  `reserve_attachment_upload` reserves an upload row before its body is staged,
  `attachment_upload_stage` returns its `AttachmentUploadStage`
  (`media_store::StageTarget`), `attachment_upload_promotion` returns an
  `AttachmentUploadPromotion` (`media_store::PromoteTarget`) for a published
  message, and `attachment_upload_file` locates the staged file for the upload.
  `SqliteMediaCatalog` implements the new `staged_file` and
  `abandon_unowned_staged` catalog methods.
- `attachment_upload_owners` pages file-backed uploads, with each sent message
  of a confirmed group that carries their descriptor, for promotion (owner rows
  are not required, so a failed owner registration cannot strand one), and
  `drop_lost_attachment_upload` deletes an upload whose media file was lost
  (with that row), so its message falls back to downloading. New
  `AttachmentUploadOwner` record.

- `MessageStorage::list_openmls_messages_in_states` leaves out, in SQL, the rows
  an `OpenMlsContentFilter` excludes (delivered applications at or below an
  epoch, everything but commits, or everything but one epoch's applications);
  rows not derived yet or unclassified are always returned (mdk#2330).
- `StorageProvider::with_group_savepoint` runs a nested unit in a SQLite
  `SAVEPOINT`: on `Err` or panic it undoes every write the unit made, drops the
  after-commit wakeups it registered and moves `mls_write_generation`, and the
  caller's transaction stays open. Canonical convergence apply uses it in place
  of a full group snapshot, so its rollback cost no longer grows with stored
  history (mdk#2326).
- `StorageProvider::rollback_group_state_keeping_live_records` restores
  canonical group state only, even from an anchor captured with full message
  and queue images, so every rewind onto a retained anchor (replay and branch
  probes, and now a reorg's historical apply) keeps the live message ledger,
  pending application events and outbound queue, and costs the same however
  much history the group stores (mdk#2330).
- `DatabaseCloser`, from `closer()` on `CloseableConnection`,
  `SqliteAccountStorage` and `SqliteSharedStorage`, closes a database through
  a weak reference with the same terminal contract as the handle's own
  `close`, and `is_released` reports whether anything is left to close. An
  owner can register one per connection it opens, including one it hands to
  an engine, and close them all before a host suspends without keeping any
  handle alive.
- `SqliteMediaCatalog` and `SlotPublication` implement the `media-store` crate's
  `MediaCatalog` and `PublishTarget` traits on the account database;
  `release_media_reference` removes a slot's reference and reports released files.
- `AttachmentPublication` publishes a claimed download into the media store with the
  job's fences and no retained-byte budget; `retained_attachment_read` locates a
  retained body (legacy bytes or a media file id).
- The `media-store-benchmarks` feature adds `media_store_bench` and its example
  (`just bench-media-store`), which time the `media-store` file format against
  the SQLCipher retained-attachment path on desktop and devices (mdk#2314
  step 0).

- Bounded account-wide attachment pages with group/sender selections,
  inclusive date bounds and account/query-bound continuation cursors.
- `SqliteAppStorage::block_attachment_storage` parks a live attempt whose
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
- `SqliteAppStorage::epoch_gap_recovery_open_since` reports when an unresolved
  epoch-gap obligation (pending, parked or retired by the user) covering a
  group's local epoch was first armed.

### Changed

- Tracing targets name the emitting module, for example
  `storage_sqlite::app::timeline`,
  `storage_sqlite::app::attachment_acquisition::file_import`,
  `storage_sqlite::base::connection` and
  `storage_sqlite::protocol::openmls_storage::provider`. They replace
  `storage_sqlite::account_projection`, `::attachments`, `::connection`,
  `::retention`, `::timeline`, `::welcomes` and
  `marmot.storage_sqlite.openmls`; update log filters that named them.
- Recovery comparison plans are stored as format 2, which keeps the complete
  pending plan, so skipped, refused and transiently failed routes stay
  retryable. A format-1 plan saved by an earlier build froze only its selected
  routes: it is rebuilt instead of reused, and its never-selected goals stay
  recorded as debt.

### Fixed

- The timeline's modifier lookups (edits, reactions, deletions, reports), and
  the deleted-reaction and poll-vote queries, write their constant event kind
  into the SQL instead of binding it, so each kind keeps one cached statement.
  A bound kind compared against the `content_report_labels` partial index made
  SQLite re-plan the join on every call, about six times per received message
  and 11% of offline catch-up CPU (#2585).
- `list_messages_in_states` and `visit_messages_in_states` take row ids from
  the `(group_id, state, epoch)` index and read rows by id. Ordering by
  `insert_order` alone let SQLite walk every row of the group, so listing a
  rare state cost the group's whole history (mdk#2330).
- `promote_legacy_message_rows` also derives the OpenMLS content columns of
  rows written before migration 0111, writing only those columns.
- Opening a database this process already holds open no longer drops the live
  connection's POSIX locks (mdk#2351). `fs_private::ensure_private_db_files`
  used to open and close the existing main file and its sidecars to set their
  mode, which released the connection's `SHARED` and `-shm` read locks, so
  another process (such as an iOS Notification Service Extension) could take
  the database exclusively under it. Existing files are now tightened by path;
  the 0600 creation posture is unchanged.
- `remove_retained_attachments` treats a received-before bound past SQLite's
  integer range as later than every attachment instead of failing.
- `complete_attachment_acquisition` publishes a body larger than one 64 KiB
  staging chunk as a completed chunked file, the layout the file sink's import
  already produces, so no SQLite value holds more than one chunk of it and the
  insert trigger never rewrites a body-sized row. Migration 0104 appends `byte_len`
  after `bytes`, and SQLite expands a `zeroblob` that is not the record's last
  field, so a pre-sized array row would still materialize the body. A body of
  at most one chunk stays one array row (mdk#2241).

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
