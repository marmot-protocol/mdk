# Changelog

## Unreleased

### Breaking changes

- Account migration 0204 drops timeline rows of own sends that failed and were then deleted; such a send no longer
  projects a row. The source rows stay. A deleted send a peer reacted to is delivered instead, also when the reaction
  arrived after the deletion, and keeps its placeholder. Account schema advances from 203 to 204; older binaries
  refuse the upgraded database. Downgrade is unsupported.
- Account migration 0203 adds `member_outcomes_json` to prepared group-image
  uploads, retaining the original partial member-resolution report across
  consumed-upload retries (#1813). Account schema advances from 202 to 203;
  older binaries refuse the upgraded database. Downgrade is unsupported.
- `PreparedGroupImageUploadRecord` carries the optional report, written through
  `SqliteAppStorage::save_prepared_image_members` before canonical creation.
- `RecoveryUnitPolicy` gains `probe_base_seconds` and `probe_cap_seconds` (mdk#3308); struct literals must set them.
  Every park now schedules the broken unit's next timed probe: a new park waits the base, and a failed probe
  re-parks under the same revision and waits the base doubled once per failed probe, up to the cap. The upgrade
  conversion's parks are due at once. Units broken before this release keep their past `next_attempt_at_seconds`, so
  their first probe is due as soon as the runner arms it.
- `SqliteAppStorage::dismiss_recovery_route_park` and `dismiss_recovery_route_park_on` are removed: nothing dismisses a
  coverage-ledger park any more. A route's remainder lasts until a rejoin or the route's end.

### Added

- `SqliteAppStorage::discard_failed_send` securely drops one failed own send (row, edits, media references) and
  returns its projection update; removals of a user-removed failed send carry `TimelineRemoveReason::Cleared`.
- `SqliteAppStorage::sticker_pack_relays` and `set_sticker_pack_relays` retain sticker-pack relay hints independently
  of NIP-01 replacement metadata (mdk#3283). Account migration 0202 adds `relays_json`, defaulting existing packs to
  an empty list. Pack replacement preserves retained hints.
- `SqliteAppStorage::arm_due_recovery_probes(now)` gives every broken unit without a probe whose next probe time has
  passed a probe, so its debt includes its park again; `pending_recovery_probes()` lists the broken units still
  waiting for one.
- `SqliteAccountStorage` reports `has_atomic_group_savepoints` (mdk#3278), so the engine keeps running contained
  rewind windows inside its `SAVEPOINT`, as before.

### Changed

- `SqliteAppStorage::retire_gone_recovery_units` counts a unit only when it newly retires it as route gone. A unit
  already retired as route gone, as a retried route settlement finds it, still retires its newly owed seconds but is
  not counted again, so the recovery runner's `retired_gone` audit row is written once.

### Fixed

- Withdrawing a delete of an edit reports `MessageEditedOrReprojected` for the edited message and
  `ReplyPreviewChanged` for replies quoting it, instead of `ReactionAdded`. Restored poll responses also use the
  reprojection trigger; restored reactions keep `ReactionAdded` (mdk#3377).
- Batch timeline withdrawals and branch-selection revivals attribute each changed row's trigger to an event that
  affected it, rather than the first event in the batch. Every cause participates: conflicting or unmatched causes
  use the generic reprojection trigger, including simultaneous reaction and reply-preview changes (mdk#2843).

### Changed

- New reads for the account worker's job deadlines (mdk#2923): `device_pairing_state_exists`,
  `push_gossip_timing_pending` and `history_dispatch_next_at`. The history delivery due columns have no index; one
  may be needed once device groups ship.

- New reads for the account worker's pass deadlines (mdk#2923): `SqliteAppStorage::attachment_work_schedule`
  (`AttachmentWorkSchedule`: the earliest timed candidate, acquisition or partial, whether polled work exists, and
  whether an admission demand waits), `avatar_work_schedule` and `chat_presentation_work_pending`.

- New `SqliteAccountStorage::post_join_work_owed`: whether any group has a post-join history fetch without a
  completion, or a post-join obligation in catch-up or its EOSE timeout, in one read (mdk#2923).

- `delete_expired_received_private_key_packages` only reads when nothing has expired (mdk#2923).

## 0.16.0 - 2026-11-12

### Breaking changes

- Shared-database migration 0004 (`0004_audit_log_retention`) adds `audit_log_retention_settings` and advances the
  shared database from schema 3 to 4 on first open (mdk#3300). Older binaries refuse it with
  `StorageError::UnsupportedSchemaVersion { found: 4, latest_supported: 3 }`; downgrade is unsupported.
- `SqliteAppStorage::remove_seen_staged_recovery_events(&[&[u8]])` becomes `settle_staged_recovery_events(&[(&[u8],
  StagedRecoverySettlement)])` (mdk#3297). A `StagedRecoverySettlement::Refused` row, which the engine refused for its
  group's resources after it could not open it, leaves whether or not its event is seen, and its second stays covered.
  An `Admitted` row leaves once its event is seen, as before.

### Added

- `SqliteAccountStorage` answers `StorageProvider::list_snapshots_with_prefixes` with one scan of the snapshot keys,
  which the primary-key index covers, so it reads no snapshot body (mdk#3272).
- `SqliteAppStorage::notification_policy_snapshot(account_label, account_id_hex)` returns committed notification
  settings, initializing defaults, with the matching `SqliteAppStorage::notification_revision()` (mdk#1800). The
  revision is a process-local counter shared by file-backed handles on the same canonical database path. TEMP triggers
  advance it on projected-group, notification-setting and chat-mute writes, including protocol forget. It is not
  persisted, and the snapshot fails inside a caller-owned transaction. No schema change.
- `SqliteSharedStorage::audit_log_retention` and `set_audit_log_retention` store the host's audit retention policy as
  `StoredAuditLogRetention { max_age_days, max_bytes_per_account }`; `None` until a host sets one (mdk#3300).

## 0.15.0 - 2026-11-09

Account storage advances from migration 116 through 201 on first open (migrations 0117–0153, 0160–0180, 0200 and 0201;
the numbers between are unused). Older binaries reject the upgraded database; downgrade is unsupported. The
per-account directory cache (`app-cache.sqlite3`) stays at schema 2 and the shared database at schema 3. See the
[release notes](../../docs/release/0.15.0.md) and the [0.14.0 → 0.15.0 upgrade
guide](../../docs/integration/0.15.0.md).

### Breaking changes

- Migrations 0117 through 0201 advance account storage from schema 116 to 201 on first open, each in its own
  transaction, so an interrupted upgrade resumes where it stopped. Older binaries reject the upgraded database (schema
  175 also gates stored-message variant 13, which they cannot decode); downgrade is unsupported. None of them copies
  or rebuilds `app_events` or `message_timeline`, but a few read or index history-sized tables once:
  - 0117–0119, 0122: push tokens. 0117 queues the current registration once for every joined group while native push
    is on (mdk#2604); 0118, 0119 and 0122 add signed tombstones and `group_push_gossip_state` with its owed snapshot,
    join window and owed announce (mdk#2611).
  - 0120–0121: members. `account_groups.member_count` counts accounts, rewriting the rows whose engine record lists an
    account more than once; the `cgka_member_capabilities` cache is dropped.
  - 0123–0124, 0126–0128, 0130, 0132, 0134–0136, 0150–0153: the recovery ledger and runner (mdk#2660): coverage and
    goals, the un-cover log, units, relays, budget and staging, loss routes, parked remainders, re-check revisions,
    unit fences, the one-time conversion marker, epoch-gap retries, saturated seconds and per-group copies. 0153 reads
    every group's engine record once to seed its copy. 0124's attempt counters belonged to the old recovery owner,
    which is gone.
  - 0141–0142: sticker packs, installs, outbox and exact-hash asset history (mdk#875). 0141 adds
    `chat_list_rows.last_message_tags_json`, so the chat-list projection rebuilds once on open.
  - 0147: the `device_removed` membership; recreates the chat-list navigation triggers that read membership.
  - 0167: attachment sources for custom-emoji reactions (mdk#2151), backfilled once from every stored reaction.
  - 0172: the authenticated group-rejoin journal.
  - 0173: recipient-confirmed sends (mdk#1291). Rebuilds the chat-preview index over `message_timeline` and settles
    failed sends from their stored reactions; the chat list rebuilds on open.
  - 0175: the pending-reference watermark. It decodes every saved outbound fanout and group evolution; one undecodable
    row aborts the migration, and the account does not open, rather than risk reusing a reference.
  - 0177: a coarse size diagnosis on pending Welcome repair pointers.
  - 0178: NIP-51 emoji sets.
  - 0179, 0200: chat-list kind and search text (mdk#2983). 0179 backfills `list_kind` for every row and drops 0072's
    navigation-revision triggers. 0200 rebuilds `chat_presentation_dependencies` and invalidates every stored chat
    presentation once: rows keep rendering their last value, but a `Text` query is not ready until the account's
    presentation worker has rewritten them.
  - 0180: original removal validation (#3016). It reads every stored removal event once and blanks the bodies of
    pruned removals whose decision could not be proved.
  - 0125, 0129, 0131, 0133, 0137–0140, 0143–0146, 0148–0149, 0160–0166, 0168–0171, 0174, 0176, 0201: experimental
    device groups, history transfer and backups (mdk#2628); most tables stay empty unless device groups are on. 0144
    adds a table that 0165 drops again. 0169 adds twelve columns and eight indexes to `cgka_processed_transport_ids`,
    one row per processed event; 0174 drops those indexes again, and the columns it no longer needs stay inert.
- Remove the old recovery owner (mdk#2660 rows 9–10); the recovery runner called none of it. Gone: the comparison slot
  API, retry reservations and pacing, scope plans, checkpoints, streaks and the attempt-cap park, qualified stall
  samples, the `SubscriptionReplay` APIs, loss acknowledgment (`acknowledge_recovery_loss*`,
  `restore_unacknowledged_recovery_loss`), the account-wide loss revision, `RecoveryRequest` and its waiters, the
  legacy delivery-loss APIs (`record_account_delivery_loss*`, `mark_account_delivery_recovery*`,
  `clear_account_delivery_recovery`, `account_delivery_recovery`, `synchronize_account_delivery_loss`,
  `RecoveryLossImport`), the obligation status and transition reads, and capacity-wait eligibility
  (`record_recovery_capacity_pressure`, `release_due_recovery_capacity_probes` and `observe_recovery_route_snapshot`,
  the route-policy snapshot that was all that released the wait). Discarding a spill row after its last retry records
  loss evidence only; the caller imports it into the ledger. Epoch-gap visits accept every pending gap that is not
  parked, so a gap the old owner left waiting for capacity or a capability is served. Conversion, the loss evidence
  writers, epoch-gap demand and parked notices stay, and `RecoveryEligibility` keeps its variants for stored rows. No
  table is dropped.
- Chat-list reads take a query (mdk#2983). `ChatListWindowQuery` replaces its `view` field with `query`
  (`ChatListViewQuery`) and adds `now_ms`, at which a window read's rows evaluate `muted`; `ChatListWindowRead` adds
  `next_mute_expiry_ms`. `ChatListPageError` gains `InvalidQuery` and `SearchTextNotReady` and
  `ChatListSelectionError` gains `InvalidQuery`. `ChatPresentationInput` adds `group_description` (captured) and
  `search_peer_names` (set by preparation). Cross-read paging is gone: `chat_list_page`, `chat_list_page_from_anchor`,
  `ChatListPageQuery`, `ChatListCursor`, the `first`/`last` cursors on `ChatListPage`, and the `InvalidLimit`,
  `CursorMismatch`, `StaleCursor` and `FilteredCursorUnsupported` errors; the runtime window composes its seeks inside
  one read snapshot and keeps its place by anchor chat ID. The unused stateful selection snapshot gives way to
  stateless `chat_list_ids` and `revalidate_chat_list_ids`: `ChatListSelectionSnapshot`,
  `chat_list_selection_snapshot`, `chat_list_selection_count`, `chat_list_selection_page`,
  `revalidate_chat_list_selection` and the `InvalidPage`/`StaleSelection` errors are removed. Block-list rebuilds no
  longer bump the chat-list navigation revision, which nothing reads; migration 0179 drops its triggers.
- New fields on existing records; struct literals add them, or `..Default::default()` where the type has one.
  `TimelineMessageRecord` adds `recipient_confirmed` (mdk#1291) and `imported_from` (mdk#2628 item 4.2d).
  `TimelineMessageQuery` adds `sender`, `since`, `until`, `attachment_type`, `search_wall_clock` and `cursor_group_id`
  (mdk#3245). `ChatListRow` adds `leave_blocked` (mdk#3014), `ChatListMessagePreview` and `TimelineReplyPreview` add
  `tags` (mdk#875), `PendingWelcomeDeliveryRecord` adds `size_class` (`None` when unknown), and
  `AttachmentAcquisitionSource` adds `message_id_hex`.
- `SelfMembership` adds `DeviceRemoved`, stored as `device_removed` (migration 0147). Update exhaustive matches.
- `SqliteAccountStorage::pending_leave_requests` returns each group's whole `LeaveRequest` instead of its request time
  (mdk#3014).
- `apply_group_push_token_tombstone` takes an `AccountGroupPushTokenTombstone` instead of eight arguments, and stores
  its optional removal proof.
- `SqliteSharedStorage::public_directory_profiles` takes the normalized query and the account ids to resolve, and
  returns each profile with its timestamp and match rank (mdk#1801).
- Storage traits: `CapabilityStorage` loses `save_member_capabilities` and `member_capabilities` (migration 0121).
  `StorageProvider` now also requires `AccountDeviceHistoryKeyStorage`, `DeviceGroupWelcomeStorage` and
  `pending_ref_high_water`, which `SqliteAccountStorage` implements; an implementation must keep the pending-reference
  bound across deletions (migration 0175).
- Methods with no caller outside their own tests are gone (mdk#2816): `SqliteAppStorage::remove_group_push_token`,
  `remove_group_push_tokens_for_member` (use `remove_group_push_tokens_for_leaves` with the member as departed),
  `clear_epoch_backfill_intents_for_groups`, `clear_local_group_deletion_frontier_if_message_is_newer`,
  `record_app_event_refreshing_moderation_grant` and its `_with_retention` variant (nothing replaces a stored grant
  any more: re-recording keeps it, and `record_app_event_with_source` decides it once from the source's authority and
  never again), `avatar_acquisition_state` (read `AvatarAssetPresentation::acquisition`) and `release_media_reference`
  (removal releases a slot's reference); `AvatarFileImage::byte_len`, `DatabaseAvatar::byte_len`,
  `SqliteSharedStorage::set_telemetry_install_id` and `impl Default for SqlCipherHardening` (use
  `SqlCipherHardening::cipher_only`).
- The test-only `test-migrated-template` feature and `SqliteAccountStorage::in_memory_from_migrated_template` are
  gone. `in_memory_for_test()` (`test-support`) now copies a migrated template that a test binary's processes share,
  so each test no longer replays every migration, and each copy draws its own store epoch. Before, a template lived in
  one process, so nextest's process per test built it again for every test, and every copy shared one store epoch and
  skipped incremental auto-vacuum.

### Added

- The recovery runner's durable state (mdk#2660), which now drives account history recovery:
  - Migration 0123 adds the coverage ledger. `account_recovery_coverage` holds, per route and relay, the `created_at`
    ranges (inclusive seconds) proved complete and how each was proved; ranges with the same route, relay and proof
    never overlap, and a write merges them. `account_recovery_coverage_goals` holds each route's goal floor; debt is
    the goal minus what is covered. No rows are seeded.
  - Migration 0126 adds the un-cover log (`account_recovery_coverage_uncovers`,
    `account_recovery_coverage_uncover_state`) and `account_recovery_coverage_released`, the seconds released for
    replay that live boundaries leave out. Loss imports and receipt releases append what they un-cover;
    `recovery_coverage_mark` and `record_recovery_coverage_since` let a fetch subtract everything un-covered since it
    started.
  - Migration 0127 adds the runner's retry state: `account_recovery_units` (per route and relay: active, broken or
    retired, backoff, park and probe), `account_recovery_unit_spans` (parked and retired spans, never coverage),
    `account_recovery_relays` (health and NIP-11 caps), `account_recovery_budget` (a rolling-hour account budget),
    `account_recovery_park_revision` and `account_recovery_staged` (a proven slice's unseen events, written with its
    coverage). `SqliteAppStorage` gains `begin_recovery_unit_attempt`, `settle_recovery_unit`, the re-arm, dismissal,
    relay and re-check writers, `stage_recovery_slice` and the matching reads; `RecoveryUnitPolicy` carries the
    caller's policy values. The retention prune trims parked and retired spans at its floor.
  - Migration 0128 adds `route_state` to `account_delivery_loss_evidence` and `account_delivery_loss_evidence_routes`:
    the routes a loss generation lost deliveries on, each with the earliest `created_at` lost there.
    `record_account_recovery_loss_routed` records them; a generation with every charge routed, and at most
    `MAX_LOSS_ROUTES` routes, un-covers only those routes at import.
  - Migration 0130 adds `account_recovery_coverage_remainders`, each route's parked remainder, and
    `settled_below_seconds` to `account_recovery_coverage_goals` (an existing goal starts settled at its own floor).
    `prune_recovery_coverage` takes the current routes with their certifying relays, parks what they still owe between
    each route's settled floor and the retention floor, then settles every route at the retention floor; loss lowers a
    route's settled floor to the loss floor. `recovery_coverage_remainders` reads the remainders.
    `dismiss_recovery_route_park` clears a route's remainder too, and accepts the newest revision among its broken
    units and its remainder, which `parked_recovery_routes` reports. A released receipt (or a discarded staged event)
    below the retention window does not change the ledger.
  - Migration 0132 adds `import_revision` to `account_delivery_loss_evidence` (the loss revision the import that last
    charged a generation left) and `acknowledged_import_revision` to `account_recovery_state`. `recovery_loss_reach`
    returns a `RecoveryLossReach`: where unresolved loss of one cause may have lost events, by route.
  - Migration 0134 adds `recheck_revision` to `account_recovery_units`. Every request that makes a re-check pass due
    bumps it (`make_recovery_recheck_due`, `rearm_all_recovery_units`, and a cooldown longer than
    `RecoveryUnitPolicy::recheck_after_cooldown_seconds` ending), and `RecoveryRecheckPass::revision` reports it.
    `record_recovery_recheck` takes the revision its quantum began on, records nothing once it moved, and returns
    whether it recorded. Ending a long cooldown, by an answer or by `record_recovery_relay_reconnected`, makes every
    re-check on the relay due in the same transaction.
  - Migration 0135 adds `account_recovery_unit_fences`: each capture range a unit fences, one row each, never
    overlapping. `set_recovery_unit_fences` replaces a unit's ranges, `recovery_unit_fences` lists every fenced range,
    `staged_recovery_routes` the routes with staged events, and `reclaim_staged_recovery_routes` drops the rows of
    routes the runner no longer lists, owing their seconds again. The retention prune drops fenced ranges below its
    floor.
  - Migration 0136 adds the one-time upgrade conversion of the old owner's obligations into ledger debt:
    `account_recovery_conversion` (its next step, whether the changed "history may be incomplete" notices still need
    announcing, whether a report is pending, and the shadow rows and units it counted),
    `account_recovery_conversion_counts` (converted obligations by cause and disposition) and
    `account_recovery_conversion_loss` (the loss watermarks of each account and cause whose live loss it un-covered).
    Every database starts with the conversion pending; the account worker runs it after open. `SqliteAppStorage` gains
    `convert_recovery_obligations` (a `RecoveryConversionInput` of `RecoveryConversionRoute`s),
    `recovery_conversion_pending`, `recovery_conversion_report` (a `RecoveryConversionReport` of
    `RecoveryConvertedObligations` by cause), `acknowledge_recovery_conversion_report`, `converted_recovery_loss`,
    `reclaim_converted_recovery_loss`, `recovery_conversion_notices_changed` and
    `acknowledge_recovery_conversion_notices`. The last step reopens every epoch gap the old owner certified as
    pending, ready demand (mdk#3059): the old owner satisfied a gap once its relays answered for its window, never
    once the engine left the stalled epoch, so a group still stalled there was never revisited and showed no notice.
    Migration 0152 counts them in `account_recovery_conversion.epoch_gaps_reopened`
    (`RecoveryConversionReport::epoch_gaps_reopened`); a database that converted before it reopened none.
  - Migration 0150 adds `account_recovery_epoch_gap_retries`, the durable return-visit state for unresolved epoch
    gaps. `SqliteAppStorage` gains `recovery_epoch_gap_retry`, `begin_recovery_epoch_gap_retry` and
    `finish_recovery_epoch_gap_retry`, with `RecoveryEpochGapRetry`, and `import_recovery_loss_to_ledger`, which turns
    loss recorded after the conversion into ledger debt.
  - Migration 0151 adds `account_recovery_units.saturated_second`: the second the unit's last answered quantum stopped
    on because its relay cannot prove it. `RecoveryUnit` gains `saturated_second`, and
    `settle_recovery_unit_saturated` settles an outcome while recording it; `settle_recovery_unit` records an
    unsaturated answer. `record_recovery_relay_caps` clears it on a unit planned under other caps. Existing units
    start unsaturated.
  - Migration 0153 records the local copy of each group the ledger last settled (mdk#2660 row 11):
    `account_recovery_copies` holds its install epoch, a rejoined copy's floor and the one notice a rejoin raises,
    `account_recovery_copy_routes` the group's routes that floor holds on (with relays or without), and
    `account_recovery_copy_units` the relays that retired what lay below it. Existing groups start with the copy their
    engine record holds at the upgrade (unknown only when the record does not decode), so a rejoin from before the
    upgrade raises nothing and one applied after it, even before the runner's first turn, does.
    `settle_recovery_rejoin` retires, in one transaction, what each of a rejoined group's routes owed or parked below
    the new copy's floor as `BeforeThisCopy` (never coverage), restarts those units with a fresh budget, drops the
    routes' remainders below the floor and raises the notice; it settles each copy once. `retire_before_recovery_copy`
    retires below the recorded floor on a relay that joined one of the group's routes after the rejoin, or returned to
    it, once per relay. Forgetting a group, or deleting a terminal one, drops its copy.
    `widen_recovery_coverage_goals` and `uncover_recovery_coverage` take a `CopyFloorReason`: `Clamp` keeps the write
    at or above the highest floor a rejoin recorded for the route, so goal widening, post-join un-covers and every
    `begin_recovery_epoch_gap_retry` visit stop there; `Loss` and `Repair` reach below it. A released receipt or a
    staged row given back still un-covers its own second below the floor, so the re-check fetches it again, and only
    that second: when it lies below the route's goal, the seconds its goal widening opens below the floor retire as
    `BeforeThisCopy`. `retire_gone_recovery_units` keeps what was retired below the floor with its reason, and the
    retention prune parks nothing from below the floor: a held second below it (or debt loss reopened below it) that
    is still unfetched when retention passes it drops without a remainder; the runner sweeps it for the whole
    retention window and the rejoin's notice already covers that history. Nothing but loss, explicit repair or one
    held event's second makes a rejoined route owe below its floor again; a route no rejoin settled is unchanged. Also
    new: `recovery_copy`, `recovery_copy_floor`, `record_recovery_copy`, `recovery_rejoin_notices`,
    `dismiss_recovery_rejoin_notice` and `recovery_copy_debt` (a route's debt on one relay less what a rejoin retired
    there).
  - `dismiss_recovery_route_park_on` dismisses a route's broken units on the given relays and its remainder, checking
    the revision against them only; a broken unit on any other relay stays as it is.
  - `settle_recovery_recheck` applies one re-check quantum's outcome to its relay and the account's rolling-hour
    budget, never to its unit's retry state. `staged_recovery_items` lists the ids and times a route has staged in a
    range, from every relay. `make_recovery_recheck_due` keeps what a due or running pass would check below an epoch
    gap's bound.
- Push-token gossip (mdk#2604, mdk#2611):
  - Migration 0117 queues the current push registration once for every joined group while native push is on, so
    members who joined before this release receive this device's token.
    `queue_current_push_registration_share_for_group` queues the stored registration for one joined group again,
    including a revision whose share already completed; it does nothing while native push is off or without a
    registration.
  - Migration 0118 adds `token_fingerprint` and `owner_sig` to push tombstones, which existing tombstones leave NULL,
    and `group_push_gossip_state`. `group_push_token_tombstones` lists a group's tombstones: one with an
    `AccountPushTokenRemovalProof` can be relayed as the owner's signed removal; one without, written before migration
    0118, stays local-only until the same removal is applied again with its proof. `group_push_gossip_state`,
    `record_group_push_gossip_join` and `record_group_push_gossip_announce` keep when this device's join became final
    and when it last announced, for its current membership. Writes need a joined group; the row goes when the device
    leaves or is removed, and with the group.
  - Migration 0119 adds `snapshot_owed_after_epoch`, with a partial index over the rows that owe one, and
    `AccountGroupPushGossipState` the matching field. `record_group_push_snapshot_owed`, `owed_group_push_snapshots`
    and `replace_group_push_snapshot_owed` keep the push snapshot this device owes a group after a Commit of its own
    adds leaves: the latest source epoch wins, and replacing or settling it needs the epoch it still holds.
  - Migration 0122 adds `joining_since_ms`, `join_window_counted_ms` and `announce_owed_at_ms`, with partial indexes
    over the rows that have a window or owe an announce. Saving the projection opens this device's push join window in
    a group when a Welcome installs or replaces its copy there; an earlier join time and its counted window time are
    dropped, and a group this device created has no window. `joining_group_push_gossip_states` lists the open windows
    and `count_push_join_window_time` adds time to every one whose join has completed.
    `record_group_push_announce_owed` and `owed_group_push_announce_states` keep the other announces this device owes
    a group: each new debt raises the stored value past the last, even if the clock went back, and returns it.
    `record_group_push_gossip_announce` closes a window, and takes the owed value the published announce was built
    under so that it settles the debt only while the debt still holds that value; a new Welcome drops it.
- Typed chat-list queries (mdk#2983). `ChatListViewQuery` (a `ChatListView` plus an optional `ChatListFilter`)
  compiles to SQL on the view's page index, with bound parameters, before keyset paging; `chat_list_ids(query,
  now_ms)` and `revalidate_chat_list_ids(query, ids, now_ms)` take `impl Into<ChatListViewQuery>`, so a `ChatListView`
  still works. `ChatListQueryError` is typed, and `ChatListFilter::from_nodes` builds a filter from the bindings' flat
  node list.
  - `Direct`, `Group` and `Muted` conditions. Migration 0179 adds `chat_list_rows.list_kind`, kept equal to the
    classifier's conversation kind by triggers on the row's group name and the account group's member count; an
    Unknown kind matches neither leaf. `Muted` tests mute settings against the read's time, so nothing is written when
    a mute expires; `ChatListWindowRead::next_mute_expiry_ms` is the next mute expiry in the view for a query that
    tests `Muted`. The migration drops 0072's unread navigation-revision triggers; `chat_list_navigation_meta` stays
    for the pin-rewrite flag.
  - A `Text` leaf: a literal substring match, after trimming and Unicode lowercasing, against the title, group name,
    description and a direct chat's peer profile names. Migration 0200 adds `chat_list_rows.search_text`, written by
    `store_chat_presentation`; widens `chat_presentation_dependencies.roles` with a search role so every eligible peer
    is a dependency; and makes a group description change invalidate the row's presentation. While any chat in the
    view has pending presentation, a `Text` query returns `ProjectionNotReady` (selection) or
    `ChatListPageError::SearchTextNotReady` (window read); other queries are unaffected. A presentation write that
    changes only the search text still advances the presentation revision. New: `normalize_search_text` (shared with
    user directory search), `MAX_CHAT_LIST_FILTER_TEXT_BYTES` (1024, across all leaves;
    `ChatListQueryError::TextTooLong`) and `chat_list_pending_search_text`.
  - A `MessageText` leaf: chats with a visible message whose text contains the query, by the `Text` rule. A visible
    message is a chat message or poll question in `visible_message_timeline`, in its latest edit, not deleted, not
    invalidated (except an own send that reached no one, which the row previews as failed), and not past its
    disappearing-message expiry at the read's `now_ms`. It scans each chat's history, so only `chat_list_ids` and
    `revalidate_chat_list_ids` accept it: every window read refuses it with `ChatListQueryError::MessageTextInWindow`
    before reading (`ChatListViewQuery::validate_for_window`). While the content-report backfill is owed, a
    `MessageText` query returns `ProjectionNotReady`. No migration.
- Advanced timeline search (mdk#3245). `TimelineMessageQuery` adds an exact `sender`, an inclusive `since` and
  exclusive `until` on `timeline_at`, and an `attachment_type` (`TimelineAttachmentType`) read per `imeta` tag: image,
  video and audio match case-insensitive MIME prefixes, file matches an attachment with none of them, and a message
  with an image and a separate file matches both. Every filter applies before the page limit, and a damaged tag blob
  matches no attachment instead of failing the search. An account-wide search can order by wall clock
  (`search_wall_clock`), with `cursor_group_id` as its cursor's group component.
- Sonar-compatible stickers (mdk#875). Migration 0141 adds the pack projection (`app_sticker_packs`, `app_stickers`),
  the installed list with its pending install operations, and the sticker outbox; migration 0142 adds
  `app_sticker_assets`, the exact-hash history that keeps a sticker a stored message names resolvable after its pack
  changes. They are numbered after the private KeyPackage schema, so a database already at schema 140 still creates
  them. `SqliteAppStorage` gains `replace_sticker_pack_if_newer`, `sticker_pack`, `sticker_packs`, `sticker_for_ref`,
  `prune_uninstalled_sticker_discovery`, the installed-list and install-operation reads and writes, and the outbox,
  with the `Stored*` sticker records. A pack changes only when the incoming event wins NIP-01 replacement; a winning
  replacement refreshes asset URLs and metadata for an unchanged exact hash, and an older pack event cannot revert it.
  Each pack keeps at most 400 historical assets; current-pack rows and assets a retained message references are never
  dropped. Migration 0141 also adds `chat_list_rows.last_message_tags_json`, so chat-list and reply previews carry the
  message's tags (`ChatListMessagePreview::tags`, `TimelineReplyPreview::tags`) and can resolve an exact sticker
  reference.
- Migration 0178 adds NIP-51 emoji set tables: the discovered projection and installed snapshots holding each emoji's
  bytes and SHA-256. New `SqliteAppStorage` emoji set methods; installs verify every digest and the set and byte caps
  in one transaction.
- Migration 0167 indexes active kind-7 reaction attachments from retained app events without creating timeline rows
  (mdk#2151), backfilling existing artwork and sharing normal acquisition, permission and retention behavior.
  `reaction_attachment_candidates` provides bounded message-scoped source discovery. Incremental projection and
  rebuilds preserve unchanged slots; authenticated reaction retractions and withdrawals revoke changed sources.
- Migration 0172 adds the protocol-owned `cgka_group_rejoin` journal for automatic rejoin, with one recipient job per
  group and bounded coordinator jobs. Capacity refusals preserve existing work. A retained nonce cannot change its
  peer or recipient local state token; refused writes leave the exact outbound artifact and retry evidence intact.
  Same-job phase, retry and source refreshes remain writable. Group deletion cascades to its jobs. Runtime ownership
  retains exact publication artifacts and per-member Commit cooldowns. Separate native and authenticated remote epoch
  baselines allow a taller losing copy to rejoin. A durable one-shot remote rearm caps each episode at 64 reservations
  between native/admin changes or explicit retry. Nonce rotation clears remote-only height claims, not cost or the
  spent refill.
- Migration 0175 adds a full-width pending-reference watermark outside group snapshots. Saved fanout and evolution
  writes raise it atomically; deletion never lowers it. Undecodable pre-index artifacts abort the migration rather
  than guess a safe handle; malformed artifacts after indexing stay isolated to their group. Stored-message variant 13
  keeps a confirmed Welcome's origin Commit; existing originless variants keep their bytes and handling.
- Migration 0177 adds a nullable coarse size diagnosis (`PendingWelcomeDeliveryRecord::size_class`) to pending Welcome
  repair pointers. Old rows read as unknown; unknown future annotations preserve the pointer. Updating a failure
  diagnosis keeps its existing identity and oldest-first position and adds no retry owner.
- `ChatListRow::leave_blocked`, read with `leave_requested_at_ms` from the engine's leave request (mdk#3014). No
  schema change.
- Migration 0147: `SelfMembership::DeviceRemoved` marks a chat this device's leaf was removed from while the account
  stays in it. The migration recreates the chat-list triggers so such a chat lists with the departed chats, and it
  suppresses the chat's unread like the other departed states.
- `OpenMlsContentFilter::CommitsAndProposalsBetween` lists only the commits and proposals whose MLS epoch falls in a
  range, plus the rows SQLite cannot classify (mdk#2684). A failed convergence batch checks its horizon through it on
  every load, reading neither the group's applications nor its older history.
- Storage for experimental device groups, history transfer and backups (mdk#2628), which marmot-app enables only in
  `dev-device-groups` builds:
  - Migration 0125 adds `device_groups`, one row per device group this device knows of, with how it came to know it:
    `creating`, `created`, `awaiting_welcome`, `linked` or `untrusted`. `SqliteAppStorage` gains `device_group`,
    `device_groups`, `insert_device_group`, `set_device_group_trust` and `delete_device_group`. At most one row claims
    the account's device group. A local forget removes the group's row.
  - Migration 0129 adds `cgka_device_group_welcome_expectations`, one row per device group a confirmed link waits to
    join: the sender leaf's signature key, the confirmed KeyPackage's `KeyPackageRef` (`key_package_ref`) and the end
    of the wait. `SqliteAccountStorage` implements `DeviceGroupWelcomeStorage` over it;
    `device_group_welcome_expectations` lists every stored expectation, expired ones included (D41). The engine
    consumes a row with the join it admits, and the app deletes it when a link is withdrawn or its wait ends.
  - Migration 0131 adds `account_sign_ins`, one row per KeyPackage slot of the account that this device found and does
    not recognize: whether this device's first check returned its slot, its client name, when it appeared and last
    published, its newest KeyPackage, whether it is still signed in, and this device's answer, with whether the device
    group's roster records a rejection yet. `account_sign_in_baseline` holds when the first check ran, and
    `account_sign_in_baseline_slots` every slot its read returned. `SqliteAppStorage` gains `record_sign_in_check`,
    `sign_ins`, `sign_in`, `answer_sign_in`, `settle_sign_in_rejection`, `rearm_sign_in_rejections` and
    `sign_in_baseline`.
  - Migration 0133 adds `device_links`, one row per device this device approved adding to the account's device group,
    written before the approving commit, with the added KeyPackage's `KeyPackageRef` (which also finds the link's
    Welcome) and its leaf's signature key, its outcome (`pending`, `linked` or `failed`), and whether a failed link's
    Welcome is withdrawn; and `device_group_joins`, the device groups this device joined through a link whose first
    commit there has not landed yet. `SqliteAppStorage` gains `record_device_link`,
    `mark_device_link_welcome_withdrawn`, `device_link`, `device_links`, `decide_device_link`,
    `record_device_group_join`, `device_group_joins` and `delete_device_group_join`. A local forget removes the
    group's rows.
  - Migrations 0137 and 0171 add `device_renames`, one row per device this device renamed in its device group's
    roster: the label and, for user edits made since 0171, the three settings flags its latest edit sets
    (`DeviceRenameRecord::settings`; legacy NULL rows stay label-only), the rename ids that edit wrote, and the rename
    ids the device's entry held where this device's edits of it were built (D37, D86). `SqliteAppStorage` gains
    `device_renames`, `device_rename`, `put_device_rename` and `drop_device_rename`.
  - Migration 0138 adds `cgka_account_device_history_keys`: this device's HPKE history key pair, one per
    account-device identity, next to its MLS signer's binding. `SqliteAccountStorage` implements
    `AccountDeviceHistoryKeyStorage`; `put_account_device_history_key_if_absent` never replaces a stored key.
  - Migration 0139 adds `app_event_imports`, which marks each app event imported from a sibling's history (item 4.2a).
    `SqliteAppStorage::import_app_events` records only events the account does not hold, as received rows with their
    epoch and no transport id, and `app_event_import_source` reads the mark. An imported review label or admin removal
    takes the sender's verdict (`ImportedAppEvent::moderation_grant`) and has no authority without one. Unread counts
    and the retention sweep's unread check skip imported rows, so they never count as unread and expire on time; the
    read marker never moves for them. `history_export_page` reads a chat's app events in chat order (epoch,
    `created_at`, id) for a history bundle, with no event for each row that must stay out.
  - Imported timeline rows name their source (item 4.2d): `TimelineMessageRecord::imported_from`
    (`HistoryImportSource`), read from `app_event_imports`, with the device's name from `set_device_labels`, which
    marmot-app gives from the roster. The names live in a TEMP table each account connection creates at open, so
    nothing is stored. `latest_history_imports` reads each chat's latest import and `parked_history_chats` each chat
    parked deliveries name, with whether a fetch failed. `watch_history_imports` starts a per-connection TEMP count of
    every change those reads see, and `history_imports_generation` reads it; `set_device_labels` writes only when the
    names differ.
  - Migration 0140 adds private KeyPackages, single-use KeyPackages a device hands to one sibling inside its device
    group (item 3.4): `cgka_private_key_packages` (one issuer record per KeyPackage, its key in the OpenMLS bundle
    store), `private_key_packages_received` (what siblings handed this device, by issuer slot; one this device used
    keeps its ref until it expires, so it is not kept again if handed over again) and `private_key_package_requests`
    (what this device still wants from each issuer). `SqliteAccountStorage` implements `PrivateKeyPackageStorage`;
    `SqliteAppStorage` gains the received-KeyPackage and need reads and writes. A caller reads
    `received_private_key_packages_from`, validates the record it selects, then calls
    `take_received_private_key_package_exact`.
  - Migration 0143 adds `device_activity`, one row per sibling the trusted device group's roster lists (that entry's
    `linked_at`, when this device first found it there and the newest time one of its heartbeats counted for), and
    `device_heartbeat_sent`, the device group this device last sent its own heartbeat in and when. `SqliteAppStorage`
    gains `device_activity`, `track_device_activity`, `note_device_active`, `device_heartbeat_sent` and
    `put_device_heartbeat_sent`, with `DeviceActivityRecord` and `DeviceHeartbeatSent`.
  - Migration 0201 adds the inactivity clock for marking and removing inactive siblings (item 3.6b-2):
    `device_activity` gains `clock_from` and `marked_inactive`, and the single-row `device_inactivity_clock` keeps
    this device's last caught-up pass and last restart. `note_device_active` restarts a sibling's clock when it reads
    a heartbeat that moves its activity later; new `note_device_marked_inactive`, `device_inactivity_clock`,
    `put_device_inactivity_clock` and `epoch_gap_recovery_given_up`. The device-group reset wipe clears the clock.
  - Migration 0145 adds `cgka_roster_tag_keys` (mdk#2761): one row per tag signature key a device-group roster this
    device applied listed for a slot, in a device entry or a `removed` record, with when it last applied one that did,
    the order it applied them in (`seen_seq`), and whether one listed it in a `removed` record (`held_as_removed`).
    `SqliteAccountStorage` implements `RosterTagKeyStorage`. Rows survive a branch-selection rewind, go with their
    group, and are pruned after 30 days or past 4 per slot; a slot's newest row held as removed is kept past the 4.
  - Migration 0146 adds `device_removals`, one row per device this device's user removed from the account's device
    group, written before anything is committed, with when the user decided and when the removed device's slot
    deletion was accepted. Only forgetting the group removes its rows. `SqliteAppStorage` gains
    `record_device_removal`, which keeps a decision already recorded, `device_removals` and
    `set_device_removal_slot_withdrawn`.
  - Migration 0148 adds the compromise warning (items 3.7a and 3.7b): `account_compromise_warning_items`, one row per
    rejection or foreign KeyPackage the warning gathers, keyed by its reason and subject, with when it was made, when
    this device first gathered it and when the user saw it; a seen row stays, so a rejection that comes back does not
    warn again. `account_compromise_warning_baseline` names the device group this device first trusted, whose roster's
    rejections then count as seen, and `account_sign_in_baseline.started_fresh_at` records that the user started this
    device fresh. `SqliteAppStorage` gains `record_compromise_warning`, `record_foreign_own_slot_key_packages`
    (KeyPackages this device found in its own slot that it did not make, reason `ForeignOwnSlotKeyPackage`, D74),
    `compromise_warning`, `dismiss_compromise_warning`, `start_fresh`, `started_fresh` and `trust_device_group`, which
    makes a device group trusted and takes its roster as this device's first in one transaction; `insert_device_group`
    and `set_device_group_trust` refuse a trusted state. A seen foreign KeyPackage goes 7,261,200 seconds after it was
    found, an unseen one stays until dismissed or the 4,096-row cap drops it.
  - Migrations 0149 and 0166 add sealed history deliveries (items 4.2b and 4.2c, D76, D77). `cgka_sibling_adds` holds
    each sibling slot one of this device's own confirmed Commits added to a group, written by the engine through
    `SiblingAddStorage` (`record_sibling_adds`, which also drops adds a week old, `sibling_adds`,
    `forget_sibling_add`); a rewind keeps its rows and deleting the group drops them. `history_deliveries_owed` holds
    the histories this device owes its siblings (`owe_history_delivery`, `unsent_history_deliveries`,
    `mark_history_delivery_sent`, `forget_history_delivery`), and a history too long for inline deliveries goes
    through Blossom (`blossom_due_at`, `blossom_attempts`; `send_history_delivery_by_blossom`,
    `due_blossom_history_deliveries`, `defer_blossom_history_delivery`). `history_delivery_sends` names the chat and
    receiver of each delivery sent, so `owe_history_delivery_again` owes the history of a delivery withdrawn or failed
    for good again and returns it (`Option<OwedHistoryDelivery>`). `history_deliveries_parked` keeps at most 1,024
    deliveries read before this device holds their chat, each with its bundle or the Blossom servers that hold it and
    when to fetch it (`ParkedBundle`, `park_history_delivery`, `parked_history_delivery_chats`,
    `parked_history_deliveries`, `drop_parked_history_delivery`, `due_parked_history_fetches`,
    `defer_parked_history_fetch`). `expire_history_deliveries` drops rows a week old, and a local forget of a chat
    drops its rows. `device_group_message_event_id` reads the app event id of a recorded device-group message. Test
    support gains `execute_batch_for_test`.
  - Migration 0160 adds `sibling_welcomes_received`, the sibling Welcomes this device admitted from its device group
    and has not joined from yet, keyed by the message that carried each, at most `MAX_STASHED_SIBLING_WELCOMES` at
    once. A row the engine held, because this device still held an active copy of its chat, keeps that chat's id, and
    a full stash drops its oldest held row to keep a new one. `SqliteAppStorage` gains `stash_sibling_welcome`,
    `stashed_sibling_welcomes`, `hold_stashed_sibling_welcome` and `delete_stashed_sibling_welcome`, over
    `StashedSiblingWelcome`.
  - Migration 0161 adds small state (item 4.3): `small_state_items`, one row per chat and item (`read`, `pin`, `mute`,
    `archive`) holding the value the account's devices agree on, what this device last observed of it and whether its
    siblings are still owed it, and `small_state_sync`, which records that this device started, when and at which
    device-group tip it last broadcast every item, and whether it owes a broadcast request or an answer to one. Only
    chats whose MLS group id is at most 256 bytes hold items. It also adds `device_group_messages`: the kind of each
    device-group message this device sent or read whose withdrawal a feature acts on, by app event id and, once known,
    the message id the engine names it by, kept a week and capped at 4,096 rows. `SqliteAppStorage` gains
    `record_device_group_message`, `note_device_group_message_ids`, `device_group_message_kind`, `start_small_state`,
    `small_state_started`, `small_state_schedule`, `begin_small_state_broadcast`, `owe_small_state_broadcast_request`,
    `small_state_broadcast_request_sent`, `owe_small_state_broadcast_answer`, `sync_small_state`, `small_state_items`,
    `unsent_small_state_items`, `mark_small_state_sent` and `owe_all_small_state_items`, with `SmallStateItem`,
    `SmallStateRule`, `SmallStateSchedule`, `SmallStateBroadcast` and their value types.
  - Migration 0162 adds `imported_media_file_keys`, the per-file attachment keys a sibling sent with imported history.
    Each key is named by its media reference's `ciphertext_sha256`, is zeroed before its app event is deleted, and
    goes with it. `ImportedAppEvent::file_keys` carries the keys, and `import_app_events` stores them only for rows it
    adds, refusing a second, different key for a ciphertext the chat already holds one for. `imported_media_file_key`,
    `imported_media_file_key_for_ciphertext` and `imported_media_file_keys` read them, and
    `AttachmentAcquisitionSource::message_id_hex` names the message. Imported chat messages get attachment slots,
    which a timeline rebuild keeps: `attachment_history_source` and its insert trigger take a row without a transport
    id when `app_event_imports` marks it, using its app event id as its `source_message_id_hex`.
  - Migration 0163 adds `backup_recovery_key`, at most one row: the public half of the recovery key that words
    confirmed while this device trusts no device group derive (item 4.4a). `trust_device_group` deletes it in the same
    transaction, since the roster's account entry is then the account's. The words and the private half are never
    stored. `SqliteAppStorage` gains `kept_recovery_key`, `keep_recovery_key` and `forget_kept_recovery_key`.
  - Migration 0164 adds the backup ledger (item 4.4b): `backup_runs` and `backup_run_blobs` (each backup this device
    is writing until a relay accepts its pointer, and its blobs, recorded before upload), `backup_condemned_blobs`
    (blobs to delete while no pointer lists their backup) and `backup_schedule` (the next pass, and the writer this
    device last saw named for a key). Nothing secret is stored. `SqliteAppStorage` gains `backup_schedule`,
    `schedule_backup_pass`, `note_backup_writer`, `begin_backup_run`, `record_backup_run_blob`,
    `record_backup_run_head`, `backup_runs`, `finish_backup_run`, `abandon_backup_run`, `condemn_backup_blobs`,
    `due_condemned_backup_blobs`, `next_condemned_backup_try`, `defer_condemned_backup_blob`,
    `forget_condemned_backup_blob` and `forget_backups_except`, with `BackupRun`, `BackupRunHead`, `BackupSchedule`
    and `CondemnedBackupBlob`.
  - Migration 0168 adds the private backup-restore catalog (`backup_restore_catalog`, `backup_restore_catalog_chats`:
    each recovery key's backups and the chats they hold; `put_backup_restore_archive`,
    `retain_backup_restore_archives`, `backup_restore_archives_for_chat`) and lets an `app_event_imports` row name a
    backup instead of a sibling slot as its source. Catalog metadata creates no group, route or membership, and each
    key's complete pointer prunes only its own catalog.
  - Migrations 0169 and 0174 add sibling-Welcome repair (D70, D89, D100): `sibling_welcome_resends` keeps one repair
    generation per original Welcome, with its first accepted publication time and its carrier reservation and
    high-water. A resend is due from current-incarnation D35 heartbeats (`sibling_welcome_resend_is_due(welcome_id,
    linked_at)`), and `sibling_welcome_resend_batch` returns `(welcome_id, carrier)` pairs.
  - Migration 0170 adds native admission metadata (`cgka_invitation_admissions`) and per-generation invitation
    decisions synced between linked devices (`invitation_decisions`), with atomic owed publication, application and
    Leave work (D96). No legacy group is seeded from its current epoch.
  - Migration 0176 adds `device_group_moves`, which holds a move of this device to another device group, at most one
    of them pending (D102).
  - Explicitly forgetting an active trusted nonterminal device-group copy with no unfinished move retires old
    device-sync preparations atomically. Ordinary chat data, admitted work, issued private keys and taken-reference
    tombstones stay; no migration.

### Changed

- `account_groups.member_count` counts member accounts, so an account with several devices in a group counts once and
  a chat between two accounts is `Direct` (mdk#2628). Migration 0120 rewrites rows whose engine record lists an
  account more than once, with the peer index and presentation members their accounts make; every other row already
  counted accounts.
- The engine reads each current leaf's capabilities from the MLS tree instead of the per-account
  `cgka_member_capabilities` cache, which migration 0121 drops: with several devices per account, one device's
  capabilities stood in for all of them, so a capability could be offered as an upgrade while a device lacked it.
  Snapshots and checkpoints keep their v2 layout: the retired list is written empty, and rows in older snapshots are
  skipped.
- A peer's reaction settles a send whose publish was judged to have reached no one (mdk#1291).
  `TimelineMessageRecord::recipient_confirmed` is true for a failed own row with no relay acceptance that another
  account reacted to, which proves that peer received it; a pending send is not settled. Such a row projects as
  delivered, with no `invalidation_status` and, as before, no `source_message_id_hex`; the chat list reports it
  `Delivered` and ranks it where it ranked as a failed send, never as a pending one. The stored `app_events` row keeps
  `local_publish_failed`, so a resend, the terminal-group sweep and convergence withdrawals are unchanged. A peer
  retracting its reaction returns the row to its failed state. When retention prunes the confirming reaction while the
  send stays, the receipt is kept in `kept_recipient_receipts` and goes with the send. Migration 0173 adds
  `message_timeline.recipient_confirmed` and that table, rebuilds the chat-preview index and settles existing rows
  from their stored reactions.
- Timeline `search` matches by the chat-list `Text` rule: Unicode lowercasing instead of SQLite's ASCII-only `NOCASE`,
  so `école` finds `ÉCOLE`. ASCII matches are unchanged. Account connections register a `marmot_search_contains` SQL
  function for both.
- Cached user search filters and ranks in SQL (mdk#1801). Account and shared connections register `marmot_search_rank`
  (exact, prefix, contains or no match, by the same Unicode rule), and `public_directory_profiles` applies its
  10,000-identity cap after matching, so it finds identities past the 10,000th cached one.
- Idle maintenance reads answer without a writer transaction (mdk#2923 step 1): upload recovery and pruning,
  recovery-job retention, the push join-window count, chat presentation inputs, and recovery conversion and loss
  import each check read-only first. New reads: `content_reports_backfill_complete`, `has_legacy_attachment_work`,
  `has_database_held_avatars`, `has_file_backed_uploads`, `media_cleanup_epoch` (a per-connection count of deleted
  `media_files` and `attachment_partial` rows, kept in TEMP tables; no migration) and `connection_serial`, unique to
  each opened handle.

### Fixed

- One `app_events.tags_json` value that does not decode is read as no tags by every reader, not only the group rebuild
  (mdk#2845). Before, it blocked its commit's withdrawal, its group's terminal sweep, retention erasure, held-send
  deadlines, deletes aimed at it, poll tallies, history export, report reads and raw message reads. Where the tags
  were the only record of what a row changed, the readers that must act on it recover its targets and media from its
  modifier edges and timeline row.
- `adopt_block_list` takes the write lock up front in an IMMEDIATE transaction and retries the whole transaction on
  `SQLITE_BUSY` (mdk#3046). A deferred read-then-write failed at once when the account engine's connection held the
  write lock, so a `block_user` the relay had accepted reported `BlockPublicationUncertain`.
- Migration 0180 preserves original removal validation separately from source authority, so damaged tags cannot turn
  an invalid removal into a valid one (#3016). Validated removals retain their effect through pruning. Uncertain
  legacy removals preserve only already-hidden targets and cannot hide new targets; verified repair remains tracked in
  #3017.
- `prune_expired_attachment_acquisitions` and `prune_attachment_partials` answer "nothing expired" from their expiry
  indexes and run their cached `DELETE` only when a row has expired. Compiling that `DELETE` coded every trigger and
  foreign-key action on the table on every call (mdk#2923).
- `delete_group` joins a caller's `with_transaction` instead of beginning its own, which failed inside one, so the
  engine's cleanup of a failed group creation now removes the group's MLS state.
- A queued proposal or proposal-queue ref list that fails to decode in the MessagePack value encoding clears the
  group's proposal queue, as a corrupt JSON row already did, instead of failing group load.
- A transaction SQLite rolled back by itself (a full disk, an I/O error or out of memory mid-statement, a trigger's
  `RAISE(ROLLBACK)`, a failed `COMMIT`) no longer marks the account's connection unusable until the account reopens.
  The caller gets the failure's own error, so a full disk reaches it as `StorageError::Capacity`, and the rest of that
  transaction, inside or after a savepoint, fails instead of committing write by write.

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
