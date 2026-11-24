# AGENTS.md - crates/marmot-session

Agent map for the account-device runtime and session crate. Overview and test coverage: [`README.md`](README.md). Test
placement: [`tests/AGENTS.md`](tests/AGENTS.md).

## Scope

Owns the account-device layer between `marmot-app` and the engine. `AccountDeviceRuntime` coordinates one session with a
pluggable `TransportAdapter`: transport account activation, transport routing policy, KeyPackage publication, durable
maintenance, and publish confirmation/rollback. `AccountDeviceSession` wires `Engine<SqliteAccountStorage>` into an
app-facing session lifecycle (`SessionConfig`, `SessionEffects` / `PublishWork`).

It must not own MLS internals, transport event parsing, SQLCipher key derivation, account homes or signing-key storage
(those are `marmot-account`'s), UI projection, notifications, real relay auth, or transport-specific relay discovery.

## Layout

`src/lib.rs` is a thin facade: crate docs, `mod` declarations, and `pub use` re-exports. Every public item has a
`marmot_session::Item` path. Source is split into focused modules:

- `session.rs` — `SessionConfig`, `AccountDeviceSession`, `SessionEffects` / `PublishWork`, `SessionError`, and the
  engine items the session's API exposes, re-exported under their engine names. The module is private, and the root
  re-exports `AccountDeviceSession` and `IngestEffects` only under `test-support`.
- `error.rs` — `AccountError` and the `AccountResult` alias.
  `AccountError::as_engine_error` finds the engine error whether the runtime met it directly or through the session;
  ask it instead of matching `Engine(..)` or `Session(..)`.
- `key_package.rs` — `KeyPackagePublisher` trait, `KeyPackagePublication`, and `NoopKeyPackagePublisher`.
- `routing.rs` — `TransportRoutingPolicy` trait, `TransportRoutingError`, and `StaticTransportRouting`.
- `recovery_key.rs` — `seal_to_recovery_key` without a session (mdk#2628 4.4b): the engine's sealing under the
  engine's own stateless crypto provider, for a backup written off the account worker.
- `runtime.rs` — `AccountDeviceRuntime` plus its effect aggregates (`AccountDeviceEffects`, `AccountIngestEffects`,
  `PublishFailure`, `PendingResolution`), durable maintenance, and KeyPackage generator upgrades.
  - `runtime/slot_announcement.rs` — the slot-announcement gate (mdk#2628 3.4): while the host names a device group,
    no KeyPackage reaches this device's slot until this device's own roster entry there names it. Maintenance
    announces first.
  - `runtime/own_slot.rs` — the own-slot check's runtime half (mdk#2628 3.4): the host hands over publications in this
    device's slot that it did not make. `slot_publication_superseded` is the one test of whether a publication of this
    device's own still stands there; every step that stages, publishes, resends or republishes asks it. One dated past
    the skew window is deleted by id (D63) and never outranked, so it never holds back a refresh. A relay the host read
    as serving nothing in the slot, though it accepted the current publication, gets a new KeyPackage
    (`refill_emptied_slot`) once that publication is a day old, so one that keeps nothing costs one a day.
  - `runtime/device_roster.rs` — this device's reads and writes of its device group's roster: its slot, the merged
    roster, the gate its roster commits wait behind (`device_group_takes_commit`: not stable, held, quarantined,
    settling, or a change of this device's still queued, unconfirmed or owed a re-issue that maintenance has not yet
    re-derived; public, so the host judges a lost rename, and answers a backup change, only once its commits there have
    an outcome), and the sends. The runtime's roster-writing steps use these rather than
    their own copies. Device entries have one write path (`edit_device_roster_entry`, mdk#2628 3.4, 3.6): one
    `SetDevice` commit replacing one device entry with an edit applied to the roster as read now, sent as
    `SendIntent::ReplaceDeviceEntry` naming the entry it read. Label/settings changes must supply a present fresh
    rename id (D86); other edits must preserve it. Validate before staging, and never generate an id behind a caller's
    write-ahead journal. The engine stages it only while the slot still holds
    that entry, so an entry is never replaced from a stale read (`DeviceEntryChanged` maps to `Busy`). Announcements,
    the tag signature key and the host's device edits all go through it; don't add another general device-entry commit.
    The sole D102 exception is the completed move's explicit old-group `MarkDeviceGroupMoved`, an own complete-entry
    CAS changing only status, preserving label/settings/rename id and the original group's tag; it is not a generic
    entry writer. `set_device_tag_key_in_group_holding` still uses the existing entry-edit path for the destination's
    first own key Commit and never changes the globally named group. Only the outer App pairing drive authorizes the
    session's present-proof Made transaction, not generic sync/projection/recovery callbacks. Each
    announcement also writes the host's `DeviceSelfReport` (this device's client and platform) and this device's
    history key (4.1) into its own entry; the tag-key commit carries the history key too. Only this device's own
    entry ever gets its history key. The account entry (backup writer and recovery key, 4.4a) has one write path
    too, `edit_roster_account_entry`, sent as `SendIntent::ReplaceAccountEntry` naming the entry it read
    (`AccountEntryChanged` and `AccountEntryUnsettled` map to `Busy`).
    `send_device_roster_update` carries rejected-slot operations only.
  - `runtime/device_tag_key.rs` — this device's tag signature key (mdk#2628 3.1d): the host names the device group to
    tag from (`set_device_tag_group`). Maintenance, and the host before each KeyPackage publication
    (`set_device_tag_key_holding`), set this device's MLS signature key in its own roster entry when the entry lacks
    it, through `edit_device_roster_entry` like the announcement. No KeyPackage is staged, announced or published
    while the key is due and not in the merged roster, and a staged one that no longer advertises what this device
    would build is replaced. The engine tags only from the entry at this device's slot. A refresh held back this way
    counts toward `key_package_refresh_overdue` like one held back by its announcement.
  - `runtime/removed_slot_expiry.rs` — maintenance drops `removed` slot records 30 days after their `rejected_at`, by
    this device's clock (device-roster-v1.md), in one roster update after the KeyPackage steps. `not_me` records stay.
  - `runtime/sign_in_rejection.rs` — the host's rejected sign-ins (mdk#2628 3.2) as `not_me` rejected slots, in one
    roster update behind the same gate (`reject_device_slots`), which refuses a `removed` record. The lone `removed`
    record a deciding device makes after a failed link's undo (mdk#2761) goes only through `record_removed_slot`, as
    `SendIntent::RecordRemovedSlot`, which the engine never queues or re-issues. A slot the merged roster already
    holds, as a device or a rejected slot, is left out: a rejection never replaces an entry.
  - `runtime/welcome_audit.rs` — the sender's v5 Welcome rows for every retained Nostr Welcome, each built from the
    Welcome's stored row (`Engine::outbound_welcome_audit_facts`), never from a caller's context. `welcome_prepared`
    and `welcome_event_size` come from `note_retained_welcomes`, where a retained Welcome first reaches the runtime
    (every create path, a host's accepted commit, `publish_group_evolution` for a drained or automatic one), which
    also starts its watch. `welcome_withdrawn` comes from the size refusal that retired the Welcome (direct, queued
    or fanout refusal: only the ids whose rows that rollback moved `Sent` → `Failed`, each with its own verdict; it
    stops the watch), or from the watcher when a watched Welcome settles undelivered; one read from the store already
    settled is not watched. One started/finished pair per relay pass. The attempt that meets a Welcome's policy marks
    it delivered (`finish_prepared_legacy_publish`, maintenance's retry, or the preparation that finds it already met)
    before its finished row; never mark it elsewhere. Start a pass
    (`V5WelcomePass::start`) only where the transport is called, after the last hold check, so a stopped attempt
    records nothing. Every row of a Welcome carries `welcome_audit_operation_id`.
  - `runtime/welcome_relays.rs` — a Welcome pass's per-relay requests, the result they join into, and the
    remaining pass of the relays still answering when the pass was done (see `runtime/welcome_delivery.rs`).
  - `runtime/welcome_delivery.rs` — outbound Welcome delivery (mdk#2628 3.5a). The engine's Welcome row is the
    obligation, and every publish reads it first (`welcome_hold`): a withdrawn Welcome never goes out again, a staged
    one waits for its commit, and a device link's Welcome never goes out from its `deliver_until` on, by this
    runtime's wall clock (mdk#2628 D40). A batch checks that deadline again before it starts each relay attempt, so a
    detached wave prepared earlier does not send it late. An expired Welcome is never sent again, but it may still close
    as delivered: a detached pass started before the deadline may be acknowledged, and a saved relay acceptance that
    meets its policy is marked (`expired_welcome_may_still_close`, `welcome_still_owes_met_policy`). Its watch records
    the expiry, and maintenance drops its retry record, only once neither can. The runtime watches the Welcomes it stages, and those the startup pass (or else the first
    maintenance pass) finds staged or owed; a group skipped because it was not live is read again on each pass until it
    is. A Welcome stays watched until its row is settled. Maintenance publishes each watched Welcome that is owed and
    that no attempt record (stored fanout or detached wave) holds, so one whose publish stored nothing (no
    route) or whose fanout expired goes out again on the next pass, as the startup pass would send it.
    Whichever attempt meets a Welcome's acknowledgement policy marks it delivered, maintenance's retry of its stored
    fanout included. A host that names Welcomes by id (the app's invite drive) publishes them through
    `deliver_owed_welcomes_with_audit_context`, which sends only those the engine says are owed now.
    With `set_detached_welcome_waves` on (the app's account worker, mdk#3466), every Welcome wave with a relay
    attempt to make is prepared and reserved on the runtime, and left for the host to run beside it
    (`take_prepared_welcome_tasks`): a founding create's, a host's owed Welcomes, the confirming pass's released
    ones, maintenance's watched release and the startup retry. The task holds the adapter, clock and prepared
    attempts, plus the session-owned Welcome holds and native-selection gate. Each queued adapter start waits for native
    selection to finish and checks its current hold; already-started I/O continues. The host finishes it in input
    order (`finish_welcome_publish_task`), after dropping the
    results of a group it no longer shows (`CompletedWelcomePublishTask::drop_gone_groups`), or abandons it
    (`abandon_welcome_publish_task`), which releases only the reservation. A pass with more inbox relays than its
    goal asks each relay with its own request (`runtime/welcome_relays.rs`), since the transport may answer one
    request at its goal and drop the other relays' answers. The pass is done once its answers meet its goal or every
    relay answered; a detached wave returns then, and the relays still answering go on as a task of their own
    (`CompletedWelcomePublishTask::take_remaining`), which takes their reservations. Its finish records their answers
    on the Welcome's fanout without counting another attempt (it counts and dates one only if the first pass's record
    was never saved), under its own started/finished pair. Left untaken, cancelled or abandoned, it records nothing
    (its pass has a started row and no finished row) and those relays are retried after their backoff, as before. Prepare has already stored each
    Welcome's exact signed bytes and endpoint snapshot as a transport fanout, with no relay attempt on any endpoint,
    and the Welcome stays owed, so the next maintenance pass retries that fanout. Every other publish path treats a reserved id as held by its wave. A pending
    create's first Welcome and `redeliver_welcome` still publish inline; a redelivery of a Welcome a wave holds
    publishes nothing and records no failure, since that Welcome is in flight.
    A confirmed recovery Welcome also waits while its native origin is `ConvergenceDeferred`: keep its exact bytes,
    watch and retry fanout, including across reopen and missed events. Only terminal origin loss retires that debt;
    native re-adoption can make it owed again under its original deadline. `tests/runtime/hydrated_welcome.rs` owns
    encrypted recovery continuation, unrelated-group cancellation, parked retry retention and terminal pruning.
  - `runtime/welcome_outcomes.rs` — the sender's view of each outbound Welcome's delivery (mdk#1706). Never store a
    Welcome's state: `welcome_delivery_outcomes` derives it on every read from the engine's stored row
    (`stored_outbound_welcome_status`, which needs no live group). The ledger, `cgka_welcome_delivery_ledger`, keeps only
    what nothing else holds: the Welcome's invite (group, recipient, origin commit) and its attempt counts, which
    outlive the 24-hour retry record. A relay pass writes its counts in the same transaction as the retry record, in
    `put_pass_fanout`, the one place every pass saves it; a route failure, which saves no retry record, writes them
    alone. A record is made only when this runtime stages or creates an invite's Welcomes (`watch_welcomes`), all of
    an invite's in one transaction; every other step only updates an existing record, so a Welcome from before the
    upgrade never gets one, is never listed, and is delivered as before. There is no reconcile, recovery or adoption
    pass. The newest invite per group and recipient is the one first recorded last, chosen before retention
    (`INVITE_DELIVERY_RETENTION_SECS`). Each seam that changes
    a Welcome's delivery queues its `(group, recipient)` for `take_welcome_delivery_changes`, so the app re-reads only
    those answers after a turn; an unqueued change only delays the host's notice.
  - `runtime/private_key_packages.rs` — issue, list, mark and discard private KeyPackages (mdk#2628 3.4b), and join a
    chat from a sibling Welcome the app admitted (3.5b); like a confirmed rejoin, that join's events wait for the
    caller's drain. It also lists the sibling Welcomes this device owes and records a carrier's outcome on one
    (3.5b-2), for the app's 461 sender. A live retry keeps its carrier association even when the app reports an
    ambiguous send failure (3.5f); already-handed-off fanout finishes under the ordinary transport contract.
    Carried-row settlement is separate from Ready-filtered new-send eligibility, so exact carrier outcomes settle
    even while the originating chat is unhydrated, deferred, or settling.
    Delivered-Welcome repair reserves the actual generated carrier timestamp/id and attaches its engine association
    through the named storage cross transaction on this session's own connection, never under the app cache's SQL
    lock. A failed reservation or readiness callback commits neither owner. Already accepted, unprojected fanouts
    and outstanding targets keep their association; new repair cannot bypass them. First accepted publication is
    durably observed with its fanout before projection; an old accepted row with unknown timing stays unknown.
    The request and hand-off checks read device tags through `member_device_tag_claim_at`.
- `time.rs` — injectable wall clock, monotonic clock, and maintenance randomness. The system implementations
  (`SystemWallClock`, `SystemMonotonicClock`, `OsMaintenanceRandom`) are the engine's, re-exported; define none here
  (mdk#3496). Persist wall-clock values and sampled jitter; use monotonic time only
  for in-process windows and timeouts.

Tests: `tests/runtime.rs` plus `tests/runtime/` (frozen fanout, KeyPackage generator upgrade, component migration,
multi-device Welcome delivery, Welcome withdrawal, staged and owed Welcome delivery), and the session's
`tests/session_lifecycle.rs` and `tests/nostr_stack.rs` (including `tests/nostr_stack/chaos.rs`).

## Rules

### Session

- Keep SQLCipher keys app-provided. Do not add key derivation or recovery here.
- Keep transport-specific code out. Inject a `TransportPeeler`; Nostr crates are dev-dependencies only.
- Surface engine effects as app events plus publishable transport work.
- Own detached Welcome admission in the session. Every native-selection entry point, including roster sends and
  direct session calls, excludes queued adapter starts until its Welcome holds are refreshed.
- `open` validates profile and convergence policy before opening storage or hydrating; keep new open-time checks
  ahead of any durable mutation.
- `SessionConfig::with_storage` runs the session on a host-opened connection so the host can close it at a known
  instant (mdk#2323). `open` must not open a second connection in that case.
- Keep storage-only legacy-format promotion explicit and host-scheduled after readiness; do not add it to the
  session-open critical path or widen the generic engine storage API for it.
- Every `SessionError` is an engine error. A storage failure the session meets itself converts to
  `EngineError::Storage`, so hosts classify it as they do the engine's own (mdk#2602). Callers ask
  `SessionError::as_engine_error`, not the variant.
- Keep account records (KeyPackage lifecycle, group maintenance, obligations, group evolutions, durable transport
  fanouts, periodic policy) on the session's own storage handle, not behind engine forwards. A group-scoped one calls
  `Engine::check_group_live` before touching storage, so a quarantined group still fails with `UnknownGroup` and an
  unhydrated one with `GroupNotHydrated` (mdk#2602, rule 4). Writes that must commit with OpenMLS state (KeyPackage
  staging and promotion) stay engine transactions.
- Keep one audit recorder per account-device: `open` wraps the configured recorder in a `SharedRecorder`, builds the
  engine with a clone, and writes the open-time `recorder_health` row through it. Do not add audit pass-through
  methods; the runtime and the host record, rotate and finish through their own clones (mdk#2602, rule 5).
- Re-export, under its engine name, each engine item a host names alongside the session: the configuration and signer
  types, the group-authority types, the KeyPackage metadata and inventory helpers, and the application message size
  model. Hosts name these through this crate, never `cgka_engine` (mdk#2602).
- Prefer behavior tests over internal state assertions.

### Runtime

- Keep the crate transport-generic. Nostr-specific publication belongs behind an injected boundary or in a
  transport-specific crate.
- Treat `StaticTransportRouting` as a test/simple harness implementation. A production Nostr routing policy should
  derive account inbox routes, KeyPackage publication routes, and group routes from Nostr/account state and the
  `marmot.transport.nostr.routing.v1` app component.
- Treat `KeyPackagePublisher` as provisional. The likely production direction is to move KeyPackage publication into the
  transport adapter family rather than keeping it as a separate app-core-owned publisher.
- Keep `AccountDeviceSession` as the owner of engine state.
- Keep the session private (mdk#2602). The root re-exports `AccountDeviceSession`, and any session type that only the
  session's own API hands out, only under `test-support`; a session type the runtime's public API, the facade or
  `marmot-app`'s production build names stays public. A session method the normal build never calls is deleted, unless
  tests call it through the re-export: then it keeps `#[cfg_attr(not(feature = "test-support"), allow(dead_code))]`
  on the method itself.
- Keep `AccountDeviceRuntime` the only production way to the session (mdk#2602). Hosts open it with
  `AccountDeviceRuntime::open`, which opens the session before it builds the host's transport. A session method a host
  needs becomes a runtime forward with the session's exact signature: same return type, error type and generics.
  Code a host hands the session to gets `group_authority_view()`, not the session. `session()`, `session_mut()` and
  `new` exist only under the `test-support` feature, which this crate's tests and `marmot-app` enable as a
  dev-dependency; never enable it in a normal dependency.
- Confirm pending work only after the adapter reports enough acknowledgements. A pending commit's relay also
  acknowledges it by serving its exact event: the account's own subscription receiving that event from a target
  (`acknowledge_own_echo`, mdk#2332) ends the target `Accepted` from any status, and so does a read-back: from
  `PENDING_COMMIT_READ_BACK_AFTER_MS` after the commit's first send attempt, each due retry of a target that may hold
  it reads the event back first (`read_back_pending_commit`). Only the exact frozen event from a target counts. Any
  other read answer changes no status, bit or schedule; the target is resent to as before. Nothing rolls back for want
  of an echo, or because a read found nothing. A confirmed commit's owed relays, and every other fanout, are never read.
- Give up a pending commit that no relay may hold (mdk#2332). From `PENDING_COMMIT_READ_BACK_AFTER_MS` after its first
  send attempt, a pending group commit that no target accepted and none may hold (`OutboundFanout::possible_exposure`,
  which reads a row stored before the exposure bit by its stored status), with some targets still outstanding, rolls
  back once the device shows it is online: a target refused it definitively in an attempt started since then, or a
  target answered a read of it (`abandon_unsent_pending_commit`, at most once per
  `PENDING_COMMIT_REACHABILITY_READ_INTERVAL_MS`, stored as `reachability_read_at_ms`). The outstanding targets end
  `Abandoned` and a queued intent is retired as `not_delivered` (`publish_not_delivered`); a drained commit's fanout
  names its queued intent from staging on (`set_queued_intent`), so that holds after a restart. A read only tells an online
  device; the exposure record alone decides, and `validate_successor_of` and the engine both refuse an abandonment of a
  fanout a relay may hold (mdk#1577). A read that returns the event confirms. Offline, nothing changes.
- Audit each of these pending-commit changes once, as a v5 `pending_commit_changed` row (mdk#3460): `stuck` at a
  commit's first read-back, kept on the stored fanout (`record_stuck`) before the read is sent; `read_back_confirmed` or
  `echo_confirmed` where `resolve_outbound_fanout_mls` confirms a commit with no relay's `OK` among its stored
  acknowledgements (`confirmed_without_ok`), whichever process stored them; `given_up` after
  `abandon_unsent_pending_commit` rolls one back. Rows name the commit by message id only.
- Pass `RollbackPass::Staging` only from the drive inside the call that staged the commit
  (`publish_one_with_post_confirmation_welcomes`), and `RollbackPass::Later` from every resume (mdk#2332). A rollback
  on a later pass of a host's change is recorded as not delivered, because its caller already returned. Host group
  changes come in through `send_host_change_with_audit_context` and
  `confirm_host_change_without_publish_with_audit_context`, and staging stores the change's kind on the fanout
  (`set_host_change`) before the first send; every other send is automatic and is never recorded. Records are read
  and acknowledged through `group_changes_not_delivered` and `acknowledge_change_not_delivered`.
- Read a pending commit's state from its fanout alone (`AccountDeviceRuntime::pending_commit`, mdk#2332): `Stuck` is
  past `PENDING_COMMIT_READ_BACK_AFTER_MS` from the first attempt, no target accepted and some may hold it, which is
  exactly when `abandon_unsent_pending_commit` never runs; `Sending` is everything else. Keep the read and those
  give-up rules on the same predicates (`first_attempt_at_ms`, `target_may_hold_event`), so a commit the host sees as
  `Stuck` is never rolled back.
- Never let a durable maintenance record depend on an engine event alone. Engine events are in-memory, and this layer
  consumes them *after* awaiting the batch's relay publishes, so the loss window is network-wide. `GroupStateInvalidated`
  retires a `DurableGroupEvolution`, and `run_due_maintenance` re-derives that same retirement from the commit's stored
  disposition (`ConvergenceDeferred`/`EpochInvalidated`) so a lost announcement cannot strand it. Both paths go through
  `mark_evolution_superseded`; keep it the sole writer of `SupersededByConvergence`, and keep the derivation forward-only
  — nothing here un-marks a supersession on re-adoption. A supersession never revives a `Failed` obligation: that phase
  is a terminal verdict (`local_member_removed` is the live one), and re-arming it would send a `SelfUpdate` into a group
  the device has left, once per tick, uncounted by `MaintenanceRunSummary.failures`. `Complete` is deliberately not
  guarded — a withdrawn commit un-completing the obligation it satisfied is the PCS re-arm this layer owes. A pending
  leave or disband is not a terminal verdict: `run_due_maintenance` leaves the group's obligation untouched while
  either is in progress, since both can resolve with the device still a member.
- The same two reconcilers also hand a withdrawn own commit's intent back to the engine
  (`reissue_superseded_own_commit` on the event path, `reissue_superseded_own_commits_from_state` in
  `run_due_maintenance`) and return the engine's `SupersededIntentReport`s in `AccountDeviceEffects::superseded_intents`.
  Every seam that produces effects must carry them through (`extend`/`absorb`); `marmot-app` turns each report into one
  `MarmotAppEvent::GroupChangeSuperseded`, so a report dropped here is a saved change the user is never told was lost
  (mdk#1734).
- Roll back pending work when publication fails before any external exposure is possible. Once publication intent is
  durable and a relay may have accepted work, retain the journaled state and retry the exact or replaceable publication
  instead.

### Logs

- Do not log account ids, group ids, relay URLs, message ids, pubkeys, payloads, ciphertext, plaintext, or key material.
- Give every event explicit `target` and `method` fields (`docs/marmot-architecture/overview/observability.md`). Each
  target is `marmot_session::<module>`, the module that emits the event: `marmot_session::session` or
  `marmot_session::runtime` today.

## Verification

```sh
cargo test -p marmot-session
```

Device groups need no feature. Policy-test timing overrides must not enter host artifacts.
