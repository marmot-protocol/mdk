# Changelog

## Unreleased

### Breaking changes

- `Engine::own_account_leaves_tagged_by` returns each leaf's signature key with the slot its tag read as.
- `Engine::queue_app_message_with_audit_context` takes the intent's `only_to_members`.

### Added

- `Engine::own_account_self_signed_tags` reads, for this account's other leaves, a device tag that verifies under
  that leaf's own signature key, with the slot it names (mdk#3679).
- An application message sent with `only_to_members` is encrypted only into an epoch whose member accounts it all
  lists, checked at encryption for direct sends and queued ones alike; otherwise it fails with
  `AppMessageNewMembers`, or, queued, is retired through `retire_refused_queued_outbound_intent` and announced as
  `QueuedIntentRefused`.
- `Engine::deferred_stall_evidence_since` returns deferred stall evidence for rows whose arrival epoch falls in
  `min_epoch..=group.epoch`, for active epoch-gap handoffs across partial advances.
- `Engine::stored_outbound_welcome_status`, an outbound Welcome's status read from its stored rows without the
  live-group gate, for the sender's invite delivery view (mdk#1706).

### Changed

- `SendIntent::UnlinkDevice` may keep the removed leaf's signature key in the slot's `removed` record once that leaf
  has committed since its Add, and refuses any `removed` record while the removed leaf is still its link's KeyPackage
  leaf (mdk#3679). Receivers are unchanged.
- Budget-expired deferred-peel evictions delete the deferred row from `cgka_messages` directly instead of calling
  `release_message_for_replay`, so storage hosts are no longer notified via the release journal for budget-expired
  rows, avoiding false epoch-gap arms, `seen_events` retirement, and relay bounce-backs.

### Fixed

- Re-deferring an unopenable `PeelDeferred` row across an epoch sweep preserves its original arrival epoch instead of
  restamping it to the tip epoch.
- Deferred-peel sweeps at the retry-budget or residence-budget cutoff attempt a newly arrived peel context once before
  deleting the row, so a commit that unlocks the row on the cutoff sweep decrypts instead of being discarded.

## 0.19.0 - 2026-11-22

### Breaking changes

- `group_context` no longer exports the `agent-text-stream-quic` MLS exporter secret
  (`marmot/agent-text-stream-quic`); the agent text stream is retired. Component `0x8006` is still validated and its
  required roles still enforced on create and invite.
- Sending a kind-1200 agent stream start is refused with `InvalidAppMessagePayload`; one queued before an upgrade is
  retired at drain and announced as `GroupEvent::QueuedIntentRefused`. Received starts are still accepted.

### Fixed

- Encrypted-media keys are kept for a kind-1111 thread message recognized by a lowercase `e` alone, as storage
  already reads its attachments, not only for one with a numeric `k`.

## 0.18.0 - 2026-11-20

### Breaking changes

- The `dev-device-groups` feature is gone (mdk#2628): every build may advertise the device-roster component
  (`marmot.account.device-roster.v1`). `marmot-app` lists it only while device groups are on.
- `SiblingWelcome` gains `forwarded`, encoded as version 3 when anything is forwarded: the original inviter, and for
  a copy with no invitation generation whether it is confirmed (mdk#3546). A sibling join reports it on
  `GroupJoined.forwarded`. Receivers older than this refuse a version-3 Welcome. An Add that forwards anything
  is refused with `SiblingAddUnsettled` rather than queued, so it never forwards facts read before a drain.
- `OutboundWelcomeStatus::Settled` carries a `WelcomeSettlement`: delivered, withdrawn (or retired with its rolled-back
  commit), commit superseded (also once convergence has retired the Welcome with its lost commit, and ahead of a
  deadline), expired, or untracked.
- `Engine::publish_failed_fanout`, `publish_not_delivered` and `publish_refused_as_too_large` take a `RollbackPass`
  (mdk#2332). On `RollbackPass::Later`, a host change the fanout names is recorded as not delivered and announced
  with `GroupChangeNotDelivered`; a retired queued intent is recorded on any pass.
- `Identity::load_or_generate` and `openmls_projection::apply_openmls_canonicalization_result` take the wall-clock
  time from their caller, as a `Timestamp`, instead of reading the system clock (mdk#3496). It dates a newly signed
  account identity proof and the replay-rotation obligations an apply creates.

### Added

- `Engine::stored_rejoin_welcomes` lists every stored rejoin candidate without loading its group, and
  `Engine::rejoin_offers` keeps the candidates whose group's MLS state loads, for the host's published read state
  (#3428).
- `Engine::outbound_welcome_audit_facts` reads one retained outbound Welcome's group, id, transport source,
  recipient, origin commit, KeyPackage event id and state, in any state and without its bytes, for the sender's audit. Invite and founding Welcomes record the
  transport event id of the KeyPackage they answer.
- `Engine::staged_invite_welcome_ids` lists the invite Welcomes still staged with one unconfirmed commit, which its
  rollback retires.
- `EngineBuilder::monotonic_clock` installs the `MonotonicClock` that times the engine's in-process budgets,
  deadlines and duration metrics, so a test moves time forward without sleeping (mdk#3496). An engine built without
  it runs on the new `SystemMonotonicClock`. `SystemWallClock` and `OsMaintenanceRandom`, the other defaults, are
  public, and all three are re-exported from the crate root.
- `Engine::send_host_change_with_audit_context` sends a host's group change, and `host_change_kind` names the change
  a pending commit carries, for its fanout to store (mdk#2332).
- `Engine::publish_not_delivered` rolls back a pending commit the session gave up because it reached no relay
  (mdk#2332), retiring its queued intent in the rollback's transaction and announcing it as `QueuedIntentRefused`
  with reason `not_delivered`.
- `Engine::drained_queued_intent_id` returns the queued intent the drain prepared a pending commit from, for its frozen
  fanout to name (mdk#2332).
- `Engine::retire_drained_queued_intent` retires the queued intent a drained application message or proposal came
  from once its fanout resolves, and is a no-op for an intent already retired (mdk#2332).
  `Engine::is_queued_outbound_intent` says whether an intent is still queued, so a host keeps the fanout naming it
  until it retires.
- `Engine::seeded_group_outbound_fanouts` reads a seeded-but-unhydrated group's stored fanouts without hydrating it,
  for deciding whether a delivery is worth hydrating the group for (mdk#2332). It is empty for a live, quarantined or
  unknown group.

- `Engine::private_key_packages_next_expiry` returns when the earliest issued private KeyPackage expires, and
  `Engine::has_rejoin_offers` whether any stored Welcome is a rejoin offer, so maintenance can wake for them
  (mdk#3265).

### Changed

- A newly signed account identity proof and a replay-rotation obligation are dated by the engine's wall clock
  (`EngineBuilder::maintenance_sources`), no longer by the system clock whatever the builder was given (mdk#3496).
- Every fanout rollback (`publish_failed_with_fanout`, `publish_refused_as_too_large`, `publish_not_delivered`) now
  also refuses a fanout a target may hold (`OutboundFanout::possible_exposure`), so a commit a relay may have kept
  never rolls back (mdk#1577, mdk#2332).

- `Engine::discard_private_key_packages` reads first and opens no writer transaction when nothing matches, so an
  idle maintenance pass no longer writes (mdk#2923).

### Fixed

- A refused Welcome delivery no longer marks the Welcome's content as seen (#3520). Only a completed join, or a
  declined rejoin offer, writes the content marker; a refusal marks only its delivery's wrapper, so a later delivery
  of the same Welcome can still join.
- Stored convergence leaves out this device's own commits that have not confirmed (#3531).
- `Engine::deferred_stall_evidence` propagates storage read failures instead of omitting unread rows from its sample.
  Only `StorageError::NotFound` is skipped when a row disappears after listing, so an incomplete read cannot retire
  recovery demand as though too few failures remained.
- A deferred row released while it may predate this copy's Welcome is journaled as no stall evidence
  (`release_message_for_replay_without_stall_evidence`), so a host consuming its release journal no longer arms the
  epoch gap the suppressed `TransportObjectResourceRefused` withheld (mdk#3536, mdk#3535).
- `uncount_outdated_private_key_packages` opens no writer transaction when nothing is outdated (mdk#3479).
- Hydration restores a pending commit's link to the queued intent it was drained from, from the frozen fanout that
  names it, so confirming the commit, refusing it for size or `publish_not_delivered` after a restart retires that
  intent instead of leaving it for the drain to prepare again (mdk#2332). A hydration that fails after restoring the
  link drops it with the rest of the restored pending state, so the intent is not left marked in flight.
- The drain treats a queued intent that a stored application-message or proposal fanout names as in flight, so a
  drain after a restart, or after a Welcome made the group live without hydrating it, does not prepare the intent
  again, and a later send does not queue behind it (mdk#2332).
- Received NIP-22 comments (kind 1111 with a numeric lowercase `k` tag) carry their source-epoch encrypted-media
  secret through the same ingest and replay handoff as chat attachments (#3409).

## 0.17.0 - 2026-11-15

### Added

- The engine keeps each group's committed roster (mdk#3273). Every record write that merges, clears or re-derives
  membership writes the distinct member account ids of the merged state in the same transaction, never a staged
  commit's projection, and a rewind leaves it as it was. A disbanded group's roster is the members its disband
  ended, from the disband's own evidence. Hydration records the roster of a group stored before rosters existed and
  replaces one that disagrees, with a warning that carries only a count; for a settled disband the session-open
  cheap pass does this from its tombstone. A wrong roster it cannot replace quarantines the group
  (`GroupRecordLoadFailed`) until an open replaces it; a missing one it cannot record stays missing, which never
  reads as a known membership.
- `GroupChangeGeneration::serves_reads` says whether the engine served the group's gated reads when the generation
  was read: neither quarantined nor awaiting hydration (mdk#3273).

### Fixed

- An own disband records the members it ends from the group's tree, not from its stored record (mdk#3273), so a
  record that disagreed with the tree no longer reaches the disband's tombstone.
- A contained rewind window on a storage provider without atomic group savepoints writes one snapshot, not two
  (mdk#3278). It used to run inside the snapshot fallback, so a crash left that snapshot beside the guard's and the
  next open quarantined the group. It now runs on the guard's snapshot alone, which the next open restores. A failed
  restore or release keeps that snapshot and quarantines the group for the session (`RewindRestoreFailed`), as a
  committing window's does, unless an enclosing committing window answers for it; that window keeps its own snapshot
  when it cannot release the nested one. SQLite is unchanged.
- Live ingest reuses the historical peel contexts that deferred sweeps and publish replay cache, and prepares each
  envelope once per ingest (#2492, #3406). A fresh, correctly signed envelope that misses the live key no longer
  makes the engine rebuild past group state again.
- Every OpenMLS load, fresh or cached, goes through one loader that refuses a group whose rewind restore failed
  (#3280, #3395). No entry path reached that state; the loader stops the next one that would. The crate's clippy
  configuration bans `MlsGroup::load` outside it.

## 0.16.0 - 2026-11-12

### Breaking changes

- `Engine::create_group_with_optional_app_components_and_audit_context` and
  `Engine::create_group_with_siblings_and_audit_context` take `welcome_check: Option<&dyn WelcomeSizeCheck>`
  (mdk#2334). After wrapping the founders' Welcomes, and before the creation's canonical write, a Welcome the check
  finds too large refuses the create with `EngineError::EventTooLarge { artifact: Welcome }`; the new group's OpenMLS
  state is removed. Sibling Welcomes and chosen-id creates are not checked. Pass `None` to keep the old behaviour.

### Changed

- A queued intent whose event fits none of its relays is retired, not re-drained forever (mdk#2334). Before, a drained
  commit that every group relay refused for size was rolled back and the drain staged it again on the next pass. The
  new `Engine::publish_refused_as_too_large` rolls the pending commit back like `publish_failed_fanout`, deletes the
  queued intent in the same transaction, and announces `GroupEvent::QueuedIntentRefused` with reason
  `event_too_large`, the artifact and its size class. `Engine::pending_is_queued_invite` tells a drained invite from a
  direct one.
- Engine paths read a group's stored record only through accessors that refuse a quarantined group, and the crate's
  `clippy.toml` bans the raw reads (mdk#3272). For any quarantined group, the settle API and `cancel_leave` return
  `UnknownGroup`, `has_pending_convergence_inputs` answers `false` unless a pass or replay is outstanding,
  `buffer_openmls_convergence_message` refuses it, `reissue_superseded_own_commits_from_state` and authority recovery
  skip it, and a removed copy's input is retained as quarantined rather than in the removed ring.
- `message_processor::MAX_PEEL_DEFERRED_ROWS_PER_GROUP` rises from 2,048 to 8,192,
  `MAX_PEEL_DEFERRED_BYTES_PER_GROUP` from 16 MiB to 64 MiB and `MAX_PEEL_DEFERRED_BYTES_PER_ACCOUNT` from 64 MiB to
  256 MiB (mdk#3297). A full-history recovery of a long-lived group passed the row cap, and with its epoch fixed no row
  aged out, so every later undecryptable input for the group was refused. The conformance snapshot's E3 values change
  with them.
- `Engine::ingest` runs its read-only dedup and own-echo lookups before the audit rows (mdk#3300). A message that ends
  `Ignored { Duplicate | OwnEcho }` records only `ingest_outcome`, with the delivery's transport context; if it ends
  any other way, `transport_received` and `ingest_entry` are written before its outcome or `ingest_error`.

### Fixed

- A convergence pass, deferred-peel sweep or past-epoch peel whose restore fails after it rewound a group onto a
  retained anchor no longer leaves the group live on anchor state (mdk#3272). The group is quarantined as
  `RewindRestoreFailed` with a `GroupHydrationQuarantined` event, and its input is retained. Neither
  `retry_hydrate_quarantined_group`, which answers `false`, nor a re-join Welcome clears it; the next open tries to
  restore the kept live state and replays the input only if that succeeds; otherwise the group is quarantined again.
  Meanwhile `pending_group_rejoins_for` omits the group's stored rejoin offers and `confirm_group_rejoin` returns
  `UnknownGroup` for them, since their consent token would be the anchor's.
- `EngineBuilder::build` restores every group's interrupted rewind before anything reads group state (mdk#3272). With
  deferred hydration, ingest and a Welcome join could read a seeded group's record before its hydration restored a
  rewind interrupted by a crash or a failed restore. A message could then be kept in a removed copy's ring, or a
  re-join committed on the anchor and the live state lost. A group whose restore fails at open is quarantined as
  `RewindRestoreFailed`, as is an ambiguous pair of interrupted rewinds, which used to be `GroupRecordLoadFailed`;
  a retry no longer clears either, and the next open tries again.

## 0.15.0 - 2026-11-09

- An admin's Leave records the leave before anything is published (mdk#3014). New `SendIntent::StepDownAndLeave`:
  from an admin with another active admin it writes the durable `LeaveRequest` and returns the new
  `SendResult::LeaveRequested` without staging anything, and the leave re-drive stages the step-down and then the
  SelfRemove, staging either again if it is refused or lost. The last active admin is refused with `AdminDepletion`,
  and a non-admin's call is a plain `Leave`. Plain `Leave` from an admin is still refused with `AdminCannotSelfRemove`.
  A call made while an earlier intent is queued is queued behind it, and the drain records the leave after that intent
  is prepared, in the same storage transaction that retires the queued leave, blocked if the account has become the
  last active admin meanwhile. No wire or schema change.

- A blocked leave is visible and can be cancelled (mdk#3014). When the selected branch makes a leaving account the
  last active admin, the leave re-drive records `LeaveRequest::blocked = Some(LastActiveAdmin)` and clears it as soon
  as the leave can move forward again; nothing retries meanwhile. New `Engine::leave_blocked`, and
  `Engine::cancel_leave`, which clears the request only while the leave is blocked on a `Stable`, settled group and
  otherwise returns the new `EngineError::LeaveNotBlocked`. A stored marker the branch no longer matches keeps
  `leave_redrive_owed` true until the re-drive records it. No wire or schema change.

- Retire D90/D91 device-group source-observation/proof recovery and its unused Engine APIs; sibling-Welcome origin, current tagged participation, expiry and immutable-carrier guards remain (D100).

- Separate explicit dev device-roster advertisement capability from policy-test timing overrides.

### Fixed

- Retry a failed buffered-message replay after a committed replacement Welcome through the normal background drain
  (mdk#3240). Messages retained while the copy was frozen no longer need redelivery or another publication to replay.
  The committed join returns success even if that replay fails, so inbox and automatic-rejoin callers receive its effects.

- A leaving account that the selected branch makes an admin again steps down again before its SelfRemove
  (mdk#3014). While a durable leave request exists and another active admin remains, the drain stages a step-down
  from the selected branch's admin list, so a promotion on the winning branch stands; the SelfRemove follows once that
  Commit merges; it carries only that update and leaves pending proposals in the store. The last active admin's leave
  stages nothing. A leaving account's lost step-down that did nothing else is no longer re-queued or reported as
  superseded. New `Engine::leave_redrive_owed` (forwarded by the session and runtime) is the
  scheduler's signal to keep a wake armed, and hydration schedules a group with a restored leave request. No wire or
  schema change.

- A pending proposal sealed on one branch no longer invalidates a rival branch's commit at the same epoch
  (mdk#3226). Candidate replay records a proposal that fails sender or membership-tag authentication as that
  branch's evidence and keeps judging the path's own commits, so a device that left on a branch that then loses
  (it holds its own SelfRemove) reaches the selected branch instead of staying there in `Leaving`. Selected-branch
  apply and every other proposal failure are unchanged. No wire or schema change.

- Filter sibling-Welcome origin checks to the device-group carriers being settled, so an unrelated retirement
  failure cannot block a healthy publication. Additive Engine/session/runtime queries preserve the full-query API;
  group and Sent-row scans and their errors still span storage. No wire or schema change.

- Report an already-present sibling as `SiblingAddRefusal::AlreadyPresent`, so stock selection stops instead of
  trying another private KeyPackage for a membership the selected chat already holds.

- Skip optional founding siblings whose KeyPackage ciphersuite differs from the chat, preserving ordinary creation
  and its Welcomes. Shared sibling admission reports the mismatch before staging.
- Retain exact SelfUpdate publication bytes across compatibility restart even when Welcome storage is unavailable.
  Ordinary updates have no Welcome artifacts to discover.
- Allow member recovery past ownerless ordinary Preparing work and obsolete ordinary source records, including
  rollback after a crash during recovery preparation. Current-source prepared/attempted publications and retained
  recovery artifacts still block it.
- Keep the origin Commit on promoted existing-group Welcomes. Reversible branch loss holds the exact artifact and
  retry owner for re-adoption; only terminal origins atomically retire undelivered Welcomes. Already delivered
  usable copies still require explicit replacement consent.
- Reserve saved publication handles from independent durable metadata before hydration. Corrupt pending artifacts
  no longer block healthy groups once that bound exists; exhausted handles refuse staging before mutation.
- Keep recovery send refusals consistent with source validation: pending leave/disband is transient; legacy-cutover
  and device-group refusal is permanent and happens before staging.
- Attachment-bearing kind-7 reactions carry their authenticated source-epoch
  encrypted-media key through receive and convergence replay, including late
  replay after that epoch's retained anchor is pruned (mdk#2151). Plain
  reactions and other attachment-free applications carry no media key.

### Changed

- Capture immutable authenticated admission generations and local Welcome associations atomically with native
  founding/join (mdk#2628 D96). `SiblingWelcome` adds optional `invitation_generation`: None retains V1 bytes, Some
  emits V2 after `to`. New automatic sibling Adds inherit the original anchor; old obligations are never converted.
  Custom experimental senders and receivers must update together; no capability negotiation is added.

- Stop collecting and recording announced KeyPackages when applying device
  rosters (mdk#2863, D81). Roster state, tag-key history and convergence
  behavior are unchanged.
