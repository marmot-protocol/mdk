# Changelog

## Unreleased

### Changed

- `Engine::create_group_with_optional_app_components_and_audit_context` and
  `Engine::create_group_with_siblings_and_audit_context` take `welcome_check: Option<&dyn WelcomeSizeCheck>`
  (mdk#2334). After wrapping the founders' Welcomes, and before the creation's canonical write, a Welcome the check
  finds too large refuses the create with `EngineError::EventTooLarge { artifact: Welcome }`; the new group's OpenMLS
  state is removed. Sibling Welcomes and chosen-id creates are not checked. Pass `None` to keep the old behaviour.
- A queued intent whose event fits none of its relays is retired, not re-drained forever (mdk#2334). Before, a drained
  commit that every group relay refused for size was rolled back and the drain staged it again on the next pass. The
  new `Engine::publish_refused_as_too_large` rolls the pending commit back like `publish_failed_with_fanout`, deletes
  the queued intent in the same transaction, and announces `GroupEvent::QueuedIntentRefused` with reason
  `event_too_large`, the artifact and its size class. `Engine::pending_is_queued_invite` tells a drained invite from a direct one.
- Engine paths read a group's stored record only through accessors that refuse a quarantined group, and the crate's
  `clippy.toml` bans the raw reads (mdk#3272). For any quarantined group, the settle API and `cancel_leave` return
  `UnknownGroup`, `has_pending_convergence_inputs` answers `false` unless a pass or replay is outstanding,
  `buffer_openmls_convergence_message` refuses it, `reissue_superseded_own_commits_from_state` and authority recovery
  skip it, and a removed copy's input is retained as quarantined rather than in the removed ring.

### Fixed

- A convergence pass, deferred-peel sweep or past-epoch peel whose restore fails after it rewound a group onto a
  retained anchor no longer leaves the group live on anchor state (mdk#3272). The group is quarantined as
  `RewindRestoreFailed` with a `GroupHydrationQuarantined` event, and its input is retained. Neither
  `retry_hydrate_quarantined_group`, which answers `false`, nor a re-join Welcome clears it; the next open restores
  the kept live state and replays the input. Meanwhile `pending_group_rejoins_for` omits the group's stored rejoin
  offers and `confirm_group_rejoin` returns `UnknownGroup` for them, since their consent token would be the anchor's.
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
