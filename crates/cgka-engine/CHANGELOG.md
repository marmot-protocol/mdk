# Changelog

## Unreleased

- Retire D90/D91 device-group source-observation/proof recovery and its unused Engine APIs; sibling-Welcome origin, current tagged participation, expiry and immutable-carrier guards remain (D100).

- Separate explicit dev device-roster advertisement capability from policy-test timing overrides.

### Fixed

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
