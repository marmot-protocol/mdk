# Changelog

## Unreleased

- Retire D90/D91 device-group source-observation/proof recovery and its unused Engine APIs; sibling-Welcome origin, current tagged participation, expiry and immutable-carrier guards remain (D100).

- Separate explicit dev device-roster advertisement capability from policy-test timing overrides.

### Fixed

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
