# Changelog

## Unreleased

### Changed

- Capture immutable authenticated admission generations and local Welcome associations atomically with native
  founding/join (mdk#2628 D96). `SiblingWelcome` adds optional `invitation_generation`: None retains V1 bytes, Some
  emits V2 after `to`. New automatic sibling Adds inherit the original anchor; old obligations are never converted.
  Custom experimental senders and receivers must update together; no capability negotiation is added.

- Stop collecting and recording announced KeyPackages when applying device
  rosters (mdk#2863, D81). Roster state, tag-key history and convergence
  behavior are unchanged.
