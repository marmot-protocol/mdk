# Changelog

## Unreleased

### Fixed

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
