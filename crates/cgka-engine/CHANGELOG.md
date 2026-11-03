# Changelog

## Unreleased

- Separate explicit dev device-roster advertisement capability from policy-test timing overrides.

### Fixed

- Attachment-bearing kind-7 reactions carry their authenticated source-epoch
  encrypted-media key through receive and convergence replay, including late
  replay after that epoch's retained anchor is pruned (mdk#2151). Plain
  reactions and other attachment-free applications carry no media key.

### Changed

- Stop collecting and recording announced KeyPackages when applying device
  rosters (mdk#2863, D81). Roster state, tag-key history and convergence
  behavior are unchanged.
