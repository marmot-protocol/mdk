### Breaking changes

- `OutboundWelcomeStatus::PastDeadline` is a Welcome past its delivery deadline that is not marked expired yet;
  `Settled(WelcomeSettlement::Expired)` now means a Welcome marked expired, at any clock (mdk#3589).

### Added

- `Engine::expire_sent_welcome` marks an outbound Welcome past its delivery deadline expired in one row write: the row
  becomes `Failed` with a `WelcomeExpiry` mark, so it reads `Settled(Expired)` whatever the clock, is never published
  or marked delivered, and is not re-owed when its commit confirms (mdk#3589). `record_sent_welcome_expiry` notes that
  its expiry was recorded, and `unrecorded_welcome_expiries` lists those a stop left unrecorded, reading only rows
  that carry no OpenMLS message and naming each group it could not read (`unrecorded_welcome_expiries_in` reads one
  again).
