### Fixed

- Batched the recovery runner's re-check survey into one storage read and reused the unit states and relay cooldowns
  already loaded by the debt survey, eliminating hundreds of per-unit SQLite lock acquisitions on every recovery step
  for accounts with many chats.
