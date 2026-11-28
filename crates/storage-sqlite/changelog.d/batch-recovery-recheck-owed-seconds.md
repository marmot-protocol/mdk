### Added

- `SqliteAppStorage::recovery_recheck_owed_seconds`, which reads covered and retired re-check seconds for a batch of
  `(route, relay, since, until)` units under one connection lock instead of per-unit queries.
