### Changed

- A new account database applies its schema through migration 227 in one transaction from a checked-in baseline,
  then replays only later migrations. Opening a fresh account no longer replays every migration, which took seconds.
  Databases with any recorded migration are unchanged.

### Breaking changes

- `StorageOpenProgress` is now `#[non_exhaustive]` and adds `StorageOpenProgress::MigrationBatchFinished`, which
  reports the number of ledger entries committed by the fresh-account baseline. Exhaustive matches outside
  `storage-sqlite` need a wildcard arm (and may handle `MigrationBatchFinished`).
