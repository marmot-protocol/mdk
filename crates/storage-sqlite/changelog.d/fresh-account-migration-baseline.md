### Changed

- A new account database applies its schema through migration 218 in one transaction from a checked-in baseline,
  then replays only later migrations. Opening a fresh account no longer replays every migration, which took seconds.
  Databases with any recorded migration are unchanged.

### Breaking changes

- Storage open observers can receive `StorageOpenProgress::MigrationBatchFinished`. It reports the number of
  ledger entries committed by the fresh-account baseline. Exhaustive matches need the new arm.
