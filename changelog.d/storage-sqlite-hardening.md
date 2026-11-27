### Breaking changes

- `storage-sqlite` now enforces `SqliteStorageOptions::cipher_compatibility` and
  `SqlCipherHardening::cipher_compatibility` (`1..=4`) after `PRAGMA key` with no silent format fallback, and rejects
  unsupported values outside `1..=4` before keying. Default `cipher_compatibility = 4` databases are unaffected; callers
  that previously created a database with a non-default value (such as `3`) produced a SQLCipher v4 file on disk and
  must reopen it with `cipher_compatibility = 4` (or migrate/rekey it offline).

### Fixed

- Hardened `storage-sqlite` database opening, deletion, compaction, and directory/media-catalog operations: SQLCipher
  compatibility and busy-timeout pragmas now apply in the order SQLCipher requires, local group deletion normalizes
  group identifiers consistently, key-package eviction watermarks preserve stronger deletion barriers across batch
  evictions, read-then-write storage transactions acquire immediate write locks under WAL contention, media-catalog
  paging and compaction recovery handle limits, retries, and close interrupts cleanly, and secure pruning scrubs full
  UTF-8 byte lengths and removes invalidated edits targeting pruned messages.
