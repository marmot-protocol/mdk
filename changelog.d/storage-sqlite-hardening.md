### Fixed

- Hardened `storage-sqlite` database opening, deletion, compaction, and directory/media-catalog operations: SQLCipher
  compatibility and busy-timeout pragmas now apply in the order SQLCipher requires, local group deletion normalizes
  group identifiers consistently, key-package eviction watermarks preserve stronger deletion barriers across batch
  evictions, read-then-write storage transactions acquire immediate write locks under WAL contention, media-catalog
  paging and compaction recovery handle limits, retries, and close interrupts cleanly, and secure pruning scrubs full
  UTF-8 byte lengths and removes invalidated edits targeting pruned messages.
