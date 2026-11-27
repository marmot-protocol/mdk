### Breaking changes

- `SqliteStorageOptions::cipher_compatibility` and `SqlCipherHardening::cipher_compatibility` are now enforced after
  `PRAGMA key` with no silent format fallback. Default `cipher_compatibility = 4` databases are unaffected; callers
  that previously created a database with a non-default value (such as `3`) produced a SQLCipher v4 file on disk and
  must reopen it with `cipher_compatibility = 4` (or migrate/rekey it offline).

### Fixed

- Hardened SQLCipher open pragma ordering (`cipher_compatibility` after `PRAGMA key`, `busy_timeout` before keying),
  key-package eviction watermark dominance, malformed directory profile resilience, lowercase hex normalization in
  local group wipes, immediate WAL write transactions, media-catalog paging and busy retries, compaction recovery and
  close classification, secret zeroization, saturating SQLite integer updates, chunked stale-component deletion,
  secure message pruning, and atomic multi-statement OpenMLS deletes.
