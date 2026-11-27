### Fixed

- Hardened SQLCipher open pragma ordering (`cipher_compatibility` after `PRAGMA key`, `busy_timeout` before keying),
  key-package eviction watermark dominance, malformed directory profile resilience, lowercase hex normalization in
  local group wipes, immediate WAL write transactions, media-catalog paging and busy retries, compaction recovery and
  close classification, secret zeroization, saturating SQLite integer updates, chunked stale-component deletion,
  secure message pruning, and atomic multi-statement OpenMLS deletes.
