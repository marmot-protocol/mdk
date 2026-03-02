# Code Review: feat: replace NIP-44 with ChaCha20-Poly1305 for kind:445 (MIP-03) and update MIP-04 exporter label

## Summary

This PR correctly implements the cryptographic core of MIP-03 (ChaCha20-Poly1305 for kind:445) and
separates the MIP-04 exporter from the MIP-03 one. The encryption logic is sound — proper AEAD,
random nonce per message, AAD binding to `nostr_group_id`, and OsRng with no weak fallback. The
new unit tests are good and cover the right failure modes. However, there is one blocking bug in the
SQLite migration: the `PRIMARY KEY` is not updated to include `label`, so `INSERT OR REPLACE` for
'encrypted-media' silently overwrites the 'group-event' row for the same `(mls_group_id, epoch)`,
destroying the MIP-03 key every time a MIP-04 key is saved.

---

## Issues

### Critical: SQLite PRIMARY KEY does not include `label` — MIP-04 save destroys MIP-03 key

**`crates/mdk-sqlite-storage/migrations/V005__add_label_to_group_exporter_secrets.sql`**

```sql
ALTER TABLE group_exporter_secrets ADD COLUMN label TEXT NOT NULL DEFAULT 'group-event';
```

The original table definition has `PRIMARY KEY (mls_group_id, epoch)`. After V005, the primary key
is still `(mls_group_id, epoch)` — `label` is not part of it. This means:

1. `save_group_exporter_secret` inserts `(group_id, epoch, secret, 'group-event')`
2. `save_group_mip04_exporter_secret` inserts `(group_id, epoch, secret, 'encrypted-media')`

Because `INSERT OR REPLACE` triggers on the `(mls_group_id, epoch)` conflict, the second insert
**deletes the first row** and inserts its own. After every epoch advance (with `mip04` feature
enabled), the MIP-03 'group-event' row is gone. Any subsequent message send or decryption that
calls `get_group_exporter_secret` with label='group-event' returns `None` (not an error), which
causes `exporter_secret()` in `groups.rs` to call `export_secret()` on the live MLS group — which
only works for the current epoch, breaking lookback for past epochs.

Verified with SQLite directly: `INSERT OR REPLACE` with a different `label` for the same
`(mls_group_id, epoch)` pair replaces the existing row.

**Fix:** The migration must rebuild the table with the correct composite primary key:

```sql
-- V005: add label, extend primary key to (mls_group_id, epoch, label)
CREATE TABLE group_exporter_secrets_new (
    mls_group_id BLOB NOT NULL,
    epoch        INTEGER NOT NULL,
    secret       BLOB NOT NULL,
    label        TEXT NOT NULL DEFAULT 'group-event',
    PRIMARY KEY (mls_group_id, epoch, label),
    FOREIGN KEY (mls_group_id) REFERENCES groups(mls_group_id) ON DELETE CASCADE
);

INSERT INTO group_exporter_secrets_new (mls_group_id, epoch, secret, label)
    SELECT mls_group_id, epoch, secret, 'group-event'
    FROM group_exporter_secrets;

DROP TABLE group_exporter_secrets;
ALTER TABLE group_exporter_secrets_new RENAME TO group_exporter_secrets;

CREATE INDEX IF NOT EXISTS idx_group_exporter_secrets_mls_group_id
    ON group_exporter_secrets(mls_group_id);
```

SQLite does not support `ALTER TABLE … ADD PRIMARY KEY`, so a table rebuild is the only option.

---

### Code Style: Imports inside test functions violate STYLE.md

**`crates/mdk-core/src/util.rs`:204–219, 213–220, 253–260, 303, 322–324**

```rust
#[test]
fn test_chacha20poly1305_roundtrip() {
    // ...
    use mdk_storage_traits::GroupId;        // ← inside function
    // ...
    use base64::Engine;                     // ← inside function
    use base64::engine::general_purpose::STANDARD as BASE64;
    use chacha20poly1305::{...};
```

STYLE.md is explicit: _"All `use` statements must be placed at the TOP of their containing scope.
Never place imports inside functions, methods, or blocks."_ The test module imports `Secret` and
`super::*` at module level, but each new test function repeats crate-level imports inline. They
should all move to the top of `mod tests { … }`.

The same pattern appears in `test_chacha20poly1305_wrong_aad_fails`, `test_decrypt_rejects_short_nonce`,
and `test_decrypt_rejects_invalid_base64`.

---

### Correctness: `exporter_secret()` stale-label read after migration

**`crates/mdk-core/src/groups.rs`:391–427**

```rust
// If it's not already in the storage, export the secret and save it
None => {
    let export_secret: [u8; 32] = group
        .export_secret(self.provider.crypto(), "marmot", b"group-event", 32)?
```

`exporter_secret()` checks storage first; on cache miss it re-derives and saves. Post-migration,
if the 'group-event' row was overwritten by a MIP-04 save (see critical bug above), this code
re-derives from the live MLS group — which only works for the current epoch. Past-epoch lookback
(`get_group_exporter_secret` for epoch N < current) will return `None` but cannot re-derive,
leading to a silent decryption failure. This is a **consequence** of the PRIMARY KEY bug; fixing
that fixes this too. Flagging it here so the failure path is understood.

---

### Correctness: `mip04_exporter_secret()` always re-derives, never checks cache

**`crates/mdk-core/src/groups.rs`:449–467**

```rust
#[cfg(feature = "mip04")]
pub(crate) fn mip04_exporter_secret(&self, group_id: &crate::GroupId)
    -> Result<group_types::GroupExporterSecret, Error>
{
    let group = self.load_mls_group(group_id)?.ok_or(Error::GroupNotFound)?;
    let export_secret: [u8; 32] = group
        .export_secret(self.provider.crypto(), "marmot", b"encrypted-media", 32)?
```

`exporter_secret()` (MIP-03) checks storage first and only calls `export_secret()` on miss. The
new `mip04_exporter_secret()` always calls `export_secret()` unconditionally, then returns the
result without saving it (the _caller_ saves it). This is asymmetric. While it happens to work
because callers always save before returning, it means every call to `mip04_exporter_secret()`
re-derives the key even when the value is already in storage, and there is no read-through cache
path for historical epochs (which `get_group_mip04_exporter_secret` provides for lookback). The
function should mirror `exporter_secret()`: check storage first, derive and save only on miss.

---

### Testing: No SQLite storage tests for new MIP-04 methods

**`crates/mdk-sqlite-storage/src/groups.rs`**

The memory storage crate has tests covering `get_group_mip04_exporter_secret` and
`save_group_mip04_exporter_secret`. The SQLite crate has zero tests for these new methods. Given
the primary key bug discovered above, targeted SQLite integration tests (save MIP-03 then MIP-04
for the same epoch, verify both are retrievable) would have caught this during development.

---

### Testing: `[0u8; 32]` sentinel for `nostr_group_id` in existing tests lacks a comment

**`crates/mdk-core/src/messages/decryption.rs`:519, 572**

```rust
let result = alice_mdk.try_decrypt_with_past_epochs(
    &mls_group,
    "invalid_encrypted_content",
    [0u8; 32],   // ← what is this?
    5,
);
```

These tests existed before this PR and were updated to pass `[0u8; 32]` as the new `nostr_group_id`
argument. The intent is clear (tests fail on base64/AEAD decode before AAD matters), but a one-line
comment explaining why any value works here would help the next reader: the content is intentionally
invalid and decryption fails at base64 decode before AAD is ever checked.

---

## Suggestions

- **`crates/mdk-core/src/groups.rs`**: Consider extracting the `nonce || ciphertext` encoding
  into a small private helper function (e.g., `chacha_encrypt`) in `util.rs`, symmetric with
  `decrypt_with_exporter_secret`. This would let `build_message_event` call the helper and make
  the roundtrip test in `util.rs` test both directions through the same code paths rather than
  duplicating the encryption logic inline.

- **`crates/mdk-core/src/util.rs` — minimum length check**: The check `combined.len() < 12` is
  correct for the nonce. Consider also checking `combined.len() < 12 + 16` (nonce + minimum AEAD
  tag) so the cipher is not even invoked with a zero-byte ciphertext. The AEAD crate will return
  an error anyway, but an early explicit check produces a clearer error message and avoids
  constructing the cipher unnecessarily.

- **`crates/mdk-sqlite-storage/migrations/V005__...sql`**: Once the migration is fixed to rebuild
  the table, also drop and recreate the `idx_group_exporter_secrets_mls_group_id` index so it
  points to the new table name.

---

## What's Done Well

- The cryptographic design is correct: separate exporters for MIP-03 and MIP-04 with distinct
  labels prevent key reuse across protocols, and AAD binding to `nostr_group_id` bytes is exactly
  the right primitive for cross-group replay prevention.

- The `OsRng` choice and the inline comment explaining that panic-on-RNG-failure is intentional
  (not a bug) is excellent — it directly addresses the spec requirement and will help future
  reviewers understand the design decision.

- The `nip44` dependency removal is clean: the `Error::NIP44` variant, the `nip44` import in
  `error.rs`, and the `nip44` feature flag are all gone without leaving dead code.

- The unit tests in `util.rs` are well structured and cover all the right failure modes: wrong
  AAD, invalid base64, and truncated nonce. These are exactly the tests that need to exist for
  AEAD-based decryption.

- The epoch-save logic (saving both MIP-03 and MIP-04 secrets on every `merge_pending_commit`)
  is placed correctly in both `groups.rs` and `messages/process.rs`, covering both the explicit
  and relay-echo commit paths.

- Changelog entries are thorough, follow the Keep a Changelog format, and correctly categorize
  items as Breaking/Changed/Added.
