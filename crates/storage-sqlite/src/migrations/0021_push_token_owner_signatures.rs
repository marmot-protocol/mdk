//! Rebuild `group_push_tokens` for owner-authenticated, relay-portable push
//! records and add the durable per-key tombstone table.
//!
//! Token records are local, re-gossipable push state (never group state), so the
//! pre-existing rows are dropped rather than migrated: they predate the owner
//! signature, `owner_ts` ordering stamp, and `leaf_index`-keyed record key, none
//! of which can be synthesized for a legacy row. Surviving members re-gossip
//! their current owner-signed records, which repopulate the table.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
DROP TABLE IF EXISTS group_push_tokens;

CREATE TABLE group_push_tokens (
    group_id_hex TEXT NOT NULL,
    member_id_hex TEXT NOT NULL,
    leaf_index INTEGER NOT NULL,
    platform INTEGER NOT NULL,
    token_fingerprint TEXT NOT NULL,
    server_pubkey_hex TEXT NOT NULL,
    relay_hint TEXT,
    encrypted_token BLOB NOT NULL,
    owner_ts INTEGER NOT NULL,
    owner_sig TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (group_id_hex, member_id_hex, leaf_index, platform, server_pubkey_hex)
);

CREATE TABLE group_push_token_tombstones (
    group_id_hex TEXT NOT NULL,
    member_id_hex TEXT NOT NULL,
    leaf_index INTEGER NOT NULL,
    platform INTEGER NOT NULL,
    server_pubkey_hex TEXT NOT NULL,
    owner_ts INTEGER NOT NULL,
    record_digest TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (group_id_hex, member_id_hex, leaf_index, platform, server_pubkey_hex)
);
"#,
    )
    .storage()
}
