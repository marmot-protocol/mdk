//! Migration 0206: the relays that refused this device's confirmed commits
//! (mdk#2333).
//!
//! One row per refused commit, keyed by the commit's frozen fanout id: the
//! refusal outlives that fanout and warns until the user acknowledges it.
//! Rows go with their group: forgetting it, or deleting a terminal group,
//! deletes the `cgka_groups` row, while an active chat wipe keeps both. The
//! table is outside every snapshot and checkpoint.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE cgka_commit_refusals (
            fanout_id BLOB PRIMARY KEY,
            group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
            record BLOB NOT NULL
        );
        CREATE INDEX idx_cgka_commit_refusals_group ON cgka_commit_refusals(group_id);",
    )
    .storage()
}
