use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Also gates the new durable reinvite/rejoin record fields against older writers.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "
CREATE TABLE app_group_membership_evidence (
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    message_id BLOB NOT NULL,
    epoch INTEGER NOT NULL,
    PRIMARY KEY (group_id, message_id)
);
CREATE TABLE app_group_membership_uncertainty (
    group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE
);
",
    )
    .storage()
}
