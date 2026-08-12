use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE cgka_disband_requests (
    group_id BLOB PRIMARY KEY REFERENCES cgka_groups(id) ON DELETE CASCADE,
    record BLOB NOT NULL
);

CREATE TABLE cgka_disband_candidates (
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    commit_id BLOB NOT NULL,
    record BLOB NOT NULL,
    PRIMARY KEY (group_id, commit_id)
);

CREATE TABLE cgka_disband_tombstones (
    group_id BLOB PRIMARY KEY,
    record BLOB NOT NULL
);
"#,
    )
    .storage()
}
