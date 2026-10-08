//! Migration 0107: per-group holds on epoch advancement while known history
//! is still being acquired, and the exact event ids each hold waits for
//! (mdk#2086).

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE cgka_history_acquisition_holds (
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    transport_group_id BLOB NOT NULL
        CHECK(typeof(transport_group_id) = 'blob' AND length(transport_group_id) = 32),
    stalled_passes INTEGER NOT NULL DEFAULT 0
        CHECK(typeof(stalled_passes) = 'integer' AND stalled_passes >= 0),
    admitted_since_settle INTEGER NOT NULL DEFAULT 0
        CHECK(typeof(admitted_since_settle) = 'integer' AND admitted_since_settle >= 0),
    PRIMARY KEY(group_id, transport_group_id)
);
CREATE TABLE cgka_history_acquisition_debt (
    transport_group_id BLOB NOT NULL,
    event_id BLOB NOT NULL CHECK(typeof(event_id) = 'blob' AND length(event_id) = 32),
    group_id BLOB NOT NULL,
    abandoned INTEGER NOT NULL DEFAULT 0 CHECK(abandoned IN (0, 1)),
    PRIMARY KEY(transport_group_id, event_id, group_id),
    FOREIGN KEY(group_id, transport_group_id)
        REFERENCES cgka_history_acquisition_holds(group_id, transport_group_id)
        ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX cgka_history_acquisition_debt_by_hold
    ON cgka_history_acquisition_debt(group_id, transport_group_id);
"#,
    )
    .storage()
}
