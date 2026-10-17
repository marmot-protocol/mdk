use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Introduce the normalized message-row format without rewriting account
/// history during session open.
///
/// Existing rows remain format 1 and retain their complete JSON `record`.
/// Current writers use format 2, where indexed scalar columns are authoritative
/// and the byte-heavy payload plus optional deferred-peel metadata are stored
/// separately. Reading or updating a format-1 row can promote it atomically.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE cgka_messages_new (
    insert_order INTEGER PRIMARY KEY AUTOINCREMENT,
    id BLOB NOT NULL UNIQUE,
    group_id BLOB NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
    epoch INTEGER NOT NULL,
    state INTEGER NOT NULL,
    storage_format INTEGER NOT NULL DEFAULT 1,
    record BLOB,
    payload BLOB,
    deferred_peel BLOB,
    CHECK (
        (storage_format = 1 AND record IS NOT NULL AND payload IS NULL)
        OR
        (storage_format = 2 AND record IS NULL AND payload IS NOT NULL)
    )
);
INSERT INTO cgka_messages_new (
    insert_order, id, group_id, epoch, state, storage_format, record, payload, deferred_peel
)
SELECT insert_order, id, group_id, epoch, state, 1, record, NULL, NULL
FROM cgka_messages;
DROP TABLE cgka_messages;
ALTER TABLE cgka_messages_new RENAME TO cgka_messages;
CREATE INDEX idx_cgka_messages_group_epoch
    ON cgka_messages (group_id, epoch, insert_order);
CREATE INDEX idx_cgka_messages_group_state_epoch
    ON cgka_messages (group_id, state, epoch);
"#,
    )
    .storage()
}
