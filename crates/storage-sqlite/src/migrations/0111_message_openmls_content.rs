use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Persist each message row's OpenMLS content class and MLS epoch beside its
/// payload (mdk#2330), so convergence listings can leave out delivered
/// application history in SQL instead of decoding every retained row.
///
/// `openmls_content` is derived from the payload on every write (see
/// `storage::messages::openmls_content_columns`). Existing rows take `-1`
/// ("not derived yet") without a table rewrite; listings return them
/// unconditionally, and the bounded promotion sweep derives them. The
/// partial index serves that sweep; the composite index serves the
/// listings' state, content, and epoch filters.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE cgka_messages ADD COLUMN openmls_content INTEGER NOT NULL DEFAULT -1;
ALTER TABLE cgka_messages ADD COLUMN openmls_epoch INTEGER;
CREATE INDEX idx_cgka_messages_group_state_openmls
    ON cgka_messages (group_id, state, openmls_content, openmls_epoch);
CREATE INDEX idx_cgka_messages_openmls_pending
    ON cgka_messages (insert_order) WHERE openmls_content = -1;
"#,
    )
    .storage()
}
