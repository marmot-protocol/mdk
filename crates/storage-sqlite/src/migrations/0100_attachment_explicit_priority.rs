//! Preserve explicit tap priority across same-source history reprojection.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Automatic demand follows history recency; explicit demand keeps its tap time.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("DROP TRIGGER attachment_acquisition_priority_update;
        CREATE TRIGGER attachment_acquisition_priority_update AFTER UPDATE OF received_at ON attachment_history BEGIN
            UPDATE attachment_acquisition SET priority_at=NEW.received_at
            WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex
                AND attachment_index=NEW.attachment_index AND explicit_request=0;
        END;").storage()
}
