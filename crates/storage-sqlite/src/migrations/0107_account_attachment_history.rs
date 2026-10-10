//! Account-wide attachment seeks and constant-work privacy invalidation.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("CREATE INDEX idx_account_event_retention_expiry ON app_events(retention_expires_at) WHERE retention_expires_at IS NOT NULL;
        CREATE INDEX idx_account_attachment_history_page ON attachment_history(
        timeline_at DESC,group_id_hex DESC,message_id_hex DESC,attachment_order DESC) WHERE visible=1;
        CREATE TABLE account_attachment_history_version(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL,additions INTEGER NOT NULL);
        INSERT INTO account_attachment_history_version VALUES(1,0,0);
        CREATE TRIGGER account_attachment_history_added AFTER INSERT ON attachment_history_versions BEGIN
            UPDATE account_attachment_history_version SET additions=additions+NEW.additions WHERE id=1;
        END;
        CREATE TRIGGER account_attachment_history_changed AFTER UPDATE ON attachment_history_versions BEGIN
            UPDATE account_attachment_history_version SET
                revision=revision+CASE WHEN NEW.revision IS NOT OLD.revision OR NEW.generation IS NOT OLD.generation THEN 1 ELSE 0 END,
                additions=additions+CASE WHEN NEW.additions IS NOT OLD.additions THEN 1 ELSE 0 END WHERE id=1;
        END;
        CREATE TRIGGER account_attachment_history_removed AFTER DELETE ON attachment_history_versions BEGIN
            UPDATE account_attachment_history_version SET revision=revision+1 WHERE id=1;
        END;
        CREATE TRIGGER account_attachment_retention_changed AFTER UPDATE OF retention_expires_at ON app_events
        WHEN OLD.retention_expires_at IS NOT NEW.retention_expires_at AND EXISTS(SELECT 1 FROM attachment_history h
            WHERE h.group_id_hex=NEW.group_id_hex AND h.message_id_hex=NEW.message_id_hex) BEGIN
            UPDATE account_attachment_history_version SET revision=revision+1 WHERE id=1;
        END;") .storage()
}
