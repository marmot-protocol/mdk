//! Account-wide attachment seeks and constant-work privacy invalidation.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("ALTER TABLE attachment_history ADD COLUMN retention_expires_at INTEGER;
        UPDATE attachment_history SET retention_expires_at=(SELECT a.retention_expires_at FROM app_events a WHERE a.group_id_hex=attachment_history.group_id_hex AND a.message_id_hex=attachment_history.message_id_hex);
        CREATE INDEX idx_account_attachment_retention_expiry ON attachment_history(retention_expires_at) WHERE visible=1 AND retention_expires_at IS NOT NULL;
        CREATE TRIGGER account_attachment_retention_added AFTER INSERT ON attachment_history BEGIN
            UPDATE attachment_history SET retention_expires_at=(SELECT a.retention_expires_at FROM app_events a WHERE a.group_id_hex=NEW.group_id_hex AND a.message_id_hex=NEW.message_id_hex)
            WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex AND attachment_index=NEW.attachment_index;
        END;
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
            UPDATE attachment_history SET retention_expires_at=NEW.retention_expires_at WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex;
            UPDATE account_attachment_history_version SET revision=revision+1 WHERE id=1;
        END;") .storage()
}

#[cfg(test)]
mod tests {
    #[test]
    fn populated_v106_upgrade_preserves_group_pages_and_installs_global_mutation_fences() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::migrations::run(&mut conn, &crate::migrations::MIGRATIONS[..106]).unwrap();
        conn.execute_batch("INSERT INTO message_timeline(group_id_hex,message_id_hex,source_message_id_hex,source_epoch,direction,sender,plaintext,kind,tags_json,timeline_at,received_at,reactions_json,media_json)
            VALUES('aa','old','old',0,'received','alice','private',9,'[]',1,1,'[]','{\"imeta\":[[\"imeta\",\"v future\"]]}');").unwrap();
        crate::migrations::run(&mut conn, &crate::migrations::MIGRATIONS[..107]).unwrap();
        crate::migrations::run(&mut conn, &crate::migrations::MIGRATIONS[..107]).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM attachment_history", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
        let before: i64 = conn
            .query_row(
                "SELECT revision FROM account_attachment_history_version",
                [],
                |r| r.get(0),
            )
            .unwrap();
        conn.execute_batch("UPDATE message_timeline SET deleted=1 WHERE message_id_hex='old';")
            .unwrap();
        let after: i64 = conn
            .query_row(
                "SELECT revision FROM account_attachment_history_version",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(after > before);
        conn.execute_batch("UPDATE message_timeline SET deleted=0 WHERE message_id_hex='old'; INSERT INTO user_blocks VALUES('alice',0,0);").unwrap();
        let visible: i64 = conn
            .query_row(
                "SELECT count(*) FROM attachment_history WHERE visible=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(visible, 0);
    }
}
