//! Migration 0168: private backup catalog and honest history provenance.
//! Existing sibling imports retain their slot; backup imports have no device
//! attribution. Both use the same import mark for retention/unread/media rules.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
-- Keep the table and its dependent views/triggers in place. Replacing only
-- the slot column removes its old NOT NULL constraint without a table rename
-- through an invalid attachment-history schema. All changes share the runner's
-- transaction; existing sibling slots retain their exact bytes.
ALTER TABLE app_event_imports ADD COLUMN sibling_source_slot BLOB
    CHECK (sibling_source_slot IS NULL OR length(sibling_source_slot) = 32);
UPDATE app_event_imports SET sibling_source_slot = source_slot;
ALTER TABLE app_event_imports DROP COLUMN source_slot;
ALTER TABLE app_event_imports RENAME COLUMN sibling_source_slot TO source_slot;
ALTER TABLE app_event_imports ADD COLUMN backup_recovery_key BLOB
    CHECK (backup_recovery_key IS NULL OR length(backup_recovery_key) = 32);
ALTER TABLE app_event_imports ADD COLUMN backup_id BLOB
    CHECK (backup_id IS NULL OR length(backup_id) = 16);
ALTER TABLE app_event_imports ADD COLUMN backup_head_sha256 BLOB
    CHECK (backup_head_sha256 IS NULL OR length(backup_head_sha256) = 32);
ALTER TABLE app_event_imports ADD COLUMN backup_written_at INTEGER
    CHECK (backup_written_at IS NULL OR backup_written_at >= 0)
    CONSTRAINT history_import_source CHECK (
        (source_slot IS NOT NULL AND backup_recovery_key IS NULL AND backup_id IS NULL
            AND backup_head_sha256 IS NULL AND backup_written_at IS NULL)
        OR
        (source_slot IS NULL AND backup_recovery_key IS NOT NULL AND backup_id IS NOT NULL
            AND backup_head_sha256 IS NOT NULL AND backup_written_at IS NOT NULL)
    );

CREATE TABLE backup_restore_catalog (
    recovery_key BLOB NOT NULL CHECK (length(recovery_key) = 32),
    backup_id BLOB NOT NULL CHECK (length(backup_id) = 16),
    head_sha256 BLOB NOT NULL CHECK (length(head_sha256) = 32),
    head_server TEXT NOT NULL,
    head_size INTEGER NOT NULL CHECK (head_size > 0 AND head_size <= 8388608),
    written_at INTEGER NOT NULL CHECK (written_at >= 0),
    PRIMARY KEY (recovery_key, backup_id)
) WITHOUT ROWID;
CREATE TABLE backup_restore_catalog_chats (
    recovery_key BLOB NOT NULL,
    backup_id BLOB NOT NULL,
    chat_id BLOB NOT NULL CHECK (length(chat_id) BETWEEN 1 AND 256),
    PRIMARY KEY (recovery_key, backup_id, chat_id),
    FOREIGN KEY (recovery_key, backup_id) REFERENCES backup_restore_catalog
        (recovery_key, backup_id) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX backup_restore_catalog_by_chat
    ON backup_restore_catalog_chats(chat_id,recovery_key,backup_id);
"#,
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::{Connection, Error, ErrorCode, params};

    /// Existing sibling provenance survives the nullable-column upgrade;
    /// backup provenance is an alternative, never a fabricated sibling.
    #[test]
    fn backup_source_upgrade_preserves_sibling_imports_and_requires_one_complete_source() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        run_through(&mut conn, 167).unwrap();
        for message in ["legacy", "backup"] {
            conn.execute(
                "INSERT INTO app_events
                 (group_id_hex,message_id_hex,direction,sender,plaintext,kind,tags_json,recorded_at,received_at)
                 VALUES ('chat',?1,'received','sender','held history',9,'[]',11,12)",
                [message],
            ).unwrap();
        }
        let slot: Vec<u8> = (1..=32).collect();
        conn.execute(
            "INSERT INTO app_event_imports(group_id_hex,message_id_hex,source_slot,imported_at)
             VALUES ('chat','legacy',?1,137)",
            [&slot],
        )
        .unwrap();
        run_through(&mut conn, 168).unwrap();
        let preserved: (Vec<u8>, i64, String) = conn
            .query_row(
                "SELECT i.source_slot,i.imported_at,e.plaintext FROM app_event_imports i
             JOIN app_events e USING(group_id_hex,message_id_hex)
             WHERE i.group_id_hex='chat' AND i.message_id_hex='legacy'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(preserved, (slot.clone(), 137, "held history".into()));
        conn.execute(
            "INSERT INTO app_event_imports(group_id_hex,message_id_hex,source_slot,imported_at,
             backup_recovery_key,backup_id,backup_head_sha256,backup_written_at)
             VALUES ('chat','backup',NULL,149,?1,?2,?3,127)",
            params![
                [2u8; 32].as_slice(),
                [3u8; 16].as_slice(),
                [4u8; 32].as_slice()
            ],
        )
        .unwrap();
        type BackupSourceRow = (Option<Vec<u8>>, i64, Vec<u8>, Vec<u8>, Vec<u8>, i64);
        let backup: BackupSourceRow = conn.query_row(
            "SELECT source_slot,imported_at,backup_recovery_key,backup_id,backup_head_sha256,backup_written_at
             FROM app_event_imports WHERE group_id_hex='chat' AND message_id_hex='backup'",
            [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
        ).unwrap();
        assert_eq!(
            backup,
            (None, 149, vec![2; 32], vec![3; 16], vec![4; 32], 127)
        );
        for change in [
            "source_slot=zeroblob(32)",
            "backup_id=NULL",
            "backup_recovery_key=NULL,backup_id=NULL,backup_head_sha256=NULL,backup_written_at=NULL",
        ] {
            let error = conn.execute(
                &format!("UPDATE app_event_imports SET {change} WHERE group_id_hex='chat' AND message_id_hex='backup'"), [],
            ).unwrap_err();
            assert!(
                matches!(error, Error::SqliteFailure(ref code,Some(ref message))
                if code.code==ErrorCode::ConstraintViolation && message.contains("history_import_source")),
                "the source-shape check must reject the invalid row: {error:?}"
            );
        }
    }
}
