use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(r#"
CREATE TABLE attachment_acquisition (
    token BLOB PRIMARY KEY NOT NULL CHECK(length(token)=16),
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    attachment_index INTEGER NOT NULL CHECK(attachment_index>=0),
    source_message_id_hex TEXT NOT NULL,
    source_epoch INTEGER NOT NULL,
    slot_json TEXT NOT NULL CHECK(length(CAST(slot_json AS BLOB))<=16384),
    plaintext_digest BLOB NOT NULL CHECK(length(plaintext_digest)=32),
    expires_at INTEGER,
    state INTEGER NOT NULL DEFAULT 0 CHECK(state BETWEEN 0 AND 5),
    due INTEGER DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
    attempt BLOB CHECK(attempt IS NULL OR length(attempt)=16),
    UNIQUE(group_id_hex,message_id_hex,attachment_index),
    FOREIGN KEY(group_id_hex,message_id_hex) REFERENCES app_events(group_id_hex,message_id_hex) ON DELETE CASCADE,
    CHECK((state IN (0,1,2) AND due IS NOT NULL AND due>=0)
       OR (state IN (3,4,5) AND due IS NULL)),
    CHECK((state=1 AND attempt IS NOT NULL) OR (state<>1 AND attempt IS NULL))
);
CREATE INDEX attachment_acquisition_due ON attachment_acquisition(due,token) WHERE due IS NOT NULL;
CREATE INDEX attachment_acquisition_expiry ON attachment_acquisition(expires_at,token) WHERE expires_at IS NOT NULL;
-- Suppression belongs to retained source records, not rebuildable timeline rows.
CREATE TABLE attachment_removal_suppression (
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    attachment_index INTEGER NOT NULL CHECK(attachment_index>=0),
    PRIMARY KEY(group_id_hex,message_id_hex,attachment_index),
    FOREIGN KEY(group_id_hex,message_id_hex) REFERENCES app_events(group_id_hex,message_id_hex) ON DELETE CASCADE
);
CREATE TABLE retained_attachment_bytes (
    token BLOB PRIMARY KEY NOT NULL REFERENCES attachment_acquisition(token) ON DELETE CASCADE,
    bytes BLOB NOT NULL CHECK(typeof(bytes)='blob' AND length(bytes)<=536870912)
);
CREATE TABLE attachment_retention_usage (
    id INTEGER PRIMARY KEY CHECK(id=1),
    byte_count INTEGER NOT NULL DEFAULT 0 CHECK(byte_count>=0)
);
INSERT INTO attachment_retention_usage(id) VALUES(1);
CREATE TRIGGER attachment_bytes_added AFTER INSERT ON retained_attachment_bytes BEGIN
    UPDATE attachment_retention_usage SET byte_count=byte_count+length(NEW.bytes) WHERE id=1;
END;
CREATE TRIGGER attachment_bytes_removed AFTER DELETE ON retained_attachment_bytes BEGIN
    UPDATE attachment_retention_usage SET byte_count=byte_count-length(OLD.bytes) WHERE id=1;
END;
CREATE TRIGGER attachment_bytes_updated AFTER UPDATE OF bytes ON retained_attachment_bytes BEGIN
    UPDATE attachment_retention_usage SET byte_count=byte_count-length(OLD.bytes)+length(NEW.bytes) WHERE id=1;
END;
CREATE TRIGGER attachment_acquisition_store_reset AFTER UPDATE OF store_epoch ON chat_presentation_meta
WHEN OLD.store_epoch IS NOT NEW.store_epoch BEGIN
    DELETE FROM attachment_acquisition;
    DELETE FROM attachment_removal_suppression;
END;
CREATE TRIGGER attachment_acquisition_retention AFTER UPDATE OF retention_expires_at ON app_events BEGIN
    UPDATE attachment_acquisition SET expires_at=NEW.retention_expires_at
    WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex;
END;
"#).storage()?;
    // Query the authoritative source view, never depend on ordering against the
    // separate attachment-index triggers. A timeline DELETE is not necessarily
    // source removal: group repair deletes/reinserts the whole projection.
    for event in ["INSERT", "UPDATE"] {
        tx.execute_batch(&format!(
            r#"
CREATE TRIGGER attachment_acquisition_source_{event} AFTER {event} ON message_timeline BEGIN
    DELETE FROM attachment_acquisition
    WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex
      AND NOT EXISTS(SELECT 1 FROM attachment_history_source s
        WHERE s.group_id_hex=attachment_acquisition.group_id_hex
          AND s.message_id_hex=attachment_acquisition.message_id_hex
          AND s.attachment_index=attachment_acquisition.attachment_index
          AND s.source_message_id_hex=attachment_acquisition.source_message_id_hex
          AND s.source_epoch=attachment_acquisition.source_epoch
          AND s.slot_json=attachment_acquisition.slot_json);
END;
"#
        ))
        .storage()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    #[test]
    fn attachment_acquisition_upgrade_preserves_discovery_and_rolls_back_atomically() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..82]).unwrap();
        conn.execute_batch(r#"
            INSERT INTO message_timeline(group_id_hex,message_id_hex,source_message_id_hex,
                direction,sender,plaintext,kind,tags_json,timeline_at,received_at,reactions_json,media_json)
            VALUES('aa','old','source','received','alice','',9,'[]',1,2,'[]',
                '{"imeta":[["imeta","url https://example.com/a"],null]}');
        "#).unwrap();
        let count = |conn: &Connection, table: &str| -> i64 {
            conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap()
        };
        let tx = conn.transaction().unwrap();
        apply(&tx).unwrap();
        assert_eq!(count(&tx, "attachment_acquisition"), 0);
        tx.rollback().unwrap();
        assert!(!conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='attachment_acquisition')", [], |r|r.get::<_,bool>(0)).unwrap());
        assert_eq!(count(&conn, "attachment_history"), 2);
        run(&mut conn, MIGRATIONS).unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        assert_eq!(count(&conn, "attachment_history"), 2);
        assert_eq!(count(&conn, "attachment_acquisition"), 0);
        assert_eq!(count(&conn, "retained_attachment_bytes"), 0);
        assert_eq!(count(&conn, "attachment_removal_suppression"), 0);
    }
}
