//! Add retained-body metadata without rewriting encrypted legacy payloads.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Keep the legacy byte-array bound; larger file bodies use migration 0106's chunk tables.
/// Existing rows retain a sentinel length and are accounted from SQLite's BLOB length.
/// No bytes or stored quota are rewritten while an account opens. Validation triggers
/// enforce new metadata on mutation; an ADD COLUMN CHECK would scan existing payloads.
/// Before mutation, indexed length queries handle legacy rows without binding the BLOB into OLD.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "ALTER TABLE retained_attachment_bytes ADD COLUMN byte_len INTEGER NOT NULL DEFAULT -1;
        DROP TRIGGER attachment_bytes_added;
        DROP TRIGGER attachment_bytes_removed;
        DROP TRIGGER attachment_bytes_updated;
        CREATE TRIGGER attachment_body_metadata_insert BEFORE INSERT ON retained_attachment_bytes
        WHEN NOT (typeof(NEW.byte_len)='integer' AND NEW.byte_len BETWEEN -1 AND 536870912
            AND (NEW.byte_len=-1 OR length(NEW.bytes)=NEW.byte_len)) BEGIN
            SELECT RAISE(ABORT,'invalid retained body length');
        END;
        CREATE TRIGGER attachment_body_metadata_update BEFORE UPDATE OF bytes,byte_len ON retained_attachment_bytes
        WHEN NOT (typeof(NEW.byte_len)='integer' AND NEW.byte_len BETWEEN -1 AND 536870912
            AND (NEW.byte_len=-1 OR length(NEW.bytes)=NEW.byte_len)) BEGIN
            SELECT RAISE(ABORT,'invalid retained body length');
        END;
        CREATE TRIGGER attachment_bytes_added AFTER INSERT ON retained_attachment_bytes BEGIN
            UPDATE retained_attachment_bytes SET byte_len=length(NEW.bytes)
                WHERE token=NEW.token AND NEW.byte_len<0;
            UPDATE attachment_retention_usage SET byte_count=byte_count+
                CASE WHEN NEW.byte_len<0 THEN length(NEW.bytes) ELSE NEW.byte_len END WHERE id=1;
        END;
        CREATE TRIGGER attachment_bytes_removed BEFORE DELETE ON retained_attachment_bytes BEGIN
            UPDATE attachment_retention_usage SET byte_count=byte_count-
                CASE WHEN OLD.byte_len<0 THEN
                    (SELECT length(bytes) FROM retained_attachment_bytes WHERE token=OLD.token)
                ELSE OLD.byte_len END WHERE id=1;
        END;
        CREATE TRIGGER attachment_bytes_updated BEFORE UPDATE OF bytes ON retained_attachment_bytes BEGIN
            UPDATE attachment_retention_usage SET byte_count=byte_count-
                CASE WHEN OLD.byte_len<0 THEN
                    (SELECT length(bytes) FROM retained_attachment_bytes WHERE token=OLD.token)
                ELSE OLD.byte_len END+
                CASE WHEN NEW.byte_len<0 THEN length(NEW.bytes) ELSE NEW.byte_len END WHERE id=1;
        END;",
    ).storage()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn populated_upgrade_preserves_bytes_and_usage_and_rolls_back() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;
            CREATE TABLE attachment_acquisition(token BLOB PRIMARY KEY);
            INSERT INTO attachment_acquisition VALUES(x'01');
            CREATE TABLE retained_attachment_bytes(token BLOB PRIMARY KEY REFERENCES attachment_acquisition(token) ON DELETE CASCADE,bytes BLOB NOT NULL);
            INSERT INTO retained_attachment_bytes VALUES(x'01',x'01020304');
            CREATE TABLE attachment_retention_usage(id INTEGER PRIMARY KEY,byte_count INTEGER);
            INSERT INTO attachment_retention_usage VALUES(1,4);
            CREATE TRIGGER attachment_bytes_added AFTER INSERT ON retained_attachment_bytes BEGIN SELECT 1; END;
            CREATE TRIGGER attachment_bytes_removed AFTER DELETE ON retained_attachment_bytes BEGIN SELECT 1; END;
            CREATE TRIGGER attachment_bytes_updated AFTER UPDATE OF bytes ON retained_attachment_bytes BEGIN SELECT 1; END;").unwrap();
        {
            let tx = conn.transaction().unwrap();
            apply(&tx).unwrap();
            tx.rollback().unwrap();
        }
        assert_eq!(
            conn.query_row("SELECT bytes FROM retained_attachment_bytes", [], |row| row
                .get::<_, Vec<u8>>(0))
                .unwrap(),
            vec![1, 2, 3, 4]
        );
        let tx = conn.transaction().unwrap();
        apply(&tx).unwrap();
        tx.commit().unwrap();
        assert_eq!(
            conn.query_row("SELECT bytes FROM retained_attachment_bytes", [], |row| row
                .get::<_, Vec<u8>>(0))
                .unwrap(),
            vec![1, 2, 3, 4]
        );
        assert_eq!(
            conn.query_row(
                "SELECT byte_count FROM attachment_retention_usage",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            4
        );
        // Legacy callers omit byte_len. Normalize it on insert so deletion
        // accounting never references OLD.bytes (SQLite loads that entire blob).
        conn.execute("INSERT INTO attachment_acquisition VALUES(x'02')", [])
            .unwrap();
        conn.execute(
            "INSERT INTO retained_attachment_bytes(token,bytes) VALUES(x'02',zeroblob(8192))",
            [],
        )
        .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT byte_len FROM retained_attachment_bytes WHERE token=x'02'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            8192
        );
        assert_eq!(
            conn.query_row(
                "SELECT byte_count FROM attachment_retention_usage",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            8196
        );
        conn.execute("DELETE FROM attachment_acquisition", [])
            .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT byte_count FROM attachment_retention_usage",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }
}
