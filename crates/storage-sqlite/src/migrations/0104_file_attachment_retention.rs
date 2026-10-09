//! Preserve retained sources while admitting bounded, file-backed large bodies.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::{Transaction, params};
use zeroize::Zeroizing;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "DROP TRIGGER attachment_bytes_added;
        DROP TRIGGER attachment_bytes_removed;
        DROP TRIGGER attachment_bytes_updated;
        CREATE TABLE retained_attachment_bytes_next (
            token BLOB PRIMARY KEY NOT NULL REFERENCES attachment_acquisition(token) ON DELETE CASCADE,
            byte_len INTEGER NOT NULL DEFAULT -1 CHECK(byte_len BETWEEN -1 AND 943718400),
            bytes BLOB NOT NULL CHECK(typeof(bytes)='blob' AND
                ((byte_len=-1 AND length(bytes)<=536870912) OR (byte_len>=0 AND length(bytes)=byte_len)))
        );",
    ).storage()?;
    let mut statement = tx
        .prepare("SELECT rowid,token,length(bytes) FROM retained_attachment_bytes")
        .storage()?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .storage()?;
    let mut buffer = Zeroizing::new(vec![0u8; 64 * 1024]);
    for row in rows {
        let (row, token, len) = row.storage()?;
        tx.execute("INSERT INTO retained_attachment_bytes_next(token,byte_len,bytes) VALUES(?1,?2,zeroblob(?2))",
            params![token, len]).storage()?;
        let target = tx.last_insert_rowid();
        let source = tx
            .blob_open("main", "retained_attachment_bytes", "bytes", row, true)
            .storage()?;
        let mut destination = tx
            .blob_open(
                "main",
                "retained_attachment_bytes_next",
                "bytes",
                target,
                false,
            )
            .storage()?;
        let mut offset = 0usize;
        while offset < len as usize {
            let count = buffer.len().min(len as usize - offset);
            source
                .read_at_exact(&mut buffer[..count], offset)
                .storage()?;
            destination.write_at(&buffer[..count], offset).storage()?;
            offset += count;
        }
        source.close().storage()?;
        destination.close().storage()?;
    }
    drop(statement);
    tx.execute_batch(
        "DROP TABLE retained_attachment_bytes;
        ALTER TABLE retained_attachment_bytes_next RENAME TO retained_attachment_bytes;
        CREATE TRIGGER attachment_bytes_added AFTER INSERT ON retained_attachment_bytes BEGIN
            UPDATE retained_attachment_bytes SET byte_len=length(NEW.bytes)
                WHERE token=NEW.token AND NEW.byte_len<0;
            UPDATE attachment_retention_usage SET byte_count=byte_count+
                CASE WHEN NEW.byte_len<0 THEN length(NEW.bytes) ELSE NEW.byte_len END WHERE id=1;
        END;
        CREATE TRIGGER attachment_bytes_removed AFTER DELETE ON retained_attachment_bytes BEGIN
            UPDATE attachment_retention_usage SET byte_count=byte_count-
                OLD.byte_len WHERE id=1;
        END;
        CREATE TRIGGER attachment_bytes_updated AFTER UPDATE OF bytes ON retained_attachment_bytes BEGIN
            UPDATE attachment_retention_usage SET byte_count=byte_count-
                OLD.byte_len+
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
        let deletion: String = conn.query_row("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='attachment_bytes_removed'", [], |r|r.get(0)).unwrap();
        assert!(
            !deletion.contains("OLD.bytes"),
            "deletion must use stored metadata"
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
