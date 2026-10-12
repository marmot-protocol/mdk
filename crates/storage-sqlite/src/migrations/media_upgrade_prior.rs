//! Frozen published media migration bodies from d4e91c8d, used only for compatibility fixtures.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::{Transaction, params};
use zeroize::Zeroizing;
/// Reproduce the published 0104 layout so reopening exercises ledger compatibility, not the new writer.
pub(super) fn retained(tx: &Transaction<'_>) -> StorageResult<()> {
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

/// Reproduce published 0105 parent/chunk tables; keep its body frozen for historical reopen fixtures.
pub(super) fn partial(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "DROP TRIGGER attachment_partial_reserved_added;
        DROP TRIGGER attachment_partial_reserved_removed;
        DROP TRIGGER attachment_partial_terminal;
        CREATE TABLE attachment_partial_next (
            token BLOB PRIMARY KEY NOT NULL REFERENCES attachment_acquisition(token) ON DELETE CASCADE,
            ciphertext_digest BLOB NOT NULL CHECK(length(ciphertext_digest)=32),
            locator_digest BLOB NOT NULL CHECK(length(locator_digest)=32),
            etag TEXT NOT NULL CHECK(length(CAST(etag AS BLOB)) BETWEEN 2 AND 1024),
            total INTEGER NOT NULL CHECK(total BETWEEN 1 AND 943718400),
            received INTEGER NOT NULL DEFAULT 0 CHECK(received>=0 AND received<=total),
            expires_at INTEGER NOT NULL CHECK(expires_at>=0)
        );
        INSERT INTO attachment_partial_next SELECT * FROM attachment_partial;
        CREATE TABLE attachment_partial_chunk_next (
            token BLOB NOT NULL REFERENCES attachment_partial_next(token) ON DELETE CASCADE,
            offset INTEGER NOT NULL CHECK(offset>=0),
            bytes BLOB NOT NULL CHECK(typeof(bytes)='blob' AND length(bytes) BETWEEN 1 AND 1048576),
            digest BLOB NOT NULL CHECK(length(digest)=32),
            PRIMARY KEY(token,offset)
        );
        INSERT INTO attachment_partial_chunk_next SELECT * FROM attachment_partial_chunk;
        DROP TABLE attachment_partial_chunk;
        DROP TABLE attachment_partial;
        ALTER TABLE attachment_partial_next RENAME TO attachment_partial;
        ALTER TABLE attachment_partial_chunk_next RENAME TO attachment_partial_chunk;
        CREATE INDEX attachment_partial_expiry ON attachment_partial(expires_at,token);
        CREATE TRIGGER attachment_partial_reserved_added AFTER INSERT ON attachment_partial BEGIN
            UPDATE attachment_partial_usage SET reserved_bytes=reserved_bytes+NEW.total WHERE id=1;
        END;
        CREATE TRIGGER attachment_partial_reserved_removed AFTER DELETE ON attachment_partial BEGIN
            UPDATE attachment_partial_usage SET reserved_bytes=reserved_bytes-OLD.total WHERE id=1;
        END;
        CREATE TRIGGER attachment_partial_terminal AFTER UPDATE OF state ON attachment_acquisition
        WHEN NEW.state=3 OR (NEW.state=5 AND NEW.permission_paused=0)
            OR (NEW.state=4 AND NEW.cancelled=0) BEGIN
            DELETE FROM attachment_partial WHERE token=NEW.token;
        END;",
    ).storage()
}
