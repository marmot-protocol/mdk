//! Bounded file-backed bodies for optional outgoing upload staging (#2175).
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Migration 0101 keeps `bytes` in the middle of a mutable row: inserting a
/// `zeroblob` there expands it in memory, and every later parent UPDATE (slot
/// binding, recovery cursor) rewrites the whole record. File-backed staging
/// keeps the parent's `bytes` empty and stores the body as the last column of
/// this narrow, never-updated row, so incremental BLOB I/O writes and reads it
/// in bounded chunks. Accounting uses the declared length, never `OLD.bytes`,
/// so DELETE/cascade does not load the body. Quota stays in the shared
/// `attachment_retention_usage` counter and inside the account's SQLCipher store.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE outgoing_attachment_upload_bodies (
        token BLOB PRIMARY KEY NOT NULL REFERENCES outgoing_attachment_uploads(token) ON DELETE CASCADE,
        byte_len INTEGER NOT NULL CHECK(byte_len>0 AND byte_len<=943718400),
        bytes BLOB NOT NULL CHECK(typeof(bytes)='blob' AND length(bytes)=byte_len)
    );
    CREATE TRIGGER outgoing_upload_body_added AFTER INSERT ON outgoing_attachment_upload_bodies BEGIN
        UPDATE attachment_retention_usage SET byte_count=byte_count+NEW.byte_len WHERE id=1;
    END;
    CREATE TRIGGER outgoing_upload_body_removed AFTER DELETE ON outgoing_attachment_upload_bodies BEGIN
        UPDATE attachment_retention_usage SET byte_count=byte_count-OLD.byte_len WHERE id=1;
    END;
    CREATE TRIGGER outgoing_upload_body_immutable BEFORE UPDATE ON outgoing_attachment_upload_bodies BEGIN
        SELECT RAISE(ABORT,'outgoing upload body is immutable');
    END;",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    #[test]
    fn body_rows_account_declared_length_and_reject_updates() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys=ON;
            CREATE TABLE attachment_retention_usage(id INTEGER PRIMARY KEY, byte_count INTEGER NOT NULL CHECK(byte_count>=0));
            INSERT INTO attachment_retention_usage VALUES(1,0);
            CREATE TABLE outgoing_attachment_uploads(token BLOB PRIMARY KEY NOT NULL);
            INSERT INTO outgoing_attachment_uploads VALUES(x'00112233445566778899aabbccddeeff');",
        )
        .unwrap();
        let tx = conn.transaction().unwrap();
        super::apply(&tx).unwrap();
        tx.commit().unwrap();
        conn.execute(
            "INSERT INTO outgoing_attachment_upload_bodies VALUES(x'00112233445566778899aabbccddeeff',5,zeroblob(5))",
            [],
        )
        .unwrap();
        let used = |conn: &Connection| -> i64 {
            conn.query_row(
                "SELECT byte_count FROM attachment_retention_usage",
                [],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(used(&conn), 5);
        assert!(
            conn.execute(
                "UPDATE outgoing_attachment_upload_bodies SET bytes=x'00'",
                []
            )
            .is_err()
        );
        conn.execute("DELETE FROM outgoing_attachment_uploads", [])
            .unwrap();
        assert_eq!(used(&conn), 0);
    }
}
