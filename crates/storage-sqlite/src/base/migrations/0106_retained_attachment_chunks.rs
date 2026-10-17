//! Keep file imports protected and unreadable while short transactions append chunks.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE attachment_chunk_bodies (nonce BLOB PRIMARY KEY NOT NULL CHECK(length(nonce)=16));
        CREATE TABLE retained_attachment_files (
            token BLOB PRIMARY KEY NOT NULL REFERENCES retained_attachment_bytes(token) ON DELETE CASCADE,
            nonce BLOB NOT NULL REFERENCES attachment_chunk_bodies(nonce),
            attempt BLOB NOT NULL CHECK(length(attempt)=16),
            byte_len INTEGER NOT NULL CHECK(byte_len BETWEEN 0 AND 943718400),
            completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN(0,1))
        );
        CREATE TABLE retained_attachment_chunks (
            token BLOB NOT NULL REFERENCES attachment_chunk_bodies(nonce) ON DELETE CASCADE,
            offset INTEGER NOT NULL CHECK(offset>=0),
            bytes BLOB NOT NULL CHECK(typeof(bytes)='blob' AND length(bytes) BETWEEN 1 AND 65536),
            PRIMARY KEY(token,offset)
        ) WITHOUT ROWID;
        CREATE TABLE outgoing_attachment_upload_files (
            token BLOB PRIMARY KEY NOT NULL REFERENCES outgoing_attachment_uploads(token) ON DELETE CASCADE,
            nonce BLOB NOT NULL REFERENCES attachment_chunk_bodies(nonce),
            byte_len INTEGER NOT NULL CHECK(byte_len BETWEEN 1 AND 943718400),
            completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN(0,1))
        );
        CREATE INDEX retained_attachment_files_nonce ON retained_attachment_files(nonce);
        CREATE INDEX outgoing_attachment_upload_files_nonce ON outgoing_attachment_upload_files(nonce);
        CREATE TRIGGER retained_file_identity_immutable BEFORE UPDATE OF token,nonce,attempt,byte_len ON retained_attachment_files BEGIN
            SELECT RAISE(ABORT,'retained file identity is immutable');
        END;
        CREATE TRIGGER outgoing_file_identity_immutable BEFORE UPDATE OF token,nonce,byte_len ON outgoing_attachment_upload_files BEGIN
            SELECT RAISE(ABORT,'outgoing file identity is immutable');
        END;
        CREATE TRIGGER attachment_file_chunk_update_immutable BEFORE UPDATE ON retained_attachment_chunks
        WHEN EXISTS(SELECT 1 FROM retained_attachment_files WHERE nonce=OLD.token AND completed=1)
            OR EXISTS(SELECT 1 FROM outgoing_attachment_upload_files WHERE nonce=OLD.token AND completed=1) BEGIN
            SELECT RAISE(ABORT,'verified file chunks are immutable');
        END;
        CREATE TRIGGER attachment_file_chunk_insert_immutable BEFORE INSERT ON retained_attachment_chunks
        WHEN EXISTS(SELECT 1 FROM retained_attachment_files WHERE nonce=NEW.token AND completed=1)
            OR EXISTS(SELECT 1 FROM outgoing_attachment_upload_files WHERE nonce=NEW.token AND completed=1) BEGIN
            SELECT RAISE(ABORT,'verified file chunks are immutable');
        END;
        CREATE TRIGGER attachment_file_chunk_delete_immutable BEFORE DELETE ON retained_attachment_chunks
        WHEN EXISTS(SELECT 1 FROM retained_attachment_files WHERE nonce=OLD.token AND completed=1)
            OR EXISTS(SELECT 1 FROM outgoing_attachment_upload_files WHERE nonce=OLD.token AND completed=1) BEGIN
            SELECT RAISE(ABORT,'verified file chunks are immutable');
        END;
        CREATE TRIGGER outgoing_file_added AFTER INSERT ON outgoing_attachment_upload_files BEGIN
            UPDATE attachment_retention_usage SET byte_count=byte_count+NEW.byte_len WHERE id=1;
        END;
        CREATE TRIGGER outgoing_file_removed AFTER DELETE ON outgoing_attachment_upload_files BEGIN
            UPDATE attachment_retention_usage SET byte_count=byte_count-OLD.byte_len WHERE id=1;
            DELETE FROM attachment_chunk_bodies WHERE nonce=OLD.nonce
                AND NOT EXISTS(SELECT 1 FROM retained_attachment_files WHERE nonce=OLD.nonce)
                AND NOT EXISTS(SELECT 1 FROM outgoing_attachment_upload_files WHERE nonce=OLD.nonce);
        END;
        CREATE TRIGGER unfinished_file_attempt_changed AFTER UPDATE OF state,attempt ON attachment_acquisition
        WHEN NEW.state<>1 OR NEW.attempt IS NOT OLD.attempt BEGIN
            DELETE FROM retained_attachment_bytes WHERE token=NEW.token AND EXISTS(
                SELECT 1 FROM retained_attachment_files f WHERE f.token=NEW.token AND f.completed=0);
        END;
        CREATE TRIGGER retained_file_added AFTER INSERT ON retained_attachment_files BEGIN
            UPDATE attachment_retention_usage SET byte_count=byte_count+NEW.byte_len WHERE id=1;
        END;
        CREATE TRIGGER retained_file_removed AFTER DELETE ON retained_attachment_files BEGIN
            UPDATE attachment_retention_usage SET byte_count=byte_count-OLD.byte_len WHERE id=1;
            DELETE FROM attachment_chunk_bodies WHERE nonce=OLD.nonce
                AND NOT EXISTS(SELECT 1 FROM retained_attachment_files WHERE nonce=OLD.nonce)
                AND NOT EXISTS(SELECT 1 FROM outgoing_attachment_upload_files WHERE nonce=OLD.nonce);
        END;",
    ).storage()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_upgrade_preserves_legacy_bytes_and_fences_unfinished_attempts() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;
            CREATE TABLE attachment_acquisition(token BLOB PRIMARY KEY,state INTEGER,attempt BLOB);
            CREATE TABLE retained_attachment_bytes(token BLOB PRIMARY KEY REFERENCES attachment_acquisition(token) ON DELETE CASCADE,bytes BLOB);
            CREATE TABLE outgoing_attachment_uploads(token BLOB PRIMARY KEY);
            CREATE TABLE attachment_retention_usage(id INTEGER PRIMARY KEY,byte_count INTEGER NOT NULL CHECK(byte_count>=0));
            INSERT INTO attachment_retention_usage VALUES(1,4);
            INSERT INTO attachment_acquisition VALUES(x'01',3,NULL);
            INSERT INTO retained_attachment_bytes VALUES(x'01',x'01020304');").unwrap();
        {
            let tx = conn.transaction().unwrap();
            apply(&tx).unwrap();
            tx.rollback().unwrap();
        }
        assert!(
            conn.prepare("SELECT * FROM retained_attachment_files")
                .is_err()
        );
        let tx = conn.transaction().unwrap();
        apply(&tx).unwrap();
        tx.commit().unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT bytes FROM retained_attachment_bytes WHERE token=x'01'",
                [],
                |r| r.get::<_, Vec<u8>>(0)
            )
            .unwrap(),
            vec![1, 2, 3, 4]
        );
        conn.execute_batch(
            "INSERT INTO attachment_acquisition VALUES(x'02',1,zeroblob(16));
            INSERT INTO retained_attachment_bytes VALUES(x'02',x'');
            INSERT INTO attachment_chunk_bodies VALUES(zeroblob(16));
            INSERT INTO retained_attachment_files VALUES(x'02',zeroblob(16),zeroblob(16),80,0);
            INSERT INTO retained_attachment_chunks VALUES(zeroblob(16),0,zeroblob(80));",
        )
        .unwrap();
        let usage = |c: &rusqlite::Connection| {
            c.query_row(
                "SELECT byte_count FROM attachment_retention_usage",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap()
        };
        assert_eq!(usage(&conn), 84);
        conn.execute_batch(
            "UPDATE attachment_acquisition SET state=0,attempt=NULL WHERE token=x'02';",
        )
        .unwrap();
        assert_eq!(usage(&conn), 4);
        assert_eq!(
            conn.query_row("SELECT count(*) FROM retained_attachment_chunks", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM attachment_chunk_bodies", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
