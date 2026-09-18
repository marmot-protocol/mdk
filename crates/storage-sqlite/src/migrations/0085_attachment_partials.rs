use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(r#"
CREATE TABLE attachment_partial (
 token BLOB PRIMARY KEY NOT NULL REFERENCES attachment_acquisition(token) ON DELETE CASCADE,
 ciphertext_digest BLOB NOT NULL CHECK(length(ciphertext_digest)=32),
 locator_digest BLOB NOT NULL CHECK(length(locator_digest)=32),
 etag TEXT NOT NULL CHECK(length(CAST(etag AS BLOB)) BETWEEN 2 AND 1024),
 total INTEGER NOT NULL CHECK(total BETWEEN 1 AND 536870912),
 received INTEGER NOT NULL DEFAULT 0 CHECK(received>=0 AND received<=total),
 expires_at INTEGER NOT NULL CHECK(expires_at>=0)
);
CREATE INDEX attachment_partial_expiry ON attachment_partial(expires_at,token);
CREATE TABLE attachment_partial_chunk (
 token BLOB NOT NULL REFERENCES attachment_partial(token) ON DELETE CASCADE,
 offset INTEGER NOT NULL CHECK(offset>=0),
 bytes BLOB NOT NULL CHECK(typeof(bytes)='blob' AND length(bytes) BETWEEN 1 AND 1048576),
 digest BLOB NOT NULL CHECK(length(digest)=32),
 PRIMARY KEY(token,offset)
);
CREATE TABLE attachment_partial_usage (
 id INTEGER PRIMARY KEY CHECK(id=1),
 byte_count INTEGER NOT NULL DEFAULT 0 CHECK(byte_count>=0),
 reserved_bytes INTEGER NOT NULL DEFAULT 0 CHECK(reserved_bytes>=0)
);
INSERT INTO attachment_partial_usage(id) VALUES(1);
CREATE TRIGGER attachment_partial_reserved_added AFTER INSERT ON attachment_partial BEGIN
 UPDATE attachment_partial_usage SET reserved_bytes=reserved_bytes+NEW.total WHERE id=1;
END;
CREATE TRIGGER attachment_partial_reserved_removed AFTER DELETE ON attachment_partial BEGIN
 UPDATE attachment_partial_usage SET reserved_bytes=reserved_bytes-OLD.total WHERE id=1;
END;
CREATE TRIGGER attachment_partial_reserved_updated AFTER UPDATE OF total ON attachment_partial BEGIN
 UPDATE attachment_partial_usage SET reserved_bytes=reserved_bytes-OLD.total+NEW.total WHERE id=1;
END;
CREATE TRIGGER attachment_partial_bytes_added AFTER INSERT ON attachment_partial_chunk BEGIN
 UPDATE attachment_partial_usage SET byte_count=byte_count+length(NEW.bytes) WHERE id=1;
END;
CREATE TRIGGER attachment_partial_bytes_removed AFTER DELETE ON attachment_partial_chunk BEGIN
 UPDATE attachment_partial_usage SET byte_count=byte_count-length(OLD.bytes) WHERE id=1;
END;
CREATE TRIGGER attachment_partial_bytes_updated AFTER UPDATE OF bytes ON attachment_partial_chunk BEGIN
 UPDATE attachment_partial_usage SET byte_count=byte_count-length(OLD.bytes)+length(NEW.bytes) WHERE id=1;
END;
CREATE TRIGGER attachment_partial_terminal AFTER UPDATE OF state ON attachment_acquisition
WHEN NEW.state IN (3,4,5) BEGIN
 DELETE FROM attachment_partial WHERE token=NEW.token;
END;
"#).storage()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::{MIGRATIONS, run};
    #[test]
    fn attachment_partial_migration_is_atomic_and_starts_empty() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..84]).unwrap();
        let tx = conn.transaction().unwrap();
        apply(&tx).unwrap();
        tx.rollback().unwrap();
        assert!(
            !conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='attachment_partial')",
                    [],
                    |r| r.get::<_, bool>(0)
                )
                .unwrap()
        );
        run(&mut conn, MIGRATIONS).unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM attachment_partial", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row("SELECT byte_count FROM attachment_partial_usage", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
