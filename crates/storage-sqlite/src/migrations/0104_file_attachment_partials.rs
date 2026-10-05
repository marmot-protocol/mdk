//! Preserve bounded ciphertext checkpoints while widening only file transfers.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
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
        WHEN NEW.state IN (3,4,5) BEGIN
            DELETE FROM attachment_partial WHERE token=NEW.token;
        END;",
    ).storage()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn populated_partial_upgrade_preserves_chunks_quota_cascades_and_rollback() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys=ON;
            CREATE TABLE attachment_acquisition(token BLOB PRIMARY KEY,state INTEGER);
            INSERT INTO attachment_acquisition VALUES(x'01',1);",
        )
        .unwrap();
        let tx = conn.transaction().unwrap();
        crate::migrations::migration_0085_attachment_partials::apply(&tx).unwrap();
        tx.execute("INSERT INTO attachment_partial(token,ciphertext_digest,locator_digest,etag,total,received,expires_at) VALUES(x'01',zeroblob(32),zeroblob(32),'\"v1\"',10,3,100)",[]).unwrap();
        tx.execute(
            "INSERT INTO attachment_partial_chunk VALUES(x'01',0,x'010203',zeroblob(32))",
            [],
        )
        .unwrap();
        tx.commit().unwrap();
        let check = |conn: &rusqlite::Connection| {
            assert_eq!(
                conn.query_row("SELECT bytes FROM attachment_partial_chunk", [], |r| r
                    .get::<_, Vec<u8>>(0))
                    .unwrap(),
                vec![1, 2, 3]
            );
            assert_eq!(
                conn.query_row(
                    "SELECT reserved_bytes FROM attachment_partial_usage",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                10
            );
            assert_eq!(
                conn.query_row("SELECT received FROM attachment_partial", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                3
            );
            assert_eq!(
                conn.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| r
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
                0
            );
        };
        let tx = conn.transaction().unwrap();
        apply(&tx).unwrap();
        tx.rollback().unwrap();
        check(&conn);
        let tx = conn.transaction().unwrap();
        apply(&tx).unwrap();
        tx.commit().unwrap();
        check(&conn);
        // Widening the representation must preserve both terminal and source deletion cleanup.
        conn.execute("UPDATE attachment_acquisition SET state=3", [])
            .unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM attachment_partial_chunk", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row(
                "SELECT reserved_bytes FROM attachment_partial_usage",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        conn.execute("INSERT INTO attachment_partial(token,ciphertext_digest,locator_digest,etag,total,expires_at) VALUES(x'01',zeroblob(32),zeroblob(32),'\"v2\"',758000016,100)",[]).unwrap();
        conn.execute("DELETE FROM attachment_acquisition", [])
            .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT reserved_bytes FROM attachment_partial_usage",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }
}
