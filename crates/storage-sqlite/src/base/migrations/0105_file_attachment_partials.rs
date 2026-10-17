//! Preserve bounded ciphertext checkpoints while widening only file transfers.
use crate::SqliteResultExt;
use cgka_traits::StorageError;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// The registry suspends enforcement before this parent rebuild and checks both parent and chunk references.
pub(crate) const SUSPEND_FOREIGN_KEYS: &[&str] =
    &["attachment_partial", "attachment_partial_chunk"];

/// Rebuild only small parent records; the defensive precondition also protects direct calls outside the runner.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    if tx
        .pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))
        .storage()?
    {
        return Err(StorageError::Backend(
            "partial metadata rebuild requires migration-runner foreign-key scope".into(),
        ));
    }
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
        DROP TABLE attachment_partial;
        ALTER TABLE attachment_partial_next RENAME TO attachment_partial;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn populated_partial_upgrade_preserves_chunks_quota_cascades_and_rollback() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys=ON;
            CREATE TABLE attachment_acquisition(token BLOB PRIMARY KEY,state INTEGER,
                cancelled INTEGER NOT NULL DEFAULT 0, permission_paused INTEGER NOT NULL DEFAULT 0);
            INSERT INTO attachment_acquisition(token,state) VALUES(x'01',1);",
        )
        .unwrap();
        conn.pragma_update(None, "foreign_keys", false).unwrap();
        let tx = conn.transaction().unwrap();
        crate::base::migrations::migration_0085_attachment_partials::apply(&tx).unwrap();
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
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        check(&conn);
        // Cancellation and revoked automatic permission preserve resumability.
        conn.execute("UPDATE attachment_acquisition SET state=4,cancelled=1", [])
            .unwrap();
        check(&conn);
        conn.execute(
            "UPDATE attachment_acquisition SET state=5,cancelled=0,permission_paused=1",
            [],
        )
        .unwrap();
        check(&conn);
        // Widening the representation must preserve both terminal and source deletion cleanup.
        conn.execute(
            "UPDATE attachment_acquisition SET state=3,permission_paused=0",
            [],
        )
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
