//! Migration 0110: last-use time for least-recently-used eviction of retained
//! attachment bodies. It follows 0109's storage-block columns.
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

use crate::SqliteResultExt;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Unix seconds of the body's publication or latest local read. Existing
    // rows start at 0, so bodies retained before this migration are evicted
    // first, oldest admitted (lowest rowid) first. The partial index serves the
    // oldest-first victim scan; its implicit rowid breaks ties in that order.
    tx.execute_batch(
        "ALTER TABLE attachment_acquisition ADD COLUMN retained_used_at INTEGER NOT NULL DEFAULT 0
             CHECK(retained_used_at>=0);
        CREATE INDEX attachment_acquisition_retained_lru
            ON attachment_acquisition(retained_used_at) WHERE state=3;",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::{MIGRATIONS, run};

    #[test]
    fn retained_lru_migration_preserves_jobs_and_indexes_ready_rows() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..109]).unwrap();
        assert_eq!(MIGRATIONS[108].version, 109);
        assert_eq!(MIGRATIONS[109].version, 110);
        assert_eq!(MIGRATIONS[109].name, "0110_attachment_retained_lru");
        conn.execute_batch("PRAGMA foreign_keys=OFF;
            INSERT INTO attachment_acquisition(token,group_id_hex,message_id_hex,attachment_index,source_message_id_hex,source_epoch,slot_json,plaintext_digest,state,attempts,due)
            VALUES(x'01010101010101010101010101010101','g','m',0,'s',1,'[\"imeta\"]',randomblob(32),3,1,NULL);").unwrap();
        let tx = conn.transaction().unwrap();
        apply(&tx).unwrap();
        tx.rollback().unwrap();
        assert!(
            conn.prepare("SELECT retained_used_at FROM attachment_acquisition")
                .is_err(),
            "a rolled-back apply leaves no column"
        );
        run(&mut conn, MIGRATIONS).unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        let row = conn
            .query_row(
                "SELECT state,attempts,retained_used_at FROM attachment_acquisition",
                [],
                |r| Ok((r.get::<_, u8>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
            )
            .unwrap();
        assert_eq!(row, (3, 1, 0), "existing bodies become the oldest");
        assert!(
            conn.execute("UPDATE attachment_acquisition SET retained_used_at=-1", [])
                .is_err(),
            "negative use times are rejected"
        );
        let plan: String = conn
            .query_row(
                "EXPLAIN QUERY PLAN SELECT token FROM attachment_acquisition
                 WHERE state=3 AND retained_used_at<=?1 ORDER BY retained_used_at,rowid",
                [0],
                |r| r.get(3),
            )
            .unwrap();
        assert!(
            plan.contains("attachment_acquisition_retained_lru"),
            "{plan}"
        );
    }
}
