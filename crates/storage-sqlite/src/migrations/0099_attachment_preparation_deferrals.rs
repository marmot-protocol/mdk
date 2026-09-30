//! Bounded local-readiness deferral for attachment acquisition.
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

use crate::SqliteResultExt;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Consecutive preparation deferrals (for example, source-epoch media key
    // material that is not available locally). Existing jobs start at zero, so
    // a job that was deferring before this migration gets one bounded window.
    tx.execute_batch(
        "ALTER TABLE attachment_acquisition ADD COLUMN preparation_deferrals INTEGER NOT NULL
             DEFAULT 0 CHECK(preparation_deferrals>=0);",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::{MIGRATIONS, run};

    #[test]
    fn preparation_deferral_migration_preserves_jobs_and_is_transactional() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..98]).unwrap();
        conn.execute_batch("PRAGMA foreign_keys=OFF;
            INSERT INTO attachment_acquisition(token,group_id_hex,message_id_hex,attachment_index,source_message_id_hex,source_epoch,slot_json,plaintext_digest,state,attempts,due)
            VALUES(randomblob(16),'g','m',0,'s',1,'[\"imeta\"]',randomblob(32),2,7,1234);").unwrap();
        let tx = conn.transaction().unwrap();
        apply(&tx).unwrap();
        tx.rollback().unwrap();
        assert!(
            conn.prepare("SELECT preparation_deferrals FROM attachment_acquisition")
                .is_err()
        );
        run(&mut conn, MIGRATIONS).unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        let row = conn
            .query_row(
                "SELECT state,attempts,due,preparation_deferrals FROM attachment_acquisition",
                [],
                |r| {
                    Ok((
                        r.get::<_, u8>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(row, (2, 7, 1234, 0));
    }
}
