//! Migration 0109: durable "not enough free disk to publish" outcome for
//! attachment acquisition. It follows 0108's account attachment history,
//! which touches no acquisition table or trigger.
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

use crate::SqliteResultExt;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Free bytes beyond the policy disk reserve that a parked transfer needs
    // before it is readmitted: the publication reserve of the check that parked
    // it plus the staging and checkpoint bytes that attempt will occupy again.
    // NULL means the job is not parked for disk space; existing jobs never
    // start parked. The partial index serves the per-tick readmission probe.
    //
    // A storage-parked job keeps its ciphertext checkpoint: the blocked state
    // is the same terminal-looking row as a failure, but the next admitted
    // attempt is meant to resume (ideally without any request), so the
    // terminal cleanup trigger must not discard the prefix for it.
    //
    // `storage_park_count` drives the readmission delay of a job that keeps
    // parking (reset by explicit retry, checkpoint progress, completion and
    // cancellation).
    //
    // The trigger is recreated from its 0105 form with one added clause:
    // storage-parked rows keep their checkpoint.
    tx.execute_batch(
        "ALTER TABLE attachment_acquisition ADD COLUMN storage_blocked_headroom INTEGER
             CHECK(storage_blocked_headroom IS NULL OR storage_blocked_headroom>=0);
        ALTER TABLE attachment_acquisition ADD COLUMN storage_park_count INTEGER NOT NULL DEFAULT 0
             CHECK(storage_park_count>=0);
        CREATE INDEX attachment_acquisition_storage_parked
            ON attachment_acquisition(priority_at DESC,token)
            WHERE state=4 AND storage_blocked_headroom IS NOT NULL;
        DROP TRIGGER attachment_partial_terminal;
        CREATE TRIGGER attachment_partial_terminal AFTER UPDATE OF state ON attachment_acquisition
        WHEN NEW.state=3 OR (NEW.state=5 AND NEW.permission_paused=0)
            OR (NEW.state=4 AND NEW.cancelled=0 AND NEW.storage_blocked_headroom IS NULL) BEGIN
            DELETE FROM attachment_partial WHERE token=NEW.token;
        END;",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::{MIGRATIONS, run};

    fn partials(conn: &rusqlite::Connection) -> i64 {
        conn.query_row("SELECT count(*) FROM attachment_partial", [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn storage_block_migration_preserves_jobs_and_is_transactional() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        // Everything before this migration, through 0108's attachment history.
        run(&mut conn, &MIGRATIONS[..108]).unwrap();
        assert_eq!(MIGRATIONS[107].version, 108);
        assert_eq!(MIGRATIONS[108].version, 109);
        assert_eq!(MIGRATIONS[108].name, "0109_attachment_storage_block");
        let trigger = |conn: &rusqlite::Connection| -> String {
            conn.query_row(
                "SELECT sql FROM sqlite_master WHERE name='attachment_partial_terminal'",
                [],
                |r| r.get(0),
            )
            .unwrap()
        };
        let before = trigger(&conn);
        assert!(
            before.contains("OR (NEW.state=4 AND NEW.cancelled=0) BEGIN"),
            "the trigger this migration replaces is still 0105's: {before}"
        );
        conn.execute_batch("PRAGMA foreign_keys=OFF;
            INSERT INTO attachment_acquisition(token,group_id_hex,message_id_hex,attachment_index,source_message_id_hex,source_epoch,slot_json,plaintext_digest,state,attempts,due)
            VALUES(x'01010101010101010101010101010101','g','m',0,'s',1,'[\"imeta\"]',randomblob(32),2,7,1234);
            INSERT INTO attachment_partial(token,ciphertext_digest,locator_digest,etag,total,received,expires_at)
            VALUES(x'01010101010101010101010101010101',randomblob(32),randomblob(32),'\"v1\"',10,3,99999);").unwrap();
        let tx = conn.transaction().unwrap();
        apply(&tx).unwrap();
        tx.rollback().unwrap();
        assert!(
            conn.prepare("SELECT storage_blocked_headroom FROM attachment_acquisition")
                .is_err()
        );
        assert_eq!(
            trigger(&conn),
            before,
            "a rolled-back apply keeps the old trigger"
        );
        // Through this migration only: 0112 later drops database checkpoints.
        run(&mut conn, &MIGRATIONS[..109]).unwrap();
        run(&mut conn, &MIGRATIONS[..109]).unwrap();
        let row = conn
            .query_row(
                "SELECT state,attempts,due,storage_blocked_headroom,storage_park_count FROM attachment_acquisition",
                [],
                |r| {
                    Ok((
                        r.get::<_, u8>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                        r.get::<_, i64>(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(row, (2, 7, 1234, None, 0));
        let after = trigger(&conn);
        assert!(
            after.contains(
                "OR (NEW.state=4 AND NEW.cancelled=0 AND NEW.storage_blocked_headroom IS NULL) BEGIN"
            ),
            "{after}"
        );
        assert!(
            conn.execute(
                "UPDATE attachment_acquisition SET storage_blocked_headroom=-1",
                []
            )
            .is_err(),
            "negative headroom targets are rejected"
        );
        // The per-tick readmission probe is served by the partial index.
        let plan: String = conn
            .query_row(
                "EXPLAIN QUERY PLAN SELECT token FROM attachment_acquisition
                 WHERE state=4 AND storage_blocked_headroom IS NOT NULL ORDER BY priority_at DESC,token",
                [],
                |r| r.get(3),
            )
            .unwrap();
        assert!(
            plan.contains("attachment_acquisition_storage_parked"),
            "{plan}"
        );
        // Parking for disk space keeps the checkpoint; any other blocked
        // transition still discards it, as before this migration.
        assert_eq!(partials(&conn), 1);
        conn.execute(
            "UPDATE attachment_acquisition SET state=4,due=NULL,storage_blocked_headroom=4096",
            [],
        )
        .unwrap();
        assert_eq!(
            partials(&conn),
            1,
            "a storage-parked job resumes its prefix"
        );
        conn.execute(
            "UPDATE attachment_acquisition SET state=0,due=1,storage_blocked_headroom=NULL",
            [],
        )
        .unwrap();
        assert_eq!(partials(&conn), 1, "readmission keeps the prefix");
        conn.execute("UPDATE attachment_acquisition SET state=4,due=NULL", [])
            .unwrap();
        assert_eq!(partials(&conn), 0, "an ordinary block still cleans up");
    }
}
