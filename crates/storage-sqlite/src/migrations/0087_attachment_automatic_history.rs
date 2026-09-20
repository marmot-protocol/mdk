use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

use crate::SqliteResultExt;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(r#"
ALTER TABLE attachment_acquisition ADD COLUMN acquisition_attempts INTEGER NOT NULL DEFAULT 0 CHECK(acquisition_attempts>=0);
ALTER TABLE attachment_acquisition ADD COLUMN network_attempts INTEGER NOT NULL DEFAULT 0 CHECK(network_attempts>=0);
ALTER TABLE attachment_acquisition ADD COLUMN body_completed INTEGER NOT NULL DEFAULT 0 CHECK(body_completed IN (0,1));
-- Old claim/backoff counters do not measure the new budgets. Existing jobs
-- keep native retry semantics; only the host-managed request API opts in.
ALTER TABLE attachment_acquisition ADD COLUMN automatic_history INTEGER NOT NULL DEFAULT 0 CHECK(automatic_history IN (0,1));
ALTER TABLE attachment_acquisition ADD COLUMN permission_paused INTEGER NOT NULL DEFAULT 0 CHECK(permission_paused IN (0,1));
ALTER TABLE attachment_acquisition ADD COLUMN retry_not_before INTEGER NOT NULL DEFAULT 0 CHECK(retry_not_before>=0);
ALTER TABLE attachment_acquisition ADD COLUMN permission_category INTEGER NOT NULL DEFAULT 3 CHECK(permission_category BETWEEN 0 AND 3);
UPDATE attachment_acquisition SET permission_category=(SELECT CASE lower(trim(CASE WHEN instr(mime,'/')>0 THEN substr(mime,1,instr(mime,'/')-1) ELSE mime END)) WHEN 'image' THEN 0 WHEN 'video' THEN 1 WHEN 'audio' THEN 2 ELSE 3 END FROM (SELECT COALESCE((SELECT substr(value,3) FROM json_each(slot_json) WHERE type='text' AND substr(value,1,2)='m ' LIMIT 1),'') AS mime));
CREATE INDEX attachment_permission_paused ON attachment_acquisition(permission_category,token) WHERE permission_paused=1 AND state=5;
DROP TRIGGER attachment_partial_terminal;
CREATE TRIGGER attachment_partial_terminal AFTER UPDATE OF state ON attachment_acquisition
WHEN NEW.state=3 OR (NEW.state=5 AND NEW.permission_paused=0) OR (NEW.state=4 AND NEW.cancelled=0) BEGIN
 DELETE FROM attachment_partial WHERE token=NEW.token;
END;

"#).storage()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::{MIGRATIONS, run};

    #[test]
    fn upgrade_preserves_jobs_with_large_historical_backoff_counters() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..86]).unwrap();
        conn.execute_batch("PRAGMA foreign_keys=OFF;
            INSERT INTO attachment_acquisition(token,group_id_hex,message_id_hex,attachment_index,source_message_id_hex,source_epoch,slot_json,plaintext_digest,attempts,due)
            VALUES(randomblob(16),'g','m',0,'s',1,'[\"imeta\",\"m VIDEO/mp4\"]',randomblob(32),99,1234);").unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        let counters = conn.query_row("SELECT attempts,acquisition_attempts,network_attempts,automatic_history,state,due,permission_category FROM attachment_acquisition", [], |r| Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?,r.get::<_,bool>(3)?,r.get::<_,u8>(4)?,r.get::<_,i64>(5)?,r.get::<_,u8>(6)?))).unwrap();
        assert_eq!(counters, (99, 0, 0, false, 0, 1234, 1));
    }

    #[test]
    fn automatic_history_migration_is_transactional_and_repeatable() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..86]).unwrap();
        let tx = conn.transaction().unwrap();
        apply(&tx).unwrap();
        tx.rollback().unwrap();
        assert!(
            conn.prepare("SELECT network_attempts FROM attachment_acquisition")
                .is_err()
        );
        run(&mut conn, MIGRATIONS).unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        assert!(
            conn.prepare("SELECT acquisition_attempts,network_attempts,body_completed FROM attachment_acquisition")
                .is_ok()
        );
    }
}
