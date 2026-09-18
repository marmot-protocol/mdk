use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(r#"
ALTER TABLE attachment_acquisition ADD COLUMN cancelled INTEGER NOT NULL DEFAULT 0 CHECK(cancelled IN (0,1));
ALTER TABLE attachment_acquisition ADD COLUMN explicit_request INTEGER NOT NULL DEFAULT 0 CHECK(explicit_request IN (0,1));
ALTER TABLE attachment_acquisition ADD COLUMN size_blocked_max INTEGER;
ALTER TABLE attachment_acquisition ADD COLUMN priority_at INTEGER NOT NULL DEFAULT 0;
UPDATE attachment_acquisition AS q SET priority_at=COALESCE((SELECT h.received_at FROM attachment_history h
 WHERE h.group_id_hex=q.group_id_hex AND h.message_id_hex=q.message_id_hex AND h.attachment_index=q.attachment_index),0);
CREATE TRIGGER attachment_acquisition_priority_insert AFTER INSERT ON attachment_acquisition BEGIN
 UPDATE attachment_acquisition SET priority_at=COALESCE((SELECT received_at FROM attachment_history
 WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex AND attachment_index=NEW.attachment_index),0) WHERE token=NEW.token;
END;
CREATE TRIGGER attachment_acquisition_priority_update AFTER UPDATE OF received_at ON attachment_history BEGIN
 UPDATE attachment_acquisition SET priority_at=NEW.received_at
 WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex AND attachment_index=NEW.attachment_index;
END;
CREATE INDEX attachment_acquisition_priority ON attachment_acquisition(explicit_request DESC,priority_at DESC,due,token) WHERE due IS NOT NULL;
ALTER TABLE attachment_acquisition ADD COLUMN progress_epoch INTEGER NOT NULL DEFAULT 0 CHECK(progress_epoch>=0);
ALTER TABLE attachment_acquisition ADD COLUMN progress_received INTEGER NOT NULL DEFAULT 0 CHECK(progress_received>=0);
ALTER TABLE attachment_acquisition ADD COLUMN progress_total INTEGER CHECK(progress_total>=progress_received);
ALTER TABLE attachment_acquisition ADD COLUMN progress_phase INTEGER NOT NULL DEFAULT 0 CHECK(progress_phase BETWEEN 0 AND 4);
DROP TRIGGER attachment_partial_terminal;
CREATE TRIGGER attachment_partial_terminal AFTER UPDATE OF state ON attachment_acquisition
WHEN NEW.state IN (3,5) OR (NEW.state=4 AND NEW.cancelled=0) BEGIN
 DELETE FROM attachment_partial WHERE token=NEW.token;
END;
CREATE TABLE attachment_download_policy (
 id INTEGER PRIMARY KEY CHECK(id=1),
 automatic INTEGER NOT NULL CHECK(automatic IN (0,1)),
 retained_bytes INTEGER NOT NULL CHECK(retained_bytes>0),
 disk_reserve INTEGER NOT NULL CHECK(disk_reserve>=0),
 transfer_limit INTEGER NOT NULL CHECK(transfer_limit BETWEEN 1 AND 536870912)
);
CREATE INDEX attachment_history_recent_demand ON attachment_history(received_at DESC,group_id_hex,message_id_hex,attachment_index);
"#).storage()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::{MIGRATIONS, run};
    #[test]
    fn attachment_controls_migration_rolls_back_and_installs_cleanly() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..85]).unwrap();
        let old_trigger: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name='attachment_partial_terminal'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let tx = conn.transaction().unwrap();
        apply(&tx).unwrap();
        tx.rollback().unwrap();
        let rolled_back: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name='attachment_partial_terminal'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(old_trigger, rolled_back);
        assert!(
            conn.prepare("SELECT cancelled FROM attachment_acquisition")
                .is_err()
        );
        run(&mut conn, MIGRATIONS).unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM attachment_download_policy", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
        assert!(conn.prepare("SELECT cancelled,explicit_request,progress_epoch,progress_received,progress_total,progress_phase FROM attachment_acquisition").is_ok());
    }
}
