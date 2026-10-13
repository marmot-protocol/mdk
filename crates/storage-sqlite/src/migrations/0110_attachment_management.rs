//! Partial per-chat work indexes for bounded local health reads.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("ALTER TABLE attachment_acquisition ADD COLUMN management_ready INTEGER NOT NULL DEFAULT 0 CHECK(management_ready IN(0,1));
        UPDATE attachment_acquisition SET management_ready=(state=3 AND EXISTS(SELECT 1 FROM retained_attachment_bytes b WHERE b.token=attachment_acquisition.token));
        CREATE INDEX attachment_management_group_work ON attachment_acquisition(group_id_hex) WHERE management_ready=0;
        CREATE INDEX attachment_management_group_notices ON account_recovery_obligations(group_id,parked_at_ms,id) WHERE state=0 AND eligibility=4;
        CREATE TRIGGER attachment_management_state_changed AFTER UPDATE OF state ON attachment_acquisition WHEN OLD.state<>NEW.state BEGIN
            UPDATE attachment_acquisition SET management_ready=(NEW.state=3 AND EXISTS(SELECT 1 FROM retained_attachment_bytes b WHERE b.token=NEW.token)) WHERE token=NEW.token;
        END;
        CREATE TRIGGER attachment_management_bytes_added AFTER INSERT ON retained_attachment_bytes BEGIN
            UPDATE attachment_acquisition SET management_ready=(state=3) WHERE token=NEW.token;
        END;
        CREATE TRIGGER attachment_management_bytes_removed AFTER DELETE ON retained_attachment_bytes BEGIN
            UPDATE attachment_acquisition SET management_ready=0 WHERE token=OLD.token;
        END;
        CREATE TRIGGER attachment_management_inserted AFTER INSERT ON attachment_acquisition BEGIN
            UPDATE attachment_acquisition SET management_ready=(state=3 AND EXISTS(SELECT 1 FROM retained_attachment_bytes b WHERE b.token=NEW.token)) WHERE token=NEW.token;
        END;") .storage()
}
#[cfg(test)]
mod tests {
    #[test]
    fn populated_v109_upgrade_indexes_work_without_global_intent_state() {
        let mut c = rusqlite::Connection::open_in_memory().unwrap();
        crate::migrations::run(&mut c, &crate::migrations::MIGRATIONS[..109]).unwrap();
        c.execute_batch("PRAGMA foreign_keys=OFF; INSERT INTO attachment_acquisition(token,group_id_hex,message_id_hex,attachment_index,source_message_id_hex,source_epoch,slot_json,plaintext_digest,state,attempts,due,expires_at) VALUES(randomblob(16),'aa','one',0,'one',0,'[]',randomblob(32),0,0,0,NULL);").unwrap();
        assert_eq!(crate::migrations::run_all(&mut c).unwrap(), 1);
        assert_eq!(crate::migrations::run_all(&mut c).unwrap(), 0);
        let ready = || {
            c.query_row(
                "SELECT management_ready FROM attachment_acquisition",
                [],
                |r| r.get::<_, bool>(0),
            )
            .unwrap()
        };
        assert!(!ready());
        c.execute_batch("UPDATE attachment_acquisition SET state=3,due=NULL; INSERT INTO retained_attachment_bytes(token,bytes) SELECT token,x'00' FROM attachment_acquisition;").unwrap();
        assert!(ready());
        c.execute_batch("DELETE FROM retained_attachment_bytes;")
            .unwrap();
        assert!(!ready());
        assert_eq!(
            c.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='attachment_management_sequence'",
                [],
                |r| r.get::<_, u32>(0)
            )
            .unwrap(),
            0
        );
    }
}
