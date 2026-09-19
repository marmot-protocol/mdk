use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(r#"
CREATE INDEX attachment_acquisition_active ON attachment_acquisition(state,token) WHERE state=1;
CREATE TABLE attachment_worker_demand (
    group_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL,
    attachment_index INTEGER NOT NULL,
    generation BLOB NOT NULL CHECK(length(generation)=16),
    PRIMARY KEY(group_id_hex,message_id_hex,attachment_index),
    FOREIGN KEY(group_id_hex,message_id_hex,attachment_index)
        REFERENCES attachment_history(group_id_hex,message_id_hex,attachment_index) ON DELETE CASCADE,
    FOREIGN KEY(group_id_hex,message_id_hex) REFERENCES app_events(group_id_hex,message_id_hex) ON DELETE CASCADE
);
CREATE VIEW attachment_worker_eligible AS
    SELECT h.group_id_hex,h.message_id_hex,h.attachment_index FROM attachment_history h
    JOIN account_groups g USING(group_id_hex)
    JOIN app_events a USING(group_id_hex,message_id_hex)
    WHERE h.visible=1 AND h.source_epoch>=0 AND g.pending_confirmation=0;
INSERT INTO attachment_worker_demand
    SELECT *,randomblob(16) FROM attachment_worker_eligible;
CREATE TRIGGER attachment_worker_store_reset AFTER UPDATE OF store_epoch ON chat_presentation_meta
WHEN OLD.store_epoch IS NOT NEW.store_epoch BEGIN
    DELETE FROM attachment_worker_demand;
    INSERT INTO attachment_worker_demand SELECT *,randomblob(16) FROM attachment_worker_eligible;
END;
"#).storage()?;
    // Rebuilt sources rediscover demand. Explicit removal lives in a separate,
    // source-owned table and still wins when the runtime admits that demand.
    for event in ["INSERT", "UPDATE"] {
        let accepted = if event == "INSERT" {
            "NEW.pending_confirmation=0"
        } else {
            "NEW.pending_confirmation=0 AND OLD.pending_confirmation<>0"
        };
        tx.execute_batch(&format!(
            r#"
CREATE TRIGGER attachment_worker_source_{event} AFTER {event} ON attachment_history BEGIN
    INSERT INTO attachment_worker_demand
        SELECT *,randomblob(16) FROM attachment_worker_eligible
        WHERE group_id_hex=NEW.group_id_hex AND message_id_hex=NEW.message_id_hex
          AND attachment_index=NEW.attachment_index
        ON CONFLICT(group_id_hex,message_id_hex,attachment_index)
        DO UPDATE SET generation=excluded.generation;
END;
CREATE TRIGGER attachment_worker_accept_{event} AFTER {event} ON account_groups
WHEN {accepted} BEGIN
    INSERT INTO attachment_worker_demand
        SELECT *,randomblob(16) FROM attachment_worker_eligible
        WHERE group_id_hex=NEW.group_id_hex
        ON CONFLICT(group_id_hex,message_id_hex,attachment_index)
        DO UPDATE SET generation=excluded.generation;
END;
"#
        ))
        .storage()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::{MIGRATIONS, run};
    use rusqlite::Connection;

    #[test]
    fn attachment_worker_upgrade_backfills_only_accepted_retained_sources_atomically() {
        let mut conn = Connection::open_in_memory().unwrap();
        run(&mut conn, &MIGRATIONS[..83]).unwrap();
        for (group, pending) in [("aa", 0), ("bb", 1)] {
            conn.execute(
                "INSERT INTO account_groups(group_id_hex,endpoint,updated_at,pending_confirmation)
                VALUES(?1,'',0,?2)",
                rusqlite::params![group, pending],
            )
            .unwrap();
            conn.execute("INSERT INTO app_events(group_id_hex,message_id_hex,source_message_id_hex,source_epoch,
                direction,sender,plaintext,kind,tags_json,recorded_at,received_at)
                VALUES(?1,?1,?1,3,'received','author','',9,'[]',1,1)", [group]).unwrap();
            conn.execute("INSERT INTO message_timeline(group_id_hex,message_id_hex,source_message_id_hex,source_epoch,
                direction,sender,plaintext,kind,tags_json,timeline_at,received_at,reactions_json,media_json)
                VALUES(?1,?1,?1,3,'received','author','',9,'[]',1,1,'[]','{\"imeta\":[[\"imeta\"]]}')", [group]).unwrap();
        }
        let tx = conn.transaction().unwrap();
        apply(&tx).unwrap();
        assert_eq!(
            tx.query_row("SELECT count(*) FROM attachment_worker_demand", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            1
        );
        tx.rollback().unwrap();
        assert!(!conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='attachment_worker_demand')", [], |r| r.get::<_,bool>(0)).unwrap());
        run(&mut conn, MIGRATIONS).unwrap();
        run(&mut conn, MIGRATIONS).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT group_id_hex FROM attachment_worker_demand",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "aa"
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM attachment_acquisition", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
