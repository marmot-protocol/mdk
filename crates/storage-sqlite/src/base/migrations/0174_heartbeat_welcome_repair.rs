//! D100 retires D90/D91 observation work. Keep lifetime wrapper markers and
//! known carrier times; nullable legacy columns stay inert to avoid rebuilding
//! the protocol ledger solely to erase unused data.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "DROP INDEX IF EXISTS idx_processed_transport_content;
         DROP INDEX IF EXISTS idx_processed_transport_activity;
         DROP INDEX IF EXISTS idx_processed_transport_source_identity;
         DROP INDEX IF EXISTS idx_processed_transport_pending_source;
         DROP INDEX IF EXISTS idx_processed_transport_source_slot;
         DROP INDEX IF EXISTS idx_processed_transport_source_application;
         DROP INDEX IF EXISTS idx_processed_transport_unavailable_source;
         DROP INDEX IF EXISTS idx_processed_transport_qualified_principal;
         DROP INDEX IF EXISTS idx_sibling_welcome_resend_activity;
         DROP INDEX IF EXISTS idx_sibling_welcome_resend_due;
         DROP TABLE IF EXISTS local_observation_clock;",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::{Connection, params};

    /// The cleanup is an upgrade of a populated old database: permanent
    /// wrapper ownership and known publication/high-water survive, while no
    /// obsolete observation index or ordering clock remains to maintain.
    #[test]
    fn cleanup_keeps_wrapper_markers_and_retained_carrier_times() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 171).unwrap();
        conn.execute(
            "INSERT INTO cgka_groups(id,epoch,record) VALUES(?1,0,x'00')",
            [b"chat"],
        )
        .unwrap();
        conn.execute("INSERT INTO cgka_processed_transport_ids(id,group_id,content_id,source_proof) VALUES(?1,?2,?3,?4)", params![b"wrapper", b"chat", b"content", b"old-proof"]).unwrap();
        conn.execute("INSERT INTO sibling_welcome_resends(welcome_id,chat_id,device_group_id,target_slot,carrier,prepared_carrier,last_carrier_created_at,published_at_ms,publication_order,activity_at_ms,due_at_ms) VALUES(?1,?2,?3,?4,?5,?6,7,1001,8,9,10)", params![b"welcome",b"chat",b"dg",[3u8;32],b"published",b"reserved"]).unwrap();
        run_through(&mut conn, 174).unwrap();
        let marker: (Vec<u8>,Vec<u8>,Vec<u8>) = conn.query_row("SELECT group_id,content_id,source_proof FROM cgka_processed_transport_ids WHERE id=?1",[b"wrapper"],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
        assert_eq!(
            marker,
            (b"chat".to_vec(), b"content".to_vec(), b"old-proof".to_vec())
        );
        let retained: (Vec<u8>,Vec<u8>,i64,i64) = conn.query_row("SELECT carrier,prepared_carrier,last_carrier_created_at,published_at_ms FROM sibling_welcome_resends WHERE welcome_id=?1",[b"welcome"],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).unwrap();
        assert_eq!(
            retained,
            (b"published".to_vec(), b"reserved".to_vec(), 7, 1001)
        );
        let obsolete: i64 = conn.query_row("SELECT count(*) FROM sqlite_master WHERE name='local_observation_clock' OR name LIKE 'idx_processed_transport_%' OR name IN ('idx_sibling_welcome_resend_activity','idx_sibling_welcome_resend_due')",[],|row|row.get(0)).unwrap();
        assert_eq!(obsolete, 0);
    }
}
