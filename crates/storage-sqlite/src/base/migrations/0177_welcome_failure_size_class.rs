//! Best-effort coarse diagnosis on the existing Welcome repair pointer.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch("ALTER TABLE app_pending_welcome_delivery ADD COLUMN size_class TEXT")
        .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;

    #[test]
    fn existing_repair_pointer_survives_with_unknown_diagnosis() {
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        run_through(&mut connection, 176).unwrap();
        connection.execute("INSERT INTO app_pending_welcome_delivery (message_id_hex, group_id_hex, recipient_hex, recorded_at) VALUES ('welcome', 'chat', 'recipient', 7)", []).unwrap();
        run_through(&mut connection, 177).unwrap();
        let row = connection.query_row("SELECT message_id_hex, group_id_hex, recipient_hex, recorded_at, size_class FROM app_pending_welcome_delivery", [], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)?, row.get::<_, Option<String>>(4)?))).unwrap();
        assert_eq!(
            row,
            ("welcome".into(), "chat".into(), "recipient".into(), 7, None)
        );
    }
}
