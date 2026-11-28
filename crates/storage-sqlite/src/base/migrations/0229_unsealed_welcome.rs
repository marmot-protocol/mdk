//! Migration 0229: gate the unsealed-Welcome payload (stored-message tag 17,
//! mdk#3498).
//!
//! The body changes no table. The schema ledger is the compatibility gate: a
//! pre-0229 reader cannot decode tag 17, so a founding Welcome a create left
//! unsealed would never be delivered, and a recovery commit whose Welcomes
//! are unsealed could not resume. The runner refuses this database to it
//! before exposing application tables.
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(_tx: &Transaction<'_>) -> StorageResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use cgka_traits::storage::StorageError;
    use rusqlite::Connection;

    #[test]
    fn schema_229_blocks_old_readers() {
        let mut connection = Connection::open_in_memory().unwrap();
        run_through(&mut connection, 229).unwrap();
        let before = connection.total_changes();
        assert!(matches!(
            run_through(&mut connection, 228),
            Err(StorageError::UnsupportedSchemaVersion {
                found: 229,
                latest_supported: 228
            })
        ));
        assert_eq!(connection.total_changes(), before);
    }
}
