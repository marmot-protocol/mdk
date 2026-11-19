//! Migration 0216: gate the Welcome payloads that name their KeyPackage's
//! transport event (stored-message tags 14 and 15).
//!
//! The body changes no table. The schema ledger is the compatibility gate: a
//! pre-0216 reader cannot decode tags 14 and 15, so the runner refuses this
//! database to it before exposing application tables, and a downgrade after a
//! staged invite cannot fail mid-confirmation on a row it cannot read.
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
    fn schema_216_blocks_old_readers() {
        let mut connection = Connection::open_in_memory().unwrap();
        run_through(&mut connection, 216).unwrap();
        let before = connection.total_changes();
        assert!(matches!(
            run_through(&mut connection, 215),
            Err(StorageError::UnsupportedSchemaVersion {
                found: 216,
                latest_supported: 215
            })
        ));
        assert_eq!(connection.total_changes(), before);
    }
}
