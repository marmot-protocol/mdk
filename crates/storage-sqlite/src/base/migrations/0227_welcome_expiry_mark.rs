//! Migration 0227: gate the Welcome payloads that carry an expiry mark
//! (stored-message tags 16 and 17, mdk#3589).
//!
//! The body changes no table. The schema ledger is the compatibility gate: a
//! pre-0227 reader cannot decode tags 16 and 17, so it would read a Welcome
//! marked expired as withdrawn and lose what its last attempt found. The
//! runner refuses this database to it before exposing application tables.
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
    fn schema_227_blocks_old_readers() {
        let mut connection = Connection::open_in_memory().unwrap();
        run_through(&mut connection, 227).unwrap();
        let before = connection.total_changes();
        assert!(matches!(
            run_through(&mut connection, 226),
            Err(StorageError::UnsupportedSchemaVersion {
                found: 227,
                latest_supported: 226
            })
        ));
        assert_eq!(connection.total_changes(), before);
    }
}
