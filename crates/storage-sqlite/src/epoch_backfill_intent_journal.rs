use crate::connection::retry_on_busy;
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::StorageResult;
use rusqlite::{OptionalExtension, params};

impl SqliteAccountStorage {
    /// Load the opaque, account-wide epoch-backfill intent journal.
    ///
    /// Serialization belongs to the app layer so storage-format changes do not
    /// require this crate to understand the queued intent envelope.
    pub fn load_epoch_backfill_intent_journal(&self) -> StorageResult<Option<Vec<u8>>> {
        self.lock()?
            .query_row(
                "SELECT record FROM app_epoch_backfill_intent_journal WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .storage()
    }

    /// Atomically replace the opaque, account-wide epoch-backfill intent
    /// journal.
    pub fn store_epoch_backfill_intent_journal(&self, record: &[u8]) -> StorageResult<()> {
        self.write_epoch_backfill_intent_journal(|| {
            self.lock()?
                .execute(
                    "INSERT INTO app_epoch_backfill_intent_journal (singleton, record)
                     VALUES (1, ?1)
                     ON CONFLICT(singleton) DO UPDATE SET record = excluded.record",
                    params![record],
                )
                .storage()?;
            Ok(())
        })
    }

    /// Clear the account-wide epoch-backfill intent journal, if present.
    pub fn clear_epoch_backfill_intent_journal(&self) -> StorageResult<()> {
        self.write_epoch_backfill_intent_journal(|| {
            self.lock()?
                .execute(
                    "DELETE FROM app_epoch_backfill_intent_journal WHERE singleton = 1",
                    [],
                )
                .storage()?;
            Ok(())
        })
    }

    fn write_epoch_backfill_intent_journal<T>(
        &self,
        op: impl Fn() -> StorageResult<T>,
    ) -> StorageResult<T> {
        if self.connection.is_current_thread_transaction_owner() {
            op()
        } else {
            retry_on_busy(op)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_round_trips_overwrites_and_clears_opaque_bytes() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        assert_eq!(store.load_epoch_backfill_intent_journal().unwrap(), None);

        let first = [0_u8, 0xff, 0x80, 0x00, b'{'];
        store.store_epoch_backfill_intent_journal(&first).unwrap();
        assert_eq!(
            store.load_epoch_backfill_intent_journal().unwrap(),
            Some(first.to_vec())
        );

        let replacement = [9_u8, 8, 7];
        store
            .store_epoch_backfill_intent_journal(&replacement)
            .unwrap();
        assert_eq!(
            store.load_epoch_backfill_intent_journal().unwrap(),
            Some(replacement.to_vec()),
            "the singleton upsert must replace, not append to, the journal"
        );

        store.clear_epoch_backfill_intent_journal().unwrap();
        assert_eq!(store.load_epoch_backfill_intent_journal().unwrap(), None);
        store.clear_epoch_backfill_intent_journal().unwrap();
    }

    #[test]
    fn journal_preserves_an_explicit_empty_blob() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.store_epoch_backfill_intent_journal(&[]).unwrap();

        assert_eq!(
            store.load_epoch_backfill_intent_journal().unwrap(),
            Some(Vec::new()),
            "an empty opaque record is occupied state, not an absent journal"
        );
    }
}
