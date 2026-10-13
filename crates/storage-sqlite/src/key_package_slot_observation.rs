//! Account-private handoff independent of the publication lifecycle journal.
use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, serialize};
use cgka_traits::{
    MessageId, Timestamp, maintenance::publication_event_wins, storage::StorageResult,
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPackageSlotObservation {
    pub slot_id: String,
    pub event_id: MessageId,
    pub created_at: Timestamp,
}

impl SqliteAccountStorage {
    pub fn key_package_slot_observation(&self) -> StorageResult<Option<KeyPackageSlotObservation>> {
        self.lock()?
            .query_row(
                "SELECT record FROM key_package_slot_observation WHERE singleton = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .storage()?
            .map(|bytes| deserialize(&bytes))
            .transpose()
    }

    /// Coalesce in one transaction so concurrent directory writers cannot lose a winner.
    pub fn remember_key_package_slot_observation(
        &self,
        observed: &KeyPackageSlotObservation,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            if self
                .key_package_slot_observation()?
                .is_some_and(|previous| {
                    previous.slot_id == observed.slot_id
                        && !publication_event_wins(
                            observed.created_at,
                            observed.event_id.as_slice(),
                            previous.created_at,
                            previous.event_id.as_slice(),
                        )
                })
            {
                return Ok(());
            }
            self.lock()?
                .execute(
                    "INSERT INTO key_package_slot_observation(singleton, record) VALUES (1, ?1)
                 ON CONFLICT(singleton) DO UPDATE SET record = excluded.record",
                    params![serialize(observed)?],
                )
                .storage()?;
            Ok(())
        })
    }

    /// Clear only the adopted version; a concurrent newer observation must survive.
    pub fn clear_key_package_slot_observation(
        &self,
        observed: &KeyPackageSlotObservation,
    ) -> StorageResult<()> {
        self.lock()?
            .execute(
                "DELETE FROM key_package_slot_observation WHERE singleton = 1 AND record = ?1",
                params![serialize(observed)?],
            )
            .storage()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_observation_coalesces_and_compare_clear_preserves_newer_winner() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let observed = |time, id| KeyPackageSlotObservation {
            slot_id: "slot".into(),
            event_id: MessageId::new(vec![id; 32]),
            created_at: Timestamp(time),
        };
        let first = observed(10, 8);
        store.remember_key_package_slot_observation(&first).unwrap();
        let winner = observed(10, 1);
        store
            .remember_key_package_slot_observation(&winner)
            .unwrap();
        store
            .remember_key_package_slot_observation(&observed(9, 0))
            .unwrap();
        store.remember_key_package_slot_observation(&first).unwrap();
        store.clear_key_package_slot_observation(&first).unwrap();
        assert!(store.key_package_slot_observation().unwrap() == Some(winner.clone()));
        store.clear_key_package_slot_observation(&winner).unwrap();
        assert!(store.key_package_slot_observation().unwrap().is_none());
    }
}
