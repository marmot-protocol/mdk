use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, serialize};
use cgka_traits::storage::{DeferredPeelGeneration, DeferredPeelGenerationStorage, StorageResult};
use cgka_traits::types::GroupId;
use rusqlite::{OptionalExtension, params};

impl DeferredPeelGenerationStorage for SqliteAccountStorage {
    fn deferred_peel_generation(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Option<DeferredPeelGeneration>> {
        let encoded: Option<Vec<u8>> = self
            .lock()?
            .query_row(
                "SELECT record FROM cgka_deferred_peel_generations WHERE group_id = ?1",
                params![group_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .storage()?;
        encoded.map(|record| deserialize(&record)).transpose()
    }

    fn put_deferred_peel_generation(
        &self,
        generation: &DeferredPeelGeneration,
    ) -> StorageResult<()> {
        let record = serialize(generation)?;
        self.lock()?
            .execute(
                "INSERT INTO cgka_deferred_peel_generations (group_id, record)
                 VALUES (?1, ?2)
                 ON CONFLICT(group_id) DO UPDATE SET record = excluded.record",
                params![generation.group_id.as_slice(), record],
            )
            .storage()?;
        Ok(())
    }

    fn delete_deferred_peel_generation(&self, group_id: &GroupId) -> StorageResult<()> {
        self.lock()?
            .execute(
                "DELETE FROM cgka_deferred_peel_generations WHERE group_id = ?1",
                params![group_id.as_slice()],
            )
            .storage()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::test_support::{gid, sample_group};
    use cgka_traits::storage::GroupStorage;

    #[test]
    fn deferred_peel_generation_round_trips_updates_and_cascades() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 4, 0);
        store.put_group(&group).unwrap();

        let mut generation = DeferredPeelGeneration {
            group_id: group.id.clone(),
            context_fingerprint: [7; 32],
        };
        store.put_deferred_peel_generation(&generation).unwrap();
        assert_eq!(
            store.deferred_peel_generation(&group.id).unwrap(),
            Some(generation.clone())
        );

        generation.context_fingerprint = [8; 32];
        store.put_deferred_peel_generation(&generation).unwrap();
        assert_eq!(
            store.deferred_peel_generation(&group.id).unwrap(),
            Some(generation)
        );

        store.delete_group(&group.id).unwrap();
        assert_eq!(store.deferred_peel_generation(&group.id).unwrap(), None);
    }
}
