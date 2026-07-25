use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, serialize};
use cgka_traits::convergence_pass::DurableConvergencePass;
use cgka_traits::storage::{ConvergencePassStorage, StorageResult};
use cgka_traits::types::GroupId;
use rusqlite::{OptionalExtension, params};

impl ConvergencePassStorage for SqliteAccountStorage {
    fn convergence_pass(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Option<DurableConvergencePass>> {
        let encoded: Option<Vec<u8>> = self
            .lock()?
            .query_row(
                "SELECT record FROM cgka_convergence_passes WHERE group_id = ?1",
                params![group_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .storage()?;
        encoded.map(|record| deserialize(&record)).transpose()
    }

    fn put_convergence_pass(&self, pass: &DurableConvergencePass) -> StorageResult<()> {
        let record = serialize(pass)?;
        self.lock()?
            .execute(
                "INSERT INTO cgka_convergence_passes (group_id, record)
                 VALUES (?1, ?2)
                 ON CONFLICT(group_id) DO UPDATE SET record = excluded.record",
                params![pass.group_id.as_slice(), record],
            )
            .storage()?;
        Ok(())
    }

    fn list_convergence_passes(&self) -> StorageResult<Vec<DurableConvergencePass>> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare("SELECT record FROM cgka_convergence_passes ORDER BY group_id")
            .storage()?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .storage()?;
        rows.map(|row| deserialize(&row.storage()?)).collect()
    }

    fn delete_convergence_pass(&self, group_id: &GroupId) -> StorageResult<()> {
        self.lock()?
            .execute(
                "DELETE FROM cgka_convergence_passes WHERE group_id = ?1",
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
    use cgka_traits::convergence_pass::{
        ConvergenceCutoffCause, ConvergencePassMember, ConvergencePassPhase,
    };
    use cgka_traits::storage::GroupStorage;
    use cgka_traits::{EpochId, MessageId};

    fn sample_pass(group_id: GroupId) -> DurableConvergencePass {
        DurableConvergencePass {
            group_id,
            generation: 7,
            phase: ConvergencePassPhase::Frozen,
            base_epoch: EpochId(4),
            clock_instance_id: 99,
            opened_monotonic_ms: 10,
            quiescence_deadline_monotonic_ms: 1_010,
            absolute_deadline_monotonic_ms: 5_010,
            opened_wall_ms: 20,
            quiescence_deadline_wall_ms: 1_020,
            absolute_deadline_wall_ms: 5_020,
            members: vec![ConvergencePassMember {
                message_id: MessageId::new(vec![8]),
                payload_digest: [9; 32],
            }],
            frozen_at_wall_ms: Some(1_020),
            cutoff_cause: Some(ConvergenceCutoffCause::Quiescence),
            fairness_slot_available: false,
        }
    }

    #[test]
    fn convergence_pass_round_trips_updates_and_cascades() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 4, 0);
        store.put_group(&group).unwrap();

        let mut pass = sample_pass(group.id.clone());
        store.put_convergence_pass(&pass).unwrap();
        assert_eq!(
            store.convergence_pass(&group.id).unwrap(),
            Some(pass.clone())
        );
        assert_eq!(store.list_convergence_passes().unwrap(), vec![pass.clone()]);

        pass.phase = ConvergencePassPhase::Completed;
        store.put_convergence_pass(&pass).unwrap();
        assert_eq!(store.convergence_pass(&group.id).unwrap(), Some(pass));

        store.delete_group(&group.id).unwrap();
        assert_eq!(store.convergence_pass(&group.id).unwrap(), None);
    }
}
