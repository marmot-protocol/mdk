use crate::connection::CachedSql;
use crate::connection::retry_on_busy;
use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, serialize};
use cgka_traits::maintenance::{
    DurableGroupEvolution, DurableTransportFanout, GroupMaintenanceState, KeyPackageLifecycleState,
    MaintenanceObligation, PeriodicMaintenancePolicy,
};
use cgka_traits::storage::{MaintenanceStorage, StorageError, StorageResult};
use cgka_traits::types::{GroupId, MessageId};
use rusqlite::{OptionalExtension, params};

impl MaintenanceStorage for SqliteAccountStorage {
    fn key_package_lifecycle(&self) -> StorageResult<Option<KeyPackageLifecycleState>> {
        read_singleton(self, "cgka_key_package_lifecycle")
    }

    fn put_key_package_lifecycle(&self, state: &KeyPackageLifecycleState) -> StorageResult<()> {
        write_singleton(self, "cgka_key_package_lifecycle", state)
    }

    fn group_maintenance(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Option<GroupMaintenanceState>> {
        read_group_record(self, "cgka_group_maintenance", group_id)
    }

    fn put_group_maintenance(&self, state: &GroupMaintenanceState) -> StorageResult<()> {
        write_group_record(self, "cgka_group_maintenance", &state.group_id, state)
    }

    fn delete_group_maintenance(&self, group_id: &GroupId) -> StorageResult<()> {
        delete_by_id(
            self,
            "cgka_group_maintenance",
            "group_id",
            group_id.as_slice(),
        )
    }

    fn put_maintenance_obligation(&self, record: &MaintenanceObligation) -> StorageResult<()> {
        write_ordered_record(
            self,
            "cgka_maintenance_obligations",
            &record.id,
            Some(&record.group_id),
            record,
        )
    }

    fn maintenance_obligation(
        &self,
        id: &MessageId,
    ) -> StorageResult<Option<MaintenanceObligation>> {
        read_id_record(self, "cgka_maintenance_obligations", id)
    }

    fn list_maintenance_obligations(&self) -> StorageResult<Vec<MaintenanceObligation>> {
        list_ordered_records(self, "cgka_maintenance_obligations")
    }

    fn list_maintenance_obligations_for_group(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<MaintenanceObligation>> {
        list_ordered_records_for_group(self, "cgka_maintenance_obligations", group_id)
    }

    fn delete_maintenance_obligation(&self, id: &MessageId) -> StorageResult<()> {
        delete_by_id(self, "cgka_maintenance_obligations", "id", id.as_slice())
    }

    fn put_group_evolution(&self, record: &DurableGroupEvolution) -> StorageResult<()> {
        write_ordered_record(
            self,
            "cgka_group_evolutions",
            &record.id,
            Some(&record.group_id),
            record,
        )
    }

    fn group_evolution(&self, id: &MessageId) -> StorageResult<Option<DurableGroupEvolution>> {
        read_id_record(self, "cgka_group_evolutions", id)
    }

    fn list_group_evolutions(&self) -> StorageResult<Vec<DurableGroupEvolution>> {
        list_ordered_records(self, "cgka_group_evolutions")
    }

    fn list_group_evolutions_for_group(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<DurableGroupEvolution>> {
        list_ordered_records_for_group(self, "cgka_group_evolutions", group_id)
    }

    fn delete_group_evolution(&self, id: &MessageId) -> StorageResult<()> {
        delete_by_id(self, "cgka_group_evolutions", "id", id.as_slice())
    }

    fn put_transport_fanout(&self, record: &DurableTransportFanout) -> StorageResult<()> {
        write_ordered_record(
            self,
            "cgka_transport_fanout",
            &record.id,
            record.group_id.as_ref(),
            record,
        )
    }

    fn transport_fanout(&self, id: &MessageId) -> StorageResult<Option<DurableTransportFanout>> {
        read_id_record(self, "cgka_transport_fanout", id)
    }

    fn list_transport_fanouts(&self) -> StorageResult<Vec<DurableTransportFanout>> {
        list_ordered_records(self, "cgka_transport_fanout")
    }

    fn delete_transport_fanout(&self, id: &MessageId) -> StorageResult<()> {
        delete_by_id(self, "cgka_transport_fanout", "id", id.as_slice())
    }

    fn periodic_maintenance_policy(&self) -> StorageResult<PeriodicMaintenancePolicy> {
        let value: i64 = self
            .lock()?
            .query_row_cached(
                "SELECT periodic_policy FROM cgka_maintenance_settings WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .storage()?;
        match value {
            0 => Ok(PeriodicMaintenancePolicy::Disabled),
            1 => Ok(PeriodicMaintenancePolicy::EnabledForNewGroups),
            _ => Err(StorageError::Serialization(
                "invalid persisted periodic maintenance policy".into(),
            )),
        }
    }

    fn put_periodic_maintenance_policy(
        &self,
        policy: PeriodicMaintenancePolicy,
    ) -> StorageResult<()> {
        let value = match policy {
            PeriodicMaintenancePolicy::Disabled => 0_i64,
            PeriodicMaintenancePolicy::EnabledForNewGroups => 1_i64,
        };
        write(self, || {
            self.lock()?
                .execute_cached(
                    "UPDATE cgka_maintenance_settings
                     SET periodic_policy = ?1
                     WHERE singleton = 1",
                    params![value],
                )
                .storage()?;
            Ok(())
        })
    }
}

fn write<T>(store: &SqliteAccountStorage, op: impl Fn() -> StorageResult<T>) -> StorageResult<T> {
    if store.connection.is_current_thread_transaction_owner() {
        op()
    } else {
        retry_on_busy(op)
    }
}

fn read_singleton<T: serde::de::DeserializeOwned>(
    store: &SqliteAccountStorage,
    table: &str,
) -> StorageResult<Option<T>> {
    let sql = format!("SELECT record FROM {table} WHERE singleton = 1");
    store
        .lock()?
        .query_row(&sql, [], |row| row.get::<_, Vec<u8>>(0))
        .optional()
        .storage()?
        .map(|bytes| deserialize(&bytes))
        .transpose()
}

fn write_singleton<T: serde::Serialize>(
    store: &SqliteAccountStorage,
    table: &str,
    record: &T,
) -> StorageResult<()> {
    let serialized = serialize(record)?;
    let sql = format!(
        "INSERT INTO {table} (singleton, record) VALUES (1, ?1)
         ON CONFLICT(singleton) DO UPDATE SET record = excluded.record"
    );
    write(store, || {
        store.lock()?.execute(&sql, params![serialized]).storage()?;
        Ok(())
    })
}

fn read_group_record<T: serde::de::DeserializeOwned>(
    store: &SqliteAccountStorage,
    table: &str,
    group_id: &GroupId,
) -> StorageResult<Option<T>> {
    let sql = format!("SELECT record FROM {table} WHERE group_id = ?1");
    store
        .lock()?
        .query_row(&sql, params![group_id.as_slice()], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .optional()
        .storage()?
        .map(|bytes| deserialize(&bytes))
        .transpose()
}

fn write_group_record<T: serde::Serialize>(
    store: &SqliteAccountStorage,
    table: &str,
    group_id: &GroupId,
    record: &T,
) -> StorageResult<()> {
    let serialized = serialize(record)?;
    let sql = format!(
        "INSERT INTO {table} (group_id, record) VALUES (?1, ?2)
         ON CONFLICT(group_id) DO UPDATE SET record = excluded.record"
    );
    write(store, || {
        store
            .lock()?
            .execute(&sql, params![group_id.as_slice(), serialized])
            .storage()?;
        Ok(())
    })
}

fn write_ordered_record<T: serde::Serialize>(
    store: &SqliteAccountStorage,
    table: &str,
    id: &MessageId,
    group_id: Option<&GroupId>,
    record: &T,
) -> StorageResult<()> {
    let serialized = serialize(record)?;
    let sql = format!(
        "INSERT INTO {table} (id, group_id, insert_order, record)
         VALUES (
            ?1,
            ?2,
            (SELECT COALESCE(MAX(insert_order), 0) + 1 FROM {table}),
            ?3
         )
         ON CONFLICT(id) DO UPDATE SET
            group_id = excluded.group_id,
            record = excluded.record"
    );
    write(store, || {
        store
            .lock()?
            .execute(
                &sql,
                params![id.as_slice(), group_id.map(GroupId::as_slice), serialized],
            )
            .storage()?;
        Ok(())
    })
}

fn read_id_record<T: serde::de::DeserializeOwned>(
    store: &SqliteAccountStorage,
    table: &str,
    id: &MessageId,
) -> StorageResult<Option<T>> {
    let sql = format!("SELECT record FROM {table} WHERE id = ?1");
    store
        .lock()?
        .query_row(&sql, params![id.as_slice()], |row| row.get::<_, Vec<u8>>(0))
        .optional()
        .storage()?
        .map(|bytes| deserialize(&bytes))
        .transpose()
}

fn list_ordered_records<T: serde::de::DeserializeOwned>(
    store: &SqliteAccountStorage,
    table: &str,
) -> StorageResult<Vec<T>> {
    let sql = format!("SELECT record FROM {table} ORDER BY insert_order");
    let connection = store.lock()?;
    let mut statement = connection.prepare_cached(&sql).storage()?;
    let records = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    records.iter().map(|bytes| deserialize(bytes)).collect()
}

fn list_ordered_records_for_group<T: serde::de::DeserializeOwned>(
    store: &SqliteAccountStorage,
    table: &str,
    group_id: &GroupId,
) -> StorageResult<Vec<T>> {
    let sql = format!("SELECT record FROM {table} WHERE group_id = ?1 ORDER BY insert_order");
    let connection = store.lock()?;
    let mut statement = connection.prepare_cached(&sql).storage()?;
    let records = statement
        .query_map(params![group_id.as_slice()], |row| row.get::<_, Vec<u8>>(0))
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    records.iter().map(|bytes| deserialize(bytes)).collect()
}

fn delete_by_id(
    store: &SqliteAccountStorage,
    table: &str,
    column: &str,
    id: &[u8],
) -> StorageResult<()> {
    let sql = format!("DELETE FROM {table} WHERE {column} = ?1");
    write(store, || {
        store.lock()?.execute(&sql, params![id]).storage()?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::test_support::{gid, mid, sample_group};
    use cgka_traits::Timestamp;
    use cgka_traits::maintenance::{GroupMaintenanceState, MaintenancePhase, MaintenanceTrigger};
    use cgka_traits::storage::GroupStorage;

    #[test]
    fn maintenance_records_roundtrip_and_group_rows_cascade() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();

        let state = GroupMaintenanceState {
            group_id: gid(1),
            enrolled_at: Some(Timestamp(10)),
            periodic_enrolled: true,
            last_own_leaf_rotation_at: Some(Timestamp(11)),
            next_periodic_rotation_at: Some(Timestamp(12)),
        };
        store.put_group_maintenance(&state).unwrap();
        let obligation = MaintenanceObligation {
            id: mid(9),
            group_id: gid(1),
            trigger: MaintenanceTrigger::PostJoin,
            phase: MaintenancePhase::Quiet,
            created_at: Timestamp(10),
            operational_target_at: Some(Timestamp(20)),
            overdue: false,
            eose_deadline_at: None,
            grace_until: None,
            quiet_since: Some(Timestamp(11)),
            own_leaf_baseline_hash: Some(vec![4, 5, 6]),
            sampled_jitter_ms: 7,
            not_before: Some(Timestamp(12)),
            attempt_count: 0,
            semantic_rearm_count: 0,
            last_failure_code: None,
        };
        store.put_maintenance_obligation(&obligation).unwrap();

        assert_eq!(store.group_maintenance(&gid(1)).unwrap(), Some(state));
        assert_eq!(
            store.list_maintenance_obligations().unwrap(),
            vec![obligation.clone()]
        );
        assert_eq!(
            store
                .list_maintenance_obligations_for_group(&gid(1))
                .unwrap(),
            vec![obligation.clone()]
        );

        store.delete_group(&gid(1)).unwrap();
        assert_eq!(store.group_maintenance(&gid(1)).unwrap(), None);
        assert!(store.list_maintenance_obligations().unwrap().is_empty());
    }

    #[test]
    fn ordered_record_allocation_is_atomic_across_concurrent_writers() {
        use std::sync::{Arc, Barrier};

        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let writers = 16u8;
        let barrier = Arc::new(Barrier::new(usize::from(writers)));
        let handles = (0..writers)
            .map(|index| {
                let store = store.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store
                        .put_maintenance_obligation(&MaintenanceObligation {
                            id: mid(index.saturating_add(1)),
                            group_id: gid(1),
                            trigger: MaintenanceTrigger::Manual,
                            phase: MaintenancePhase::Quiet,
                            created_at: Timestamp(u64::from(index)),
                            operational_target_at: None,
                            overdue: false,
                            eose_deadline_at: None,
                            grace_until: None,
                            quiet_since: None,
                            own_leaf_baseline_hash: None,
                            sampled_jitter_ms: 0,
                            not_before: None,
                            attempt_count: 0,
                            semantic_rearm_count: 0,
                            last_failure_code: None,
                        })
                        .unwrap();
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().unwrap();
        }

        let (rows, distinct_orders): (i64, i64) = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*), COUNT(DISTINCT insert_order)
                 FROM cgka_maintenance_obligations",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(rows, i64::from(writers));
        assert_eq!(distinct_orders, rows);
    }

    #[test]
    fn periodic_policy_defaults_enabled_for_new_groups_and_roundtrips() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        assert_eq!(
            store.periodic_maintenance_policy().unwrap(),
            PeriodicMaintenancePolicy::EnabledForNewGroups
        );
        store
            .put_periodic_maintenance_policy(PeriodicMaintenancePolicy::Disabled)
            .unwrap();
        assert_eq!(
            store.periodic_maintenance_policy().unwrap(),
            PeriodicMaintenancePolicy::Disabled
        );
    }
}
