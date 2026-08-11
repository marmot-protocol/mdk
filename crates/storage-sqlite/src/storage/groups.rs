use crate::openmls_storage::mls_group_key;
use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, epoch_to_i64, serialize};
use cgka_traits::group::Group;
use cgka_traits::storage::{GroupStorage, StorageError, StorageResult, TransportGroupRoute};
use cgka_traits::types::{EpochId, GroupId};
use rusqlite::{OptionalExtension, params};

impl GroupStorage for SqliteAccountStorage {
    fn put_group(&self, group: &Group) -> StorageResult<()> {
        self.lock()?
            .execute(
                "INSERT INTO cgka_groups (id, epoch, record)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET
                    epoch = excluded.epoch,
                    record = excluded.record",
                params![
                    group.id.as_slice(),
                    epoch_to_i64(group.epoch)?,
                    serialize(group)?
                ],
            )
            .storage()?;
        Ok(())
    }

    fn get_group(&self, id: &GroupId) -> StorageResult<Group> {
        let record: Vec<u8> = self
            .lock()?
            .query_row(
                "SELECT record FROM cgka_groups WHERE id = ?1",
                params![id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .storage()?
            .ok_or(StorageError::NotFound)?;
        deserialize(&record)
    }

    fn delete_group(&self, id: &GroupId) -> StorageResult<()> {
        let mls_group_key = mls_group_key(id)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let deleted = tx
            .execute(
                "DELETE FROM cgka_groups WHERE id = ?1",
                params![id.as_slice()],
            )
            .storage()?;
        if deleted == 0 {
            return Err(StorageError::NotFound);
        }
        tx.execute(
            "DELETE FROM pending_application_events WHERE group_id = ?1",
            params![id.as_slice()],
        )
        .storage()?;
        tx.execute(
            "DELETE FROM openmls_values WHERE provider_version = ?1 AND group_key = ?2",
            params![openmls_traits::storage::CURRENT_VERSION, mls_group_key],
        )
        .storage()?;
        tx.commit().storage()?;
        Ok(())
    }

    fn list_groups(&self) -> StorageResult<Vec<GroupId>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT id FROM cgka_groups ORDER BY id")
            .storage()?;
        stmt.query_map([], |row| row.get::<_, Vec<u8>>(0).map(GroupId::new))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()
    }

    fn list_group_records(&self) -> StorageResult<Vec<Group>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT record FROM cgka_groups ORDER BY id")
            .storage()?;
        let records = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        records.iter().map(|record| deserialize(record)).collect()
    }

    fn put_transport_group_route(
        &self,
        transport_group_id: &[u8],
        group_id: &GroupId,
        source_epoch: EpochId,
    ) -> StorageResult<()> {
        super::transport_routes::put(self, transport_group_id, group_id, source_epoch)
    }

    fn list_transport_group_routes(&self) -> StorageResult<Vec<TransportGroupRoute>> {
        super::transport_routes::list(self)
    }

    fn delete_transport_group_route(&self, transport_group_id: &[u8]) -> StorageResult<()> {
        super::transport_routes::delete_route(self, transport_group_id)
    }

    fn delete_transport_group_routes_below_epoch(
        &self,
        group_id: &GroupId,
        cutoff: EpochId,
    ) -> StorageResult<()> {
        super::transport_routes::delete_below_epoch(self, group_id, cutoff)
    }

    fn delete_transport_group_routes_for_group(&self, group_id: &GroupId) -> StorageResult<()> {
        super::transport_routes::delete_for_group(self, group_id)
    }
}

#[cfg(test)]
mod tests {
    use crate::SqliteAccountStorage;
    use crate::storage::test_support::{
        TestGroupState, gid, mid, sample_group, sample_message, sample_queued_intent,
    };
    use cgka_traits::capabilities::GroupCapabilities;
    use cgka_traits::engine::GroupEvent;
    use cgka_traits::group::ProtocolProfile;
    use cgka_traits::storage::{
        CapabilityStorage, ConvergencePolicyStorage, GroupStorage, MessageStorage,
        OutboundIntentStorage, StorageError, StorageProvider, TransportGroupRoute,
    };
    use cgka_traits::types::{EpochId, MemberId};
    use openmls_traits::storage::StorageProvider as OpenMlsStorageProvider;

    #[test]
    fn list_group_records_returns_every_stored_record() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let first = sample_group(gid(1), 7, 3);
        let second = sample_group(gid(2), 4, 2);
        store.put_group(&first).unwrap();
        store.put_group(&second).unwrap();
        let records = store.list_group_records().unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.contains(&first));
        assert!(records.contains(&second));
    }

    fn route(
        transport_group_id: [u8; 32],
        group_id: &cgka_traits::types::GroupId,
        source_epoch: u64,
    ) -> TransportGroupRoute {
        TransportGroupRoute {
            transport_group_id: transport_group_id.to_vec(),
            group_id: group_id.clone(),
            source_epoch: EpochId(source_epoch),
        }
    }

    fn sorted_routes(store: &SqliteAccountStorage) -> Vec<TransportGroupRoute> {
        let mut routes = store.list_transport_group_routes().unwrap();
        routes.sort_by(|a, b| a.transport_group_id.cmp(&b.transport_group_id));
        routes
    }

    #[test]
    fn transport_group_routes_roundtrip_and_rotation_keeps_prior_route() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 1, 1);
        store.put_group(&group).unwrap();

        // Rotation overlap (mdk#740): both the prior and the current route
        // resolve to the group until the prior route is retired.
        store
            .put_transport_group_route(&[0xAA; 32], &group.id, EpochId(3))
            .unwrap();
        store
            .put_transport_group_route(&[0xBB; 32], &group.id, EpochId(4))
            .unwrap();
        assert_eq!(
            sorted_routes(&store),
            vec![
                route([0xAA; 32], &group.id, 3),
                route([0xBB; 32], &group.id, 4)
            ]
        );

        // Re-pointing an existing route replaces its target and refreshes its
        // source epoch, matching the in-memory index's insert semantics.
        let other = sample_group(gid(2), 1, 1);
        store.put_group(&other).unwrap();
        store
            .put_transport_group_route(&[0xBB; 32], &other.id, EpochId(9))
            .unwrap();
        assert_eq!(
            sorted_routes(&store),
            vec![
                route([0xAA; 32], &group.id, 3),
                route([0xBB; 32], &other.id, 9)
            ]
        );

        store
            .delete_transport_group_routes_for_group(&group.id)
            .unwrap();
        assert_eq!(sorted_routes(&store), vec![route([0xBB; 32], &other.id, 9)]);
    }

    #[test]
    fn transport_group_route_retirement_is_per_route_and_per_epoch_window() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 1, 1);
        store.put_group(&group).unwrap();
        let bystander = sample_group(gid(2), 1, 1);
        store.put_group(&bystander).unwrap();

        store
            .put_transport_group_route(&[0x01; 32], &group.id, EpochId(2))
            .unwrap();
        store
            .put_transport_group_route(&[0x02; 32], &group.id, EpochId(7))
            .unwrap();
        store
            .put_transport_group_route(&[0x03; 32], &group.id, EpochId(12))
            .unwrap();
        store
            .put_transport_group_route(&[0x04; 32], &bystander.id, EpochId(1))
            .unwrap();

        // Bulk retirement below the retention cutoff touches only the named
        // group; the bystander's old route survives.
        store
            .delete_transport_group_routes_below_epoch(&group.id, EpochId(7))
            .unwrap();
        assert_eq!(
            sorted_routes(&store),
            vec![
                route([0x02; 32], &group.id, 7),
                route([0x03; 32], &group.id, 12),
                route([0x04; 32], &bystander.id, 1),
            ]
        );

        // Single-route retirement.
        store.delete_transport_group_route(&[0x02; 32]).unwrap();
        assert_eq!(
            sorted_routes(&store),
            vec![
                route([0x03; 32], &group.id, 12),
                route([0x04; 32], &bystander.id, 1),
            ]
        );
    }

    #[test]
    fn deleting_a_group_cascades_its_transport_routes() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 1, 1);
        store.put_group(&group).unwrap();
        store
            .put_transport_group_route(&[0xCC; 32], &group.id, EpochId(1))
            .unwrap();
        store.delete_group(&group.id).unwrap();
        assert!(store.list_transport_group_routes().unwrap().is_empty());
    }

    #[test]
    fn group_roundtrip_preserves_every_field() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mut group = sample_group(gid(1), 7, 3);
        group.protocol_profile = ProtocolProfile::Current;
        store.put_group(&group).unwrap();
        assert_eq!(store.get_group(&group.id).unwrap(), group);
    }

    #[test]
    fn pre_profile_group_record_reopens_as_legacy() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 7, 3);
        let mut record = serde_json::to_value(&group).unwrap();
        record.as_object_mut().unwrap().remove("protocol_profile");
        let bytes = serde_json::to_vec(&record).unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO cgka_groups (id, epoch, record) VALUES (?1, ?2, ?3)",
                rusqlite::params![group.id.as_slice(), 7, bytes],
            )
            .unwrap();

        let reopened = store.get_group(&group.id).unwrap();
        assert_eq!(reopened, group);
    }

    #[test]
    fn corrupt_present_group_profile_fails_closed() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 7, 3);
        let mut record = serde_json::to_value(&group).unwrap();
        record["protocol_profile"] = serde_json::json!("nope");
        let bytes = serde_json::to_vec(&record).unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO cgka_groups (id, epoch, record) VALUES (?1, ?2, ?3)",
                rusqlite::params![group.id.as_slice(), 7, bytes],
            )
            .unwrap();

        let error = store
            .get_group(&group.id)
            .expect_err("a present corrupt profile must not fall through the serde default");
        assert!(
            matches!(&error, StorageError::Serialization(message) if message.contains("unknown variant")),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn group_update_preserves_foreign_key_owned_rows() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 0, 1);
        store.put_group(&group).unwrap();
        let message = sample_message(mid(1), group.id.clone(), 0);
        store.put_message(&message).unwrap();
        store
            .put_pending_application_event(&GroupEvent::MessageReceived {
                group_id: group.id.clone(),
                message_id: message.id.clone(),
                sender: MemberId::new(vec![7; 32]),
                epoch: EpochId(0),
                payload: b"authenticated chat".to_vec(),
                retention: None,
            })
            .unwrap();
        store
            .put_queued_outbound_intent(&sample_queued_intent(mid(2), group.id.clone()))
            .unwrap();
        store
            .save_member_capabilities(&group.id, &group.members[0], GroupCapabilities::default())
            .unwrap();
        store.put_convergence_policy(&group.id, b"policy").unwrap();
        store.create_group_snapshot(&group.id, "anchor").unwrap();

        store.put_group(&sample_group(gid(1), 1, 1)).unwrap();

        assert_eq!(store.list_messages(&group.id, EpochId(0)).unwrap().len(), 1);
        assert_eq!(
            store.list_queued_outbound_intents(&group.id).unwrap().len(),
            1
        );
        assert!(
            store
                .member_capabilities(&group.id, &group.members[0].id)
                .unwrap()
                .is_some()
        );
        assert!(store.convergence_policy(&group.id).unwrap().is_some());
        assert_eq!(
            store.list_group_snapshots(&group.id).unwrap(),
            vec!["anchor".to_owned()]
        );
    }

    #[test]
    fn group_missing_returns_not_found() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        assert!(matches!(
            store.get_group(&gid(9)),
            Err(StorageError::NotFound)
        ));
    }

    #[test]
    fn group_delete_cascades_messages_queued_caps_policy_and_openmls_group_state() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 0, 1);
        store.put_group(&group).unwrap();
        store
            .put_message(&sample_message(mid(1), group.id.clone(), 0))
            .unwrap();
        store
            .put_queued_outbound_intent(&sample_queued_intent(mid(2), group.id.clone()))
            .unwrap();
        store
            .save_member_capabilities(&group.id, &group.members[0], GroupCapabilities::default())
            .unwrap();
        store.put_convergence_policy(&group.id, b"policy").unwrap();
        let mls_group_id = openmls::group::GroupId::from_slice(group.id.as_slice());
        store
            .mls_storage()
            .write_group_state(&mls_group_id, &TestGroupState(b"epoch-0".to_vec()))
            .unwrap();

        store.delete_group(&group.id).unwrap();

        assert!(
            store
                .list_messages(&group.id, EpochId(0))
                .unwrap()
                .is_empty()
        );
        assert!(store.list_pending_application_events().unwrap().is_empty());
        assert!(
            store
                .list_queued_outbound_intents(&group.id)
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .member_capabilities(&group.id, &group.members[0].id)
                .unwrap()
                .is_none()
        );
        assert!(store.convergence_policy(&group.id).unwrap().is_none());
        let state: Option<TestGroupState> = store.mls_storage().group_state(&mls_group_id).unwrap();
        assert!(state.is_none());
    }

    #[test]
    fn list_groups_returns_all_ids() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        store.put_group(&sample_group(gid(2), 0, 0)).unwrap();
        assert_eq!(store.list_groups().unwrap(), vec![gid(1), gid(2)]);
    }
}
