use crate::openmls_storage::mls_group_key;
use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, epoch_to_i64, serialize};
use cgka_traits::group::Group;
use cgka_traits::storage::{GroupStorage, StorageError, StorageResult};
use cgka_traits::types::GroupId;
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
}

#[cfg(test)]
mod tests {
    use crate::SqliteAccountStorage;
    use crate::storage::test_support::{
        TestGroupState, gid, mid, sample_group, sample_message, sample_queued_intent,
    };
    use cgka_traits::capabilities::GroupCapabilities;
    use cgka_traits::storage::{
        CapabilityStorage, ConvergencePolicyStorage, GroupStorage, MessageStorage,
        OutboundIntentStorage, StorageError, StorageProvider,
    };
    use cgka_traits::types::EpochId;
    use openmls_traits::storage::StorageProvider as OpenMlsStorageProvider;

    #[test]
    fn group_roundtrip_preserves_every_field() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 7, 3);
        store.put_group(&group).unwrap();
        assert_eq!(store.get_group(&group.id).unwrap(), group);
    }

    #[test]
    fn group_update_preserves_foreign_key_owned_rows() {
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
