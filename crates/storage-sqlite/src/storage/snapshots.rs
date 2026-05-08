mod capture;
mod lifecycle;
mod restore;
mod rows;

use crate::SqliteStorage;
use cgka_traits::storage::StorageResult;
use cgka_traits::types::GroupId;

pub(super) fn create(store: &SqliteStorage, group_id: &GroupId, name: &str) -> StorageResult<()> {
    capture::create(store, group_id, name)
}

pub(super) fn list(store: &SqliteStorage, group_id: &GroupId) -> StorageResult<Vec<String>> {
    lifecycle::list(store, group_id)
}

pub(super) fn rollback(store: &SqliteStorage, group_id: &GroupId, name: &str) -> StorageResult<()> {
    restore::rollback(store, group_id, name)
}

pub(super) fn release(store: &SqliteStorage, group_id: &GroupId, name: &str) -> StorageResult<()> {
    lifecycle::release(store, group_id, name)
}

#[cfg(test)]
mod tests {
    use crate::SqliteStorage;
    use crate::storage::test_support::{
        TestGroupState, gid, mid, sample_group, sample_message, sample_queued_intent,
    };
    use cgka_traits::capabilities::{Capability, GroupCapabilities};
    use cgka_traits::storage::{
        CapabilityStorage, GroupStorage, MessageStorage, OutboundIntentStorage, StorageError,
        StorageProvider,
    };
    use cgka_traits::types::EpochId;
    use openmls_traits::storage::StorageProvider as OpenMlsStorageProvider;

    #[test]
    fn snapshot_rollback_restores_group_messages_queue_caps_and_openmls_group_state() {
        let store = SqliteStorage::in_memory().unwrap();
        let g0 = sample_group(gid(1), 0, 1);
        store.put_group(&g0).unwrap();
        store
            .put_message(&sample_message(mid(1), g0.id.clone(), 0))
            .unwrap();
        store
            .put_queued_outbound_intent(&sample_queued_intent(mid(10), g0.id.clone()))
            .unwrap();
        let mut caps = GroupCapabilities::default();
        caps.insert(Capability::Proposal(10));
        store
            .save_member_capabilities(&g0.id, &g0.members[0], caps.clone())
            .unwrap();
        let mls_group_id = openmls::group::GroupId::from_slice(g0.id.as_slice());
        store
            .mls_storage()
            .write_group_state(&mls_group_id, &TestGroupState(b"epoch-0".to_vec()))
            .unwrap();

        store.create_group_snapshot(&g0.id, "pre-commit").unwrap();

        let g1 = sample_group(gid(1), 1, 2);
        store.put_group(&g1).unwrap();
        store
            .put_message(&sample_message(mid(2), g0.id.clone(), 1))
            .unwrap();
        store.delete_queued_outbound_intent(&mid(10)).unwrap();
        store
            .mls_storage()
            .write_group_state(&mls_group_id, &TestGroupState(b"epoch-1".to_vec()))
            .unwrap();

        store
            .rollback_group_to_snapshot(&g0.id, "pre-commit")
            .unwrap();

        assert_eq!(store.get_group(&g0.id).unwrap(), g0);
        let msgs = store.list_messages(&g0.id, EpochId(0)).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].id, mid(1));
        let queued = store.list_queued_outbound_intents(&g0.id).unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].id, mid(10));
        assert_eq!(
            store
                .member_capabilities(&g0.id, &g0.members[0].id)
                .unwrap(),
            Some(caps)
        );
        let state: Option<TestGroupState> = store.mls_storage().group_state(&mls_group_id).unwrap();
        assert_eq!(state, Some(TestGroupState(b"epoch-0".to_vec())));
    }

    #[test]
    fn snapshot_listing_and_release_are_group_scoped() {
        let store = SqliteStorage::in_memory().unwrap();
        let g1 = sample_group(gid(1), 0, 0);
        let g2 = sample_group(gid(2), 0, 0);
        store.put_group(&g1).unwrap();
        store.put_group(&g2).unwrap();

        store.create_group_snapshot(&g1.id, "z-after").unwrap();
        store.create_group_snapshot(&g2.id, "other-group").unwrap();
        store.create_group_snapshot(&g1.id, "a-before").unwrap();
        assert_eq!(
            store.list_group_snapshots(&g1.id).unwrap(),
            vec!["a-before".to_string(), "z-after".to_string()]
        );

        store.release_group_snapshot(&g1.id, "a-before").unwrap();
        assert_eq!(
            store.list_group_snapshots(&g1.id).unwrap(),
            vec!["z-after".to_string()]
        );
        assert!(matches!(
            store.rollback_group_to_snapshot(&g1.id, "a-before"),
            Err(StorageError::SnapshotMissing(_))
        ));
    }
}
