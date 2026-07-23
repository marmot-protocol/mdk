mod capture;
mod lifecycle;
mod restore;
mod rows;

use crate::SqliteAccountStorage;
use cgka_traits::storage::StorageResult;
use cgka_traits::types::GroupId;

pub(super) fn create(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    name: &str,
) -> StorageResult<()> {
    capture::create(store, group_id, name)
}

pub(super) fn list(store: &SqliteAccountStorage, group_id: &GroupId) -> StorageResult<Vec<String>> {
    lifecycle::list(store, group_id)
}

pub(super) fn rollback(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    name: &str,
) -> StorageResult<()> {
    restore::rollback(store, group_id, name)
}

pub(super) fn release(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    name: &str,
) -> StorageResult<()> {
    lifecycle::release(store, group_id, name)
}

#[cfg(test)]
mod tests {
    use crate::SqliteAccountStorage;
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
        let store = SqliteAccountStorage::in_memory().unwrap();
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
    fn snapshot_rollback_joins_outer_transaction() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let anchor_group = sample_group(gid(1), 0, 1);
        let anchor_message = sample_message(mid(1), anchor_group.id.clone(), 0);
        let anchor_queued = sample_queued_intent(mid(10), anchor_group.id.clone());
        store.put_group(&anchor_group).unwrap();
        store.put_message(&anchor_message).unwrap();
        store.put_queued_outbound_intent(&anchor_queued).unwrap();
        store
            .create_group_snapshot(&anchor_group.id, "historical-anchor")
            .unwrap();

        let live_group = sample_group(gid(1), 1, 2);
        let live_message = sample_message(mid(2), live_group.id.clone(), 1);
        let live_queued = sample_queued_intent(mid(11), live_group.id.clone());
        store.put_group(&live_group).unwrap();
        store.put_message(&live_message).unwrap();
        store.put_queued_outbound_intent(&live_queued).unwrap();

        let result: cgka_traits::storage::StorageResult<()> = store.with_transaction(|storage| {
            storage.rollback_group_to_snapshot(&live_group.id, "historical-anchor")?;
            // Simulate restoring only part of the live record set before a
            // process/error boundary interrupts the operation.
            storage.put_message(&live_message)?;
            Err(cgka_traits::storage::StorageError::Backend(
                "injected after partial live restore".into(),
            ))
        });
        assert!(result.is_err());

        assert_eq!(store.get_group(&live_group.id).unwrap(), live_group);
        assert_eq!(
            store.list_messages(&live_group.id, EpochId(0)).unwrap(),
            vec![anchor_message, live_message]
        );
        assert_eq!(
            store.list_queued_outbound_intents(&live_group.id).unwrap(),
            vec![anchor_queued, live_queued]
        );
    }

    #[test]
    fn snapshot_create_joins_outer_transaction() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 0, 1);
        store.put_group(&group).unwrap();

        let result: cgka_traits::storage::StorageResult<()> = store.with_transaction(|storage| {
            storage.create_group_snapshot(&group.id, "nested")?;
            Err(StorageError::Backend("force rollback".to_owned()))
        });

        assert!(matches!(
            result,
            Err(StorageError::Backend(message)) if message == "force rollback"
        ));
        assert!(store.list_group_snapshots(&group.id).unwrap().is_empty());
    }

    #[test]
    fn snapshot_create_and_rollback_retry_writer_contention() {
        use crate::{SqlCipherKey, SqliteStorageOptions};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snapshot-contention.sqlite");
        let key = SqlCipherKey::new("snapshot contention key").unwrap();
        let options = SqliteStorageOptions {
            busy_timeout_ms: 50,
            ..SqliteStorageOptions::default()
        };
        let store = SqliteAccountStorage::open_encrypted_with_options(&path, &key, options.clone())
            .unwrap();
        let original = sample_group(gid(1), 0, 1);
        store.put_group(&original).unwrap();

        let spawn_blocker = || {
            let blocker_path = path.clone();
            let blocker_options = options.clone();
            let blocker_key = SqlCipherKey::new("snapshot contention key").unwrap();
            let (lock_acquired_tx, lock_acquired_rx) = std::sync::mpsc::channel();
            let handle = std::thread::spawn(move || {
                let blocker = SqliteAccountStorage::open_encrypted_with_options(
                    &blocker_path,
                    &blocker_key,
                    blocker_options,
                )
                .unwrap();
                let conn = blocker.lock().unwrap();
                conn.execute_batch("BEGIN IMMEDIATE").unwrap();
                lock_acquired_tx.send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(200));
                conn.execute_batch("COMMIT").unwrap();
            });
            lock_acquired_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            handle
        };

        let blocker = spawn_blocker();
        store
            .create_group_snapshot(&original.id, "contended")
            .expect("snapshot capture retries after transient contention");
        blocker.join().unwrap();

        let changed = sample_group(gid(1), 1, 1);
        store.put_group(&changed).unwrap();
        let blocker = spawn_blocker();
        store
            .rollback_group_to_snapshot(&original.id, "contended")
            .expect("snapshot rollback retries after transient contention");
        blocker.join().unwrap();
        assert_eq!(store.get_group(&original.id).unwrap(), original);
    }

    #[test]
    fn snapshot_listing_and_release_are_group_scoped() {
        let store = SqliteAccountStorage::in_memory().unwrap();
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
