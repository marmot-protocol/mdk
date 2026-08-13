mod capture;
mod checkpoints;
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
    capture::create(store, group_id, name, capture::SnapshotScope::Full)
}

pub(super) fn create_state_scoped(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    name: &str,
) -> StorageResult<()> {
    capture::create(store, group_id, name, capture::SnapshotScope::GroupState)
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

pub(super) fn create_group_state_checkpoint(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    checkpoint: &cgka_traits::storage::GroupStateCheckpointRef,
) -> StorageResult<()> {
    checkpoints::create_group_state_checkpoint(store, group_id, checkpoint)
}

pub(super) fn restore_group_state_checkpoint(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    checkpoint_id: &str,
) -> StorageResult<()> {
    checkpoints::restore_group_state_checkpoint(store, group_id, checkpoint_id)
}

pub(super) fn list_group_state_checkpoints(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
) -> StorageResult<Vec<cgka_traits::storage::GroupStateCheckpointRef>> {
    checkpoints::list_group_state_checkpoints(store, group_id)
}

pub(super) fn release_group_state_checkpoint(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    checkpoint_id: &str,
) -> StorageResult<()> {
    checkpoints::release_group_state_checkpoint(store, group_id, checkpoint_id)
}

#[cfg(feature = "test-conformance-replay")]
pub(crate) fn export_replay(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
) -> StorageResult<Vec<u8>> {
    capture::export(store, group_id)
}

#[cfg(feature = "test-conformance-replay")]
pub(crate) fn import_replay(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    snapshot: &[u8],
) -> StorageResult<()> {
    restore::import(store, group_id, snapshot)
}

#[cfg(test)]
mod tests {
    use crate::SqliteAccountStorage;
    use crate::storage::test_support::{
        TestGroupState, gid, mid, sample_group, sample_message, sample_queued_intent,
    };
    use cgka_traits::capabilities::{Capability, GroupCapabilities};
    use cgka_traits::engine::GroupEvent;
    use cgka_traits::storage::{
        CapabilityStorage, GroupStateCheckpointRef, GroupStorage, MemberValidationCacheStorage,
        MessageStorage, OutboundIntentStorage, StorageError, StorageProvider,
    };
    use cgka_traits::types::{EpochId, MemberId};
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
        for message_id in [mid(1), mid(2)] {
            store
                .put_pending_application_event(&GroupEvent::MessageReceived {
                    group_id: g0.id.clone(),
                    message_id,
                    sender: MemberId::new(vec![7; 32]),
                    epoch: EpochId(0),
                    payload: b"authenticated chat".to_vec(),
                    retention: None,
                })
                .unwrap();
        }
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
        let pending = store.list_pending_application_events().unwrap();
        assert_eq!(pending.len(), 1);
        assert!(matches!(
            &pending[0],
            GroupEvent::MessageReceived { message_id, .. } if *message_id == mid(1)
        ));
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
    fn state_scoped_snapshot_rolls_back_group_state_without_touching_messages_or_queue() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let g0 = sample_group(gid(1), 0, 1);
        store.put_group(&g0).unwrap();
        store
            .put_message(&sample_message(mid(1), g0.id.clone(), 0))
            .unwrap();
        store
            .put_queued_outbound_intent(&sample_queued_intent(mid(10), g0.id.clone()))
            .unwrap();
        let mls_group_id = openmls::group::GroupId::from_slice(g0.id.as_slice());
        store
            .mls_storage()
            .write_group_state(&mls_group_id, &TestGroupState(b"epoch-0".to_vec()))
            .unwrap();

        store
            .create_group_state_snapshot(&g0.id, "retained-anchor")
            .unwrap();

        let g1 = sample_group(gid(1), 1, 2);
        store.put_group(&g1).unwrap();
        store
            .put_message(&sample_message(mid(2), g0.id.clone(), 1))
            .unwrap();
        store.delete_queued_outbound_intent(&mid(10)).unwrap();
        let live_queued = sample_queued_intent(mid(11), g0.id.clone());
        store.put_queued_outbound_intent(&live_queued).unwrap();
        store
            .mls_storage()
            .write_group_state(&mls_group_id, &TestGroupState(b"epoch-1".to_vec()))
            .unwrap();

        store
            .rollback_group_to_snapshot(&g0.id, "retained-anchor")
            .unwrap();

        // Canonical state rewinds to capture time...
        assert_eq!(store.get_group(&g0.id).unwrap(), g0);
        let state: Option<TestGroupState> = store.mls_storage().group_state(&mls_group_id).unwrap();
        assert_eq!(state, Some(TestGroupState(b"epoch-0".to_vec())));
        // ...while the live message ledger and outbound queue are untouched.
        let ids: Vec<_> = store
            .list_messages(&g0.id, EpochId(0))
            .unwrap()
            .into_iter()
            .map(|m| m.id)
            .collect();
        assert_eq!(ids, vec![mid(1), mid(2)]);
        assert_eq!(
            store.list_queued_outbound_intents(&g0.id).unwrap(),
            vec![live_queued]
        );
    }

    #[test]
    fn legacy_full_snapshot_blob_with_plain_array_fields_still_restores() {
        // Blobs written before state-scoped snapshots serialized `messages`
        // and `queued_outbound` as plain JSON arrays (the fields were `Vec`,
        // not `Option<Vec>`). Serde decodes those arrays as `Some(..)`, so a
        // pre-change anchor keeps its capture-time restore semantics. This
        // builds such a blob from scratch — no `Option` involved — and locks
        // that compatibility in.
        let store = SqliteAccountStorage::in_memory().unwrap();
        let anchor_group = sample_group(gid(1), 0, 1);
        let anchor_message = sample_message(mid(1), anchor_group.id.clone(), 0);
        store.put_group(&anchor_group).unwrap();

        let legacy_blob = serde_json::to_vec(&serde_json::json!({
            "group": serde_json::to_value(&anchor_group).unwrap(),
            "messages": [{
                "insert_order": 1,
                "record": serde_json::to_value(&anchor_message).unwrap(),
            }],
            "queued_outbound": [],
            "member_caps": [],
            "convergence_policy": null,
            "validated_tree_marker": null,
            "openmls_values": [],
        }))
        .unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO cgka_group_snapshots (group_id, name, snapshot)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    anchor_group.id.as_slice(),
                    "legacy-full",
                    legacy_blob.as_slice()
                ],
            )
            .unwrap();

        let live_group = sample_group(gid(1), 1, 2);
        store.put_group(&live_group).unwrap();
        store
            .put_message(&sample_message(mid(2), live_group.id.clone(), 1))
            .unwrap();

        store
            .rollback_group_to_snapshot(&live_group.id, "legacy-full")
            .unwrap();

        // Full-image semantics preserved: the legacy blob's ledger replaces
        // the live rows, exactly as before the Option change.
        assert_eq!(store.get_group(&anchor_group.id).unwrap(), anchor_group);
        assert_eq!(
            store.list_messages(&anchor_group.id, EpochId(0)).unwrap(),
            vec![anchor_message]
        );
        assert!(
            store
                .list_queued_outbound_intents(&anchor_group.id)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn group_state_checkpoint_restores_canonical_state_without_rewinding_live_work() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let g1 = sample_group(gid(1), 1, 1);
        store.put_group(&g1).unwrap();
        let mls_group_id = openmls::group::GroupId::from_slice(g1.id.as_slice());
        store
            .mls_storage()
            .write_group_state(&mls_group_id, &TestGroupState(b"branch-a".to_vec()))
            .unwrap();
        let mut branch_a_caps = GroupCapabilities::default();
        branch_a_caps.insert(Capability::Proposal(10));
        store
            .save_member_capabilities(&g1.id, &g1.members[0], branch_a_caps.clone())
            .unwrap();
        store
            .put_validated_tree_marker(&g1.id, b"branch-a-marker")
            .unwrap();
        let checkpoint = GroupStateCheckpointRef {
            id: "own-commit-a".into(),
            resulting_epoch: EpochId(1),
        };
        store
            .create_group_state_checkpoint(&g1.id, &checkpoint)
            .unwrap();
        // Exact retry is idempotent.
        store
            .create_group_state_checkpoint(&g1.id, &checkpoint)
            .unwrap();

        let g2 = sample_group(gid(1), 2, 2);
        store.put_group(&g2).unwrap();
        let live_message = sample_message(mid(2), g2.id.clone(), 2);
        let live_queue = sample_queued_intent(mid(10), g2.id.clone());
        store.put_message(&live_message).unwrap();
        store.put_queued_outbound_intent(&live_queue).unwrap();
        store
            .mls_storage()
            .write_group_state(&mls_group_id, &TestGroupState(b"branch-b".to_vec()))
            .unwrap();
        let mut branch_b_caps = GroupCapabilities::default();
        branch_b_caps.insert(Capability::Extension(11));
        store
            .save_member_capabilities(&g2.id, &g2.members[0], branch_b_caps)
            .unwrap();
        store
            .put_validated_tree_marker(&g2.id, b"branch-b-marker")
            .unwrap();

        store
            .restore_group_state_checkpoint(&g2.id, &checkpoint.id)
            .unwrap();

        assert_eq!(store.get_group(&g1.id).unwrap(), g1);
        let state: Option<TestGroupState> = store.mls_storage().group_state(&mls_group_id).unwrap();
        assert_eq!(state, Some(TestGroupState(b"branch-a".to_vec())));
        assert_eq!(
            store
                .member_capabilities(&g1.id, &g1.members[0].id)
                .unwrap(),
            Some(branch_a_caps)
        );
        assert_eq!(
            store.validated_tree_marker(&g1.id).unwrap(),
            Some(b"branch-a-marker".to_vec())
        );
        assert_eq!(
            store.list_messages(&g1.id, EpochId(0)).unwrap(),
            vec![live_message]
        );
        assert_eq!(
            store.list_queued_outbound_intents(&g1.id).unwrap(),
            vec![live_queue]
        );
    }

    #[test]
    fn group_state_checkpoint_id_is_immutable() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let g1 = sample_group(gid(1), 1, 1);
        store.put_group(&g1).unwrap();
        let checkpoint = GroupStateCheckpointRef {
            id: "own-commit-a".into(),
            resulting_epoch: EpochId(1),
        };
        store
            .create_group_state_checkpoint(&g1.id, &checkpoint)
            .unwrap();

        let g2 = sample_group(gid(1), 2, 2);
        store.put_group(&g2).unwrap();
        assert!(matches!(
            store.create_group_state_checkpoint(&g2.id, &checkpoint),
            Err(StorageError::AlreadyExists)
        ));
        assert_eq!(
            store.list_group_state_checkpoints(&g2.id).unwrap(),
            vec![checkpoint]
        );
    }

    #[test]
    fn releasing_missing_group_state_checkpoint_reports_snapshot_missing() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 1, 1);
        store.put_group(&group).unwrap();
        let checkpoint = GroupStateCheckpointRef {
            id: "own-commit-a".into(),
            resulting_epoch: EpochId(1),
        };
        store
            .create_group_state_checkpoint(&group.id, &checkpoint)
            .unwrap();

        store
            .release_group_state_checkpoint(&group.id, &checkpoint.id)
            .unwrap();
        assert!(matches!(
            store.release_group_state_checkpoint(&group.id, &checkpoint.id),
            Err(StorageError::SnapshotMissing(id)) if id == checkpoint.id
        ));
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
    fn malformed_snapshot_is_rejected_before_restore_mutates_live_state() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let live_group = sample_group(gid(1), 1, 2);
        store.put_group(&live_group).unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO cgka_group_snapshots (group_id, name, snapshot)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    live_group.id.as_slice(),
                    "malformed",
                    b"{\"openmls_values\":[[1,2,3]".as_slice()
                ],
            )
            .unwrap();

        let error = store
            .rollback_group_to_snapshot(&live_group.id, "malformed")
            .unwrap_err();

        assert!(matches!(error, StorageError::Serialization(_)));
        assert_eq!(store.get_group(&live_group.id).unwrap(), live_group);
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

    #[cfg(feature = "test-conformance-replay")]
    #[test]
    fn conformance_replay_snapshot_round_trips_into_a_fresh_database() {
        use cgka_traits::convergence_pass::{
            ConvergenceCutoffCause, ConvergencePassMember, ConvergencePassMemberRole,
            ConvergencePassPhase, DurableConvergencePass,
        };
        use cgka_traits::storage::ConvergencePassStorage;

        let source = SqliteAccountStorage::in_memory().unwrap();
        let group = sample_group(gid(1), 3, 2);
        source.put_group(&group).unwrap();
        source
            .put_message(&sample_message(mid(7), group.id.clone(), 3))
            .unwrap();
        let mls_group_id = openmls::group::GroupId::from_slice(group.id.as_slice());
        source
            .mls_storage()
            .write_group_state(&mls_group_id, &TestGroupState(b"captured-state".to_vec()))
            .unwrap();
        let pass = DurableConvergencePass {
            group_id: group.id.clone(),
            generation: 9,
            phase: ConvergencePassPhase::Frozen,
            base_epoch: EpochId(3),
            clock_instance_id: 42,
            opened_monotonic_ms: 100,
            quiescence_deadline_monotonic_ms: 1_100,
            absolute_deadline_monotonic_ms: 5_100,
            opened_wall_ms: 200,
            quiescence_deadline_wall_ms: 1_200,
            absolute_deadline_wall_ms: 5_200,
            members: vec![ConvergencePassMember {
                message_id: mid(7),
                payload_digest: [8; 32],
                role: ConvergencePassMemberRole::CommitEdge,
                source_epoch: 3,
            }],
            frozen_at_wall_ms: Some(1_200),
            cutoff_cause: Some(ConvergenceCutoffCause::Quiescence),
            fairness_slot_available: false,
        };
        source.put_convergence_pass(&pass).unwrap();

        let snapshot = source
            .export_conformance_replay_snapshot(&group.id)
            .unwrap();
        let restored = SqliteAccountStorage::in_memory().unwrap();
        restored
            .import_conformance_replay_snapshot(&group.id, &snapshot)
            .unwrap();

        assert_eq!(restored.get_group(&group.id).unwrap(), group);
        assert_eq!(
            restored
                .list_messages(&group.id, cgka_traits::types::EpochId(0))
                .unwrap(),
            source
                .list_messages(&group.id, cgka_traits::types::EpochId(0))
                .unwrap()
        );
        let state: Option<TestGroupState> =
            restored.mls_storage().group_state(&mls_group_id).unwrap();
        assert_eq!(state, Some(TestGroupState(b"captured-state".to_vec())));
        assert_eq!(restored.convergence_pass(&group.id).unwrap(), Some(pass));

        assert!(matches!(
            restored.import_conformance_replay_snapshot(&gid(2), &snapshot),
            Err(StorageError::Serialization(message))
                if message == "conformance replay snapshot group id mismatch"
        ));
    }
}
