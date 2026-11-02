//! Orphan recovery must not retire its repair signal before its mirror is durable.

use super::*;
use cgka_traits::engine::GroupHydrationQuarantineReason;
use cgka_traits::error::EngineError;
use cgka_traits::group::{Group, Member};
use cgka_traits::message::MessageRecord;
use cgka_traits::storage::{
    MaintenanceStorage, OutboundFanoutStorage, StorageError, StorageProvider,
};
use cgka_traits::types::GroupId;
use openmls::prelude::{BasicCredential, MlsGroup};
use rusqlite::{Connection, types::Value};
use storage_sqlite::{SqlCipherHardening, open_hardened_sqlcipher};

fn observer(path: &std::path::Path, key: &SqlCipherKey) -> Connection {
    let connection = Connection::open(path).unwrap();
    open_hardened_sqlcipher(&connection, key, SqlCipherHardening::live_cache()).unwrap();
    connection
}

fn member_ids(members: &[Member]) -> Vec<Vec<u8>> {
    let mut ids: Vec<_> = members.iter().map(|m| m.id.as_slice().to_vec()).collect();
    ids.sort();
    ids
}

struct DurableState {
    group: Group,
    mls_epoch: EpochId,
    mls_members: Vec<Vec<u8>>,
    pending: bool,
    welcome_state: MessageState,
    welcome_staged: bool,
    welcome_outbound: bool,
    welcome: MessageRecord,
    welcome_row: Vec<Value>,
    mls_rows: Vec<Vec<Value>>,
}

fn durable_state(
    storage: &SqliteAccountStorage,
    observer: &Connection,
    group_id: &GroupId,
    welcome_id: &MessageId,
) -> DurableState {
    // The mirror and complete Welcome payload are read through a distinct
    // SQLCipher connection, not the engine's record or MLS cache.
    let (epoch_column, record): (i64, Vec<u8>) = observer
        .query_row(
            "SELECT epoch, record FROM cgka_groups WHERE id = ?1",
            [group_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let group: Group = serde_json::from_slice(&record).unwrap();
    assert_eq!(group.epoch, EpochId(epoch_column.try_into().unwrap()));
    assert_eq!(storage.get_group(group_id).unwrap(), group);
    let (state, payload): (i64, Vec<u8>) = observer
        .query_row(
            "SELECT state, payload FROM cgka_messages WHERE id = ?1",
            [welcome_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let welcome = storage.get_message(welcome_id).unwrap();
    assert_eq!(
        state,
        match welcome.state {
            MessageState::Sent => 0,
            MessageState::Failed => 3,
            other => panic!("unexpected Welcome state: {other:?}"),
        }
    );
    assert_eq!(welcome.payload, payload);
    let payload = StoredMessagePayload::decode(&payload).unwrap();
    let welcome_row = observer
        .query_row(
            "SELECT id, group_id, epoch, state, storage_format, record, payload, deferred_peel
             FROM cgka_messages WHERE id = ?1",
            [welcome_id.as_slice()],
            |row| (0..8).map(|index| row.get(index)).collect(),
        )
        .unwrap();
    let group_key =
        serde_json::to_vec(&openmls::group::GroupId::from_slice(group_id.as_slice())).unwrap();
    let mls_rows = observer
        .prepare("SELECT label, storage_key, value FROM openmls_values WHERE group_key = ?1 ORDER BY storage_key")
        .unwrap()
        .query_map([group_key], |row| (0..3).map(|index| row.get(index)).collect())
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();

    // A fresh OpenMLS load reads the actual current tree and pending state.
    // Public members() deliberately reads the projected Marmot record.
    let mls_group = MlsGroup::load(
        storage.mls_storage(),
        &openmls::group::GroupId::from_slice(group_id.as_slice()),
    )
    .unwrap()
    .unwrap();
    let mut mls_members: Vec<_> = mls_group
        .members()
        .map(|member| {
            BasicCredential::try_from(member.credential)
                .unwrap()
                .identity()
                .to_vec()
        })
        .collect();
    mls_members.sort();
    DurableState {
        group,
        mls_epoch: EpochId(mls_group.epoch().as_u64()),
        mls_members,
        pending: mls_group.pending_commit().is_some(),
        welcome_state: welcome.state,
        welcome_staged: payload.as_staged_invite_welcome().is_some(),
        welcome_outbound: payload.as_outbound_welcome().is_some(),
        welcome,
        welcome_row,
        mls_rows,
    }
}

fn report(phase: &str, state: &DurableState) {
    eprintln!(
        "{phase}: mirror_epoch={} mirror_members={} mls_epoch={} mls_members={} pending={} welcome_state={:?} staged_welcome={} outbound_welcome={}",
        state.group.epoch.0,
        state.group.members.len(),
        state.mls_epoch.0,
        state.mls_members.len(),
        state.pending,
        state.welcome_state,
        state.welcome_staged,
        state.welcome_outbound,
    );
}

fn assert_recovered(
    engine: &cgka_engine::Engine<SqliteAccountStorage>,
    group_id: &GroupId,
    state: &DurableState,
    expected_members: &[Vec<u8>],
) {
    assert_eq!(engine.epoch(group_id).unwrap(), EpochId(1));
    assert_eq!(engine.group_context(group_id).unwrap().epoch(), EpochId(1));
    assert_eq!(state.mls_epoch, EpochId(1));
    assert_eq!(state.group.epoch, EpochId(1));
    assert!(!state.pending);
    assert_eq!(state.welcome_state, MessageState::Failed);
    assert!(!state.welcome_staged);
    assert!(state.welcome_outbound);
    assert_eq!(state.mls_members, expected_members);
    assert_eq!(
        member_ids(&state.group.members),
        state.mls_members,
        "recovery retry must not expose the canceled invitee in the durable mirror"
    );
    assert_eq!(
        member_ids(&engine.members(group_id).unwrap()),
        state.mls_members,
        "public roster must agree with fresh OpenMLS after recovery"
    );
    assert_eq!(engine.group_record(group_id).unwrap(), state.group);
}

/// Healthy recovery runs first with the identical staged-invite fixture. The
/// fault then aborts precisely the mirror rollback, followed by explicit full
/// hydration retry and another physical close/reopen.
#[tokio::test]
async fn orphan_recovery_mirror_failure_remains_retryable() {
    for inject_failure in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alice.sqlite");
        let key = SqlCipherKey::raw([0x63; 32]);
        let group_id;
        let baseline;
        let welcome_id;
        let mut expected_members = vec![
            pad32(b"alice-recovery-mirror"),
            pad32(b"bob-recovery-mirror"),
        ];
        expected_members.sort();

        {
            let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            let mut alice = build_client(storage.clone(), b"alice-recovery-mirror");
            let mut bob = build_client(
                SqliteAccountStorage::in_memory_for_test().unwrap(),
                b"bob-recovery-mirror",
            );
            let mut carol = build_client(
                SqliteAccountStorage::in_memory_for_test().unwrap(),
                b"carol-recovery-mirror",
            );
            let (id, result) = alice
                .create_group(CreateGroupRequest {
                    name: "recovery mirror".into(),
                    description: "".into(),
                    members: vec![bob.fresh_key_package().await.unwrap()],
                    required_features: vec![],
                    app_components: vec![],
                    initial_admins: vec![],
                })
                .await
                .unwrap();
            group_id = id;
            let SendResult::GroupCreated { pending, .. } = result else {
                panic!("expected legacy staged creation");
            };
            alice.confirm_published(pending).await.unwrap();
            baseline = alice.group_record(&group_id).unwrap();
            assert_eq!(baseline.epoch, EpochId(1));
            assert_eq!(member_ids(&baseline.members), expected_members);
            let result = alice
                .send(SendIntent::Invite {
                    group_id: group_id.clone(),
                    key_packages: vec![carol.fresh_key_package().await.unwrap()],
                    initial_admins: vec![],
                })
                .await
                .unwrap();
            let SendResult::GroupEvolution { welcomes, .. } = result else {
                panic!("expected staged invite");
            };
            assert_eq!(welcomes.len(), 1);
            welcome_id = welcomes[0].id.clone();
            assert!(
                storage
                    .list_outbound_fanouts_for_group(&group_id)
                    .unwrap()
                    .is_empty()
            );
            assert!(
                storage
                    .list_group_evolutions_for_group(&group_id)
                    .unwrap()
                    .is_empty()
            );
            // No publish outcome, fanout or durable evolution is recorded.
            // Drop every handle so the next phase uses a physical reopen.
        }

        let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let observer = observer(&path, &key);
        let before = durable_state(&storage, &observer, &group_id, &welcome_id);
        report("before hydrate", &before);
        assert_eq!(before.group.epoch, EpochId(1));
        assert_eq!(before.group.members.len(), 3);
        assert_eq!(before.mls_members, expected_members);
        assert!(before.pending);
        assert_eq!(before.welcome_state, MessageState::Sent);
        assert!(before.welcome_staged);
        assert!(!before.welcome_outbound);

        if inject_failure {
            // The trigger is temporary to this fixture, shared with the real
            // engine connection, and refuses only this group's mirror change.
            observer
                .execute_batch(&format!(
                    "CREATE TRIGGER fail_orphan_recovery_mirror BEFORE UPDATE ON cgka_groups
                 WHEN NEW.id = X'{}' AND NEW.record <> OLD.record
                 BEGIN SELECT RAISE(ABORT, 'injected orphan recovery mirror write failure'); END",
                    hex::encode(group_id.as_slice()),
                ))
                .unwrap();
            let failure = storage.put_group(&baseline);
            assert!(
                matches!(&failure, Err(StorageError::Backend(detail))
                if detail.contains("injected orphan recovery mirror write failure")),
                "the mirror fault must match its exact injected cause: {failure:?}"
            );
        }
        let mut alice = build_client(storage.clone(), b"alice-recovery-mirror");
        alice.hydrate_all_stored_groups().unwrap();
        let after = durable_state(&storage, &observer, &group_id, &welcome_id);
        report(
            if inject_failure {
                "failed hydrate"
            } else {
                "healthy hydrate"
            },
            &after,
        );

        if inject_failure {
            assert_eq!(
                alice.quarantined_groups(),
                vec![(
                    group_id.clone(),
                    GroupHydrationQuarantineReason::PendingCommitRecoveryFailed
                )]
            );
            assert!(
                matches!(alice.members(&group_id), Err(EngineError::UnknownGroup(id)) if id == group_id)
            );
            assert!(
                !alice
                    .drain_events()
                    .iter()
                    .any(|event| matches!(event, GroupEvent::PendingCommitRecovered { .. }))
            );
            assert_eq!(
                after.group, before.group,
                "failed recovery keeps the complete projected record"
            );
            assert!(
                after.pending,
                "failed mirror write must retain the pending-commit recovery signal"
            );
            assert_eq!(
                after.mls_rows, before.mls_rows,
                "failed recovery rolls back every OpenMLS write"
            );
            assert_eq!(
                after.welcome, before.welcome,
                "failed recovery keeps the complete staged Welcome"
            );
            assert_eq!(
                after.welcome_row, before.welcome_row,
                "the independent connection must see the original Welcome row"
            );
            observer
                .execute_batch("DROP TRIGGER fail_orphan_recovery_mirror")
                .unwrap();
            assert!(alice.retry_hydrate_quarantined_group(&group_id).unwrap());
            assert!(alice.quarantined_groups().is_empty());
            let retried = durable_state(&storage, &observer, &group_id, &welcome_id);
            report("healed explicit retry", &retried);
            eprintln!(
                "retry public: epoch={} context_epoch={} members={} record_members={}",
                alice.epoch(&group_id).unwrap().0,
                alice.group_context(&group_id).unwrap().epoch().0,
                alice.members(&group_id).unwrap().len(),
                alice.group_record(&group_id).unwrap().members.len()
            );
            assert_recovered(&alice, &group_id, &retried, &expected_members);
        } else {
            assert!(alice.quarantined_groups().is_empty());
            assert!(alice.drain_events().iter().any(|event| matches!(event,
                GroupEvent::PendingCommitRecovered { group_id: id, recovered_epoch: EpochId(1) } if id == &group_id)));
            assert_recovered(&alice, &group_id, &after, &expected_members);
        }
        drop(alice);
        drop(storage);
        drop(observer);

        let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let observer = self::observer(&path, &key);
        let mut alice = build_client(storage.clone(), b"alice-recovery-mirror");
        alice.hydrate_all_stored_groups().unwrap();
        let reopened = durable_state(&storage, &observer, &group_id, &welcome_id);
        report(
            if inject_failure {
                "reopen after healed retry"
            } else {
                "healthy reopen"
            },
            &reopened,
        );
        assert_recovered(&alice, &group_id, &reopened, &expected_members);
    }
}
