//! Process termination during orphan-pending recovery keeps the whole durable unit (#2422).

use super::*;
use cgka_traits::group::Group;
use cgka_traits::storage::{MaintenanceStorage, OutboundFanoutStorage, StorageProvider};
use openmls::prelude::MlsGroup;
use rusqlite::{Connection, types::Value};
use storage_sqlite::{SqlCipherHardening, open_hardened_sqlcipher};

pub(super) const POINT: &str = "orphan-pending-after-clear";
const KEY: [u8; 32] = [0x64; 32];
const ALICE: &[u8] = b"orphan-crash-alice";
const BOB: &[u8] = b"orphan-crash-bob";
const CAROL: &[u8] = b"orphan-crash-carol";

fn observer(path: &Path) -> Connection {
    let connection = Connection::open(path).unwrap();
    open_hardened_sqlcipher(
        &connection,
        &SqlCipherKey::raw(KEY),
        SqlCipherHardening::live_cache(),
    )
    .unwrap();
    connection
}

fn stored_rows(
    connection: &Connection,
    group: &GroupId,
) -> (Group, Vec<Vec<Value>>, Vec<Vec<Value>>) {
    let (epoch, record): (i64, Vec<u8>) = connection
        .query_row(
            "SELECT epoch, record FROM cgka_groups WHERE id = ?1",
            [group.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let record: Group = serde_json::from_slice(&record).unwrap();
    assert_eq!(record.epoch.0, u64::try_from(epoch).unwrap());
    let messages = connection
        .prepare(
            "SELECT id, group_id, epoch, state, storage_format, record, payload, deferred_peel
         FROM cgka_messages WHERE group_id = ?1 ORDER BY id",
        )
        .unwrap()
        .query_map([group.as_slice()], |row| {
            (0..8).map(|index| row.get(index)).collect()
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let group_key =
        serde_json::to_vec(&openmls::group::GroupId::from_slice(group.as_slice())).unwrap();
    let mls = connection.prepare(
        "SELECT label, storage_key, value FROM openmls_values WHERE group_key = ?1 ORDER BY storage_key"
    ).unwrap().query_map([group_key], |row| (0..3).map(|index| row.get(index)).collect())
        .unwrap().collect::<rusqlite::Result<_>>().unwrap();
    (record, messages, mls)
}

fn load_mls(storage: &SqliteAccountStorage, group: &GroupId) -> MlsGroup {
    MlsGroup::load(
        storage.mls_storage(),
        &openmls::group::GroupId::from_slice(group.as_slice()),
    )
    .unwrap()
    .unwrap()
}

fn assert_recovered(
    engine: &Engine<SqliteAccountStorage>,
    storage: &SqliteAccountStorage,
    group: &GroupId,
) {
    let mut expected = vec![identity(ALICE), identity(BOB)];
    expected.sort();
    let mut actual: Vec<_> = engine
        .members(group)
        .unwrap()
        .iter()
        .map(|member| member.id.as_slice().to_vec())
        .collect();
    actual.sort();
    assert_eq!(actual, expected);
    assert_eq!(engine.epoch(group).unwrap(), EpochId(1));
    assert_eq!(engine.group_context(group).unwrap().epoch(), EpochId(1));
    assert_eq!(
        engine.group_record(group).unwrap(),
        storage.get_group(group).unwrap()
    );
    let mls = load_mls(storage, group);
    assert_eq!(mls.epoch().as_u64(), 1);
    assert_eq!(mls.members().count(), 2);
    assert!(mls.pending_commit().is_none());
}

#[tokio::test]
async fn kill_during_orphan_pending_recovery_preserves_retryable_state() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let group;
    let welcome;
    let before;
    {
        let storage =
            SqliteAccountStorage::open_encrypted(&database, &SqlCipherKey::raw(KEY)).unwrap();
        let mut alice = build_client_with_storage(ALICE, storage.clone());
        let (mut bob, _) = build_memory_client(BOB);
        let (mut carol, _) = build_memory_client(CAROL);
        let (id, created) = alice
            .create_group(CreateGroupRequest {
                name: "orphan recovery crash".into(),
                description: String::new(),
                members: vec![bob.fresh_key_package().await.unwrap()],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        group = id;
        let SendResult::GroupCreated { pending, .. } = created else {
            panic!("expected legacy create")
        };
        alice.confirm_published(pending).await.unwrap();
        let invited = alice
            .send(SendIntent::Invite {
                group_id: group.clone(),
                key_packages: vec![carol.fresh_key_package().await.unwrap()],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        let SendResult::GroupEvolution { welcomes, .. } = invited else {
            panic!("expected invite")
        };
        assert_eq!(welcomes.len(), 1);
        welcome = storage.get_message(&welcomes[0].id).unwrap();
        assert_eq!(welcome.state, MessageState::Sent);
        assert!(
            StoredMessagePayload::decode(&welcome.payload)
                .unwrap()
                .as_staged_invite_welcome()
                .is_some()
        );
        assert!(
            storage
                .list_outbound_fanouts_for_group(&group)
                .unwrap()
                .is_empty()
        );
        assert!(
            storage
                .list_group_evolutions_for_group(&group)
                .unwrap()
                .is_empty()
        );
        assert_eq!(load_mls(&storage, &group).members().count(), 2);
        assert!(load_mls(&storage, &group).pending_commit().is_some());
        before = stored_rows(&observer(&database), &group);
        assert_eq!(before.0.members.len(), 3);
    }

    // The existing harness requires this exact child's ready marker before
    // killing it, so a missing child or missed pause point cannot pass.
    spawn_crash_child(&database, POINT, &[]).kill_when_ready();
    let storage = SqliteAccountStorage::open_encrypted(&database, &SqlCipherKey::raw(KEY)).unwrap();
    let connection = observer(&database);
    let after = stored_rows(&connection, &group);
    let mls = load_mls(&storage, &group);
    let retained_welcome = storage.get_message(&welcome.id).unwrap();
    eprintln!(
        "killed recovery before hydration: mirror_members={} mls_members={} pending={} welcome_state={:?}",
        after.0.members.len(),
        mls.members().count(),
        mls.pending_commit().is_some(),
        retained_welcome.state
    );
    assert!(
        mls.pending_commit().is_some(),
        "termination must roll back the clear until the corrected mirror is durable"
    );
    assert_eq!(
        after.0, before.0,
        "the complete mirror survives the aborted recovery"
    );
    assert!(
        after.1 == before.1,
        "the independent connection sees every original complete message row"
    );
    assert!(
        after.2 == before.2,
        "the independent connection sees the original OpenMLS state"
    );
    assert_eq!(
        retained_welcome, welcome,
        "the complete staged Welcome must be retryable"
    );
    drop(mls);
    let mut alice = build_client_with_storage(ALICE, storage.clone());
    alice.hydrate_all_stored_groups().unwrap();
    assert_recovered(&alice, &storage, &group);
    assert!(alice.drain_events().iter().any(|event| matches!(event, GroupEvent::PendingCommitRecovered { group_id, recovered_epoch: EpochId(1) } if group_id == &group)));
    let welcome = storage.get_message(&welcome.id).unwrap();
    assert_eq!(welcome.state, MessageState::Failed);
    assert!(
        StoredMessagePayload::decode(&welcome.payload)
            .unwrap()
            .as_outbound_welcome()
            .is_some()
    );
    drop(alice);
    drop(storage);
    drop(connection);
    let storage = SqliteAccountStorage::open_encrypted(&database, &SqlCipherKey::raw(KEY)).unwrap();
    let mut alice = build_client_with_storage(ALICE, storage.clone());
    alice.hydrate_all_stored_groups().unwrap();
    assert_recovered(&alice, &storage, &group);
}

pub(super) async fn run_child(database: &Path) {
    let storage = SqliteAccountStorage::open_encrypted(database, &SqlCipherKey::raw(KEY)).unwrap();
    let mut alice = build_client_with_storage(ALICE, storage);
    alice.hydrate_all_stored_groups().unwrap();
}
