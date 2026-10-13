//! Frozen master writer, including account-only capability rows in v2 snapshots.
use super::{MIGRATIONS, run};
use crate::{SqlCipherHardening, SqlCipherKey, SqliteAccountStorage, open_hardened_sqlcipher};
use cgka_traits::capabilities::{Capability, GroupCapabilities};
use cgka_traits::group::Member;
use cgka_traits::storage::{CapabilityStorage, GroupStorage, MessageStorage, StorageError};
use cgka_traits::{GroupId, MemberId};

const FIXTURE: &str = include_str!("../../fixtures/account-c27300be.sql");

#[test]
fn populated_master_c27300be_upgrades_capabilities_and_restores_historical_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let key = SqlCipherKey::new("round4 upgrade test key").unwrap();
    fs_private::create_new_private(&path).unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    open_hardened_sqlcipher(&connection, &key, SqlCipherHardening::live_cache()).unwrap();
    // A SQL dump loads dependent tables before their referenced tables.
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    connection.execute_batch(FIXTURE).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .unwrap();
    let retained =
        |connection: &rusqlite::Connection| {
            [
            "SELECT snapshot FROM cgka_group_snapshots ORDER BY group_id, name",
            "SELECT checkpoint FROM cgka_group_state_checkpoints ORDER BY group_id, checkpoint_id",
        ].map(|sql| {
            connection.prepare(sql).unwrap().query_map([], |row| row.get::<_, Vec<u8>>(0))
                .unwrap().collect::<Result<Vec<_>, _>>().unwrap()
        })
        };
    let before = retained(&connection);
    assert!(before.iter().all(|rows| rows.len() == 2));
    assert!(
        before
            .iter()
            .flatten()
            .all(|blob| blob.starts_with(b"MDKS\x00\x02"))
    );
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM cgka_schema_migrations", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        107
    );
    connection.close().unwrap();

    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut expected = GroupCapabilities::default();
    expected.insert(Capability::Proposal(10));
    expected.insert(Capability::Extension(42));
    for n in [1, 2] {
        let id = GroupId::new(vec![n; 4]);
        assert_eq!(store.get_group(&id).unwrap().members.len(), 2);
        for member in [0, 1] {
            assert_eq!(
                store
                    .member_capabilities(&id, &MemberId::new(vec![member; 4]))
                    .unwrap(),
                Some(expected.clone())
            );
        }
        let record: Vec<u8> = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT capabilities FROM cgka_member_capabilities WHERE group_id = ?1 LIMIT 1",
                [id.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&record).unwrap()["version"],
            2
        );
        // Both restore paths must retain old single-leaf knowledge even when
        // the first subsequent write is for a new sibling device.
        for checkpoint in [false, true] {
            if checkpoint {
                store
                    .restore_group_state_checkpoint(&id, "master-checkpoint")
                    .unwrap();
            } else {
                store
                    .rollback_group_to_snapshot(&id, "master-snapshot")
                    .unwrap();
            }
            let mut group = store.get_group(&id).unwrap();
            let sibling = Member {
                id: group.members[0].id.clone(),
                credential: vec![9; 8],
            };
            store
                .save_member_capabilities(&id, &sibling, expected.clone())
                .unwrap();
            group.members.push(sibling.clone());
            store.put_group(&group).unwrap();
            assert_eq!(
                store.member_capabilities(&id, &sibling.id).unwrap(),
                Some(expected.clone())
            );
        }
    }
    assert_eq!(
        retained(&store.lock().unwrap()),
        before,
        "open must not rewrite historical snapshots"
    );
    store.close().unwrap();
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let connection = reopened.lock().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM cgka_schema_migrations WHERE version = 108",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    drop(connection);
    reopened.close().unwrap();
    let mut connection = rusqlite::Connection::open(&path).unwrap();
    open_hardened_sqlcipher(&connection, &key, SqlCipherHardening::live_cache()).unwrap();
    assert!(matches!(
        run(&mut connection, &MIGRATIONS[..107]),
        Err(StorageError::UnsupportedSchemaVersion {
            found: 108,
            latest_supported: 107
        })
    ));
}
