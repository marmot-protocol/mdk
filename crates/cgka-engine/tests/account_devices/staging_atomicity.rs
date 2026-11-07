//! Late device-operation staging faults must leave no unowned outbound rows.

use super::device_roster::{
    NO_WELCOME_DEADLINE, entry, expect_link_welcome, found_device_group, key_package_ref, roster,
    roster_device, roster_device_on, slot,
};
use super::tagged_siblings::{
    assert_joins_from, chat_device, handed, owed, routed_members, tag_devices,
};
use super::*;
use cgka_traits::app_components::{
    DeviceEntryV1, DeviceRosterOperationV1, DeviceRosterUpdateV1, encode_device_roster_update_v1,
};
use cgka_traits::storage::{GroupStorage, StorageError};
use cgka_traits::types::EpochId;
use storage_sqlite::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};

#[derive(Clone, Copy, Debug)]
enum StagingKind {
    Link,
    Sibling,
}

#[tokio::test]
async fn late_link_projection_failure_preserves_the_complete_staging_owner() {
    late_staging_failure(StagingKind::Link).await;
}

#[tokio::test]
async fn late_same_account_add_projection_failure_preserves_the_complete_staging_owner() {
    late_staging_failure(StagingKind::Sibling).await;
}

fn independent_rows(
    connection: &rusqlite::Connection,
) -> std::collections::BTreeMap<String, Vec<Vec<rusqlite::types::Value>>> {
    let tables = connection
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let mut statement = connection
                .prepare(&format!("SELECT * FROM \"{table}\""))
                .unwrap();
            let columns = statement.column_count();
            let mut rows = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get::<_, rusqlite::types::Value>(column))
                        .collect::<Result<Vec<_>, _>>()
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            rows.sort_by_cached_key(|row| format!("{row:?}"));
            (table, rows)
        })
        .collect()
}

async fn late_staging_failure(kind: StagingKind) {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("device-staging.sqlite");
    let key = SqlCipherKey::raw([0xa6; 32]);
    let storage = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
    let (mut sender, mut target, group_id, device_group, intent, key_package) = match kind {
        StagingKind::Link => {
            let mut phone = roster_device_on(storage.clone(), b"alice");
            let mut laptop = roster_device(b"alice");
            let gid = found_device_group(
                &mut phone,
                &roster(&[(1, "Phone"), (2, "Laptop")]),
                &mut [&mut laptop],
            )
            .await;
            let mut tablet = roster_device(b"alice");
            let key_package = tablet.engine.fresh_key_package().await.unwrap();
            let update = DeviceRosterUpdateV1::new(vec![DeviceRosterOperationV1::SetDevice(
                slot(3),
                DeviceEntryV1 {
                    linked_by: Some(slot(1)),
                    announced_key_package: Some(key_package_ref(&key_package)),
                    ..entry("Tablet")
                },
            )])
            .unwrap();
            let intent = SendIntent::LinkDevice {
                group_id: gid.clone(),
                key_package: key_package.clone(),
                roster_update: encode_device_roster_update_v1(&update).unwrap(),
                deliver_until: NO_WELCOME_DEADLINE,
            };
            (phone, tablet, gid, None, intent, Some(key_package))
        }
        StagingKind::Sibling => {
            let (bob, mut new, device_gid) = tag_devices(vec![
                roster_device_on(storage.clone(), b"bob"),
                roster_device(b"bob"),
            ])
            .await;
            let mut laptop = new.remove(0);
            let members = routed_members(chat_device(b"alice"), bob).await;
            let private = handed(&mut laptop, slot(2), slot(1));
            let intent = add_own_devices(&members.gid, vec![private]);
            (
                members.bob,
                laptop,
                members.gid,
                Some(device_gid),
                intent,
                None,
            )
        }
    };
    sender.engine.drain_events();
    let before_record = storage.get_group(&group_id).unwrap();
    let before_messages = storage.list_messages(&group_id, EpochId(0)).unwrap();
    let observer = rusqlite::Connection::open(&database).unwrap();
    open_hardened_sqlcipher(&observer, &key, SqlCipherHardening::live_cache()).unwrap();
    let before = independent_rows(&observer);
    // This fixture's wrapper id is the MLS content id, so staging adds
    // exactly its signed Commit and one transport or sibling Welcome row.
    observer
        .execute_batch(&format!(
            "CREATE TRIGGER fail_device_staging_projection BEFORE UPDATE ON cgka_groups
         WHEN NEW.id = X'{}' AND json_array_length(json_extract(NEW.record, '$.members')) = {}
          AND (SELECT COUNT(*) FROM cgka_messages WHERE group_id = NEW.id) = {}
         BEGIN SELECT RAISE(ABORT, 'device-staging-projection-fault'); END;",
            hex::encode(group_id.as_slice()),
            before_record.members.len() + 1,
            before_messages.len() + 2
        ))
        .unwrap();
    let failed = sender.engine.send(intent.clone()).await;
    assert!(
        matches!(&failed,Err(EngineError::Storage(StorageError::Backend(detail))) if detail.contains("device-staging-projection-fault")),
        "{kind:?}: final projection must be the failing step: {failed:?}"
    );
    let after_messages = storage.list_messages(&group_id, EpochId(0)).unwrap();
    assert!(
        after_messages == before_messages,
        "{kind:?}: late account-device staging left unowned artifacts ({} before, {} after)",
        before_messages.len(),
        after_messages.len(),
    );
    assert_eq!(
        independent_rows(&observer),
        before,
        "{kind:?}: staging failure changed durable protocol state"
    );
    assert_eq!(
        sender.engine.group_record(&group_id).unwrap(),
        before_record
    );
    assert!(sender.engine.epoch_state(&group_id).unwrap().is_stable());
    assert!(load_group(&sender, &group_id).pending_commit().is_none());
    assert!(sender.engine.drain_events().is_empty());
    drop(sender);
    drop(observer);
    storage.close().unwrap();
    drop(storage);
    let storage = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
    let observer = rusqlite::Connection::open(&database).unwrap();
    open_hardened_sqlcipher(&observer, &key, SqlCipherHardening::live_cache()).unwrap();
    assert_eq!(
        independent_rows(&observer),
        before,
        "{kind:?}: failed staging changed after physical reopen"
    );
    observer
        .execute_batch("DROP TRIGGER fail_device_staging_projection")
        .unwrap();
    let identity = match kind {
        StagingKind::Link => b"alice".as_slice(),
        StagingKind::Sibling => b"bob".as_slice(),
    };
    let mut sender = roster_device_on(storage.clone(), identity);
    sender.engine.hydrate_all_stored_groups().unwrap();
    if let Some(device_gid) = device_group {
        sender
            .engine
            .set_device_tag_group(Some(device_gid))
            .unwrap();
    }
    let SendResult::GroupEvolution {
        pending, welcomes, ..
    } = sender.engine.send(intent).await.unwrap()
    else {
        panic!("{kind:?}: expected staged retry")
    };
    sender.engine.confirm_published(pending).await.unwrap();
    match kind {
        StagingKind::Link => {
            assert_eq!(welcomes.len(), 1);
            expect_link_welcome(
                &mut target,
                &group_id,
                &sender,
                key_package.as_ref().unwrap(),
            );
            assert_joins(&mut target, &welcomes[0], &group_id, &sender).await;
        }
        StagingKind::Sibling => {
            assert!(welcomes.is_empty());
            let owed = owed(&sender);
            assert_eq!(owed.len(), 1);
            assert_joins_from(&mut target, &owed[0], &group_id, &sender).await;
        }
    }
    assert_eq!(
        sender.engine.epoch(&group_id).unwrap().0,
        before_record.epoch.0 + 1
    );
    assert_eq!(
        load_group(&sender, &group_id).members().count(),
        before_record.members.len() + 1
    );
    drop(sender);
    drop(observer);
    storage.close().unwrap();
    drop(storage);
    let storage = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
    let mut restarted = roster_device_on(storage, identity);
    restarted.engine.hydrate_all_stored_groups().unwrap();
    assert_eq!(
        restarted.engine.epoch(&group_id).unwrap().0,
        before_record.epoch.0 + 1
    );
    assert_eq!(
        load_group(&restarted, &group_id).members().count(),
        before_record.members.len() + 1
    );
}
