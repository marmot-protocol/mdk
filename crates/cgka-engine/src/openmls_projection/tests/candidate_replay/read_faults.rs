//! Selective backend read failures at the native replay wrappers (#3171).

use super::*;
use crate::openmls_projection::{
    OpenMlsProjectionError, PrevalidatedOwnCommits, process_openmls_messages_inner,
    project_mls_message, retained_anchor_snapshot_name, update_group_record_from_replay,
};
use rusqlite::{Connection, types::Value};
use std::collections::{BTreeMap, BTreeSet};
use storage_sqlite::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};

fn observer(path: &std::path::Path, key: &SqlCipherKey) -> Connection {
    let observer = Connection::open(path).unwrap();
    open_hardened_sqlcipher(&observer, key, SqlCipherHardening::live_cache()).unwrap();
    observer
}

fn native_context(connection: &Connection, group: &GroupId) -> (Vec<u8>, Vec<u8>) {
    let group_key =
        serde_json::to_vec(&openmls::group::GroupId::from_slice(group.as_slice())).unwrap();
    connection
        .query_row(
            "SELECT storage_key, value FROM openmls_values
             WHERE label = ?1 AND group_key = ?2",
            rusqlite::params![b"GroupContext".as_slice(), group_key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

fn replace_context(connection: &Connection, key: &[u8], value: &[u8]) {
    assert_eq!(
        connection
            .execute(
                "UPDATE openmls_values SET value = ?1 WHERE storage_key = ?2",
                rusqlite::params![value, key],
            )
            .unwrap(),
        1
    );
}

fn protocol_rows(connection: &Connection) -> BTreeMap<String, Vec<Vec<Value>>> {
    let tables = connection
        .prepare(
            "SELECT name FROM sqlite_schema WHERE type='table'
             AND (name LIKE 'cgka_%' OR name LIKE 'openmls_%') ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    tables
        .into_iter()
        .map(|name| {
            let mut statement = connection
                .prepare(&format!("SELECT * FROM {name}"))
                .unwrap();
            let columns = statement.column_count();
            let order = (1..=columns)
                .map(|column| column.to_string())
                .collect::<Vec<_>>()
                .join(",");
            statement = connection
                .prepare(&format!("SELECT * FROM {name} ORDER BY {order}"))
                .unwrap();
            let rows = statement
                .query_map([], |row| {
                    (0..columns).map(|column| row.get(column)).collect()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            (name, rows)
        })
        .collect()
}

fn assert_storage<T>(result: &Result<T, OpenMlsProjectionError>, prefix: &str) {
    assert!(
        matches!(result, Err(OpenMlsProjectionError::Storage(reason) | OpenMlsProjectionError::Replay(reason)) if reason.starts_with(prefix)),
        "fault must reach the exact named backend wrapper"
    );
    assert!(
        matches!(result, Err(OpenMlsProjectionError::Storage(reason)) if reason.starts_with(prefix)),
        "the exact replay backend read must retain its infrastructure category"
    );
}

async fn peer_add(sender: &mut Engine<SqliteAccountStorage>, group: &GroupId) -> TransportMessage {
    let (mut new_member, _) = build_client(b"read-fault-real-invitee");
    let package = new_member.fresh_key_package().await.unwrap();
    let SendResult::GroupEvolution { msg, pending, .. } = sender
        .send(SendIntent::Invite {
            group_id: group.clone(),
            key_packages: vec![package],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    else {
        panic!("a real peer Invite must prepare a Commit")
    };
    sender.confirm_published(pending).await.unwrap();
    msg
}

enum ReadSite {
    InitialNative,
    PostReplayNative,
    AddedProfile,
}

async fn read_wrapper(site: ReadSite) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("native-read.sqlite");
    let key = SqlCipherKey::raw([0x73; 32]);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut receiver = build_client_with_storage(b"read-fault-receiver", storage.clone());
    let (mut sender, _) = build_client(b"read-fault-sender");
    let group = group_with(&mut sender, &mut [&mut receiver]).await;
    let source_epoch = storage.get_group(&group).unwrap().epoch;
    let commit = peer_add(&mut sender, &group).await;
    let sql = observer(&path, &key);
    let own = PrevalidatedOwnCommits::default();
    let process = || {
        process_openmls_messages_inner(
            &storage,
            &group,
            std::slice::from_ref(&commit),
            &own,
            ReplayProfilePolicy::default(),
            None,
        )
    };
    let before = protocol_rows(&sql);
    match site {
        ReadSite::InitialNative => {
            let (context_key, bytes) = native_context(&sql, &group);
            replace_context(&sql, &context_key, &[0xff]);
            let failed = process();
            replace_context(&sql, &context_key, &bytes);
            assert_storage(&failed, "load:");
            assert!(protocol_rows(&sql) == before, "restore exact backend bytes");
            assert_eq!(process().unwrap().final_epoch, source_epoch.0 + 1);
        }
        ReadSite::PostReplayNative => {
            let output = process().unwrap();
            let after_replay = protocol_rows(&sql);
            let (context_key, bytes) = native_context(&sql, &group);
            replace_context(&sql, &context_key, &[0xff]);
            let failed =
                update_group_record_from_replay(&storage, &group, &output, &BTreeSet::new(), None);
            replace_context(&sql, &context_key, &bytes);
            assert_storage(&failed, "load post-replay group:");
            assert!(
                protocol_rows(&sql) == after_replay,
                "the failed mirror cannot alter its real post-replay state"
            );
            update_group_record_from_replay(&storage, &group, &output, &BTreeSet::new(), None)
                .unwrap();
            assert_eq!(
                storage.get_group(&group).unwrap().epoch.0,
                source_epoch.0 + 1
            );
            assert_eq!(storage.get_group(&group).unwrap().members.len(), 3);
            let native = MlsGroup::load(
                storage.mls_storage(),
                &openmls::group::GroupId::from_slice(group.as_slice()),
            )
            .unwrap()
            .expect("the healthy post-replay native group must exist");
            assert_eq!(native.epoch().as_u64(), source_epoch.0 + 1);
        }
        ReadSite::AddedProfile => {
            let bytes: Vec<u8> = sql
                .query_row(
                    "SELECT record FROM cgka_groups WHERE id = ?1",
                    [group.as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            sql.execute(
                "UPDATE cgka_groups SET record = X'ff' WHERE id = ?1",
                [group.as_slice()],
            )
            .unwrap();
            let failed = process();
            sql.execute(
                "UPDATE cgka_groups SET record = ?1 WHERE id = ?2",
                rusqlite::params![bytes, group.as_slice()],
            )
            .unwrap();
            assert_storage(&failed, "check replayed Add leaves:");
            assert!(protocol_rows(&sql) == before, "restore exact backend bytes");
            assert_eq!(process().unwrap().final_members.len(), 3);
        }
    }
    drop(sql);
    drop(receiver);
    storage.close().unwrap();
}

#[tokio::test]
async fn initial_native_replay_read_failure_is_infrastructure() {
    read_wrapper(ReadSite::InitialNative).await;
}

#[tokio::test]
async fn post_replay_native_read_failure_is_infrastructure() {
    read_wrapper(ReadSite::PostReplayNative).await;
}

#[tokio::test]
async fn replayed_add_profile_read_failure_is_infrastructure() {
    read_wrapper(ReadSite::AddedProfile).await;
}

#[tokio::test]
async fn authenticated_own_checkpoint_reload_failure_is_infrastructure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("checkpoint-read.sqlite");
    let key = SqlCipherKey::raw([0x74; 32]);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut author = build_client_with_storage(b"checkpoint-read-author", storage.clone());
    let (mut peer, _) = build_client(b"checkpoint-read-peer");
    let group = group_with(&mut author, &mut [&mut peer]).await;
    let source_epoch = storage.get_group(&group).unwrap().epoch.0;
    let SendResult::GroupEvolution { msg, pending, .. } = author
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("a real SelfUpdate must prepare a Commit")
    };
    author.confirm_published(pending).await.unwrap();
    let record = storage.get_message(&msg.id).unwrap();
    let payload = StoredMessagePayload::decode(&record.payload).unwrap();
    let stamp = payload.own_commit_stamp().unwrap().clone();
    assert!(stamp.checkpoint_id.is_some());
    assert!(stamp.resulting_epoch_authenticator.is_some());
    let mut own = PrevalidatedOwnCommits::default();
    own.insert_stamped(
        project_mls_message(&msg.payload).unwrap().message_digest,
        stamp,
    );
    let sql = observer(&path, &key);
    let (_, target_context) = native_context(&sql, &group);
    storage
        .rollback_group_state_keeping_live_records(
            &group,
            &retained_anchor_snapshot_name(source_epoch),
        )
        .unwrap();
    let (_, source_context) = native_context(&sql, &group);
    assert!(
        source_context != target_context,
        "fault must exclude the source load"
    );
    let before = protocol_rows(&sql);
    sql.execute_batch(&format!(
        "CREATE TRIGGER fail_checkpoint_read AFTER INSERT ON openmls_values
         WHEN NEW.label = X'{}' AND NEW.value = X'{}'
         BEGIN UPDATE openmls_values SET value = X'ff'
         WHERE storage_key = NEW.storage_key; END;",
        hex::encode(b"GroupContext"),
        hex::encode(&target_context),
    ))
    .unwrap();
    let process = || {
        storage.with_group_savepoint(&group, "read-fault-owner", |storage| {
            process_openmls_messages_inner(
                storage,
                &group,
                std::slice::from_ref(&msg),
                &own,
                ReplayProfilePolicy::default(),
                None,
            )
        })
    };
    let failed = process();
    assert_storage(&failed, "checkpoint reload:");
    assert!(
        protocol_rows(&sql) == before,
        "the real apply savepoint must restore every protocol/native row"
    );
    sql.execute_batch("DROP TRIGGER fail_checkpoint_read")
        .unwrap();
    assert_eq!(process().unwrap().final_epoch, source_epoch + 1);
    drop(sql);
    drop(author);
    storage.close().unwrap();
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let native = MlsGroup::load(
        reopened.mls_storage(),
        &openmls::group::GroupId::from_slice(group.as_slice()),
    )
    .unwrap()
    .unwrap();
    assert_eq!(native.epoch().as_u64(), source_epoch + 1);
    reopened.close().unwrap();
}
