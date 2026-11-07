//! Failed preparation must not retain an unowned sent Commit (#3170).

use super::*;
use rusqlite::{Connection, types::Value};
use std::collections::BTreeMap;
use storage_sqlite::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};

fn observer(path: &std::path::Path, key: &SqlCipherKey) -> Connection {
    let connection = Connection::open(path).unwrap();
    open_hardened_sqlcipher(&connection, key, SqlCipherHardening::live_cache()).unwrap();
    connection
}

fn rows(connection: &Connection, table: &str) -> Vec<Vec<Value>> {
    let columns = connection
        .prepare(&format!("SELECT * FROM {table}"))
        .unwrap()
        .column_count();
    let order = (1..=columns)
        .map(|column| column.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let mut query = connection
        .prepare(&format!("SELECT * FROM {table} ORDER BY {order}"))
        .unwrap();
    query
        .query_map([], |row| {
            (0..columns).map(|column| row.get(column)).collect()
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn protocol_state(connection: &Connection) -> BTreeMap<String, Vec<Vec<Value>>> {
    // All protocol/native tables, including snapshots, routes, pending-ref
    // watermark, sent rows, intents and the original irreversible request.
    let tables = connection
        .prepare(
            "SELECT name FROM sqlite_schema WHERE type = 'table'
         AND (name LIKE 'cgka_%' OR name LIKE 'openmls_%') ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let state = rows(connection, &table);
            (table, state)
        })
        .collect()
}

async fn assert_failed_descriptor_retry(disband: bool) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("late-descriptor.sqlite");
    let key = SqlCipherKey::raw([0x71; 32]);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let identity = b"late-descriptor-native";
    let mut alice = current_client(identity, storage.clone(), &clock);
    let (group_id, created) = alice
        .create_group(CreateGroupRequest {
            name: "late descriptor".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    assert!(
        matches!(created, SendResult::FoundingGroupCreated { ref welcomes } if welcomes.is_empty())
    );
    if disband {
        assert!(matches!(
            alice
                .send(SendIntent::Disband {
                    group_id: group_id.clone()
                })
                .await
                .unwrap(),
            SendResult::DisbandRequested { .. }
        ));
    }
    alice.drain_events();
    alice.drain_pending_convergence_groups();
    let reader = observer(&path, &key);
    let before = protocol_state(&reader);
    let before_group = storage.get_group(&group_id).unwrap();
    let before_epoch = alice.epoch(&group_id).unwrap();
    let request = storage.disband_request(&group_id).unwrap();
    let (table, condition, marker) = if disband {
        // The final request write follows the real candidate INSERT in its
        // transaction, so this is later than a candidate-write refusal.
        (
            "cgka_disband_requests",
            "json_extract(CAST(NEW.record AS TEXT), '$.last_prepared_epoch') IS NOT NULL",
            "late-disband-request",
        )
    } else {
        (
            "cgka_group_evolutions",
            "json_extract(CAST(NEW.record AS TEXT), '$.phase') = 'prepared'",
            "late-self-update-prepared",
        )
    };
    reader
        .execute_batch(&format!(
            "CREATE TRIGGER fail_late_descriptor BEFORE INSERT ON {table}
         WHEN {condition} BEGIN SELECT RAISE(ABORT, '{marker}'); END;",
        ))
        .unwrap();
    let failed = if disband {
        alice.advance_convergence(&group_id).await.map(|_| ())
    } else {
        alice
            .send(SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            })
            .await
            .map(|_| ())
    };
    assert!(
        matches!(&failed, Err(EngineError::Storage(error)) if format!("{error:?}").contains(marker)),
        "the actual late descriptor write must fail after signed Commit persistence: {failed:?}"
    );
    assert_eq!(
        rows(&reader, "cgka_messages"),
        before["cgka_messages"],
        "failed preparation must leave no orphan signed Commit or content marker"
    );
    assert_eq!(
        protocol_state(&reader),
        before,
        "all native/protocol state must roll back with the late descriptor"
    );
    assert_eq!(storage.get_group(&group_id).unwrap(), before_group);
    assert_eq!(alice.epoch(&group_id).unwrap(), before_epoch);
    assert!(alice.epoch_state(&group_id).unwrap().is_stable());
    assert!(
        stored_mls_group(&storage, &group_id)
            .pending_commit()
            .is_none()
    );
    assert_eq!(storage.disband_request(&group_id).unwrap(), request);
    assert!(alice.drain_auto_publish().is_empty());
    assert!(alice.drain_events().is_empty());
    reader
        .execute_batch("DROP TRIGGER fail_late_descriptor")
        .unwrap();
    drop(reader);
    drop(alice);
    storage.close().unwrap();
    drop(storage);

    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut alice = current_client(identity, storage.clone(), &clock);
    alice.hydrate_all_stored_groups().unwrap();
    assert!(alice.quarantined_groups().is_empty());
    assert!(
        alice.drain_auto_publish().is_empty(),
        "reopen cannot publish the abandoned artifact"
    );
    assert_eq!(storage.get_group(&group_id).unwrap(), before_group);
    assert_eq!(storage.disband_request(&group_id).unwrap(), request);
    let retry = if disband {
        let mut prepared = alice.advance_convergence(&group_id).await.unwrap();
        assert_eq!(prepared.len(), 1);
        prepared.remove(0)
    } else {
        alice
            .send(SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            })
            .await
            .unwrap()
    };
    let (commit, pending) = evolution(retry);
    assert_eq!(
        storage.get_message(&commit.id).unwrap().state,
        MessageState::Sent
    );
    assert!(
        stored_mls_group(&storage, &group_id)
            .pending_commit()
            .is_some()
    );
    alice.confirm_published(pending).await.unwrap();
    if disband {
        for _ in 0..2 {
            clock.advance_ms(1_000);
            assert!(
                alice
                    .advance_convergence(&group_id)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        assert!(storage.disband_tombstone(&group_id).unwrap().is_some());
    } else {
        assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(before_epoch.0 + 1));
        assert!(alice.epoch_state(&group_id).unwrap().is_stable());
        let records = storage.list_group_evolutions_for_group(&group_id).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].phase, GroupEvolutionPhase::Confirmed);
        assert_eq!(records[0].signed_message_id.as_ref(), Some(&commit.id));
    }
    drop(alice);
    storage.close().unwrap();
    drop(storage);
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert_eq!(
        reopened.get_message(&commit.id).unwrap().state,
        MessageState::Processed
    );
    assert_eq!(
        reopened.get_group(&group_id).unwrap().epoch,
        EpochId(before_epoch.0 + 1)
    );
    let native = openmls::group::MlsGroup::load(
        reopened.mls_storage(),
        &openmls::group::GroupId::from_slice(group_id.as_slice()),
    )
    .unwrap();
    if disband {
        // Terminal settling deletes native MLS state while retaining the
        // authenticated tombstone and former group projection.
        assert!(native.is_none());
        assert!(reopened.disband_tombstone(&group_id).unwrap().is_some());
    } else {
        assert!(native.unwrap().pending_commit().is_none());
    }
    reopened.close().unwrap();
}

#[tokio::test]
async fn self_update_prepared_write_failure_keeps_the_complete_staging_unit_retryable() {
    assert_failed_descriptor_retry(false).await;
}

#[tokio::test]
async fn disband_descriptor_write_failure_keeps_the_complete_staging_unit_retryable() {
    assert_failed_descriptor_retry(true).await;
}
