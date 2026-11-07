//! Actual device-roster apply must distinguish backend faults from invalid input.

use super::*;
use cgka_engine::{ConvergenceClock, openmls_projection::OpenMlsProjectionError};
use cgka_traits::convergence_pass::{ConvergencePassPhase, ConvergencePassStep};
use cgka_traits::{ConvergencePassStorage, EpochId, MessageState};
use rusqlite::{Connection, types::Value};
use std::collections::BTreeMap;
use storage_sqlite::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};

fn observer(path: &std::path::Path, key: &SqlCipherKey) -> Connection {
    let sql = Connection::open(path).unwrap();
    open_hardened_sqlcipher(&sql, key, SqlCipherHardening::live_cache()).unwrap();
    sql
}

fn protocol_rows(sql: &Connection) -> BTreeMap<String, Vec<Vec<Value>>> {
    let tables = sql.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND (name LIKE 'cgka_%' OR name LIKE 'openmls_%') AND name != 'cgka_convergence_passes' ORDER BY name")
        .unwrap().query_map([], |row| row.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
    tables
        .into_iter()
        .map(|name| {
            let columns = sql
                .prepare(&format!("SELECT * FROM {name}"))
                .unwrap()
                .column_count();
            let order = (1..=columns)
                .map(|column| column.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let rows = sql
                .prepare(&format!("SELECT * FROM {name} ORDER BY {order}"))
                .unwrap()
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

#[tokio::test]
async fn roster_departure_backend_read_failure_retains_public_apply_for_retry() {
    let dir = tempfile::tempdir().unwrap();
    let phone_path = dir.path().join("phone.sqlite");
    let laptop_path = dir.path().join("laptop.sqlite");
    let phone_key = SqlCipherKey::raw([0x75; 32]);
    let laptop_key = SqlCipherKey::raw([0x76; 32]);
    let phone_storage = SqliteAccountStorage::open_encrypted(&phone_path, &phone_key).unwrap();
    let laptop_storage = SqliteAccountStorage::open_encrypted(&laptop_path, &laptop_key).unwrap();
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let account = b"roster-replay-read";
    let mut phone = build_roster_device(
        phone_storage.clone(),
        account,
        Some(&clock),
        Box::<MockPeeler>::default(),
        None,
    );
    let mut laptop = build_roster_device(
        laptop_storage.clone(),
        account,
        Some(&clock),
        Box::<MockPeeler>::default(),
        None,
    );
    let gid = found_device_group(
        &mut phone,
        &roster(&[(1, "Phone"), (2, "Laptop")]),
        &mut [&mut laptop],
    )
    .await;
    // Founding helper explicitly settles at 1_000_000. Keep the actual clock
    // beyond that boundary before opening the next real collecting pass.
    clock.advance_ms(2_000_000);
    let source_epoch = laptop.engine.epoch(&gid).unwrap();
    let mut expected = roster_of(&phone, &gid);
    expected.devices.remove(&slot(2));
    let commit = send_commit(
        &mut phone,
        roster_update(&gid, vec![DeviceRosterOperationV1::RemoveDevice(slot(2))]),
        &gid,
    )
    .await;
    let source_sql = observer(&phone_path, &phone_key);
    let group_key =
        serde_json::to_vec(&openmls::group::GroupId::from_slice(gid.as_slice())).unwrap();
    let target: Vec<u8> = source_sql
        .query_row(
            "SELECT value FROM openmls_values WHERE label=?1 AND group_key=?2",
            rusqlite::params![b"GroupContext".as_slice(), group_key],
            |row| row.get(0),
        )
        .unwrap();
    drop(source_sql);
    assert!(matches!(
        laptop.engine.ingest(commit.clone()).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));
    assert_eq!(laptop.engine.epoch(&gid).unwrap(), source_epoch);
    let content_id = hash_id(&commit.payload);
    let retained = laptop_storage.get_message(&content_id).unwrap();
    let collecting = laptop_storage.convergence_pass(&gid).unwrap().unwrap();
    assert_eq!(collecting.phase, ConvergencePassPhase::Collecting);
    let sql = observer(&laptop_path, &laptop_key);
    let before = protocol_rows(&sql);
    laptop.engine.drain_events();
    sql.execute_batch(&format!("CREATE TRIGGER fail_roster_departure_read AFTER INSERT ON openmls_values WHEN NEW.label=X'{}' AND NEW.value=X'{}' BEGIN UPDATE cgka_groups SET record=X'ff' WHERE id=X'{}'; END;",hex::encode(b"GroupContext"),hex::encode(target),hex::encode(gid.as_slice()))).unwrap();
    clock.advance_ms(10_000);
    let failed = laptop
        .engine
        .converge_stored_openmls_messages_at(&gid, clock.now().monotonic_ms);
    // The old wrapper has no operation prefix; this serialization error can
    // occur only after our exact target merge poisons the record. Probe-only
    // native loads and profile reads preceded it; probes skip this writer.
    assert!(
        matches!(&failed,Err(OpenMlsProjectionError::Replay(reason)) if reason.starts_with("serialization failure:"))
            || matches!(&failed,Err(OpenMlsProjectionError::Storage(reason)) if reason.starts_with("record replayed device-roster departures:")),
        "fault must reach the apply-only roster record lookup"
    );
    assert!(
        matches!(&failed,Err(OpenMlsProjectionError::Storage(reason)) if reason.starts_with("record replayed device-roster departures:")),
        "roster backend read must remain infrastructure"
    );
    assert!(
        protocol_rows(&sql) == before,
        "failed apply must restore every native/protocol row except its explicit pass progress"
    );
    assert_eq!(laptop_storage.get_message(&content_id).unwrap(), retained);
    assert_eq!(laptop.engine.epoch(&gid).unwrap(), source_epoch);
    assert!(laptop.engine.drain_events().is_empty());
    let pass = laptop_storage.convergence_pass(&gid).unwrap().unwrap();
    assert_eq!(pass.generation, collecting.generation);
    assert_eq!(pass.base_epoch, collecting.base_epoch);
    assert_eq!(pass.members, collecting.members);
    assert_eq!(pass.phase, ConvergencePassPhase::Resolving);
    assert_eq!(
        pass.retry.as_ref().unwrap().failed_step,
        ConvergencePassStep::Apply
    );
    assert_eq!(pass.retry.as_ref().unwrap().failed_attempts, 1);
    sql.execute_batch("DROP TRIGGER fail_roster_departure_read")
        .unwrap();
    drop(sql);
    drop(laptop);
    laptop_storage.close().unwrap();
    drop(laptop_storage);
    let storage = SqliteAccountStorage::open_encrypted(&laptop_path, &laptop_key).unwrap();
    let mut laptop = build_roster_device(
        storage.clone(),
        account,
        Some(&clock),
        Box::<MockPeeler>::default(),
        None,
    );
    laptop.engine.hydrate_all_stored_groups().unwrap();
    assert!(laptop.engine.quarantined_groups().is_empty());
    clock.advance_ms(10_000);
    let healed = laptop
        .engine
        .converge_stored_openmls_messages_at(&gid, clock.now().monotonic_ms)
        .unwrap();
    assert_eq!(
        healed.accepted_commits,
        vec![hex::encode(content_id.as_slice())]
    );
    assert_eq!(roster_of(&laptop, &gid), expected);
    let group = storage.get_group(&gid).unwrap();
    assert!(
        group
            .device_roster_departures
            .iter()
            .any(|cause| cause.slot == slot(2) && cause.commit_id == content_id)
    );
    assert_eq!(
        laptop.engine.epoch(&gid).unwrap(),
        EpochId(source_epoch.0 + 1)
    );
    assert_eq!(
        storage.get_message(&content_id).unwrap().state,
        MessageState::Processed
    );
    drop(laptop);
    storage.close().unwrap();
    drop(phone);
    phone_storage.close().unwrap();
}
