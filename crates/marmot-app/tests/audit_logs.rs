use marmot_account::AccountHome;
use marmot_app::{
    AuditLogDeleteOutcome, AuditLogSettings, MarmotApp, MarmotAppConfig, MarmotAppRuntime,
};
use nostr_relay_builder::MockRelay;
use serde_json::Value;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tracker_update_without_a_v5_destination_reports_only_the_audit_switch() {
    let tmp = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    let runtime = MarmotAppRuntime::new(app.clone());

    let disabled = runtime.post_audit_log_tracker_update().await.unwrap();
    assert!(!disabled.enabled);
    assert!(disabled.v5.is_none());

    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let enabled = runtime.post_audit_log_tracker_update().await.unwrap();
    assert!(enabled.enabled);
    assert!(enabled.v5.is_none(), "no destination, no delivery result");
}

#[test]
fn audit_log_files_lists_local_jsonl_logs() {
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let audit_path = home.account_dir(&account.label).join("audit-abc123.jsonl");
    std::fs::write(
        &audit_path,
        b"{\"schema_version\":\"marmot-forensics-audit/v1\"}\n",
    )
    .unwrap();

    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    let files = app.audit_log_files().unwrap();

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].account_ref, "alice");
    assert_eq!(files[0].file_name, "audit-abc123.jsonl");
    assert_eq!(files[0].path, audit_path.to_string_lossy());
    assert!(files[0].size_bytes > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_log_setting_enables_jsonl_recorder_for_opened_accounts() {
    storage_sqlite::relax_storage_for_test_process();
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");

    let client = app.client(&account.label).await.unwrap();
    assert!(
        app.audit_log_files().unwrap().is_empty(),
        "audit logs should be off by default"
    );
    drop(client);

    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let _client = app.client(&account.label).await.unwrap();

    let files = app.audit_log_files().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].account_ref, "alice");
    assert!(files[0].file_name.starts_with("audit-"));
    assert!(files[0].file_name.ends_with(".jsonl"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deferred_runtime_open_records_the_stored_group_baseline() {
    storage_sqlite::relax_storage_for_test_process();
    let tmp = tempfile::tempdir().unwrap();
    let account = AccountHome::open(tmp.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    let mut client = app.client(&account.label).await.unwrap();
    let group = client
        .create_group("stored baseline", &[])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    drop(client);
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();

    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    let group_ref = marmot_forensics::v5::GroupRef::from_group_id(group.as_slice())
        .unwrap()
        .as_str()
        .to_owned();
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let files = app.audit_log_files().unwrap();
            let found = files.iter().any(|file| {
                std::fs::read_to_string(&file.path).is_ok_and(|body| {
                    body.lines().any(|line| {
                        let row: Value = serde_json::from_str(line).unwrap();
                        row["event"]["type"] == "group_baseline"
                            && row["event"]["reason"] == "opened"
                            && row["group_ref"] == group_ref
                    })
                })
            });
            if found {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("deferred runtime hydration should record opened baseline");
    runtime
        .set_audit_log_settings(AuditLogSettings { enabled: false })
        .await
        .unwrap();
    runtime
        .set_audit_log_settings(AuditLogSettings { enabled: true })
        .await
        .unwrap();
    let files = app.audit_log_files().unwrap();
    let body = std::fs::read_to_string(&files[0].path).unwrap();
    let rows = body
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert!(rows.iter().any(|row| {
        row["event"]["type"] == "group_baseline"
            && row["event"]["reason"] == "audit_enabled"
            && row["group_ref"] == group_ref
    }));
    assert!(rows.iter().any(|row| {
        row["event"]["type"] == "group_baseline_inventory"
            && row["event"]["reason"] == "audit_enabled"
            && row["event"]["selected_group_count"] == 1
    }));
    runtime.shutdown_and_close().await.unwrap();
    let final_rows = std::fs::read_to_string(&files[0].path)
        .unwrap()
        .lines()
        .map(|line| marmot_forensics::v5::Record::from_json(line.as_bytes()).unwrap())
        .collect::<Vec<_>>();
    assert!(matches!(
        &final_rows.last().unwrap().fields().event,
        marmot_forensics::v5::Event::RecordingSessionStopped(stop)
            if stop.reason == marmot_forensics::v5::RecordingStopReason::CleanRuntimeShutdown
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn opened_baseline_inventory_exposes_the_64_group_cap() {
    storage_sqlite::relax_storage_for_test_process();
    let tmp = tempfile::tempdir().unwrap();
    let account = AccountHome::open(tmp.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    let mut client = app.client(&account.label).await.unwrap();
    for index in 0..65 {
        client
            .create_group(&format!("baseline group {index}"), &[])
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members");
    }
    drop(client);
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let _reopened = app.client(&account.label).await.unwrap();
    let files = app.audit_log_files().unwrap();
    let body = std::fs::read_to_string(&files[0].path).unwrap();
    let rows = body
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    let inventory = rows
        .iter()
        .find(|row| row["event"]["type"] == "group_baseline_inventory")
        .expect("bounded selection must leave an account-scoped inventory row");
    assert!(inventory["group_ref"].is_null());
    assert_eq!(inventory["event"]["eligible_group_count"], 65);
    assert_eq!(inventory["event"]["selected_group_count"], 64);
    assert_eq!(inventory["event"]["omitted_by_limit_count"], 1);
    assert_eq!(inventory["event"]["failed_read_count"], 0);
    assert_eq!(
        rows.iter()
            .filter(|row| row["event"]["type"] == "group_baseline"
                && row["event"]["reason"] == "opened")
            .count(),
        64
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_group_action_writes_human_action_context() {
    storage_sqlite::relax_storage_for_test_process();
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();

    let mut client = app.client(&account.label).await.unwrap();
    client
        .create_group("audit actions", &[])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");

    let files = app.audit_log_files().unwrap();
    assert_eq!(files.len(), 1);
    let body = std::fs::read_to_string(&files[0].path).unwrap();
    let events = body
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();

    let human_action = events
        .iter()
        .find(|event| {
            event["event"]["type"] == "human_action"
                && event["event"]["action"] == "create_group"
                && event["event"]["phase"] == "succeeded"
        })
        .expect("create_group should write a human_action audit row");
    assert_eq!(human_action["event"]["origin"], "local_user");
    assert!(
        human_action["event"]["fields"]
            .as_array()
            .unwrap()
            .contains(&Value::String("name".into()))
    );
    assert!(
        human_action["event"]["fields"]
            .as_array()
            .unwrap()
            .contains(&Value::String("members".into()))
    );

    let create_entry = events
        .iter()
        .find(|event| event["event"]["type"] == "create_group_entry")
        .expect("create_group should write a create_group_entry audit row");
    assert_eq!(
        create_entry["event"]["record_context"]["human_action"]["action"],
        "create_group"
    );
    assert_eq!(
        create_entry["event"]["record_context"]["human_action"]["origin"],
        "local_user"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_message_send_tags_engine_rows_with_human_action() {
    storage_sqlite::relax_storage_for_test_process();
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let app = MarmotApp::with_relay_and_config(
        tmp.path(),
        relay_url,
        MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
    );
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();

    let mut client = app.client(&account.label).await.unwrap();
    let group_id = client
        .create_group("audit actions", &[])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    client
        .send(&group_id, b"hello marmots")
        .await
        .expect("mock relay should accept the audited send");

    let files = app.audit_log_files().unwrap();
    let body = std::fs::read_to_string(&files[0].path).unwrap();
    let events = body
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();

    // The app threads the human action through `send_with_audit_context`, so the
    // engine's `send_entry` row carries it (previously context-free for sends).
    let send_entry = events
        .iter()
        .find(|event| event["event"]["type"] == "send_entry")
        .expect("send should write a send_entry audit row");
    assert_eq!(
        send_entry["event"]["record_context"]["human_action"]["action"],
        "send_message"
    );
    assert_eq!(
        send_entry["event"]["record_context"]["human_action"]["origin"],
        "local_user"
    );

    // The engine's ambient operation context backfills the secondary
    // `message_state_changed` row, which the engine emits context-free.
    let state_changed = events
        .iter()
        .find(|event| {
            event["event"]["type"] == "message_state_changed"
                && event["event"]["record_context"]["human_action"]["action"] == "send_message"
        })
        .expect("send's message_state_changed row should inherit the human action");
    assert_eq!(
        state_changed["event"]["record_context"]["human_action"]["origin"],
        "local_user"
    );
}

fn decode_account_id_hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("account id hex"))
        .collect()
}

fn source_events(path: &str) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|event| event["event"]["type"] == "source_context")
        .collect()
}

async fn wait_for_audit_file_quiesce(path: &str) -> String {
    let mut body = std::fs::read_to_string(path).unwrap();
    let mut unchanged = 0;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let next = std::fs::read_to_string(path).unwrap();
        if next == body {
            unchanged += 1;
            if unchanged >= 10 {
                return body;
            }
        } else {
            unchanged = 0;
            body = next;
        }
    }
    body
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enabled_recorder_emits_local_member_ref_before_any_group_mutation() {
    storage_sqlite::relax_storage_for_test_process();
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let _client = app.client(&account.label).await.unwrap();
    let files = app.audit_log_files().unwrap();
    assert_eq!(files.len(), 1);
    let events = source_events(&files[0].path);
    assert_eq!(events.len(), 1, "startup should write one source row");
    let expected =
        marmot_forensics::member_ref_hex(&decode_account_id_hex(&account.account_id_hex));
    assert_eq!(events[0]["event"]["source"]["local_member_ref"], expected);
    assert!(events[0].get("account_ref").is_none());
    let body = std::fs::read_to_string(&files[0].path).unwrap();
    assert!(!body.contains(&account.account_id_hex));
    assert!(!body.contains("\"account_label\""));
}

fn assert_source_linkage(actual: &Value, expected: &Value) {
    assert_eq!(
        actual["event"]["source"]["local_member_ref"],
        expected["event"]["source"]["local_member_ref"]
    );
    assert_eq!(actual["source_ref"], expected["source_ref"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reopen_and_toggle_restore_source_row_without_group_mutation() {
    storage_sqlite::relax_storage_for_test_process();
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let client = app.client(&account.label).await.unwrap();
    let path = app.audit_log_files().unwrap()[0].path.clone();
    let first = source_events(&path);
    assert_eq!(first.len(), 1, "startup should write one source row");
    drop(client);

    let client = app.client(&account.label).await.unwrap();
    let reopened = source_events(&path);
    assert_eq!(
        reopened.len(),
        first.len() + 1,
        "reopen must append a new source_context"
    );
    assert_source_linkage(reopened.last().unwrap(), &first[0]);
    assert_ne!(
        reopened.last().unwrap()["session_id"],
        first[0]["session_id"]
    );
    drop(client);

    let live_tmp = tempfile::tempdir().unwrap();
    let live_home = AccountHome::open(live_tmp.path());
    let live_account = live_home.create_account("alice").unwrap();
    let live_app = MarmotApp::with_relay(live_tmp.path(), "wss://relay.example");
    live_app
        .set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let runtime = MarmotAppRuntime::new(live_app);
    runtime.start().await.unwrap();
    runtime.sign_in_account(&live_account.label).await.unwrap();
    let live_path = runtime.audit_log_files().unwrap()[0].path.clone();
    // Sign-in returns when commands are available, before startup catch-up.
    // A quiet file interval during acquisition is not completion: wait for the
    // real completion signal before sampling the pre-disable body.
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while runtime
            .shared_services()
            .app_performance_telemetry()
            .snapshot()
            .account_sync
            .attempts
            == 0
        {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("startup catch-up completed before testing live audit disable");
    let before_disable_body = wait_for_audit_file_quiesce(&live_path).await;
    let before_toggle = source_events(&live_path);
    assert_eq!(
        before_toggle.len(),
        1,
        "live worker startup should write one source row"
    );
    let before_toggle_row = before_toggle[0].clone();

    runtime
        .set_audit_log_settings(AuditLogSettings { enabled: false })
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(source_events(&live_path).len(), before_toggle.len());
    let after_disable_body = std::fs::read_to_string(&live_path).unwrap();
    assert_eq!(after_disable_body, before_disable_body);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        std::fs::read_to_string(&live_path).unwrap(),
        after_disable_body
    );

    runtime
        .set_audit_log_settings(AuditLogSettings { enabled: true })
        .await
        .unwrap();
    let restored = source_events(&live_path);
    assert_eq!(
        restored.len(),
        before_toggle.len() + 1,
        "live re-enable must append a new source_context"
    );
    let latest = restored.last().unwrap();
    assert_source_linkage(latest, &before_toggle_row);
    assert_ne!(latest["session_id"], before_toggle_row["session_id"]);
    runtime.shutdown().await;
    let final_rows = std::fs::read_to_string(&live_path)
        .unwrap()
        .lines()
        .map(|line| marmot_forensics::v5::Record::from_json(line.as_bytes()).unwrap())
        .collect::<Vec<_>>();
    let last = final_rows.last().unwrap().fields();
    assert!(matches!(
        &last.event,
        marmot_forensics::v5::Event::RecordingSessionStopped(stop)
            if stop.reason == marmot_forensics::v5::RecordingStopReason::CleanRuntimeShutdown
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_delete_rotates_and_replays_source_context() {
    storage_sqlite::relax_storage_for_test_process();
    let tmp = tempfile::tempdir().unwrap();
    let home = AccountHome::open(tmp.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(tmp.path(), "wss://relay.example");
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    let runtime = MarmotAppRuntime::new(app);
    runtime.start().await.unwrap();
    runtime.sign_in_account(&account.label).await.unwrap();
    let files = runtime.audit_log_files().unwrap();
    assert_eq!(files.len(), 1);
    let path = files[0].path.clone();
    let before = source_events(&path);
    assert_eq!(before.len(), 1);
    let outcome = runtime.delete_audit_log_file(&path).await.unwrap();
    assert_eq!(
        outcome,
        AuditLogDeleteOutcome {
            still_recording: true
        }
    );
    let after = source_events(&path);
    assert_eq!(after.len(), 1);
    assert_eq!(
        after[0]["event"]["source"]["local_member_ref"],
        before[0]["event"]["source"]["local_member_ref"]
    );
    assert_eq!(after[0]["source_ref"], before[0]["source_ref"]);
    assert_ne!(after[0]["session_id"], before[0]["session_id"]);
    runtime.shutdown().await;
}
