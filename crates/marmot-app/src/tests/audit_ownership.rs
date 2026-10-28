//! The account-device's audit log has one recorder. Engine, runtime and app
//! rows share its sequence, and finishing the log closes it for every clone.

use super::*;
use marmot_forensics::ForensicRecorder as _;

fn audit_rows(app: &MarmotApp, label: &str) -> Vec<serde_json::Value> {
    let mut files: Vec<_> = std::fs::read_dir(app.account_dir(label))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            name.starts_with("audit-") && name.ends_with(".jsonl")
        })
        .collect();
    files.sort();
    files
        .iter()
        .flat_map(|path| {
            std::fs::read_to_string(path)
                .unwrap()
                .lines()
                .map(|line| {
                    marmot_forensics::v5::Record::from_json(line.as_bytes()).expect("valid v5 row");
                    serde_json::from_str::<serde_json::Value>(line).unwrap()
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn kind(row: &serde_json::Value) -> &str {
    row["event"]["type"].as_str().unwrap()
}

fn position(rows: &[serde_json::Value], wanted: &str) -> usize {
    rows.iter()
        .position(|row| kind(row) == wanted)
        .unwrap_or_else(|| panic!("no {wanted} row"))
}

async fn audited_alice(relay: &str) -> (tempfile::TempDir, MarmotApp) {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), relay)
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    app.set_audit_log_settings(AuditLogSettings { enabled: true })
        .unwrap();
    (dir, app)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn app_rows_and_engine_rows_share_one_sequence_and_group_ref() {
    let (_dir, app) = audited_alice("wss://audit-one-sequence.example").await;
    let mut client = app.client("alice").await.unwrap();
    let group_id = client.create_group("one sequence", &[]).await.unwrap();
    client.record_epoch_stall_backfill_escalated(&group_id, 7, 3);
    client.send(&group_id, b"after the app row").await.unwrap();
    drop(client);

    let rows = audit_rows(&app, "alice");
    let sessions: std::collections::BTreeSet<&str> = rows
        .iter()
        .map(|row| row["session_id"].as_str().unwrap())
        .collect();
    assert_eq!(sessions.len(), 1, "one recording session: {sessions:?}");
    let seqs: Vec<u64> = rows
        .iter()
        .map(|row| row["seq"].as_str().unwrap().parse().unwrap())
        .collect();
    assert!(
        seqs.windows(2).all(|pair| pair[0] < pair[1]),
        "one strictly increasing sequence: {seqs:?}"
    );

    let created = position(&rows, "create_group_outcome");
    let app_row = position(&rows, "epoch_stall_backfill_escalated");
    let sent = position(&rows, "send_entry");
    assert!(
        created < app_row && app_row < sent,
        "the app row lands between the engine rows around it"
    );
    assert_eq!(
        rows[app_row]["group_ref"], rows[created]["group_ref"],
        "an app row names its group as the engine's rows do"
    );
    assert_eq!(
        rows.iter()
            .filter(|row| kind(row) == "recorder_health")
            .count(),
        1,
        "the session writes one recorder-health row at open"
    );
    assert!(position(&rows, "engine_context") < position(&rows, "recorder_health"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finishing_the_audit_log_closes_it_for_every_clone() {
    let (_dir, app) = audited_alice("wss://audit-finish.example").await;
    let mut client = app.client("alice").await.unwrap();
    let group_id = client.create_group("finish", &[]).await.unwrap();
    // Stands in for a clone that outlives shutdown. The runtime, the session
    // and the engine hold theirs inside the client.
    let surviving = client.audit.clone();

    client.finish_audit_recording();
    let finished = audit_rows(&app, "alice");
    assert_eq!(kind(finished.last().unwrap()), "recording_session_stopped");
    assert!(!surviving.is_enabled());

    surviving.record(marmot_forensics::AuditRecord::new(
        None,
        marmot_forensics::AuditEventKind::RecorderHealth {
            serialization_failures: 0,
            write_failures: 0,
            flush_failures: 0,
        },
    ));
    client.record_epoch_stall_backfill_escalated(&group_id, 7, 3);
    client.send(&group_id, b"after finish").await.unwrap();
    assert_eq!(
        audit_rows(&app, "alice"),
        finished,
        "no clone writes after the stop row: not the app's, the runtime's or the engine's"
    );
    drop(client);

    // The next open appends a new session to the same file. The finished
    // session never resumes, so the file never holds two live counters.
    let reopened = app.client("alice").await.unwrap();
    surviving.record(marmot_forensics::AuditRecord::new(
        None,
        marmot_forensics::AuditEventKind::RecorderHealth {
            serialization_failures: 0,
            write_failures: 0,
            flush_failures: 0,
        },
    ));
    drop(reopened);
    let rows = audit_rows(&app, "alice");
    let stop = position(&rows, "recording_session_stopped");
    assert!(
        rows.len() > stop + 1,
        "the reopened client records a new session"
    );
    let finished_session = &rows[stop]["session_id"];
    assert!(
        rows[stop + 1..]
            .iter()
            .all(|row| &row["session_id"] != finished_session),
        "no row of the finished session follows its stop row"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_session_and_live_toggle_register_the_writer_for_retention() {
    let (_dir, app) = audited_alice("wss://audit-retention.example").await;
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("retention", &[]).await.unwrap();
    let path = client.audit.audit_log_path().unwrap();
    let age = || {
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH))
            .unwrap()
    };
    age();
    assert!(!app.expire_audit_file(&path).unwrap());
    let before = std::fs::metadata(&path).unwrap().len();
    client.record_epoch_stall_backfill_escalated(&group, 7, 3);
    assert!(std::fs::metadata(&path).unwrap().len() > before);
    client.set_audit_recording(false);
    age();
    assert!(app.expire_audit_file(&path).unwrap());
    client.set_audit_recording(true);
    age();
    assert!(!app.expire_audit_file(&path).unwrap());
    let before = std::fs::metadata(&path).unwrap().len();
    client.record_epoch_stall_backfill_escalated(&group, 8, 3);
    assert!(std::fs::metadata(&path).unwrap().len() > before);
}
