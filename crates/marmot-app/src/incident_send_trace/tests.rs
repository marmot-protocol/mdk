use super::*;
use serde_json::Value;

fn wait_for(mut predicate: impl FnMut() -> bool) {
    let limit = Instant::now() + Duration::from_secs(5);
    while !predicate() {
        assert!(
            Instant::now() < limit,
            "diagnostic writer did not reach expected state"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn rows(root: &Path) -> Vec<Value> {
    let mut rows = Vec::new();
    for n in 0..SEGMENTS {
        if let Ok(text) =
            fs::read_to_string(root.join(format!("local-send-trace/segment-{n}.jsonl")))
        {
            rows.extend(
                text.lines()
                    .filter_map(|line| serde_json::from_str::<Value>(line).ok()),
            );
        }
    }
    rows.sort_by_key(|row| row["seq"].as_u64());
    rows
}
fn manifest(root: &Path) -> Option<Value> {
    serde_json::from_slice(&fs::read(root.join("local-send-trace/manifest.json")).ok()?).ok()
}

#[test]
fn disabled_capture_creates_nothing_and_producer_never_waits_for_state_lock() {
    let dir = tempfile::tempdir().unwrap();
    let trace = Trace::new(dir.path());
    trace.emit(Kind::AdmissionBegin, 0, 1, [0; 8]);
    assert!(!dir.path().join("local-send-trace").exists());
    let held = trace.state.lock().unwrap();
    trace.emit(Kind::AdmissionBegin, 0, 1, [0; 8]);
    assert_eq!(trace.lost_lock.load(Ordering::Relaxed), 1);
    drop(held);
}

#[test]
fn private_correlation_never_reaches_disk_and_reenable_changes_generation() {
    let dir = tempfile::tempdir().unwrap();
    let trace = Arc::new(Trace::new(dir.path()));
    trace.enable(true);
    let owner = trace.owner("secret-account-label");
    let op = trace.operation(owner, "secret-message-derived-key", trace.token());
    trace.emit(Kind::AdmissionCommitted, owner, op, values(op));
    wait_for(|| !rows(dir.path()).is_empty());
    let old = rows(dir.path())[0]["process"].clone();
    trace.enable(false);
    let bytes = fs::read_to_string(dir.path().join("local-send-trace/segment-0.jsonl")).unwrap();
    assert!(!bytes.contains("secret"));
    assert_eq!(manifest(dir.path()).unwrap()["recording"], false);
    trace.enable(true);
    trace.emit(Kind::AdmissionBegin, 0, trace.token(), [0; 8]);
    wait_for(|| {
        rows(dir.path())
            .first()
            .is_some_and(|r| r["process"] != old)
    });
    trace.enable(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(dir.path().join("local-send-trace"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(dir.path().join("local-send-trace/segment-0.jsonl"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn explicit_clear_does_not_reexport_unlinked_rows() {
    let dir = tempfile::tempdir().unwrap();
    let trace = Trace::new(dir.path());
    trace.enable(true);
    trace.emit(Kind::AdmissionBegin, 0, 123, [0; 8]);
    wait_for(|| rows(dir.path()).len() == 1);
    fs::remove_file(dir.path().join("local-send-trace/segment-0.jsonl")).unwrap();
    wait_for(|| manifest(dir.path()).is_some_and(|m| m["clear_count"].as_u64().unwrap() > 0));
    trace.emit(Kind::AdmissionBegin, 0, 456, [0; 8]);
    wait_for(|| rows(dir.path()).iter().any(|r| r["operation"] == 456));
    assert!(!rows(dir.path()).iter().any(|r| r["operation"] == 123));
    trace.enable(false);
}

#[test]
fn bounded_queue_and_correlation_report_loss_without_false_join() {
    let dir = tempfile::tempdir().unwrap();
    let trace = Trace::new(dir.path());
    let (tx, _rx) = mpsc::sync_channel(CAPACITY);
    let counts = Arc::new(Counts::default());
    counts.running.store(true, Ordering::Relaxed);
    trace.state.lock().unwrap().session = Some(Session {
        process: "00".repeat(16),
        start: Instant::now(),
        tx,
        counts: counts.clone(),
        writer: None,
    });
    for _ in 0..CAPACITY + 3 {
        trace.emit(Kind::AdmissionBegin, 1, 2, [0; 8]);
    }
    assert_eq!(counts.dropped.load(Ordering::Relaxed), 3);
    let owner = trace.owner("private");
    for n in 0..CAPACITY {
        assert_ne!(trace.operation(owner, &format!("key{n}"), trace.token()), 0);
    }
    assert_eq!(trace.operation(owner, "overflow", trace.token()), 0);
    assert_eq!(trace.operation(owner, "unknown", 0), 0);
}

#[test]
fn writer_rotates_with_four_bounded_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("local-send-trace");
    let (tx, rx) = mpsc::sync_channel(CAPACITY);
    let counts = Arc::new(Counts::default());
    counts.running.store(true, Ordering::Release);
    counts
        .live
        .lock()
        .unwrap()
        .observe(Kind::AdmissionBegin, 1, 77, [0; 8], 7);
    let worker_counts = counts.clone();
    let worker_path = path.clone();
    let handle = std::thread::spawn(move || {
        write_loop(&worker_path, &"ab".repeat(16), &worker_counts, rx).unwrap()
    });
    for seq in 1..=8000 {
        tx.send(Row {
            schema: 1,
            process: "ab".repeat(16),
            seq,
            elapsed_ms: seq,
            kind: Kind::AdmissionBegin,
            owner: 1,
            operation: seq,
            values: [0; 8],
        })
        .unwrap();
    }
    wait_for(|| manifest(dir.path()).is_some_and(|m| m["last_written_seq"] == 8000));
    counts.running.store(false, Ordering::Release);
    drop(tx);
    handle.join().unwrap();
    assert!(manifest(dir.path()).unwrap()["rotations"].as_u64().unwrap() >= 4);
    assert_eq!(manifest(dir.path()).unwrap()["operations"][0][0], 77);
    assert_eq!(manifest(dir.path()).unwrap()["operations"][0][4], 7);
    for n in 0..SEGMENTS {
        assert!(
            fs::metadata(path.join(format!("segment-{n}.jsonl")))
                .unwrap()
                .len()
                <= SEGMENT_BYTES as u64
        );
    }
    assert!(rows(dir.path()).first().unwrap()["seq"].as_u64().unwrap() > 1);
}

#[cfg(unix)]
#[test]
fn symlink_sidecar_is_rejected_without_touching_target() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("keep"), b"unchanged").unwrap();
    symlink(outside.path(), dir.path().join("local-send-trace")).unwrap();
    let trace = Trace::new(dir.path());
    trace.enable(true);
    wait_for(|| {
        trace
            .state
            .lock()
            .unwrap()
            .session
            .as_ref()
            .unwrap()
            .counts
            .write_failures
            .load(Ordering::Relaxed)
            > 0
    });
    trace.enable(false);
    assert_eq!(fs::read(outside.path().join("keep")).unwrap(), b"unchanged");
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 1);
}

struct Spy(Arc<Mutex<Vec<AuditRecord>>>);
impl ForensicRecorder for Spy {
    fn record(&self, r: AuditRecord) {
        self.0.lock().unwrap().push(r);
    }
    fn records_v5(&self) -> bool {
        true
    }
}
#[test]
fn recorder_correlates_actual_entry_and_forwards_original_context_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let trace = Arc::new(Trace::new(dir.path()));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorder = trace.decorate("private-owner", Box::new(Spy(calls.clone())));
    let owner = trace.owner("private-owner");
    let token = trace.operation(owner, "private-operation", trace.token());
    let record = AuditRecord {
        group_ref: Some("private-group".into()),
        context: Some(marmot_forensics::AuditEventContext {
            operation_id: Some("private-operation".into()),
            ..Default::default()
        }),
        kind: AuditEventKind::SendEntry {
            intent_kind: "app_message".into(),
        },
    };
    recorder.record(record);
    assert!(recorder.records_v5());
    wait_for(|| rows(dir.path()).iter().any(|r| r["kind"] == "engine_entry"));
    let entry = rows(dir.path())
        .into_iter()
        .find(|r| r["kind"] == "engine_entry")
        .unwrap();
    assert_eq!(entry["operation"], token);
    assert_eq!(entry["values"][1], 1);
    assert_eq!(
        calls.lock().unwrap()[0]
            .context
            .as_ref()
            .unwrap()
            .operation_id
            .as_deref(),
        Some("private-operation")
    );
    assert!(
        !serde_json::to_string(&rows(dir.path()))
            .unwrap()
            .contains("private")
    );
    trace.enable(false);
    // A late old recorder cannot re-enable revoked capture.
    let _late = trace.decorate("private-owner", Box::new(Spy(calls)));
    assert!(trace.state.lock().unwrap().session.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn durable_send_has_ordered_admission_selection_sync_and_real_engine_entry() {
    let dir = tempfile::tempdir().unwrap();
    let account = crate::AccountHome::open(dir.path())
        .create_account("trace-fixture")
        .unwrap();
    let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()));
    app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .unwrap();
    let group = app
        .client(&account.label)
        .await
        .unwrap()
        .create_group("fixture", &[])
        .await
        .unwrap();
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    runtime
        .submit_text(
            &account.label,
            &group,
            "private fixture content".into(),
            "private fixture token".into(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if rows(dir.path()).iter().any(|r| r["kind"] == "completion") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let captured = rows(dir.path());
    let commit = captured
        .iter()
        .find(|r| r["kind"] == "admission_committed")
        .unwrap();
    let op = commit["operation"].clone();
    let kinds: Vec<_> = captured
        .iter()
        .filter(|r| r["operation"] == op)
        .map(|r| r["kind"].as_str().unwrap())
        .collect();
    let mut previous = 0;
    for required in [
        "admission_begin",
        "worker_acquired",
        "gate_wait",
        "gate_acquired",
        "admission_committed",
        "selected",
        "execution_begin",
        "pre_engine_sync_begin",
        "pre_engine_sync_end",
        "runtime_send_begin",
        "engine_entry",
        "runtime_send_end",
        "execution_end",
        "completion",
    ] {
        let found = kinds
            .iter()
            .position(|kind| *kind == required)
            .unwrap_or_else(|| panic!("missing {required}: {kinds:?}"));
        assert!(found >= previous, "out-of-order {required}: {kinds:?}");
        previous = found;
    }
    let serialized = serde_json::to_string(&captured).unwrap();
    assert!(!serialized.contains("private fixture"));
    assert!(!serialized.contains(&account.account_id_hex));
    runtime.shutdown_and_close().await.unwrap();
}

#[test]
fn unsampled_long_phase_and_pending_admission_remain_visible_without_new_events() {
    let dir = tempfile::tempdir().unwrap();
    let trace = Arc::new(Trace::new(dir.path()));
    trace.enable(true);
    let owner = trace.owner("private-owner");
    let operation = trace.token();
    trace.emit(Kind::AdmissionBegin, 0, operation, [0; 8]);
    trace.emit(Kind::WorkerAcquired, owner, operation, [0; 8]);
    {
        let _first = trace.branch(owner, 4);
    }
    let held = trace.branch(owner, 4);
    assert!(
        !held.recorded,
        "second branch must exercise sample suppression"
    );
    wait_for(|| manifest(dir.path()).is_some_and(|m| m["owners"][0][2] == 4));
    let m = manifest(dir.path()).unwrap();
    assert_eq!(m["operations"][0][0], operation);
    assert_eq!(m["operations"][0][1], owner);
    assert_eq!(m["operations"][0][2].as_u64().unwrap() & 3, 3);
    assert_eq!(m["owners"][0][4], held.phase_token);
    let age = m["live_snapshot_elapsed_ms"].as_u64().unwrap();
    wait_for(|| {
        manifest(dir.path())
            .is_some_and(|m| m["live_snapshot_elapsed_ms"].as_u64().unwrap() > age + 200)
    });
    drop(held);
    wait_for(|| manifest(dir.path()).is_some_and(|m| m["owners"][0][2] == 0));
    trace.enable(false);
}

#[test]
fn final_manifest_counts_lock_loss_without_a_later_successful_emit() {
    let dir = tempfile::tempdir().unwrap();
    let trace = Trace::new(dir.path());
    trace.enable(true);
    {
        let _held = trace.state.lock().unwrap();
        trace.emit(Kind::AdmissionBegin, 0, 7, [0; 8]);
    }
    trace.enable(false);
    assert_eq!(manifest(dir.path()).unwrap()["dropped"], 1);
}

#[test]
fn active_snapshot_is_bounded_and_clear_removes_preclear_milestones() {
    let dir = tempfile::tempdir().unwrap();
    let trace = Trace::new(dir.path());
    trace.enable(true);
    for operation in 1..=257 {
        trace.emit(Kind::AdmissionBegin, 1, operation, [0; 8]);
    }
    wait_for(|| {
        manifest(dir.path()).is_some_and(|m| m["operations"].as_array().unwrap().len() == 256)
    });
    assert!(manifest(dir.path()).unwrap()["dropped"].as_u64().unwrap() >= 1);
    fs::remove_file(dir.path().join("local-send-trace/segment-0.jsonl")).unwrap();
    wait_for(|| manifest(dir.path()).is_some_and(|m| m["clear_count"] == 1));
    assert!(
        manifest(dir.path()).unwrap()["operations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    trace.enable(false);
}

#[test]
fn failed_completion_stays_pending_when_terminal_snapshots_are_evicted() {
    let mut live = Live::default();
    assert!(live.observe(Kind::AdmissionBegin, 1, 1, [0; 8], 1));
    assert!(live.observe(Kind::Completion, 1, 1, values(0), 2));
    for operation in 2..=256 {
        assert!(live.observe(Kind::Completion, 1, operation, values(1), operation));
    }
    assert!(live.observe(Kind::AdmissionBegin, 1, 257, [0; 8], 300));
    assert!(live.operations.contains_key(&1));
    assert!(!live.operations.contains_key(&2));
    assert_eq!(live.operations[&1][2] >> 63, 0);
}

#[test]
fn controlled_recorder_overhead_sanity() {
    // Same in-memory forensic recorder and callbacks in both modes. This is a
    // measured diagnostic, not a timing SLA or a phone performance prediction.
    for enabled in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let trace = Arc::new(Trace::new(dir.path()));
        trace.enable(enabled);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorder = trace.decorate("fixture", Box::new(Spy(calls.clone())));
        let owner = trace.owner("fixture");
        let operation = trace.operation(owner, "fixture-op", trace.token());
        let start = Instant::now();
        let mut worst_ns = 0;
        for _ in 0..1000 {
            let before = Instant::now();
            recorder.record(AuditRecord {
                group_ref: None,
                context: Some(marmot_forensics::AuditEventContext {
                    operation_id: Some("fixture-op".into()),
                    ..Default::default()
                }),
                kind: AuditEventKind::SendEntry {
                    intent_kind: "app_message".into(),
                },
            });
            worst_ns = worst_ns.max(before.elapsed().as_nanos());
        }
        let elapsed = start.elapsed();
        assert_eq!(calls.lock().unwrap().len(), 1000);
        if enabled {
            wait_for(|| {
                manifest(dir.path())
                    .is_some_and(|m| m["last_written_seq"].as_u64().unwrap_or(0) >= 1000)
            });
        }
        trace.enable(false);
        let drops = manifest(dir.path())
            .map(|m| m["dropped"].as_u64().unwrap())
            .unwrap_or(0);
        eprintln!(
            "incident_trace_overhead enabled={enabled} callbacks=1000 total_us={} max_callback_ns={worst_ns} drops={drops} operation_known={}",
            elapsed.as_micros(),
            operation != 0
        );
    }
}

#[test]
fn running_owner_resolves_after_enable_and_across_capture_generations() {
    let dir = tempfile::tempdir().unwrap();
    let trace = Arc::new(Trace::new(dir.path()));
    assert_eq!(trace.owner("running-worker"), 0);
    trace.enable(true);
    let first = trace.owner("running-worker");
    assert_ne!(first, 0);
    {
        let _phase = trace.branch(first, 10);
        trace.worker_state(first, [0, 0, 0, 0, 0, 0, 7, 0]);
    }
    wait_for(|| manifest(dir.path()).is_some_and(|m| m["owners"][0][0] == first));
    trace.enable(false);
    trace.enable(true);
    let second = trace.owner("running-worker");
    assert_ne!(second, first);
    let held = trace.branch(second, 4);
    wait_for(|| {
        manifest(dir.path()).is_some_and(|m| m["owners"][0][0] == second && m["owners"][0][2] == 4)
    });
    drop(held);
    trace.enable(false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_worker_refreshes_owner_after_live_enable_and_reenable() {
    let dir = tempfile::tempdir().unwrap();
    let account = crate::AccountHome::open(dir.path())
        .create_account("toggle-fixture")
        .unwrap();
    let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()));
    app.set_audit_log_settings(crate::AuditLogSettings { enabled: false })
        .unwrap();
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    // Completion proves the managed worker ran before capture was enabled.
    runtime
        .create_group(&account.label, "before", &[], None)
        .await
        .unwrap();
    assert!(manifest(dir.path()).is_none());
    let mut prior_owner = 0;
    let mut prior_process = Value::Null;
    for _ in 0..2 {
        runtime
            .set_audit_log_settings(crate::AuditLogSettings { enabled: true })
            .await
            .unwrap();
        let group = runtime
            .create_group(&account.label, "after", &[], None)
            .await
            .unwrap();
        runtime
            .submit_text(
                &account.label,
                &group,
                "fixture".into(),
                "fixture-token".into(),
            )
            .await
            .unwrap();
        let snapshot = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(m) = manifest(dir.path())
                    && rows(dir.path()).iter().any(|r| {
                        r["kind"] == "engine_entry"
                            && r["owner"].as_u64().unwrap() != 0
                            && r["operation"].as_u64().unwrap() != 0
                    })
                    && m["process"] != prior_process
                    && m["owners"].as_array().is_some_and(|owners| {
                        owners.iter().any(|o| {
                            o[0].as_u64().unwrap() != 0
                                && o[1].as_u64().unwrap() != 0
                                && o[2].as_u64().unwrap() != 0
                        })
                    })
                {
                    break m;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let owner = snapshot["owners"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o[1].as_u64().unwrap() != 0 && o[2].as_u64().unwrap() != 0)
            .unwrap()[0]
            .as_u64()
            .unwrap();
        assert_ne!(owner, prior_owner);
        prior_owner = owner;
        prior_process = snapshot["process"].clone();
        runtime
            .set_audit_log_settings(crate::AuditLogSettings { enabled: false })
            .await
            .unwrap();
    }
    runtime.shutdown_and_close().await.unwrap();
}

#[test]
fn shutdown_counts_every_prequeued_row_without_drain_race() {
    let dir = tempfile::tempdir().unwrap();
    let (tx, rx) = mpsc::sync_channel(CAPACITY);
    for seq in 1..=37 {
        tx.send(Row {
            schema: 1,
            process: "ab".repeat(16),
            seq,
            elapsed_ms: seq,
            kind: Kind::AdmissionBegin,
            owner: 1,
            operation: 1,
            values: [0; 8],
        })
        .unwrap();
    }
    let counts = Counts::default(); // Already stopped before writer starts.
    write_loop(
        &dir.path().join("local-send-trace"),
        &"ab".repeat(16),
        &counts,
        rx,
    )
    .unwrap();
    let m = manifest(dir.path()).unwrap();
    assert_eq!(m["dropped"], 37);
    assert_eq!(m["last_written_seq"], 0);
    assert_eq!(m["recording"], false);
}
