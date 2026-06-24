use super::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn noop_recorder_is_no_op() {
    let recorder = NoopRecorder;
    recorder.record(AuditRecord::new(
        Some("aa".into()),
        AuditEventKind::IngestEntry {
            msg_id: "bb".into(),
            envelope_kind: "welcome".into(),
            transport_source: "nostr".into(),
            payload_len: 0,
            payload_digest: "cc".into(),
        },
    ));
}

#[test]
fn jsonl_recorder_appends_events_with_monotonic_seq() {
    let dir = TempDir::new().unwrap();
    let path = default_jsonl_path(dir.path(), "engine-abc");
    let recorder = JsonlRecorder::open(&path, "engine-abc".to_string()).unwrap();
    recorder.record(AuditRecord::new(
        None,
        AuditEventKind::SendEntry {
            intent_kind: "app_message".into(),
        },
    ));
    recorder.record(AuditRecord::new(
        Some("group-1".into()),
        AuditEventKind::IngestEntry {
            msg_id: "msg-1".into(),
            envelope_kind: "group_message".into(),
            transport_source: "nostr".into(),
            payload_len: 42,
            payload_digest: "deadbeef".into(),
        },
    ));
    drop(recorder);

    let contents = fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 3);

    let first: AuditEvent = serde_json::from_str(lines[0]).unwrap();
    let second: AuditEvent = serde_json::from_str(lines[1]).unwrap();
    let third: AuditEvent = serde_json::from_str(lines[2]).unwrap();
    assert_eq!(first.seq, 0);
    assert_eq!(second.seq, 1);
    assert_eq!(third.seq, 2);
    assert_eq!(first.account_ref, None);
    assert_eq!(first.engine_id, "engine-abc");
    assert!(matches!(first.kind, AuditEventKind::RecorderStarted { .. }));
    assert_eq!(third.group_ref.as_deref(), Some("group-1"));
    assert_eq!(first.schema_version, AUDIT_LOG_SCHEMA_VERSION);
    assert!(first.recorder_session_id.is_some());
}

#[test]
fn jsonl_recorder_rotate_discards_old_lines_and_keeps_recording() {
    let dir = TempDir::new().unwrap();
    let path = default_jsonl_path(dir.path(), "engine-abc");
    let recorder = JsonlRecorder::open(&path, "engine-abc".to_string()).unwrap();
    recorder.record(AuditRecord::new(
        None,
        AuditEventKind::SendEntry {
            intent_kind: "app_message".into(),
        },
    ));
    // `recorder_started` + the one row above.
    assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 2);

    assert_eq!(recorder.audit_log_path().as_deref(), Some(path.as_path()));
    recorder.rotate().unwrap();

    // The rotated file replaces the old contents: it holds only the fresh
    // `recorder_started` boundary line, with the sequence reset to 0.
    let contents = fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 1);
    let started: AuditEvent = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(started.seq, 0);
    assert!(matches!(
        started.kind,
        AuditEventKind::RecorderStarted { .. }
    ));

    // Recording continues into the new file from that point forward.
    recorder.record(AuditRecord::new(
        None,
        AuditEventKind::SendEntry {
            intent_kind: "app_message".into(),
        },
    ));
    drop(recorder);
    let contents = fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 2);
    let second: AuditEvent = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(second.seq, 1);
}

#[test]
fn noop_recorder_has_no_path_and_rotate_is_a_no_op() {
    let recorder = NoopRecorder;
    assert!(recorder.audit_log_path().is_none());
    recorder.rotate().unwrap();
}

#[test]
fn jsonl_recorder_stamps_unattributed_rows_with_system_human_action() {
    let dir = TempDir::new().unwrap();
    let path = default_jsonl_path(dir.path(), "engine-abc");
    let recorder = JsonlRecorder::open(&path, "engine-abc".to_string()).unwrap();
    // `recorder_started` is emitted by `open`. Add the other two lifecycle
    // kinds, an inbound message-processing row (no human action), plus an
    // operation row that already carries a human action.
    recorder.record(AuditRecord::new(
        None,
        AuditEventKind::EngineContext {
            context: AuditEngineContext::default(),
        },
    ));
    recorder.record(AuditRecord::new(
        None,
        AuditEventKind::RecorderHealth {
            serialization_failures: 0,
            write_failures: 0,
            flush_failures: 0,
        },
    ));
    recorder.record(AuditRecord::new(
        Some("group-1".into()),
        AuditEventKind::IngestEntry {
            msg_id: "msg-1".into(),
            envelope_kind: "group_message".into(),
            transport_source: "nostr".into(),
            payload_len: 42,
            payload_digest: "deadbeef".into(),
        },
    ));
    recorder.record(
        AuditRecord::new(
            Some("group-1".into()),
            AuditEventKind::SendEntry {
                intent_kind: "app_message".into(),
            },
        )
        .with_context(AuditEventContext {
            human_action: Some(AuditHumanActionContext {
                action: "send_message".into(),
                origin: "local_user".into(),
                ..Default::default()
            }),
            ..Default::default()
        }),
    );
    drop(recorder);

    let events: Vec<AuditEvent> = fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();

    let human_action = |kind_name: &str| -> AuditHumanActionContext {
        events
            .iter()
            .find(|event| event.kind.type_tag() == kind_name)
            .and_then(|event| event.context.as_ref())
            .and_then(|ctx| ctx.human_action.clone())
            .unwrap_or_else(|| panic!("{kind_name} row should carry a human_action"))
    };

    // Every row that arrived without a human action — lifecycle rows and
    // the inbound ingest row alike — is backfilled with a system action
    // named after its own kind.
    for kind_name in [
        "recorder_started",
        "engine_context",
        "recorder_health",
        "ingest_entry",
    ] {
        let action = human_action(kind_name);
        assert_eq!(action.origin, "system");
        assert_eq!(action.action, kind_name);
    }
    // A row that already carries a human action keeps it untouched.
    let send = human_action("send_entry");
    assert_eq!(send.origin, "local_user");
    assert_eq!(send.action, "send_message");
}

#[test]
fn jsonl_recorder_records_account_ref_when_supplied() {
    let dir = TempDir::new().unwrap();
    let path = default_jsonl_path(dir.path(), "engine-abc");
    let account_ref = "0123456789abcdef0123456789abcdef".to_owned();
    let recorder = JsonlRecorder::open_with_account_ref(
        &path,
        "engine-abc".to_string(),
        Some(account_ref.clone()),
    )
    .unwrap();
    recorder.record(AuditRecord::new(
        None,
        AuditEventKind::SendEntry {
            intent_kind: "app_message".into(),
        },
    ));
    drop(recorder);

    let contents = fs::read_to_string(&path).unwrap();
    let event: AuditEvent = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
    assert_eq!(event.account_ref.as_deref(), Some(account_ref.as_str()));
}

#[test]
fn jsonl_recorder_rejects_invalid_account_ref() {
    let dir = TempDir::new().unwrap();
    let path = default_jsonl_path(dir.path(), "engine-abc");

    let err = match JsonlRecorder::open_with_account_ref(
        &path,
        "engine-abc".to_string(),
        Some("account-abc".to_string()),
    ) {
        Ok(_) => panic!("invalid account_ref should be rejected"),
        Err(err) => err,
    };

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn audit_event_round_trips_through_serde() {
    let event = AuditEvent {
        schema_version: AUDIT_LOG_SCHEMA_VERSION.into(),
        seq: 7,
        wall_time_ms: 1_700_000_000_000,
        recorder_session_id: Some("recorder-1".into()),
        account_ref: Some("account-1".into()),
        engine_id: "engine-xyz".into(),
        group_ref: Some("group-1".into()),
        context: Some(AuditEventContext {
            operation_id: Some("op-7".into()),
            human_action: Some(AuditHumanActionContext {
                action: "update_group_profile".into(),
                origin: "local_user".into(),
                fields: vec!["name".into()],
                component_ids: vec![0x8001],
                target_count: None,
            }),
            transport: None,
            engine: None,
            group: None,
        }),
        kind: AuditEventKind::ForkResolution {
            source_epoch: 4,
            candidate_digest: "aaaa".into(),
            incumbent_digest: Some("bbbb".into()),
            winner: ForkWinner::Candidate,
            invalidated_msg_id: Some("msg-x".into()),
        },
    };
    let json = serde_json::to_string(&event).unwrap();
    let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, event);
}

fn sample_audit_event_kinds() -> Vec<AuditEventKind> {
    vec![
        AuditEventKind::RecorderStarted {
            recorder_session_id: "recorder-1".into(),
            recorder: "jsonl".into(),
        },
        AuditEventKind::EngineContext {
            context: AuditEngineContext {
                ciphersuite: Some(1),
                max_past_epochs: Some(10),
                convergence_max_rewind_commits: Some(5),
                supported_app_component_count: Some(2),
                feature_count: Some(3),
            },
        },
        AuditEventKind::GroupContext {
            reason: "open".into(),
            context: AuditGroupContext {
                epoch: Some(1),
                member_count: Some(2),
                required_app_component_count: Some(1),
                admin_count: Some(1),
                convergence_max_rewind_commits: Some(5),
            },
        },
        AuditEventKind::RecorderHealth {
            serialization_failures: 0,
            write_failures: 1,
            flush_failures: 2,
        },
        AuditEventKind::HumanAction {
            action: "update_group_profile".into(),
            origin: "local_user".into(),
            phase: "succeeded".into(),
            fields: vec!["name".into(), "description".into()],
            component_ids: vec![0x8001],
            target_count: None,
            message_ids: vec!["m".into()],
            from_epoch: Some(1),
            to_epoch: Some(2),
            error_kind: None,
            detail: None,
        },
        AuditEventKind::IngestEntry {
            msg_id: "m".into(),
            envelope_kind: "welcome".into(),
            transport_source: "nostr".into(),
            payload_len: 1,
            payload_digest: "d".into(),
        },
        AuditEventKind::IngestOutcome {
            msg_id: "m".into(),
            outcome_kind: "stale".into(),
            stale_reason: Some("already_seen".into()),
            epoch: Some(0),
        },
        AuditEventKind::IngestError {
            msg_id: "m".into(),
            error_kind: "unknown_group".into(),
            detail: Some("unknown group".into()),
        },
        AuditEventKind::SendEntry {
            intent_kind: "app_message".into(),
        },
        AuditEventKind::SendOutcome {
            intent_kind: "invite".into(),
            result_kind: "group_evolution".into(),
            outbound_msg_id: Some("m".into()),
            outbound_welcome_msg_ids: vec!["w1".into(), "w2".into()],
        },
        AuditEventKind::SendError {
            intent_kind: "invite".into(),
            error_kind: "unknown_member".into(),
            detail: None,
        },
        AuditEventKind::CreateGroupEntry {
            member_count: 3,
            required_feature_count: 1,
            app_component_count: 2,
            initial_admin_count: 1,
        },
        AuditEventKind::CreateGroupOutcome {
            result_kind: "group_created".into(),
            outbound_welcome_msg_ids: vec!["w1".into()],
        },
        AuditEventKind::CreateGroupError {
            error_kind: "missing_required_capabilities".into(),
            detail: Some("feature missing".into()),
        },
        AuditEventKind::PublishAttempt {
            msg_id: "m".into(),
            target_kind: "group".into(),
            relay_urls: vec!["wss://relay.example".into()],
            required_acks: 1,
        },
        AuditEventKind::PublishOutcome {
            msg_id: "m".into(),
            target_kind: "group".into(),
            accepted_relay_urls: vec!["wss://relay.example".into()],
            failed_relays: vec![PublishRelayFailure {
                relay_url: "wss://bad.example".into(),
                reason: "timeout".into(),
            }],
            required_acks: 1,
            met_required_acks: true,
        },
        AuditEventKind::PublishFailure {
            msg_id: "m".into(),
            stage: "required_acks".into(),
            target_kind: "group".into(),
            relay_urls: vec!["wss://bad.example".into()],
            reason: "insufficient publish acknowledgements".into(),
        },
        AuditEventKind::EpochConfirmed {
            from_epoch: 0,
            to_epoch: 1,
            pending_kind: "create_group".into(),
        },
        AuditEventKind::EpochRolledBack {
            pending_epoch: 1,
            restored_epoch: 0,
            pending_kind: "group_evolution".into(),
        },
        AuditEventKind::EpochStateChanged {
            previous_state: Some("pending_publish".into()),
            new_state: "stable".into(),
            epoch: 1,
            reason: "publish_confirmed".into(),
            pending_ref: Some(7),
            pending_kind: Some("group_evolution".into()),
        },
        AuditEventKind::GroupStateChanged {
            epoch: 2,
            change_kind: "member_added".into(),
            actor_member_ref: Some("a".repeat(32)),
            subject_member_ref: Some("b".repeat(32)),
            origin_commit_id: Some("m".into()),
            fields: vec!["members".into()],
            component_ids: Vec::new(),
            value_digest: None,
            value_len: None,
        },
        AuditEventKind::PendingCommitRecoveredOnOpen { recovered_epoch: 3 },
        AuditEventKind::GroupHydrationQuarantined {
            group_digest: "b".repeat(64),
            reason: "openmls_load_failed".into(),
        },
        AuditEventKind::GroupHydrationRecovered {
            group_digest: "a".repeat(64),
        },
        AuditEventKind::SnapshotCreated {
            snapshot_name: "fork-1-2-abc".into(),
            source_epoch: 0,
            reason: "pre_commit".into(),
        },
        AuditEventKind::ForkResolution {
            source_epoch: 2,
            candidate_digest: "c".repeat(64),
            incumbent_digest: Some("d".repeat(64)),
            winner: ForkWinner::Candidate,
            invalidated_msg_id: Some("m".into()),
        },
        AuditEventKind::ConvergenceDecision {
            current_tip_epoch: 3,
            candidate_count: 2,
            eligible_count: 1,
            max_rewind_commits: 5,
            selected_branch_id: Some("br-1".into()),
            selected_fork_epoch: Some(2),
            selected_tip_epoch: Some(3),
            error_kinds: vec!["missing_retained_anchor".into()],
        },
        AuditEventKind::PeelerOutcome {
            msg_id: "m".into(),
            outcome: PeelerOutcomeKind::DecryptFailed,
            fallback_snapshot_used: true,
            fallback_snapshot_name: Some("fork-anchor-1".into()),
            fallback_snapshot_source_epoch: Some(1),
            fallback_attempt_count: Some(2),
            error_kind: Some("decrypt_failed".into()),
            detail: None,
        },
        AuditEventKind::AutoCommitDecision {
            proposal_kind: "self_remove".into(),
            decision: "observe".into(),
            reason: Some("not_lowest_index".into()),
        },
        AuditEventKind::MessageStateChanged {
            msg_id: "m".into(),
            previous_state: Some("created".into()),
            new_state: "epoch_invalidated".into(),
            epoch: Some(3),
            reason: "fork_loser".into(),
        },
        AuditEventKind::Rejection {
            msg_id: "m".into(),
            reason: "unattributable_sender".into(),
        },
    ]
}

#[test]
fn audit_event_kind_round_trips_all_variants() {
    for kind in sample_audit_event_kinds() {
        let event = AuditEvent {
            schema_version: AUDIT_LOG_SCHEMA_VERSION.into(),
            seq: 0,
            wall_time_ms: 0,
            recorder_session_id: None,
            account_ref: None,
            engine_id: "e".into(),
            group_ref: None,
            context: None,
            kind: kind.clone(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.kind, kind);
    }
}

#[test]
fn audit_log_event_schema_tracks_kind_catalog() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../schema/audit-log-event.v1.schema.json")).unwrap();
    assert_eq!(
        schema
            .pointer("/properties/schema_version/const")
            .and_then(serde_json::Value::as_str),
        Some(AUDIT_LOG_SCHEMA_VERSION)
    );

    let schema_tags = schema
        .pointer("/$defs/auditEventKind/oneOf")
        .and_then(serde_json::Value::as_array)
        .expect("schema kind oneOf")
        .iter()
        .map(|variant| {
            variant
                .pointer("/properties/type/const")
                .and_then(serde_json::Value::as_str)
                .expect("kind type const")
                .to_string()
        })
        .collect::<std::collections::BTreeSet<_>>();

    let code_tags = sample_audit_event_kinds()
        .iter()
        .map(|kind| kind.type_tag().to_string())
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(schema_tags, code_tags);
}
