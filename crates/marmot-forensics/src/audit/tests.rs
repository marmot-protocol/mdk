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
        audit_data_mode: AuditDataMode::FullData,
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
            convergence: None,
            source: None,
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
            recorder: "jsonl".into(),
        },
        AuditEventKind::AuditDataModeChanged {
            previous_mode: AuditDataMode::ObfuscatedSensitiveData,
            new_mode: AuditDataMode::FullData,
            reason: "settings_changed".into(),
            recorder_restarted: Some(true),
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
        AuditEventKind::TransportReceived {
            msg_id: Some("m".into()),
            transport: AuditTransportWire {
                transport: Some("nostr".into()),
                delivery_plane: Some("group".into()),
                wire_id: Some("e".repeat(64)),
                wire_kind: Some("445".into()),
                wire_pubkey_hex: Some("f".repeat(64)),
                transport_group_id: Some("ab".repeat(16)),
                relay_url: Some("wss://relay.example".into()),
                subscription_id: Some("sub-1".into()),
                nostr_event_id: Some("e".repeat(64)),
                nostr_kind: Some(445),
                nostr_pubkey_hex: Some("f".repeat(64)),
                gift_wrap_event_id: None,
                welcome_nostr_event_id: None,
                welcome_rumor_event_id: None,
                welcome_key_package_tag: None,
                publish_result_id: None,
            },
            payload_len: 1,
            payload_digest: "d".repeat(64),
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
        AuditEventKind::RecipientExpectation {
            msg_id: "m".into(),
            expectation: RecipientExpectation {
                artifact_kind: MessageArtifactKind::Commit,
                recipient_scope: RecipientScope::AllOtherCurrentGroupMembers,
                membership_epoch: Some(3),
                basis_commit_id: None,
                expected_member_refs: vec!["a".repeat(32), "b".repeat(32)],
                expected_pubkeys_hex: vec!["c".repeat(64)],
                expected_count: Some(2),
            },
        },
        AuditEventKind::SendOutcome {
            intent_kind: "invite".into(),
            result_kind: "group_evolution".into(),
            outbound_messages: vec![
                OutboundMessage {
                    msg_id: "m".into(),
                    artifact_kind: MessageArtifactKind::Commit,
                    transport: None,
                    recipient_expectation: None,
                },
                OutboundMessage {
                    msg_id: "w1".into(),
                    artifact_kind: MessageArtifactKind::Welcome,
                    transport: None,
                    recipient_expectation: None,
                },
            ],
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
            outbound_messages: vec![OutboundMessage {
                msg_id: "w1".into(),
                artifact_kind: MessageArtifactKind::Welcome,
                transport: None,
                recipient_expectation: Some(RecipientExpectation {
                    artifact_kind: MessageArtifactKind::Welcome,
                    recipient_scope: RecipientScope::AddedMemberOnly,
                    membership_epoch: Some(1),
                    basis_commit_id: None,
                    expected_member_refs: vec!["a".repeat(32)],
                    expected_pubkeys_hex: Vec::new(),
                    expected_count: Some(1),
                }),
            }],
        },
        AuditEventKind::CreateGroupError {
            error_kind: "missing_required_capabilities".into(),
            detail: Some("feature missing".into()),
        },
        AuditEventKind::PublishAttempt {
            msg_id: "m".into(),
            artifact_kind: Some(MessageArtifactKind::Commit),
            target_kind: "group".into(),
            relay_url: None,
            relay_urls: vec!["wss://relay.example".into()],
            required_acks: 1,
            transport: Some(AuditTransportWire {
                transport: Some("nostr".into()),
                delivery_plane: Some("group".into()),
                transport_group_id: Some("ab".repeat(16)),
                ..Default::default()
            }),
        },
        AuditEventKind::PublishOutcome {
            msg_id: "m".into(),
            artifact_kind: Some(MessageArtifactKind::Commit),
            target_kind: "group".into(),
            relay_url: None,
            accepted_relay_urls: vec!["wss://relay.example".into()],
            failed_relays: vec![PublishRelayFailure {
                relay_url: "wss://bad.example".into(),
                reason: "timeout".into(),
            }],
            required_acks: 1,
            met_required_acks: true,
            transport: None,
        },
        AuditEventKind::PublishFailure {
            msg_id: "m".into(),
            artifact_kind: Some(MessageArtifactKind::Welcome),
            stage: "required_acks".into(),
            target_kind: "group".into(),
            relay_url: None,
            relay_urls: vec!["wss://bad.example".into()],
            required_acks: Some(1),
            reason: "insufficient publish acknowledgements".into(),
            detail: None,
            transport: None,
        },
        AuditEventKind::EpochConfirmed {
            from_epoch: 0,
            to_epoch: 1,
            pending_kind: "create_group".into(),
            origin_commit_id: Some("m".into()),
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
            membership_change_source: Some(MembershipChangeSource::AdminAction),
            actor_member_ref: Some("a".repeat(32)),
            actor_pubkey_hex: Some("a".repeat(64)),
            subject_member_ref: Some("b".repeat(32)),
            subject_pubkey_hex: Some("b".repeat(64)),
            origin_commit_id: Some("m".into()),
            fields: vec!["members".into()],
            component_ids: Vec::new(),
            value: Some(GroupStateValue {
                digest: Some("c".repeat(64)),
                len: Some(4),
                text: Some("Team".into()),
                json: None,
                pubkeys_hex: vec!["a".repeat(64)],
            }),
        },
        AuditEventKind::SourceContext {
            source: AuditSourceContext {
                account_label: Some("Alice".into()),
                device_label: Some("Alice iPhone".into()),
                device_id: Some("device-1".into()),
                device_name: Some("iPhone".into()),
                platform: Some("ios".into()),
                app_version: Some("2026.6.8".into()),
                upload_trigger: Some("managed_send".into()),
                account_pubkey_hex: Some("a".repeat(64)),
                account_npub: Some("npub1example".into()),
            },
        },
        AuditEventKind::MessageContentDecoded {
            msg_id: "m".into(),
            artifact_kind: Some(MessageArtifactKind::ApplicationMessage),
            author: MessageAuthor {
                member_ref: Some("a".repeat(32)),
                member_pubkey_hex: Some("a".repeat(64)),
                account_pubkey_hex: Some("a".repeat(64)),
                npub: Some("npub1example".into()),
            },
            decoded_payload: DecodedPayload {
                content_type: "application/x-marmot-app-event".into(),
                text: None,
                json: Some(serde_json::json!({"kind": 9, "content": "hi"})),
                bytes_b64: None,
            },
            decoded_app_event: Some(DecodedApplicationEvent {
                format: "marmot.app_event.v1".into(),
                kind: Some(9),
                content: Some("hi".into()),
                pubkey_hex: Some("a".repeat(64)),
                tags: vec![vec!["imeta".into(), "url https://blossom.example/x".into()]],
                created_at_ms: Some(1_700_000_000_000),
                client_message_id: Some("client-1".into()),
                reply_to_message_id: None,
                thread_root_message_id: None,
                attachments: vec![AttachmentMetadata {
                    component_id: Some(0x8001),
                    content_type: Some("image/png".into()),
                    file_name: Some("pic.png".into()),
                    byte_len: Some(1024),
                    digest: Some("d".repeat(64)),
                    metadata: None,
                }],
                raw: None,
            }),
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
            state_digest: Some("e".repeat(64)),
        },
        AuditEventKind::ForkResolution {
            source_epoch: 2,
            candidate_digest: "c".repeat(64),
            incumbent_digest: Some("d".repeat(64)),
            winner: ForkWinner::Candidate,
            invalidated_msg_id: Some("m".into()),
        },
        AuditEventKind::ConvergenceRunState {
            phase: ConvergencePhase::Evaluating,
            current_tip_epoch: Some(3),
            retained_anchor_horizon: Some(1),
            reason: Some("input_window_open".into()),
            error_kind: None,
        },
        AuditEventKind::ConvergenceDecision {
            current_tip_epoch: 3,
            max_rewind_commits: 5,
            candidates: vec![ConvergenceCandidate {
                branch_id: "br-1".into(),
                fork_epoch: 2,
                tip_epoch: 3,
                commit_ids: vec!["m".into()],
                commit_count: Some(1),
                state_digest: None,
                tip_digest: Some("a".repeat(64)),
                tip_priority: Some("ordinary".into()),
                tip_committer_ref: Some("b".repeat(32)),
                tip_committer_pubkey_hex: None,
                retained_anchor_status: Some("at_or_after".into()),
                last_input_time_ms: Some(1_700_000_000_000),
                eligible: Some(true),
                rejection_reasons: Vec::new(),
                score: Some(ConvergenceScore {
                    valid_commit_depth: Some(1),
                    effective_commit_depth: Some(1),
                    witness_quorum_met: Some(false),
                    app_witness_score: Some(0),
                    tip_priority: Some("ordinary".into()),
                    tip_committer_ref: Some("b".repeat(32)),
                    tip_committer_pubkey_hex: None,
                    tip_digest: Some("a".repeat(64)),
                }),
                app_witnesses: vec![ConvergenceAppWitness {
                    epoch: 3,
                    sender_ref: Some("c".repeat(32)),
                    sender_pubkey_hex: None,
                }],
            }],
            rule_trace: vec![ConvergenceRuleEvaluation {
                rule_name: "effective_commit_depth".into(),
                scope: Some("candidate_pair".into()),
                candidate_branch_id: Some("br-1".into()),
                other_candidate_branch_id: Some("br-2".into()),
                inputs: Some(serde_json::json!({"a": 1, "b": 0})),
                result: serde_json::json!("greater"),
                decisive: Some(true),
                selected_branch_id: Some("br-1".into()),
                rejected_branch_id: Some("br-2".into()),
            }],
            selected_branch_id: Some("br-1".into()),
            selected_fork_epoch: Some(2),
            selected_tip_epoch: Some(3),
            losing_branch_ids: vec!["br-2".into()],
            error_kinds: vec!["missing_retained_anchor".into()],
        },
        AuditEventKind::PeelerOutcome {
            msg_id: "m".into(),
            artifact_kind: None,
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
            artifact_kind: Some(MessageArtifactKind::ApplicationMessage),
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
            audit_data_mode: AuditDataMode::default(),
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
        serde_json::from_str(include_str!("../../schema/audit-log-event.v2.schema.json")).unwrap();
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

#[test]
fn jsonl_recorder_defaults_to_obfuscated_mode_and_stamps_every_event() {
    let dir = TempDir::new().unwrap();
    let path = default_jsonl_path(dir.path(), "engine-abc");
    let recorder = JsonlRecorder::open(&path, "engine-abc".to_string()).unwrap();
    assert_eq!(recorder.data_mode(), AuditDataMode::ObfuscatedSensitiveData);
    recorder.record(AuditRecord::new(
        None,
        AuditEventKind::SendEntry {
            intent_kind: "app_message".into(),
        },
    ));
    drop(recorder);

    // Both the `recorder_started` boundary and the row above carry the mode.
    let events: Vec<AuditEvent> = fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .all(|event| event.audit_data_mode == AuditDataMode::ObfuscatedSensitiveData)
    );
}

#[test]
fn jsonl_recorder_opened_in_full_data_mode_stamps_full_data() {
    let dir = TempDir::new().unwrap();
    let path = default_jsonl_path(dir.path(), "engine-full");
    let recorder = JsonlRecorder::open_with_data_mode(
        &path,
        "engine-full".to_string(),
        None,
        AuditDataMode::FullData,
    )
    .unwrap();
    assert_eq!(recorder.data_mode(), AuditDataMode::FullData);
    drop(recorder);

    let event: AuditEvent =
        serde_json::from_str(fs::read_to_string(&path).unwrap().lines().next().unwrap()).unwrap();
    assert_eq!(event.audit_data_mode, AuditDataMode::FullData);
}

#[test]
fn set_data_mode_rotates_and_writes_a_clear_boundary() {
    let dir = TempDir::new().unwrap();
    let path = default_jsonl_path(dir.path(), "engine-abc");
    let recorder = JsonlRecorder::open(&path, "engine-abc".to_string()).unwrap();
    recorder.record(AuditRecord::new(
        None,
        AuditEventKind::SendEntry {
            intent_kind: "app_message".into(),
        },
    ));
    // `recorder_started` + the obfuscated send row.
    assert_eq!(fs::read_to_string(&path).unwrap().lines().count(), 2);

    recorder
        .set_data_mode(AuditDataMode::FullData, "settings_changed")
        .unwrap();
    assert_eq!(recorder.data_mode(), AuditDataMode::FullData);

    // The rotation discards the obfuscated lines: the fresh file holds only the
    // `recorder_started` marker and the `audit_data_mode_changed` boundary, both
    // stamped with the new mode and starting from seq 0.
    let events: Vec<AuditEvent> = fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].seq, 0);
    assert!(matches!(
        events[0].kind,
        AuditEventKind::RecorderStarted { .. }
    ));
    assert_eq!(events[1].seq, 1);
    match &events[1].kind {
        AuditEventKind::AuditDataModeChanged {
            previous_mode,
            new_mode,
            reason,
            recorder_restarted,
        } => {
            assert_eq!(*previous_mode, AuditDataMode::ObfuscatedSensitiveData);
            assert_eq!(*new_mode, AuditDataMode::FullData);
            assert_eq!(reason, "settings_changed");
            assert_eq!(*recorder_restarted, Some(true));
        }
        other => panic!("expected audit_data_mode_changed, got {other:?}"),
    }
    assert!(
        events
            .iter()
            .all(|event| event.audit_data_mode == AuditDataMode::FullData),
        "the rotated file must be entirely the new mode"
    );

    // Recording continues into the new file under the new mode.
    recorder.record(AuditRecord::new(
        None,
        AuditEventKind::SendEntry {
            intent_kind: "app_message".into(),
        },
    ));
    drop(recorder);
    let last: AuditEvent =
        serde_json::from_str(fs::read_to_string(&path).unwrap().lines().last().unwrap()).unwrap();
    assert_eq!(last.audit_data_mode, AuditDataMode::FullData);
}

#[test]
fn set_data_mode_is_a_no_op_when_mode_is_unchanged() {
    let dir = TempDir::new().unwrap();
    let path = default_jsonl_path(dir.path(), "engine-abc");
    let recorder = JsonlRecorder::open(&path, "engine-abc".to_string()).unwrap();
    recorder.record(AuditRecord::new(
        None,
        AuditEventKind::SendEntry {
            intent_kind: "app_message".into(),
        },
    ));
    let before = fs::read_to_string(&path).unwrap();

    // Requesting the mode the recorder is already in must not rotate the file
    // nor insert a spurious boundary row.
    recorder
        .set_data_mode(AuditDataMode::ObfuscatedSensitiveData, "noop")
        .unwrap();

    assert_eq!(fs::read_to_string(&path).unwrap(), before);
    assert_eq!(recorder.data_mode(), AuditDataMode::ObfuscatedSensitiveData);
}

#[test]
fn noop_recorder_reports_default_mode_and_ignores_mode_change() {
    let recorder = NoopRecorder;
    assert_eq!(recorder.data_mode(), AuditDataMode::ObfuscatedSensitiveData);
    recorder
        .set_data_mode(AuditDataMode::FullData, "ignored")
        .unwrap();
    // A no-op recorder has no backing store; the default mode never changes.
    assert_eq!(recorder.data_mode(), AuditDataMode::ObfuscatedSensitiveData);
}

/// Minimal recursive JSON-Schema conformance check for the subset our schema
/// uses ($ref, properties, additionalProperties:false, items, and oneOf
/// discriminated by a `type` const). It does not validate value patterns; its
/// job is to prove every key we serialize is a key the schema allows — i.e. that
/// darkmatter never emits a field that Goggles' `additionalProperties: false`
/// would reject.
fn resolve_ref<'a>(
    schema: &'a serde_json::Value,
    defs: &'a serde_json::Value,
) -> &'a serde_json::Value {
    if let Some(reference) = schema.get("$ref").and_then(|v| v.as_str())
        && let Some(name) = reference.strip_prefix("#/$defs/")
        && let Some(def) = defs.get(name)
    {
        return resolve_ref(def, defs);
    }
    schema
}

fn assert_keys_within_schema(
    value: &serde_json::Value,
    schema: &serde_json::Value,
    defs: &serde_json::Value,
    path: &str,
) {
    let schema = resolve_ref(schema, defs);
    if let Some(one_of) = schema.get("oneOf").and_then(|v| v.as_array()) {
        // Discriminated union: match the branch by its `type` const. A oneOf
        // without a type discriminant (e.g. jsonValue) is treated as permissive.
        if let Some(tag) = value.get("type").and_then(|v| v.as_str()) {
            for branch in one_of {
                if branch
                    .pointer("/properties/type/const")
                    .and_then(|v| v.as_str())
                    == Some(tag)
                {
                    assert_keys_within_schema(value, branch, defs, path);
                    return;
                }
            }
            panic!("{path}: no schema branch for type {tag}");
        }
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            let props = schema.get("properties").and_then(|v| v.as_object());
            let closed = matches!(
                schema.get("additionalProperties"),
                Some(serde_json::Value::Bool(false))
            );
            for (key, child) in map {
                match props.and_then(|p| p.get(key)) {
                    Some(child_schema) => assert_keys_within_schema(
                        child,
                        child_schema,
                        defs,
                        &format!("{path}.{key}"),
                    ),
                    None => assert!(!closed, "{path}.{key}: key not allowed by schema"),
                }
            }
        }
        serde_json::Value::Array(items) => {
            if let Some(item_schema) = schema.get("items") {
                for (i, item) in items.iter().enumerate() {
                    assert_keys_within_schema(item, item_schema, defs, &format!("{path}[{i}]"));
                }
            }
        }
        _ => {}
    }
}

#[test]
fn sample_events_serialize_within_schema_property_names() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../schema/audit-log-event.v2.schema.json")).unwrap();
    let defs = schema["$defs"].clone();

    // Every sample kind, wrapped in a full event, must serialize using only keys
    // the schema allows (recursively, including nested wire/candidate/value/etc.).
    for kind in sample_audit_event_kinds() {
        let event = AuditEvent {
            schema_version: AUDIT_LOG_SCHEMA_VERSION.into(),
            seq: 0,
            wall_time_ms: 0,
            audit_data_mode: AuditDataMode::FullData,
            recorder_session_id: Some("r".into()),
            account_ref: Some("0".repeat(32)),
            engine_id: "e".into(),
            group_ref: Some("ab".into()),
            context: None,
            kind,
        };
        let value = serde_json::to_value(&event).unwrap();
        assert_keys_within_schema(&value, &schema, &defs, "event");
    }

    // Also exercise a fully-populated context (transport wire + convergence +
    // source + human_action), which the kind samples don't cover.
    let event = AuditEvent {
        schema_version: AUDIT_LOG_SCHEMA_VERSION.into(),
        seq: 0,
        wall_time_ms: 0,
        audit_data_mode: AuditDataMode::FullData,
        recorder_session_id: None,
        account_ref: None,
        engine_id: "e".into(),
        group_ref: None,
        context: Some(AuditEventContext {
            operation_id: Some("op".into()),
            human_action: Some(AuditHumanActionContext {
                action: "send_message".into(),
                origin: "local_user".into(),
                fields: vec!["name".into()],
                component_ids: vec![0x8001],
                target_count: Some(1),
            }),
            transport: Some(AuditTransportContext {
                transport_source: "nostr".into(),
                delivery_plane: Some("group".into()),
                relay_url: Some("wss://relay.example".into()),
                subscription_id: Some("sub".into()),
                wire: Some(AuditTransportWire {
                    transport: Some("nostr".into()),
                    wire_kind: Some("445".into()),
                    nostr_kind: Some(445),
                    nostr_event_id: Some("a".repeat(64)),
                    ..Default::default()
                }),
            }),
            engine: Some(AuditEngineContext::default()),
            group: Some(AuditGroupContext::default()),
            convergence: Some(AuditConvergenceContext {
                run_id: "conv-1".into(),
                phase: Some(ConvergencePhase::Evaluating),
                inferred: Some(false),
            }),
            source: Some(AuditSourceContext {
                account_label: Some("Alice".into()),
                account_pubkey_hex: Some("a".repeat(64)),
                ..Default::default()
            }),
        }),
        kind: AuditEventKind::SendEntry {
            intent_kind: "app_message".into(),
        },
    };
    let value = serde_json::to_value(&event).unwrap();
    assert_keys_within_schema(&value, &schema, &defs, "event");
}
