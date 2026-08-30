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
    assert!(recorder.is_enabled());
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
#[cfg(unix)]
fn audit_file_is_owner_only_on_open_and_rotation() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let path = default_jsonl_path(dir.path(), "engine-abc");
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;

    let recorder = JsonlRecorder::open(&path, "engine-abc".to_string()).unwrap();
    assert_eq!(mode(&path), 0o600);

    // Rotation stages a fresh file and renames it over the live path; the
    // fresh file must be owner-only too.
    recorder.rotate().unwrap();
    assert_eq!(mode(&path), 0o600);
}

#[test]
#[cfg(unix)]
fn pre_existing_permissive_audit_file_is_tightened_on_open() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let path = default_jsonl_path(dir.path(), "engine-abc");
    fs::write(&path, b"").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    let _recorder = JsonlRecorder::open(&path, "engine-abc".to_string()).unwrap();

    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
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
    assert!(!recorder.is_enabled());
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

#[test]
fn subscription_rebuild_round_trips_through_serde() {
    let kind = AuditEventKind::SubscriptionRebuild {
        since_secs: Some(1_699_999_880),
        lookback_secs: Some(120),
        relay_results: vec![
            RelayRegistration {
                relay_url: "wss://relay.example".into(),
                accepted: true,
            },
            RelayRegistration {
                relay_url: "wss://down.example".into(),
                accepted: false,
            },
        ],
    };
    let event = AuditEvent {
        schema_version: AUDIT_LOG_SCHEMA_VERSION.into(),
        seq: 11,
        wall_time_ms: 1_700_000_000_000,
        recorder_session_id: Some("recorder-1".into()),
        account_ref: None,
        engine_id: "engine-xyz".into(),
        group_ref: None,
        context: None,
        kind: kind.clone(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.kind, kind);
    // Full-history replay: `None` since floor is omitted, not serialized as null.
    let replay = AuditEventKind::SubscriptionRebuild {
        since_secs: None,
        lookback_secs: Some(120),
        relay_results: Vec::new(),
    };
    let replay_json = serde_json::to_string(&replay).unwrap();
    assert!(!replay_json.contains("since_secs"));
    assert!(!replay_json.contains("relay_results"));
    assert_eq!(
        serde_json::from_str::<AuditEventKind>(&replay_json).unwrap(),
        replay
    );
}

#[test]
fn sync_drain_round_trips_through_serde() {
    let kind = AuditEventKind::SyncDrain {
        duration_ms: 250,
        deliveries: 3,
        skipped: Some(17),
        refused: Some(1),
        cursor_before_secs: Some(1_699_999_880),
        cursor_after_secs: Some(1_700_000_000),
    };
    let event = AuditEvent {
        schema_version: AUDIT_LOG_SCHEMA_VERSION.into(),
        seq: 12,
        wall_time_ms: 1_700_000_000_000,
        recorder_session_id: Some("recorder-1".into()),
        account_ref: None,
        engine_id: "engine-xyz".into(),
        group_ref: None,
        context: None,
        kind: kind.clone(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.kind, kind);
    // A drain before any cursor advance omits both cursor fields.
    let empty = AuditEventKind::SyncDrain {
        duration_ms: 8,
        deliveries: 0,
        skipped: None,
        refused: None,
        cursor_before_secs: None,
        cursor_after_secs: None,
    };
    let empty_json = serde_json::to_string(&empty).unwrap();
    assert!(!empty_json.contains("cursor_before_secs"));
    assert!(!empty_json.contains("cursor_after_secs"));
    // An unrecorded skip count is omitted rather than written as zero: absent
    // means "this build did not count", which is not the same claim as "no
    // receive was skipped".
    assert!(!empty_json.contains("skipped"));
    // Same rule for `refused`: absent is "this build did not count", which is
    // not the same claim as "no delivery was refused".
    assert!(!empty_json.contains("refused"));
    assert_eq!(
        serde_json::from_str::<AuditEventKind>(&empty_json).unwrap(),
        empty
    );
    // A row written before `skipped` existed still parses, and reads as
    // unrecorded.
    let legacy: AuditEventKind =
        serde_json::from_str(r#"{"type":"sync_drain","duration_ms":250,"deliveries":3}"#)
            .expect("a v2 sync_drain row predating `skipped` must still parse");
    assert_eq!(
        legacy,
        AuditEventKind::SyncDrain {
            duration_ms: 250,
            deliveries: 3,
            skipped: None,
            refused: None,
            cursor_before_secs: None,
            cursor_after_secs: None,
        }
    );
    // And a row from the build that had `skipped` but not yet `refused` parses
    // with its recorded skip count intact.
    let pre_refused: AuditEventKind = serde_json::from_str(
        r#"{"type":"sync_drain","duration_ms":250,"deliveries":3,"skipped":17}"#,
    )
    .expect("a v2 sync_drain row predating `refused` must still parse");
    assert_eq!(
        pre_refused,
        AuditEventKind::SyncDrain {
            duration_ms: 250,
            deliveries: 3,
            skipped: Some(17),
            refused: None,
            cursor_before_secs: None,
            cursor_after_secs: None,
        }
    );
}

#[test]
fn epoch_stall_backfill_armed_roundtrips_and_carries_its_fields() {
    let kind = AuditEventKind::EpochStallBackfillArmed {
        stalled_epoch: 19,
        threshold: 8,
        trigger: Some(EpochStallBackfillTrigger::ResourceRefusal),
    };
    let event = AuditEvent {
        schema_version: AUDIT_LOG_SCHEMA_VERSION.into(),
        seq: 7,
        wall_time_ms: 1_700_000_000_000,
        recorder_session_id: Some("recorder-1".into()),
        account_ref: None,
        engine_id: "engine-xyz".into(),
        group_ref: None,
        context: None,
        kind: kind.clone(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["kind"]["type"], "epoch_stall_backfill_armed");
    assert_eq!(value["kind"]["stalled_epoch"], 19);
    assert_eq!(value["kind"]["threshold"], 8);
    assert_eq!(value["kind"]["trigger"], "resource_refusal");
    let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.kind, kind);
}

#[test]
fn epoch_stall_backfill_armed_accepts_pre_trigger_v2_rows() {
    let parsed: AuditEventKind = serde_json::from_value(serde_json::json!({
        "type": "epoch_stall_backfill_armed",
        "stalled_epoch": 19,
        "threshold": 8
    }))
    .unwrap();
    assert_eq!(
        parsed,
        AuditEventKind::EpochStallBackfillArmed {
            stalled_epoch: 19,
            threshold: 8,
            trigger: None,
        }
    );
}

#[test]
fn epoch_stall_backfill_escalated_roundtrips_and_carries_its_fields() {
    let kind = AuditEventKind::EpochStallBackfillEscalated {
        stalled_epoch: 12,
        arms: 3,
        arm_threshold: 3,
    };
    let event = AuditEvent {
        schema_version: AUDIT_LOG_SCHEMA_VERSION.into(),
        seq: 9,
        wall_time_ms: 1_700_000_000_000,
        recorder_session_id: Some("recorder-1".into()),
        account_ref: None,
        engine_id: "engine-xyz".into(),
        group_ref: None,
        context: None,
        kind: kind.clone(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["kind"]["type"], "epoch_stall_backfill_escalated");
    assert_eq!(value["kind"]["stalled_epoch"], 12);
    assert_eq!(value["kind"]["arms"], 3);
    assert_eq!(value["kind"]["arm_threshold"], 3);
    let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.kind, kind);
}

fn sample_audit_event_kinds() -> Vec<AuditEventKind> {
    vec![
        AuditEventKind::RecorderStarted {
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
            subject_member_ref: Some("b".repeat(32)),
            origin_commit_id: Some("m".into()),
            fields: vec!["members".into()],
            component_ids: Vec::new(),
            value: Some(GroupStateValue {
                digest: Some("c".repeat(64)),
                len: Some(4),
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
            },
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
                    tip_digest: Some("a".repeat(64)),
                }),
                app_witnesses: vec![ConvergenceAppWitness {
                    epoch: 3,
                    sender_ref: Some("c".repeat(32)),
                }],
            }],
            decisive_rule: Some("effective_commit_depth".into()),
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
            retry_count: Some(2),
            residence_ms: Some(5_000),
        },
        AuditEventKind::Rejection {
            msg_id: "m".into(),
            reason: "unattributable_sender".into(),
        },
        AuditEventKind::SubscriptionRebuild {
            since_secs: Some(1_700_000_000),
            lookback_secs: Some(120),
            relay_results: vec![
                RelayRegistration {
                    relay_url: "wss://relay.example".into(),
                    accepted: true,
                },
                RelayRegistration {
                    relay_url: "wss://down.example".into(),
                    accepted: false,
                },
            ],
        },
        AuditEventKind::SyncDrain {
            duration_ms: 250,
            deliveries: 3,
            skipped: Some(17),
            refused: Some(1),
            cursor_before_secs: Some(1_699_999_880),
            cursor_after_secs: Some(1_700_000_000),
        },
        AuditEventKind::EpochStallBackfillArmed {
            stalled_epoch: 19,
            threshold: 8,
            trigger: Some(EpochStallBackfillTrigger::UndecryptableThreshold),
        },
        AuditEventKind::EpochStallBackfillStarted {
            seam: EpochBackfillExecutionSeam::ExplicitCatchUp,
            replay_scope: EpochBackfillReplayScope::AccountFullHistory,
            retry_ordinal: 0,
        },
        AuditEventKind::EpochStallBackfillCompleted {
            retry_ordinal: 0,
            duration_ms: 120,
            activation_outcome: EpochBackfillActivationOutcome::Succeeded,
            completion_kind: Some(EpochBackfillCompletionKind::EndOfStoredEvents),
            deliveries: 4,
            skipped: Some(21),
            refused: Some(0),
            local_epoch_before: 19,
            local_epoch_after: 20,
            group_advanced: true,
        },
        AuditEventKind::EpochStallBackfillFailed {
            retry_ordinal: 0,
            duration_ms: 50,
            activation_outcome: EpochBackfillActivationOutcome::Failed,
            error_kind: Some("account_transport".into()),
            deliveries: 0,
            skipped: Some(0),
            refused: Some(0),
            local_epoch_before: 19,
            local_epoch_after: 19,
            group_advanced: false,
        },
        AuditEventKind::EpochStallBackfillDeferred {
            reason: EpochBackfillDeferredReason::GroupEpochUnavailable,
            retry_ordinal: 1,
        },
        AuditEventKind::EpochStallBackfillEscalated {
            stalled_epoch: 12,
            arms: 3,
            arm_threshold: 3,
        },
        AuditEventKind::ConvergencePassDiscarded {
            stale_base_epoch: 7,
            current_tip_epoch: 13,
            generation: 4,
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
        serde_json::from_str(include_str!("../../schema/audit-log-event.v3.schema.json")).unwrap();
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

/// The trigger enum is a schema-visible catalog, so the two halves must move
/// together. Without this the v3 `$defs` can be reverted to a narrower set — or
/// left behind when a variant is added — and every other test still passes,
/// because nothing else compares the two.
#[test]
fn v3_schema_tracks_the_epoch_stall_backfill_trigger_catalog() {
    let triggers = [
        EpochStallBackfillTrigger::UndecryptableThreshold,
        EpochStallBackfillTrigger::ContestedForkDeferral,
        EpochStallBackfillTrigger::ResourceRefusal,
    ];
    // Exhaustiveness guard: a new variant fails to compile here rather than
    // silently shrinking the set this test compares.
    for trigger in triggers {
        match trigger {
            EpochStallBackfillTrigger::UndecryptableThreshold
            | EpochStallBackfillTrigger::ContestedForkDeferral
            | EpochStallBackfillTrigger::ResourceRefusal => {}
        }
    }

    let emitted = triggers
        .iter()
        .map(|trigger| {
            serde_json::to_value(trigger)
                .expect("trigger serializes")
                .as_str()
                .expect("trigger serializes to a string")
                .to_string()
        })
        .collect::<std::collections::BTreeSet<_>>();

    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../schema/audit-log-event.v3.schema.json")).unwrap();
    let defined = schema
        .pointer("/$defs/epochStallBackfillTrigger/enum")
        .and_then(serde_json::Value::as_array)
        .expect("epochStallBackfillTrigger enum")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("trigger enum entry is a string")
                .to_string()
        })
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(emitted, defined);
}

#[test]
fn v3_schema_cannot_express_former_sensitive_audit_fields() {
    let schema = include_str!("../../schema/audit-log-event.v3.schema.json");
    for forbidden in [
        "audit_data_mode",
        "full_data",
        "message_content_decoded",
        "decoded_payload",
        "decoded_app_event",
        "account_pubkey_hex",
        "account_npub",
        "expected_pubkeys_hex",
        "actor_pubkey_hex",
        "subject_pubkey_hex",
        "tip_committer_pubkey_hex",
        "sender_pubkey_hex",
        "rule_trace",
        "pubkeys_hex",
    ] {
        assert!(
            !schema.contains(forbidden),
            "v3 schema unexpectedly exposes former sensitive field {forbidden}"
        );
    }
}

#[test]
#[cfg(unix)]
fn rotate_failure_keeps_recording_to_original_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    // A dedicated subdir takes the chmod fault so TempDir cleanup of the root
    // is never blocked if an assertion fails before the mode is restored.
    let logs = dir.path().join("logs");
    fs::create_dir(&logs).unwrap();
    let path = default_jsonl_path(&logs, "engine-abc");
    let recorder = JsonlRecorder::open(&path, "engine-abc".to_string()).unwrap();
    recorder.record(AuditRecord::new(
        None,
        AuditEventKind::SendEntry {
            intent_kind: "app_message".into(),
        },
    ));
    let before = fs::read_to_string(&path).unwrap();

    // Injected fault: a read-only directory rejects creating the staged swap
    // file. Root bypasses directory modes, so probe and skip silently in that
    // case (the repo-wide tracing audit bans direct output under src/).
    fs::set_permissions(&logs, fs::Permissions::from_mode(0o500)).unwrap();
    if fs::write(logs.join("probe.tmp"), b"").is_ok() {
        fs::set_permissions(&logs, fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }

    let err = recorder.rotate().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(fs::read_to_string(&path).unwrap(), before);

    fs::set_permissions(&logs, fs::Permissions::from_mode(0o700)).unwrap();

    // The failed rotation must leave the recorder appending to the original
    // file with a continuing sequence.
    recorder.record(AuditRecord::new(
        None,
        AuditEventKind::SendEntry {
            intent_kind: "app_message".into(),
        },
    ));
    let events: Vec<AuditEvent> = fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 3);
    assert_eq!(events[2].seq, 2);
}

/// Minimal recursive JSON-Schema conformance check for the subset our schema
/// uses ($ref, properties, additionalProperties:false, items, and oneOf
/// discriminated by a `type` const). It does not validate value patterns; its
/// job is to prove every key we serialize is a key the schema allows — i.e. that
/// mdk never emits a field that Goggles' `additionalProperties: false`
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
        serde_json::from_str(include_str!("../../schema/audit-log-event.v3.schema.json")).unwrap();
    let defs = schema["$defs"].clone();

    // Every sample kind, wrapped in a full event, must serialize using only keys
    // the schema allows (recursively, including nested wire/candidate/value/etc.).
    for kind in sample_audit_event_kinds() {
        let event = AuditEvent {
            schema_version: AUDIT_LOG_SCHEMA_VERSION.into(),
            seq: 0,
            wall_time_ms: 0,
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
