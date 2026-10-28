#[derive(Clone, Default)]
struct CrashDuringFanoutPublishAdapter {
    publishes: Arc<Mutex<Vec<TransportPublishRequest>>>,
}

impl CrashDuringFanoutPublishAdapter {
    fn publishes(&self) -> Vec<TransportPublishRequest> {
        self.publishes.lock().unwrap().clone()
    }
}

#[async_trait]
impl TransportAdapter for CrashDuringFanoutPublishAdapter {
    async fn activate_account(
        &self,
        _activation: TransportAccountActivation,
    ) -> Result<(), TransportAdapterError> {
        Ok(())
    }

    async fn sync_account_groups(
        &self,
        _sync: TransportGroupSync,
    ) -> Result<(), TransportAdapterError> {
        Ok(())
    }

    async fn deactivate_account(
        &self,
        _account_id: &MemberId,
    ) -> Result<(), TransportAdapterError> {
        Ok(())
    }

    async fn publish(
        &self,
        request: TransportPublishRequest,
    ) -> Result<TransportPublishReport, TransportAdapterError> {
        self.publishes.lock().unwrap().push(request);
        // The send-before-side-effect edge (`Attempting`) is already durable
        // for every target when the concurrent publishes run; crash inside
        // the first one polled.
        panic!("simulated process crash during the fanout publish");
    }

    async fn receive(&self) -> Result<Option<TransportDelivery>, TransportAdapterError> {
        Ok(None)
    }
}

async fn assert_frozen_fanout_case(
    accept_at: Option<usize>,
    error_at: &[usize],
    error_kind: Option<TransportEndpointFailureKind>,
    expect_unresolved: bool,
) {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot fanout matrix key").unwrap();
    let mut alice = session(
        dir.path().join("alice.sqlite"),
        &key,
        b"alice-fanout-matrix",
    );
    let mut bob = session(dir.path().join("bob.sqlite"), &key, b"bob-fanout-matrix");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "fanout matrix".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let group_id = created.group_id.clone();
    let create_pending = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, .. } => *pending,
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(create_pending).await.unwrap();

    let endpoints = vec![
        TransportEndpoint("wss://fanout-one.example".into()),
        TransportEndpoint("wss://fanout-two.example".into()),
        TransportEndpoint("wss://fanout-three.example".into()),
    ];
    let adapter = RecordingAdapter::default();
    adapter.accept_only_endpoints(
        accept_at
            .map(|index| vec![endpoints[index].clone()])
            .unwrap_or_default(),
    );
    // The production adapter surfaces a rejected/unreachable relay as a
    // whole-call `Err` on that endpoint's single-endpoint publish (an unmet
    // `required_acks: 1` discards the report), so error endpoints model the
    // real contract rather than an `Ok` report with no receipt.
    let error_endpoints = error_at
        .iter()
        .map(|&index| endpoints[index].clone())
        .collect();
    if let Some(kind) = error_kind {
        adapter.fail_endpoints_as(error_endpoints, kind);
    } else {
        adapter.error_for_endpoints(error_endpoints);
    }
    let policy = StaticTransportRouting::new(vec![TransportEndpoint("wss://inbox.example".into())])
        .with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            endpoints.clone(),
        );
    let mut runtime = AccountDeviceRuntime::new(
        alice,
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    );

    let effects = runtime
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("fanout result".into()),
            description: None,
        })
        .await
        .unwrap();

    // Every outstanding endpoint is attempted as its own concurrent
    // single-endpoint publish with `required_acks: 1` — the per-endpoint
    // adapter contract — instead of one awaited ack at a time. Completion
    // order is nondeterministic, so compare the attempted set.
    let publishes = adapter.publishes();
    assert_eq!(publishes.len(), endpoints.len());
    let mut attempted = publishes
        .iter()
        .flat_map(|publish| publish.target.endpoints().to_vec())
        .collect::<Vec<_>>();
    attempted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut expected = endpoints.clone();
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(attempted, expected);
    assert!(publishes.iter().all(|publish| publish.required_acks == 1));
    assert_eq!(effects.reports.len(), 1);
    assert_eq!(effects.fanout.len(), 1);
    assert_eq!(effects.fanout[0].fanout_complete, !expect_unresolved);
    assert_eq!(
        effects.fanout[0].outstanding_targets,
        if expect_unresolved { error_at.len() } else { 0 }
    );
    assert_eq!(
        runtime.session().outbound_fanouts().unwrap().is_empty(),
        !expect_unresolved,
        "unresolved fanouts must remain durable while terminal fanouts are pruned"
    );

    if accept_at.is_some() {
        assert!(effects.fanout[0].mls_confirmed);
        assert_eq!(effects.fanout[0].accepted_targets, 1);
        assert_eq!(runtime.session().epoch(&group_id).unwrap().0, 2);
        assert!(matches!(
            effects.pending.as_slice(),
            [PendingResolution::Confirmed { .. }]
        ));
    } else if expect_unresolved {
        assert!(effects.failures.is_empty());
        assert!(matches!(
            effects.unresolved_publishes.as_slice(),
            [marmot_session::UnresolvedPublish {
                reason,
                ..
            }] if *reason == match error_kind {
                Some(TransportEndpointFailureKind::RetryableUnavailable) => {
                    marmot_session::UnresolvedPublishReason::RetryableUnavailable
                }
                _ => marmot_session::UnresolvedPublishReason::AcknowledgementUnknown,
            }
        ));
        assert!(!effects.fanout[0].mls_confirmed);
        assert_eq!(effects.fanout[0].accepted_targets, 0);
        assert_eq!(
            runtime.session().epoch(&group_id).unwrap().0,
            2,
            "the staged MLS transition must remain intact while completion is unknown"
        );
        assert!(effects.pending.is_empty());
    } else {
        assert!(!effects.fanout[0].mls_confirmed);
        assert_eq!(effects.fanout[0].accepted_targets, 0);
        assert_eq!(runtime.session().epoch(&group_id).unwrap().0, 1);
        assert!(matches!(
            effects.pending.as_slice(),
            [PendingResolution::RolledBack { .. }]
        ));
    }

    let privacy_safe = serde_json::to_string(&effects.fanout[0]).unwrap();
    assert!(!privacy_safe.contains("wss://"));
    let publish_count = adapter.publishes().len();
    let duplicate_resume = runtime.resume_outbound_fanouts().await.unwrap();
    assert!(duplicate_resume.reports.is_empty());
    assert!(duplicate_resume.pending.is_empty());
    assert_eq!(adapter.publishes().len(), publish_count);
}

#[tokio::test]
async fn frozen_fanout_first_middle_last_ack_and_all_fail_are_terminal() {
    for accept_at in [Some(0), Some(1), Some(2), None] {
        assert_frozen_fanout_case(accept_at, &[], None, false).await;
    }
}

#[tokio::test]
async fn frozen_fanout_ambiguous_adapter_errors_remain_unresolved() {
    assert_frozen_fanout_case(None, &[0, 1, 2], None, true).await;
}

#[tokio::test]
async fn terminal_application_fanout_replays_failure_after_restart_before_delete() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot terminal app fanout key").unwrap();
    let mut alice = session(
        dir.path().join("alice.sqlite"),
        &key,
        b"alice-terminal-app-fanout",
    );
    let created = alice
        .create_group(CreateGroupRequest {
            name: "terminal app fanout".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let group_id = created.group_id;
    let pending = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, .. } => *pending,
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let endpoint = TransportEndpoint("wss://terminal-app-fanout.example".into());
    let message_id = MessageId::new(vec![0xA1; 32]);
    let mut fanout = OutboundFanout::stage(
        TransportPublishRequest {
            account_id: alice.self_id(),
            message: TransportMessage {
                id: message_id.clone(),
                payload: vec![0xA1],
                timestamp: Timestamp(100),
                causal_deps: Vec::new(),
                source: TransportSource("terminal-app-fanout-test".into()),
                envelope: TransportEnvelope::GroupMessage {
                    transport_group_id: group_id.as_slice().to_vec(),
                },
            },
            target: TransportPublishTarget::Group {
                group_id: group_id.clone(),
                transport_group_id: group_id.as_slice().to_vec(),
                endpoints: vec![endpoint.clone()],
            },
            required_acks: 1,
        },
        None,
        None,
        100_000,
    )
    .unwrap();
    fanout
        .set_application_message(OutboundApplicationMessage {
            authority: None,
            group_id: group_id.clone(),
            app_event_id: "terminal-app-event".into(),
            source_epoch: EpochId(1),
            retention: AppMessageRetentionDecision::new(100, 0),
        })
        .unwrap();
    fanout.mark_attempt_started_at(0, 100_000).unwrap();
    fanout
        .record_target_failure(
            0,
            TransportEndpointFailure {
                endpoint: endpoint.clone(),
                reason: "relay rejected the event".into(),
                kind: TransportEndpointFailureKind::TerminalRejected,
                rejection_category: Some(TransportEndpointRejectionCategory::Blocked),
            },
        )
        .unwrap();
    assert!(fanout.outcome().fanout_complete);
    alice.put_outbound_fanout(&fanout).unwrap();

    let policy = StaticTransportRouting::new(Vec::new()).with_group_route(
        group_id.clone(),
        group_id.as_slice().to_vec(),
        vec![endpoint],
    );
    let mut runtime = AccountDeviceRuntime::new(
        alice,
        RecordingAdapter::default(),
        policy,
        RecordingKeyPackages::default(),
    );

    let effects = runtime.resume_outbound_fanouts().await.unwrap();

    assert!(matches!(
        effects.failures.as_slice(),
        [marmot_session::PublishFailure {
            message_id: failed_message_id,
            reason,
        }] if failed_message_id == &message_id
            && reason == "insufficient publish acknowledgements"
    ));
    assert!(matches!(
        effects.failed_app_messages.as_slice(),
        [marmot_session::FailedApplicationMessage {
            group_id: failed_group_id,
            app_event_id,
            message_id: failed_message_id,
            reason,
        }] if failed_group_id == &group_id
            && app_event_id == "terminal-app-event"
            && failed_message_id == &message_id
            && reason == "insufficient publish acknowledgements"
    ));
    assert!(runtime.session().outbound_fanouts().unwrap().is_empty());
}

#[tokio::test]
async fn terminally_failed_queued_app_message_is_retired_instead_of_rearmed() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot terminal queued app key").unwrap();
    let mut alice = session(
        dir.path().join("alice.sqlite"),
        &key,
        b"alice-terminal-queued-app",
    );
    let sender_hex = hex::encode(alice.self_id().as_slice());
    let created = alice
        .create_group(CreateGroupRequest {
            name: "terminal queued app".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let group_id = created.group_id;
    let pending = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, .. } => *pending,
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let endpoint = TransportEndpoint("wss://terminal-queued-app.example".into());
    let adapter = RecordingAdapter::default();
    adapter.fail_endpoints_as(
        vec![endpoint.clone()],
        TransportEndpointFailureKind::TerminalRejected,
    );
    let policy = StaticTransportRouting::new(Vec::new()).with_group_route(
        group_id.clone(),
        group_id.as_slice().to_vec(),
        vec![endpoint],
    );
    let mut runtime = AccountDeviceRuntime::new(
        alice,
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    );

    let queued = runtime
        .queue_app_message_with_audit_context(
            group_id.clone(),
            app_payload_for(&sender_hex, b"terminal queued message"),
            Default::default(),
        )
        .await
        .unwrap();
    assert!(queued.failures.is_empty());
    assert!(adapter.publishes().is_empty());

    let failed = runtime.advance_convergence(&group_id).await.unwrap();
    assert_eq!(failed.failed_app_messages.len(), 1);
    let publish_count = adapter.publishes().len();
    assert_eq!(publish_count, 1);

    let repeated = runtime.advance_convergence(&group_id).await.unwrap();
    assert!(repeated.failed_app_messages.is_empty());
    assert_eq!(
        adapter.publishes().len(),
        publish_count,
        "a terminally failed queued intent must not regenerate on the next convergence pass"
    );
}

#[tokio::test]
async fn queued_app_message_with_missing_route_remains_retryable() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot queued app missing route key").unwrap();
    let mut alice = session(
        dir.path().join("alice.sqlite"),
        &key,
        b"alice-queued-app-missing-route",
    );
    let sender_hex = hex::encode(alice.self_id().as_slice());
    let created = alice
        .create_group(CreateGroupRequest {
            name: "queued app missing route".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let group_id = created.group_id;
    let pending = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, .. } => *pending,
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let mut runtime = AccountDeviceRuntime::new(
        alice,
        RecordingAdapter::default(),
        StaticTransportRouting::new(Vec::new()),
        RecordingKeyPackages::default(),
    );
    runtime
        .queue_app_message_with_audit_context(
            group_id.clone(),
            app_payload_for(&sender_hex, b"wait for a route"),
            Default::default(),
        )
        .await
        .unwrap();

    let failed = runtime.advance_convergence(&group_id).await.unwrap();
    assert_eq!(failed.failures.len(), 1);
    assert!(failed.failed_app_messages.is_empty());
    assert!(
        runtime.has_queued_outbound_intents(&group_id).unwrap(),
        "a routing failure has not proved terminal delivery failure"
    );
}

#[tokio::test]
async fn deferred_fanout_blocks_newer_sends_but_not_convergence_settlement() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot ordered fanout key").unwrap();
    let mut alice = session(
        dir.path().join("alice.sqlite"),
        &key,
        b"alice-ordered-fanout",
    );
    let mut bob = session(dir.path().join("bob.sqlite"), &key, b"bob-ordered-fanout");
    let bob_key_package = bob.fresh_key_package().await.unwrap();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "ordered fanout".into(),
            description: String::new(),
            members: vec![bob_key_package],
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let group_id = created.group_id;
    let (pending, welcome) = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, welcomes } => (*pending, welcomes[0].clone()),
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.ingest(welcome).await.unwrap();

    let bob_update = bob
        .send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    let (commit, update_pending) = match &bob_update.publish[0] {
        PublishWork::GroupEvolution { msg, pending, .. } => (msg.clone(), *pending),
        other => panic!("expected GroupEvolution publish work, got {other:?}"),
    };
    bob.confirm_published(update_pending).await.unwrap();
    let buffered = alice.ingest(commit).await.unwrap();
    assert!(matches!(
        buffered.outcome,
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));
    assert!(alice.has_pending_convergence_inputs(&group_id).unwrap());

    let sender_hex = hex::encode(alice.self_id().as_slice());
    alice
        .queue_app_message_with_audit_context(
            group_id.clone(),
            app_payload_for(&sender_hex, b"newer queued message"),
            Default::default(),
        )
        .await
        .unwrap();

    let endpoint = TransportEndpoint("wss://ordered-fanout.example".into());
    let make_request = |id: u8| TransportPublishRequest {
        account_id: alice.self_id(),
        message: TransportMessage {
            id: MessageId::new(vec![id; 32]),
            payload: vec![id],
            timestamp: Timestamp(100),
            causal_deps: Vec::new(),
            source: TransportSource("ordered-fanout-test".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
        },
        target: TransportPublishTarget::Group {
            group_id: group_id.clone(),
            transport_group_id: group_id.as_slice().to_vec(),
            endpoints: vec![endpoint.clone()],
        },
        required_acks: 1,
    };
    let mut older = OutboundFanout::stage(make_request(1), None, None, 100_000).unwrap();
    older.mark_attempt_started_at(0, 100_000).unwrap();
    older
        .record_target_failure(
            0,
            TransportEndpointFailure {
                endpoint: endpoint.clone(),
                reason: "acknowledgement unknown".into(),
                kind: TransportEndpointFailureKind::PossiblyExposed,
                rejection_category: None,
            },
        )
        .unwrap();
    let newer = OutboundFanout::stage(make_request(2), None, None, 100_001).unwrap();
    alice.put_outbound_fanout(&older).unwrap();
    alice.put_outbound_fanout(&newer).unwrap();
    let convergence_delay = alice
        .prepare_convergence_cutoff_delay_ms(&group_id)
        .unwrap()
        .expect("buffered commit must open a convergence pass");

    let adapter = RecordingAdapter::default();
    let wall = Arc::new(TestWallClock::new(100));
    let policy = StaticTransportRouting::new(Vec::new()).with_group_route(
        group_id.clone(),
        group_id.as_slice().to_vec(),
        vec![endpoint],
    );
    let mut runtime = AccountDeviceRuntime::new(
        alice,
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );

    tokio::time::sleep(Duration::from_millis(convergence_delay.saturating_add(1))).await;

    let effects = runtime.advance_convergence(&group_id).await.unwrap();

    assert!(effects.reports.is_empty());
    assert!(adapter.publishes().is_empty());
    assert!(
        !runtime.has_pending_convergence_inputs(&group_id).unwrap(),
        "the older transport fanout must not wedge convergence settlement"
    );
    assert_eq!(
        runtime.outbound_fanout_retry_delay_ms(&group_id).unwrap(),
        Some(30_000),
        "the later NotAttempted fanout must not pull the older retry cutoff forward"
    );
    let stored = runtime
        .session()
        .outbound_fanouts_for_group(&group_id)
        .unwrap();
    assert_eq!(stored.len(), 2);
    assert_eq!(
        stored[1].target_status(0),
        Some(FanoutTargetStatus::NotAttempted),
        "the newer event must remain untouched until the older obligation is retryable"
    );
    assert!(
        runtime.has_queued_outbound_intents(&group_id).unwrap(),
        "newer queued outbound work must remain behind the older durable fanout"
    );
}

#[tokio::test]
async fn met_quorum_secondary_retry_allows_queued_app_after_convergence() {
    assert_met_quorum_secondary_retry(false).await;
}

#[tokio::test]
async fn met_quorum_tail_does_not_hide_newer_unmet_quorum_fanout() {
    assert_met_quorum_secondary_retry(true).await;
}

/// Exercise both replication-only debt and an unsafe publication hidden behind it.
async fn assert_met_quorum_secondary_retry(newer_below_quorum: bool) {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot met quorum ordered fanout key").unwrap();
    let alice_path = dir.path().join("alice.sqlite");
    let audit_path = dir.path().join("application-audit.jsonl");
    let open_alice = || {
        let session = session(&alice_path, &key, b"alice-met-quorum-order");
        session.audit_recorder().swap(Box::new(
            marmot_forensics::JsonlRecorder::open_v5_with_account_ref(
                &audit_path,
                "11".repeat(16),
                Some("22".repeat(16)),
                marmot_forensics::v5::Producer {
                    mdk_revision: None,
                    build_profile: marmot_forensics::v5::BuildProfile::Debug,
                    platform: marmot_forensics::v5::Platform::Other,
                    host_build: None,
                },
            )
            .unwrap(),
        ));
        session
    };
    let mut alice = open_alice();
    let mut bob = session(dir.path().join("bob.sqlite"), &key, b"bob-met-quorum-order");
    let created = alice
        .create_group(CreateGroupRequest {
            name: "met quorum ordered fanout".into(),
            description: String::new(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let group_id = created.group_id;
    let (pending, welcome) = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, welcomes } => (*pending, welcomes[0].clone()),
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.ingest(welcome).await.unwrap();

    let update = bob
        .send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    let (commit, update_pending) = match &update.publish[0] {
        PublishWork::GroupEvolution { msg, pending, .. } => (msg.clone(), *pending),
        other => panic!("expected GroupEvolution publish work, got {other:?}"),
    };
    bob.confirm_published(update_pending).await.unwrap();
    assert!(matches!(
        alice.ingest(commit).await.unwrap().outcome,
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));

    let sender_hex = hex::encode(alice.self_id().as_slice());
    alice
        .queue_app_message_with_audit_context(
            group_id.clone(),
            app_payload_for(&sender_hex, b"queued behind met quorum"),
            Default::default(),
        )
        .await
        .unwrap();
    let healthy = TransportEndpoint("wss://met-quorum-healthy.example".into());
    let secondary = TransportEndpoint("wss://met-quorum-secondary.example".into());
    let older_id = MessageId::new(vec![0xA1; 32]);
    let mut older = OutboundFanout::stage(
        TransportPublishRequest {
            account_id: alice.self_id(),
            message: TransportMessage {
                id: older_id.clone(),
                payload: vec![0xA1],
                timestamp: Timestamp(100),
                causal_deps: Vec::new(),
                source: TransportSource("met-quorum-order-test".into()),
                envelope: TransportEnvelope::GroupMessage {
                    transport_group_id: group_id.as_slice().to_vec(),
                },
            },
            target: TransportPublishTarget::Group {
                group_id: group_id.clone(),
                transport_group_id: group_id.as_slice().to_vec(),
                endpoints: vec![healthy.clone(), secondary.clone()],
            },
            required_acks: 1,
        },
        None,
        None,
        100_000,
    )
    .unwrap();
    older.mark_attempt_started_at(0, 100_000).unwrap();
    older.mark_target_accepted(0).unwrap();
    older.mark_attempt_started_at(1, 100_000).unwrap();
    older
        .record_target_failure(
            1,
            TransportEndpointFailure {
                endpoint: secondary.clone(),
                reason: "acknowledgement unknown".into(),
                kind: TransportEndpointFailureKind::PossiblyExposed,
                rejection_category: None,
            },
        )
        .unwrap();
    assert_eq!(older.outcome().accepted_targets, 1);
    assert_eq!(older.outcome().outstanding_targets, 1);
    alice.put_outbound_fanout(&older).unwrap();
    let newer_id = MessageId::new(vec![0xA2; 32]);
    if newer_below_quorum {
        let mut request = older.request().clone();
        request.message.id = newer_id.clone();
        request.message.payload = vec![0xA2];
        request.required_acks = 2;
        let mut newer = OutboundFanout::stage(request, None, None, 100_001).unwrap();
        newer.mark_attempt_started_at(0, 100_000).unwrap();
        newer.mark_target_accepted(0).unwrap();
        newer.mark_attempt_started_at(1, 100_000).unwrap();
        newer
            .record_target_failure(
                1,
                TransportEndpointFailure {
                    endpoint: secondary.clone(),
                    reason: "second required acknowledgement unknown".into(),
                    kind: TransportEndpointFailureKind::PossiblyExposed,
                    rejection_category: None,
                },
            )
            .unwrap();
        alice.put_outbound_fanout(&newer).unwrap();
    }
    let convergence_delay = alice
        .prepare_convergence_cutoff_delay_ms(&group_id)
        .unwrap()
        .expect("buffered update must open a convergence pass");

    let adapter = RecordingAdapter::default();
    adapter.fail_endpoints_as(
        vec![secondary.clone()],
        TransportEndpointFailureKind::PossiblyExposed,
    );
    let wall = Arc::new(TestWallClock::new(100));
    let policy = StaticTransportRouting::new(Vec::new()).with_group_route(
        group_id.clone(),
        group_id.as_slice().to_vec(),
        vec![healthy.clone(), secondary.clone()],
    );
    let mut runtime = AccountDeviceRuntime::new(
        alice,
        adapter.clone(),
        policy.clone(),
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );

    tokio::time::sleep(Duration::from_millis(convergence_delay.saturating_add(1))).await;
    let held = runtime.advance_convergence(&group_id).await.unwrap();
    assert_eq!(
        held.published_app_messages.len(),
        usize::from(!newer_below_quorum)
    );
    let early_app_id = held
        .published_app_messages
        .first()
        .map(|message| message.message_id.clone());
    let early_publishes = adapter.publishes();
    assert_eq!(
        early_publishes.len(),
        if newer_below_quorum { 0 } else { 2 }
    );
    if let Some(app_id) = &early_app_id {
        assert!(
            early_publishes
                .iter()
                .all(|publish| &publish.message.id == app_id)
        );
        assert!(
            early_publishes
                .iter()
                .any(|publish| publish.target.endpoints() == [healthy.clone()])
        );
        assert!(
            early_publishes
                .iter()
                .any(|publish| publish.target.endpoints() == [secondary.clone()])
        );
    }
    assert!(!runtime.has_pending_convergence_inputs(&group_id).unwrap());
    assert_eq!(
        runtime.has_queued_outbound_intents(&group_id).unwrap(),
        newer_below_quorum
    );
    let retained = runtime
        .session()
        .outbound_fanouts_for_group(&group_id)
        .unwrap();
    let retained_old = retained
        .iter()
        .find(|fanout| fanout.message_id() == &older_id)
        .unwrap();
    assert_eq!(retained_old.request(), older.request());
    assert_eq!(
        retained_old.target_status(0),
        Some(FanoutTargetStatus::Accepted)
    );
    assert_eq!(
        retained_old.target_status(1),
        Some(FanoutTargetStatus::PossiblyExposed)
    );
    assert_eq!(
        runtime.outbound_fanout_retry_delay_ms(&group_id).unwrap(),
        Some(30_000),
    );

    drop(runtime);
    let mut runtime = AccountDeviceRuntime::new(
        open_alice(),
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );
    assert_eq!(
        runtime.has_queued_outbound_intents(&group_id).unwrap(),
        newer_below_quorum
    );
    assert_eq!(
        runtime.outbound_fanout_retry_delay_ms(&group_id).unwrap(),
        Some(30_000),
    );
    let deferred = runtime.resume_outbound_fanouts().await.unwrap();
    assert!(
        deferred
            .published_app_messages
            .iter()
            .all(|published| Some(&published.message_id) == early_app_id.as_ref())
    );
    assert_eq!(adapter.publishes().len(), early_publishes.len());

    adapter.fail_endpoints_as(Vec::new(), TransportEndpointFailureKind::PossiblyExposed);
    wall.set(130);
    let released = runtime.advance_convergence(&group_id).await.unwrap();
    let publishes = adapter.publishes();
    assert_eq!(released.published_app_messages.len(), 1);
    let app_id = released.published_app_messages[0].message_id.clone();
    assert_eq!(
        publishes.len(),
        early_publishes.len() + if newer_below_quorum { 4 } else { 2 }
    );
    assert_eq!(publishes[early_publishes.len()].message.id, older_id);
    assert_eq!(
        publishes[early_publishes.len()].message.payload,
        older.request().message.payload
    );
    assert_eq!(
        publishes[early_publishes.len()].target.endpoints(),
        std::slice::from_ref(&secondary)
    );
    if newer_below_quorum {
        assert_eq!(publishes[1].message.id, newer_id);
        assert_eq!(
            publishes[1].target.endpoints(),
            std::slice::from_ref(&secondary)
        );
        assert!(
            publishes[2..]
                .iter()
                .all(|publish| publish.message.id == app_id)
        );
    } else {
        assert_eq!(early_app_id.as_ref(), Some(&app_id));
        assert_eq!(publishes[early_publishes.len() + 1].message.id, app_id);
        assert_eq!(
            publishes[early_publishes.len() + 1].message.payload,
            early_publishes[0].message.payload
        );
        assert_eq!(
            publishes[early_publishes.len() + 1].target.endpoints(),
            &[secondary]
        );
    }
    assert!(!runtime.has_queued_outbound_intents(&group_id).unwrap());
    runtime
        .acknowledge_published_app_messages(&released.published_app_messages)
        .unwrap();

    let repeated = runtime.advance_convergence(&group_id).await.unwrap();
    assert!(repeated.published_app_messages.is_empty());
    assert_eq!(adapter.publishes().len(), publishes.len());
    drop(runtime);
    let audit = std::fs::read_to_string(&audit_path).unwrap();
    assert!(!audit.contains("queued behind met quorum"));
    assert!(!audit.contains("wss://"));
    assert!(!audit.contains(&hex::encode(group_id.as_slice())));
    let rows = audit
        .lines()
        .map(|line| {
            marmot_forensics::v5::Record::from_json(line.as_bytes()).expect("strict v5 row");
            serde_json::from_str::<serde_json::Value>(line).unwrap()
        })
        .collect::<Vec<_>>();
    let queued = rows
        .iter()
        .find(|row| {
            row["event"]["type"] == "send_outcome" && row["event"]["result_kind"] == "queued"
        })
        .expect("queued admission audit");
    let operation = queued["event"]["record_context"]["operation_ref"]
        .as_str()
        .unwrap();
    let correlated = rows
        .iter()
        .filter(|row| row["event"]["record_context"]["operation_ref"].as_str() == Some(operation))
        .collect::<Vec<_>>();
    assert_eq!(
        correlated
            .iter()
            .filter(|row| row["event"]["type"] == "send_outcome"
                && row["event"]["result_kind"] == "application_message")
            .count(),
        1
    );
    assert_eq!(
        correlated
            .iter()
            .filter(|row| row["event"]["type"] == "publish_outcome")
            .count(),
        if newer_below_quorum { 1 } else { 2 },
        "queue admission, preparation, first publication and retained retry must share one operation"
    );
}

#[tokio::test]
async fn ambiguous_commit_retries_exact_event_after_restart_and_peer_can_advance() {
    let dir = tempfile::tempdir().unwrap();
    let alice_path = dir.path().join("alice-unknown-retry.sqlite");
    let key_text = "marmot unknown retry key";
    let key = SqlCipherKey::new(key_text).unwrap();
    let mut alice = session(&alice_path, &key, b"alice-unknown-retry");
    let mut bob = session(
        dir.path().join("bob-unknown-retry.sqlite"),
        &key,
        b"bob-unknown-retry",
    );
    let created = alice
        .create_group(CreateGroupRequest {
            name: "unknown retry".into(),
            description: String::new(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let group_id = created.group_id.clone();
    let (create_pending, welcome) = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, welcomes } => (*pending, welcomes[0].clone()),
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(create_pending).await.unwrap();
    bob.ingest(welcome).await.unwrap();

    let endpoint = TransportEndpoint("wss://unknown-retry.example".into());
    let adapter = RecordingAdapter::default();
    let transport_event_id = MessageId::new(vec![0xE7; 32]);
    adapter.report_message_id_next(transport_event_id.clone());
    adapter.report_message_id_next(transport_event_id.clone());
    adapter.fail_endpoints_as(
        vec![endpoint.clone()],
        TransportEndpointFailureKind::PossiblyExposed,
    );
    let policy = StaticTransportRouting::new(vec![TransportEndpoint(
        "wss://unknown-retry-inbox.example".into(),
    )])
    .with_group_route(
        group_id.clone(),
        group_id.as_slice().to_vec(),
        vec![endpoint],
    );
    let wall = Arc::new(TestWallClock::new(100_000));
    let mut runtime = AccountDeviceRuntime::new(
        alice,
        adapter.clone(),
        policy.clone(),
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );

    let unresolved = runtime
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("possibly exposed".into()),
            description: None,
        })
        .await
        .unwrap();
    assert!(unresolved.pending.is_empty());
    assert_eq!(unresolved.unresolved_publishes.len(), 1);
    assert_eq!(
        unresolved.unresolved_publishes[0].message_id,
        transport_event_id
    );
    let first_attempt = adapter.publishes()[0].clone();

    // The endpoint could have forwarded these exact bytes even though its OK
    // was lost. A peer applying them proves sender rollback would split state.
    bob.ingest(first_attempt.message.clone()).await.unwrap();
    let convergence_delay = bob
        .prepare_convergence_cutoff_delay_ms(&group_id)
        .unwrap()
        .expect("buffered commit must open a convergence pass");
    tokio::time::sleep(Duration::from_millis(convergence_delay.saturating_add(1))).await;
    bob.advance_convergence(&group_id).await.unwrap();
    assert_eq!(bob.epoch(&group_id).unwrap().0, 2);
    assert_eq!(runtime.session().epoch(&group_id).unwrap().0, 2);
    drop(runtime);

    adapter.error_for_endpoints(Vec::new());
    let reopened = session(
        &alice_path,
        &SqlCipherKey::new(key_text).unwrap(),
        b"alice-unknown-retry",
    );
    let mut restarted = AccountDeviceRuntime::new(
        reopened,
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );

    let deferred = restarted.resume_outbound_fanouts().await.unwrap();
    assert!(deferred.reports.is_empty());
    assert_eq!(adapter.publishes().len(), 1);

    wall.set(100_030);
    let recovered = restarted.resume_outbound_fanouts().await.unwrap();
    assert!(matches!(
        recovered.pending.as_slice(),
        [PendingResolution::Confirmed { .. }]
    ));
    assert_eq!(restarted.session().epoch(&group_id).unwrap().0, 2);
    assert_eq!(recovered.reports[0].message_id, transport_event_id);
    assert!(restarted.session().outbound_fanouts().unwrap().is_empty());
    let attempts = adapter.publishes();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].message.id, attempts[1].message.id);
    assert_eq!(attempts[0].message.payload, attempts[1].message.payload);
}

#[tokio::test]
async fn ambiguous_application_publish_is_retained_without_definite_failure() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot unknown app message key").unwrap();
    let mut alice = session(
        dir.path().join("alice-unknown-app.sqlite"),
        &key,
        b"alice-unknown-app",
    );
    let mut bob = session(
        dir.path().join("bob-unknown-app.sqlite"),
        &key,
        b"bob-unknown-app",
    );
    let alice_id = alice.self_id();
    let alice_hex = hex::encode(alice_id.as_slice());
    let created = alice
        .create_group(CreateGroupRequest {
            name: "unknown app message".into(),
            description: String::new(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let group_id = created.group_id.clone();
    let (create_pending, welcome) = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, welcomes } => (*pending, welcomes[0].clone()),
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(create_pending).await.unwrap();
    bob.ingest(welcome).await.unwrap();
    let endpoint = TransportEndpoint("wss://unknown-app.example".into());
    let adapter = RecordingAdapter::default();
    let transport_event_id = MessageId::new(vec![0xA7; 32]);
    adapter.report_message_id_next(transport_event_id.clone());
    adapter.fail_endpoints_as(
        vec![endpoint.clone()],
        TransportEndpointFailureKind::PossiblyExposed,
    );
    let policy = StaticTransportRouting::new(vec![TransportEndpoint(
        "wss://unknown-app-inbox.example".into(),
    )])
    .with_group_route(
        group_id.clone(),
        group_id.as_slice().to_vec(),
        vec![endpoint],
    );
    let mut runtime =
        AccountDeviceRuntime::new(alice, adapter, policy, RecordingKeyPackages::default());
    let payload = app_payload_for(&alice_hex, b"only one semantic message");
    let app_event_id = MarmotAppEvent::decode(&payload).unwrap().id;

    let effects = runtime
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload,
            expected_epoch: None,
        })
        .await
        .unwrap();

    assert!(effects.failures.is_empty());
    assert!(effects.published_app_messages.is_empty());
    assert_eq!(effects.unresolved_app_messages.len(), 1);
    assert_eq!(effects.unresolved_app_messages[0].group_id, group_id);
    assert_eq!(
        effects.unresolved_app_messages[0].app_event_id,
        app_event_id
    );
    assert_eq!(
        effects.unresolved_app_messages[0].message_id,
        transport_event_id
    );
    assert_eq!(
        effects.unresolved_app_messages[0].reason,
        marmot_session::UnresolvedPublishReason::AcknowledgementUnknown
    );
    assert_eq!(runtime.session().outbound_fanouts().unwrap().len(), 1);
}

#[tokio::test]
async fn ambiguous_legacy_create_welcome_confirms_after_restart_with_exact_retry() {
    let dir = tempfile::tempdir().unwrap();
    let alice_path = dir.path().join("alice-create-unknown.sqlite");
    let key_text = "marmot unknown create key";
    let key = SqlCipherKey::new(key_text).unwrap();
    let alice = session(&alice_path, &key, b"alice-create-unknown");
    let mut bob = session(
        dir.path().join("bob-create-unknown.sqlite"),
        &key,
        b"bob-create-unknown",
    );
    let bob_id = bob.self_id();
    let endpoint = TransportEndpoint("wss://create-unknown.example".into());
    let adapter = RecordingAdapter::default();
    let transport_event_id = MessageId::new(vec![0xC7; 32]);
    adapter.report_message_id_next(transport_event_id.clone());
    adapter.report_message_id_next(transport_event_id.clone());
    adapter.fail_endpoints_as(
        vec![endpoint.clone()],
        TransportEndpointFailureKind::PossiblyExposed,
    );
    let policy = StaticTransportRouting::new(vec![endpoint.clone()])
        .with_inbox_route(bob_id, vec![endpoint]);
    let wall = Arc::new(TestWallClock::new(200_000));
    let mut runtime = AccountDeviceRuntime::new(
        alice,
        adapter.clone(),
        policy.clone(),
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );

    let (group_id, unresolved) = runtime
        .create_group(CreateGroupRequest {
            name: "unknown create".into(),
            description: String::new(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    assert!(unresolved.pending.is_empty());
    assert_eq!(unresolved.unresolved_publishes.len(), 1);
    assert_eq!(runtime.session().outbound_fanouts().unwrap().len(), 1);
    let first_attempt = adapter.publishes()[0].clone();
    drop(runtime);

    adapter.fail_endpoints_as(Vec::new(), TransportEndpointFailureKind::PossiblyExposed);
    let reopened = session(
        &alice_path,
        &SqlCipherKey::new(key_text).unwrap(),
        b"alice-create-unknown",
    );
    let mut restarted = AccountDeviceRuntime::new(
        reopened,
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );
    wall.set(200_030);

    let recovered = restarted.resume_outbound_fanouts().await.unwrap();
    assert!(
        matches!(
            recovered.pending.as_slice(),
            [PendingResolution::Confirmed { .. }]
        ),
        "recovered effects: {recovered:?}; fanouts: {:?}; quarantined: {:?}",
        restarted.session().outbound_fanouts().unwrap(),
        restarted.session().quarantined_groups()
    );
    assert_eq!(restarted.session().epoch(&group_id).unwrap().0, 1);
    let attempts = adapter.publishes();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].message, attempts[1].message);
    assert_eq!(recovered.reports[0].message_id, transport_event_id);
    bob.ingest(first_attempt.message).await.unwrap();
}

#[tokio::test]
async fn ambiguous_invite_commit_recovery_publishes_its_frozen_welcome() {
    let dir = tempfile::tempdir().unwrap();
    let alice_path = dir.path().join("alice-invite-unknown.sqlite");
    let key_text = "marmot unknown invite key";
    let key = SqlCipherKey::new(key_text).unwrap();
    let mut alice = session(&alice_path, &key, b"alice-invite-unknown");
    let mut bob = session(
        dir.path().join("bob-invite-unknown.sqlite"),
        &key,
        b"bob-invite-unknown",
    );
    let mut carol = session(
        dir.path().join("carol-invite-unknown.sqlite"),
        &key,
        b"carol-invite-unknown",
    );
    let carol_id = carol.self_id();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "unknown invite".into(),
            description: String::new(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let create_pending = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, .. } => *pending,
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(create_pending).await.unwrap();
    let group_id = created.group_id;

    let group_endpoint = TransportEndpoint("wss://invite-commit.example".into());
    let inbox_endpoint = TransportEndpoint("wss://invite-welcome.example".into());
    let adapter = RecordingAdapter::default();
    adapter.fail_endpoints_as(
        vec![group_endpoint.clone()],
        TransportEndpointFailureKind::PossiblyExposed,
    );
    let policy = StaticTransportRouting::new(vec![inbox_endpoint.clone()])
        .with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            vec![group_endpoint.clone()],
        )
        .with_inbox_route(carol_id, vec![inbox_endpoint.clone()]);
    let wall = Arc::new(TestWallClock::new(300_000));
    let mut runtime = AccountDeviceRuntime::new(
        alice,
        adapter.clone(),
        policy.clone(),
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );

    let unresolved = runtime
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol.fresh_key_package().await.unwrap()],
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    assert!(unresolved.pending.is_empty());
    assert_eq!(unresolved.unresolved_publishes.len(), 1);
    let original_commit = adapter.publishes()[0].message.clone();
    drop(runtime);

    adapter.fail_endpoints_as(Vec::new(), TransportEndpointFailureKind::PossiblyExposed);
    adapter.accept_only_endpoints(vec![group_endpoint, inbox_endpoint]);
    let reopened = session(
        &alice_path,
        &SqlCipherKey::new(key_text).unwrap(),
        b"alice-invite-unknown",
    );
    let mut restarted = AccountDeviceRuntime::new(
        reopened,
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );
    wall.set(300_030);

    let recovered = restarted.resume_outbound_fanouts().await.unwrap();
    assert!(matches!(
        recovered.pending.as_slice(),
        [PendingResolution::Confirmed { .. }]
    ));
    let attempts = adapter.publishes();
    assert_eq!(
        attempts.len(),
        3,
        "commit retry must release the frozen Welcome"
    );
    assert_eq!(attempts[1].message, original_commit);
    let recovered_welcome = attempts
        .iter()
        .find(|attempt| matches!(attempt.message.envelope, TransportEnvelope::Welcome { .. }))
        .expect("confirmed invite must publish its Welcome")
        .message
        .clone();
    carol.ingest(recovered_welcome).await.unwrap();
    assert_eq!(carol.epoch(&group_id).unwrap().0, 2);
}

#[tokio::test]
async fn ambiguous_disband_recovery_preserves_terminal_pending_kind() {
    let dir = tempfile::tempdir().unwrap();
    let alice_path = dir.path().join("alice-disband-unknown.sqlite");
    let key_text = "marmot unknown disband key";
    let key = SqlCipherKey::new(key_text).unwrap();
    let mut alice = current_session(&alice_path, &key, b"alice-disband-unknown");
    let created = alice
        .create_group(CreateGroupRequest {
            name: "unknown disband".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let group_id = created.group_id;
    alice
        .send(SendIntent::Disband {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();

    let endpoint = TransportEndpoint("wss://disband-unknown.example".into());
    let adapter = RecordingAdapter::default();
    adapter.fail_endpoints_as(
        vec![endpoint.clone()],
        TransportEndpointFailureKind::PossiblyExposed,
    );
    let policy = StaticTransportRouting::new(Vec::new()).with_group_route(
        group_id.clone(),
        group_id.as_slice().to_vec(),
        vec![endpoint.clone()],
    );
    let wall = Arc::new(TestWallClock::new(400_000));
    let mut runtime = AccountDeviceRuntime::new(
        alice,
        adapter.clone(),
        policy.clone(),
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );

    let unresolved = runtime.advance_convergence(&group_id).await.unwrap();
    assert_eq!(unresolved.unresolved_publishes.len(), 1);
    assert!(unresolved.pending.is_empty());
    let original_commit = adapter.publishes()[0].message.clone();
    drop(runtime);

    adapter.fail_endpoints_as(Vec::new(), TransportEndpointFailureKind::PossiblyExposed);
    adapter.accept_only_endpoints(vec![endpoint]);
    let reopened = current_session(
        &alice_path,
        &SqlCipherKey::new(key_text).unwrap(),
        b"alice-disband-unknown",
    );
    let mut restarted = AccountDeviceRuntime::new(
        reopened,
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );
    wall.set(400_030);

    let recovered = restarted.resume_outbound_fanouts().await.unwrap();
    assert!(matches!(
        recovered.pending.as_slice(),
        [PendingResolution::Confirmed { .. }]
    ));
    assert!(
        recovered.pending_convergence.contains(&group_id),
        "disband confirmation must schedule its terminal convergence pass"
    );
    let attempts = adapter.publishes();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[1].message, original_commit);
}

/// The production-adapter partial-accept shape: one relay accepts while its
/// siblings surface whole-call `Err`s. The accepted endpoint must stay
/// accepted and confirm pending MLS state — sibling errors must never read as
/// "everything failed".
#[tokio::test]
async fn frozen_fanout_partial_accept_with_sibling_adapter_errors_confirms_mls() {
    assert_frozen_fanout_case(Some(0), &[1, 2], None, true).await;
    assert_frozen_fanout_case(Some(2), &[0, 1], None, true).await;
    // Accepted + explicit rejection + acknowledgement-unknown remains
    // confirmed while retaining only the unresolved endpoint.
    assert_frozen_fanout_case(Some(0), &[2], None, true).await;
}

#[tokio::test]
async fn frozen_fanout_typed_unavailable_is_retryable_but_rejection_is_terminal() {
    assert_frozen_fanout_case(
        None,
        &[0, 1, 2],
        Some(TransportEndpointFailureKind::RetryableUnavailable),
        true,
    )
    .await;
    assert_frozen_fanout_case(
        None,
        &[0, 1, 2],
        Some(TransportEndpointFailureKind::TerminalRejected),
        false,
    )
    .await;
}

async fn assert_frozen_fanout_restart_edge(
    send_before_ack_persist: bool,
    resume_via_deferred_advance: bool,
) {
    let dir = tempfile::tempdir().unwrap();
    let alice_path = dir.path().join("alice-restart-edge.sqlite");
    let key_text = "marmot fanout restart edge key";
    let key = SqlCipherKey::new(key_text).unwrap();
    let mut alice = session(&alice_path, &key, b"alice-fanout-restart-edge");
    let mut bob = session(
        dir.path().join("bob-restart-edge.sqlite"),
        &key,
        b"bob-fanout-restart-edge",
    );
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "fanout restart edge".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let group_id = created.group_id.clone();
    let create_pending = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, .. } => *pending,
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(create_pending).await.unwrap();

    let staged = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("resume frozen bytes".into()),
            description: None,
        })
        .await
        .unwrap();
    let (message, pending) = match &staged.publish[0] {
        PublishWork::GroupEvolution { msg, pending, .. } => (msg.clone(), *pending),
        other => panic!("expected GroupEvolution publish work, got {other:?}"),
    };
    let transport_group_id = match &message.envelope {
        TransportEnvelope::GroupMessage { transport_group_id } => transport_group_id.clone(),
        other => panic!("expected group message, got {other:?}"),
    };
    let endpoints = vec![
        TransportEndpoint("wss://restart-one.example".into()),
        TransportEndpoint("wss://restart-two.example".into()),
        TransportEndpoint("wss://restart-three.example".into()),
    ];
    let request = TransportPublishRequest {
        account_id: alice.self_id(),
        message: message.clone(),
        target: TransportPublishTarget::Group {
            group_id: group_id.clone(),
            transport_group_id: transport_group_id.clone(),
            endpoints: endpoints.clone(),
        },
        required_acks: 1,
    };
    let mut fanout =
        OutboundFanout::stage(request.clone(), Some(pending), Some(group_id.clone()), 0).unwrap();
    alice.put_outbound_fanout(&fanout).unwrap();

    let adapter = RecordingAdapter::default();
    if send_before_ack_persist {
        fanout.mark_attempt_started(0).unwrap();
        alice.put_outbound_fanout(&fanout).unwrap();
        adapter
            .publish(TransportPublishRequest {
                account_id: request.account_id.clone(),
                message: message.clone(),
                target: TransportPublishTarget::Group {
                    group_id: group_id.clone(),
                    transport_group_id: transport_group_id.clone(),
                    endpoints: vec![endpoints[0].clone()],
                },
                required_acks: 1,
            })
            .await
            .unwrap();
    }
    let pre_restart_publish_count = adapter.publishes().len();
    drop(alice);

    let reopened = if resume_via_deferred_advance {
        deferred_session(
            &alice_path,
            &SqlCipherKey::new(key_text).unwrap(),
            b"alice-fanout-restart-edge",
        )
    } else {
        session(
            &alice_path,
            &SqlCipherKey::new(key_text).unwrap(),
            b"alice-fanout-restart-edge",
        )
    };
    if resume_via_deferred_advance {
        assert_eq!(reopened.unhydrated_group_ids(), vec![group_id.clone()]);
    }
    let replacement_policy = StaticTransportRouting::new(vec![TransportEndpoint(
        "wss://replacement-inbox.example".into(),
    )])
    .with_group_route(
        group_id.clone(),
        vec![0xEE; 32],
        vec![TransportEndpoint("wss://replacement.example".into())],
    );
    let mut resumed = AccountDeviceRuntime::new(
        reopened,
        adapter.clone(),
        replacement_policy,
        RecordingKeyPackages::default(),
    );
    let effects = if resume_via_deferred_advance {
        resumed.advance_convergence(&group_id).await.unwrap()
    } else {
        resumed.drain().await.unwrap()
    };

    assert!(effects.fanout[0].mls_confirmed);
    assert!(effects.fanout[0].fanout_complete);
    assert!(resumed.session().unhydrated_group_ids().is_empty());
    assert_eq!(resumed.session().epoch(&group_id).unwrap().0, 2);
    let attempts = adapter.publishes();
    let resumed_attempts = &attempts[pre_restart_publish_count..];
    // Every outstanding target — including the pre-restart `Attempting` one —
    // resumes as concurrent single-endpoint publishes over the frozen route.
    assert_eq!(resumed_attempts.len(), endpoints.len());
    assert!(resumed_attempts.iter().all(|attempt| {
        attempt.message.id == message.id && attempt.message.payload == message.payload
    }));
    let mut resumed_endpoints = resumed_attempts
        .iter()
        .flat_map(|attempt| attempt.target.endpoints().to_vec())
        .collect::<Vec<_>>();
    resumed_endpoints.sort_by(|a, b| a.0.cmp(&b.0));
    let mut expected = endpoints.clone();
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(resumed_endpoints, expected);
}

#[tokio::test]
async fn frozen_fanout_resumes_after_intent_and_after_send_before_ack_persistence() {
    assert_frozen_fanout_restart_edge(false, false).await;
    assert_frozen_fanout_restart_edge(true, false).await;
}

#[tokio::test]
async fn scheduled_advance_hydrates_before_resuming_frozen_fanout() {
    assert_frozen_fanout_restart_edge(false, true).await;
}

#[tokio::test]
async fn frozen_fanout_survives_crash_and_ignores_changed_routing_on_resume() {
    let dir = tempfile::tempdir().unwrap();
    let alice_path = dir.path().join("alice-frozen-fanout.sqlite");
    let key_text = "marmot frozen fanout key";
    let key = SqlCipherKey::new(key_text).unwrap();
    let mut alice = session(&alice_path, &key, b"alice-frozen-fanout");
    let mut bob = session(
        dir.path().join("bob-frozen-fanout.sqlite"),
        &key,
        b"bob-frozen-fanout",
    );
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "frozen fanout".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let group_id = created.group_id.clone();
    let create_pending = match &created.effects.publish[0] {
        PublishWork::GroupCreated { pending, .. } => *pending,
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    alice.confirm_published(create_pending).await.unwrap();

    let original_endpoints = vec![
        TransportEndpoint("wss://original-one.example".into()),
        TransportEndpoint("wss://original-two.example".into()),
        TransportEndpoint("wss://original-three.example".into()),
    ];
    let crash_adapter = CrashDuringFanoutPublishAdapter::default();
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())])
            .with_group_route(
                group_id.clone(),
                group_id.as_slice().to_vec(),
                original_endpoints.clone(),
            );
    let mut runtime = AccountDeviceRuntime::new(
        alice,
        crash_adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    );
    let crashed = tokio::spawn(async move {
        runtime
            .send(SendIntent::UpdateGroupData {
                group_id,
                name: Some("published before crash".into()),
                description: None,
            })
            .await
    })
    .await;
    assert!(crashed.unwrap_err().is_panic());

    // The stream initially polls publishes in order; the crash lands
    // in the first one, before its siblings are polled.
    let first_attempts = crash_adapter.publishes();
    assert_eq!(first_attempts.len(), 1);
    assert_eq!(
        first_attempts[0].target.endpoints(),
        &original_endpoints[..1]
    );
    let frozen_id = first_attempts[0].message.id.clone();
    let frozen_bytes = first_attempts[0].message.payload.clone();

    {
        let stored = SqliteAccountStorage::open_encrypted(
            &alice_path,
            &SqlCipherKey::new(key_text).unwrap(),
        )
        .unwrap();
        let fanouts = stored.list_outbound_fanouts().unwrap();
        assert_eq!(fanouts.len(), 1);
        assert_eq!(fanouts[0].message_id(), &frozen_id);
        assert_eq!(fanouts[0].request().message.payload, frozen_bytes);
        assert_eq!(fanouts[0].request().target.endpoints(), original_endpoints);
        assert_eq!(
            fanouts[0].target_statuses(),
            &[
                FanoutTargetStatus::Attempting,
                FanoutTargetStatus::Attempting,
                FanoutTargetStatus::Attempting,
            ]
        );
        assert!(matches!(fanouts[0].mls_state(), FanoutMlsState::Pending(_)));
    }

    let reopened = session(
        &alice_path,
        &SqlCipherKey::new(key_text).unwrap(),
        b"alice-frozen-fanout",
    );
    let replacement_endpoints = vec![TransportEndpoint("wss://replacement.example".into())];
    let resumed_adapter = RecordingAdapter::default();
    let replacement_policy = StaticTransportRouting::new(vec![TransportEndpoint(
        "wss://replacement-inbox.example".into(),
    )])
    .with_group_route(
        created.group_id.clone(),
        vec![0xEE; 32],
        replacement_endpoints,
    );
    let mut resumed = AccountDeviceRuntime::new(
        reopened,
        resumed_adapter.clone(),
        replacement_policy,
        RecordingKeyPackages::default(),
    );

    let effects = resumed.resume_outbound_fanouts().await.unwrap();
    assert_eq!(effects.reports.len(), 1);
    assert_eq!(effects.fanout.len(), 1);
    assert!(effects.fanout[0].mls_confirmed);
    assert!(effects.fanout[0].fanout_complete);

    let resumed_attempts = resumed_adapter.publishes();
    // The resumed fanout re-attempts every outstanding target as concurrent
    // single-endpoint publishes over the frozen route, ignoring the
    // replacement routing policy.
    assert_eq!(resumed_attempts.len(), original_endpoints.len());
    let mut resumed_endpoints = resumed_attempts
        .iter()
        .flat_map(|request| request.target.endpoints().to_vec())
        .collect::<Vec<_>>();
    resumed_endpoints.sort_by(|a, b| a.0.cmp(&b.0));
    let mut expected = original_endpoints.clone();
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(resumed_endpoints, expected);
    assert!(resumed_attempts.iter().all(|request| {
        request.message.id == frozen_id && request.message.payload == frozen_bytes
    }));

    let duplicate_resume = resumed.resume_outbound_fanouts().await.unwrap();
    assert!(duplicate_resume.reports.is_empty());
    assert_eq!(resumed_adapter.publishes().len(), original_endpoints.len());
}

#[tokio::test]
#[ignore = "diagnostic member-size and stalled-relay timing matrix"]
async fn send_skips_slow_relay() {
    for member_count in [2, 5, 9, 17] {
        let dir = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new("send latency test key").unwrap();
        let mut alice = session(dir.path().join("alice.sqlite"), &key, b"latency-alice");
        let sender = hex::encode(alice.self_id().as_slice());
        let mut members = Vec::new();
        for index in 1..member_count {
            let name = format!("latency-member-{index}");
            let mut member = session(
                dir.path().join(format!("{index}.sqlite")),
                &key,
                name.as_bytes(),
            );
            members.push(member.fresh_key_package().await.unwrap());
        }
        let created = alice
            .create_group(CreateGroupRequest {
                name: "send latency".into(),
                description: String::new(),
                members,
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        let group_id = created.group_id;
        let pending = match &created.effects.publish[0] {
            PublishWork::GroupCreated { pending, .. } => *pending,
            other => panic!("expected group creation, got {other:?}"),
        };
        alice.confirm_published(pending).await.unwrap();
        let fast = TransportEndpoint("wss://fast.example".into());
        let slow = TransportEndpoint("wss://slow.example".into());
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let adapter = RecordingAdapter::default();
        let routing = StaticTransportRouting::new(Vec::new()).with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            vec![fast, slow.clone()],
        );
        let mut runtime = AccountDeviceRuntime::new(
            alice,
            adapter.clone(),
            routing,
            RecordingKeyPackages::default(),
        );
        let mut timings = Vec::new();
        for index in 0..10 {
            let payload = app_payload_for(&sender, format!("healthy send {index}"));
            let started = std::time::Instant::now();
            let effects = runtime
                .send(SendIntent::AppMessage {
                    group_id: group_id.clone(),
                    payload,
                    expected_epoch: None,
                })
                .await
                .unwrap();
            timings.push(started.elapsed().as_micros());
            assert_eq!(effects.published_app_messages.len(), 1);
        }
        eprintln!("members={member_count} healthy_send_us={timings:?}");
        adapter.inner.publishes.lock().unwrap().clear();
        *adapter.inner.endpoint_gate.lock().unwrap() = Some((slow, gate.clone()));
        let send = runtime.send(SendIntent::AppMessage {
            group_id,
            payload: app_payload_for(&sender, b"latency probe"),
            expected_epoch: None,
        });
        // The first acknowledgement releases the caller while the second
        // relay remains stalled and its exact event stays durable for retry.
        let effects = tokio::time::timeout(Duration::from_secs(1), send)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(effects.published_app_messages.len(), 1);
        assert_eq!(effects.reports[0].required_acks, 1);
        assert_eq!(effects.reports[0].accepted.len(), 1);
        assert_eq!(adapter.publishes().len(), 2);
        assert_eq!(effects.fanout[0].outstanding_targets, 1);
    }
}

/// Poll a gated operation until its expected publish attempts have started.
async fn wait_for_publish_count<F: std::future::Future>(
    mut future: std::pin::Pin<&mut F>,
    adapter: &RecordingAdapter,
    expected: usize,
) {
    tokio::time::timeout(
        Duration::from_secs(10),
        std::future::poll_fn(|cx| {
            assert!(
                future.as_mut().poll(cx).is_pending(),
                "must wait for quorum"
            );
            if adapter.publishes().len() == expected {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        }),
    )
    .await
    .expect("publishes must reach the gated relay");
}

/// Quorum releases Welcomes once; cancelled relay retries retain their backoff across restart.
#[tokio::test]
async fn invite_quorum_survives_restart() {
    for required_acks in [0, 1, 2] {
        let dir = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new("invite quorum test key").unwrap();
        let alice_path = dir.path().join("alice.sqlite");
        let mut alice = session(&alice_path, &key, b"invite-quorum-alice");
        let mut bob = session(dir.path().join("bob.sqlite"), &key, b"invite-quorum-bob");
        let created = alice
            .create_group(CreateGroupRequest {
                name: "invite quorum".into(),
                description: String::new(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        let group_id = created.group_id;
        let pending = match &created.effects.publish[0] {
            PublishWork::GroupCreated { pending, .. } => *pending,
            other => panic!("expected group creation, got {other:?}"),
        };
        alice.confirm_published(pending).await.unwrap();
        let slow = TransportEndpoint("wss://slow.example".into());
        let routing = StaticTransportRouting::new(vec![])
            .required_acks(required_acks)
            .with_inbox_route(
                bob.self_id(),
                vec![
                    TransportEndpoint("wss://inbox-one.example".into()),
                    TransportEndpoint("wss://inbox-two.example".into()),
                ],
            )
            .with_group_route(
                group_id.clone(),
                group_id.as_slice().to_vec(),
                vec![slow.clone(), TransportEndpoint("wss://fast.example".into())],
            );
        let adapter = RecordingAdapter::default();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        *adapter.inner.endpoint_gate.lock().unwrap() = Some((slow.clone(), gate.clone()));
        let wall = Arc::new(TestWallClock::new(100_000));
        let mut runtime = AccountDeviceRuntime::new(
            alice,
            adapter.clone(),
            routing.clone(),
            RecordingKeyPackages::default(),
        )
        .with_maintenance_sources(
            wall.clone(),
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(0)),
        );
        let first = {
            let send = runtime.send(SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages: vec![bob.fresh_key_package().await.unwrap()],
                initial_admins: vec![],
            });
            tokio::pin!(send);
            if required_acks == 2 {
                wait_for_publish_count(send.as_mut(), &adapter, 2).await;
                None
            } else {
                Some(
                    tokio::time::timeout(Duration::from_secs(10), send)
                        .await
                        .unwrap()
                        .unwrap(),
                )
            }
        };
        let effects = if required_acks == 2 {
            assert_eq!(adapter.publishes().len(), 2);
            let fanouts = runtime.session().outbound_fanouts().unwrap();
            assert_eq!(fanouts[0].outcome().accepted_targets, 1);
            assert!(matches!(fanouts[0].mls_state(), FanoutMlsState::Pending(_)));
            drop(runtime);
            runtime = AccountDeviceRuntime::new(
                session(&alice_path, &key, b"invite-quorum-alice"),
                adapter.clone(),
                routing.clone(),
                RecordingKeyPackages::default(),
            );
            let retry = runtime.resume_outbound_fanouts();
            tokio::pin!(retry);
            wait_for_publish_count(retry.as_mut(), &adapter, 3).await;
            assert_eq!(
                adapter.publishes().len(),
                3,
                "restart must not release Welcome early"
            );
            gate.add_permits(1);
            retry.await.unwrap()
        } else {
            first.expect("invite must finish once its acknowledgement threshold is met")
        };
        assert!(effects.failures.is_empty());
        assert!(
            effects
                .pending
                .iter()
                .any(|pending| matches!(pending, PendingResolution::Confirmed { .. }))
        );
        assert_eq!(
            adapter.publishes().len(),
            if required_acks == 2 { 4 } else { 3 },
            "Welcome starts once quorum is met"
        );
        assert!(matches!(
            adapter.publishes().last().unwrap().message.envelope,
            TransportEnvelope::Welcome { .. }
        ));
        if required_acks == 2 {
            assert!(runtime.session().outbound_fanouts().unwrap().is_empty());
            continue;
        }
        let fanouts = runtime.session().outbound_fanouts().unwrap();
        assert_eq!(fanouts.len(), 1);
        assert_eq!(fanouts[0].outcome().accepted_targets, 1);
        assert_eq!(fanouts[0].outcome().outstanding_targets, 1);
        assert_eq!(
            fanouts[0].target_status(0),
            Some(FanoutTargetStatus::PossiblyExposed)
        );
        assert!(fanouts[0].outcome().mls_confirmed);
        assert!(effects.pending_convergence.contains(&group_id));
        assert_eq!(
            runtime.outbound_fanout_retry_delay_ms(&group_id).unwrap(),
            Some(30_000)
        );
        drop(runtime);

        let resumed_adapter = RecordingAdapter::default();
        *resumed_adapter.inner.endpoint_gate.lock().unwrap() = Some((slow.clone(), gate.clone()));
        let mut resumed = AccountDeviceRuntime::new(
            session(&alice_path, &key, b"invite-quorum-alice"),
            resumed_adapter.clone(),
            routing,
            RecordingKeyPackages::default(),
        )
        .with_maintenance_sources(
            wall.clone(),
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(0)),
        );
        let deferred = resumed.resume_outbound_fanouts().await.unwrap();
        assert!(deferred.reports.is_empty());
        assert!(resumed_adapter.publishes().is_empty());
        assert_eq!(
            resumed.outbound_fanout_retry_delay_ms(&group_id).unwrap(),
            Some(30_000)
        );
        wall.set(100_030);
        {
            let retry = resumed.resume_outbound_fanouts();
            tokio::pin!(retry);
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut retry)
                    .await
                    .is_err(),
                "an already-met quorum must not cancel outstanding retries"
            );
            gate.add_permits(1);
            let effects = retry.await.unwrap();
            assert!(effects.failures.is_empty());
            assert!(
                effects.pending.is_empty(),
                "MLS must not be confirmed twice"
            );
        }
        let attempts = resumed_adapter.publishes();
        assert_eq!(
            attempts.len(),
            1,
            "retry only the outstanding relay, without repeating the Welcome"
        );
        assert_eq!(attempts[0].target.endpoints(), &[slow]);
        assert_eq!(attempts[0].message, fanouts[0].request().message);
        assert!(resumed.session().outbound_fanouts().unwrap().is_empty());
    }
}

/// Foreground pressure can interrupt confirmed replication, never an unmet quorum.
#[tokio::test]
async fn secondary_retry_yield_preserves_exact_fanout_and_required_quorum() {
    for required_acks in [1, 2] {
        let dir = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new("secondary retry yield key").unwrap();
        let path = dir.path().join("alice.sqlite");
        let mut alice = session(&path, &key, b"secondary-yield-alice");
        let mut bob = session(dir.path().join("bob.sqlite"), &key, b"secondary-yield-bob");
        let created = alice
            .create_group(CreateGroupRequest {
                name: "secondary yield".into(),
                description: String::new(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        let group = created.group_id;
        let pending = match created.effects.publish[0] {
            PublishWork::GroupCreated { pending, .. } => pending,
            _ => panic!("group creation required"),
        };
        alice.confirm_published(pending).await.unwrap();
        let slow = TransportEndpoint("wss://yield-slow.example".into());
        let fast = TransportEndpoint("wss://yield-fast.example".into());
        let routing = StaticTransportRouting::new(vec![])
            .required_acks(required_acks)
            .with_inbox_route(
                bob.self_id(),
                vec![
                    TransportEndpoint("wss://yield-welcome-one.example".into()),
                    TransportEndpoint("wss://yield-welcome-two.example".into()),
                ],
            )
            .with_group_route(
                group.clone(),
                group.as_slice().to_vec(),
                vec![slow.clone(), fast],
            );
        let adapter = RecordingAdapter::default();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        *adapter.inner.endpoint_gate.lock().unwrap() = Some((slow.clone(), gate.clone()));
        let wall = Arc::new(TestWallClock::new(100_000));
        let mut runtime = AccountDeviceRuntime::new(
            alice,
            adapter.clone(),
            routing.clone(),
            RecordingKeyPackages::default(),
        )
        .with_maintenance_sources(
            wall.clone(),
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(0)),
        );
        {
            let send = runtime.send(SendIntent::Invite {
                group_id: group.clone(),
                key_packages: vec![bob.fresh_key_package().await.unwrap()],
                initial_admins: vec![],
            });
            tokio::pin!(send);
            if required_acks == 2 {
                wait_for_publish_count(send.as_mut(), &adapter, 2).await;
            } else {
                tokio::time::timeout(Duration::from_secs(10), send)
                    .await
                    .unwrap()
                    .unwrap();
            }
        }
        let original = runtime
            .session()
            .outbound_fanouts_for_group(&group)
            .unwrap()
            .remove(0);
        assert_eq!(original.outcome().accepted_targets, 1);
        assert_eq!(
            matches!(original.mls_state(), FanoutMlsState::Pending(_)),
            required_acks == 2
        );
        wall.set(100_031);
        let (request_yield, requested) = tokio::sync::oneshot::channel();
        {
            let retry = runtime.advance_convergence_with_publication_progress_and_yield(
                &group,
                Arc::new(|_, _| {}),
                async {
                    let _ = requested.await;
                },
            );
            tokio::pin!(retry);
            wait_for_publish_count(
                retry.as_mut(),
                &adapter,
                if required_acks == 1 { 4 } else { 3 },
            )
            .await;
            request_yield.send(()).unwrap();
            if required_acks == 2 {
                assert!(
                    tokio::time::timeout(Duration::from_millis(30), retry.as_mut())
                        .await
                        .is_err(),
                    "foreground work cannot cancel the second required ACK or pending MLS"
                );
                gate.add_permits(1);
            }
            tokio::time::timeout(Duration::from_secs(2), retry)
                .await
                .expect("confirmed secondary retry must yield while its ACK is withheld")
                .unwrap();
        }
        let attempts = adapter.publishes();
        let retried = &attempts[if required_acks == 1 { 3 } else { 2 }];
        assert_eq!(retried.message, original.request().message);
        assert_eq!(retried.target.endpoints(), std::slice::from_ref(&slow));
        assert_eq!(
            attempts
                .iter()
                .filter(|attempt| matches!(
                    attempt.message.envelope,
                    TransportEnvelope::Welcome { .. }
                ))
                .count(),
            1,
            "required confirmation must release its Welcome exactly once despite foreground pressure"
        );
        if required_acks == 1 {
            let retained = runtime
                .session()
                .outbound_fanouts_for_group(&group)
                .unwrap()
                .remove(0);
            assert_eq!(retained.request(), original.request());
            assert_eq!(retained.outcome().accepted_targets, 1);
            assert_eq!(
                retained.target_status(0),
                Some(FanoutTargetStatus::PossiblyExposed)
            );
            let delay = runtime
                .outbound_fanout_retry_delay_ms(&group)
                .unwrap()
                .unwrap();
            assert!(delay >= 30_000);
            drop(runtime);
            runtime = AccountDeviceRuntime::new(
                session(&path, &key, b"secondary-yield-alice"),
                adapter.clone(),
                routing,
                RecordingKeyPackages::default(),
            )
            .with_maintenance_sources(
                wall.clone(),
                Arc::new(TestMonotonicClock::default()),
                Arc::new(TestRandom::new(0)),
            );
            assert_eq!(
                runtime.outbound_fanout_retry_delay_ms(&group).unwrap(),
                Some(delay)
            );
            wall.set(100_031 + delay.div_ceil(1_000));
            runtime
                .advance_convergence_with_publication_progress_and_yield(
                    &group,
                    Arc::new(|_, _| {}),
                    std::future::ready(()),
                )
                .await
                .unwrap();
            assert_eq!(
                adapter.publishes().len(),
                4,
                "already-ready pressure must not start another attempt"
            );
            assert_eq!(
                runtime.outbound_fanout_retry_delay_ms(&group).unwrap(),
                Some(0),
                "skipped attempts must not move the retry deadline"
            );
            gate.add_permits(1);
            runtime.advance_convergence(&group).await.unwrap();
            assert_eq!(
                adapter.publishes().len(),
                5,
                "a fresh quiet pass must resume replication"
            );
            assert_eq!(adapter.publishes()[4].message, original.request().message);
            assert_eq!(
                adapter.publishes()[4].target.endpoints(),
                std::slice::from_ref(&slow)
            );
        }
        assert!(
            runtime
                .session()
                .outbound_fanouts_for_group(&group)
                .unwrap()
                .is_empty(),
            "replication must finish after foreground pressure ends"
        );
    }
}

fn recovery_inbox_delivery(account_id: MemberId, message: TransportMessage) -> TransportDelivery {
    TransportDelivery {
        account_id,
        group_id_hint: None,
        message,
        received_at: Timestamp(0),
        source: TransportDeliverySource {
            transport: TransportSource("recovery-test".into()),
            plane: TransportDeliveryPlane::AccountInbox,
            endpoint: None,
            subscription_id: None,
            wire: None,
        },
    }
}

#[tokio::test]
async fn recovery_live_cancel_resume() {
    assert_recovery_cancel(RecoveryCancelPoint::Commit).await;
}

#[tokio::test]
async fn recovery_one_admin_device() {
    let mut peers = recovery_peers().await;
    let key = SqlCipherKey::new("live recovery cancellation key").unwrap();
    let mut sibling = Device::open(
        peers._dir.path().join("admin-sibling.sqlite"),
        &key,
        b"cancel-alice",
    )
    .await;
    let alice_id = peers.coordinator.self_id();
    let bob_id = peers.recipient.self_id();
    assert_eq!(sibling.runtime.self_id(), alice_id);
    peers
        .coordinator
        .send(SendIntent::Invite {
            group_id: peers.group.clone(),
            key_packages: vec![sibling.key_package.clone()],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome = peers.adapter.publishes().into_iter().find(|request| matches!(
        &request.message.envelope, TransportEnvelope::Welcome { recipient } if recipient == &alice_id
    )).unwrap().message;
    sibling.ingest(&welcome).await;
    let epoch = peers.coordinator.session().epoch(&peers.group).unwrap();
    assert_eq!(
        sibling.runtime.session().epoch(&peers.group).unwrap(),
        epoch
    );
    let inbox = TransportEndpoint("wss://recovery-inbox.example".into());
    let routing = StaticTransportRouting::new(vec![inbox.clone()])
        .key_package_endpoints(vec![inbox.clone()])
        .with_group_route(
            peers.group.clone(),
            vec![0x5a; 32],
            vec![TransportEndpoint("wss://recovery-group.example".into())],
        )
        .with_inbox_route(alice_id.clone(), vec![inbox.clone()])
        .with_inbox_route(bob_id.clone(), vec![inbox]);
    let sibling_adapter = sibling.adapter.clone();
    drop(sibling);
    let mut sibling = AccountDeviceRuntime::new(
        nostr_device_session(
            peers._dir.path().join("admin-sibling.sqlite"),
            &key,
            b"cancel-alice",
        ),
        sibling_adapter.clone(),
        routing,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        peers.wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );
    let prior = peers.adapter.publishes().len();
    peers.recipient.prepare_group_recovery().unwrap();
    peers.recipient.advance_group_recovery().await.unwrap();
    let request = peers
        .bob_adapter
        .publishes()
        .last()
        .unwrap()
        .message
        .clone();
    for coordinator in [&mut peers.coordinator, &mut sibling] {
        coordinator
            .ingest_delivery(&recovery_inbox_delivery(alice_id.clone(), request.clone()))
            .await
            .unwrap();
        coordinator.prepare_group_recovery().unwrap();
        coordinator.advance_group_recovery().await.unwrap();
    }
    for adapter in [&peers.adapter, &sibling_adapter] {
        let challenge = adapter.publishes().last().unwrap().message.clone();
        peers
            .recipient
            .ingest_delivery(&recovery_inbox_delivery(bob_id.clone(), challenge))
            .await
            .unwrap();
    }
    peers.recipient.prepare_group_recovery().unwrap();
    peers.recipient.advance_group_recovery().await.unwrap();
    let grant = peers
        .bob_adapter
        .publishes()
        .last()
        .unwrap()
        .message
        .clone();
    for coordinator in [&mut peers.coordinator, &mut sibling] {
        coordinator
            .ingest_delivery(&recovery_inbox_delivery(alice_id.clone(), grant.clone()))
            .await
            .unwrap();
        coordinator.prepare_group_recovery().unwrap();
        coordinator.advance_group_recovery().await.unwrap();
    }
    let sent = peers.adapter.publishes();
    let commits = sent[prior..]
        .iter()
        .chain(sibling_adapter.publishes().iter())
        .filter(|request| {
            matches!(
                request.message.envelope,
                TransportEnvelope::GroupMessage { .. }
            )
        })
        .count();
    assert_eq!(
        commits, 1,
        "one grant must authorize only its selected coordinator device"
    );
    assert!(peers.coordinator.session().epoch(&peers.group).unwrap() > epoch);
    assert_eq!(sibling.session().epoch(&peers.group).unwrap(), epoch);
    let welcome = sent[prior..]
        .iter()
        .find(|request| is_recovery_welcome(&request.message))
        .unwrap()
        .message
        .clone();
    peers
        .recipient
        .ingest_delivery(&recovery_inbox_delivery(bob_id, welcome))
        .await
        .unwrap();
    assert!(
        !peers
            .recipient
            .group_record(&peers.group)
            .unwrap()
            .unrecoverable
    );
    assert_recovery_chat(
        &mut peers.coordinator,
        &peers.adapter,
        &mut peers.recipient,
        &peers.group,
    )
    .await;
}

#[tokio::test]
async fn recovery_welcome_cancel() {
    assert_recovery_cancel(RecoveryCancelPoint::Welcome).await;
}

#[tokio::test]
async fn recovery_lost_welcome() {
    let mut peers = recovery_peers().await;
    let old_leaf = peers.recipient.own_leaf_index(&peers.group).unwrap();
    exchange_recovery(&mut peers).await;
    peers.coordinator.advance_group_recovery().await.unwrap();
    let bob_id = peers.recipient.self_id();
    let current = peers
        .coordinator
        .canonical_group_membership(&peers.group)
        .unwrap();
    let moved_leaf = current
        .member_leaves
        .iter()
        .find(|leaf| leaf.member == bob_id)
        .unwrap()
        .leaf_index;
    assert_ne!(moved_leaf, old_leaf);
    // The acknowledged Welcome is lost before the offline device sees it.
    let lost = peers
        .adapter
        .publishes()
        .into_iter()
        .find(|attempt| is_recovery_welcome(&attempt.message))
        .unwrap()
        .message;
    peers.wall.set(peers.wall.now().0 + 1_200);
    exchange_recovery(&mut peers).await;
    peers.coordinator.advance_group_recovery().await.unwrap();
    let replacement = peers
        .adapter
        .publishes()
        .into_iter()
        .rfind(|attempt| is_recovery_welcome(&attempt.message))
        .unwrap()
        .message;
    assert_ne!(replacement.id, lost.id);
    peers
        .recipient
        .ingest_delivery(&recovery_inbox_delivery(bob_id, replacement))
        .await
        .unwrap();
    assert!(
        !peers
            .recipient
            .group_record(&peers.group)
            .unwrap()
            .unrecoverable
    );
    assert_eq!(
        peers.recipient.session().epoch(&peers.group).unwrap(),
        peers.coordinator.session().epoch(&peers.group).unwrap()
    );
    assert_recovery_chat(
        &mut peers.coordinator,
        &peers.adapter,
        &mut peers.recipient,
        &peers.group,
    )
    .await;
}

#[derive(Clone, Copy)]
enum RecoveryCancelPoint {
    Commit,
    Welcome,
}

#[tokio::test]
async fn recovery_heal_race() {
    let mut peers = recovery_peers().await;
    exchange_recovery(&mut peers).await;
    peers.coordinator.advance_group_recovery().await.unwrap();
    let first = peers
        .adapter
        .publishes()
        .into_iter()
        .find(|attempt| is_recovery_welcome(&attempt.message))
        .unwrap()
        .message;
    peers.wall.set(peers.wall.now().0 + 1_200);
    exchange_recovery(&mut peers).await;
    let bob = peers.recipient.self_id();
    peers
        .recipient
        .ingest_delivery(&recovery_inbox_delivery(bob.clone(), first))
        .await
        .unwrap();
    assert!(
        !peers
            .recipient
            .group_record(&peers.group)
            .unwrap()
            .unrecoverable
    );
    // Its second grant was already delivered before the first Welcome healed it.
    peers.coordinator.advance_group_recovery().await.unwrap();
    let attempts = peers.adapter.publishes();
    let commit = attempts
        .iter()
        .rfind(|attempt| {
            matches!(
                attempt.message.envelope,
                TransportEnvelope::GroupMessage { .. }
            )
        })
        .unwrap()
        .message
        .clone();
    let welcome = attempts
        .into_iter()
        .rfind(|attempt| is_recovery_welcome(&attempt.message))
        .unwrap()
        .message;
    peers
        .recipient
        .ingest_delivery(&recovery_inbox_delivery(bob, welcome))
        .await
        .unwrap();
    peers.recipient.session_mut().ingest(commit).await.unwrap();
    if let Some(delay) = peers
        .recipient
        .session_mut()
        .prepare_convergence_cutoff_delay_ms(&peers.group)
        .unwrap()
    {
        tokio::time::sleep(Duration::from_millis(delay.saturating_add(1))).await;
        peers
            .recipient
            .advance_convergence(&peers.group)
            .await
            .unwrap();
    }
    peers
        .recipient
        .retry_rejoins_after_trusted_removal()
        .await
        .unwrap();
    assert!(!peers.recipient.group_record(&peers.group).unwrap().removed);
    assert_eq!(
        peers.recipient.session().epoch(&peers.group).unwrap(),
        peers.coordinator.session().epoch(&peers.group).unwrap()
    );
    assert_recovery_chat(
        &mut peers.coordinator,
        &peers.adapter,
        &mut peers.recipient,
        &peers.group,
    )
    .await;
}

// Fixture-owned keys identify the actual MLS Welcome, not every inbox control.
fn is_recovery_welcome(message: &TransportMessage) -> bool {
    if !matches!(message.envelope, TransportEnvelope::Welcome { .. }) {
        return false;
    }
    let event = nostr::prelude::Event::from_json(&message.payload).unwrap();
    let unwrapped =
        nostr::nips::nip59::extract_rumor(&deterministic_nostr_keys(b"cancel-bob"), &event)
            .unwrap();
    unwrapped.rumor.kind
        == nostr::prelude::Kind::Custom(transport_nostr_peeler::KIND_MARMOT_WELCOME_RUMOR)
}

impl RecoveryCancelPoint {
    fn matches_artifact(self, message: &TransportMessage) -> bool {
        match self {
            Self::Commit => matches!(message.envelope, TransportEnvelope::GroupMessage { .. }),
            Self::Welcome => is_recovery_welcome(message),
        }
    }
}

type RecoveryRuntime =
    AccountDeviceRuntime<RecordingAdapter, StaticTransportRouting, RecordingKeyPackages>;

struct RecoveryPeers {
    coordinator: RecoveryRuntime,
    recipient: RecoveryRuntime,
    adapter: RecordingAdapter,
    bob_adapter: RecordingAdapter,
    wall: Arc<TestWallClock>,
    group: GroupId,
    before: cgka_traits::EpochId,
    _dir: tempfile::TempDir,
}

async fn recovery_peers() -> RecoveryPeers {
    use cgka_traits::storage::GroupStorage;

    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("live recovery cancellation key").unwrap();
    let bob_path = dir.path().join("bob.sqlite");
    let mut bob_device = Device::open(bob_path.clone(), &key, b"cancel-bob").await;
    let filler = Device::open(dir.path().join("filler.sqlite"), &key, b"cancel-filler").await;
    let bob_id = bob_device.runtime.self_id();
    let mut alice = nostr_device_session(dir.path().join("alice.sqlite"), &key, b"cancel-alice");
    let alice_id = alice.self_id();
    let (group, welcomes) = create_group(
        &mut alice,
        &[&filler.key_package, &bob_device.key_package],
        "cancel recovery",
    )
    .await;
    let welcome = welcomes
        .iter()
        .find(|message| {
            matches!(&message.envelope,
        TransportEnvelope::Welcome { recipient } if recipient == &bob_id)
        })
        .unwrap();
    bob_device.ingest(welcome).await;
    alice.mark_sent_welcome_delivered(&welcome.id).unwrap();
    // A lower vacant slot makes recovery move the target's current leaf.
    evolve(
        &mut alice,
        SendIntent::RemoveMembers {
            group_id: group.clone(),
            members: vec![filler.runtime.self_id()],
        },
    )
    .await;
    let before = alice.epoch(&group).unwrap();
    drop(bob_device);
    let store = storage_sqlite::SqliteAccountStorage::open_encrypted(
        &bob_path,
        &SqlCipherKey::new(key.as_secret_str()).unwrap(),
    )
    .unwrap();
    let mut frozen = store.get_group(&group).unwrap();
    frozen.unrecoverable = true;
    store.put_group(&frozen).unwrap();
    drop(store);
    let bob = nostr_device_session(bob_path, &key, b"cancel-bob");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let wall = Arc::new(TestWallClock::new(now));
    let group_endpoint = TransportEndpoint("wss://recovery-group.example".into());
    let inbox = TransportEndpoint("wss://recovery-inbox.example".into());
    let routing = StaticTransportRouting::new(vec![inbox.clone()])
        .key_package_endpoints(vec![inbox.clone()])
        .with_group_route(group.clone(), vec![0x5a; 32], vec![group_endpoint.clone()])
        .with_inbox_route(alice_id.clone(), vec![inbox.clone()])
        .with_inbox_route(bob_id.clone(), vec![inbox.clone()]);
    let adapter = RecordingAdapter::default();
    let bob_adapter = RecordingAdapter::default();
    let coordinator = AccountDeviceRuntime::new(
        alice,
        adapter.clone(),
        routing.clone(),
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );
    let recipient = AccountDeviceRuntime::new(
        bob,
        bob_adapter.clone(),
        routing,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );
    RecoveryPeers {
        _dir: dir,
        coordinator,
        recipient,
        adapter,
        bob_adapter,
        wall,
        group,
        before,
    }
}

async fn exchange_recovery(peers: &mut RecoveryPeers) {
    let RecoveryPeers {
        coordinator,
        recipient,
        adapter,
        bob_adapter,
        wall,
        ..
    } = peers;
    let alice_id = coordinator.self_id();
    let bob_id = recipient.self_id();
    let mut selected = recipient.prepare_group_recovery().unwrap();
    if selected == vec![bob_id.clone()] {
        // This fixture has no healthy sibling. Let the own-account fallback
        // expire normally before the next known-admin turn.
        recipient.advance_group_recovery().await.unwrap();
        wall.set(wall.now().0 + 601);
        coordinator.prepare_group_recovery().unwrap();
        selected = recipient.prepare_group_recovery().unwrap();
    }
    assert_eq!(selected, vec![alice_id.clone()]);
    recipient.advance_group_recovery().await.unwrap();
    let request = bob_adapter.publishes().last().unwrap().message.clone();
    let received = coordinator
        .ingest_delivery(&recovery_inbox_delivery(alice_id.clone(), request))
        .await
        .unwrap();
    assert!(
        matches!(received.outcome, cgka_traits::IngestOutcome::Processed),
        "current device remains eligible after its old leaf position changes"
    );
    coordinator.prepare_group_recovery().unwrap();
    coordinator.advance_group_recovery().await.unwrap();
    let challenge = adapter.publishes().last().unwrap().message.clone();
    recipient
        .ingest_delivery(&recovery_inbox_delivery(bob_id.clone(), challenge))
        .await
        .unwrap();
    recipient.prepare_group_recovery().unwrap();
    recipient.advance_group_recovery().await.unwrap();
    let grant = bob_adapter.publishes().last().unwrap().message.clone();
    coordinator
        .ingest_delivery(&recovery_inbox_delivery(alice_id.clone(), grant))
        .await
        .unwrap();
    coordinator.prepare_group_recovery().unwrap();
}

async fn assert_recovery_cancel(point: RecoveryCancelPoint) {
    let mut peers = recovery_peers().await;
    exchange_recovery(&mut peers).await;
    let RecoveryPeers {
        _dir,
        mut coordinator,
        mut recipient,
        adapter,
        wall,
        group,
        before,
        ..
    } = peers;
    let bob_id = recipient.self_id();
    let now = wall.now().0;
    let group_endpoint = TransportEndpoint("wss://recovery-group.example".into());
    let inbox = TransportEndpoint("wss://recovery-inbox.example".into());
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let endpoint = match point {
        RecoveryCancelPoint::Commit => group_endpoint,
        RecoveryCancelPoint::Welcome => inbox,
    };
    *adapter.inner.endpoint_gate.lock().unwrap() = Some((endpoint, gate));
    let mut publication = Box::pin(coordinator.advance_group_recovery());
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            _ = async {
                while !adapter.publishes().iter().any(|attempt| point.matches_artifact(&attempt.message)) {
                    tokio::task::yield_now().await;
                }
            } => {}
            result = &mut publication => panic!("publication must remain in flight: {result:?}"),
        }
    }).await.unwrap();
    drop(publication);
    let original = adapter
        .publishes()
        .into_iter()
        .find(|attempt| {
            matches!(
                attempt.message.envelope,
                TransportEnvelope::GroupMessage { .. }
            )
        })
        .unwrap()
        .message;
    let interrupted = adapter
        .publishes()
        .into_iter()
        .find(|attempt| point.matches_artifact(&attempt.message))
        .unwrap()
        .message;
    recipient
        .session_mut()
        .ingest(original.clone())
        .await
        .unwrap();
    assert!(recipient.group_record(&group).unwrap().unrecoverable);
    let fanouts = coordinator.outbound_fanouts().unwrap();
    match point {
        RecoveryCancelPoint::Commit => {
            assert!(
                fanouts
                    .iter()
                    .any(|fanout| matches!(fanout.mls_state(), FanoutMlsState::Pending(_)))
            );
            assert!(
                !adapter
                    .publishes()
                    .iter()
                    .any(|attempt| is_recovery_welcome(&attempt.message))
            );
        }
        RecoveryCancelPoint::Welcome => {
            assert!(fanouts.iter().any(|fanout| matches!(
                fanout.mls_state(),
                FanoutMlsState::Confirmed
            )
                && !fanout.pending_post_confirmation_welcomes().is_empty()));
        }
    }

    *adapter.inner.endpoint_gate.lock().unwrap() = None;
    // Authorization may expire after staging; a possibly exposed Commit still
    // owns its exact retry and Welcome on this same live runtime.
    wall.set(now + 1_200);
    coordinator.prepare_group_recovery().unwrap();
    let resumed = coordinator.advance_group_recovery().await.unwrap();
    if matches!(point, RecoveryCancelPoint::Commit) {
        assert!(matches!(
            resumed.pending.as_slice(),
            [PendingResolution::Confirmed { .. }]
        ));
    }
    let attempts = adapter.publishes();
    let retried = attempts
        .iter()
        .filter(|attempt| point.matches_artifact(&attempt.message))
        .collect::<Vec<_>>();
    assert_eq!(retried.len(), 2);
    assert_eq!(retried[1].message, interrupted);
    let welcome = attempts
        .iter()
        .find(|attempt| is_recovery_welcome(&attempt.message))
        .unwrap()
        .message
        .clone();
    recipient
        .ingest_delivery(&recovery_inbox_delivery(bob_id, welcome))
        .await
        .unwrap();
    assert!(!recipient.group_record(&group).unwrap().unrecoverable);
    assert!(recipient.session().epoch(&group).unwrap() > before);
    assert_eq!(
        recipient.session().epoch(&group).unwrap(),
        coordinator.session().epoch(&group).unwrap()
    );
    assert_recovery_chat(&mut coordinator, &adapter, &mut recipient, &group).await;
}

async fn assert_recovery_chat(
    coordinator: &mut RecoveryRuntime,
    adapter: &RecordingAdapter,
    recipient: &mut RecoveryRuntime,
    group: &GroupId,
) {
    let alice_id = coordinator.self_id();
    let payload = app_payload_for(
        &hex::encode(alice_id.as_slice()),
        b"chat after cancelled recovery",
    );
    coordinator
        .send(SendIntent::AppMessage {
            group_id: group.clone(),
            expected_epoch: None,
            payload: payload.clone(),
        })
        .await
        .unwrap();
    let message = adapter.publishes().last().unwrap().message.clone();
    let received = recipient.session_mut().ingest(message).await.unwrap();
    assert!(received.effects.events.iter().any(|event| matches!(event,
        GroupEvent::MessageReceived { group_id, sender, payload: actual, .. }
            if group_id == group && sender == &alice_id && actual == &payload)));
}
