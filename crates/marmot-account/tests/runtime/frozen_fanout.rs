
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
            [marmot_account::UnresolvedPublish {
                reason,
                ..
            }] if *reason == match error_kind {
                Some(TransportEndpointFailureKind::RetryableUnavailable) => {
                    marmot_account::UnresolvedPublishReason::RetryableUnavailable
                }
                _ => marmot_account::UnresolvedPublishReason::AcknowledgementUnknown,
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
async fn deferred_fanout_blocks_newer_same_group_fanouts_and_sets_the_retry_cutoff() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot ordered fanout key").unwrap();
    let mut alice = session(dir.path().join("alice.sqlite"), &key, b"alice-ordered-fanout");
    let created = alice
        .create_group(CreateGroupRequest {
            name: "ordered fanout".into(),
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

    let effects = runtime.resume_outbound_fanouts().await.unwrap();

    assert!(effects.reports.is_empty());
    assert!(adapter.publishes().is_empty());
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
    let mut runtime = AccountDeviceRuntime::new(
        alice,
        adapter,
        policy,
        RecordingKeyPackages::default(),
    );
    let payload = app_payload_for(&alice_hex, b"only one semantic message");
    let app_event_id = MarmotAppEvent::decode(&payload).unwrap().id;

    let effects = runtime
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload,
        })
        .await
        .unwrap();

    assert!(effects.failures.is_empty());
    assert!(effects.published_app_messages.is_empty());
    assert_eq!(effects.unresolved_app_messages.len(), 1);
    assert_eq!(effects.unresolved_app_messages[0].group_id, group_id);
    assert_eq!(effects.unresolved_app_messages[0].app_event_id, app_event_id);
    assert_eq!(
        effects.unresolved_app_messages[0].message_id,
        transport_event_id
    );
    assert_eq!(
        effects.unresolved_app_messages[0].reason,
        marmot_account::UnresolvedPublishReason::AcknowledgementUnknown
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
    assert_eq!(attempts.len(), 3, "commit retry must release the frozen Welcome");
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

    // `join_all` polls the per-endpoint publishes in order; the crash lands
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
