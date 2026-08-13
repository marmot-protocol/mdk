
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

async fn assert_frozen_fanout_case(accept_at: Option<usize>, error_at: &[usize]) {
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
    adapter.error_for_endpoints(
        error_at
            .iter()
            .map(|&index| endpoints[index].clone())
            .collect(),
    );
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
    assert!(effects.fanout[0].fanout_complete);
    assert_eq!(effects.fanout[0].outstanding_targets, 0);
    assert!(
        runtime.session().outbound_fanouts().unwrap().is_empty(),
        "terminal fanouts must be pruned after their outcome is surfaced"
    );

    if accept_at.is_some() {
        assert!(effects.fanout[0].mls_confirmed);
        assert_eq!(effects.fanout[0].accepted_targets, 1);
        assert_eq!(runtime.session().epoch(&group_id).unwrap().0, 2);
        assert!(matches!(
            effects.pending.as_slice(),
            [PendingResolution::Confirmed { .. }]
        ));
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
        assert_frozen_fanout_case(accept_at, &[]).await;
    }
}

#[tokio::test]
async fn frozen_fanout_whole_call_adapter_errors_are_terminal() {
    assert_frozen_fanout_case(None, &[0, 1, 2]).await;
}

/// The production-adapter partial-accept shape: one relay accepts while its
/// siblings surface whole-call `Err`s. The accepted endpoint must stay
/// accepted and confirm pending MLS state — sibling errors must never read as
/// "everything failed".
#[tokio::test]
async fn frozen_fanout_partial_accept_with_sibling_adapter_errors_confirms_mls() {
    assert_frozen_fanout_case(Some(0), &[1, 2]).await;
    assert_frozen_fanout_case(Some(2), &[0, 1]).await;
}

async fn assert_frozen_fanout_restart_edge(send_before_ack_persist: bool) {
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

    let reopened = session(
        &alice_path,
        &SqlCipherKey::new(key_text).unwrap(),
        b"alice-fanout-restart-edge",
    );
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
    let effects = resumed.drain().await.unwrap();

    assert!(effects.fanout[0].mls_confirmed);
    assert!(effects.fanout[0].fanout_complete);
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
    assert_frozen_fanout_restart_edge(false).await;
    assert_frozen_fanout_restart_edge(true).await;
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
