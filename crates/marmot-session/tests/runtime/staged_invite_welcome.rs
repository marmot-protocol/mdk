// Welcomes staged with an invite commit wait for it (mdk#2726).

fn staged_welcome_publishes(adapter: &RecordingAdapter) -> Vec<TransportMessage> {
    adapter
        .publishes()
        .into_iter()
        .filter(|request| matches!(request.message.envelope, TransportEnvelope::Welcome { .. }))
        .map(|request| request.message)
        .collect()
}

/// mdk#2726: an invite whose commit the relays leave unresolved keeps its
/// Welcome staged, and the runtime refuses to publish it however it is
/// asked, recording no failure. Once the commit confirms, the same Welcome is
/// owed and goes out.
#[tokio::test]
async fn staged_invite_welcome_waits_for_its_commit() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot staged invite welcome key").unwrap();
    let mut alice = session(dir.path().join("alice.sqlite"), &key, b"alice-staged");
    let mut bob = session(dir.path().join("bob.sqlite"), &key, b"bob-staged");
    let mut carol = session(dir.path().join("carol.sqlite"), &key, b"carol-staged");
    let carol_id = carol.self_id();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "staged invite welcome".into(),
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

    let group_relay = TransportEndpoint("wss://group.example".into());
    let adapter = RecordingAdapter::default();
    let policy = StaticTransportRouting::new(vec![TransportEndpoint(
        "wss://alice-inbox.example".into(),
    )])
    .with_group_route(
        group_id.clone(),
        group_id.as_slice().to_vec(),
        vec![group_relay.clone()],
    )
    .with_inbox_route(
        carol_id,
        vec![TransportEndpoint("wss://carol-inbox.example".into())],
    );
    let wall = Arc::new(TestWallClock::new(300_000));
    let mut runtime = AccountDeviceRuntime::new(
        alice,
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );

    // The app's invite path: stage the commit, take its Welcomes, publish.
    let marmot_session::PreparedSessionSend::Commit(prepared) = runtime
        .confirm_commit_without_publish_with_audit_context(
            SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages: vec![carol.fresh_key_package().await.unwrap()],
                initial_admins: Vec::new(),
            },
            Default::default(),
        )
        .await
        .unwrap()
    else {
        panic!("a ready group stages the invite commit");
    };
    let (effects, welcomes) = prepared.into_effects_and_welcomes();
    assert_eq!(welcomes.len(), 1);
    let welcome_id = welcomes[0].id.clone();
    // The relay may or may not have seen the commit.
    adapter.error_for_endpoints(vec![group_relay]);
    let published = runtime
        .publish_prepared_session_effects_with_audit_context(effects, Default::default())
        .await
        .unwrap();
    assert!(published.failures.is_empty());
    assert!(!published.unresolved_publishes.is_empty(), "commit retained");
    assert!(published.pending.is_empty(), "neither confirmed nor rolled back");

    let held = runtime
        .publish_welcome_messages_with_audit_context(
            welcomes.clone(),
            Some(group_id.clone()),
            Default::default(),
        )
        .await
        .unwrap();
    let retried = runtime
        .retry_welcome_messages_with_audit_context(welcomes.clone(), Default::default())
        .await
        .unwrap();
    let task = runtime
        .prepare_welcome_retry_task_with_audit_context(welcomes.clone(), Default::default())
        .unwrap();
    assert!(task.message_ids().is_empty(), "no detached relay attempt");
    assert!(
        staged_welcome_publishes(&adapter).is_empty(),
        "no Welcome may be published before its Add commit confirms"
    );
    for effects in [&held, &retried] {
        assert!(effects.welcome_failures.is_empty());
        assert!(effects.failures.is_empty());
    }
    assert!(
        runtime
            .session()
            .transport_fanout(&welcome_id)
            .unwrap()
            .is_none(),
        "a held Welcome leaves no retry record"
    );
    let index = runtime.welcome_delivery_index().unwrap();
    assert!(index.outstanding.is_empty());
    assert!(index.tracked_ids.contains(&welcome_id));

    // The commit confirms once its retry is due; the Welcome is promoted
    // and now goes out.
    adapter.error_for_endpoints(Vec::new());
    wall.set(300_100);
    let resumed = runtime.resume_outbound_fanouts().await.unwrap();
    assert!(matches!(
        resumed.pending.as_slice(),
        [PendingResolution::Confirmed { .. }]
    ));
    let owed = runtime.outstanding_welcome_deliveries().unwrap();
    assert_eq!(owed.len(), 1);
    assert_eq!(owed[0].1.id, welcome_id);
    runtime
        .publish_welcome_messages_with_audit_context(
            welcomes,
            Some(group_id),
            Default::default(),
        )
        .await
        .unwrap();
    let sent = staged_welcome_publishes(&adapter);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].id, welcome_id);
    assert!(runtime.outstanding_welcome_deliveries().unwrap().is_empty());
}
