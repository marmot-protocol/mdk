// A pass records `Attempting` before its bytes leave. If the process dies
// after the send and before the result is recorded, the relay may hold the
// commit and forward it to peers. After restart, the exact retry can draw a
// definite refusal that speaks only for the retry: strfry checks size and
// `created_at` age before its duplicate lookup. The pending commit must stay
// possibly exposed rather than roll back (mdk#1577, mdk#2332).
#[tokio::test]
async fn interrupted_commit_attempt_stays_possibly_exposed_after_restart() {
    let dir = relaxed_storage_dir().unwrap();
    let alice_path = dir.path().join("alice-interrupted.sqlite");
    let key_text = "marmot interrupted attempt key";
    let key = SqlCipherKey::new(key_text).unwrap();
    let mut alice = session(&alice_path, &key, b"alice-interrupted");
    let mut bob = session(
        dir.path().join("bob-interrupted.sqlite"),
        &key,
        b"bob-interrupted",
    );
    let created = alice
        .create_group(CreateGroupRequest {
            name: "interrupted attempt".into(),
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

    let relay = TransportEndpoint("wss://interrupted-attempt.example".into());
    let adapter = RecordingAdapter::default();
    *adapter.inner.endpoint_gate.lock().unwrap() =
        Some((relay.clone(), Arc::new(tokio::sync::Semaphore::new(0))));
    let policy = StaticTransportRouting::new(vec![TransportEndpoint(
        "wss://interrupted-attempt-inbox.example".into(),
    )])
    .with_group_route(
        group_id.clone(),
        group_id.as_slice().to_vec(),
        vec![relay.clone()],
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

    // The relay holds the attempt open; the process dies while it is in flight.
    let mut send = Box::pin(runtime.send(SendIntent::UpdateGroupData {
        group_id: group_id.clone(),
        name: Some("interrupted".into()),
        description: None,
    }));
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            _ = async {
                while adapter.publishes().is_empty() {
                    tokio::task::yield_now().await;
                }
            } => {}
            result = &mut send => panic!("the attempt must remain in flight: {result:?}"),
        }
    })
    .await
    .unwrap();
    drop(send);
    drop(runtime);
    let sent = adapter.publishes()[0].message.clone();

    // The relay stored and forwarded the bytes before the process died, and
    // a peer applied them. Rolling the sender back would split the group.
    bob.ingest(sent.clone()).await.unwrap();
    let convergence_delay = bob
        .prepare_convergence_cutoff_delay_ms(&group_id)
        .unwrap()
        .expect("buffered commit must open a convergence pass");
    tokio::time::sleep(Duration::from_millis(convergence_delay.saturating_add(1))).await;
    bob.advance_convergence(&group_id).await.unwrap();
    assert_eq!(bob.epoch(&group_id).unwrap().0, 2);

    // After restart the relay refuses the exact retry with a final answer.
    *adapter.inner.endpoint_gate.lock().unwrap() = None;
    adapter.fail_endpoints_as(
        vec![relay.clone()],
        TransportEndpointFailureKind::TerminalRejected,
    );
    let reopened = session(
        &alice_path,
        &SqlCipherKey::new(key_text).unwrap(),
        b"alice-interrupted",
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
    let stored = restarted.session().outbound_fanouts().unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored[0].target_status(0),
        Some(FanoutTargetStatus::Attempting)
    );
    assert!(
        stored[0].possible_exposure(),
        "an unfinished attempt may have reached the relay"
    );

    let refused = restarted.resume_outbound_fanouts().await.unwrap();
    assert!(
        refused.pending.is_empty(),
        "a refusal of the retry must not resolve the commit: {:?}",
        refused.pending
    );
    let fanouts = restarted.session().outbound_fanouts().unwrap();
    assert_eq!(fanouts.len(), 1);
    assert_eq!(
        fanouts[0].target_status(0),
        Some(FanoutTargetStatus::PossiblyExposed)
    );
    assert!(matches!(fanouts[0].mls_state(), FanoutMlsState::Pending(_)));
    let attempts = adapter.publishes();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[1].message.id, sent.id);
    assert_eq!(attempts[1].message.payload, sent.payload);

    // The relay that holds the commit later acknowledges the exact retry, and
    // the sender joins the peer at the commit's epoch.
    adapter.error_for_endpoints(Vec::new());
    wall.set(100_000 + 2 * 60);
    let recovered = restarted.resume_outbound_fanouts().await.unwrap();
    assert!(matches!(
        recovered.pending.as_slice(),
        [PendingResolution::Confirmed { .. }]
    ));
    assert_eq!(restarted.session().epoch(&group_id).unwrap().0, 2);
    assert!(restarted.session().outbound_fanouts().unwrap().is_empty());
}
