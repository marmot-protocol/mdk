type WithdrawalRuntime =
    AccountDeviceRuntime<RecordingAdapter, StaticTransportRouting, RecordingKeyPackages>;

struct OwedInviteWelcome {
    runtime: WithdrawalRuntime,
    adapter: RecordingAdapter,
    wall: Arc<TestWallClock>,
    group_id: GroupId,
    welcome: TransportMessage,
}

/// Alice invites carol into a confirmed group. The relay accepts the commit
/// but not carol's Welcome, so the Welcome stays owed with a retry record.
async fn owed_invite_welcome(dir: &std::path::Path) -> OwedInviteWelcome {
    let key = SqlCipherKey::new("marmot welcome withdrawal key").unwrap();
    let mut alice = session(dir.join("alice.sqlite"), &key, b"alice-withdrawal");
    let mut bob = session(dir.join("bob.sqlite"), &key, b"bob-withdrawal");
    let mut carol = session(dir.join("carol.sqlite"), &key, b"carol-withdrawal");
    let carol_id = carol.self_id();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "welcome withdrawal".into(),
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

    let adapter = RecordingAdapter::default();
    adapter.accept_next(1);
    adapter.accept_next(0);
    let policy = StaticTransportRouting::new(vec![TransportEndpoint(
        "wss://alice-inbox.example".into(),
    )])
    .with_group_route(
        group_id.clone(),
        group_id.as_slice().to_vec(),
        vec![TransportEndpoint("wss://group.example".into())],
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

    let effects = runtime
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol.fresh_key_package().await.unwrap()],
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    assert!(matches!(
        effects.pending.as_slice(),
        [PendingResolution::Confirmed { .. }]
    ));
    assert_eq!(effects.welcome_failures.len(), 1);
    let welcome = welcome_publishes(&adapter)
        .pop()
        .expect("the first pass tried carol's Welcome");
    assert_eq!(welcome.id, effects.welcome_failures[0].message_id);
    assert!(
        runtime
            .session()
            .transport_fanout(&welcome.id)
            .unwrap()
            .is_some(),
        "the failed Welcome keeps a retry record"
    );
    OwedInviteWelcome {
        runtime,
        adapter,
        wall,
        group_id,
        welcome,
    }
}

fn welcome_publishes(adapter: &RecordingAdapter) -> Vec<TransportMessage> {
    adapter
        .publishes()
        .into_iter()
        .filter(|request| matches!(request.message.envelope, TransportEnvelope::Welcome { .. }))
        .map(|request| request.message)
        .collect()
}

/// mdk#2628 3.5a: a withdrawn Welcome leaves the owed list, and none of the
/// paths that still hold its bytes publishes it: the app's deferred publish,
/// the startup retry, maintenance, or explicit redelivery.
#[tokio::test]
async fn withdrawn_welcome_is_not_published_again() {
    let dir = tempfile::tempdir().unwrap();
    let OwedInviteWelcome {
        mut runtime,
        adapter,
        wall,
        group_id,
        welcome,
    } = owed_invite_welcome(dir.path()).await;
    adapter.accept_only_endpoints(vec![
        TransportEndpoint("wss://group.example".into()),
        TransportEndpoint("wss://carol-inbox.example".into()),
    ]);

    assert_eq!(
        runtime.withdraw_welcome(&welcome.id).unwrap(),
        WelcomeWithdrawal::Withdrawn
    );
    assert_eq!(
        runtime.withdraw_welcome(&welcome.id).unwrap(),
        WelcomeWithdrawal::AlreadyWithdrawn
    );
    assert!(
        runtime
            .session()
            .transport_fanout(&welcome.id)
            .unwrap()
            .is_none(),
        "withdrawal drops the Welcome's retry record"
    );
    // The host's pending list drops a Welcome that is tracked but not owed.
    let index = runtime.welcome_delivery_index().unwrap();
    assert!(index.outstanding.is_empty());
    assert!(index.tracked_ids.contains(&welcome.id));
    let tried = welcome_publishes(&adapter).len();

    let deferred = runtime
        .publish_welcome_messages_with_audit_context(
            vec![welcome.clone()],
            Some(group_id),
            Default::default(),
        )
        .await
        .unwrap();
    assert!(deferred.welcome_failures.is_empty());
    assert!(deferred.failures.is_empty());
    let startup = runtime
        .retry_welcome_messages_with_audit_context(vec![welcome.clone()], Default::default())
        .await
        .unwrap();
    assert!(startup.welcome_failures.is_empty());
    assert!(startup.failures.is_empty());
    let task = runtime
        .prepare_welcome_retry_task_with_audit_context(vec![welcome.clone()], Default::default())
        .unwrap();
    assert!(task.message_ids().is_empty(), "no detached relay attempt");
    wall.set(300_100);
    runtime.run_due_maintenance().await.unwrap();
    assert!(runtime.redeliver_welcome(&welcome.id).await.is_err());

    assert_eq!(welcome_publishes(&adapter).len(), tried);
    assert_eq!(
        runtime.withdraw_welcome(&welcome.id).unwrap(),
        WelcomeWithdrawal::AlreadyWithdrawn,
        "no path marked the withdrawn Welcome delivered"
    );
}

/// A withdrawn Welcome whose retry record survived, as one does while a
/// detached startup publish holds it, is dropped by maintenance unpublished.
#[tokio::test]
async fn maintenance_drops_the_retry_record_of_a_withdrawn_welcome() {
    let dir = tempfile::tempdir().unwrap();
    let OwedInviteWelcome {
        mut runtime,
        adapter,
        wall,
        welcome,
        ..
    } = owed_invite_welcome(dir.path()).await;
    adapter.accept_only_endpoints(vec![
        TransportEndpoint("wss://group.example".into()),
        TransportEndpoint("wss://carol-inbox.example".into()),
    ]);
    // Withdraw the row only, leaving the retry record behind.
    runtime
        .session()
        .withdraw_sent_welcome(&welcome.id)
        .unwrap();
    let tried = welcome_publishes(&adapter).len();

    wall.set(300_100);
    runtime.run_due_maintenance().await.unwrap();

    assert_eq!(welcome_publishes(&adapter).len(), tried);
    assert!(
        runtime
            .session()
            .transport_fanout(&welcome.id)
            .unwrap()
            .is_none()
    );
}

/// A Welcome withdrawn while its Add commit is still unconfirmed is never
/// published, even after the commit confirms on a restart.
#[tokio::test]
async fn withdrawn_staged_welcome_stays_unpublished_after_its_commit_confirms() {
    let dir = tempfile::tempdir().unwrap();
    let alice_path = dir.path().join("alice-staged-withdrawal.sqlite");
    let key_text = "marmot staged withdrawal key";
    let key = SqlCipherKey::new(key_text).unwrap();
    let mut alice = session(&alice_path, &key, b"alice-staged-withdrawal");
    let mut bob = session(
        dir.path().join("bob-staged-withdrawal.sqlite"),
        &key,
        b"bob-staged-withdrawal",
    );
    let mut carol = session(
        dir.path().join("carol-staged-withdrawal.sqlite"),
        &key,
        b"carol-staged-withdrawal",
    );
    let carol_id = carol.self_id();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "staged withdrawal".into(),
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

    let group_endpoint = TransportEndpoint("wss://staged-commit.example".into());
    let inbox_endpoint = TransportEndpoint("wss://staged-welcome.example".into());
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

    let tracked_before = runtime.welcome_delivery_index().unwrap().tracked_ids;
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
    let staged = runtime
        .welcome_delivery_index()
        .unwrap()
        .tracked_ids
        .into_iter()
        .filter(|id| !tracked_before.contains(id))
        .collect::<Vec<_>>();
    let [staged_welcome_id] = staged.as_slice() else {
        panic!("the invite stages exactly one Welcome, got {staged:?}");
    };
    assert_eq!(
        runtime.withdraw_welcome(staged_welcome_id).unwrap(),
        WelcomeWithdrawal::Withdrawn
    );
    drop(runtime);

    adapter.fail_endpoints_as(Vec::new(), TransportEndpointFailureKind::PossiblyExposed);
    adapter.accept_only_endpoints(vec![group_endpoint, inbox_endpoint]);
    let reopened = session(
        &alice_path,
        &SqlCipherKey::new(key_text).unwrap(),
        b"alice-staged-withdrawal",
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
    assert!(recovered.welcome_failures.is_empty());
    assert_eq!(restarted.session().epoch(&group_id).unwrap().0, 2);
    assert!(
        welcome_publishes(&adapter).is_empty(),
        "the withdrawn Welcome is not released when its commit confirms"
    );
    assert!(restarted.outstanding_welcome_deliveries().unwrap().is_empty());
}

/// Withdrawal reports a Welcome that already went out, and refuses an id
/// that is not an outbound Welcome.
#[tokio::test]
async fn withdrawal_reports_a_delivered_welcome_and_refuses_other_messages() {
    let dir = tempfile::tempdir().unwrap();
    let OwedInviteWelcome {
        mut runtime,
        adapter,
        welcome,
        ..
    } = owed_invite_welcome(dir.path()).await;
    adapter.accept_only_endpoints(vec![
        TransportEndpoint("wss://group.example".into()),
        TransportEndpoint("wss://carol-inbox.example".into()),
    ]);
    let redelivered = runtime.redeliver_welcome(&welcome.id).await.unwrap();
    assert!(redelivered.welcome_failures.is_empty());

    assert_eq!(
        runtime.withdraw_welcome(&welcome.id).unwrap(),
        WelcomeWithdrawal::AlreadyDelivered
    );
    let commit_id = adapter
        .publishes()
        .into_iter()
        .find(|request| {
            matches!(
                request.message.envelope,
                TransportEnvelope::GroupMessage { .. }
            )
        })
        .expect("the invite published its commit")
        .message
        .id;
    assert!(runtime.withdraw_welcome(&commit_id).is_err());
}
