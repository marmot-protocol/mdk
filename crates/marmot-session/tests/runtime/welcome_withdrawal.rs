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

/// A Welcome withdrawn after a detached startup retry was prepared, but
/// before the task runs, never reaches the relay.
#[tokio::test]
async fn detached_startup_retry_skips_a_welcome_withdrawn_before_it_runs() {
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
    let tried = welcome_publishes(&adapter).len();
    let task = runtime
        .prepare_welcome_retry_task_with_audit_context(vec![welcome.clone()], Default::default())
        .unwrap();
    assert_eq!(task.message_ids(), std::slice::from_ref(&welcome.id));

    assert_eq!(
        runtime.withdraw_welcome(&welcome.id).unwrap(),
        WelcomeWithdrawal::Withdrawn
    );
    let finished = runtime
        .finish_welcome_publish_task(task.run().await)
        .await
        .unwrap();

    assert!(finished.welcome_failures.is_empty());
    assert!(finished.failures.is_empty());
    assert_eq!(welcome_publishes(&adapter).len(), tried);
    // The task held the retry record; the next maintenance pass drops it.
    wall.set(300_100);
    runtime.run_due_maintenance().await.unwrap();
    assert!(
        runtime
            .session()
            .transport_fanout(&welcome.id)
            .unwrap()
            .is_none()
    );
    assert_eq!(welcome_publishes(&adapter).len(), tried);
}

/// A Welcome withdrawn while a detached startup retry runs is skipped if it
/// is still queued behind the concurrency limit; the started ones finish.
#[tokio::test]
async fn detached_startup_retry_skips_a_queued_welcome_withdrawn_while_it_runs() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot queued withdrawal key").unwrap();
    let mut members = Vec::new();
    let mut policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())]);
    for index in 0..9 {
        let mut recipient = current_session(
            dir.path().join(format!("recipient-{index}.sqlite")),
            &key,
            format!("queued-withdrawal-{index}").as_bytes(),
        );
        members.push(recipient.fresh_key_package().await.unwrap());
        policy = policy.with_inbox_route(
            recipient.self_id(),
            vec![TransportEndpoint(format!("wss://recipient-{index}.example"))],
        );
    }
    let adapter = RecordingAdapter::default();
    let wall = Arc::new(TestWallClock::new(300_000));
    let mut runtime = AccountDeviceRuntime::new(
        current_session(dir.path().join("alice.sqlite"), &key, b"alice-queued"),
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );
    // Created but never published, as after a crash: all nine Welcomes are
    // owed for the startup retry.
    runtime
        .session_mut()
        .create_group(CreateGroupRequest {
            name: "queued withdrawal".into(),
            description: String::new(),
            members,
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let welcomes = runtime
        .outstanding_welcome_deliveries()
        .unwrap()
        .into_iter()
        .map(|(_, welcome)| welcome)
        .collect::<Vec<_>>();
    assert_eq!(welcomes.len(), 9);
    let queued = welcomes[8].id.clone();

    let gate = adapter.gate_welcome_publishes();
    let task = runtime
        .prepare_welcome_retry_task_with_audit_context(welcomes, Default::default())
        .unwrap();
    assert_eq!(task.message_ids().len(), 9);
    let running = tokio::spawn(task.run());
    tokio::time::timeout(Duration::from_secs(5), async {
        while gate.active.load(Ordering::SeqCst) < 8 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("eight Welcome publishes fill the bounded worker set");
    assert_eq!(
        runtime.withdraw_welcome(&queued).unwrap(),
        WelcomeWithdrawal::Withdrawn
    );
    gate.release.add_permits(9);
    let finished = runtime
        .finish_welcome_publish_task(running.await.unwrap())
        .await
        .unwrap();

    let published = welcome_publishes(&adapter);
    assert_eq!(published.len(), 8);
    assert!(published.iter().all(|welcome| welcome.id != queued));
    assert!(finished.welcome_failures.is_empty());
    let outstanding = runtime.outstanding_welcome_deliveries().unwrap();
    assert!(outstanding.is_empty(), "eight delivered, one withdrawn");
    wall.set(300_100);
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(welcome_publishes(&adapter).len(), 8);
    assert!(
        runtime
            .session()
            .transport_fanout(&queued)
            .unwrap()
            .is_none()
    );
}

/// A legacy-profile create's Welcome is the create's own publication on its
/// frozen fanout, which withdrawal could not stop, so it is refused and the
/// Welcome is left as it was.
#[tokio::test]
async fn legacy_create_welcome_cannot_be_withdrawn() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot legacy withdrawal key").unwrap();
    let mut alice = session(dir.path().join("alice.sqlite"), &key, b"alice-legacy");
    let mut bob = session(dir.path().join("bob.sqlite"), &key, b"bob-legacy");
    let created = alice
        .create_group(CreateGroupRequest {
            name: "legacy withdrawal".into(),
            description: String::new(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let welcome_id = match &created.effects.publish[0] {
        PublishWork::GroupCreated { welcomes, .. } => welcomes[0].id.clone(),
        other => panic!("expected GroupCreated publish work, got {other:?}"),
    };
    let runtime = AccountDeviceRuntime::new(
        alice,
        RecordingAdapter::default(),
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())]),
        RecordingKeyPackages::default(),
    );

    assert!(runtime.withdraw_welcome(&welcome_id).is_err());
    assert!(
        !runtime
            .session()
            .sent_welcome_withdrawn(&welcome_id)
            .unwrap()
    );
}

/// Withdrawal needs no hydration: a restart can stop a Welcome before its
/// group is hydrated, and nothing publishes it afterwards, hydrated or not.
#[tokio::test]
async fn welcome_is_withdrawn_before_its_group_is_hydrated() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("marmot unhydrated withdrawal key").unwrap();
    let mut bob = current_session(dir.path().join("bob.sqlite"), &key, b"bob-unhydrated");
    let bob_inbox = TransportEndpoint("wss://bob-inbox.example".into());
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())])
            .with_inbox_route(bob.self_id(), vec![bob_inbox.clone()]);
    let adapter = RecordingAdapter::default();
    adapter.accept_next(0);
    let wall = Arc::new(TestWallClock::new(300_000));
    let open = |session: AccountDeviceSession| {
        AccountDeviceRuntime::new(
            session,
            adapter.clone(),
            policy.clone(),
            RecordingKeyPackages::default(),
        )
        .with_maintenance_sources(
            wall.clone(),
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(0)),
        )
    };
    let mut runtime = open(current_session(&database, &key, b"alice-unhydrated"));
    let (group_id, created) = runtime
        .create_group(CreateGroupRequest {
            name: "unhydrated withdrawal".into(),
            description: String::new(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    assert_eq!(created.welcome_failures.len(), 1);
    let welcome = welcome_publishes(&adapter)
        .pop()
        .expect("creation tried Bob's Welcome");
    drop(runtime);

    adapter.accept_only_endpoints(vec![bob_inbox]);
    let mut runtime = open(deferred_current_session(
        &database,
        &key,
        b"alice-unhydrated",
    ));
    assert_eq!(runtime.session().unhydrated_group_ids(), vec![group_id.clone()]);
    assert_eq!(
        runtime.withdraw_welcome(&welcome.id).unwrap(),
        WelcomeWithdrawal::Withdrawn
    );
    assert!(
        runtime
            .session()
            .transport_fanout(&welcome.id)
            .unwrap()
            .is_none()
    );
    runtime
        .publish_welcome_messages_with_audit_context(
            vec![welcome.clone()],
            Some(group_id.clone()),
            Default::default(),
        )
        .await
        .unwrap();
    runtime
        .retry_welcome_messages_with_audit_context(vec![welcome.clone()], Default::default())
        .await
        .unwrap();
    let task = runtime
        .prepare_welcome_retry_task_with_audit_context(vec![welcome.clone()], Default::default())
        .unwrap();
    assert!(task.message_ids().is_empty(), "no detached relay attempt");
    runtime.resume_outbound_fanouts().await.unwrap();
    wall.set(300_100);
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(welcome_publishes(&adapter).len(), 1);
    assert_eq!(runtime.session().unhydrated_group_ids(), vec![group_id]);
    drop(runtime);

    let mut runtime = open(current_session(&database, &key, b"alice-unhydrated"));
    assert!(runtime.outstanding_welcome_deliveries().unwrap().is_empty());
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(welcome_publishes(&adapter).len(), 1);
}

/// mdk#2628 D40: a device link's Welcome is never published from its delivery
/// deadline on, by any path that still holds its bytes: a detached startup
/// retry prepared before the deadline but run after it, the app's deferred
/// publish, the startup retry, maintenance's watch and fanout retry, and
/// explicit redelivery. Its watch and its retry record are dropped, and
/// nothing reports a delivery failure.
#[tokio::test]
async fn a_link_welcome_is_never_published_from_its_deadline_on() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("marmot link welcome deadline key").unwrap();
    let mut alice = current_session(dir.path().join("alice.sqlite"), &key, b"alice-deadline");
    let mut bob = current_session(dir.path().join("bob.sqlite"), &key, b"bob-deadline");
    let bob_id = bob.self_id();
    let chosen = GroupId::new(vec![0x42; 16]);
    let created = alice
        .create_group_with_chosen_id_and_audit_context(
            CreateGroupRequest {
                name: String::new(),
                description: String::new(),
                members: vec![bob.fresh_key_package().await.unwrap()],
                required_features: Vec::new(),
                app_components: Vec::new(),
                initial_admins: Vec::new(),
            },
            chosen.clone(),
            None,
            Timestamp(300_100),
            Default::default(),
        )
        .await
        .unwrap();
    let welcome = match &created.effects.publish[0] {
        PublishWork::FoundingGroupCreated { welcomes } => welcomes[0].clone(),
        other => panic!("expected FoundingGroupCreated publish work, got {other:?}"),
    };

    let adapter = RecordingAdapter::default();
    adapter.accept_only_endpoints(vec![TransportEndpoint("wss://bob-inbox.example".into())]);
    let policy = StaticTransportRouting::new(vec![TransportEndpoint(
        "wss://alice-inbox.example".into(),
    )])
    .with_group_route(
        chosen.clone(),
        chosen.as_slice().to_vec(),
        vec![TransportEndpoint("wss://group.example".into())],
    )
    .with_inbox_route(
        bob_id,
        vec![TransportEndpoint("wss://bob-inbox.example".into())],
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

    // Prepared before the deadline, the detached retry reserves the Welcome
    // but does not start its attempt once the deadline passes.
    let task = runtime
        .prepare_welcome_retry_task_with_audit_context(vec![welcome.clone()], Default::default())
        .unwrap();
    assert_eq!(task.message_ids(), std::slice::from_ref(&welcome.id));
    wall.set(300_100);
    let finished = runtime
        .finish_welcome_publish_task(task.run().await)
        .await
        .unwrap();
    assert!(finished.welcome_failures.is_empty());
    assert!(finished.failures.is_empty());

    let deferred = runtime
        .publish_welcome_messages_with_audit_context(
            vec![welcome.clone()],
            Some(chosen),
            Default::default(),
        )
        .await
        .unwrap();
    assert!(deferred.welcome_failures.is_empty());
    let startup = runtime
        .retry_welcome_messages_with_audit_context(vec![welcome.clone()], Default::default())
        .await
        .unwrap();
    assert!(startup.welcome_failures.is_empty());
    wall.set(300_200);
    runtime.run_due_maintenance().await.unwrap();
    let redelivered = runtime.redeliver_welcome(&welcome.id).await.unwrap();
    assert!(redelivered.welcome_failures.is_empty());

    assert!(welcome_publishes(&adapter).is_empty());
    assert!(
        runtime
            .session()
            .transport_fanout(&welcome.id)
            .unwrap()
            .is_none(),
        "maintenance drops the expired Welcome's retry record"
    );
}
