// Detached Welcome waves (mdk#3466). With `set_detached_welcome_waves` on, a
// wave is prepared and reserved for its host instead of being awaited; the
// host runs it, then finishes or abandons it.

/// Alice's group, on a runtime whose Welcome waves are detached. Alice
/// invites carol and dave; once the commit confirms, the confirming pass
/// releases their Welcomes as a wave that waits for its host. The relay
/// takes the commit and carol's Welcome but not dave's. Erin, not yet
/// invited, has an inbox too.
struct DetachedInvite {
    runtime: WithdrawalRuntime,
    adapter: RecordingAdapter,
    policy: StaticTransportRouting,
    wall: Arc<TestWallClock>,
    group_id: GroupId,
    /// What the invite's send returned.
    sent: AccountDeviceEffects,
    erin: AccountDeviceSession,
}

const DETACHED_KEY: &str = "marmot detached wave key";

/// Alice's session, opened from her database in `dir`.
fn alice_session(dir: &std::path::Path) -> AccountDeviceSession {
    let key = SqlCipherKey::new(DETACHED_KEY).unwrap();
    current_session(dir.join("alice.sqlite"), &key, b"alice-detached")
}

/// A runtime over `alice` whose Welcome waves are detached.
fn detached_runtime(
    alice: AccountDeviceSession,
    adapter: &RecordingAdapter,
    policy: &StaticTransportRouting,
    wall: &Arc<TestWallClock>,
) -> WithdrawalRuntime {
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
    runtime.set_detached_welcome_waves(true);
    runtime
}

async fn detached_invite(dir: &std::path::Path) -> DetachedInvite {
    let key = SqlCipherKey::new(DETACHED_KEY).unwrap();
    let mut alice = alice_session(dir);
    let mut carol = current_session(dir.join("carol.sqlite"), &key, b"carol-detached");
    let mut dave = current_session(dir.join("dave.sqlite"), &key, b"dave-detached");
    let erin = current_session(dir.join("erin.sqlite"), &key, b"erin-detached");
    // A founding create with no members is canonical at once.
    let group_id = alice
        .create_group(CreateGroupRequest {
            name: "detached waves".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap()
        .group_id;

    let adapter = RecordingAdapter::default();
    adapter.accept_only_endpoints(vec![
        TransportEndpoint("wss://group.example".into()),
        TransportEndpoint("wss://carol-inbox.example".into()),
    ]);
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())])
            .with_group_route(
                group_id.clone(),
                group_id.as_slice().to_vec(),
                vec![TransportEndpoint("wss://group.example".into())],
            )
            .with_inbox_route(
                carol.self_id(),
                vec![TransportEndpoint("wss://carol-inbox.example".into())],
            )
            .with_inbox_route(
                dave.self_id(),
                vec![TransportEndpoint("wss://dave-inbox.example".into())],
            )
            .with_inbox_route(
                erin.self_id(),
                vec![TransportEndpoint("wss://erin-inbox.example".into())],
            );
    let wall = Arc::new(TestWallClock::new(300_000));
    let mut runtime = detached_runtime(alice, &adapter, &policy, &wall);
    let sent = runtime
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![
                carol.fresh_key_package().await.unwrap(),
                dave.fresh_key_package().await.unwrap(),
            ],
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    assert!(matches!(
        sent.pending.as_slice(),
        [PendingResolution::Confirmed { .. }]
    ));
    DetachedInvite {
        runtime,
        adapter,
        policy,
        wall,
        group_id,
        sent,
        erin,
    }
}

fn the_wave(runtime: &mut WithdrawalRuntime) -> marmot_session::PreparedWelcomePublishTask {
    let mut tasks = runtime.take_prepared_welcome_tasks();
    assert_eq!(tasks.len(), 1, "one wave is prepared");
    tasks.pop().unwrap()
}

/// W1 and W2: the send publishes only its commit and leaves the wave to its
/// host. The host's finish applies the mixed results in input order: carol's
/// Welcome is delivered, and dave's failure names the wave's group. Dave's
/// is retried only after its backoff, as an awaited wave's would be.
#[tokio::test]
async fn a_detached_wave_waits_for_its_host_and_keeps_its_terms() {
    let dir = relaxed_storage_dir().unwrap();
    let DetachedInvite {
        mut runtime,
        adapter,
        group_id,
        sent,
        ..
    } = detached_invite(dir.path()).await;
    assert!(welcome_publishes(&adapter).is_empty());
    assert!(sent.welcome_failures.is_empty());
    let task = the_wave(&mut runtime);
    let ids = task.message_ids().to_vec();
    assert_eq!(ids.len(), 2);

    let finished = runtime
        .finish_welcome_publish_task(task.run().await)
        .await
        .unwrap();
    let reported = finished
        .reports
        .iter()
        .map(|report| report.message_id.clone())
        .filter(|id| ids.contains(id))
        .collect::<Vec<_>>();
    assert_eq!(reported, ids, "results are applied in input order");
    let [failure] = finished.welcome_failures.as_slice() else {
        panic!("only dave's Welcome failed");
    };
    assert_eq!(failure.message_id, ids[1]);
    assert_eq!(failure.group_id.as_ref(), Some(&group_id));
    let owed = runtime.outstanding_welcome_deliveries().unwrap();
    assert_eq!(
        owed.iter().map(|(_, welcome)| welcome.id.clone()).collect::<Vec<_>>(),
        vec![ids[1].clone()]
    );

    let tried = welcome_publishes(&adapter).len();
    runtime.run_due_maintenance().await.unwrap();
    assert!(runtime.take_prepared_welcome_tasks().is_empty());
    assert_eq!(welcome_publishes(&adapter).len(), tried, "no retry before backoff");
}

/// W3: each Welcome has one publisher. A Welcome withdrawn while its wave is
/// reserved is skipped. While the wave's publish is held, maintenance
/// publishes none of its Welcomes, even past their backoff, and an explicit
/// redelivery leaves the Welcome to its wave: it publishes nothing and
/// records no delivery failure, since the Welcome is in flight.
#[tokio::test]
async fn a_reserved_wave_is_its_welcomes_only_publisher() {
    let dir = relaxed_storage_dir().unwrap();
    let DetachedInvite {
        mut runtime,
        adapter,
        wall,
        ..
    } = detached_invite(dir.path()).await;
    let task = the_wave(&mut runtime);
    let [carol, dave] = task.message_ids() else {
        panic!("carol's and dave's Welcomes");
    };
    let (carol, dave) = (carol.clone(), dave.clone());
    assert_eq!(
        runtime.withdraw_welcome(&dave).unwrap(),
        WelcomeWithdrawal::Withdrawn
    );
    let gate = adapter.gate_welcome_publishes();
    let running = tokio::spawn(task.run());
    tokio::time::timeout(Duration::from_secs(5), async {
        while gate.active.load(Ordering::SeqCst) < 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("carol's Welcome reaches the relay");

    wall.set(300_000 + 3_600);
    runtime.run_due_maintenance().await.unwrap();
    assert!(runtime.take_prepared_welcome_tasks().is_empty());
    let redelivered = runtime.redeliver_welcome(&carol).await.unwrap();
    assert!(redelivered.welcome_failures.is_empty());
    assert!(redelivered.reports.is_empty());
    gate.release.add_permits(2);
    let finished = runtime
        .finish_welcome_publish_task(running.await.unwrap())
        .await
        .unwrap();
    assert!(finished.welcome_failures.is_empty());

    let published = welcome_publishes(&adapter);
    assert_eq!(published.iter().filter(|welcome| welcome.id == carol).count(), 1);
    assert!(published.iter().all(|welcome| welcome.id != dave));
    assert!(runtime.outstanding_welcome_deliveries().unwrap().is_empty());
}

/// W4: a wave its host abandons leaves its Welcomes owed, and maintenance
/// sends them: an invite's, released once its commit confirmed; a founding
/// create's; a host's owed Welcome; and the startup retry. Maintenance's
/// own release is in `an_interrupted_maintenance_release_stays_owed`.
#[tokio::test]
async fn an_abandoned_wave_leaves_its_welcomes_owed() {
    let dir = relaxed_storage_dir().unwrap();
    let DetachedInvite {
        mut runtime,
        adapter,
        wall,
        group_id,
        mut erin,
        ..
    } = detached_invite(dir.path()).await;
    let task = the_wave(&mut runtime);
    let invited = task.message_ids().to_vec();
    runtime.abandon_welcome_publish_task(&invited);
    drop(task);

    let created = runtime
        .prepare_create_group_with_audit_context(
            CreateGroupRequest {
                name: "founding wave".into(),
                description: String::new(),
                members: vec![erin.fresh_key_package().await.unwrap()],
                required_features: Vec::new(),
                app_components: Vec::new(),
                initial_admins: Vec::new(),
            },
            Default::default(),
        )
        .await
        .unwrap();
    runtime
        .publish_prepared_session_effects_with_audit_context(created.effects, Default::default())
        .await
        .unwrap();
    let task = the_wave(&mut runtime);
    let founding = task.message_ids().to_vec();
    assert_eq!(founding.len(), 1);
    runtime.abandon_welcome_publish_task(&founding);
    drop(task);

    runtime
        .deliver_owed_welcomes_with_audit_context(&invited[..1], group_id, Default::default())
        .await
        .unwrap();
    let task = the_wave(&mut runtime);
    assert_eq!(task.message_ids(), &invited[..1]);
    runtime.abandon_welcome_publish_task(&invited[..1]);
    drop(task);
    let (retried, task) = runtime
        .prepare_owed_welcome_retry_task_with_audit_context(Default::default())
        .unwrap()
        .expect("the startup retry finds owed Welcomes");
    for id in invited.iter().chain(&founding) {
        assert!(retried.contains(id), "the startup retry takes every owed Welcome");
    }
    runtime.abandon_welcome_publish_task(&retried);
    drop(task);

    let owed = runtime
        .outstanding_welcome_deliveries()
        .unwrap()
        .into_iter()
        .map(|(_, welcome)| welcome.id)
        .collect::<Vec<_>>();
    for id in invited.iter().chain(&founding) {
        assert!(owed.contains(id), "an abandoned Welcome stays owed");
    }

    adapter.accept_only_endpoints(vec![
        TransportEndpoint("wss://group.example".into()),
        TransportEndpoint("wss://carol-inbox.example".into()),
        TransportEndpoint("wss://dave-inbox.example".into()),
        TransportEndpoint("wss://erin-inbox.example".into()),
    ]);
    wall.set(300_000 + 3_600);
    runtime.run_due_maintenance().await.unwrap();
    for task in runtime.take_prepared_welcome_tasks() {
        runtime
            .finish_welcome_publish_task(task.run().await)
            .await
            .unwrap();
    }
    let published = welcome_publishes(&adapter);
    for id in invited.iter().chain(&founding) {
        assert!(
            published.iter().any(|welcome| &welcome.id == id),
            "maintenance sends an abandoned Welcome"
        );
    }
}

/// T3: a run writes none of the inputs whose answers are reused while a
/// write count is unchanged. The owned KeyPackage list's count and the
/// recovery answer's count are as they were once the run returns; only the
/// writer's finish may write the account.
#[tokio::test]
async fn a_wave_run_writes_no_counted_input() {
    let dir = relaxed_storage_dir().unwrap();
    let DetachedInvite { mut runtime, .. } = detached_invite(dir.path()).await;
    let storage = SqliteAccountStorage::open_encrypted(
        dir.path().join("alice.sqlite"),
        &SqlCipherKey::new(DETACHED_KEY).unwrap(),
    )
    .unwrap();
    let counts = || {
        (
            storage.key_package_write_count(),
            storage.recovery_notice_write_count(),
        )
    };
    let task = the_wave(&mut runtime);
    let before = counts();
    let completed = task.run().await;
    assert_eq!(counts(), before);
    runtime.finish_welcome_publish_task(completed).await.unwrap();
}

/// W4 across restarts: a runtime that stops mid-wave leaves every Welcome
/// of that wave owed, whatever the wave's kind, and a later start's startup
/// retry sends each one. The first runtime stops with a confirming pass's
/// released Welcomes and a founding create's in flight; the second with a
/// host's owed Welcome; the third with its own startup retry. Maintenance's
/// release is in `an_interrupted_maintenance_release_stays_owed`.
#[tokio::test]
async fn a_restart_mid_wave_leaves_its_welcomes_owed() {
    let dir = relaxed_storage_dir().unwrap();
    let DetachedInvite {
        mut runtime,
        adapter,
        policy,
        wall,
        group_id,
        mut erin,
        ..
    } = detached_invite(dir.path()).await;
    let invited = the_wave(&mut runtime).message_ids().to_vec();
    let created = runtime
        .prepare_create_group_with_audit_context(
            CreateGroupRequest {
                name: "founding wave".into(),
                description: String::new(),
                members: vec![erin.fresh_key_package().await.unwrap()],
                required_features: Vec::new(),
                app_components: Vec::new(),
                initial_admins: Vec::new(),
            },
            Default::default(),
        )
        .await
        .unwrap();
    runtime
        .publish_prepared_session_effects_with_audit_context(created.effects, Default::default())
        .await
        .unwrap();
    let founding = the_wave(&mut runtime).message_ids().to_vec();
    drop(runtime);
    let every = invited.iter().chain(&founding).cloned().collect::<Vec<_>>();
    let owed = |runtime: &WithdrawalRuntime| {
        let owed = runtime
            .outstanding_welcome_deliveries()
            .unwrap()
            .into_iter()
            .map(|(_, welcome)| welcome.id)
            .collect::<Vec<_>>();
        every.iter().all(|id| owed.contains(id))
    };

    let mut runtime = detached_runtime(alice_session(dir.path()), &adapter, &policy, &wall);
    assert!(owed(&runtime));
    runtime
        .deliver_owed_welcomes_with_audit_context(&invited[..1], group_id, Default::default())
        .await
        .unwrap();
    let host = the_wave(&mut runtime);
    assert_eq!(host.message_ids(), &invited[..1]);
    drop(host);
    drop(runtime);

    let mut runtime = detached_runtime(alice_session(dir.path()), &adapter, &policy, &wall);
    assert!(owed(&runtime));
    let (_, startup) = runtime
        .prepare_owed_welcome_retry_task_with_audit_context(Default::default())
        .unwrap()
        .expect("the startup retry finds owed Welcomes");
    drop(startup);
    drop(runtime);

    adapter.accept_only_endpoints(vec![
        TransportEndpoint("wss://group.example".into()),
        TransportEndpoint("wss://carol-inbox.example".into()),
        TransportEndpoint("wss://dave-inbox.example".into()),
        TransportEndpoint("wss://erin-inbox.example".into()),
    ]);
    let mut runtime = detached_runtime(alice_session(dir.path()), &adapter, &policy, &wall);
    assert!(owed(&runtime));
    let (_, startup) = runtime
        .prepare_owed_welcome_retry_task_with_audit_context(Default::default())
        .unwrap()
        .expect("the startup retry finds owed Welcomes");
    runtime
        .finish_welcome_publish_task(startup.run().await)
        .await
        .unwrap();
    let published = welcome_publishes(&adapter);
    for id in &every {
        assert!(
            published.iter().any(|welcome| &welcome.id == id),
            "the last start sends an interrupted Welcome"
        );
    }
    assert!(runtime.outstanding_welcome_deliveries().unwrap().is_empty());
}

/// W4 for maintenance's watched release. A Welcome whose first publish found
/// no inbox route is owed with no fanout, so once its route resolves,
/// maintenance releases it as a detached wave. Frank's wave is abandoned,
/// and the next pass sends his Welcome. Grace's is left unfinished when the
/// runtime stops, and the next start's maintenance sends hers.
#[tokio::test]
async fn an_interrupted_maintenance_release_stays_owed() {
    let dir = relaxed_storage_dir().unwrap();
    let DetachedInvite {
        mut runtime,
        adapter,
        policy,
        wall,
        ..
    } = detached_invite(dir.path()).await;
    let invite = the_wave(&mut runtime);
    runtime
        .finish_welcome_publish_task(invite.run().await)
        .await
        .unwrap();
    let key = SqlCipherKey::new(DETACHED_KEY).unwrap();
    let mut routed = policy.clone();
    let mut unrouted = Vec::new();
    for name in ["frank", "grace"] {
        let mut member = current_session(
            dir.path().join(format!("{name}.sqlite")),
            &key,
            format!("{name}-detached").as_bytes(),
        );
        routed = routed.with_inbox_route(
            member.self_id(),
            vec![TransportEndpoint(format!("wss://{name}-inbox.example"))],
        );
        let created = runtime
            .prepare_create_group_with_audit_context(
                CreateGroupRequest {
                    name: format!("{name}'s group"),
                    description: String::new(),
                    members: vec![member.fresh_key_package().await.unwrap()],
                    required_features: Vec::new(),
                    app_components: Vec::new(),
                    initial_admins: Vec::new(),
                },
                Default::default(),
            )
            .await
            .unwrap();
        let created_group = created.group_id.clone();
        runtime
            .publish_prepared_session_effects_with_audit_context(
                created.effects,
                Default::default(),
            )
            .await
            .unwrap();
        // Prepare found no route, so nothing runs and no fanout is stored.
        assert!(runtime.take_prepared_welcome_tasks().is_empty());
        let (_, welcome) = runtime
            .outstanding_welcome_deliveries()
            .unwrap()
            .into_iter()
            .find(|(group, _)| *group == created_group)
            .expect("an unrouted Welcome stays owed");
        unrouted.push(welcome.id);
    }
    let [frank, grace]: [MessageId; 2] = unrouted.try_into().unwrap();
    drop(runtime);

    adapter.accept_only_endpoints(vec![
        TransportEndpoint("wss://group.example".into()),
        TransportEndpoint("wss://carol-inbox.example".into()),
        TransportEndpoint("wss://dave-inbox.example".into()),
        TransportEndpoint("wss://frank-inbox.example".into()),
        TransportEndpoint("wss://grace-inbox.example".into()),
    ]);
    let finish_all = async |runtime: &mut WithdrawalRuntime| {
        for task in runtime.take_prepared_welcome_tasks() {
            runtime
                .finish_welcome_publish_task(task.run().await)
                .await
                .unwrap();
        }
    };
    let mut runtime = detached_runtime(alice_session(dir.path()), &adapter, &routed, &wall);
    wall.set(300_000 + 3_600);
    runtime.run_due_maintenance().await.unwrap();
    let mut waves = runtime.take_prepared_welcome_tasks();
    assert_eq!(waves.len(), 2, "maintenance releases each group's Welcome");
    let at = waves
        .iter()
        .position(|wave| wave.message_ids() == std::slice::from_ref(&frank))
        .expect("frank's Welcome is released as a wave of its own");
    let frank_wave = waves.remove(at);
    let grace_wave = waves.pop().unwrap();
    assert_eq!(grace_wave.message_ids(), std::slice::from_ref(&grace));
    runtime.abandon_welcome_publish_task(std::slice::from_ref(&frank));
    drop(frank_wave);
    runtime.run_due_maintenance().await.unwrap();
    finish_all(&mut runtime).await;
    let published = welcome_publishes(&adapter);
    assert!(
        published.iter().any(|welcome| welcome.id == frank),
        "the next pass sends an abandoned maintenance Welcome"
    );
    assert!(
        published.iter().all(|welcome| welcome.id != grace),
        "a held maintenance wave is its Welcome's one publisher"
    );
    drop(grace_wave);
    drop(runtime);

    let mut runtime = detached_runtime(alice_session(dir.path()), &adapter, &routed, &wall);
    assert!(
        runtime
            .outstanding_welcome_deliveries()
            .unwrap()
            .iter()
            .any(|(_, welcome)| welcome.id == grace),
        "an interrupted maintenance Welcome stays owed"
    );
    runtime.run_due_maintenance().await.unwrap();
    finish_all(&mut runtime).await;
    assert!(
        welcome_publishes(&adapter)
            .iter()
            .any(|welcome| welcome.id == grace),
        "the next start sends an interrupted maintenance Welcome"
    );
    assert!(runtime.outstanding_welcome_deliveries().unwrap().is_empty());
}

/// Carol's two inbox relays: one that answers at once, and one that may be
/// held.
const FAST_INBOX: &str = "wss://carol-fast.example";
const SLOW_INBOX: &str = "wss://carol-slow.example";

/// Alice's invite of carol, whose inbox relays are [`FAST_INBOX`] and
/// [`SLOW_INBOX`], on a detached runtime that records its v5 audit at
/// `audit`. The commit is confirmed, and carol's Welcome waits in its wave.
struct TwoInboxInvite {
    runtime: WithdrawalRuntime,
    adapter: RecordingAdapter,
    wall: Arc<TestWallClock>,
    audit: std::path::PathBuf,
}

async fn two_inbox_invite(dir: &std::path::Path) -> TwoInboxInvite {
    let key = SqlCipherKey::new(DETACHED_KEY).unwrap();
    let mut alice =
        current_nostr_welcome_session(dir.join("alice.sqlite"), &key, b"alice-two-inbox");
    let mut carol = current_session(dir.join("carol.sqlite"), &key, b"carol-two-inbox");
    let group_id = alice
        .create_group(CreateGroupRequest {
            name: "two inbox relays".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap()
        .group_id;
    let adapter = RecordingAdapter::default();
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())])
            .with_group_route(
                group_id.clone(),
                group_id.as_slice().to_vec(),
                vec![TransportEndpoint("wss://group.example".into())],
            )
            .with_inbox_route(
                carol.self_id(),
                vec![
                    TransportEndpoint(FAST_INBOX.into()),
                    TransportEndpoint(SLOW_INBOX.into()),
                ],
            );
    let wall = Arc::new(TestWallClock::new(300_000));
    let mut runtime = detached_runtime(alice, &adapter, &policy, &wall);
    let audit = dir.join("two-inbox-audit-v5.jsonl");
    runtime.audit_recorder().swap(v5_audit_recorder(&audit));
    let sent = runtime
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol.fresh_key_package().await.unwrap()],
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    assert!(matches!(
        sent.pending.as_slice(),
        [PendingResolution::Confirmed { .. }]
    ));
    TwoInboxInvite {
        runtime,
        adapter,
        wall,
        audit,
    }
}

/// The state and attempt count of the Welcome's retry record for `endpoint`.
fn inbox_target(
    runtime: &WithdrawalRuntime,
    welcome: &MessageId,
    endpoint: &str,
) -> (cgka_traits::TransportFanoutAttemptState, u32) {
    let fanout = runtime
        .session()
        .transport_fanout(welcome)
        .unwrap()
        .expect("the Welcome keeps its retry record");
    let target = fanout
        .targets
        .iter()
        .find(|target| target.endpoint.0 == endpoint)
        .unwrap();
    (target.state, target.attempt_count)
}

/// The v5 publish rows of `welcome`, in order.
fn publish_rows(audit: &std::path::Path, welcome: &MessageId) -> Vec<serde_json::Value> {
    let outer = marmot_forensics::v5::NostrEventRef::from_validated_event_id(
        &<[u8; 32]>::try_from(welcome.as_slice()).unwrap(),
    );
    v5_audit_rows(audit)
        .into_iter()
        .filter(|row| row["event"]["outer_event_ref"] == outer.as_str())
        .filter(|row| {
            row["event"]["type"]
                .as_str()
                .unwrap()
                .starts_with("welcome_publish_")
        })
        .collect()
}

/// A Welcome reaches every inbox relay of its recipient in its first pass.
/// The transport may answer a request at its acknowledgement goal and leave
/// the other relays unanswered, so a Welcome sent as one request reached
/// only the first relay that took it, and a relay that takes gift wraps it
/// cannot serve back could be that one. Each relay is asked on its own: both
/// accept in one attempt each, and the pass's finished row names both.
#[tokio::test]
async fn a_welcome_reaches_every_inbox_relay_in_its_first_pass() {
    let dir = relaxed_storage_dir().unwrap();
    let TwoInboxInvite {
        mut runtime,
        adapter,
        audit,
        ..
    } = two_inbox_invite(dir.path()).await;
    let task = the_wave(&mut runtime);
    let [welcome] = task.message_ids() else {
        panic!("carol's Welcome");
    };
    let welcome = welcome.clone();
    // The next request answers once one relay has taken it.
    adapter.accept_next(1);

    let finished = runtime
        .finish_welcome_publish_task(task.run().await)
        .await
        .unwrap();

    assert!(finished.welcome_failures.is_empty());
    assert!(runtime.outstanding_welcome_deliveries().unwrap().is_empty());
    for inbox in [FAST_INBOX, SLOW_INBOX] {
        assert_eq!(
            inbox_target(&runtime, &welcome, inbox),
            (cgka_traits::TransportFanoutAttemptState::Accepted, 1),
            "{inbox} took the Welcome in the first pass"
        );
    }
    let rows = publish_rows(&audit, &welcome);
    assert_eq!(rows.len(), 2, "one pass: {rows:?}");
    let finished = &rows[1]["event"];
    assert_eq!(finished["results_complete"], true, "{finished}");
    assert_eq!(finished["accepted_this_attempt_count"], 2, "{finished}");
    assert_eq!(finished["retained_state"], "completed", "{finished}");
}

/// A slow inbox relay does not hold back a Welcome's settlement. The wave
/// returns once the fast relay took the Welcome, and its finish marks the
/// Welcome delivered while the slow relay is still answering. That relay goes
/// on as the wave's remaining pass, whose finish records its acceptance on
/// the same attempt: nothing is left to retry, and the remaining pass has
/// its own started and finished rows.
#[tokio::test]
async fn a_slow_inbox_relay_answers_after_its_welcome_settled() {
    let dir = relaxed_storage_dir().unwrap();
    let TwoInboxInvite {
        mut runtime,
        adapter,
        wall,
        audit,
        ..
    } = two_inbox_invite(dir.path()).await;
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *adapter.inner.endpoint_gate.lock().unwrap() =
        Some((TransportEndpoint(SLOW_INBOX.into()), gate.clone()));
    let task = the_wave(&mut runtime);
    let welcome = task.message_ids()[0].clone();

    let mut completed = tokio::time::timeout(Duration::from_secs(5), task.run())
        .await
        .expect("the wave returns at the fast relay's acceptance");
    let remaining = completed
        .take_remaining()
        .expect("the slow relay is still answering");
    assert_eq!(remaining.message_ids(), std::slice::from_ref(&welcome));
    let finished = runtime.finish_welcome_publish_task(completed).await.unwrap();
    assert!(finished.welcome_failures.is_empty());
    assert!(
        runtime.outstanding_welcome_deliveries().unwrap().is_empty(),
        "the fast relay's acceptance settled the Welcome"
    );
    assert_eq!(
        inbox_target(&runtime, &welcome, SLOW_INBOX).0,
        cgka_traits::TransportFanoutAttemptState::AttemptedFailed,
        "the slow relay has not answered yet"
    );

    gate.add_permits(1);
    runtime
        .finish_welcome_publish_task(remaining.run().await)
        .await
        .unwrap();

    assert_eq!(
        inbox_target(&runtime, &welcome, SLOW_INBOX),
        (cgka_traits::TransportFanoutAttemptState::Accepted, 1),
        "its late acceptance ends the first attempt"
    );
    let tried = welcome_publishes(&adapter).len();
    wall.set(300_000 + 3_600);
    runtime.run_due_maintenance().await.unwrap();
    assert!(runtime.take_prepared_welcome_tasks().is_empty());
    assert_eq!(welcome_publishes(&adapter).len(), tried, "nothing is retried");

    let rows = publish_rows(&audit, &welcome);
    let kinds = rows
        .iter()
        .map(|row| row["event"]["type"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        [
            "welcome_publish_started",
            "welcome_publish_started",
            "welcome_publish_finished",
            "welcome_publish_finished"
        ]
    );
    let (first, rest) = (&rows[0]["event"], &rows[1]["event"]);
    assert_eq!(first["target_count"], 2, "{first}");
    assert_eq!(rest["target_count"], 1, "{rest}");
    assert_eq!(rest["accepted_before_count"], 1, "{rest}");
    assert_eq!(rest["route_source"], "retained_target", "{rest}");
    assert_ne!(first["attempt_id"], rest["attempt_id"]);
    let first_finished = &rows[2]["event"];
    assert_eq!(first_finished["attempt_id"], first["attempt_id"]);
    assert_eq!(first_finished["results_complete"], false, "{first_finished}");
    assert_eq!(first_finished["policy"], "met", "{first_finished}");
    let rest_finished = &rows[3]["event"];
    assert_eq!(rest_finished["attempt_id"], rest["attempt_id"]);
    assert_eq!(rest_finished["results_complete"], true, "{rest_finished}");
    assert_eq!(rest_finished["accepted_total_count"], 2, "{rest_finished}");
    assert_eq!(rest_finished["retained_state"], "completed", "{rest_finished}");
}

/// A remaining pass cut short, as when its worker stops, keeps what the
/// first pass settled: the Welcome stays delivered and the fast relay's
/// acceptance stays stored. The slow relay is retried after its backoff, as
/// a relay the first pass did not hear from always was.
#[tokio::test]
async fn a_remaining_pass_cut_short_keeps_the_settled_acceptance() {
    let dir = relaxed_storage_dir().unwrap();
    let TwoInboxInvite {
        mut runtime,
        adapter,
        wall,
        ..
    } = two_inbox_invite(dir.path()).await;
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *adapter.inner.endpoint_gate.lock().unwrap() =
        Some((TransportEndpoint(SLOW_INBOX.into()), gate.clone()));
    let task = the_wave(&mut runtime);
    let welcome = task.message_ids()[0].clone();
    let mut completed = tokio::time::timeout(Duration::from_secs(5), task.run())
        .await
        .expect("the wave returns at the fast relay's acceptance");
    let remaining = completed.take_remaining().unwrap();
    runtime.finish_welcome_publish_task(completed).await.unwrap();

    runtime.abandon_welcome_publish_task(remaining.message_ids());
    drop(remaining);

    assert!(runtime.outstanding_welcome_deliveries().unwrap().is_empty());
    assert_eq!(
        runtime.withdraw_welcome(&welcome).unwrap(),
        WelcomeWithdrawal::AlreadyDelivered
    );
    assert_eq!(
        inbox_target(&runtime, &welcome, FAST_INBOX).0,
        cgka_traits::TransportFanoutAttemptState::Accepted
    );
    *adapter.inner.endpoint_gate.lock().unwrap() = None;
    let tried = welcome_publishes(&adapter).len();
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(welcome_publishes(&adapter).len(), tried, "no retry before backoff");
    wall.set(300_000 + 31);
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(
        inbox_target(&runtime, &welcome, SLOW_INBOX),
        (cgka_traits::TransportFanoutAttemptState::Accepted, 2),
        "maintenance retries the slow relay"
    );
}

/// A late acceptance after the first pass's record could not be saved
/// counts and dates the attempt it ends: the stored record never shows an
/// accepted relay with no attempt.
#[tokio::test]
async fn a_late_acceptance_after_a_failed_first_record_counts_its_attempt() {
    let dir = relaxed_storage_dir().unwrap();
    let TwoInboxInvite {
        mut runtime,
        adapter,
        ..
    } = two_inbox_invite(dir.path()).await;
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *adapter.inner.endpoint_gate.lock().unwrap() =
        Some((TransportEndpoint(SLOW_INBOX.into()), gate.clone()));
    let task = the_wave(&mut runtime);
    let welcome = task.message_ids()[0].clone();
    let mut completed = tokio::time::timeout(Duration::from_secs(5), task.run())
        .await
        .expect("the wave returns at the fast relay's acceptance");
    let remaining = completed.take_remaining().unwrap();
    runtime.arm_finish_stage_failure(welcome.clone());
    assert!(
        runtime.finish_welcome_publish_task(completed).await.is_err(),
        "the first pass's record is not saved"
    );
    // Only another message's record fails from here.
    runtime.arm_finish_stage_failure(MessageId::new(vec![0; 32]));

    gate.add_permits(1);
    runtime
        .finish_welcome_publish_task(remaining.run().await)
        .await
        .unwrap();

    assert_eq!(
        inbox_target(&runtime, &welcome, SLOW_INBOX),
        (cgka_traits::TransportFanoutAttemptState::Accepted, 1)
    );
}
