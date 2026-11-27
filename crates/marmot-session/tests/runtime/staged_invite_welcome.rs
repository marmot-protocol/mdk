// Welcomes staged with an invite commit wait for it (mdk#2726).

fn staged_welcome_publishes(adapter: &RecordingAdapter) -> Vec<TransportMessage> {
    adapter
        .publishes()
        .into_iter()
        .filter(|request| matches!(request.message.envelope, TransportEnvelope::Welcome { .. }))
        .map(|request| request.message)
        .collect()
}

type StagedInviteRuntime =
    AccountDeviceRuntime<RecordingAdapter, SharedRouting, RecordingKeyPackages>;

/// An invite of Carol made the app's way (stage the commit, take its
/// Welcome, publish), whose commit the relay may or may not have seen, so it
/// is retained with its Welcome still staged.
struct RetainedInvite {
    runtime: StagedInviteRuntime,
    adapter: RecordingAdapter,
    policy: SharedRouting,
    wall: Arc<TestWallClock>,
    group_id: GroupId,
    group_relay: TransportEndpoint,
    carol_id: MemberId,
    carol_inbox: TransportEndpoint,
    welcome: TransportMessage,
}

const STAGED_INVITE_KEY: &str = "marmot staged invite welcome key";
const STAGED_INVITE_ALICE: &[u8] = b"alice-staged";

async fn retained_invite(dir: &std::path::Path) -> RetainedInvite {
    retained_invite_failing(dir, |adapter, group_relay| {
        adapter.error_for_endpoints(vec![group_relay]);
    })
    .await
}

/// [`retained_invite`], with the group relay failing the commit as `fail`
/// sets up.
async fn retained_invite_failing(
    dir: &std::path::Path,
    fail: impl FnOnce(&RecordingAdapter, TransportEndpoint),
) -> RetainedInvite {
    let key = SqlCipherKey::new(STAGED_INVITE_KEY).unwrap();
    let mut alice = session(dir.join("alice.sqlite"), &key, STAGED_INVITE_ALICE);
    let mut bob = session(dir.join("bob.sqlite"), &key, b"bob-staged");
    let mut carol = session(dir.join("carol.sqlite"), &key, b"carol-staged");
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
    let carol_inbox = TransportEndpoint("wss://carol-inbox.example".into());
    let adapter = RecordingAdapter::default();
    let policy = SharedRouting(Arc::new(Mutex::new(
        staged_invite_routing(&group_id, &group_relay)
            .with_inbox_route(carol_id.clone(), vec![carol_inbox.clone()]),
    )));
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
    // A running app's runtime has read the store before it stages an invite.
    runtime.run_due_maintenance().await.unwrap();

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
    let (effects, mut welcomes) = prepared.into_effects_and_welcomes();
    assert_eq!(welcomes.len(), 1);
    fail(&adapter, group_relay.clone());
    let published = runtime
        .publish_prepared_session_effects_with_audit_context(effects, Default::default())
        .await
        .unwrap();
    assert!(published.failures.is_empty());
    assert!(!published.unresolved_publishes.is_empty(), "commit retained");
    assert!(published.pending.is_empty(), "neither confirmed nor rolled back");
    RetainedInvite {
        runtime,
        adapter,
        policy,
        wall,
        group_id,
        group_relay,
        carol_id,
        carol_inbox,
        welcome: welcomes.pop().unwrap(),
    }
}

/// Alice's routing for the invite's group, with no inbox routes.
fn staged_invite_routing(
    group_id: &GroupId,
    group_relay: &TransportEndpoint,
) -> StaticTransportRouting {
    StaticTransportRouting::new(vec![TransportEndpoint(
        "wss://alice-inbox.example".into(),
    )])
    .with_group_route(
        group_id.clone(),
        group_id.as_slice().to_vec(),
        vec![group_relay.clone()],
    )
}

impl RetainedInvite {
    /// Give Carol's inbox a route again, or take it away.
    fn route_carol(&self, routed: bool) {
        let routing = staged_invite_routing(&self.group_id, &self.group_relay);
        let routing = if routed {
            routing.with_inbox_route(self.carol_id.clone(), vec![self.carol_inbox.clone()])
        } else {
            routing
        };
        self.policy.update(|_| routing);
    }

    /// Let the relay take the retained commit once its retry is due, which
    /// confirms it and promotes its Welcome.
    async fn confirm_commit(&mut self) {
        self.adapter.error_for_endpoints(Vec::new());
        self.adapter
            .fail_endpoints_as(Vec::new(), TransportEndpointFailureKind::PossiblyExposed);
        self.wall.set(300_100);
        let resumed = self.runtime.resume_outbound_fanouts().await.unwrap();
        assert!(matches!(
            resumed.pending.as_slice(),
            [PendingResolution::Confirmed { .. }]
        ));
    }

    /// Stop the runtime and open it again over the same store, as an app
    /// restart does.
    fn restart(&mut self, dir: &std::path::Path) {
        self.reopen(dir, SessionConfig::legacy_compatibility_profile, Arc::new(MockSealer));
    }

    /// [`Self::restart`], leaving the group unhydrated.
    fn restart_unhydrated(&mut self, dir: &std::path::Path) {
        self.reopen(
            dir,
            |config| config.legacy_compatibility_profile().defer_group_hydration(),
            Arc::new(MockSealer),
        );
    }

    fn reopen(
        &mut self,
        dir: &std::path::Path,
        configure: impl FnOnce(SessionConfig) -> SessionConfig,
        sealer: Arc<dyn InboxSealer>,
    ) {
        let restarted = reopen_staged_invite_runtime(
            dir, configure, sealer, self.adapter.clone(), self.policy.clone(), self.wall.clone(),
        );
        drop(std::mem::replace(&mut self.runtime, restarted));
    }
}

fn reopen_staged_invite_runtime(
    dir: &std::path::Path,
    configure: impl FnOnce(SessionConfig) -> SessionConfig,
    sealer: Arc<dyn InboxSealer>,
    adapter: RecordingAdapter,
    routing: SharedRouting,
    wall: Arc<TestWallClock>,
) -> StagedInviteRuntime {
    let config = mock_session_config(
        dir.join("alice.sqlite"),
        &SqlCipherKey::new(STAGED_INVITE_KEY).unwrap(),
        STAGED_INVITE_ALICE,
        sealer,
    );
    AccountDeviceRuntime::new(
        AccountDeviceSession::open(configure(config)).unwrap(),
        adapter,
        routing,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall,
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    )
}

#[tokio::test]
async fn founding_welcome_unsealed_at_stop_is_delivered_after_restart() {
    retry_founding_after_restart(FoundingRestart::BeforeDeadline).await;
}

#[tokio::test]
async fn expired_founding_skips_signer() {
    retry_founding_after_restart(FoundingRestart::AtDeadline).await;
}

#[derive(Clone, Copy)]
enum FoundingRestart {
    BeforeDeadline,
    AtDeadline,
}

async fn retry_founding_after_restart(restart: FoundingRestart) {
    let dir = relaxed_storage_dir().unwrap();
    let key = SqlCipherKey::new(STAGED_INVITE_KEY).unwrap();
    let mut bob = current_session(dir.path().join("bob.sqlite"), &key, b"founding-bob");
    let bob_id = bob.self_id();
    let bob_inbox = TransportEndpoint("wss://bob-inbox.example".into());
    let group_relay = TransportEndpoint("wss://group.example".into());
    let adapter = RecordingAdapter::default();
    let routing = SharedRouting(Arc::new(Mutex::new(
        StaticTransportRouting::new(vec![])
            .with_inbox_route(bob_id.clone(), vec![bob_inbox.clone()]),
    )));
    let now = unix_now();
    let wall = Arc::new(TestWallClock::new(now));
    let sealer = Arc::new(FirstRecipientRefusingSealer::default());
    let mut runtime = reopen_staged_invite_runtime(
        dir.path(),
        |config| config.maintenance_sources(wall.clone(), Arc::new(TestRandom::new(0))),
        sealer.clone(),
        adapter.clone(),
        routing.clone(),
        wall.clone(),
    );
    let (group, _) = runtime
        .create_group(CreateGroupRequest {
            name: "founding Welcome retry".into(),
            description: String::new(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    assert!(staged_welcome_publishes(&adapter).is_empty());
    let unsealed = runtime.session().unsealed_owed_welcomes().unwrap();
    let [welcome] = unsealed.as_slice() else { panic!("expected one unsealed founding Welcome") };
    let local_id = welcome.local_id.clone();
    assert_eq!(sealer.attempts.load(Ordering::SeqCst), 1);
    drop(runtime);

    routing.update(|_| {
        staged_invite_routing(&group, &group_relay)
            .with_inbox_route(bob_id.clone(), vec![bob_inbox.clone()])
    });
    if matches!(restart, FoundingRestart::AtDeadline) {
        wall.set(now + 7 * 24 * 60 * 60);
    }
    sealer.allow_all.store(true, Ordering::SeqCst);
    let mut runtime = reopen_staged_invite_runtime(
        dir.path(),
        std::convert::identity,
        sealer.clone(),
        adapter.clone(),
        routing,
        wall.clone(),
    );
    runtime.run_due_maintenance().await.unwrap();
    if matches!(restart, FoundingRestart::AtDeadline) {
        assert_eq!(sealer.attempts.load(Ordering::SeqCst), 1);
        assert!(staged_welcome_publishes(&adapter).is_empty());
        assert_eq!(runtime.session().stored_message_state(&local_id).unwrap(), Some(cgka_traits::MessageState::Failed));
        assert!(runtime.session().outbound_welcome_audit_facts(&local_id).unwrap().is_none());

        wall.set(now);
        runtime.run_due_maintenance().await.unwrap();
        assert_eq!(sealer.attempts.load(Ordering::SeqCst), 1);
        assert!(staged_welcome_publishes(&adapter).is_empty());
        assert_eq!(
            runtime.session().expire_sent_welcome(&local_id, Timestamp(now)).unwrap(),
            Some(cgka_traits::message::WelcomeExpiry::Recorded),
            "the local row stays expired even before the deadline"
        );
        return;
    }
    assert_eq!(sealer.attempts.load(Ordering::SeqCst), 2);
    let publishes = adapter.publishes();
    let welcomes = publishes.iter().filter(|request| {
        matches!(request.message.envelope, TransportEnvelope::Welcome { .. })
    }).collect::<Vec<_>>();
    let [published] = welcomes.as_slice() else {
        panic!("maintenance must publish exactly one founding Welcome, got {}", welcomes.len());
    };
    assert_eq!(published.target.endpoints(), &[bob_inbox]);
    assert_eq!(published.message.envelope, TransportEnvelope::Welcome { recipient: bob_id.clone() });
    let outcomes = runtime.welcome_delivery_outcomes(Some(&group), Some(&bob_id)).unwrap();
    let [outcome] = outcomes.as_slice() else { panic!("expected one founding invite") };
    let [outcome] = outcome.as_slice() else { panic!("expected one founding Welcome") };
    assert_eq!(outcome.record.welcome_id, published.message.id);
    assert_eq!(outcome.state, cgka_traits::maintenance::WelcomeDeliveryState::RelayAccepted);
    assert_eq!(
        runtime.session().stored_message_state(&published.message.id).unwrap(),
        Some(cgka_traits::MessageState::Processed),
    );
    let joined = bob.ingest(published.message.clone()).await.unwrap();
    assert_eq!(joined.outcome, cgka_traits::IngestOutcome::Processed);
    assert!(joined.effects.events.iter().any(|event| matches!(
        event, GroupEvent::GroupJoined { group_id, .. } if group_id == &group
    )));
}

/// Refuses Welcomes to the first recipient until `allow_all` is set.
#[derive(Default)]
struct FirstRecipientRefusingSealer {
    refused: Mutex<Option<MemberId>>,
    attempts: AtomicUsize,
    allow_all: AtomicBool,
}

#[async_trait]
impl InboxSealer for FirstRecipientRefusingSealer {
    async fn unseal(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        MockSealer.unseal(msg).await
    }

    async fn seal_welcome(
        &self,
        welcome: &OutboundWelcome,
    ) -> Result<TransportMessage, PeelerError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let refused = self
            .refused
            .lock()
            .unwrap()
            .get_or_insert_with(|| welcome.recipient.clone())
            .clone();
        if refused == welcome.recipient && !self.allow_all.load(Ordering::SeqCst) {
            return Err(PeelerError::MissingContext {
                label: "welcome_metadata".into(),
            });
        }
        MockSealer.seal_welcome(welcome).await
    }

    async fn seal_group_recovery(
        &self,
        message: &cgka_traits::GroupRecoveryMessage,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        MockSealer.seal_group_recovery(message, recipient).await
    }

    fn sealed_welcome_len(&self, welcome: &OutboundWelcome) -> usize {
        MockSealer.sealed_welcome_len(welcome)
    }
}

/// Maintenance seals and sends every founding Welcome it can: one that never
/// seals, whichever row maintenance reads first, stays owed and holds back no
/// other recipient's.
#[tokio::test]
async fn an_unsealable_founding_welcome_holds_back_no_other() {
    let dir = relaxed_storage_dir().unwrap();
    let key = SqlCipherKey::new(STAGED_INVITE_KEY).unwrap();
    let mut bob = current_session(dir.path().join("bob.sqlite"), &key, b"founding-bob-2");
    let mut carol = current_session(dir.path().join("carol.sqlite"), &key, b"founding-carol-2");
    let (bob_id, carol_id) = (bob.self_id(), carol.self_id());
    let bob_inbox = TransportEndpoint("wss://bob-inbox.example".into());
    let carol_inbox = TransportEndpoint("wss://carol-inbox.example".into());
    let group_relay = TransportEndpoint("wss://group.example".into());
    let inboxes = |routing: StaticTransportRouting| {
        routing
            .with_inbox_route(bob_id.clone(), vec![bob_inbox.clone()])
            .with_inbox_route(carol_id.clone(), vec![carol_inbox.clone()])
    };
    let adapter = RecordingAdapter::default();
    let routing = SharedRouting(Arc::new(Mutex::new(inboxes(StaticTransportRouting::new(
        vec![],
    )))));
    let wall = Arc::new(TestWallClock::new(unix_now()));
    let refusing = SwitchableSealer::default();
    refusing.fail.store(true, Ordering::SeqCst);
    let mut runtime = reopen_staged_invite_runtime(
        dir.path(),
        std::convert::identity,
        Arc::new(refusing),
        adapter.clone(),
        routing.clone(),
        wall.clone(),
    );
    let (group, _) = runtime
        .create_group(CreateGroupRequest {
            name: "one unsealable founding Welcome".into(),
            description: String::new(),
            members: vec![
                bob.fresh_key_package().await.unwrap(),
                carol.fresh_key_package().await.unwrap(),
            ],
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    assert_eq!(runtime.session().unsealed_owed_welcomes().unwrap().len(), 2);
    drop(runtime);

    routing.update(|_| inboxes(staged_invite_routing(&group, &group_relay)));
    let mut runtime = reopen_staged_invite_runtime(
        dir.path(),
        std::convert::identity,
        Arc::new(FirstRecipientRefusingSealer::default()),
        adapter.clone(),
        routing,
        wall,
    );
    runtime.run_due_maintenance().await.unwrap();
    let publishes = staged_welcome_publishes(&adapter);
    let [published] = publishes.as_slice() else {
        panic!("maintenance must publish the one sealable founding Welcome");
    };
    let TransportEnvelope::Welcome { recipient } = &published.envelope else {
        unreachable!("a Welcome publish")
    };
    let unsealed = runtime.session().unsealed_owed_welcomes().unwrap();
    let [still_owed] = unsealed.as_slice() else {
        panic!("the unsealable founding Welcome stays owed");
    };
    assert_ne!(&still_owed.recipient, recipient);
    let joiner = if *recipient == bob_id { &mut bob } else { &mut carol };
    let joined = joiner.ingest(published.clone()).await.unwrap();
    assert_eq!(joined.outcome, cgka_traits::IngestOutcome::Processed);
}

#[tokio::test]
async fn prepared_send_preserves_a_durably_queued_invite() {
    let dir = relaxed_storage_dir().unwrap();
    let key = SqlCipherKey::new(STAGED_INVITE_KEY).unwrap();
    let mut alice = current_session(dir.path().join("alice.sqlite"), &key, b"queued-alice");
    let mut bob = current_session(dir.path().join("bob.sqlite"), &key, b"queued-bob");
    let mut carol = current_session(dir.path().join("carol.sqlite"), &key, b"queued-carol");
    let bob_id = bob.self_id();
    let created = alice
        .create_group(CreateGroupRequest {
            name: "queued prepared invite".into(),
            description: String::new(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: vec![bob_id],
        })
        .await
        .unwrap();
    let group = created.group_id;
    let [PublishWork::FoundingGroupCreated { welcomes }] = created.effects.publish.as_slice() else {
        panic!("expected a founding Welcome");
    };
    let joined = bob.ingest(welcomes[0].clone()).await.unwrap();
    assert_eq!(joined.outcome, cgka_traits::IngestOutcome::Processed);

    let effects = alice.send(SendIntent::SelfUpdate { group_id: group.clone() }).await.unwrap();
    let [PublishWork::GroupEvolution { msg, pending, .. }] = effects.publish.as_slice() else {
        panic!("expected a self-update commit");
    };
    alice.confirm_published(*pending).await.unwrap();
    let mut commit = msg.clone();
    commit.envelope = TransportEnvelope::GroupMessage {
        transport_group_id: group.as_slice().to_vec(),
    };
    bob.set_convergence_policy(cgka_engine::canonicalization::CanonicalizationPolicy {
        settlement_quiescence_ms: 3_600_000,
        ..Default::default()
    }).unwrap();
    assert!(matches!(bob.ingest(commit).await.unwrap().outcome, cgka_traits::IngestOutcome::Buffered { .. }));

    let adapter = RecordingAdapter::default();
    let mut runtime = AccountDeviceRuntime::new(
        bob,
        adapter.clone(),
        staged_invite_routing(&group, &TransportEndpoint("wss://group.example".into())),
        RecordingKeyPackages::default(),
    );
    let prepared = runtime.confirm_commit_without_publish_with_audit_context(
        SendIntent::Invite {
            group_id: group.clone(),
            key_packages: vec![carol.fresh_key_package().await.unwrap()],
            initial_admins: Vec::new(),
        },
        Default::default(),
    ).await.unwrap();
    let marmot_session::PreparedSessionSend::Queued(effects) = prepared else {
        panic!("queued invite must not pretend to be staged");
    };
    let [queued] = effects.queued.as_slice() else { panic!("expected one queued invite") };
    assert_eq!(queued.group_id, group);
    assert!(runtime.session().is_queued_outbound_intent(queued).unwrap());
    assert_eq!(effects.pending_convergence, [group]);
    assert!(effects.publish.is_empty());
    assert!(adapter.publishes().is_empty());
}

/// mdk#2726: an invite whose commit the relays leave unresolved keeps its
/// Welcome staged, and the runtime refuses to publish it however it is
/// asked, recording no failure. Once the commit confirms, the same Welcome is
/// owed and goes out.
#[tokio::test]
async fn staged_invite_welcome_waits_for_its_commit() {
    let dir = relaxed_storage_dir().unwrap();
    let mut invite = retained_invite(dir.path()).await;
    let runtime = &mut invite.runtime;
    let welcome = invite.welcome.clone();

    let held = runtime
        .publish_welcome_messages_with_audit_context(
            vec![welcome.clone()],
            Some(invite.group_id.clone()),
            Default::default(),
        )
        .await
        .unwrap();
    let retried = runtime
        .retry_welcome_messages_with_audit_context(vec![welcome.clone()], Default::default())
        .await
        .unwrap();
    let task = runtime
        .prepare_welcome_retry_task_with_audit_context(vec![welcome.clone()], Default::default())
        .unwrap();
    assert!(task.message_ids().is_empty(), "no detached relay attempt");
    assert!(
        staged_welcome_publishes(&invite.adapter).is_empty(),
        "no Welcome may be published before its Add commit confirms"
    );
    for effects in [&held, &retried] {
        assert!(effects.welcome_failures.is_empty());
        assert!(effects.failures.is_empty());
    }
    assert!(
        runtime
            .session()
            .transport_fanout(&welcome.id)
            .unwrap()
            .is_none(),
        "a held Welcome leaves no retry record"
    );
    let index = runtime.welcome_delivery_index().unwrap();
    assert!(index.outstanding.is_empty());
    assert!(index.tracked_ids.contains(&welcome.id));

    invite.confirm_commit().await;
    let runtime = &mut invite.runtime;
    let owed = runtime.outstanding_welcome_deliveries().unwrap();
    assert_eq!(owed.len(), 1);
    assert_eq!(owed[0].1.id, welcome.id);
    runtime
        .publish_welcome_messages_with_audit_context(
            vec![welcome.clone()],
            Some(invite.group_id.clone()),
            Default::default(),
        )
        .await
        .unwrap();
    let sent = staged_welcome_publishes(&invite.adapter);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].id, welcome.id);
    assert!(runtime.outstanding_welcome_deliveries().unwrap().is_empty());
}

/// mdk#2726: before this fix a staged Welcome's publish could store its
/// retry record. Maintenance retries such a record, and holds it too while
/// the Welcome is staged, then delivers from it once the commit confirms.
#[tokio::test]
async fn maintenance_holds_a_stored_fanout_of_a_staged_welcome() {
    let dir = relaxed_storage_dir().unwrap();
    let mut invite = retained_invite(dir.path()).await;
    let welcome = invite.welcome.clone();
    // The record the old path wrote before its relay attempt.
    invite
        .runtime
        .session()
        .put_transport_fanout(&cgka_traits::DurableTransportFanout {
            id: welcome.id.clone(),
            group_id: Some(invite.group_id.clone()),
            evolution_id: None,
            exact_message: welcome.clone(),
            target: TransportPublishTarget::Inbox {
                recipient: invite.carol_id.clone(),
                endpoints: vec![invite.carol_inbox.clone()],
            },
            targets: vec![cgka_traits::TransportFanoutTarget {
                endpoint: invite.carol_inbox.clone(),
                state: cgka_traits::TransportFanoutAttemptState::Unattempted,
                attempt_count: 0,
                last_attempt_at: None,
                failure_code: None,
            }],
            required_acks: 1,
            evolution_confirmed: false,
            possible_exposure: false,
            created_at: Timestamp(300_000),
            bounded_until: Some(Timestamp(300_000 + 86_400)),
        })
        .unwrap();

    invite.runtime.run_due_maintenance().await.unwrap();
    assert!(
        staged_welcome_publishes(&invite.adapter).is_empty(),
        "no Welcome may be published before its Add commit confirms"
    );
    assert!(
        invite
            .runtime
            .session()
            .transport_fanout(&welcome.id)
            .unwrap()
            .is_some(),
        "the held Welcome keeps its retry record"
    );

    invite.confirm_commit().await;
    invite.runtime.run_due_maintenance().await.unwrap();
    let sent = staged_welcome_publishes(&invite.adapter);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].id, welcome.id);
}

/// mdk#2628 3.5a: a Welcome held while its commit was retained goes out on
/// the first maintenance pass after the commit confirms, once, with no
/// restart and no caller holding it.
#[tokio::test]
async fn staged_invite_welcome_goes_out_once_its_commit_confirms() {
    let dir = relaxed_storage_dir().unwrap();
    let mut invite = retained_invite(dir.path()).await;
    let welcome_id = invite.welcome.id.clone();

    invite.confirm_commit().await;
    assert!(staged_welcome_publishes(&invite.adapter).is_empty());
    let delivered = invite.runtime.run_due_maintenance().await.unwrap();
    assert!(delivered.welcome_failures.is_empty());
    let sent = staged_welcome_publishes(&invite.adapter);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].id, welcome_id);
    assert!(
        invite
            .runtime
            .outstanding_welcome_deliveries()
            .unwrap()
            .is_empty()
    );

    invite.wall.set(400_000);
    invite.runtime.run_due_maintenance().await.unwrap();
    assert_eq!(staged_welcome_publishes(&invite.adapter).len(), 1);
}

/// A Welcome whose commit rolls back is never published, however many
/// maintenance passes follow.
#[tokio::test]
async fn staged_invite_welcome_never_goes_out_when_its_commit_rolls_back() {
    let dir = relaxed_storage_dir().unwrap();
    let mut invite = retained_invite_failing(dir.path(), |adapter, group_relay| {
        adapter.fail_endpoints_as(
            vec![group_relay],
            TransportEndpointFailureKind::RetryableUnavailable,
        );
    })
    .await;
    invite.adapter.fail_endpoints_as(
        vec![invite.group_relay.clone()],
        TransportEndpointFailureKind::TerminalRejected,
    );
    invite.wall.set(300_100);
    let resumed = invite.runtime.resume_outbound_fanouts().await.unwrap();
    assert!(matches!(
        resumed.pending.as_slice(),
        [PendingResolution::RolledBack { .. }]
    ));

    invite.runtime.run_due_maintenance().await.unwrap();
    invite.wall.set(400_000);
    invite.runtime.run_due_maintenance().await.unwrap();
    assert!(staged_welcome_publishes(&invite.adapter).is_empty());
    assert!(
        invite
            .runtime
            .outstanding_welcome_deliveries()
            .unwrap()
            .is_empty()
    );
}

/// How a restarted runtime first reads the store for Welcomes.
#[derive(Clone, Copy)]
enum FirstRead {
    StartupPass,
    MaintenanceBeforeConfirm,
    MaintenanceAfterConfirm,
}

/// A restart before the commit confirms loses nothing: the restarted runtime
/// reads the store for Welcomes still staged or already owed, so maintenance
/// delivers the Welcome once the resumed commit confirms. The startup pass
/// reads the store; without one, the first maintenance pass does, whether the
/// commit confirmed before it or not.
async fn staged_invite_welcome_goes_out_after_a_restart(first_read: FirstRead) {
    let dir = relaxed_storage_dir().unwrap();
    let mut invite = retained_invite(dir.path()).await;
    let welcome_id = invite.welcome.id.clone();
    invite.restart(dir.path());

    if matches!(first_read, FirstRead::StartupPass) {
        let startup = invite
            .runtime
            .prepare_owed_welcome_retry_task_with_audit_context(Default::default())
            .unwrap();
        assert!(startup.is_none(), "nothing is owed while the commit is staged");
    }
    if !matches!(first_read, FirstRead::MaintenanceAfterConfirm) {
        invite.runtime.run_due_maintenance().await.unwrap();
        assert!(
            staged_welcome_publishes(&invite.adapter).is_empty(),
            "no Welcome may be published before its Add commit confirms"
        );
    }
    invite.confirm_commit().await;
    invite.runtime.run_due_maintenance().await.unwrap();

    let sent = staged_welcome_publishes(&invite.adapter);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].id, welcome_id);
    assert!(
        invite
            .runtime
            .outstanding_welcome_deliveries()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn staged_invite_welcome_goes_out_after_a_restart_with_a_startup_pass() {
    staged_invite_welcome_goes_out_after_a_restart(FirstRead::StartupPass).await;
}

#[tokio::test]
async fn staged_invite_welcome_goes_out_after_a_restart_without_a_startup_pass() {
    staged_invite_welcome_goes_out_after_a_restart(FirstRead::MaintenanceBeforeConfirm).await;
}

#[tokio::test]
async fn staged_invite_welcome_goes_out_when_its_commit_confirms_before_the_first_pass() {
    staged_invite_welcome_goes_out_after_a_restart(FirstRead::MaintenanceAfterConfirm).await;
}

/// A group that is not live when the runtime first reads the store is read
/// again on each pass until it is, so its Welcome still goes out when the
/// group is hydrated and its commit confirms between two passes.
#[tokio::test]
async fn staged_invite_welcome_goes_out_once_its_group_is_hydrated() {
    let dir = relaxed_storage_dir().unwrap();
    let mut invite = retained_invite(dir.path()).await;
    let welcome_id = invite.welcome.id.clone();
    invite.restart_unhydrated(dir.path());
    assert_eq!(
        invite.runtime.unhydrated_group_ids(),
        vec![invite.group_id.clone()]
    );

    invite.runtime.run_due_maintenance().await.unwrap();
    assert!(staged_welcome_publishes(&invite.adapter).is_empty());
    assert!(invite.runtime.ensure_group_hydrated(&invite.group_id).unwrap());
    invite.confirm_commit().await;
    invite.runtime.run_due_maintenance().await.unwrap();

    let sent = staged_welcome_publishes(&invite.adapter);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].id, welcome_id);
}

/// A maintenance send that finds no route stores no retry record, so the
/// runtime paces the recipient instead (mdk#2261): a pass inside the wait
/// prepares nothing, records no failure, leaves the Welcome's delivery
/// record alone and tells the host nothing, even once a route exists. Each
/// paced attempt that finds no route is counted on that record once, and the
/// first pass after a wait that finds a route sends the Welcome on it.
#[tokio::test]
async fn staged_invite_welcome_without_a_route_waits_for_its_paced_retry() {
    let dir = relaxed_storage_dir().unwrap();
    let mut invite = retained_invite(dir.path()).await;
    let welcome_id = invite.welcome.id.clone();
    let carol_changed = vec![(invite.group_id.clone(), invite.carol_id.clone())];
    let attempts = |invite: &RetainedInvite| {
        let record = invite
            .runtime
            .session()
            .welcome_delivery_record(&welcome_id)
            .unwrap()
            .expect("a watched Welcome has a delivery record");
        assert_eq!(
            record.last_problem,
            Some(cgka_traits::maintenance::WelcomeDeliveryProblem::NoInboxRelays)
        );
        record.attempts
    };
    invite.route_carol(false);
    invite.confirm_commit().await;
    invite.runtime.take_welcome_delivery_changes();

    let unrouted = invite.runtime.run_due_maintenance().await.unwrap();
    assert!(
        unrouted
            .failures
            .iter()
            .any(|failure| failure.message_id == welcome_id)
    );
    assert!(staged_welcome_publishes(&invite.adapter).is_empty());
    assert!(
        invite
            .runtime
            .session()
            .transport_fanout(&welcome_id)
            .unwrap()
            .is_none(),
        "a send that found no route leaves no retry record"
    );
    let first = attempts(&invite);
    assert_eq!(invite.runtime.take_welcome_delivery_changes(), carol_changed);

    invite.wall.set(300_100 + 599);
    let held = invite.runtime.run_due_maintenance().await.unwrap();
    assert!(
        !held
            .failures
            .iter()
            .any(|failure| failure.message_id == welcome_id),
        "a pass inside the wait records no failure"
    );
    assert_eq!(attempts(&invite), first, "nor counts an attempt");
    assert!(
        invite.runtime.take_welcome_delivery_changes().is_empty(),
        "nor tells the host of one"
    );

    // The paced attempt still finds no route: counted once, and the next
    // wait is twice as long.
    invite.wall.set(300_100 + 600);
    invite.runtime.run_due_maintenance().await.unwrap();
    assert_eq!(attempts(&invite), first + 1);
    assert_eq!(invite.runtime.take_welcome_delivery_changes(), carol_changed);

    invite.route_carol(true);
    invite.wall.set(300_700 + 1_199);
    invite.runtime.run_due_maintenance().await.unwrap();
    assert!(
        staged_welcome_publishes(&invite.adapter).is_empty(),
        "a pass inside the wait does not send it"
    );
    assert_eq!(attempts(&invite), first + 1);

    invite.wall.set(300_700 + 1_200);
    invite.runtime.run_due_maintenance().await.unwrap();
    let sent = staged_welcome_publishes(&invite.adapter);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].id, welcome_id);
    assert!(
        invite
            .runtime
            .outstanding_welcome_deliveries()
            .unwrap()
            .is_empty()
    );
}

/// mdk#2261: each paced attempt that finds no route owes the host one lookup
/// of the recipient's inbox list, taken once. A pass inside the wait owes
/// none. Once the host installs a route and releases the retry, the next
/// pass sends the Welcome without waiting out the pacing, and a delivered
/// Welcome owes no lookup.
#[tokio::test]
async fn a_route_less_welcome_owes_one_lookup_per_paced_attempt() {
    let dir = relaxed_storage_dir().unwrap();
    let mut invite = retained_invite(dir.path()).await;
    let carol = vec![invite.carol_id.clone()];
    let take = |invite: &RetainedInvite| {
        invite
            .runtime
            .plan_welcome_route_lookups(4, &[])
            .unwrap()
            .start
    };
    invite.route_carol(false);
    invite.confirm_commit().await;
    assert!(take(&invite).is_empty(), "no attempt has found no route yet");

    invite.runtime.run_due_maintenance().await.unwrap();
    assert_eq!(
        invite.runtime.plan_welcome_route_lookups(0, &[]).unwrap(),
        WelcomeRouteLookupPlan::default(),
        "a host that starts none, as while maintenance is paused, leaves it owed"
    );
    assert_eq!(
        invite
            .runtime
            .plan_welcome_route_lookups(4, &carol)
            .unwrap(),
        WelcomeRouteLookupPlan::default(),
        "a recipient the host is already looking up is left owed"
    );
    assert_eq!(take(&invite), carol);
    assert!(take(&invite).is_empty(), "one lookup per paced attempt");

    invite.wall.set(300_100 + 599);
    invite.runtime.run_due_maintenance().await.unwrap();
    assert!(take(&invite).is_empty(), "a pass inside the wait owes none");
    invite.wall.set(300_100 + 600);
    invite.runtime.run_due_maintenance().await.unwrap();
    assert_eq!(take(&invite), carol);

    // The lookup found a list: the host installs it and says so.
    invite.route_carol(true);
    invite
        .runtime
        .finish_welcome_route_lookup(&invite.carol_id, WelcomeRouteLookup::Routed);
    invite.wall.set(300_100 + 601);
    invite.runtime.run_due_maintenance().await.unwrap();
    let sent = staged_welcome_publishes(&invite.adapter);
    assert_eq!(sent.len(), 1, "released, it goes out inside the wait");
    assert_eq!(sent[0].id, invite.welcome.id);
    assert!(
        invite
            .runtime
            .outstanding_welcome_deliveries()
            .unwrap()
            .is_empty()
    );
    assert!(take(&invite).is_empty());
}

/// mdk#2261: nobody is looked up for a Welcome that is no longer owed. A
/// lookup owed when the Welcome is withdrawn, or when it passes its delivery
/// deadline, is never started, and a running one is stopped.
#[tokio::test]
async fn no_lookup_is_taken_for_a_withdrawn_or_expired_welcome() {
    for withdraw in [true, false] {
        let dir = relaxed_storage_dir().unwrap();
        let mut invite = retained_invite(dir.path()).await;
        invite.route_carol(false);
        invite.confirm_commit().await;
        invite.runtime.run_due_maintenance().await.unwrap();
        if withdraw {
            assert_eq!(
                invite.runtime.withdraw_welcome(&invite.welcome.id).unwrap(),
                WelcomeWithdrawal::Withdrawn
            );
        } else {
            let deadline = invite
                .runtime
                .session()
                .sent_welcome_deliver_until(&invite.welcome.id)
                .unwrap()
                .expect("an invite's Welcome has a delivery deadline");
            invite.wall.set(deadline.0);
        }
        assert_eq!(
            invite.runtime.plan_welcome_route_lookups(4, &[]).unwrap(),
            WelcomeRouteLookupPlan::default(),
            "withdrawn: {withdraw}"
        );
        assert_eq!(
            invite
                .runtime
                .plan_welcome_route_lookups(4, std::slice::from_ref(&invite.carol_id))
                .unwrap(),
            WelcomeRouteLookupPlan {
                start: Vec::new(),
                stop: vec![invite.carol_id.clone()],
            },
            "withdrawn: {withdraw}"
        );
    }
}

/// A Welcome stays watched while its stored fanout retries it, so if that
/// fanout expires with the Welcome still owed, the next pass sends it again,
/// as the startup pass would at the next open.
#[tokio::test]
async fn staged_invite_welcome_goes_out_again_after_its_fanout_expires() {
    let dir = relaxed_storage_dir().unwrap();
    let mut invite = retained_invite(dir.path()).await;
    let welcome_id = invite.welcome.id.clone();
    invite.confirm_commit().await;
    invite
        .adapter
        .error_for_endpoints(vec![invite.carol_inbox.clone()]);

    invite.runtime.run_due_maintenance().await.unwrap();
    let fanout = invite
        .runtime
        .session()
        .transport_fanout(&welcome_id)
        .unwrap()
        .expect("the failed send stored its retry record");
    invite.wall.set(300_200);
    invite.runtime.run_due_maintenance().await.unwrap();
    assert_eq!(
        staged_welcome_publishes(&invite.adapter).len(),
        2,
        "the stored fanout retried it"
    );

    invite.adapter.error_for_endpoints(Vec::new());
    invite.wall.set(fanout.bounded_until.unwrap().0);
    invite.runtime.run_due_maintenance().await.unwrap();
    let sent = staged_welcome_publishes(&invite.adapter);
    assert_eq!(sent.len(), 3);
    assert_eq!(sent[2].id, welcome_id);
    assert!(
        invite
            .runtime
            .outstanding_welcome_deliveries()
            .unwrap()
            .is_empty()
    );
}

/// mdk#2628 3.5a: a host that names an invite's Welcomes by id has the
/// runtime publish only those the engine owes. One staged with its retained
/// commit waits, an owed one goes out, and once delivered it is skipped.
#[tokio::test]
async fn welcomes_named_by_id_go_out_only_while_owed() {
    let dir = relaxed_storage_dir().unwrap();
    let mut invite = retained_invite(dir.path()).await;
    let ids = [invite.welcome.id.clone()];

    let staged = invite
        .runtime
        .deliver_owed_welcomes_with_audit_context(
            &ids,
            invite.group_id.clone(),
            Default::default(),
        )
        .await
        .unwrap();
    assert!(staged.welcome_failures.is_empty());
    assert!(
        staged_welcome_publishes(&invite.adapter).is_empty(),
        "no Welcome may be published before its Add commit confirms"
    );

    invite.confirm_commit().await;
    for _ in 0..2 {
        let effects = invite
            .runtime
            .deliver_owed_welcomes_with_audit_context(
                &ids,
                invite.group_id.clone(),
                Default::default(),
            )
            .await
            .unwrap();
        assert!(effects.welcome_failures.is_empty());
    }
    let sent = staged_welcome_publishes(&invite.adapter);
    assert_eq!(sent.len(), 1, "a delivered Welcome is not sent again");
    assert_eq!(sent[0].id, ids[0]);
    assert!(
        invite
            .runtime
            .outstanding_welcome_deliveries()
            .unwrap()
            .is_empty()
    );
}

/// A Welcome withdrawn while owed is skipped when a host names it by id.
#[tokio::test]
async fn a_withdrawn_welcome_named_by_id_stays_unsent() {
    let dir = relaxed_storage_dir().unwrap();
    let mut invite = retained_invite(dir.path()).await;
    let ids = [invite.welcome.id.clone()];
    invite.confirm_commit().await;
    assert_eq!(
        invite.runtime.withdraw_welcome(&ids[0]).unwrap(),
        WelcomeWithdrawal::Withdrawn
    );

    let effects = invite
        .runtime
        .deliver_owed_welcomes_with_audit_context(
            &ids,
            invite.group_id.clone(),
            Default::default(),
        )
        .await
        .unwrap();
    assert!(effects.welcome_failures.is_empty());
    assert!(effects.failures.is_empty());
    assert!(staged_welcome_publishes(&invite.adapter).is_empty());
}
