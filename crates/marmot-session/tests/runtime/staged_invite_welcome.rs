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
    AccountDeviceRuntime<RecordingAdapter, StaticTransportRouting, RecordingKeyPackages>;

/// An invite of Carol made the app's way (stage the commit, take its
/// Welcome, publish), whose commit the relay may or may not have seen, so it
/// is retained with its Welcome still staged.
struct RetainedInvite {
    runtime: StagedInviteRuntime,
    adapter: RecordingAdapter,
    wall: Arc<TestWallClock>,
    group_id: GroupId,
    carol_id: MemberId,
    carol_inbox: TransportEndpoint,
    welcome: TransportMessage,
}

async fn retained_invite(dir: &std::path::Path) -> RetainedInvite {
    let key = SqlCipherKey::new("marmot staged invite welcome key").unwrap();
    let mut alice = session(dir.join("alice.sqlite"), &key, b"alice-staged");
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
    let policy = StaticTransportRouting::new(vec![TransportEndpoint(
        "wss://alice-inbox.example".into(),
    )])
    .with_group_route(
        group_id.clone(),
        group_id.as_slice().to_vec(),
        vec![group_relay.clone()],
    )
    .with_inbox_route(carol_id.clone(), vec![carol_inbox.clone()]);
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
    adapter.error_for_endpoints(vec![group_relay]);
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
        wall,
        group_id,
        carol_id,
        carol_inbox,
        welcome: welcomes.pop().unwrap(),
    }
}

impl RetainedInvite {
    /// Let the relay take the retained commit once its retry is due, which
    /// confirms it and promotes its Welcome.
    async fn confirm_commit(&mut self) {
        self.adapter.error_for_endpoints(Vec::new());
        self.wall.set(300_100);
        let resumed = self.runtime.resume_outbound_fanouts().await.unwrap();
        assert!(matches!(
            resumed.pending.as_slice(),
            [PendingResolution::Confirmed { .. }]
        ));
    }
}

/// mdk#2726: an invite whose commit the relays leave unresolved keeps its
/// Welcome staged, and the runtime refuses to publish it however it is
/// asked, recording no failure. Once the commit confirms, the same Welcome is
/// owed and goes out.
#[tokio::test]
async fn staged_invite_welcome_waits_for_its_commit() {
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
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
