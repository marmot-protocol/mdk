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
        self.reopen(dir, session);
    }

    /// [`Self::restart`], leaving the group unhydrated.
    fn restart_unhydrated(&mut self, dir: &std::path::Path) {
        self.reopen(dir, deferred_session);
    }

    fn reopen(
        &mut self,
        dir: &std::path::Path,
        open: fn(std::path::PathBuf, &SqlCipherKey, &[u8]) -> AccountDeviceSession,
    ) {
        let reopened = open(
            dir.join("alice.sqlite"),
            &SqlCipherKey::new(STAGED_INVITE_KEY).unwrap(),
            STAGED_INVITE_ALICE,
        );
        let restarted = AccountDeviceRuntime::new(
            reopened,
            self.adapter.clone(),
            self.policy.clone(),
            RecordingKeyPackages::default(),
        )
        .with_maintenance_sources(
            self.wall.clone(),
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(0)),
        );
        drop(std::mem::replace(&mut self.runtime, restarted));
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

/// mdk#2628 3.5a: a Welcome held while its commit was retained goes out on
/// the first maintenance pass after the commit confirms, once, with no
/// restart and no caller holding it.
#[tokio::test]
async fn staged_invite_welcome_goes_out_once_its_commit_confirms() {
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
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

/// A maintenance send that reaches no relay, here for want of a route, keeps
/// the Welcome watched, so the next pass sends it once a route exists.
#[tokio::test]
async fn staged_invite_welcome_goes_out_after_a_send_that_found_no_route() {
    let dir = tempfile::tempdir().unwrap();
    let mut invite = retained_invite(dir.path()).await;
    let welcome_id = invite.welcome.id.clone();
    invite.route_carol(false);
    invite.confirm_commit().await;

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

    invite.route_carol(true);
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

/// A Welcome stays watched while its stored fanout retries it, so if that
/// fanout expires with the Welcome still owed, the next pass sends it again,
/// as the startup pass would at the next open.
#[tokio::test]
async fn staged_invite_welcome_goes_out_again_after_its_fanout_expires() {
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
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
