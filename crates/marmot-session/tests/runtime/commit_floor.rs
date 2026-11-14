// mdk#2332: commit size refusals before sending, and the exposure they keep.
//
// A commit over a relay's known limit, or over the 64 KiB floor where the
// relay's limit is unknown, is refused there before anything is sent. The
// session asks for each target before it marks that target `Attempting`, so a
// refusal leaves no attempt behind, and one relay's check holds back no other
// relay's send. A commit every relay refused rolls back typed. A refusal
// recorded on a target that may already hold the commit never lets it roll
// back (mdk#1577).

/// Alice and Bob share a group whose route is `relays`, and Alice's runtime
/// publishes through `adapter`.
struct FloorFixture {
    _dir: tempfile::TempDir,
    alice_path: std::path::PathBuf,
    alice_seed: &'static [u8],
    group_id: GroupId,
    policy: StaticTransportRouting,
    wall: Arc<TestWallClock>,
}

const FLOOR_KEY: &str = "marmot commit floor key";

impl FloorFixture {
    async fn new(name: &'static str, relays: &[&TransportEndpoint]) -> (Self, AccountDeviceSession) {
        let dir = relaxed_storage_dir().unwrap();
        let alice_path = dir.path().join(format!("alice-{name}.sqlite"));
        let key = SqlCipherKey::new(FLOOR_KEY).unwrap();
        let alice_seed: &'static [u8] = name.as_bytes();
        let mut alice = session(&alice_path, &key, alice_seed);
        let mut bob = session(dir.path().join(format!("bob-{name}.sqlite")), &key, b"bob");
        let created = alice
            .create_group(CreateGroupRequest {
                name: name.into(),
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
        let policy = StaticTransportRouting::new(vec![TransportEndpoint(
            "wss://commit-floor-inbox.example".into(),
        )])
        .with_group_route(
            group_id.clone(),
            group_id.as_slice().to_vec(),
            relays.iter().map(|relay| (*relay).clone()).collect(),
        );
        let fixture = Self {
            _dir: dir,
            alice_path,
            alice_seed,
            group_id,
            policy,
            wall: Arc::new(TestWallClock::new(100_000)),
        };
        (fixture, alice)
    }

    fn reopen(&self) -> AccountDeviceSession {
        session(
            &self.alice_path,
            &SqlCipherKey::new(FLOOR_KEY).unwrap(),
            self.alice_seed,
        )
    }

    fn runtime(
        &self,
        alice: AccountDeviceSession,
        adapter: &RecordingAdapter,
    ) -> AccountDeviceRuntime<RecordingAdapter, StaticTransportRouting, RecordingKeyPackages> {
        AccountDeviceRuntime::new(
            alice,
            adapter.clone(),
            self.policy.clone(),
            RecordingKeyPackages::default(),
        )
        .with_maintenance_sources(
            self.wall.clone(),
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(0)),
        )
    }

    fn rename(&self) -> SendIntent {
        SendIntent::UpdateGroupData {
            group_id: self.group_id.clone(),
            name: Some("renamed".into()),
            description: None,
        }
    }
}

fn oversized_commit() -> Option<marmot_session::OversizedEvent> {
    Some(marmot_session::OversizedEvent {
        artifact: marmot_session::OversizedArtifact::Commit,
        size_class: cgka_traits::EventSizeClass::of_bytes(70_000),
    })
}

/// Drive `send` until the adapter has seen `seen`, then drop it: the process
/// dies with that work in flight.
async fn crash_when<F: std::future::Future>(send: F, seen: impl Fn() -> bool) {
    let mut send = Box::pin(send);
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            _ = async {
                while !seen() {
                    tokio::task::yield_now().await;
                }
            } => {}
            _ = &mut send => panic!("the work must remain in flight"),
        }
    })
    .await
    .unwrap();
}

/// A commit every relay refuses for its size is never sent: the size check
/// runs before any target is marked, the commit rolls back typed, and the
/// refused relay never reaches the commit entry point.
#[tokio::test]
async fn a_commit_every_relay_refuses_for_size_rolls_back_unsent() {
    let relay = TransportEndpoint("wss://floor-only.example".into());
    let (fixture, alice) = FloorFixture::new("floor-only", &[&relay]).await;
    let adapter = RecordingAdapter::default();
    adapter.refuse_commits_as_too_large(vec![relay.clone()]);
    let mut runtime = fixture.runtime(alice, &adapter);

    let effects = runtime.send(fixture.rename()).await.unwrap();

    assert!(matches!(
        effects.pending.as_slice(),
        [PendingResolution::RolledBack { .. }]
    ));
    assert!(
        matches!(
            effects.failures.as_slice(),
            [marmot_session::PublishFailure { oversized, .. }] if *oversized == oversized_commit()
        ),
        "{:?}",
        effects.failures
    );
    assert_eq!(adapter.commit_size_checks(), vec![vec![relay]]);
    assert!(adapter.commit_publishes().is_empty(), "refused before marking");
    assert!(adapter.publishes().is_empty(), "nothing was sent");
    assert_eq!(runtime.session().epoch(&fixture.group_id).unwrap().0, 1);
    assert!(runtime.session().outbound_fanouts().unwrap().is_empty());
}

/// One relay refuses the commit for its size and the other accepts it: the
/// commit confirms, and the refused relay ends `Failed` with the size proof.
/// Commits go through the commit entry point; application messages do not,
/// and are never size-checked as commits.
#[tokio::test]
async fn a_commit_one_relay_refuses_for_size_confirms_on_the_other() {
    let refusing = TransportEndpoint("wss://floor-refusing.example".into());
    let accepting = TransportEndpoint("wss://floor-accepting.example".into());
    let (fixture, alice) = FloorFixture::new("floor-split", &[&refusing, &accepting]).await;
    let alice_hex = hex::encode(alice.self_id().as_slice());
    let adapter = RecordingAdapter::default();
    adapter.refuse_commits_as_too_large(vec![refusing.clone()]);
    let mut runtime = fixture.runtime(alice, &adapter);

    let effects = runtime.send(fixture.rename()).await.unwrap();

    assert!(matches!(
        effects.pending.as_slice(),
        [PendingResolution::Confirmed { .. }]
    ));
    assert_eq!(runtime.session().epoch(&fixture.group_id).unwrap().0, 2);
    let refused = effects
        .reports
        .iter()
        .flat_map(|report| &report.failed)
        .find(|failure| failure.endpoint == refusing)
        .expect("the refusal is reported");
    assert_eq!(refused, &RecordingAdapter::commit_size_refusal(&refusing));
    let commit_targets = adapter
        .commit_publishes()
        .iter()
        .map(|request| request.target.endpoints().to_vec())
        .collect::<Vec<_>>();
    assert_eq!(commit_targets, vec![vec![accepting.clone()]]);
    assert_eq!(adapter.publishes().len(), 1);

    let checks = adapter.commit_size_checks().len();
    runtime
        .send(SendIntent::AppMessage {
            group_id: fixture.group_id.clone(),
            payload: app_payload_for(&alice_hex, b"not a commit"),
            expected_epoch: None,
        })
        .await
        .unwrap();
    assert_eq!(adapter.publishes().len(), 3, "one publish per relay");
    assert_eq!(adapter.commit_size_checks().len(), checks);
    assert_eq!(adapter.commit_publishes().len(), 1);
}

/// Each relay's size check runs on its own: a check that stalls, as a
/// connection probe to a relay of unknown limit can, holds back no other
/// relay's send. The commit confirms on the relay whose check finished, and
/// the stalled relay stays unmarked until a later pass checks it again and
/// sends to it.
#[tokio::test]
async fn a_stalled_size_check_holds_back_no_other_relay() {
    let stalled = TransportEndpoint("wss://floor-stalled-check.example".into());
    let ready = TransportEndpoint("wss://floor-ready-check.example".into());
    let (fixture, alice) = FloorFixture::new("floor-stalled-check", &[&stalled, &ready]).await;
    let adapter = RecordingAdapter::default();
    let gate = adapter.gate_commit_size_checks_at(stalled.clone());
    let mut runtime = fixture.runtime(alice, &adapter);

    let effects = tokio::time::timeout(Duration::from_secs(5), runtime.send(fixture.rename()))
        .await
        .expect("the ready relay's send waits for no other relay's check")
        .unwrap();

    assert!(matches!(
        effects.pending.as_slice(),
        [PendingResolution::Confirmed { .. }]
    ));
    let commit_targets = || {
        adapter
            .commit_publishes()
            .iter()
            .map(|request| request.target.endpoints().to_vec())
            .collect::<Vec<_>>()
    };
    assert_eq!(commit_targets(), vec![vec![ready.clone()]]);
    let stored = runtime.session().outbound_fanouts().unwrap();
    assert_eq!(stored.len(), 1);
    let index = stored[0]
        .request()
        .target
        .endpoints()
        .iter()
        .position(|target| *target == stalled)
        .unwrap();
    assert_eq!(
        stored[0].target_status(index),
        Some(FanoutTargetStatus::NotAttempted)
    );
    assert_eq!(stored[0].target_attempt_count(index), 0);

    gate.add_permits(1);
    runtime.resume_outbound_fanouts().await.unwrap();
    assert_eq!(commit_targets(), vec![vec![ready], vec![stalled]]);

    // A check that finishes only once the commit met its acknowledgements
    // starts no send: the pass would cancel it unfinished, leaving the relay
    // possibly exposed for nothing. The relay waits, unmarked, for the next
    // pass.
    let late = TransportEndpoint("wss://floor-late-check.example".into());
    let ready = TransportEndpoint("wss://floor-before-late.example".into());
    let (fixture, alice) = FloorFixture::new("floor-late-check", &[&late, &ready]).await;
    let adapter = RecordingAdapter::default();
    let check = adapter.gate_commit_size_checks_at(late.clone());
    *adapter.inner.publish_releases.lock().unwrap() = Some((ready.clone(), check));
    *adapter.inner.endpoint_gate.lock().unwrap() =
        Some((late.clone(), Arc::new(tokio::sync::Semaphore::new(0))));
    let mut runtime = fixture.runtime(alice, &adapter);

    let effects = runtime.send(fixture.rename()).await.unwrap();

    assert!(matches!(
        effects.pending.as_slice(),
        [PendingResolution::Confirmed { .. }]
    ));
    assert_eq!(adapter.commit_size_checks().len(), 2);
    assert!(
        adapter
            .commit_publishes()
            .iter()
            .all(|request| request.target.endpoints() == [ready.clone()]),
        "no send to the relay checked late"
    );
    let stored = runtime.session().outbound_fanouts().unwrap();
    let index = stored[0]
        .request()
        .target
        .endpoints()
        .iter()
        .position(|target| *target == late)
        .unwrap();
    assert_eq!(
        stored[0].target_status(index),
        Some(FanoutTargetStatus::NotAttempted)
    );
}

/// A refusal before marking leaves no attempt on the refused target: when the
/// process dies with the other relay's send in flight, the refused target is
/// stored `Failed`, never attempted and unexposed. A commit whose only relay
/// refuses it after a restart still rolls back typed, unsent.
#[tokio::test]
async fn a_size_refusal_before_marking_leaves_no_attempt_behind() {
    let refusing = TransportEndpoint("wss://floor-first.example".into());
    let held = TransportEndpoint("wss://floor-held.example".into());
    let (fixture, alice) = FloorFixture::new("floor-no-attempt", &[&refusing, &held]).await;
    let adapter = RecordingAdapter::default();
    adapter.refuse_commits_as_too_large(vec![refusing.clone()]);
    *adapter.inner.endpoint_gate.lock().unwrap() =
        Some((held.clone(), Arc::new(tokio::sync::Semaphore::new(0))));
    let mut runtime = fixture.runtime(alice, &adapter);
    crash_when(runtime.send(fixture.rename()), || !adapter.publishes().is_empty()).await;
    drop(runtime);

    let stored = fixture.reopen().outbound_fanouts().unwrap();
    assert_eq!(stored.len(), 1);
    let fanout = &stored[0];
    let index = |endpoint: &TransportEndpoint| {
        fanout
            .request()
            .target
            .endpoints()
            .iter()
            .position(|target| target == endpoint)
            .unwrap()
    };
    assert_eq!(
        fanout.target_status(index(&refusing)),
        Some(FanoutTargetStatus::Failed)
    );
    assert_eq!(fanout.target_attempt_count(index(&refusing)), 0);
    assert_eq!(
        fanout.target_failure(index(&refusing)),
        Some(&RecordingAdapter::commit_size_refusal(&refusing))
    );
    assert_eq!(
        fanout.target_status(index(&held)),
        Some(FanoutTargetStatus::Attempting)
    );

    // A commit staged but not yet checked when the process died.
    let only = TransportEndpoint("wss://floor-restart.example".into());
    let (fixture, alice) = FloorFixture::new("floor-restart", &[&only]).await;
    let adapter = RecordingAdapter::default();
    let gate = adapter.gate_commit_size_checks();
    let mut runtime = fixture.runtime(alice, &adapter);
    crash_when(runtime.send(fixture.rename()), || {
        !adapter.commit_size_checks().is_empty()
    })
    .await;
    drop(runtime);
    drop(gate);
    *adapter.inner.commit_size_check_gate.lock().unwrap() = None;
    adapter.refuse_commits_as_too_large(vec![only.clone()]);
    let mut restarted = fixture.runtime(fixture.reopen(), &adapter);
    let stored = restarted.session().outbound_fanouts().unwrap();
    assert_eq!(
        stored[0].target_status(0),
        Some(FanoutTargetStatus::NotAttempted)
    );

    let effects = restarted.resume_outbound_fanouts().await.unwrap();
    assert!(matches!(
        effects.pending.as_slice(),
        [PendingResolution::RolledBack { .. }]
    ));
    assert!(matches!(
        effects.failures.as_slice(),
        [marmot_session::PublishFailure { oversized, .. }] if *oversized == oversized_commit()
    ));
    assert!(adapter.commit_publishes().is_empty());
    assert!(adapter.publishes().is_empty());
    assert_eq!(restarted.session().epoch(&fixture.group_id).unwrap().0, 1);
}

/// Round 4's B1: the commit was sent and the process died before the result.
/// After the restart the relay's limit reads as unknown and the commit is
/// over the floor, so the size check refuses it before any resend. The
/// interrupted attempt may have reached the relay, so the refusal ends the
/// target `PossiblyExposed` and the commit never rolls back. Each refusal
/// restarts the target's retry clock, so past the interrupted attempt's
/// deadline the refused commit backs off instead of coming due on every pass.
#[tokio::test]
async fn a_size_refusal_after_an_interrupted_send_keeps_the_commit_pending() {
    let relay = TransportEndpoint("wss://floor-interrupted.example".into());
    let (fixture, alice) = FloorFixture::new("floor-interrupted", &[&relay]).await;
    let adapter = RecordingAdapter::default();
    *adapter.inner.endpoint_gate.lock().unwrap() =
        Some((relay.clone(), Arc::new(tokio::sync::Semaphore::new(0))));
    let mut runtime = fixture.runtime(alice, &adapter);
    crash_when(runtime.send(fixture.rename()), || !adapter.publishes().is_empty()).await;
    drop(runtime);

    *adapter.inner.endpoint_gate.lock().unwrap() = None;
    adapter.refuse_commits_as_too_large(vec![relay.clone()]);
    let mut restarted = fixture.runtime(fixture.reopen(), &adapter);
    let effects = restarted.resume_outbound_fanouts().await.unwrap();

    assert!(effects.pending.is_empty(), "{:?}", effects.pending);
    assert!(effects.failures.is_empty(), "{:?}", effects.failures);
    let stored = restarted.session().outbound_fanouts().unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored[0].target_status(0),
        Some(FanoutTargetStatus::PossiblyExposed)
    );
    assert!(matches!(stored[0].mls_state(), FanoutMlsState::Pending(_)));
    assert_eq!(adapter.publishes().len(), 1, "the refusal sent nothing");
    assert_eq!(restarted.session().epoch(&fixture.group_id).unwrap().0, 2);

    // An hour on, past any deadline the interrupted attempt set, the target
    // is due again and refused again; each refusal backs off further.
    let retry_delay = |runtime: &AccountDeviceRuntime<_, _, _>| {
        runtime
            .outbound_fanout_retry_delay_ms(&fixture.group_id)
            .unwrap()
            .unwrap_or_default()
    };
    let first_backoff = retry_delay(&restarted);
    fixture.wall.set(100_000 + 60 * 60);
    let checks = adapter.commit_size_checks().len();
    restarted.resume_outbound_fanouts().await.unwrap();
    assert_eq!(adapter.commit_size_checks().len(), checks + 1);
    let second_backoff = retry_delay(&restarted);
    assert!(
        second_backoff > first_backoff && first_backoff > 0,
        "{first_backoff} ms, then {second_backoff} ms"
    );
    restarted.resume_outbound_fanouts().await.unwrap();
    assert_eq!(
        adapter.commit_size_checks().len(),
        checks + 1,
        "a pass at the same moment does not check the size again"
    );
    assert_eq!(adapter.publishes().len(), 1, "the refusals sent nothing");
}

/// Round 4's B2: a relay answered `rate-limited:`, so it received the commit.
/// Its later `invalid:` speaks only for that retry, and a definitive refusal
/// everywhere else no longer lets the commit roll back.
#[tokio::test]
async fn a_relay_that_answered_rate_limited_keeps_the_commit_pending() {
    use TransportEndpointFailureKind::{RetryableUnavailable, TerminalRejected};
    let limited = TransportEndpoint("wss://floor-rate-limited.example".into());
    let refusing = TransportEndpoint("wss://floor-invalid.example".into());
    let (fixture, alice) = FloorFixture::new("floor-rate-limited", &[&limited, &refusing]).await;
    let answer = |endpoint: &TransportEndpoint, kind, category| TransportEndpointFailure {
        endpoint: endpoint.clone(),
        reason: format!("relay rejected event ({})", TransportEndpointRejectionCategory::as_str(category)),
        kind,
        rejection_category: Some(category),
        size_class: None,
        pre_send: false,
    };
    let adapter = RecordingAdapter::default();
    adapter.script_failures(
        limited.clone(),
        vec![
            answer(&limited, RetryableUnavailable, TransportEndpointRejectionCategory::RateLimited),
            answer(&limited, TerminalRejected, TransportEndpointRejectionCategory::Invalid),
        ],
    );
    adapter.script_failures(
        refusing.clone(),
        vec![answer(&refusing, TerminalRejected, TransportEndpointRejectionCategory::Invalid)],
    );
    let mut runtime = fixture.runtime(alice, &adapter);

    let first = runtime.send(fixture.rename()).await.unwrap();
    assert!(first.pending.is_empty(), "{:?}", first.pending);
    fixture.wall.set(100_000 + 60 * 60);
    let second = runtime.resume_outbound_fanouts().await.unwrap();

    assert!(second.pending.is_empty(), "{:?}", second.pending);
    assert_eq!(adapter.publishes().len(), 3, "the rate-limited relay was retried");
    let stored = runtime.session().outbound_fanouts().unwrap();
    assert_eq!(stored.len(), 1);
    let status = |endpoint: &TransportEndpoint| {
        let index = stored[0]
            .request()
            .target
            .endpoints()
            .iter()
            .position(|target| target == endpoint)
            .unwrap();
        stored[0].target_status(index)
    };
    assert_eq!(status(&limited), Some(FanoutTargetStatus::PossiblyExposed));
    assert_eq!(status(&refusing), Some(FanoutTargetStatus::Failed));
    assert!(matches!(stored[0].mls_state(), FanoutMlsState::Pending(_)));
    assert_eq!(runtime.session().epoch(&fixture.group_id).unwrap().0, 2);
}

/// A relay that may hold the commit and then cannot be reached (D9's hold: no
/// connection, nothing sent) stays possibly exposed. A hold on a relay with
/// no earlier exposure only waits: the commit neither rolls back nor counts
/// as possibly delivered.
#[tokio::test]
async fn a_held_relay_keeps_the_exposure_it_had() {
    let exposed = TransportEndpoint("wss://floor-hold-exposed.example".into());
    let fresh = TransportEndpoint("wss://floor-hold-fresh.example".into());
    let (fixture, alice) = FloorFixture::new("floor-hold", &[&exposed, &fresh]).await;
    let hold = |endpoint: &TransportEndpoint| TransportEndpointFailure {
        endpoint: endpoint.clone(),
        reason: "connect relay failed".into(),
        kind: TransportEndpointFailureKind::RetryableUnavailable,
        rejection_category: None,
        size_class: None,
        pre_send: true,
    };
    let adapter = RecordingAdapter::default();
    adapter.script_failures(
        exposed.clone(),
        vec![
            TransportEndpointFailure {
                endpoint: exposed.clone(),
                reason: "send event timed out".into(),
                kind: TransportEndpointFailureKind::PossiblyExposed,
                rejection_category: None,
                size_class: None,
                pre_send: false,
            },
            hold(&exposed),
        ],
    );
    adapter.script_failures(fresh.clone(), vec![hold(&fresh), hold(&fresh)]);
    let mut runtime = fixture.runtime(alice, &adapter);

    runtime.send(fixture.rename()).await.unwrap();
    fixture.wall.set(100_000 + 60 * 60);
    let effects = runtime.resume_outbound_fanouts().await.unwrap();

    assert!(effects.pending.is_empty(), "{:?}", effects.pending);
    assert_eq!(adapter.publishes().len(), 4);
    let stored = runtime.session().outbound_fanouts().unwrap();
    let fanout = &stored[0];
    let index = |endpoint: &TransportEndpoint| {
        fanout
            .request()
            .target
            .endpoints()
            .iter()
            .position(|target| target == endpoint)
            .unwrap()
    };
    assert_eq!(
        fanout.target_status(index(&exposed)),
        Some(FanoutTargetStatus::PossiblyExposed)
    );
    assert_eq!(
        fanout.target_status(index(&fresh)),
        Some(FanoutTargetStatus::RetryableUnavailable)
    );
    assert!(matches!(fanout.mls_state(), FanoutMlsState::Pending(_)));
}

/// A relay's `rate-limited:` answer stored before pre-send proof existed: a
/// `RetryableUnavailable` row whose failure carries no proof, bit clear. That
/// relay received the commit, so neither a size refusal before marking nor a
/// definitive refusal of a later retry lets the commit roll back.
#[tokio::test]
async fn a_relay_answer_stored_before_the_upgrade_keeps_the_commit_pending() {
    for floor_refusal in [true, false] {
        let name = if floor_refusal {
            "legacy-answer-floor"
        } else {
            "legacy-answer-retry"
        };
        let answered = TransportEndpoint(format!("wss://{name}-answered.example"));
        let refusing = TransportEndpoint(format!("wss://{name}-refusing.example"));
        let (fixture, alice) = FloorFixture::new(name, &[&answered, &refusing]).await;
        let failure = |endpoint: &TransportEndpoint, kind, category, pre_send| {
            TransportEndpointFailure {
                endpoint: endpoint.clone(),
                reason: "scripted".into(),
                kind,
                rejection_category: category,
                size_class: None,
                pre_send,
            }
        };
        let adapter = RecordingAdapter::default();
        adapter.script_failures(
            answered.clone(),
            vec![
                failure(&answered, TransportEndpointFailureKind::RetryableUnavailable, None, true),
                failure(
                    &answered,
                    TransportEndpointFailureKind::TerminalRejected,
                    Some(TransportEndpointRejectionCategory::Invalid),
                    false,
                ),
            ],
        );
        adapter.script_failures(
            refusing.clone(),
            vec![failure(
                &refusing,
                TransportEndpointFailureKind::TerminalRejected,
                Some(TransportEndpointRejectionCategory::Invalid),
                false,
            )],
        );
        let mut runtime = fixture.runtime(alice, &adapter);
        let first = runtime.send(fixture.rename()).await.unwrap();
        assert!(first.pending.is_empty(), "{name}: {:?}", first.pending);
        drop(runtime);

        // Rewrite the waiting target as the previous release stored an answer.
        let alice = fixture.reopen();
        let stored = alice.outbound_fanouts().unwrap().remove(0);
        let index = stored
            .request()
            .target
            .endpoints()
            .iter()
            .position(|target| target == &answered)
            .unwrap();
        assert_eq!(
            stored.target_status(index),
            Some(FanoutTargetStatus::RetryableUnavailable)
        );
        let answer = failure(
            &answered,
            TransportEndpointFailureKind::RetryableUnavailable,
            Some(TransportEndpointRejectionCategory::RateLimited),
            false,
        );
        let mut row = serde_json::to_value(&stored).unwrap();
        row["target_failures"][index] = serde_json::to_value(&answer).unwrap();
        assert!(!row.to_string().contains("pre_send"), "{name}: no proof field");
        let legacy: cgka_traits::OutboundFanout = serde_json::from_value(row).unwrap();
        assert!(!legacy.possible_exposure(), "{name}: the old row's bit is clear");
        alice.put_outbound_fanout(&legacy).unwrap();

        if floor_refusal {
            adapter.refuse_commits_as_too_large(vec![answered.clone()]);
        }
        fixture.wall.set(100_000 + 60 * 60);
        let mut restarted = fixture.runtime(alice, &adapter);
        let effects = restarted.resume_outbound_fanouts().await.unwrap();

        assert!(effects.pending.is_empty(), "{name}: {:?}", effects.pending);
        let stored = restarted.session().outbound_fanouts().unwrap();
        assert_eq!(stored.len(), 1, "{name}");
        assert_eq!(
            stored[0].target_status(index),
            Some(FanoutTargetStatus::PossiblyExposed),
            "{name}"
        );
        assert!(matches!(stored[0].mls_state(), FanoutMlsState::Pending(_)), "{name}");
        assert_eq!(restarted.session().epoch(&fixture.group_id).unwrap().0, 2, "{name}");
    }
}
