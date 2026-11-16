// mdk#2332: reading a pending commit back from its relays.
//
// For ten minutes after a pending commit's first send attempt, a relay that
// may hold it is only resent to. From then on, each retry of such a relay
// reads the commit back first. A relay that returns the exact event holds it,
// so it counts as having acknowledged the commit, and the commit confirms.
// Any other answer changes nothing, and the relay is resent to as before. A
// read never rolls a commit back.

/// The bound past a pending commit's first send attempt, in seconds.
const READ_BACK_BOUND_SECS: u64 = 10 * 60;

/// The group's own commit that the test expects to be pending.
fn pending_commit(runtime: &FloorRuntime, fixture: &FloorFixture) -> PendingCommit {
    runtime
        .pending_commit(&fixture.group_id)
        .unwrap()
        .expect("the commit is pending")
}

/// Proofs 1, 6 and 16: four relays, three of which may hold the commit.
/// - `sized` timed out, then answered that the commit is too large;
/// - `blocking` timed out, then answered `blocked:`;
/// - `serving` stays ambiguous;
/// - `offline` was never reached.
///
/// A retry a second before the bound only resends. Past the bound, a pass
/// that retries only `offline` reads nothing: a relay is read only when its
/// own retry is due. The next retry of the three, a minute after their last
/// attempt, reads them back first; the bound counts from the first attempt,
/// not the last. `serving` returns the commit and confirms it. The relay
/// that was never reached is not read. At
/// confirmation, the size answer after ambiguity ends `sized` refused with
/// no size class, and `blocking` stays owed (mdk#2333). A confirmed
/// commit's owed relay is resent to, never read.
#[tokio::test]
async fn a_read_back_past_the_bound_confirms_a_pending_commit() {
    let sized = TransportEndpoint("wss://read-sized.example".into());
    let blocking = TransportEndpoint("wss://read-blocking.example".into());
    let serving = TransportEndpoint("wss://read-serving.example".into());
    let offline = TransportEndpoint("wss://read-offline.example".into());
    let (fixture, alice) =
        FloorFixture::new("read-back", &[&sized, &blocking, &serving, &offline]).await;
    let adapter = RecordingAdapter::default();
    let mut runtime = fixture.runtime(alice, &adapter);
    adapter.fail_endpoints_as(
        vec![sized.clone(), blocking.clone(), serving.clone()],
        TransportEndpointFailureKind::PossiblyExposed,
    );
    adapter.script_failures(
        sized.clone(),
        vec![timed_out(&sized), strfry_too_large(&sized), strfry_too_large(&sized)],
    );
    adapter.script_failures(
        blocking.clone(),
        vec![
            timed_out(&blocking),
            blocked(&blocking),
            blocked(&blocking),
            blocked(&blocking),
        ],
    );
    adapter.script_failures(offline.clone(), vec![unreachable(&offline); 8]);
    adapter.answer_read_backs(sized.clone(), TransportReadBack::NotFound);
    adapter.answer_read_backs(serving.clone(), TransportReadBack::Found);
    adapter.answer_read_backs(offline.clone(), TransportReadBack::Found);

    let start = fixture.wall.now().0;
    let sent = runtime.send(fixture.rename()).await.unwrap();
    assert!(sent.pending.is_empty(), "{:?}", sent.pending);
    let commit = adapter.publishes().last().unwrap().message.id.clone();

    fixture.wall.set(start + READ_BACK_BOUND_SECS - 1);
    let effects = runtime.resume_outbound_fanouts().await.unwrap();
    assert!(effects.pending.is_empty(), "{:?}", effects.pending);
    assert!(adapter.read_backs().is_empty(), "{:?}", adapter.read_backs());
    assert_eq!(
        stored_status(&runtime, &sized),
        Some(FanoutTargetStatus::PossiblyExposed)
    );

    fixture.wall.set(start + READ_BACK_BOUND_SECS + 20);
    runtime.resume_outbound_fanouts().await.unwrap();
    assert!(adapter.read_backs().is_empty(), "{:?}", adapter.read_backs());

    fixture.wall.set(start + READ_BACK_BOUND_SECS - 1 + 60);
    let effects = runtime.resume_outbound_fanouts().await.unwrap();

    assert_eq!(
        adapter.read_backs(),
        vec![(commit, vec![sized.clone(), blocking.clone(), serving.clone()])]
    );
    assert!(
        matches!(effects.pending.as_slice(), [PendingResolution::Confirmed { .. }]),
        "{:?}",
        effects.pending
    );
    let (fanout, index) = stored_fanout(&runtime, &serving);
    assert_eq!(fanout.mls_state(), FanoutMlsState::Confirmed);
    assert_eq!(fanout.target_status(index), Some(FanoutTargetStatus::Accepted));
    assert_eq!(
        fanout.target_acknowledgement(index),
        Some(cgka_traits::FanoutAcknowledgement::ReadBack)
    );
    assert_eq!(stored_status(&runtime, &sized), Some(FanoutTargetStatus::Failed));
    assert_eq!(
        reported_refusals(&runtime, &fixture),
        vec![refused(&sized, too_large(None))]
    );
    assert_eq!(
        stored_status(&runtime, &blocking),
        Some(FanoutTargetStatus::PossiblyExposed)
    );
    assert_eq!(
        stored_status(&runtime, &offline),
        Some(FanoutTargetStatus::RetryableUnavailable)
    );

    let resent = publishes_to(&adapter, &blocking);
    fixture.wall.set(start + 2 * HOUR);
    runtime.resume_outbound_fanouts().await.unwrap();
    assert!(publishes_to(&adapter, &blocking) > resent);
    assert_eq!(adapter.read_backs().len(), 1, "{:?}", adapter.read_backs());
}

/// A hit confirms the commit in the pass that reads it, even with nothing
/// left to send, and the relay that returned it is not resent to. The audit
/// records the commit stuck as it is read, then confirmed by the read
/// (mdk#3460).
#[tokio::test]
async fn a_read_back_hit_confirms_without_a_resend() {
    let relay = TransportEndpoint("wss://read-hit.example".into());
    let (fixture, alice) = FloorFixture::new("read-back-hit", &[&relay]).await;
    let adapter = RecordingAdapter::default();
    let mut runtime = fixture.runtime(alice, &adapter);
    let audit_path = fixture.alice_path.with_extension("audit.jsonl");
    runtime.audit_recorder().swap(v5_audit_recorder(&audit_path));
    adapter.fail_endpoints_as(
        vec![relay.clone()],
        TransportEndpointFailureKind::PossiblyExposed,
    );
    adapter.answer_read_backs(relay.clone(), TransportReadBack::Found);
    let start = fixture.wall.now().0;
    runtime.send(fixture.rename()).await.unwrap();
    let commit = adapter.publishes().last().unwrap().message.id.clone();

    fixture.wall.set(start + HOUR);
    let effects = runtime.resume_outbound_fanouts().await.unwrap();

    assert!(
        matches!(effects.pending.as_slice(), [PendingResolution::Confirmed { .. }]),
        "{:?}",
        effects.pending
    );
    assert_eq!(adapter.read_backs().len(), 1, "{:?}", adapter.read_backs());
    assert_eq!(publishes_to(&adapter, &relay), 1);
    assert_eq!(runtime.pending_commit(&fixture.group_id).unwrap(), None);
    assert_eq!(
        pending_commit_changes(&audit_path, &fixture.group_id, &commit),
        [("stuck".into(), HOUR), ("read_back_confirmed".into(), HOUR)]
    );
}

/// mdk#3460: a stuck commit is audited once, at its first read-back. Later
/// reads, and a restart that reads it again, record nothing more, and
/// confirmation by a resend's `OK` adds no pending-commit row: the commit's
/// publish rows show that.
#[tokio::test]
async fn a_stuck_commit_is_audited_once() {
    let relay = TransportEndpoint("wss://read-audit.example".into());
    let (fixture, alice) = FloorFixture::new("read-back-audit", &[&relay]).await;
    let adapter = RecordingAdapter::default();
    adapter.script_failures(relay.clone(), vec![timed_out(&relay); 4]);
    adapter.answer_read_backs(relay.clone(), TransportReadBack::NotFound);
    let mut runtime = fixture.runtime(alice, &adapter);
    let audit_path = fixture.alice_path.with_extension("audit.jsonl");
    runtime.audit_recorder().swap(v5_audit_recorder(&audit_path));
    let start = fixture.wall.now().0;
    runtime.send(fixture.rename()).await.unwrap();
    let commit = adapter.publishes().last().unwrap().message.id.clone();

    for hours in [1, 2] {
        fixture.wall.set(start + hours * HOUR);
        runtime.resume_outbound_fanouts().await.unwrap();
    }
    drop(runtime);
    let mut restarted = fixture.runtime(fixture.reopen(), &adapter);
    let restarted_path = fixture.alice_path.with_extension("restarted-audit.jsonl");
    restarted
        .audit_recorder()
        .swap(v5_audit_recorder(&restarted_path));
    fixture.wall.set(start + 3 * HOUR);
    restarted.resume_outbound_fanouts().await.unwrap();
    fixture.wall.set(start + 4 * HOUR);
    let effects = restarted.resume_outbound_fanouts().await.unwrap();

    assert!(
        matches!(effects.pending.as_slice(), [PendingResolution::Confirmed { .. }]),
        "{:?}",
        effects.pending
    );
    // Every read missed: the fifth send's `OK` confirmed it.
    assert_eq!(adapter.read_backs().len(), 4, "{:?}", adapter.read_backs());
    assert_eq!(publishes_to(&adapter, &relay), 5);
    assert_eq!(
        pending_commit_changes(&audit_path, &fixture.group_id, &commit),
        [("stuck".into(), HOUR)]
    );
    assert!(
        pending_commit_changes(&restarted_path, &fixture.group_id, &commit).is_empty()
    );
}

/// Proof 16: the bound counts from when the first attempt was sent, after its
/// size check, however long the check took. A commit whose check took eleven
/// minutes is not read back a minute after it was sent, and still reads
/// `Sending`.
#[tokio::test]
async fn the_bound_counts_from_the_send_after_a_slow_size_check() {
    let relay = TransportEndpoint("wss://read-slow-check.example".into());
    let (fixture, alice) = FloorFixture::new("read-back-slow-check", &[&relay]).await;
    let adapter = RecordingAdapter::default();
    let mut runtime = fixture.runtime(alice, &adapter);
    adapter.fail_endpoints_as(
        vec![relay.clone()],
        TransportEndpointFailureKind::PossiblyExposed,
    );
    adapter.answer_read_backs(relay.clone(), TransportReadBack::Found);
    let start = fixture.wall.now().0;
    let sent = start + READ_BACK_BOUND_SECS + 60;
    adapter.slow_next_commit_size_check(fixture.wall.clone(), sent - start);
    runtime.send(fixture.rename()).await.unwrap();

    let (fanout, _) = stored_fanout(&runtime, &relay);
    assert_eq!(fanout.first_attempt_at_ms(), Some(sent * 1_000));
    fixture.wall.set(sent + 60);
    let effects = runtime.resume_outbound_fanouts().await.unwrap();
    assert!(effects.pending.is_empty(), "{:?}", effects.pending);
    assert!(adapter.read_backs().is_empty(), "{:?}", adapter.read_backs());
    assert_eq!(publishes_to(&adapter, &relay), 2);
    // Stuck counts from the send too: the commit was staged eleven minutes ago.
    let pending = pending_commit(&runtime, &fixture);
    assert_eq!(pending.first_attempt_at.map(|at| at.0), Some(sent));
    assert_eq!(pending.state, PendingCommitState::Sending);
}

/// Proofs 2 and 12: a relay that never returns the commit, whether it ends
/// each read (`NotFound`) or answers none (`NoAnswer`, all an adapter without
/// read-back gives). For 72 hours the commit stays pending and never rolls
/// back, the relay stays possibly exposed, and every retry past the bound
/// reads it and then resends, on the backoff a commit had before read-back:
/// 30 seconds, doubling to an hour. The host reads it `Stuck`, held by that
/// relay.
#[tokio::test]
async fn a_read_back_miss_changes_nothing() {
    let mut schedules = Vec::new();
    for answer in [TransportReadBack::NotFound, TransportReadBack::NoAnswer] {
        let relay = TransportEndpoint("wss://read-miss.example".into());
        let (fixture, alice) = FloorFixture::new("read-back-miss", &[&relay]).await;
        let adapter = RecordingAdapter::default();
        let mut runtime = fixture.runtime(alice, &adapter);
        adapter.fail_endpoints_as(
            vec![relay.clone()],
            TransportEndpointFailureKind::PossiblyExposed,
        );
        adapter.answer_read_backs(relay.clone(), answer);
        let start = fixture.wall.now().0;
        runtime.send(fixture.rename()).await.unwrap();

        let mut sends = vec![0];
        while fixture.wall.now().0 < start + 72 * HOUR {
            let delay_ms = runtime
                .outbound_fanout_retry_delay_ms(&fixture.group_id)
                .unwrap()
                .expect("the commit stays scheduled");
            fixture
                .wall
                .set(fixture.wall.now().0 + delay_ms.div_ceil(1_000).max(1));
            let published = adapter.publishes().len();
            let effects = runtime.resume_outbound_fanouts().await.unwrap();
            assert!(effects.pending.is_empty(), "{answer:?}: {:?}", effects.pending);
            assert_eq!(adapter.publishes().len(), published + 1, "{answer:?}");
            sends.push(fixture.wall.now().0 - start);
        }

        let past_bound = sends
            .iter()
            .filter(|&&sent| sent >= READ_BACK_BOUND_SECS)
            .count();
        assert_eq!(adapter.read_backs().len(), past_bound, "{answer:?}");
        let (fanout, index) = stored_fanout(&runtime, &relay);
        assert!(
            matches!(fanout.mls_state(), FanoutMlsState::Pending(_)),
            "{answer:?}"
        );
        assert_eq!(
            fanout.target_status(index),
            Some(FanoutTargetStatus::PossiblyExposed),
            "{answer:?}"
        );
        assert_eq!(fanout.first_attempt_at_ms(), Some(start * 1_000), "{answer:?}");
        let stuck = pending_commit(&runtime, &fixture);
        assert_eq!(stuck.state, PendingCommitState::Stuck, "{answer:?}");
        assert_eq!(stuck.unconfirmed_endpoints, vec![relay.clone()], "{answer:?}");
        assert!(stuck.owed_endpoints.is_empty(), "{answer:?}");
        assert!(stuck.refused_endpoints.is_empty(), "{answer:?}");
        schedules.push(sends);
    }
    assert_eq!(schedules[0], schedules[1]);
    let gaps = schedules[0]
        .windows(2)
        .map(|pair| pair[1] - pair[0])
        .collect::<Vec<_>>();
    assert_eq!(gaps[..7], [30, 60, 120, 240, 480, 960, 1920]);
    assert!(gaps[7..].iter().all(|&gap| gap == HOUR), "{gaps:?}");
}

/// Only a pending commit is read back. A group creation is pending too,
/// until its first Welcome is accepted, but that Welcome went to an
/// invitee's inbox: a relay that may hold it is resent to past the bound,
/// never read.
#[tokio::test]
async fn only_a_pending_commit_is_read_back() {
    let dir = relaxed_storage_dir().unwrap();
    let key = SqlCipherKey::new("marmot read-back create key").unwrap();
    let mut bob = session(dir.path().join("bob.sqlite"), &key, b"bob");
    let bob_key_package = bob.fresh_key_package().await.unwrap();
    let inbox = TransportEndpoint("wss://read-bob-inbox.example".into());
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://read-alice-inbox.example".into())])
            .with_inbox_route(bob.self_id(), vec![inbox.clone()]);
    let adapter = RecordingAdapter::default();
    adapter.fail_endpoints_as(
        vec![inbox.clone()],
        TransportEndpointFailureKind::PossiblyExposed,
    );
    adapter.answer_read_backs(inbox.clone(), TransportReadBack::Found);
    let wall = Arc::new(TestWallClock::new(100_000));
    let mut runtime = AccountDeviceRuntime::new(
        session(dir.path().join("alice.sqlite"), &key, b"alice"),
        adapter.clone(),
        policy,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        wall.clone(),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );
    let (_, effects) = runtime
        .create_group(CreateGroupRequest {
            name: "read-back create".into(),
            description: String::new(),
            members: vec![bob_key_package],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    assert!(effects.pending.is_empty(), "{:?}", effects.pending);

    wall.set(100_000 + 2 * HOUR);
    let effects = runtime.resume_outbound_fanouts().await.unwrap();

    assert!(effects.pending.is_empty(), "{:?}", effects.pending);
    assert_eq!(publishes_to(&adapter, &inbox), 2);
    assert!(adapter.read_backs().is_empty(), "{:?}", adapter.read_backs());
}

/// Rule 4 of mdk#2602 for the pending-commit read: the engine hides a
/// non-live group's fanouts, so the read checks liveness first rather than
/// report a group with a stored pending commit as having none. After a
/// restart, the seeded group fails with the retryable `GroupNotHydrated`
/// and answers once hydrated; a group that quarantines on hydration fails
/// with `UnknownGroup`.
#[tokio::test]
async fn the_pending_commit_read_answers_only_for_a_live_group() {
    let (fixture, alice) = FloorFixture::new(
        "pending-commit-liveness",
        &[
            &TransportEndpoint("wss://echo-a.example".into()),
            &TransportEndpoint("wss://echo-b.example".into()),
        ],
    )
    .await;
    let adapter = RecordingAdapter::default();
    let commit = rename_left_pending(&fixture, alice, &adapter).await;

    let mut runtime = reopened_seeded(&fixture, &adapter);
    let error = runtime.pending_commit(&fixture.group_id).unwrap_err();
    assert!(
        matches!(
            &error,
            AccountError::Session(SessionError::Engine(cgka_traits::EngineError::GroupNotHydrated(id)))
                if id == &fixture.group_id
        ),
        "{error:?}"
    );
    runtime.ensure_group_hydrated(&fixture.group_id).unwrap();
    assert_eq!(pending_commit(&runtime, &fixture).message_id, commit.id);
    drop(runtime);

    openmls_state::lose_openmls_group_state(
        &fixture.alice_path,
        &SqlCipherKey::new(FLOOR_KEY).unwrap(),
        &fixture.group_id,
    );
    let mut runtime = reopened_seeded(&fixture, &adapter);
    runtime.ensure_group_hydrated(&fixture.group_id).unwrap();
    assert!(runtime.unhydrated_group_ids().is_empty());
    let error = runtime.pending_commit(&fixture.group_id).unwrap_err();
    assert!(
        matches!(
            &error,
            AccountError::Session(SessionError::Engine(cgka_traits::EngineError::UnknownGroup(id)))
                if id == &fixture.group_id
        ),
        "{error:?}"
    );
}
