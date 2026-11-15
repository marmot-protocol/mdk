// mdk#2332: giving up a pending commit that reached no relay.
//
// Past the bound, a pending commit no relay accepted and none may hold was
// refused, sent nothing to, or never delivered everywhere. Once one of its
// relays answers, the device is online and the relays it never reached are
// down: they end `Abandoned` and the commit rolls back. A read of the commit
// only shows that the device is online. Whether the commit may roll back is
// the exposure record's alone, so a commit a relay may hold never rolls back
// (mdk#1577), and an offline device never gives a commit up.

/// The group's epoch state, to tell a pending commit from a rolled-back one.
fn epoch_is_pending(runtime: &FloorRuntime, fixture: &FloorFixture) -> bool {
    matches!(
        runtime.session().epoch_state(&fixture.group_id),
        Some(cgka_traits::EpochState::PendingPublish { .. })
    )
}

/// Proof 7: one relay refuses the commit for good, the other is never
/// reached. Before the bound the dead relay is only retried. Past it, the
/// refusing relay's answer to a read shows the device online, so the dead
/// relay is given up and the commit rolls back: its fanout is gone, the group
/// is back where it was, and a restart sends nothing.
#[tokio::test]
async fn a_commit_no_relay_received_rolls_back_once_another_relay_answers() {
    let refusing = TransportEndpoint("wss://abandon-refusing.example".into());
    let dead = TransportEndpoint("wss://abandon-dead.example".into());
    let (fixture, alice) = FloorFixture::new("abandon", &[&refusing, &dead]).await;
    let adapter = RecordingAdapter::default();
    adapter.script_failures(refusing.clone(), vec![blocked(&refusing)]);
    adapter.fail_endpoints_as(
        vec![dead.clone()],
        TransportEndpointFailureKind::RetryableUnavailable,
    );
    adapter.answer_read_backs(refusing.clone(), TransportReadBack::NotFound);
    let mut runtime = fixture.runtime(alice, &adapter);
    let start = fixture.wall.now().0;
    let sent = runtime.send(fixture.rename()).await.unwrap();
    assert!(sent.pending.is_empty(), "{:?}", sent.pending);
    let commit = adapter.publishes().last().unwrap().message.id.clone();
    assert_eq!(stored_status(&runtime, &refusing), Some(FanoutTargetStatus::Failed));
    assert_eq!(
        stored_status(&runtime, &dead),
        Some(FanoutTargetStatus::RetryableUnavailable)
    );

    fixture.wall.set(start + READ_BACK_BOUND_SECS - 1);
    let effects = runtime.resume_outbound_fanouts().await.unwrap();
    assert!(effects.pending.is_empty(), "{:?}", effects.pending);
    assert!(adapter.read_backs().is_empty(), "{:?}", adapter.read_backs());
    assert!(epoch_is_pending(&runtime, &fixture));

    fixture.wall.set(start + READ_BACK_BOUND_SECS);
    let effects = runtime.resume_outbound_fanouts().await.unwrap();

    assert!(
        matches!(effects.pending.as_slice(), [PendingResolution::RolledBack { .. }]),
        "{:?}",
        effects.pending
    );
    assert_eq!(
        adapter.read_backs(),
        vec![(commit, vec![refusing.clone(), dead.clone()])]
    );
    let outcome = effects.fanout.last().unwrap();
    assert!(outcome.fanout_complete, "{outcome:?}");
    assert_eq!((outcome.accepted_targets, outcome.failed_targets), (0, 2));
    assert!(runtime.session().outbound_fanouts().unwrap().is_empty());
    assert!(!epoch_is_pending(&runtime, &fixture));
    assert_ne!(
        runtime.session().group_record(&fixture.group_id).unwrap().name,
        "renamed"
    );

    drop(runtime);
    let publishes = adapter.publishes().len();
    let mut restarted = fixture.runtime(fixture.reopen(), &adapter);
    fixture.wall.set(start + 2 * HOUR);
    restarted.resume_outbound_fanouts().await.unwrap();
    assert_eq!(adapter.publishes().len(), publishes, "a restart sends nothing");
}

/// Proof 7, offline: no relay is ever reached and no read is answered, so
/// for three days the commit stays pending and its relays are retried. The
/// read that would show the device online runs at most once an hour.
#[tokio::test]
async fn an_offline_device_never_gives_up_an_unsent_commit() {
    let first = TransportEndpoint("wss://abandon-offline-1.example".into());
    let second = TransportEndpoint("wss://abandon-offline-2.example".into());
    let (fixture, alice) = FloorFixture::new("abandon-offline", &[&first, &second]).await;
    let adapter = RecordingAdapter::default();
    adapter.fail_endpoints_as(
        vec![first.clone(), second.clone()],
        TransportEndpointFailureKind::RetryableUnavailable,
    );
    let mut runtime = fixture.runtime(alice, &adapter);
    let start = fixture.wall.now().0;
    runtime.send(fixture.rename()).await.unwrap();

    for step in 0..(72 * 2) {
        fixture.wall.set(start + READ_BACK_BOUND_SECS + step * HOUR / 2);
        let effects = runtime.resume_outbound_fanouts().await.unwrap();
        assert!(effects.pending.is_empty(), "step {step}: {:?}", effects.pending);
    }

    assert!(epoch_is_pending(&runtime, &fixture));
    assert_eq!(adapter.read_backs().len(), 72, "one read an hour");
    assert_eq!(
        stored_status(&runtime, &first),
        Some(FanoutTargetStatus::RetryableUnavailable)
    );
    assert!(publishes_to(&adapter, &second) > 72 * 2, "still retried");
}

/// A relay's definitive refusal of an attempt started since the bound shows
/// the device online by itself: the relay never reached is given up in the
/// same pass, with no read.
#[tokio::test]
async fn a_refusal_since_the_bound_shows_the_device_online() {
    let refusing = TransportEndpoint("wss://abandon-late-refusal.example".into());
    let dead = TransportEndpoint("wss://abandon-late-dead.example".into());
    let (fixture, alice) = FloorFixture::new("abandon-late", &[&refusing, &dead]).await;
    let adapter = RecordingAdapter::default();
    adapter.script_failures(
        refusing.clone(),
        vec![unreachable(&refusing), blocked(&refusing)],
    );
    adapter.fail_endpoints_as(
        vec![dead.clone()],
        TransportEndpointFailureKind::RetryableUnavailable,
    );
    let mut runtime = fixture.runtime(alice, &adapter);
    let start = fixture.wall.now().0;
    runtime.send(fixture.rename()).await.unwrap();

    fixture.wall.set(start + READ_BACK_BOUND_SECS);
    let effects = runtime.resume_outbound_fanouts().await.unwrap();

    assert!(
        matches!(effects.pending.as_slice(), [PendingResolution::RolledBack { .. }]),
        "{:?}",
        effects.pending
    );
    assert!(adapter.read_backs().is_empty(), "{:?}", adapter.read_backs());
    assert!(!epoch_is_pending(&runtime, &fixture));
}

/// A relay that returns the commit to the read holds it, whatever it answered
/// before: the commit confirms instead of rolling back.
#[tokio::test]
async fn a_read_that_returns_the_unsent_commit_confirms_it() {
    let mirrored = TransportEndpoint("wss://abandon-mirrored.example".into());
    let dead = TransportEndpoint("wss://abandon-mirrored-dead.example".into());
    let (fixture, alice) = FloorFixture::new("abandon-mirrored", &[&mirrored, &dead]).await;
    let adapter = RecordingAdapter::default();
    adapter.script_failures(mirrored.clone(), vec![blocked(&mirrored)]);
    adapter.fail_endpoints_as(
        vec![dead.clone()],
        TransportEndpointFailureKind::RetryableUnavailable,
    );
    adapter.answer_read_backs(mirrored.clone(), TransportReadBack::Found);
    let mut runtime = fixture.runtime(alice, &adapter);
    let start = fixture.wall.now().0;
    runtime.send(fixture.rename()).await.unwrap();

    fixture.wall.set(start + READ_BACK_BOUND_SECS);
    let effects = runtime.resume_outbound_fanouts().await.unwrap();

    assert!(
        matches!(effects.pending.as_slice(), [PendingResolution::Confirmed { .. }]),
        "{:?}",
        effects.pending
    );
    let (fanout, index) = stored_fanout(&runtime, &mirrored);
    assert_eq!(fanout.mls_state(), FanoutMlsState::Confirmed);
    assert_eq!(
        fanout.target_acknowledgement(index),
        Some(cgka_traits::FanoutAcknowledgement::ReadBack)
    );
    assert_eq!(
        stored_status(&runtime, &dead),
        Some(FanoutTargetStatus::RetryableUnavailable),
        "a confirmed commit's unreached relay stays owed"
    );
}

/// Proof 15b past the bound: a relay that answered `rate-limited:` received
/// the commit, so its later `invalid:` keeps it possibly exposed. The other
/// relay is never reached and the device is online, yet the commit is never
/// given up; the exposed relay is only read back, and nothing rolls back on a
/// read.
#[tokio::test]
async fn a_relay_that_answered_rate_limited_keeps_an_unreached_commit_pending() {
    let limited = TransportEndpoint("wss://abandon-rate-limited.example".into());
    let dead = TransportEndpoint("wss://abandon-rate-limited-dead.example".into());
    let (fixture, alice) = FloorFixture::new("abandon-rate-limited", &[&limited, &dead]).await;
    let invalid = |endpoint: &TransportEndpoint| TransportEndpointFailure {
        endpoint: endpoint.clone(),
        reason: "scripted".into(),
        kind: TransportEndpointFailureKind::TerminalRejected,
        rejection_category: Some(TransportEndpointRejectionCategory::Invalid),
        size_class: None,
        pre_send: false,
    };
    let adapter = RecordingAdapter::default();
    // The limited relay refuses every later attempt as `invalid:`.
    let mut answers = vec![rate_limited(&limited)];
    answers.extend(std::iter::repeat_with(|| invalid(&limited)).take(16));
    adapter.script_failures(limited.clone(), answers);
    adapter.fail_endpoints_as(
        vec![dead.clone()],
        TransportEndpointFailureKind::RetryableUnavailable,
    );
    adapter.answer_read_backs(limited.clone(), TransportReadBack::NotFound);
    adapter.answer_read_backs(dead.clone(), TransportReadBack::NotFound);
    let mut runtime = fixture.runtime(alice, &adapter);
    let start = fixture.wall.now().0;
    runtime.send(fixture.rename()).await.unwrap();

    for at in [start + 60, start + READ_BACK_BOUND_SECS, start + 3 * HOUR] {
        fixture.wall.set(at);
        let effects = runtime.resume_outbound_fanouts().await.unwrap();
        assert!(effects.pending.is_empty(), "{:?}", effects.pending);
    }

    assert!(epoch_is_pending(&runtime, &fixture));
    assert_eq!(
        stored_status(&runtime, &limited),
        Some(FanoutTargetStatus::PossiblyExposed)
    );
    assert!(
        adapter
            .read_backs()
            .iter()
            .all(|(_, endpoints)| endpoints == std::slice::from_ref(&limited)),
        "{:?}",
        adapter.read_backs()
    );
}

/// The orchestrator's slice-3 note: a release before the exposure bit stored
/// a relay's retryable answer as `RetryableUnavailable` with the bit clear.
/// That status records that the relay received the commit, so the commit is
/// never given up, even with the device online and every other relay
/// refusing it.
#[tokio::test]
async fn a_relay_stored_before_the_exposure_bit_keeps_the_commit_pending() {
    let legacy = TransportEndpoint("wss://abandon-legacy.example".into());
    let refusing = TransportEndpoint("wss://abandon-legacy-refusing.example".into());
    let (fixture, alice) = FloorFixture::new("abandon-legacy", &[&legacy, &refusing]).await;
    let adapter = RecordingAdapter::default();
    adapter.script_failures(legacy.clone(), vec![unreachable(&legacy)]);
    adapter.script_failures(refusing.clone(), vec![blocked(&refusing)]);
    adapter.answer_read_backs(legacy.clone(), TransportReadBack::NotFound);
    adapter.answer_read_backs(refusing.clone(), TransportReadBack::NotFound);
    let mut runtime = fixture.runtime(alice, &adapter);
    let start = fixture.wall.now().0;
    runtime.send(fixture.rename()).await.unwrap();

    // Past the bound, store the legacy relay's last attempt as that release
    // did: just made, answered `rate-limited:`, the bit clear. It is not due
    // again for a few seconds, so this pass does not retry it.
    let now = start + READ_BACK_BOUND_SECS + 1;
    fixture.wall.set(now);
    let (mut fanout, index) = stored_fanout(&runtime, &legacy);
    assert!(fanout.mark_attempt_started_at(index, now * 1_000).unwrap());
    runtime.session().put_outbound_fanout(&fanout).unwrap();
    let mut stored = serde_json::to_value(&fanout).unwrap();
    stored["target_statuses"][index] =
        serde_json::to_value(FanoutTargetStatus::RetryableUnavailable).unwrap();
    stored["target_failures"][index] = serde_json::to_value(rate_limited(&legacy)).unwrap();
    assert_eq!(
        stored["target_possible_exposure"][index],
        serde_json::Value::Bool(false),
        "the old row's bit is clear"
    );
    let stored: OutboundFanout = serde_json::from_value(stored).unwrap();
    runtime.session().put_outbound_fanout(&stored).unwrap();
    let publishes = adapter.publishes().len();

    let effects = runtime.resume_outbound_fanouts().await.unwrap();

    assert!(effects.pending.is_empty(), "{:?}", effects.pending);
    assert!(epoch_is_pending(&runtime, &fixture));
    assert_eq!(adapter.publishes().len(), publishes, "nothing was due");
    assert!(adapter.read_backs().is_empty(), "{:?}", adapter.read_backs());
    let (fanout, index) = stored_fanout(&runtime, &legacy);
    assert_eq!(
        fanout.target_status(index),
        Some(FanoutTargetStatus::RetryableUnavailable)
    );
    assert!(fanout.target_may_hold_event(index));
}
