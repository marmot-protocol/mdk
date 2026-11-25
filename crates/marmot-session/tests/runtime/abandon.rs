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
/// is back where it was, and a restart sends nothing. The audit records it
/// given up, and never stuck: no relay may hold it (mdk#3460).
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
    let audit_path = fixture.alice_path.with_extension("audit.jsonl");
    runtime.audit_recorder().swap(v5_audit_recorder(&audit_path));
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
        vec![(commit.clone(), vec![refusing.clone(), dead.clone()])]
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
    assert_eq!(
        pending_commit_changes(&audit_path, &fixture.group_id, &commit),
        [("given_up".into(), READ_BACK_BOUND_SECS)]
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
    let pending = pending_commit(&runtime, &fixture);
    assert_eq!(pending.state, PendingCommitState::Sending, "no relay may hold it");
    assert!(pending.unconfirmed_endpoints.is_empty());
    assert_eq!(pending.owed_endpoints, vec![first.clone(), second.clone()]);
    assert_eq!(adapter.read_backs().len(), 72, "one read an hour");
    assert_eq!(
        stored_status(&runtime, &first),
        Some(FanoutTargetStatus::RetryableUnavailable)
    );
    assert!(publishes_to(&adapter, &second) > 72 * 2, "still retried");
}

/// The hourly read is recorded before it is sent: a device that stops while
/// the read is in flight does not read again until the hour is up.
#[tokio::test]
async fn an_interrupted_online_read_waits_out_its_hour() {
    let first = TransportEndpoint("wss://abandon-interrupted-1.example".into());
    let second = TransportEndpoint("wss://abandon-interrupted-2.example".into());
    let (fixture, alice) = FloorFixture::new("abandon-interrupted", &[&first, &second]).await;
    let adapter = RecordingAdapter::default();
    adapter.fail_endpoints_as(
        vec![first.clone(), second.clone()],
        TransportEndpointFailureKind::RetryableUnavailable,
    );
    let mut runtime = fixture.runtime(alice, &adapter);
    let start = fixture.wall.now().0;
    runtime.send(fixture.rename()).await.unwrap();

    fixture.wall.set(start + READ_BACK_BOUND_SECS);
    adapter.stall_read_backs(true);
    {
        let pass = runtime.resume_outbound_fanouts();
        tokio::pin!(pass);
        while adapter.read_backs().is_empty() {
            tokio::select! {
                biased;
                _ = &mut pass => panic!("the stalled read never answers"),
                () = tokio::task::yield_now() => {}
            }
        }
    }
    drop(runtime);
    adapter.stall_read_backs(false);
    adapter.answer_read_backs(first.clone(), TransportReadBack::NotFound);

    let mut restarted = fixture.runtime(fixture.reopen(), &adapter);
    fixture.wall.set(start + READ_BACK_BOUND_SECS + HOUR - 1);
    let effects = restarted.resume_outbound_fanouts().await.unwrap();
    assert!(effects.pending.is_empty(), "{:?}", effects.pending);
    assert_eq!(adapter.read_backs().len(), 1, "no second read within the hour");
    assert!(epoch_is_pending(&restarted, &fixture));

    fixture.wall.set(start + READ_BACK_BOUND_SECS + HOUR);
    let effects = restarted.resume_outbound_fanouts().await.unwrap();
    assert_eq!(adapter.read_backs().len(), 2);
    assert!(
        matches!(effects.pending.as_slice(), [PendingResolution::RolledBack { .. }]),
        "{:?}",
        effects.pending
    );
}

/// A queued change whose commit reached no relay is given up after a restart
/// too, and retired: its frozen fanout names the intent it was drained from,
/// so the rollback records and announces it as `not_delivered` and nothing
/// sends it again.
#[tokio::test]
async fn a_queued_change_given_up_after_a_restart_is_retired() {
    let refusing = TransportEndpoint("wss://abandon-queued-refusing.example".into());
    let dead = TransportEndpoint("wss://abandon-queued-dead.example".into());
    let (fixture, alice) = FloorFixture::new("abandon-queued", &[&refusing, &dead]).await;
    let adapter = RecordingAdapter::default();
    // The refusing relay takes the queued message and refuses the change.
    adapter.script_commit_failures(refusing.clone(), vec![blocked(&refusing)]);
    adapter.fail_endpoints_as(
        vec![dead.clone()],
        TransportEndpointFailureKind::RetryableUnavailable,
    );
    adapter.answer_read_backs(refusing.clone(), TransportReadBack::NotFound);
    let mut runtime = fixture.runtime(alice, &adapter);
    let start = fixture.wall.now().0;
    let sender = hex::encode(runtime.session().self_id().as_slice());
    runtime
        .queue_app_message_with_audit_context(
            fixture.group_id.clone(),
            app_payload_for(&sender, b"queued first"),
            None,
            Default::default())
        .await
        .unwrap();
    // A change sent behind a queued send waits in the queue too (mdk#2842).
    let queued = runtime.send(fixture.rename()).await.unwrap();
    let [intent] = queued.queued.as_slice() else {
        panic!("the change is queued: {queued:?}")
    };
    let intent_id = intent.intent_id.clone();
    let drained = runtime.advance_convergence(&fixture.group_id).await.unwrap();
    runtime
        .acknowledge_published_app_messages(&drained.published_app_messages)
        .unwrap();
    assert!(
        !adapter.commit_publishes().is_empty(),
        "the drained change was sent"
    );
    let staged = runtime
        .session()
        .outbound_fanouts()
        .unwrap()
        .into_iter()
        .find(|fanout| matches!(fanout.mls_state(), FanoutMlsState::Pending(_)))
        .expect("the drained commit is pending");
    assert_eq!(staged.queued_intent_id(), Some(&intent_id));
    let pending = pending_commit(&runtime, &fixture);
    assert_eq!(
        pending.origin,
        Some(cgka_traits::storage::ChangeOrigin::QueuedIntent {
            intent_id: intent_id.clone(),
        })
    );
    assert_eq!(pending.intent_kind.as_deref(), Some("update_group_data"));
    drop(runtime);

    let mut restarted = fixture.runtime(fixture.reopen(), &adapter);
    fixture.wall.set(start + READ_BACK_BOUND_SECS);
    let effects = restarted.resume_outbound_fanouts().await.unwrap();

    assert!(
        matches!(effects.pending.as_slice(), [PendingResolution::RolledBack { .. }]),
        "{:?}",
        effects.pending
    );
    assert!(
        effects.events.iter().any(|event| matches!(
            event,
            GroupEvent::QueuedIntentRefused { intent_id: refused, reason, .. }
                if refused == &intent_id && reason == "not_delivered"
        )),
        "{:?}",
        effects.events
    );
    assert!(
        !effects
            .events
            .iter()
            .any(|event| matches!(event, GroupEvent::GroupChangeNotDelivered { .. })),
        "a queued change is announced as refused only"
    );
    let records = restarted
        .group_changes_not_delivered(&fixture.group_id)
        .unwrap();
    assert!(
        matches!(
            records.as_slice(),
            [cgka_traits::storage::ChangeNotDelivered {
                commit_id,
                origin: cgka_traits::storage::ChangeOrigin::QueuedIntent { intent_id: retired },
                intent_kind,
                reason,
                ..
            }] if commit_id == staged.message_id()
                && *retired == intent_id
                && intent_kind == "update_group_data"
                && reason == "not_delivered"
        ),
        "the retirement records the change not delivered: {records:?}"
    );
    assert!(
        !restarted
            .has_queued_outbound_intents(&fixture.group_id)
            .unwrap()
    );
    let commits = adapter.commit_publishes().len();
    restarted
        .advance_convergence(&fixture.group_id)
        .await
        .unwrap();
    assert_eq!(
        adapter.commit_publishes().len(),
        commits,
        "the retired change is not sent again"
    );
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
/// read. The host reads it `Sending`, then `Stuck` from the bound, with the
/// limited relay both unconfirmed and refused.
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
    let commit = adapter.publishes().last().unwrap().message.id.clone();
    let sending = pending_commit(&runtime, &fixture);
    assert_eq!(
        (sending.message_id, sending.origin, sending.intent_kind),
        (commit, None, None),
        "an automatic commit names no change"
    );
    assert_eq!(sending.first_attempt_at.map(|at| at.0), Some(start));
    assert_eq!(sending.state, PendingCommitState::Sending);
    assert_eq!(sending.unconfirmed_endpoints, vec![limited.clone()]);
    assert_eq!(sending.owed_endpoints, vec![dead.clone()]);
    assert!(sending.refused_endpoints.is_empty(), "rate-limited is no final answer");
    assert_eq!(sending.endpoint_count, 2);

    // Proof 16: `Stuck` from the bound past the first attempt, though the
    // last attempt was a second earlier.
    let mut states = Vec::new();
    for at in [
        start + 60,
        start + READ_BACK_BOUND_SECS - 1,
        start + READ_BACK_BOUND_SECS,
        start + 3 * HOUR,
    ] {
        fixture.wall.set(at);
        let effects = runtime.resume_outbound_fanouts().await.unwrap();
        assert!(effects.pending.is_empty(), "{:?}", effects.pending);
        states.push(pending_commit(&runtime, &fixture).state);
    }
    assert_eq!(
        states,
        [
            PendingCommitState::Sending,
            PendingCommitState::Sending,
            PendingCommitState::Stuck,
            PendingCommitState::Stuck,
        ]
    );
    let stuck = pending_commit(&runtime, &fixture);
    assert_eq!(stuck.unconfirmed_endpoints, vec![limited.clone()]);
    assert_eq!(stuck.owed_endpoints, vec![dead.clone()]);
    assert_eq!(
        stuck.refused_endpoints,
        vec![refused(&limited, CommitRefusalCause::Rejected)],
        "the latest final answer, from a relay that may still hold the commit"
    );

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
