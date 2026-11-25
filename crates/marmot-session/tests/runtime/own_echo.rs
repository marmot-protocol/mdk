// mdk#2332: the account's own echo of a pending commit.
//
// The account's subscription receiving its pending commit's exact event from
// one of the commit's relays shows that relay holds it, whatever the relay
// answered the publish. The relay counts as having acknowledged the commit,
// and the commit confirms. A copy under another event id, or from a relay that
// is not a target, shows nothing. The account already holds the event, so a
// host that skips held events before ingest asks `takes_own_echo` first, which
// passes exactly the copies that acknowledge a relay.

/// `message` as the account's group subscription receives it from `endpoint`.
fn group_delivery(
    runtime: &FloorRuntime,
    fixture: &FloorFixture,
    message: &TransportMessage,
    endpoint: Option<&str>,
) -> TransportDelivery {
    TransportDelivery {
        account_id: runtime.session().self_id(),
        group_id_hint: Some(fixture.group_id.clone()),
        message: message.clone(),
        received_at: Timestamp(0),
        source: TransportDeliverySource {
            transport: TransportSource("own-echo-test".into()),
            plane: TransportDeliveryPlane::Group,
            endpoint: endpoint.map(|endpoint| TransportEndpoint(endpoint.into())),
            subscription_id: None,
            wire: None,
        },
    }
}

/// Proofs 5 and 14: one relay's publish was ambiguous and the other refused
/// it outright, so the commit waits. Its echo from the refusing relay, in
/// another spelling of that relay's URL, confirms it; the relay is
/// `Accepted` by its echo, and the ambiguous relay stays owed. The audit
/// records that the echo confirmed it.
#[tokio::test]
async fn an_own_echo_from_a_target_relay_confirms_a_pending_commit() {
    let ambiguous = TransportEndpoint("wss://echo-a.example".into());
    let refusing = TransportEndpoint("wss://echo-b.example".into());
    let (fixture, alice) = FloorFixture::new("own-echo", &[&ambiguous, &refusing]).await;
    let adapter = RecordingAdapter::default();
    let mut runtime = fixture.runtime(alice, &adapter);
    let audit_path = fixture.alice_path.with_extension("audit.jsonl");
    runtime.audit_recorder().swap(v5_audit_recorder(&audit_path));
    // An earlier message of Alice's own, delivered before the commit.
    let alice_hex = hex::encode(runtime.session().self_id().as_slice());
    let earlier = runtime
        .send(SendIntent::AppMessage {
            group_id: fixture.group_id.clone(),
            payload: app_payload_for(&alice_hex, b"before the rename"),
            expected_epoch: None,
            only_to_members: None,
        })
        .await
        .unwrap();
    runtime
        .acknowledge_published_app_messages(&earlier.published_app_messages)
        .unwrap();
    let earlier = adapter.publishes()[0].message.clone();
    adapter.script_failures(ambiguous.clone(), vec![timed_out(&ambiguous)]);
    adapter.script_failures(refusing.clone(), vec![blocked(&refusing)]);

    let sent = runtime.send(fixture.rename()).await.unwrap();
    assert!(sent.pending.is_empty(), "{:?}", sent.pending);
    assert_eq!(stored_status(&runtime, &refusing), Some(FanoutTargetStatus::Failed));
    let commit = adapter.publishes().last().unwrap().message.clone();
    assert_ne!(commit.id, earlier.id);

    let mut rewrapped = commit.clone();
    rewrapped.id = MessageId::new(vec![0xEE; 32]);
    for (message, endpoint, case) in [
        (&earlier, Some("wss://echo-b.example"), "another own event"),
        (&rewrapped, Some("wss://echo-b.example"), "another event id"),
        (&commit, Some("wss://echo-elsewhere.example"), "not a target"),
        (&commit, None, "no relay"),
    ] {
        let delivery = group_delivery(&runtime, &fixture, message, endpoint);
        // A host that skips held events may skip this copy: it acknowledges nothing.
        assert!(!runtime.takes_own_echo(&delivery).unwrap(), "{case}");
        let ingested = runtime.ingest_delivery(&delivery).await.unwrap();
        assert!(ingested.effects.pending.is_empty(), "{case}");
        assert_eq!(
            stored_status(&runtime, &refusing),
            Some(FanoutTargetStatus::Failed),
            "{case}"
        );
        assert!(
            matches!(stored_fanout(&runtime, &refusing).0.mls_state(), FanoutMlsState::Pending(_)),
            "{case}"
        );
    }

    let delivery = group_delivery(&runtime, &fixture, &commit, Some("wss://ECHO-B.example:443/"));
    // The account holds this event too, but a host must still pass this copy.
    assert!(runtime.takes_own_echo(&delivery).unwrap());
    let ingested = runtime.ingest_delivery(&delivery).await.unwrap();

    assert_eq!(
        ingested.outcome,
        cgka_traits::IngestOutcome::Ignored {
            category: cgka_traits::ingest::InputRejectionCategory::OwnEcho
        }
    );
    assert!(
        matches!(ingested.effects.pending.as_slice(), [PendingResolution::Confirmed { .. }]),
        "{:?}",
        ingested.effects.pending
    );
    let (fanout, index) = stored_fanout(&runtime, &refusing);
    assert_eq!(fanout.mls_state(), FanoutMlsState::Confirmed);
    assert_eq!(fanout.target_status(index), Some(FanoutTargetStatus::Accepted));
    assert_eq!(
        fanout.target_acknowledgement(index),
        Some(cgka_traits::FanoutAcknowledgement::Echo)
    );
    assert_eq!(
        stored_status(&runtime, &ambiguous),
        Some(FanoutTargetStatus::PossiblyExposed)
    );
    // Once the commit confirms, no copy of it acknowledges anything more.
    assert!(!runtime.takes_own_echo(&delivery).unwrap());
    let ambiguous_copy = group_delivery(&runtime, &fixture, &commit, Some("wss://echo-a.example"));
    assert!(!runtime.takes_own_echo(&ambiguous_copy).unwrap());
    // The audit records the commit confirmed by its echo (mdk#3460).
    assert_eq!(
        pending_commit_changes(&audit_path, &fixture.group_id, &commit.id),
        [("echo_confirmed".into(), 0)]
    );
}

/// mdk#3460: under a goal of two acknowledgements, a commit one relay's echo
/// acknowledged past the read-back bound is not stuck, though it is still
/// pending and the other relay is read back first in the same pass. The audit
/// records no `stuck`, as the host reads `Sending`; the pass then confirms the
/// commit on the echo it had.
#[tokio::test]
async fn an_acknowledged_commit_below_its_goal_is_not_audited_stuck() {
    let echoing = TransportEndpoint("wss://echo-goal-a.example".into());
    let silent = TransportEndpoint("wss://echo-goal-b.example".into());
    let (mut fixture, alice) = FloorFixture::new("own-echo-goal", &[&echoing, &silent]).await;
    fixture.policy = fixture.policy.clone().required_acks(2);
    let adapter = RecordingAdapter::default();
    adapter.fail_endpoints_as(
        vec![echoing.clone(), silent.clone()],
        TransportEndpointFailureKind::PossiblyExposed,
    );
    adapter.answer_read_backs(silent.clone(), TransportReadBack::NotFound);
    let mut runtime = fixture.runtime(alice, &adapter);
    let audit_path = fixture.alice_path.with_extension("audit.jsonl");
    runtime.audit_recorder().swap(v5_audit_recorder(&audit_path));
    let start = fixture.wall.now().0;
    let sent = runtime.send(fixture.rename()).await.unwrap();
    assert!(sent.pending.is_empty(), "{:?}", sent.pending);
    let commit = adapter.publishes().last().unwrap().message.clone();

    fixture.wall.set(start + READ_BACK_BOUND_SECS + 60);
    let delivery = group_delivery(&runtime, &fixture, &commit, Some("wss://echo-goal-a.example"));
    let ingested = runtime.ingest_delivery(&delivery).await.unwrap();

    assert_eq!(
        adapter.read_backs(),
        vec![(commit.id.clone(), vec![silent.clone()])],
        "the other relay is still read back"
    );
    assert!(
        matches!(ingested.effects.pending.as_slice(), [PendingResolution::Confirmed { .. }]),
        "{:?}",
        ingested.effects.pending
    );
    assert_eq!(
        pending_commit_changes(&audit_path, &fixture.group_id, &commit.id),
        [("echo_confirmed".into(), READ_BACK_BOUND_SECS + 60)]
    );
}

/// Alice renamed her group, and neither relay answered the publish, when her
/// process exited: the commit waits for a relay to show it holds the event.
/// Returns the commit.
async fn rename_left_pending(
    fixture: &FloorFixture,
    alice: AccountDeviceSession,
    adapter: &RecordingAdapter,
) -> TransportMessage {
    let ambiguous = TransportEndpoint("wss://echo-a.example".into());
    let refusing = TransportEndpoint("wss://echo-b.example".into());
    let mut runtime = fixture.runtime(alice, adapter);
    adapter.script_failures(ambiguous.clone(), vec![timed_out(&ambiguous)]);
    adapter.script_failures(refusing.clone(), vec![blocked(&refusing)]);
    let sent = runtime.send(fixture.rename()).await.unwrap();
    assert!(sent.pending.is_empty(), "{:?}", sent.pending);
    adapter.publishes().last().unwrap().message.clone()
}

/// The next process opens Alice's account as the account worker does, with
/// her group only seeded (mdk#1161).
fn reopened_seeded(fixture: &FloorFixture, adapter: &RecordingAdapter) -> FloorRuntime {
    let reopened = deferred_session(
        &fixture.alice_path,
        &SqlCipherKey::new(FLOOR_KEY).unwrap(),
        fixture.alice_seed,
    );
    let runtime = fixture.runtime(reopened, adapter);
    assert_eq!(runtime.unhydrated_group_ids(), vec![fixture.group_id.clone()]);
    runtime
}

/// Proof 5 after a restart. The engine answers the echo from its stored
/// record without hydrating the group, so the copy is judged by the group's
/// stored fanouts, without hydrating it, and its ingest hydrates the group
/// and confirms the commit.
#[tokio::test]
async fn an_own_echo_confirms_a_commit_a_previous_process_left_pending() {
    let refusing = TransportEndpoint("wss://echo-b.example".into());
    let (fixture, alice) = FloorFixture::new(
        "own-echo-restart",
        &[&TransportEndpoint("wss://echo-a.example".into()), &refusing],
    )
    .await;
    let adapter = RecordingAdapter::default();
    let commit = rename_left_pending(&fixture, alice, &adapter).await;
    let mut runtime = reopened_seeded(&fixture, &adapter);
    let delivery = group_delivery(&runtime, &fixture, &commit, Some("wss://echo-b.example"));
    assert!(runtime.takes_own_echo(&delivery).unwrap());
    assert_eq!(
        runtime.unhydrated_group_ids(),
        vec![fixture.group_id.clone()],
        "judging the copy hydrates nothing"
    );

    let ingested = runtime.ingest_delivery(&delivery).await.unwrap();
    assert!(runtime.unhydrated_group_ids().is_empty());
    assert!(
        matches!(ingested.effects.pending.as_slice(), [PendingResolution::Confirmed { .. }]),
        "{:?}",
        ingested.effects.pending
    );
    let (fanout, index) = stored_fanout(&runtime, &refusing);
    assert_eq!(fanout.mls_state(), FanoutMlsState::Confirmed);
    assert_eq!(
        fanout.target_acknowledgement(index),
        Some(cgka_traits::FanoutAcknowledgement::Echo)
    );
}

/// After a restart, an echo whose group then fails to hydrate acknowledges
/// nothing, and the quarantine its ingest caused is announced with that
/// ingest's effects, not left for a later one.
#[tokio::test]
async fn an_own_echo_whose_group_fails_to_hydrate_announces_the_quarantine() {
    let (fixture, alice) = FloorFixture::new(
        "own-echo-quarantine",
        &[
            &TransportEndpoint("wss://echo-a.example".into()),
            &TransportEndpoint("wss://echo-b.example".into()),
        ],
    )
    .await;
    let adapter = RecordingAdapter::default();
    let commit = rename_left_pending(&fixture, alice, &adapter).await;
    // The group's OpenMLS state is lost between the processes; its Marmot
    // record and stored fanouts are not.
    openmls_state::lose_openmls_group_state(
        &fixture.alice_path,
        &SqlCipherKey::new(FLOOR_KEY).unwrap(),
        &fixture.group_id,
    );
    let mut runtime = reopened_seeded(&fixture, &adapter);
    let delivery = group_delivery(&runtime, &fixture, &commit, Some("wss://echo-b.example"));
    assert!(runtime.takes_own_echo(&delivery).unwrap());

    let ingested = runtime.ingest_delivery(&delivery).await.unwrap();
    assert!(ingested.effects.pending.is_empty(), "{:?}", ingested.effects.pending);
    assert!(
        ingested.effects.events.iter().any(|event| matches!(
            event,
            GroupEvent::GroupHydrationQuarantined { group_id, .. } if group_id == &fixture.group_id
        )),
        "{:?}",
        ingested.effects.events
    );
    assert!(runtime.unhydrated_group_ids().is_empty());
    assert!(!runtime.takes_own_echo(&delivery).unwrap());
}
