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
/// `Accepted` by its echo, and the ambiguous relay stays owed.
#[tokio::test]
async fn an_own_echo_from_a_target_relay_confirms_a_pending_commit() {
    let ambiguous = TransportEndpoint("wss://echo-a.example".into());
    let refusing = TransportEndpoint("wss://echo-b.example".into());
    let (fixture, alice) = FloorFixture::new("own-echo", &[&ambiguous, &refusing]).await;
    let adapter = RecordingAdapter::default();
    let mut runtime = fixture.runtime(alice, &adapter);
    // An earlier message of Alice's own, delivered before the commit.
    let alice_hex = hex::encode(runtime.session().self_id().as_slice());
    let earlier = runtime
        .send(SendIntent::AppMessage {
            group_id: fixture.group_id.clone(),
            payload: app_payload_for(&alice_hex, b"before the rename"),
            expected_epoch: None,
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
}
