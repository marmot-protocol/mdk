// mdk#2332: the queued intent a drained application message was prepared from.
//
// The drain prepares a queued message once and stages it in a frozen fanout
// that names the intent. The intent stays queued until the message resolves,
// on whichever pass that is: a relay accepted it, or every relay refused it
// for good. Until then it is in flight, after a restart too, so no drain
// prepares it a second time.

/// Every distinct event the adapter was asked to publish.
fn published_ids(adapter: &RecordingAdapter) -> std::collections::HashSet<MessageId> {
    adapter
        .publishes()
        .iter()
        .map(|publish| publish.message.id.clone())
        .collect()
}

async fn queue_message(runtime: &mut FloorRuntime, fixture: &FloorFixture) {
    let sender = hex::encode(runtime.session().self_id().as_slice());
    runtime
        .queue_app_message_with_audit_context(
            fixture.group_id.clone(),
            app_payload_for(&sender, b"queued"),
            None,
            Default::default())
        .await
        .unwrap();
}

fn queued(runtime: &FloorRuntime, fixture: &FloorFixture) -> bool {
    runtime
        .has_queued_outbound_intents(&fixture.group_id)
        .unwrap()
}

/// A first attempt no relay received leaves the intent queued and named by
/// the stored fanout. The retry resolves it: accepted, or refused for good.
/// Either way the intent retires with that pass, and the next drain prepares
/// nothing.
#[tokio::test]
async fn a_drained_message_retried_to_an_answer_is_prepared_once() {
    for (name, refused) in [
        ("drained-retry-accepted", false),
        ("drained-retry-refused", true),
    ] {
        let relay = TransportEndpoint(format!("wss://{name}.example"));
        let (fixture, alice) = FloorFixture::new(name, &[&relay]).await;
        let adapter = RecordingAdapter::default();
        let mut answers = vec![unreachable(&relay)];
        if refused {
            answers.push(blocked(&relay));
        }
        adapter.script_failures(relay.clone(), answers);
        let mut runtime = fixture.runtime(alice, &adapter);
        queue_message(&mut runtime, &fixture).await;

        runtime.advance_convergence(&fixture.group_id).await.unwrap();
        let stored = runtime.session().outbound_fanouts().unwrap();
        assert_eq!(stored.len(), 1, "{name}");
        assert!(stored[0].queued_intent_id().is_some(), "{name}");
        assert!(queued(&runtime, &fixture), "{name}: nothing answered yet");

        fixture.wall.set(fixture.wall.now().0 + HOUR);
        runtime.advance_convergence(&fixture.group_id).await.unwrap();
        assert!(!queued(&runtime, &fixture), "{name}: the answer retires it");
        runtime.advance_convergence(&fixture.group_id).await.unwrap();
        assert_eq!(published_ids(&adapter).len(), 1, "{name}: prepared once");
    }
}

/// The process dies while the first attempt is in flight. After the restart
/// the fanout's retry is accepted and retires the intent its record names,
/// so the drain that follows prepares nothing.
#[tokio::test]
async fn a_drained_message_sent_before_a_crash_is_prepared_once() {
    let relay = TransportEndpoint("wss://drained-crash.example".into());
    let (fixture, alice) = FloorFixture::new("drained-crash", &[&relay]).await;
    let adapter = RecordingAdapter::default();
    *adapter.inner.endpoint_gate.lock().unwrap() =
        Some((relay.clone(), Arc::new(tokio::sync::Semaphore::new(0))));
    let mut runtime = fixture.runtime(alice, &adapter);
    queue_message(&mut runtime, &fixture).await;
    crash_when(runtime.advance_convergence(&fixture.group_id), || {
        !adapter.publishes().is_empty()
    })
    .await;
    drop(runtime);

    *adapter.inner.endpoint_gate.lock().unwrap() = None;
    let mut restarted = fixture.runtime(fixture.reopen(), &adapter);
    restarted
        .advance_convergence(&fixture.group_id)
        .await
        .unwrap();

    assert!(!queued(&restarted, &fixture));
    assert_eq!(published_ids(&adapter).len(), 1, "prepared once");
}

/// After a restart with the message still unanswered, the intent is in
/// flight: a drain of the group, even one no stalled fanout holds back,
/// prepares nothing.
#[tokio::test]
async fn a_drained_message_still_unanswered_after_a_restart_is_in_flight() {
    let relay = TransportEndpoint("wss://drained-unanswered.example".into());
    let (fixture, alice) = FloorFixture::new("drained-unanswered", &[&relay]).await;
    let adapter = RecordingAdapter::default();
    adapter.fail_endpoints_as(
        vec![relay.clone()],
        TransportEndpointFailureKind::RetryableUnavailable,
    );
    let mut runtime = fixture.runtime(alice, &adapter);
    queue_message(&mut runtime, &fixture).await;
    runtime.advance_convergence(&fixture.group_id).await.unwrap();
    drop(runtime);

    let mut restarted = fixture.runtime(fixture.reopen(), &adapter);
    let _ = restarted
        .session_mut()
        .ensure_group_hydrated(&fixture.group_id)
        .unwrap();
    let effects = restarted
        .session_mut()
        .advance_convergence(&fixture.group_id)
        .await
        .unwrap();

    assert!(effects.publish.is_empty(), "{:?}", effects.publish);
    assert!(queued(&restarted, &fixture));
    assert_eq!(published_ids(&adapter).len(), 1);
}

/// The intent cannot be retired when its message is accepted. The app's
/// acknowledgement of the message then keeps the fanout, the intent's only
/// durable link to the sent message. After a restart, with the retirement
/// still failing and nothing in memory, the drain reads that link and
/// prepares nothing; this is also what a Welcome that makes the group live
/// without hydrating it relies on. The first pass whose retirement succeeds
/// retires the intent, and only then does an acknowledgement delete the
/// fanout.
#[tokio::test]
async fn a_drained_message_whose_intent_fails_to_retire_is_prepared_once() {
    let relay = TransportEndpoint("wss://drained-cleanup.example".into());
    let (fixture, alice) = FloorFixture::new("drained-cleanup", &[&relay]).await;
    let adapter = RecordingAdapter::default();
    let mut runtime = fixture.runtime(alice, &adapter);
    queue_message(&mut runtime, &fixture).await;
    let connection = rusqlite::Connection::open(&fixture.alice_path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &SqlCipherKey::new(FLOOR_KEY).unwrap(),
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_intent_retirement BEFORE DELETE ON cgka_queued_outbound
             BEGIN SELECT RAISE(ABORT, 'injected intent retirement failure'); END;",
        )
        .unwrap();

    let sent = runtime.advance_convergence(&fixture.group_id).await.unwrap();
    assert_eq!(sent.published_app_messages.len(), 1);
    runtime
        .acknowledge_published_app_messages(&sent.published_app_messages)
        .unwrap();
    assert!(queued(&runtime, &fixture));
    assert_eq!(runtime.session().outbound_fanouts().unwrap().len(), 1);
    drop(runtime);

    let mut restarted = fixture.runtime(fixture.reopen(), &adapter);
    restarted
        .advance_convergence(&fixture.group_id)
        .await
        .unwrap();
    assert!(queued(&restarted, &fixture));
    assert_eq!(published_ids(&adapter).len(), 1, "still in flight");

    connection
        .execute_batch("DROP TRIGGER fail_intent_retirement;")
        .unwrap();
    drop(connection);
    let resumed = restarted
        .advance_convergence(&fixture.group_id)
        .await
        .unwrap();
    assert!(!queued(&restarted, &fixture));
    restarted
        .acknowledge_published_app_messages(&resumed.published_app_messages)
        .unwrap();
    assert!(restarted.session().outbound_fanouts().unwrap().is_empty());
    restarted
        .advance_convergence(&fixture.group_id)
        .await
        .unwrap();
    assert_eq!(published_ids(&adapter).len(), 1, "prepared once");
}
