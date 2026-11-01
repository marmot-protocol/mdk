//! A sender's sends to one group are prepared in the order it made them
//! (mdk#2842).
//!
//! Carol's sends queue behind alice's Commit while her convergence is
//! unsettled. Once it settles she keeps sending, before the scheduled drain
//! runs. Those sends used to be encrypted at once, ahead of the queue, so her
//! generations ran against send order. A member reading the group's history
//! in `created_at` order (the Nostr binding stamps each event with its inner
//! app event's `created_at`, the moment it was sent) took the drained sends
//! first, and its ratchet for carol then ran more than 100 generations past
//! the earliest sends that went ahead, which it could no longer decrypt.

use super::*;

/// Sends queued while carol's convergence is unsettled.
const QUEUED: usize = 60;
/// Sends made once it settles, before the scheduled drain runs. With
/// `QUEUED`, more than the ratchet's out-of-order window of 100 generations.
const AFTER_SETTLING: usize = 50;
const FIRST_CREATED_AT: u64 = 1_700_000_000;

/// Carol's `index`th send, made at `FIRST_CREATED_AT + index`.
fn numbered_send(carol: &Engine<SqliteAccountStorage>, index: usize) -> MarmotAppEvent {
    MarmotAppEvent::new(
        hex::encode(carol.self_id().as_slice()),
        FIRST_CREATED_AT + index as u64,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        format!("send-{index:03}"),
    )
}

async fn send(
    carol: &mut Engine<SqliteAccountStorage>,
    group_id: &GroupId,
    event: &MarmotAppEvent,
) -> SendResult {
    carol
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: event.encode().unwrap(),
            expected_epoch: None,
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn a_send_never_overtakes_the_senders_queued_sends() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let carol_storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut carol =
        build_client_with_storage_and_clock(b"carol", carol_storage.clone(), clock.clone());
    let group_id = create_reservation_test_group(&mut alice, &mut carol, "send-order").await;

    let self_update = alice
        .send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    let (commit, pending) = evolution(self_update);
    alice.confirm_published(pending).await.unwrap();
    let settled_epoch = alice.epoch(&group_id).unwrap();
    assert!(matches!(
        carol.ingest(route(commit, &group_id)).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));

    let sends: Vec<MarmotAppEvent> = (0..QUEUED + AFTER_SETTLING)
        .map(|index| numbered_send(&carol, index))
        .collect();
    let index_of = |app_event_id: &str| {
        sends
            .iter()
            .position(|send| send.id == app_event_id)
            .expect("every prepared message is one of carol's sends")
    };

    for (index, event) in sends[..QUEUED].iter().enumerate() {
        let result = send(&mut carol, &group_id, event).await;
        assert!(
            matches!(result, SendResult::Queued { .. }),
            "send {index} waits for the unsettled Commit: {result:?}"
        );
    }

    // The pass's quiescence ends; the next send's own preflight applies
    // alice's Commit, and the drain the queued sends wait for has not run.
    clock.advance_ms(V1_MAX_CONVERGENCE_PASS_MS);
    let mut prepared = Vec::new();
    let mut after_settling = Vec::new();
    for event in &sends[QUEUED..] {
        let result = send(&mut carol, &group_id, event).await;
        assert_eq!(carol.epoch(&group_id).unwrap(), settled_epoch);
        assert!(!carol.has_pending_convergence_inputs(&group_id).unwrap());
        after_settling.push(matches!(result, SendResult::Queued { .. }));
        if let SendResult::ApplicationMessage { .. } = result {
            prepared.push(result);
        }
    }

    // The scheduled drain, as the host runs it, confirming each publication.
    for _ in 0..8 {
        if !carol.has_queued_outbound_intents(&group_id).unwrap() {
            break;
        }
        for result in carol.advance_convergence(&group_id).await.unwrap() {
            if let SendResult::ApplicationMessage { msg, .. } = &result {
                let (_, intent_id) = carol
                    .regenerated_queued_intent_for_message(&msg.id)
                    .expect("a drained message carries its queued intent");
                carol.confirm_queued_outbound_intent(&intent_id).unwrap();
            }
            prepared.push(result);
        }
    }
    assert!(!carol.has_queued_outbound_intents(&group_id).unwrap());

    // Each encryption takes carol's next generation in the settled epoch, so
    // the order of preparation is the order of generations.
    let mut published = Vec::new();
    for result in prepared {
        let SendResult::ApplicationMessage {
            msg,
            app_event_id,
            source_epoch,
            ..
        } = result
        else {
            panic!("carol prepares only her application messages: {result:?}");
        };
        assert_eq!(source_epoch, settled_epoch);
        published.push((index_of(&app_event_id), route(msg, &group_id)));
    }
    let generation_order: Vec<usize> = published.iter().map(|(index, _)| *index).collect();
    assert_eq!(
        generation_order,
        (0..QUEUED + AFTER_SETTLING).collect::<Vec<_>>(),
        "carol's generations follow her send order"
    );

    // A member catching up reads the history in `created_at` order.
    published.sort_by_key(|(index, _)| sends[*index].created_at);
    alice.drain_events();
    let mut undecrypted = Vec::new();
    for (index, msg) in published {
        let outcome = alice.ingest(msg).await.unwrap();
        if !matches!(outcome, IngestOutcome::Processed) {
            undecrypted.push((index, outcome));
        }
    }
    assert!(
        undecrypted.is_empty(),
        "alice decrypts every send in created_at order: {undecrypted:?}"
    );
    let received: Vec<Vec<u8>> = alice
        .drain_events()
        .into_iter()
        .filter_map(|event| match event {
            GroupEvent::MessageReceived { payload, .. } => Some(app_content(&payload)),
            _ => None,
        })
        .collect();
    assert_eq!(
        received,
        sends
            .iter()
            .map(|send| send.content.clone().into_bytes())
            .collect::<Vec<_>>()
    );

    assert!(
        after_settling.iter().all(|queued| *queued),
        "a send made while earlier ones wait is queued behind them, and the drain publishes it"
    );
}

/// A queued change the settled state already holds is done at drain: nothing
/// to publish confirms it, so the drain retires it rather than leave it
/// waiting forever with every later send queued behind it.
#[tokio::test]
async fn a_queued_change_already_made_holds_no_later_send() {
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut carol, _carol_storage) = build_client(b"carol");
    let group_id = create_reservation_test_group(&mut alice, &mut carol, "no-change").await;
    let enable = SendIntent::EnableDisbanding {
        group_id: group_id.clone(),
    };
    let direct = alice.send(enable.clone()).await.unwrap();
    assert!(
        matches!(direct, SendResult::NoChange { .. }),
        "a new group can already be disbanded: {direct:?}"
    );

    let outbox = alice
        .queue_app_message(group_id.clone(), app_payload_for(&alice, "from the outbox"))
        .await
        .unwrap();
    assert!(matches!(outbox, SendResult::Queued { .. }), "{outbox:?}");
    let again = alice.send(enable).await.unwrap();
    assert!(matches!(again, SendResult::Queued { .. }), "{again:?}");

    let drained = alice.advance_convergence(&group_id).await.unwrap();
    let [
        SendResult::ApplicationMessage { msg, .. },
        SendResult::NoChange { .. },
    ] = drained.as_slice()
    else {
        panic!("the outbox message, then the change already made: {drained:?}");
    };
    let (_, intent_id) = alice
        .regenerated_queued_intent_for_message(&msg.id)
        .unwrap();
    alice.confirm_queued_outbound_intent(&intent_id).unwrap();
    assert!(
        alice_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty()
    );

    let later = alice
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&alice, "sent once the queue is done"),
            expected_epoch: None,
        })
        .await
        .unwrap();
    assert!(
        matches!(later, SendResult::ApplicationMessage { .. }),
        "{later:?}"
    );
}
