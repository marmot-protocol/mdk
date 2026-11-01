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
//!
//! The same order holds for every other intent kind that queues behind a
//! waiting row: a leave, an invite and a removal go out after a queued
//! message, and a message after a queued group change.

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

/// An intent that never queues is refused, not queued, while an earlier one
/// waits for the drain, as it is while the group settles: an epoch-pinned
/// message would otherwise encrypt under whatever epoch the drain finds.
#[tokio::test]
async fn a_pinned_send_behind_a_queued_one_is_refused() {
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut carol, _carol_storage) = build_client(b"carol");
    let group_id = create_reservation_test_group(&mut alice, &mut carol, "pinned").await;
    let pin = alice.epoch_pin(&group_id).unwrap();
    let pinned_epoch = pin.epoch;
    let pinned_payload = app_payload_for(&alice, "media bound to its epoch");
    let pinned_send = || SendIntent::AppMessage {
        group_id: group_id.clone(),
        payload: pinned_payload.clone(),
        expected_epoch: Some(pin),
    };

    let outbox = alice
        .queue_app_message(group_id.clone(), app_payload_for(&alice, "from the outbox"))
        .await
        .unwrap();
    assert!(matches!(outbox, SendResult::Queued { .. }), "{outbox:?}");
    let refused = alice.send(pinned_send()).await;
    assert!(
        matches!(
            refused,
            Err(cgka_traits::error::EngineError::AppMessageEpochUnsettled { expected })
                if expected == pinned_epoch
        ),
        "{refused:?}"
    );
    assert_eq!(
        alice_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1,
        "the refused send left nothing queued"
    );

    let drained = alice.advance_convergence(&group_id).await.unwrap();
    let [SendResult::ApplicationMessage { msg, .. }] = drained.as_slice() else {
        panic!("the drain prepares only the outbox message: {drained:?}");
    };
    let (_, intent_id) = alice
        .regenerated_queued_intent_for_message(&msg.id)
        .unwrap();
    alice.confirm_queued_outbound_intent(&intent_id).unwrap();
    let sent = alice.send(pinned_send()).await.unwrap();
    assert!(
        matches!(sent, SendResult::ApplicationMessage { source_epoch, .. } if source_epoch == pinned_epoch),
        "{sent:?}"
    );
}

/// A queued intent the drain prepared and the host has not yet confirmed or
/// retried holds no later send: its generation is already taken, so a send
/// made then is prepared at once, at the next one.
#[tokio::test]
async fn a_drained_intent_awaiting_its_outcome_holds_no_later_send() {
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut carol, _carol_storage) = build_client(b"carol");
    let group_id = create_reservation_test_group(&mut alice, &mut carol, "in-flight").await;
    let outbox = alice
        .queue_app_message(group_id.clone(), app_payload_for(&alice, "from the outbox"))
        .await
        .unwrap();
    assert!(matches!(outbox, SendResult::Queued { .. }), "{outbox:?}");
    let drained = alice.advance_convergence(&group_id).await.unwrap();
    let [SendResult::ApplicationMessage { msg, .. }] = drained.as_slice() else {
        panic!("the drain prepares the outbox message: {drained:?}");
    };

    let later = alice
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&alice, "sent while the outbox message publishes"),
            expected_epoch: None,
        })
        .await
        .unwrap();
    assert!(
        matches!(later, SendResult::ApplicationMessage { .. }),
        "{later:?}"
    );
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

/// What the host publishes for a group, in the order it publishes it.
#[derive(Default)]
struct Published {
    messages: Vec<TransportMessage>,
    kinds: Vec<&'static str>,
    welcomes: Vec<TransportMessage>,
}

impl Published {
    /// Publish one send result as the host does: a group change is
    /// confirmed, and a drained message's queued intent with it.
    async fn take(
        &mut self,
        engine: &mut Engine<SqliteAccountStorage>,
        group_id: &GroupId,
        result: SendResult,
    ) {
        let (msg, kind) = match result {
            SendResult::ApplicationMessage { msg, .. } => (msg, "message"),
            SendResult::Proposal { msg } => (msg, "proposal"),
            SendResult::GroupEvolution {
                msg,
                welcomes,
                pending,
            } => {
                engine.confirm_published(pending).await.unwrap();
                self.welcomes.extend(welcomes);
                (msg, "commit")
            }
            SendResult::Queued { .. } => return,
            other => panic!("unexpected send result: {other:?}"),
        };
        if let Some((_, intent_id)) = engine.regenerated_queued_intent_for_message(&msg.id) {
            engine.confirm_queued_outbound_intent(&intent_id).unwrap();
        }
        self.messages.push(route(msg, group_id));
        self.kinds.push(kind);
    }

    /// The scheduled drain, run until the group's queue is empty.
    async fn drain(&mut self, engine: &mut Engine<SqliteAccountStorage>, group_id: &GroupId) {
        for _ in 0..8 {
            if !engine.has_queued_outbound_intents(group_id).unwrap() {
                return;
            }
            for result in engine.advance_convergence(group_id).await.unwrap() {
                self.take(engine, group_id, result).await;
            }
        }
        panic!("the drain never emptied the queue");
    }
}

/// What `receiver` makes of `messages`, read in order: each message it
/// decrypts as `content@epoch`, each epoch it moves to as `-> epoch`. A
/// Commit it buffers is settled at once. A message it cannot read adds
/// nothing, so an outcome is not asserted.
async fn read(
    receiver: &mut Engine<SqliteAccountStorage>,
    group_id: &GroupId,
    messages: &[TransportMessage],
) -> Vec<String> {
    receiver.drain_events();
    let mut seen = Vec::new();
    for msg in messages {
        let epoch = receiver.epoch(group_id).ok();
        if let Ok(IngestOutcome::Buffered { .. }) = receiver.ingest(msg.clone()).await {
            let _ = receiver.converge_stored_openmls_messages_at(group_id, 1_000_000);
        }
        for event in receiver.drain_events() {
            if let GroupEvent::MessageReceived { payload, epoch, .. } = event {
                seen.push(format!(
                    "{}@{}",
                    String::from_utf8(app_content(&payload)).unwrap(),
                    epoch.0
                ));
            }
        }
        let now = receiver.epoch(group_id).ok();
        if let Some(to) = now.filter(|_| now != epoch) {
            seen.push(format!("-> {}", to.0));
        }
    }
    seen
}

/// Alice, carol (an admin) and bob, at the group's first epoch.
async fn three_member_group(
    alice: &mut Engine<SqliteAccountStorage>,
    carol: &mut Engine<SqliteAccountStorage>,
    bob: &mut Engine<SqliteAccountStorage>,
) -> GroupId {
    let members = vec![
        carol.fresh_key_package().await.unwrap(),
        bob.fresh_key_package().await.unwrap(),
    ];
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "three".into(),
            description: "".into(),
            members,
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![carol.self_id()],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, welcomes } = create else {
        panic!("expected GroupCreated, got {create:?}");
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    group_id
}

async fn queue_message(
    engine: &mut Engine<SqliteAccountStorage>,
    group_id: &GroupId,
    content: &str,
) {
    let queued = engine
        .queue_app_message(group_id.clone(), app_payload_for(engine, content))
        .await
        .unwrap();
    assert!(matches!(queued, SendResult::Queued { .. }), "{queued:?}");
}

/// A leave made while a message waits in the queue goes out after it: the
/// message the member sent before leaving still reaches the group.
#[tokio::test]
async fn a_leave_behind_a_queued_message_goes_out_after_it() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, _carol_storage) = build_client(b"carol");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let group_id = three_member_group(&mut alice, &mut carol, &mut bob).await;
    let epoch = bob.epoch(&group_id).unwrap().0;
    queue_message(&mut bob, &group_id, "sent before leaving").await;

    let leave = bob
        .send(SendIntent::Leave {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    let leave_queued = matches!(leave, SendResult::Queued { .. });
    let mut published = Published::default();
    published.take(&mut bob, &group_id, leave).await;
    published.drain(&mut bob, &group_id).await;

    assert_eq!(
        read(&mut alice, &group_id, &published.messages).await,
        vec![format!("sent before leaving@{epoch}")],
        "alice reads the message bob sent before leaving"
    );
    assert_eq!(published.kinds, vec!["message", "proposal"]);
    assert!(leave_queued, "the leave waits behind the queued message");
}

/// An invite made while a message waits in the queue is committed after it,
/// so the invitee never reads a message sent before it was invited.
#[tokio::test]
async fn an_invite_behind_a_queued_message_never_shows_it_to_the_invitee() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, _carol_storage) = build_client(b"carol");
    let (mut dave, _dave_storage) = build_client(b"dave");
    let group_id = create_reservation_test_group(&mut alice, &mut carol, "invite").await;
    let epoch = alice.epoch(&group_id).unwrap().0;
    queue_message(&mut alice, &group_id, "sent before the invite").await;

    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![dave.fresh_key_package().await.unwrap()],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let invite_queued = matches!(invite, SendResult::Queued { .. });
    let mut published = Published::default();
    published.take(&mut alice, &group_id, invite).await;
    published.drain(&mut alice, &group_id).await;

    dave.join_welcome(welcome_for(&published.welcomes, b"dave"))
        .await
        .unwrap();
    assert!(
        read(&mut dave, &group_id, &published.messages)
            .await
            .iter()
            .all(|seen| !seen.starts_with("sent before the invite")),
        "dave never reads a message sent before his invite"
    );
    assert_eq!(
        read(&mut carol, &group_id, &published.messages).await,
        vec![
            format!("sent before the invite@{epoch}"),
            format!("-> {}", epoch + 1)
        ]
    );
    assert_eq!(published.kinds, vec!["message", "commit"]);
    assert!(invite_queued, "the invite waits behind the queued message");
}

/// A removal made while a message waits in the queue is committed after it,
/// so the removed member still reads the message sent while it was a member.
#[tokio::test]
async fn a_removal_behind_a_queued_message_lets_the_removed_member_read_it() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, _carol_storage) = build_client(b"carol");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let group_id = three_member_group(&mut alice, &mut carol, &mut bob).await;
    let epoch = alice.epoch(&group_id).unwrap().0;
    queue_message(&mut alice, &group_id, "sent before the removal").await;

    let remove = alice
        .send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let remove_queued = matches!(remove, SendResult::Queued { .. });
    let mut published = Published::default();
    published.take(&mut alice, &group_id, remove).await;
    published.drain(&mut alice, &group_id).await;

    let bob_seen = read(&mut bob, &group_id, &published.messages).await;
    assert_eq!(
        bob_seen.first(),
        Some(&format!("sent before the removal@{epoch}")),
        "bob reads the message sent while he was a member: {bob_seen:?}"
    );
    assert_eq!(published.kinds, vec!["message", "commit"]);
    assert!(remove_queued, "the removal waits behind the queued message");
}

/// A message made while a group change waits in the queue is encrypted after
/// the change, so every member applies the change first.
#[tokio::test]
async fn a_message_behind_a_queued_group_change_applies_after_it() {
    let (mut alice, alice_storage) = build_client(b"alice");
    let (mut carol, _carol_storage) = build_client(b"carol");
    let group_id = create_reservation_test_group(&mut alice, &mut carol, "change").await;
    let epoch = alice.epoch(&group_id).unwrap().0;
    // Queued as a send made while the group settled would be.
    queue_intent(
        &alice_storage,
        &group_id,
        b"queued-rename",
        SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("renamed".into()),
            description: None,
        },
        0,
    );

    let message = alice
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(&alice, "sent after the rename"),
            expected_epoch: None,
        })
        .await
        .unwrap();
    let message_queued = matches!(message, SendResult::Queued { .. });
    let mut published = Published::default();
    published.take(&mut alice, &group_id, message).await;
    published.drain(&mut alice, &group_id).await;

    assert_eq!(
        read(&mut carol, &group_id, &published.messages).await,
        vec![
            format!("-> {}", epoch + 1),
            format!("sent after the rename@{}", epoch + 1)
        ],
        "carol applies the rename before the message sent after it"
    );
    assert_eq!(published.kinds, vec!["commit", "message"]);
    assert!(message_queued, "the message waits behind the queued change");
}
