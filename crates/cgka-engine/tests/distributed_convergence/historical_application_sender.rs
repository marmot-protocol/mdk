//! Delayed applications retain their authenticated source-epoch author when
//! removal or leaf reuse changes the recipient's current membership tree.

use super::*;

#[derive(Clone, Copy, Debug)]
enum Delivery {
    Direct,
    BufferedAfterRestart,
}

#[derive(Clone, Copy, Debug)]
enum MembershipChange {
    Remove,
    Replace,
    Rejoin,
}

#[tokio::test]
async fn historical_sender_survives_removal() {
    for delivery in [Delivery::Direct, Delivery::BufferedAfterRestart] {
        check_historical_sender(delivery, MembershipChange::Remove, false).await;
    }
}

#[tokio::test]
async fn historical_sender_survives_leaf_reuse() {
    for delivery in [Delivery::Direct, Delivery::BufferedAfterRestart] {
        check_historical_sender(delivery, MembershipChange::Replace, false).await;
        check_historical_sender(delivery, MembershipChange::Rejoin, false).await;
    }
}

#[tokio::test]
async fn historical_sender_cannot_impersonate_replacement_member() {
    for delivery in [Delivery::Direct, Delivery::BufferedAfterRestart] {
        check_historical_sender(delivery, MembershipChange::Replace, true).await;
    }
}

async fn check_historical_sender(
    delivery: Delivery,
    change: MembershipChange,
    forge_replacement_author: bool,
) {
    let (mut alice, storage) = build_client(b"alice");
    let (mut bob, bob_storage) = build_client(b"bob");
    let (mut carol, _) = build_client(b"carol");
    let (mut david, _) = build_client(b"david");
    let (group, create) = alice
        .create_group(CreateGroupRequest {
            name: "historical sender".into(),
            description: "".into(),
            members: vec![
                bob.fresh_key_package().await.unwrap(),
                carol.fresh_key_package().await.unwrap(),
            ],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected group creation, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    let source_epoch = bob.epoch(&group).unwrap();
    let old_leaf = bob.own_leaf_index(&group).unwrap();
    let content = b"sent before removal";
    let message = if forge_replacement_author {
        // Bob authenticates the MLS message, but lies about its inner author.
        // A lookup against the reused current leaf would wrongly name David.
        let payload = app_payload_for(&david, content);
        raw_app_message_with_payload(&bob_storage, &bob.self_id(), &group, &payload)
    } else {
        send_app(&mut bob, &group, content.to_vec()).await
    };
    let (removal, pending) = evolution(
        alice
            .send(SendIntent::RemoveMembers {
                group_id: group.clone(),
                members: vec![bob.self_id()],
            })
            .await
            .unwrap(),
    );
    alice.confirm_published(pending).await.unwrap();
    if matches!(change, MembershipChange::Rejoin) {
        // The returning device must learn its removal before accepting a
        // replacement Welcome through the normal authenticated join path.
        bob.buffer_openmls_convergence_message_at(&group, route(removal, &group), 1_000)
            .unwrap();
        bob.converge_stored_openmls_messages_at(&group, 2_000_000)
            .unwrap();
    }
    if !matches!(change, MembershipChange::Remove) {
        let joining = if matches!(change, MembershipChange::Rejoin) {
            &mut bob
        } else {
            &mut david
        };
        let invite = alice
            .send(SendIntent::Invite {
                group_id: group.clone(),
                key_packages: vec![joining.fresh_key_package().await.unwrap()],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        let (pending, mut welcomes) = match invite {
            SendResult::GroupEvolution {
                pending, welcomes, ..
            } => (pending, welcomes),
            other => panic!("expected invite, got {other:?}"),
        };
        alice.confirm_published(pending).await.unwrap();
        joining.join_welcome(welcomes.remove(0)).await.unwrap();
        assert_eq!(joining.own_leaf_index(&group).unwrap(), old_leaf);
    }
    assert!(alice.epoch(&group).unwrap() > source_epoch);
    alice.drain_events();
    match delivery {
        Delivery::Direct => {
            let result = alice.ingest(message.clone()).await.unwrap();
            if forge_replacement_author {
                assert!(matches!(result, IngestOutcome::Ignored { .. }));
            } else {
                assert!(matches!(result, IngestOutcome::Processed));
            }
        }
        Delivery::BufferedAfterRestart => {
            alice
                .buffer_openmls_convergence_message_at(&group, message.clone(), 1_000)
                .unwrap();
            drop(alice);
            alice = build_client_with_storage(b"alice", storage.clone());
            alice.hydrate_all_stored_groups().unwrap();
            alice.drain_events();
            alice
                .advance_convergence_inputs_until_settled(&group, 2_000_000)
                .await
                .unwrap();
        }
    }
    let events = alice.drain_events();
    let received: Vec<_> = events
        .iter()
        .filter(|event| matches!(event, GroupEvent::MessageReceived { .. }))
        .collect();
    let state = storage.get_message(&content_id(&message)).unwrap().state;
    if forge_replacement_author {
        assert!(received.is_empty(), "{delivery:?}: forged author escaped");
        assert!(matches!(
            state,
            MessageState::Failed | MessageState::EpochInvalidated
        ));
        assert!(
            storage
                .list_pending_application_events()
                .unwrap()
                .is_empty()
        );
    } else {
        assert_eq!(state, MessageState::Processed, "{delivery:?}, {change:?}");
        assert_eq!(received.len(), 1, "{delivery:?}, {change:?}");
        let GroupEvent::MessageReceived {
            sender,
            epoch,
            payload,
            ..
        } = received[0]
        else {
            unreachable!()
        };
        assert_eq!(sender, &bob.self_id());
        assert_eq!(epoch, &source_epoch);
        assert_eq!(app_content(payload), content);
        // Redelivery must not surface a second copy after consuming the ratchet.
        alice.ingest(message).await.unwrap();
        assert!(
            !alice
                .drain_events()
                .iter()
                .any(|event| matches!(event, GroupEvent::MessageReceived { .. }))
        );
    }
}
