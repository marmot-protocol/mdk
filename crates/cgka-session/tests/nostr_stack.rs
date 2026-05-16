mod support;

use cgka_engine::canonicalization::CanonicalizationPolicy;
use cgka_session::IngestEffects;
use cgka_session::PublishWork;
use cgka_traits::engine::{CreateGroupRequest, GroupEvent, SendIntent};
use cgka_traits::ingest::{IngestOutcome, StaleReason};
use cgka_traits::{EpochId, TransportAdapterError, TransportEndpoint, TransportPublishReport};
use support::nostr_stack::{CreatedGroup, NostrStackHarness, StackClient};

#[tokio::test]
async fn nostr_adapter_peeler_and_session_deliver_welcome_and_group_message() {
    let stack = NostrStackHarness::new();
    let mut alice = stack.client("alice").await;
    let mut bob = stack.client("bob").await;

    let created = create_group_for_bob(&mut alice, &mut bob).await;
    let welcome_report = publish_confirm_and_deliver_welcome(
        &stack,
        &mut alice,
        &mut bob,
        created.pending,
        created.welcome,
    )
    .await;

    assert!(welcome_report.met_required_acks());
    stack.sync_group(&bob, &created.group_id).await;

    let sent = alice
        .session
        .send(SendIntent::AppMessage {
            group_id: created.group_id.clone(),
            payload: b"hello through the nostr stack".to_vec(),
        })
        .await
        .unwrap();
    let app_message = match &sent.publish[0] {
        PublishWork::ApplicationMessage { msg } => msg.clone(),
        other => panic!("expected application message publish work, got {other:?}"),
    };
    let app_report = stack
        .publish_group(&alice, &created.group_id, app_message, 1)
        .await
        .unwrap();
    assert!(app_report.met_required_acks());

    let received = stack
        .deliver_next_to_group_session(&mut bob)
        .await
        .expect("group delivery should reach bob");
    assert_eq!(received.outcome, IngestOutcome::Processed);
    assert_eq!(
        received.effects.events,
        vec![GroupEvent::MessageReceived {
            group_id: created.group_id,
            sender: alice.session.self_id(),
            payload: b"hello through the nostr stack".to_vec(),
        }]
    );
}

#[tokio::test]
async fn insufficient_publish_acks_roll_back_pending_group_create() {
    let stack = NostrStackHarness::new();
    let mut alice = stack.client("alice").await;
    let mut bob = stack.client("bob").await;
    let created = create_group_for_bob(&mut alice, &mut bob).await;

    stack.accept_only_next_publish(1);
    let report = stack
        .publish_welcome_to_endpoints(
            &alice,
            &bob,
            created.welcome,
            vec![bob.inbox_endpoint.clone(), backup_inbox("bob")],
            2,
        )
        .await
        .unwrap();

    assert_eq!(report.accepted_count(), 1);
    assert_eq!(report.failed.len(), 1);
    assert!(!report.met_required_acks());
    let failed = alice.session.publish_failed(created.pending).await.unwrap();
    assert!(failed.is_empty());
    assert_eq!(alice.session.epoch(&created.group_id).unwrap(), EpochId(0));
    assert_eq!(alice.session.members(&created.group_id).unwrap().len(), 1);
}

#[tokio::test]
async fn publish_error_rolls_back_pending_group_create() {
    let stack = NostrStackHarness::new();
    let mut alice = stack.client("alice").await;
    let mut bob = stack.client("bob").await;
    let created = create_group_for_bob(&mut alice, &mut bob).await;

    stack.fail_next_publish("synthetic relay failure");
    let err = stack
        .publish_welcome(&alice, &bob, created.welcome, 1)
        .await
        .expect_err("publish should fail");
    assert!(matches!(err, TransportAdapterError::Publish(_)));

    let failed = alice.session.publish_failed(created.pending).await.unwrap();
    assert!(failed.is_empty());
    assert_eq!(alice.session.epoch(&created.group_id).unwrap(), EpochId(0));
    assert_eq!(alice.session.members(&created.group_id).unwrap().len(), 1);
}

#[tokio::test]
async fn group_delivery_requires_synced_group_subscription() {
    let stack = NostrStackHarness::new();
    let mut alice = stack.client("alice").await;
    let mut bob = stack.client("bob").await;
    let created = create_group_for_bob(&mut alice, &mut bob).await;
    publish_confirm_and_deliver_welcome(
        &stack,
        &mut alice,
        &mut bob,
        created.pending,
        created.welcome,
    )
    .await;

    let app_message = send_app_message(&mut alice, &created.group_id, b"sync gated").await;
    let report = stack
        .publish_group(&alice, &created.group_id, app_message, 1)
        .await
        .unwrap();
    assert!(report.met_required_acks());
    let published = stack.take_one_published();

    let before_sync = stack
        .deliver_event_to_session(
            &mut bob,
            stack.group_endpoint(),
            "before-sync",
            published.event.clone(),
        )
        .await;
    assert!(before_sync.is_none());

    stack.sync_group(&bob, &created.group_id).await;
    let after_sync = stack
        .deliver_event_to_session(
            &mut bob,
            stack.group_endpoint(),
            "after-sync",
            published.event,
        )
        .await
        .expect("synced group delivery should reach bob");
    assert_eq!(after_sync.outcome, IngestOutcome::Processed);
    assert_eq!(
        after_sync.effects.events,
        vec![GroupEvent::MessageReceived {
            group_id: created.group_id,
            sender: alice.session.self_id(),
            payload: b"sync gated".to_vec(),
        }]
    );
}

#[tokio::test]
async fn duplicate_group_relay_delivery_is_idempotent_at_session_boundary() {
    let stack = NostrStackHarness::new();
    let mut alice = stack.client("alice").await;
    let mut bob = stack.client("bob").await;
    let created = create_group_for_bob(&mut alice, &mut bob).await;
    publish_confirm_and_deliver_welcome(
        &stack,
        &mut alice,
        &mut bob,
        created.pending,
        created.welcome,
    )
    .await;
    stack.sync_group(&bob, &created.group_id).await;
    bob.session.set_convergence_policy(CanonicalizationPolicy {
        stable_quiescence_ms: 0,
        ..CanonicalizationPolicy::default()
    });

    let app_message = send_app_message(&mut alice, &created.group_id, b"dedupe me").await;
    let report = stack
        .publish_group(&alice, &created.group_id, app_message, 1)
        .await
        .unwrap();
    assert!(report.met_required_acks());
    let published = stack.take_one_published();

    let first = stack
        .deliver_event_to_session(
            &mut bob,
            stack.group_endpoint(),
            "first-delivery",
            published.event.clone(),
        )
        .await
        .expect("first delivery should reach bob");
    assert_eq!(first.outcome, IngestOutcome::Processed);

    let duplicate = stack
        .deliver_event_to_session(
            &mut bob,
            stack.group_endpoint(),
            "duplicate-delivery",
            published.event,
        )
        .await
        .expect("duplicate delivery should still route to bob");
    assert!(matches!(
        duplicate.outcome,
        IngestOutcome::Stale {
            reason: StaleReason::AlreadySeen
        }
    ));
    assert!(duplicate.effects.events.is_empty());
}

#[tokio::test]
async fn reordered_and_duplicated_group_app_deliveries_preserve_valid_outputs() {
    let stack = NostrStackHarness::new();
    let mut alice = stack.client("alice").await;
    let mut bob = stack.client("bob").await;
    let created = create_group_for_bob(&mut alice, &mut bob).await;
    publish_confirm_and_deliver_welcome(
        &stack,
        &mut alice,
        &mut bob,
        created.pending,
        created.welcome,
    )
    .await;
    stack.sync_group(&bob, &created.group_id).await;

    let event_zero = publish_app_event(&stack, &mut alice, &created.group_id, b"zero").await;
    let event_one = publish_app_event(&stack, &mut alice, &created.group_id, b"one").await;
    let event_two = publish_app_event(&stack, &mut alice, &created.group_id, b"two").await;

    let second = stack
        .deliver_event_to_session(
            &mut bob,
            stack.group_endpoint(),
            "second",
            event_two.clone(),
        )
        .await
        .expect("second delivery should route");
    let first = stack
        .deliver_event_to_session(&mut bob, stack.group_endpoint(), "first", event_zero)
        .await
        .expect("first delivery should route");
    let middle = stack
        .deliver_event_to_session(&mut bob, stack.group_endpoint(), "middle", event_one)
        .await
        .expect("middle delivery should route");
    let duplicate = stack
        .deliver_event_to_session(&mut bob, stack.group_endpoint(), "duplicate", event_two)
        .await
        .expect("duplicate delivery should route");

    assert_eq!(message_payloads(&second), vec![b"two".to_vec()]);
    assert_eq!(message_payloads(&first), vec![b"zero".to_vec()]);
    assert_eq!(message_payloads(&middle), vec![b"one".to_vec()]);
    assert!(matches!(
        duplicate.outcome,
        IngestOutcome::Stale {
            reason: StaleReason::AlreadySeen
        }
    ));
    assert!(duplicate.effects.events.is_empty());
}

#[tokio::test]
async fn invite_group_evolution_publishes_commit_and_welcome_through_stack() {
    let stack = NostrStackHarness::new();
    let mut alice = stack.client("alice").await;
    let mut bob = stack.client("bob").await;
    let mut carol = stack.client("carol").await;
    let created = create_group_for_bob(&mut alice, &mut bob).await;
    publish_confirm_and_deliver_welcome(
        &stack,
        &mut alice,
        &mut bob,
        created.pending,
        created.welcome,
    )
    .await;
    stack.sync_group(&bob, &created.group_id).await;

    let carol_key_package = carol.session.fresh_key_package().await.unwrap();
    let invite = alice
        .session
        .send(SendIntent::Invite {
            group_id: created.group_id.clone(),
            key_packages: vec![carol_key_package],
        })
        .await
        .unwrap();
    let (pending, commit, welcome) = match &invite.publish[0] {
        PublishWork::GroupEvolution {
            msg,
            welcomes,
            pending,
        } => (*pending, msg.clone(), welcomes[0].clone()),
        other => panic!("expected group evolution publish work, got {other:?}"),
    };

    let commit_report = stack
        .publish_group(&alice, &created.group_id, commit, 1)
        .await
        .unwrap();
    let welcome_report = stack
        .publish_welcome(&alice, &carol, welcome, 1)
        .await
        .unwrap();
    assert!(commit_report.met_required_acks());
    assert!(welcome_report.met_required_acks());
    alice.session.confirm_published(pending).await.unwrap();
    assert_eq!(alice.session.epoch(&created.group_id).unwrap(), EpochId(2));

    let commit_event = stack.take_next_published();
    assert_eq!(commit_event.endpoints, vec![stack.group_endpoint()]);
    let bob_commit = stack
        .deliver_event_to_session(
            &mut bob,
            stack.group_endpoint(),
            "bob-commit",
            commit_event.event,
        )
        .await
        .expect("commit delivery should reach bob");
    assert!(matches!(bob_commit.outcome, IngestOutcome::Buffered { .. }));
    bob.session.set_convergence_policy(CanonicalizationPolicy {
        stable_quiescence_ms: 0,
        ..CanonicalizationPolicy::default()
    });
    bob.session
        .advance_convergence(&created.group_id)
        .await
        .unwrap();
    assert_eq!(bob.session.epoch(&created.group_id).unwrap(), EpochId(2));

    let welcome_event = stack.take_next_published();
    assert_eq!(welcome_event.endpoints, vec![carol.inbox_endpoint.clone()]);
    let carol_endpoint = carol.inbox_endpoint.clone();
    let carol_joined = stack
        .deliver_event_to_session(
            &mut carol,
            carol_endpoint,
            "carol-welcome",
            welcome_event.event,
        )
        .await
        .expect("welcome delivery should reach carol");
    assert_eq!(
        carol_joined.effects.events,
        vec![GroupEvent::GroupJoined {
            group_id: created.group_id.clone(),
            via_welcome: welcome_report.message_id,
        }]
    );
    assert_eq!(carol.session.epoch(&created.group_id).unwrap(), EpochId(2));
}

async fn create_group_for_bob(alice: &mut StackClient, bob: &mut StackClient) -> CreatedGroup {
    let bob_key_package = bob.session.fresh_key_package().await.unwrap();
    let created = alice
        .session
        .create_group(CreateGroupRequest {
            name: "nostr-stack".into(),
            description: "session adapter peeler integration".into(),
            members: vec![bob_key_package],
            required_features: vec![],
            app_components: vec![support::nostr_stack::nostr_routing_component(
                b"nostr-stack",
            )],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    CreatedGroup::from_effects(created)
}

async fn publish_app_event(
    stack: &NostrStackHarness,
    sender: &mut StackClient,
    group_id: &cgka_traits::GroupId,
    payload: &[u8],
) -> transport_nostr_peeler::NostrTransportEvent {
    let app_message = send_app_message(sender, group_id, payload).await;
    let report = stack
        .publish_group(sender, group_id, app_message, 1)
        .await
        .unwrap();
    assert!(report.met_required_acks());
    stack.take_one_published().event
}

async fn send_app_message(
    sender: &mut StackClient,
    group_id: &cgka_traits::GroupId,
    payload: &[u8],
) -> cgka_traits::TransportMessage {
    let sent = sender
        .session
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: payload.to_vec(),
        })
        .await
        .unwrap();
    match &sent.publish[0] {
        PublishWork::ApplicationMessage { msg } => msg.clone(),
        other => panic!("expected application message publish work, got {other:?}"),
    }
}

fn message_payloads(ingest: &IngestEffects) -> Vec<Vec<u8>> {
    ingest
        .effects
        .events
        .iter()
        .filter_map(|event| match event {
            GroupEvent::MessageReceived { payload, .. } => Some(payload.clone()),
            _ => None,
        })
        .collect()
}

async fn publish_confirm_and_deliver_welcome(
    stack: &NostrStackHarness,
    alice: &mut StackClient,
    bob: &mut StackClient,
    pending: cgka_traits::PendingStateRef,
    welcome: cgka_traits::TransportMessage,
) -> TransportPublishReport {
    let welcome_report = stack.publish_welcome(alice, bob, welcome, 1).await.unwrap();
    assert!(welcome_report.met_required_acks());
    let confirmed = alice.session.confirm_published(pending).await.unwrap();
    assert_eq!(confirmed.events.len(), 1);

    let joined = stack
        .deliver_next_to_inbox_session(bob)
        .await
        .expect("welcome delivery should reach bob");
    assert_eq!(
        joined.effects.events,
        vec![GroupEvent::GroupJoined {
            group_id: match &confirmed.events[0] {
                GroupEvent::GroupCreated { group_id } => group_id.clone(),
                other => panic!("expected GroupCreated event, got {other:?}"),
            },
            via_welcome: welcome_report.message_id.clone(),
        }]
    );
    welcome_report
}

fn backup_inbox(label: &str) -> TransportEndpoint {
    TransportEndpoint(format!("wss://{label}-backup.example"))
}
