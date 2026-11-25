//! A queued intent that the settled state refuses is retired and announced,
//! and the drain goes on to the work queued behind it (mdk#2694).
//!
//! Carol, an admin, queues an admin change behind alice's unsettled Commit
//! that demotes her, and a self-update behind that. Once the group settles,
//! preparing the change fails `NotGroupAdmin`, as the same change sent
//! directly would. It used to stay queued and fail every later drain, so the
//! self-update never went out.

use super::*;
use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_AGENT_STREAM_START;

/// Alice's confirmed Commit that leaves only alice an admin, routed for
/// delivery to carol.
async fn alice_demotes_carol(
    alice: &mut Engine<SqliteAccountStorage>,
    group_id: &GroupId,
) -> TransportMessage {
    let result = alice
        .send(SendIntent::UpdateAppComponents {
            group_id: group_id.clone(),
            updates: vec![cgka_traits::app_components::AppComponentData {
                component_id: GROUP_ADMIN_POLICY_COMPONENT_ID,
                data: encode_admin_policy_for_test(&[alice.self_id()]),
            }],
        })
        .await
        .unwrap();
    let (commit, pending) = evolution(result);
    alice.confirm_published(pending).await.unwrap();
    route(commit, group_id)
}

/// Carol after draining an intent she queued before her demotion settled.
struct DemotedDrain {
    carol: Engine<SqliteAccountStorage>,
    carol_storage: SqliteAccountStorage,
    group_id: GroupId,
    /// The id `SendResult::Queued` returned for the refused intent.
    intent_id: MessageId,
    drained: Vec<SendResult>,
    events: Vec<GroupEvent>,
}

impl DemotedDrain {
    fn queued(&self) -> Vec<SendIntent> {
        self.carol_storage
            .list_queued_outbound_intents(&self.group_id)
            .unwrap()
            .into_iter()
            .map(|record| record.intent)
            .collect()
    }

    fn refusals(&self) -> Vec<&GroupEvent> {
        self.events
            .iter()
            .filter(|event| matches!(event, GroupEvent::QueuedIntentRefused { .. }))
            .collect()
    }
}

/// Carol queues `intent` behind alice's unsettled demotion of her, then a
/// self-update behind it, and drains three times. Every drain must succeed.
async fn drain_after_demotion(intent: impl FnOnce(&GroupId) -> SendIntent) -> DemotedDrain {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let group_id = create_reservation_test_group(&mut alice, &mut carol, "refused-queued").await;

    let demotion = alice_demotes_carol(&mut alice, &group_id).await;
    assert!(matches!(
        carol.ingest(demotion).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));
    let intent_id = match carol.send(intent(&group_id)).await {
        Ok(SendResult::Queued { intent_id, .. }) => intent_id,
        other => panic!("the change waits for the demotion to settle: {other:?}"),
    };
    let queued = carol
        .send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await;
    assert!(
        matches!(queued, Ok(SendResult::Queued { .. })),
        "{queued:?}"
    );
    carol.drain_events();

    let mut drained = Vec::new();
    let mut events = Vec::new();
    for pass in 0..3 {
        drained.extend(
            carol
                .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000 + pass * 1_000)
                .await
                .expect("a refused queued intent must not fail the drain"),
        );
        events.extend(carol.drain_events());
    }
    assert!(
        !carol.group_authority(&group_id).unwrap().facts.is_admin,
        "the demotion settled"
    );
    DemotedDrain {
        carol,
        carol_storage,
        group_id,
        intent_id,
        drained,
        events,
    }
}

/// The refused intent is retired and announced once, with its kind and the
/// refusal's privacy-safe name, and the self-update behind it drains.
#[track_caller]
fn assert_refused_and_retired(drain: &DemotedDrain, intent_kind: &str) {
    match drain.refusals().as_slice() {
        [
            GroupEvent::QueuedIntentRefused {
                group_id,
                intent_id,
                intent_kind: kind,
                reason,
                artifact: None,
                size_class: None,
                app_event_id: None,
            },
        ] => {
            assert_eq!(group_id, &drain.group_id);
            assert_eq!(intent_id, &drain.intent_id);
            assert_eq!(kind, intent_kind);
            assert_eq!(reason, "not_group_admin");
        }
        other => panic!("expected one refusal announcement, got {other:?}"),
    }
    assert!(
        matches!(
            drain.drained.as_slice(),
            [SendResult::GroupEvolution { .. }]
        ),
        "the self-update queued behind the refused intent drains: {:?}",
        drain.drained
    );
    assert_eq!(
        drain.queued(),
        vec![SendIntent::SelfUpdate {
            group_id: drain.group_id.clone(),
        }],
        "only the in-flight self-update is still queued"
    );
}

#[tokio::test]
async fn a_queued_rename_refused_after_demotion_is_retired_and_never_prepared_again() {
    let mut drain = drain_after_demotion(|group_id| SendIntent::UpdateGroupData {
        group_id: group_id.clone(),
        name: Some("renamed by a demoted admin".into()),
        description: None,
    })
    .await;
    assert_refused_and_retired(&drain, "update_group_data");

    let (_, pending) = evolution(drain.drained.remove(0));
    drain.carol.confirm_published(pending).await.unwrap();
    assert!(drain.queued().is_empty());
    for pass in 0..2 {
        let again = drain
            .carol
            .converge_and_drain_queued_outbound_intents(&drain.group_id, 2_000_000 + pass)
            .await
            .unwrap();
        assert!(again.is_empty(), "{again:?}");
    }
    assert!(
        !drain
            .carol
            .drain_events()
            .iter()
            .any(|event| matches!(event, GroupEvent::QueuedIntentRefused { .. })),
        "a retired intent is announced once"
    );
    assert_eq!(
        drain.carol.group_record(&drain.group_id).unwrap().name,
        "refused-queued",
        "the refused rename was never committed"
    );
}

#[tokio::test]
async fn a_queued_invite_refused_after_demotion_is_retired() {
    let (mut dave, _dave_storage) = build_client(b"dave");
    let dave_kp = dave.fresh_key_package().await.unwrap();
    let drain = drain_after_demotion(|group_id| SendIntent::Invite {
        group_id: group_id.clone(),
        key_packages: vec![dave_kp],
        initial_admins: vec![],
    })
    .await;
    assert_refused_and_retired(&drain, "invite");
}

#[tokio::test]
async fn a_queued_removal_refused_after_demotion_is_retired() {
    let alice_id = build_client(b"alice").0.self_id();
    let drain = drain_after_demotion(|group_id| SendIntent::RemoveMembers {
        group_id: group_id.clone(),
        members: vec![alice_id],
    })
    .await;
    assert_refused_and_retired(&drain, "remove_members");
}

#[tokio::test]
async fn a_queued_enable_disbanding_refused_after_demotion_is_retired() {
    let drain = drain_after_demotion(|group_id| SendIntent::EnableDisbanding {
        group_id: group_id.clone(),
    })
    .await;
    assert_refused_and_retired(&drain, "enable_disbanding");
}

#[tokio::test]
async fn a_queued_admin_policy_edit_refused_after_demotion_is_retired() {
    let carol_id = build_client(b"carol").0.self_id();
    let drain = drain_after_demotion(|group_id| SendIntent::UpdateAppComponents {
        group_id: group_id.clone(),
        updates: vec![cgka_traits::app_components::AppComponentData {
            component_id: GROUP_ADMIN_POLICY_COMPONENT_ID,
            data: encode_admin_policy_for_test(&[carol_id]),
        }],
    })
    .await;
    assert_refused_and_retired(&drain, "update_app_components");
}

/// An Invite whose KeyPackage a direct send would refuse is refused when sent
/// during convergence, not queued: the sender is answered at once, as from a
/// direct send, rather than by a later refusal announcement.
#[tokio::test]
async fn an_invite_with_a_bad_key_package_signature_is_refused_before_it_is_queued() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let carol_storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut carol = build_client_with_storage_and_clock(b"carol", carol_storage.clone(), clock);
    let (mut dave, _dave_storage) = build_client(b"dave");
    let group_id = create_reservation_test_group(&mut alice, &mut carol, "bad-key-package").await;
    let rename = alice_rename_commit(&mut alice, &group_id, "unsettled").await;
    assert!(matches!(
        carol.ingest(rename).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));

    let valid_key_package = dave.fresh_key_package().await.unwrap();
    let mut key_package = valid_key_package.clone();
    // The KeyPackage's signature is its last field.
    *key_package.bytes.last_mut().unwrap() ^= 0x01;
    let sent = carol
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![key_package],
            initial_admins: vec![],
        })
        .await;
    assert!(
        matches!(&sent, Err(cgka_traits::error::EngineError::Backend(reason)) if reason.starts_with("key_package validate:")),
        "{sent:?}"
    );
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty(),
        "nothing was queued"
    );
    let valid = carol
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![valid_key_package],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    assert!(matches!(valid, SendResult::Queued { .. }), "{valid:?}");
    assert_eq!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1
    );
}

/// A retired agent stream start (kind 1200) queued before an upgrade is
/// retired at drain, never published (agent-text-stream-quic-v1.md,
/// "Retirement"), and the chat queued behind it still goes out.
#[tokio::test]
async fn a_queued_retired_stream_start_is_retired_not_published() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let carol_storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut carol = build_client_with_storage_and_clock(b"carol", carol_storage.clone(), clock);
    let group_id = create_reservation_test_group(&mut alice, &mut carol, "stream-start").await;
    let rename = alice_rename_commit(&mut alice, &group_id, "unsettled").await;
    assert!(matches!(
        carol.ingest(rename).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));

    let carol_hex = hex::encode(carol.self_id().as_slice());
    let mut intent_ids = Vec::new();
    for (kind, created_at) in [
        (MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, 1_700_000_000),
        (MARMOT_APP_EVENT_KIND_CHAT, 1_700_000_001),
    ] {
        let payload =
            MarmotAppEvent::new(carol_hex.clone(), created_at, kind, vec![], "x".to_owned())
                .encode()
                .unwrap();
        match carol
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload,
                expected_epoch: None,
                only_to_members: None,
            })
            .await
        {
            Ok(SendResult::Queued { intent_id, .. }) => intent_ids.push(intent_id),
            other => panic!("the send waits for the rename to settle: {other:?}"),
        }
    }
    carol.drain_events();

    let drained = carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .unwrap();
    let events = carol.drain_events();

    assert!(
        matches!(drained.as_slice(), [SendResult::ApplicationMessage { .. }]),
        "only the chat is published: {drained:?}"
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            GroupEvent::QueuedIntentRefused { intent_id, .. } if intent_id == &intent_ids[0]
        )),
        "{events:?}"
    );
    let queued_ids = carol_storage
        .list_queued_outbound_intents(&group_id)
        .unwrap()
        .into_iter()
        .map(|record| record.id)
        .collect::<Vec<_>>();
    assert!(!queued_ids.contains(&intent_ids[0]), "{queued_ids:?}");
}

/// A message limited to its members (`only_to_members`) and queued while an
/// Add is unsettled is refused at drain once the Add merges, instead of being
/// encrypted to the new member; one that lists the new member still goes out.
/// A direct send is refused the same way.
#[tokio::test]
async fn a_queued_message_not_for_a_new_member_is_refused_once_the_add_merges() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut dave, _dave_storage) = build_client(b"dave");
    let group_id = create_reservation_test_group(&mut alice, &mut carol, "only-to-members").await;
    let dave_kp = dave.fresh_key_package().await.unwrap();
    let (add, pending) = evolution(
        alice
            .send(SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages: vec![dave_kp],
                initial_admins: vec![],
            })
            .await
            .unwrap(),
    );
    alice.confirm_published(pending).await.unwrap();
    assert!(matches!(
        carol.ingest(route(add, &group_id)).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));

    let carol_hex = hex::encode(carol.self_id().as_slice());
    let members = vec![alice.self_id(), carol.self_id()];
    let message = |created_at, only_to_members| {
        let event = MarmotAppEvent::new(
            carol_hex.clone(),
            created_at,
            MARMOT_APP_EVENT_KIND_CHAT,
            vec![],
            "x".to_owned(),
        );
        (
            event.id.clone(),
            SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: event.encode().unwrap(),
                expected_epoch: None,
                only_to_members: Some(only_to_members),
            },
        )
    };
    let (refused_event_id, not_for_dave) = message(1_700_000_000, members.clone());
    let (_, for_dave) = message(
        1_700_000_001,
        vec![alice.self_id(), carol.self_id(), dave.self_id()],
    );
    let mut intent_ids = Vec::new();
    for intent in [not_for_dave, for_dave] {
        match carol.send(intent).await {
            Ok(SendResult::Queued { intent_id, .. }) => intent_ids.push(intent_id),
            other => panic!("the send waits for the Add to settle: {other:?}"),
        }
    }
    carol.drain_events();

    let drained = carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .unwrap();
    let events = carol.drain_events();

    assert!(
        matches!(drained.as_slice(), [SendResult::ApplicationMessage { .. }]),
        "only the message that lists dave is published: {drained:?}"
    );
    let refusals = events
        .iter()
        .filter(|event| matches!(event, GroupEvent::QueuedIntentRefused { .. }))
        .collect::<Vec<_>>();
    match refusals.as_slice() {
        [
            GroupEvent::QueuedIntentRefused {
                intent_id,
                reason,
                app_event_id,
                ..
            },
        ] => {
            assert_eq!(intent_id, &intent_ids[0]);
            assert_eq!(reason, "app_message_new_members");
            assert_eq!(app_event_id.as_deref(), Some(refused_event_id.as_str()));
        }
        other => panic!("expected one refusal announcement, got {other:?}"),
    }
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .iter()
            .all(|record| record.id != intent_ids[0]),
        "the refused message is no longer queued"
    );

    let (_, direct) = message(1_700_000_002, members);
    assert!(matches!(
        carol.send(direct).await,
        Err(cgka_traits::error::EngineError::AppMessageNewMembers)
    ));
}
