//! A queued intent that the settled state refuses is retired and announced,
//! and the drain goes on to the work queued behind it (mdk#2694).
//!
//! Carol, an admin, queues an admin change behind alice's unsettled Commit
//! that demotes her, and a self-update behind that. Once the group settles,
//! preparing the change fails `NotGroupAdmin`, as the same change sent
//! directly would. It used to stay queued and fail every later drain, so the
//! self-update never went out.

use super::*;

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
    let (mut carol, carol_storage) = build_client(b"carol");
    let (mut dave, _dave_storage) = build_client(b"dave");
    let group_id = create_reservation_test_group(&mut alice, &mut carol, "bad-key-package").await;
    let rename = alice_rename_commit(&mut alice, &group_id, "unsettled").await;
    assert!(matches!(
        carol.ingest(rename).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));

    let mut key_package = dave.fresh_key_package().await.unwrap();
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
        matches!(sent, Err(cgka_traits::error::EngineError::Backend(_))),
        "{sent:?}"
    );
    assert!(
        carol_storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .is_empty(),
        "nothing was queued"
    );
}
