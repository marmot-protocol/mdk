//! A host's direct group change that a later pass rolls back is recorded as
//! not delivered (mdk#2332).
//!
//! The call that stages a change returns its rollback as the call's own
//! error, so only a later pass (a retry, a wake, a resume) leaves a caller
//! holding an unresolved result. An automatic commit has no such caller.

use super::*;
use cgka_engine::RollbackPass;
use cgka_traits::engine::GroupEvent;
use cgka_traits::storage::{ChangeNotDelivered, ChangeOrigin};
use cgka_traits::{
    EpochState, TransportEndpoint, TransportEndpointFailure, TransportEndpointFailureKind,
    TransportPublishRequest, TransportPublishTarget,
};

/// Which send staged the change.
#[derive(Clone, Copy, Debug)]
enum Sender {
    Host,
    Automatic,
}

/// Stage one change and store its fanout, every target refused before it
/// could hold the commit.
async fn refused_change(
    sender: Sender,
) -> (
    cgka_engine::Engine<SqliteAccountStorage>,
    SqliteAccountStorage,
    GroupId,
    cgka_traits::PendingStateRef,
    OutboundFanout,
) {
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut engine = build_engine_with_storage(b"change-not-delivered", storage.clone());
    let (group_id, created) = engine
        .create_group(CreateGroupRequest {
            name: "not delivered".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, .. } = created else {
        panic!("create")
    };
    engine.confirm_published(pending).await.unwrap();
    let (msg, pending) = evolution(match sender {
        Sender::Host => engine
            .send_host_change_with_audit_context(
                SendIntent::UpdateGroupData {
                    group_id: group_id.clone(),
                    name: Some("never applied".into()),
                    description: None,
                },
                None,
            )
            .await
            .unwrap(),
        Sender::Automatic => engine
            .send(SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            })
            .await
            .unwrap(),
    });
    engine.drain_events();
    let TransportEnvelope::GroupMessage { transport_group_id } = &msg.envelope else {
        panic!("a group commit: {:?}", msg.envelope)
    };
    let refusing = TransportEndpoint("wss://not-delivered-refusing.example".into());
    let mut fanout = OutboundFanout::stage(
        TransportPublishRequest {
            account_id: engine.self_id(),
            message: msg.clone(),
            target: TransportPublishTarget::Group {
                group_id: group_id.clone(),
                transport_group_id: transport_group_id.clone(),
                endpoints: vec![refusing.clone()],
            },
            required_acks: 1,
        },
        Some(pending),
        Some(group_id.clone()),
        0,
    )
    .unwrap();
    if let Some(kind) = engine.host_change_kind(pending) {
        fanout.set_host_change(kind).unwrap();
    }
    engine.put_outbound_fanout(&fanout).unwrap();
    fanout.mark_attempt_started_at(0, 100).unwrap();
    engine.put_outbound_fanout(&fanout).unwrap();
    fanout
        .record_target_failure(
            0,
            TransportEndpointFailure {
                endpoint: refusing,
                reason: "scripted refusal".into(),
                kind: TransportEndpointFailureKind::TerminalRejected,
                rejection_category: None,
                size_class: None,
                pre_send: false,
            },
        )
        .unwrap();
    engine.put_outbound_fanout(&fanout).unwrap();
    assert!(fanout.outcome().fanout_complete && !fanout.possible_exposure());
    (engine, storage, group_id, pending, fanout)
}

/// Only a host's change rolled back on a later pass is recorded and
/// announced; the staging pass and an automatic commit leave nothing behind.
/// The record outlives the events and goes once the host acknowledges it.
#[tokio::test]
async fn a_host_change_rolled_back_on_a_later_pass_is_recorded_not_delivered() {
    for (sender, pass, recorded) in [
        (Sender::Host, RollbackPass::Staging, false),
        (Sender::Host, RollbackPass::Later, true),
        (Sender::Automatic, RollbackPass::Later, false),
    ] {
        let (mut engine, storage, group_id, pending, mut fanout) = refused_change(sender).await;
        assert_eq!(
            engine.host_change_kind(pending),
            matches!(sender, Sender::Host).then_some("update_group_data"),
            "{sender:?}"
        );
        engine
            .publish_failed_fanout(pending, &mut fanout, pass)
            .await
            .unwrap();
        assert!(matches!(
            engine.epoch_state(&group_id),
            Some(EpochState::Stable { .. })
        ));
        assert_eq!(engine.host_change_kind(pending), None);
        let records = storage.changes_not_delivered(&group_id).unwrap();
        let announced: Vec<_> = engine
            .drain_events()
            .into_iter()
            .filter(|event| matches!(event, GroupEvent::GroupChangeNotDelivered { .. }))
            .collect();
        if !recorded {
            assert!(records.is_empty(), "{sender:?} {pass:?}: {records:?}");
            assert!(announced.is_empty(), "{sender:?} {pass:?}: {announced:?}");
            continue;
        }
        let commit_id = fanout.message_id().clone();
        assert!(
            matches!(
                records.as_slice(),
                [ChangeNotDelivered {
                    group_id: recorded_group,
                    commit_id: recorded_commit,
                    origin: ChangeOrigin::Direct,
                    intent_kind,
                    reason,
                    ..
                }] if *recorded_group == group_id
                    && *recorded_commit == commit_id
                    && intent_kind == "update_group_data"
                    && reason == "refused"
            ),
            "{records:?}"
        );
        assert!(
            matches!(
                announced.as_slice(),
                [GroupEvent::GroupChangeNotDelivered {
                    group_id: announced_group,
                    commit_id: announced_commit,
                    intent_kind,
                    reason,
                }] if *announced_group == group_id
                    && *announced_commit == commit_id
                    && intent_kind == "update_group_data"
                    && reason == "refused"
            ),
            "{announced:?}"
        );
        assert_ne!(
            engine.group_record(&group_id).unwrap().name,
            "never applied"
        );

        // A later change confirming leaves the record for the host.
        let (_, next) = evolution(
            engine
                .send(SendIntent::SelfUpdate {
                    group_id: group_id.clone(),
                })
                .await
                .unwrap(),
        );
        engine.confirm_published(next).await.unwrap();
        assert_eq!(storage.changes_not_delivered(&group_id).unwrap(), records);

        assert!(
            storage
                .delete_change_not_delivered(&group_id, &commit_id)
                .unwrap()
        );
        assert!(
            !storage
                .delete_change_not_delivered(&group_id, &commit_id)
                .unwrap()
        );
        assert!(storage.changes_not_delivered(&group_id).unwrap().is_empty());
    }
}
