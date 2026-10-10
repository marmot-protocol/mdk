//! Restart scheduling must separate required publication from secondary replication.
use super::*;
use crate::MarmotApp;
use crate::tests::{ScriptedPushRelayClient, client_on_app_relay_plane};
use cgka_traits::{
    MarmotAppEvent, MessageId, OutboundFanout, Timestamp, TransportEndpoint,
    TransportEndpointFailure, TransportEndpointFailureKind, TransportEnvelope, TransportMessage,
    TransportPublishRequest, TransportPublishTarget, TransportSource,
};
use marmot_account::AccountHome;
use std::sync::Arc;

#[tokio::test]
async fn restarted_safe_queued_send_does_not_inherit_secondary_retry_cutoff() {
    assert_restart_schedule(1).await;
}

#[tokio::test]
async fn restarted_below_quorum_send_keeps_required_retry_cutoff() {
    assert_restart_schedule(2).await;
}

async fn assert_restart_schedule(required_acks: usize) {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group = client.create_group("queued restart", &[]).await.unwrap();
    let account = client.runtime.session().self_id();
    let payload = MarmotAppEvent::new(
        hex::encode(account.as_slice()),
        1_700_000_000,
        9,
        vec![],
        "queued restart",
    )
    .encode()
    .unwrap();
    client
        .runtime
        .session_mut()
        .queue_app_message_with_audit_context(group.clone(), payload, Default::default())
        .await
        .unwrap();
    let now = crate::unix_now_seconds() * 1_000;
    let secondary = TransportEndpoint("wss://secondary.example".into());
    let mut retained = OutboundFanout::stage(
        TransportPublishRequest {
            account_id: account,
            message: TransportMessage {
                id: MessageId::new(vec![0xa1; 32]),
                payload: vec![0xa1],
                timestamp: Timestamp(100),
                causal_deps: vec![],
                source: TransportSource("scheduler-fixture".into()),
                envelope: TransportEnvelope::GroupMessage {
                    transport_group_id: group.as_slice().to_vec(),
                },
            },
            target: TransportPublishTarget::Group {
                group_id: group.clone(),
                transport_group_id: group.as_slice().to_vec(),
                endpoints: vec![
                    TransportEndpoint("wss://relay.example".into()),
                    secondary.clone(),
                ],
            },
            required_acks,
        },
        None,
        None,
        now,
    )
    .unwrap();
    retained.mark_attempt_started_at(0, now).unwrap();
    retained.mark_target_accepted(0).unwrap();
    retained.mark_attempt_started_at(1, now).unwrap();
    retained
        .record_target_failure(
            1,
            TransportEndpointFailure {
                endpoint: secondary,
                reason: "acknowledgement unknown".into(),
                kind: TransportEndpointFailureKind::PossiblyExposed,
                rejection_category: None,
            },
        )
        .unwrap();
    client
        .runtime
        .session()
        .put_outbound_fanout(&retained)
        .unwrap();
    drop(client);

    // Local reopen restores persisted work without an inbound event or network-maintenance drain.
    let mut reopened = app
        .local_client_with_relay_plane("alice", &app.relay_plane, None)
        .await
        .unwrap();
    assert!(
        !reopened
            .runtime
            .has_pending_convergence_inputs(&group)
            .unwrap()
    );
    assert!(
        reopened
            .runtime
            .outbound_fanout_retry_delay_ms(&group)
            .unwrap()
            .unwrap()
            > 20_000
    );
    let schedule = reopened.convergence_schedule_state(&group).unwrap();
    if required_acks == 1 {
        assert_eq!(
            schedule,
            ConvergenceScheduleState::PendingOutbound {
                retry_after_ms: None
            },
            "restart must arm the queued send independently of secondary replication"
        );
        reopened.prepare_transport().await.unwrap();
        let effects = reopened.runtime.advance_convergence(&group).await.unwrap();
        assert_eq!(effects.published_app_messages.len(), 1);
        assert!(
            !reopened
                .runtime
                .has_queued_outbound_intents(&group)
                .unwrap()
        );
        let fanouts = reopened
            .runtime
            .session()
            .outbound_fanouts_for_group(&group)
            .unwrap();
        assert!(
            fanouts.iter().any(|fanout| fanout == &retained),
            "the older exact-byte retry must remain unchanged"
        );
    } else {
        assert!(
            matches!(schedule, ConvergenceScheduleState::PendingOutbound { retry_after_ms: Some(ms) } if ms > 20_000)
        );
        let effects = reopened.runtime.advance_convergence(&group).await.unwrap();
        assert!(effects.published_app_messages.is_empty());
        assert!(
            reopened
                .runtime
                .has_queued_outbound_intents(&group)
                .unwrap()
        );
    }
}

#[tokio::test]
async fn publication_barrier_rejects_unhydrated_inventory() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group = client
        .create_group("deferred inventory", &[])
        .await
        .unwrap();
    drop(client);
    let mut reopened = app
        .local_client_with_relay_plane_and_hydration("alice", &app.relay_plane, None, true, None)
        .await
        .unwrap();
    assert!(
        reopened
            .runtime
            .session()
            .unhydrated_group_ids()
            .contains(&group)
    );
    assert!(
        reopened
            .runtime
            .queued_outbound_intents_blocked_by_fanouts(&group)
            .is_err(),
        "hidden fanouts must not certify an unhydrated group safe"
    );
    reopened
        .runtime
        .session_mut()
        .ensure_group_hydrated(&group)
        .unwrap();
    assert!(
        !reopened
            .runtime
            .queued_outbound_intents_blocked_by_fanouts(&group)
            .unwrap()
    );
}

#[tokio::test]
async fn publication_barrier_keeps_pending_mls_after_quorum() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group = client
        .create_group("pending confirmation", &[])
        .await
        .unwrap();
    let effects = client
        .runtime
        .session_mut()
        .send(cgka_traits::SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap();
    let (message, pending) = match &effects.publish[0] {
        cgka_session::PublishWork::GroupEvolution { msg, pending, .. } => (msg.clone(), *pending),
        other => panic!("expected staged evolution, got {other:?}"),
    };
    let transport_group_id = match &message.envelope {
        TransportEnvelope::GroupMessage { transport_group_id } => transport_group_id.clone(),
        other => panic!("expected group envelope, got {other:?}"),
    };
    let mut fanout = OutboundFanout::stage(
        TransportPublishRequest {
            account_id: client.runtime.session().self_id(),
            message,
            target: TransportPublishTarget::Group {
                group_id: group.clone(),
                transport_group_id,
                endpoints: vec![TransportEndpoint("wss://relay.example".into())],
            },
            required_acks: 1,
        },
        Some(pending),
        Some(group.clone()),
        crate::unix_now_seconds() * 1_000,
    )
    .unwrap();
    fanout.mark_attempt_started(0).unwrap();
    fanout.mark_target_accepted(0).unwrap();
    client
        .runtime
        .session()
        .put_outbound_fanout(&fanout)
        .unwrap();
    assert_eq!(fanout.outcome().outstanding_targets, 0);
    assert!(
        client
            .runtime
            .queued_outbound_intents_blocked_by_fanouts(&group)
            .unwrap(),
        "relay acknowledgement alone does not confirm the MLS transition"
    );
}
