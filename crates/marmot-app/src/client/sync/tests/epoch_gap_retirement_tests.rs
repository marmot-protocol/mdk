use super::*;
use crate::tests::run_composed_app_runtime_test;
use cgka_traits::engine::SendIntent;
use cgka_traits::ingest::{DeferralLineage, IngestOutcome};
use cgka_traits::storage::MessageStorage;
use cgka_traits::{GroupId, MessageId, Timestamp, TransportDelivery, TransportDeliveryPlane};
use storage_sqlite::{RecoveryCause, RecoveryDemandTicket, SqliteAppStorage};
use transport_nostr_peeler::NostrTransportEvent;

async fn pair(
    dir: &tempfile::TempDir,
    relay: Arc<ScriptedPushRelayClient>,
) -> (MarmotApp, crate::AppClient, crate::AppClient, GroupId) {
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob_account = home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        crate::MarmotAppConfig::white_noise()
            .with_dev_settlement_quiescence_ms(0)
            .with_dev_scheduled_convergence_delay_ms(0),
    )
    .with_test_relay_client(relay.clone());
    crate::tests::remember_test_member_inbox(
        &app,
        &bob_account.account_id_hex,
        "wss://relay.example",
    );
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();
    let mut alice = app.client("alice").await.unwrap();
    let group = alice
        .create_group("retirement", &[&bob_account.account_id_hex])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    let welcome = relay
        .attempted_events()
        .into_iter()
        .find(|event| {
            event.kind == 1059
                && event.tags.iter().any(|tag| {
                    tag.first().is_some_and(|value| value == "p")
                        && tag.get(1) == Some(&bob_account.account_id_hex)
                })
        })
        .expect("Bob's founding Welcome");
    bob.ingest_received_delivery(delivery(
        &bob,
        &welcome,
        TransportDeliveryPlane::AccountInbox,
    ))
    .await
    .unwrap();
    bob.sync().await.unwrap();
    bob.accept_group_invite(&group).unwrap();
    assert_eq!(
        alice.runtime.epoch_pin(&group).unwrap(),
        bob.runtime.epoch_pin(&group).unwrap()
    );
    (app, alice, bob, group)
}

fn delivery(
    client: &crate::AppClient,
    event: &NostrTransportEvent,
    plane: TransportDeliveryPlane,
) -> TransportDelivery {
    TransportDelivery {
        account_id: client.runtime.session().self_id(),
        group_id_hint: None,
        message: event.to_transport_message().unwrap(),
        received_at: Timestamp(crate::unix_now_seconds()),
        source: cgka_traits::TransportDeliverySource {
            transport: cgka_traits::transport::TransportSource("nostr".into()),
            plane,
            endpoint: None,
            subscription_id: None,
            wire: None,
        },
    }
}

fn group_events(
    relay: &ScriptedPushRelayClient,
    cursor: usize,
) -> impl Iterator<Item = NostrTransportEvent> {
    relay
        .attempted_events()
        .into_iter()
        .skip(cursor)
        .filter(|event| event.kind == transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE)
}

async fn self_update(client: &mut crate::AppClient, group: &GroupId) {
    client
        .runtime
        .send(SendIntent::SelfUpdate {
            group_id: group.clone(),
        })
        .await
        .unwrap();
}

async fn receive(receiver: &mut crate::AppClient, event: &NostrTransportEvent) -> IngestOutcome {
    let delivery = delivery(receiver, event, TransportDeliveryPlane::Group);
    receiver
        .runtime
        .ingest_delivery(&delivery)
        .await
        .unwrap()
        .outcome
}

fn gap_ticket(storage: &SqliteAppStorage, group: &GroupId, epoch: u64) -> RecoveryDemandTicket {
    let demands = storage.pending_recovery_demands().unwrap();
    let mut gaps = demands.iter().filter(|demand| {
        demand.cause == RecoveryCause::EpochGap
            && demand.group_id.as_deref() == Some(group.as_slice())
    });
    let gap = gaps.next().expect("outstanding epoch gap");
    assert_eq!(gap.stalled_epoch, Some(epoch));
    assert!(gaps.next().is_none(), "only one gap should be outstanding");
    gap.ticket
}

async fn retain_sample(
    sender: &mut crate::AppClient,
    receiver: &mut crate::AppClient,
    relay: &ScriptedPushRelayClient,
    group: &GroupId,
    lineage: DeferralLineage,
) -> MessageId {
    // Withhold Bob's next commit, so Alice cannot peel his new ciphertexts.
    self_update(sender, group).await;
    let cursor = relay.attempted_events().len();
    let threshold = receiver
        .history_recovery
        .test_state()
        .epoch_stall
        .threshold();
    for index in 0..threshold {
        sender
            .send(group, format!("retained-{index}").as_bytes())
            .await
            .unwrap();
    }
    // Ingest below the app detector, as when a frozen wake retains ciphertext.
    for event in group_events(relay, cursor) {
        assert!(matches!(
            receive(receiver, &event).await,
            IngestOutcome::TransportDeferred { .. }
        ));
    }
    let evidence = receiver
        .runtime
        .deferred_stall_evidence(group, threshold)
        .unwrap();
    assert_eq!(evidence.rows.len(), threshold);
    assert_eq!(evidence.lineage, lineage);
    evidence.rows.into_iter().next().unwrap().message_id
}

#[test]
fn contested_gap_survives() {
    run_composed_app_runtime_test("contested-gap", contested_gap_body);
}

async fn contested_gap_body() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let (app, mut alice, mut bob, group) = pair(&dir, relay.clone()).await;
    let account_storage = app.account_storage("alice").unwrap();
    let storage = account_storage.app_storage();
    let old_epoch = alice.runtime.group_record(&group).unwrap().epoch.0;
    storage
        .arm_epoch_backfill_intents(&armed_backfill(&group, old_epoch))
        .unwrap();
    let ticket = gap_ticket(&storage, &group, old_epoch);

    // Hold both children of the old epoch in Alice's commit graph.
    alice
        .runtime
        .session_mut()
        .set_convergence_policy(marmot_session::CanonicalizationPolicy {
            settlement_quiescence_ms: 3_600_000,
            ..marmot_session::CanonicalizationPolicy::default()
        })
        .unwrap();
    self_update(&mut alice, &group).await;
    let cursor = relay.attempted_events().len();
    self_update(&mut bob, &group).await;
    let rival = group_events(&relay, cursor).next().expect("rival commit");
    receive(&mut alice, &rival).await;
    assert_eq!(
        alice.runtime.group_record(&group).unwrap().epoch.0,
        old_epoch + 1
    );
    let retained = retain_sample(
        &mut bob,
        &mut alice,
        &relay,
        &group,
        DeferralLineage::ContestedFork,
    )
    .await;

    alice.queue_epoch_gap_handoffs();
    alice.finish_epoch_gap_handoff(&group).unwrap();
    assert!(
        alice.has_pending_epoch_backfill(),
        "a full contested sample cannot retire old demand"
    );
    assert!(gap_ticket(&storage, &group, old_epoch) == ticket);

    // Retire one retained delivery. The next assessment is below threshold.
    account_storage.delete_message(&retained).unwrap();
    alice.finish_epoch_gap_handoff(&group).unwrap();
    assert!(!alice.has_pending_epoch_backfill());
    assert!(storage.pending_epoch_backfill_intents().unwrap().is_empty());
}

#[test]
fn restored_gap_survives() {
    run_composed_app_runtime_test("restored-gap", restored_gap_body);
}

async fn restored_gap_body() {
    let dir = tempfile::tempdir().unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let (app, mut alice, mut bob, group) = pair(&dir, relay.clone()).await;
    let storage = app.account_storage("alice").unwrap().app_storage();
    let old_epoch = alice.runtime.group_record(&group).unwrap().epoch.0;
    storage
        .arm_epoch_backfill_intents(&armed_backfill(&group, old_epoch))
        .unwrap();
    let ticket = gap_ticket(&storage, &group, old_epoch);

    let cursor = relay.attempted_events().len();
    self_update(&mut bob, &group).await;
    let commit = group_events(&relay, cursor)
        .next()
        .expect("advancing commit");
    receive(&mut alice, &commit).await;
    alice.runtime.advance_convergence(&group).await.unwrap();
    let current_epoch = alice.runtime.group_record(&group).unwrap().epoch.0;
    assert_eq!(current_epoch, old_epoch + 1);
    let _ = retain_sample(
        &mut bob,
        &mut alice,
        &relay,
        &group,
        DeferralLineage::Uncontested,
    )
    .await;

    // Older writers could persist the fired latch after the arm write failed.
    app.record_epoch_stall_evidence(
        "alice",
        &[storage_sqlite::StoredEpochStallEvidence {
            group_id_hex: hex::encode(group.as_slice()),
            stalled_epoch: current_epoch,
            fruitless_completions: 0,
            fruitless_reported: false,
            last_arm_at_ms: crate::client::sync::epoch_stall_now_ms(),
        }],
        alice
            .history_recovery
            .test_state()
            .epoch_stall
            .fruitless_completion_threshold(),
    )
    .unwrap();
    drop(alice);
    let mut alice = app.client("alice").await.unwrap();
    let threshold = alice.history_recovery.test_state().epoch_stall.threshold();
    let retained = alice
        .runtime
        .deferred_stall_evidence(&group, threshold)
        .unwrap();
    assert_eq!(retained.epoch.0, current_epoch);
    assert_eq!(retained.rows.len(), threshold);
    assert!(gap_ticket(&storage, &group, old_epoch) == ticket);
    alice.queue_epoch_gap_handoffs();
    alice.finish_epoch_gap_handoff(&group).unwrap();
    assert!(
        alice.has_pending_epoch_backfill(),
        "a restored latch is not a durable successor"
    );
    assert!(gap_ticket(&storage, &group, old_epoch) == ticket);
}
