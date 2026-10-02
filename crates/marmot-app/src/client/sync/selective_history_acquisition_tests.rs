use crate::MarmotApp;
use crate::tests::{
    ScriptedPushRelayClient, client_on_app_relay_plane, every_subscription, scripted_eose_pump,
};
use marmot_forensics::EpochBackfillExecutionSeam;
use std::sync::Arc;
use storage_sqlite::TransportReconciliationRoute;
use transport_nostr_adapter::NostrReconciliationSummary;

#[tokio::test]
async fn unfinished_selected_id_suffix_stays_pending_and_owner_paced() {
    let dir = tempfile::tempdir().unwrap();
    crate::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let _pump = scripted_eose_pump(app.relay_plane.clone(), relay, every_subscription);
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    client.create_group("selected suffix", &[]).await.unwrap();
    client.request_bounded_comparison().unwrap();
    let storage = app.account_storage("alice").unwrap();
    let before = storage.recovery_comparison().unwrap();
    assert!(before.pending());
    let grant = client
        .authorize_account_recovery(None, EpochBackfillExecutionSeam::Startup)
        .unwrap()
        .unwrap();
    assert_eq!(grant.inventory.len(), 2);
    client.test_comparison_results = Some(
        grant
            .inventory
            .iter()
            .map(|inventory| {
                Ok(Some((
                    if matches!(inventory.route, TransportReconciliationRoute::Group(_)) {
                        NostrReconciliationSummary {
                            relays_succeeded: 0,
                            relays_failed: 1,
                            remote_items: 17,
                            received_items: 16,
                            ..Default::default()
                        }
                    } else {
                        NostrReconciliationSummary {
                            relays_succeeded: 1,
                            ..Default::default()
                        }
                    },
                    Vec::new(),
                )))
            })
            .collect(),
    );
    client.run_recovery_grant_for_test(grant).await.unwrap();
    assert!(client.test_comparison_results.as_ref().unwrap().is_empty());

    let after = storage.recovery_comparison().unwrap();
    assert!(
        after.pending(),
        "a selected but unadmitted suffix is still debt"
    );
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.settled_revision, before.settled_revision);
    let plan = after.plan.unwrap();
    assert_eq!(plan.retry_routes.len(), 1);
    assert_eq!(
        plan.routes
            .iter()
            .find(|route| route.scope_id == plan.retry_routes[0])
            .unwrap()
            .route_kind,
        1
    );

    let retry_state = storage.recovery_retry_state().unwrap();
    assert!(
        client
            .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
            .unwrap()
            .is_none(),
        "an incomplete comparison cannot bypass owner pacing"
    );
    assert_eq!(storage.recovery_retry_state().unwrap(), retry_state);
    client.recovery_owner.test_advance_to_retry(&storage);
    let retry = client
        .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
        .unwrap()
        .unwrap();
    assert_eq!(retry.inventory.len(), 1);
    assert!(matches!(
        retry.inventory[0].route,
        TransportReconciliationRoute::Group(_)
    ));
}

/// Run one owner-paced comparison pass whose group route returns `summary`.
async fn run_group_comparison(
    client: &mut crate::client::AppClient,
    storage: &storage_sqlite::SqliteAccountStorage,
    summary: fn(&[cgka_traits::TransportEndpoint]) -> NostrReconciliationSummary,
) {
    client.request_bounded_comparison().unwrap();
    client.recovery_owner.test_advance_to_retry(storage);
    let grant = client
        .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
        .unwrap()
        .unwrap();
    client.test_comparison_results = Some(
        grant
            .inventory
            .iter()
            .map(|inventory| {
                Ok(Some((
                    if matches!(inventory.route, TransportReconciliationRoute::Group(_)) {
                        summary(inventory.work.endpoints())
                    } else {
                        NostrReconciliationSummary {
                            relays_succeeded: 1,
                            ..Default::default()
                        }
                    },
                    Vec::new(),
                )))
            })
            .collect(),
    );
    client.run_recovery_grant_for_test(grant).await.unwrap();
}

/// A comparison that learned nothing proves nothing was downloaded. A route
/// whose relay failed negotiation names no IDs, so it must keep the hold an
/// earlier pass installed until a certified pass finds nothing missing
/// (mdk#2086).
#[tokio::test]
async fn failed_comparison_keeps_the_history_acquisition_hold() {
    use cgka_traits::storage::HistoryAcquisitionHoldStorage;

    let dir = tempfile::tempdir().unwrap();
    crate::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let _pump = scripted_eose_pump(app.relay_plane.clone(), relay, every_subscription);
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group_id = client.create_group("held", &[]).await.unwrap();
    let storage = app.account_storage("alice").unwrap();

    // The relay names one event this pass did not return.
    run_group_comparison(&mut client, &storage, |_| NostrReconciliationSummary {
        relays_failed: 1,
        remote_items: 1,
        unreturned_items: 1,
        ..Default::default()
    })
    .await;
    assert!(storage.history_acquisition_held(&group_id).unwrap());

    // The next comparison fails negotiation: it names nothing.
    run_group_comparison(&mut client, &storage, |endpoints| {
        NostrReconciliationSummary {
            relays_failed: 1,
            failed_endpoints: endpoints.to_vec(),
            ..Default::default()
        }
    })
    .await;
    assert!(
        storage.history_acquisition_held(&group_id).unwrap(),
        "a comparison that learned nothing keeps the hold"
    );

    // A certified comparison that finds nothing missing releases it.
    run_group_comparison(&mut client, &storage, |_| NostrReconciliationSummary {
        relays_succeeded: 1,
        ..Default::default()
    })
    .await;
    assert!(!storage.history_acquisition_held(&group_id).unwrap());
}
