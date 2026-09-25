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
    client
        .execute_recovery_grant(grant, None, None)
        .await
        .unwrap();
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
