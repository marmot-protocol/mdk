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
    // Request a comparison only when no debt is pending: every new request
    // bumps the obligation revision, which restarts its parking streaks.
    client.recovery_owner.test_advance_to_retry(storage);
    let grant = match client
        .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
        .unwrap()
    {
        Some(grant) => grant,
        None => {
            client.request_bounded_comparison().unwrap();
            client.recovery_owner.test_advance_to_retry(storage);
            client
                .authorize_account_recovery(None, EpochBackfillExecutionSeam::Maintenance)
                .unwrap()
                .unwrap()
        }
    };
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

/// The one event the scripted comparisons name as missing.
const NAMED: [u8; 32] = [0xab; 32];

/// Durably admit `NAMED` on `group_id`'s route, as ingest would.
fn admit_named(app: &MarmotApp, group_id: &cgka_traits::GroupId) {
    let route: [u8; 32] = hex::decode(
        app.group("alice", &hex::encode(group_id.as_slice()))
            .unwrap()
            .unwrap()
            .nostr_routing
            .nostr_group_id_hex,
    )
    .unwrap()
    .try_into()
    .unwrap();
    app.account_storage("alice")
        .unwrap()
        .record_transport_reconciliation_item(
            &TransportReconciliationRoute::Group(route),
            &storage_sqlite::TransportReconciliationItem {
                event_id: NAMED,
                created_at: crate::unix_now_seconds(),
            },
        )
        .unwrap();
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
        remote_ids: vec![NAMED],
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

    // A comparison that no longer names it proves nothing either; the
    // event's durable admission is what releases the hold.
    run_group_comparison(&mut client, &storage, |_| NostrReconciliationSummary {
        relays_succeeded: 1,
        ..Default::default()
    })
    .await;
    assert!(storage.history_acquisition_held(&group_id).unwrap());
    admit_named(&app, &group_id);
    run_group_comparison(&mut client, &storage, |_| NostrReconciliationSummary {
        relays_succeeded: 1,
        ..Default::default()
    })
    .await;
    assert!(!storage.history_acquisition_held(&group_id).unwrap());
}

/// Known history a relay named but the pass did not return is debt even when
/// every required relay certified: a best-effort relay can be the only one
/// that has an older message. The route must not certify, so settlement
/// cannot satisfy the obligation and sweep the hold away (mdk#2086).
#[tokio::test]
async fn unreturned_history_withholds_the_certificate_that_would_release_the_hold() {
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

    // Every required relay finished, but a relay named one event this pass
    // did not return.
    run_group_comparison(&mut client, &storage, |_| NostrReconciliationSummary {
        relays_succeeded: 1,
        remote_items: 1,
        remote_ids: vec![NAMED],
        ..Default::default()
    })
    .await;
    assert!(
        storage.history_acquisition_held(&group_id).unwrap(),
        "named but undownloaded history keeps the hold through settlement"
    );

    admit_named(&app, &group_id);
    run_group_comparison(&mut client, &storage, |_| NostrReconciliationSummary {
        relays_succeeded: 1,
        ..Default::default()
    })
    .await;
    assert!(!storage.history_acquisition_held(&group_id).unwrap());
}

/// History a best-effort relay named stays owed when that relay later fails
/// to answer: the operated relay's clean comparison says nothing about it, so
/// the hold must survive both the checkpoint and settlement (mdk#2086).
#[tokio::test]
async fn debt_named_by_a_best_effort_relay_survives_its_later_failure() {
    use cgka_traits::storage::HistoryAcquisitionHoldStorage;
    const OPERATED: &str = "wss://operated.example";
    const BEST_EFFORT: &str = "wss://best-effort.example";

    let dir = tempfile::tempdir().unwrap();
    crate::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relays_and_config(
        dir.path(),
        vec!["wss://relay.example".into()],
        crate::MarmotAppConfig::default()
            .with_open_ranking_provider(None, Vec::new())
            .with_recovery_operated_relays(vec![OPERATED.into()]),
    )
    .with_test_relay_client(relay.clone());
    let _pump = scripted_eose_pump(app.relay_plane.clone(), relay, every_subscription);
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group_id = client
        .create_group_with_options(
            "best effort",
            &[],
            crate::AppCreateGroupOptions {
                relays: Some(vec![OPERATED.into(), BEST_EFFORT.into()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let storage = app.account_storage("alice").unwrap();

    // Both relays answer; the best-effort relay names an event this pass
    // did not return.
    run_group_comparison(&mut client, &storage, |_| NostrReconciliationSummary {
        relays_succeeded: 2,
        remote_items: 1,
        remote_ids: vec![NAMED],
        ..Default::default()
    })
    .await;
    assert!(storage.history_acquisition_held(&group_id).unwrap());

    // The operated relay certifies; the best-effort relay fails negotiation
    // and so names nothing.
    run_group_comparison(&mut client, &storage, |_| NostrReconciliationSummary {
        relays_succeeded: 1,
        relays_failed: 1,
        failed_endpoints: vec![cgka_traits::TransportEndpoint(BEST_EFFORT.into())],
        ..Default::default()
    })
    .await;
    assert!(
        storage.history_acquisition_held(&group_id).unwrap(),
        "a silent claimant keeps the debt it named"
    );

    // The event arrives.
    admit_named(&app, &group_id);
    run_group_comparison(&mut client, &storage, |_| NostrReconciliationSummary {
        relays_succeeded: 2,
        ..Default::default()
    })
    .await;
    assert!(!storage.history_acquisition_held(&group_id).unwrap());
}

/// A best-effort relay that is simply down named nothing, so it cannot keep
/// a hold on history the operated relay named and the account then admitted.
/// The group must not wait for recovery to park, or report missing history,
/// because of a relay that never claimed anything.
#[tokio::test]
async fn a_dead_best_effort_relay_does_not_block_the_release() {
    use cgka_traits::storage::HistoryAcquisitionHoldStorage;
    const OPERATED: &str = "wss://operated.example";
    const BEST_EFFORT: &str = "wss://best-effort.example";

    let dir = tempfile::tempdir().unwrap();
    crate::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relays_and_config(
        dir.path(),
        vec!["wss://relay.example".into()],
        crate::MarmotAppConfig::default()
            .with_open_ranking_provider(None, Vec::new())
            .with_recovery_operated_relays(vec![OPERATED.into()]),
    )
    .with_test_relay_client(relay.clone());
    let _pump = scripted_eose_pump(app.relay_plane.clone(), relay, every_subscription);
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group_id = client
        .create_group_with_options(
            "dead best effort",
            &[],
            crate::AppCreateGroupOptions {
                relays: Some(vec![OPERATED.into(), BEST_EFFORT.into()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let storage = app.account_storage("alice").unwrap();
    // The operated relay names one event; the best-effort relay is down.
    run_group_comparison(&mut client, &storage, |_| NostrReconciliationSummary {
        relays_succeeded: 1,
        relays_failed: 1,
        failed_endpoints: vec![cgka_traits::TransportEndpoint(BEST_EFFORT.into())],
        remote_items: 1,
        remote_ids: vec![NAMED],
        ..Default::default()
    })
    .await;
    assert!(storage.history_acquisition_held(&group_id).unwrap());

    admit_named(&app, &group_id);
    run_group_comparison(&mut client, &storage, |_| NostrReconciliationSummary {
        relays_succeeded: 1,
        relays_failed: 1,
        failed_endpoints: vec![cgka_traits::TransportEndpoint(BEST_EFFORT.into())],
        ..Default::default()
    })
    .await;
    assert!(
        !storage.history_acquisition_held(&group_id).unwrap(),
        "every named event is held, so the dead relay changes nothing"
    );
    assert!(
        storage.parked_recovery_obligations().unwrap().is_empty(),
        "and no history notice"
    );
}

/// A relay that is down may be the one holding the named history, so it must
/// not run the stall backstop out while another relay answers empty. The
/// hold waits for the naming relay to return; the history then arrives in
/// time and the hold ends normally (mdk#2086).
#[tokio::test]
async fn a_silent_naming_relay_keeps_the_hold_while_another_relay_answers() {
    use cgka_traits::storage::HistoryAcquisitionHoldStorage;
    const OPERATED: &str = "wss://operated.example";
    const BEST_EFFORT: &str = "wss://best-effort.example";

    let dir = tempfile::tempdir().unwrap();
    crate::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relays_and_config(
        dir.path(),
        vec!["wss://relay.example".into()],
        crate::MarmotAppConfig::default()
            .with_open_ranking_provider(None, Vec::new())
            .with_recovery_operated_relays(vec![OPERATED.into()]),
    )
    .with_test_relay_client(relay.clone());
    let _pump = scripted_eose_pump(app.relay_plane.clone(), relay, every_subscription);
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group_id = client
        .create_group_with_options(
            "silent naming relay",
            &[],
            crate::AppCreateGroupOptions {
                relays: Some(vec![OPERATED.into(), BEST_EFFORT.into()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let storage = app.account_storage("alice").unwrap();

    // The operated relay names an event this pass does not return.
    run_group_comparison(&mut client, &storage, |_| NostrReconciliationSummary {
        relays_succeeded: 2,
        remote_items: 1,
        remote_ids: vec![NAMED],
        ..Default::default()
    })
    .await;
    assert!(storage.history_acquisition_held(&group_id).unwrap());

    // The operated relay then fails while the best-effort relay answers
    // empty, for well past the stall limit.
    for _ in 0..storage_sqlite::HISTORY_ACQUISITION_STALL_PASSES * 2 {
        run_group_comparison(&mut client, &storage, |_| NostrReconciliationSummary {
            relays_succeeded: 1,
            relays_failed: 1,
            failed_endpoints: vec![cgka_traits::TransportEndpoint(OPERATED.into())],
            ..Default::default()
        })
        .await;
        assert!(
            storage.history_acquisition_held(&group_id).unwrap(),
            "the epoch waits for the relay that named the history"
        );
    }

    // The operated relay returns the event, still in time to decrypt.
    admit_named(&app, &group_id);
    assert!(!storage.history_acquisition_held(&group_id).unwrap());
    assert!(storage.parked_recovery_obligations().unwrap().is_empty());
}
