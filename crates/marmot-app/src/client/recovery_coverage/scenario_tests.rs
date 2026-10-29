//! The shadow coverage ledger against the obligations, driven through the
//! real owner seams: native admission, loss import at authorization, and a
//! settled comparison pass.
use std::sync::Arc;

use storage_sqlite::{
    RecoveryCause, RecoveryCoverageProof, RecoveryCoverageSlice, SqliteAccountStorage,
    TRANSPORT_RECONCILIATION_RETENTION_SECS, TransportReconciliationRoute,
};

use super::CoverageShadowReport;
use crate::client::AppClient;
use crate::client::recovery::AttemptGrant;
use crate::client::sync::ScriptedComparisons;
use crate::tests::{
    ScriptedEosePump, ScriptedPushRelayClient, client_on_app_relay_plane, every_subscription,
    scripted_eose_pump,
};
use crate::unix_now_seconds;

pub(super) const RELAY: &str = "wss://relay.example";

/// When the one stored event the fixture relay returns before each EOSE was
/// created. It is older than every window the fixture asks for, which no
/// real relay returns; it only makes each count prove its REQ's whole window,
/// so scenarios can watch that proof come and go.
pub(super) const STORED_AT: u64 = 1;

/// The ledger's spelling of the fixture relay.
pub(in crate::client) fn relay() -> String {
    transport_nostr::canonical_relay(RELAY)
}

pub(in crate::client) struct Fixture {
    pub(in crate::client) _dir: tempfile::TempDir,
    pub(in crate::client) _pump: ScriptedEosePump,
    pub(in crate::client) relay: Arc<ScriptedPushRelayClient>,
    pub(in crate::client) client: AppClient,
    pub(in crate::client) storage: SqliteAccountStorage,
    pub(in crate::client) group: cgka_traits::GroupId,
}

/// One account with one group and a checkpointed cursor whose live
/// subscriptions have reached owner admission: the normal caught-up state.
pub(in crate::client) async fn fixture() -> Fixture {
    fixture_with_stored(Some(STORED_AT)).await
}

/// [`fixture`], with the relay returning one stored event created at
/// `stored` before each EOSE, or none.
pub(super) async fn fixture_with_stored(stored: Option<u64>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    crate::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = crate::MarmotApp::with_relays_and_config(
        dir.path(),
        vec![RELAY.into()],
        crate::MarmotAppConfig::white_noise(),
    )
    .with_test_relay_client(relay.clone());
    *relay.stored_before_eose.lock().unwrap() = stored;
    let pump = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
    let mut state = app.load_state("alice").unwrap();
    state.last_transport_timestamp = Some(unix_now_seconds().saturating_sub(60));
    app.save_state(&state).unwrap();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group = client.create_group("coverage ledger", &[]).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            client.synchronize_native_replay().await.unwrap();
            let observation = client.adapter.replay_admission().await;
            if client
                .recovery_owner
                .native_replay_authorizes(observation.generation())
            {
                break;
            }
            drop(observation);
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the scripted native windows reach owner admission");
    let storage = app.account_storage("alice").unwrap();
    Fixture {
        _dir: dir,
        _pump: pump,
        relay,
        client,
        storage,
        group,
    }
}

/// Start the account's REQs again, as a reconnect does, and wait until the
/// new generation's boundaries are admitted.
pub(super) async fn reactivate(fixture: &mut Fixture) {
    fixture.client.prepare_transport().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            fixture.client.synchronize_native_replay().await.unwrap();
            let observation = fixture.client.adapter.replay_admission().await;
            if fixture
                .client
                .recovery_owner
                .native_replay_authorizes(observation.generation())
            {
                break;
            }
            drop(observation);
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the new generation reaches owner admission");
}

pub(in crate::client) fn routes(client: &AppClient) -> Vec<TransportReconciliationRoute> {
    client
        .current_coverage_routes()
        .into_iter()
        .map(|current| current.route)
        .collect()
}

pub(super) async fn report(fixture: &Fixture) -> CoverageShadowReport {
    fixture
        .client
        .coverage_shadow_report(&fixture.storage.app_storage())
        .await
        .unwrap()
}

/// Whether `route` owes anything on the fixture relay at `now`, as debt that
/// drives work reads it: the ledger's debt short of the live tail.
pub(super) async fn owed(
    fixture: &Fixture,
    route: &TransportReconciliationRoute,
    now: u64,
) -> bool {
    let app = fixture.storage.app_storage();
    let tails = fixture.client.live_tails(&app, now).await;
    !app.recovery_coverage_debt(route, &[relay()], tails.owed_until(route, &relay(), now))
        .unwrap()
        .is_empty()
}

pub(super) async fn authorize(client: &mut AppClient) -> AttemptGrant {
    client
        .authorize_account_recovery(
            None,
            marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
        )
        .await
        .unwrap()
        .expect("loss selects a grant")
}

/// Every compared route's relay answers and certifies it.
pub(super) fn certified_routes(grant: &AttemptGrant) -> ScriptedComparisons {
    grant
        .inventory
        .iter()
        .map(|_| {
            Ok(Some((
                transport_nostr_adapter::NostrReconciliationSummary {
                    relays_succeeded: 1,
                    ..Default::default()
                },
                Vec::new(),
            )))
        })
        .collect()
}

/// The normal catch-up path: live boundaries cover every route, a bounded
/// queue loss un-covers them from its floor, and the certified pass that
/// settles the loss covers them again. Ledger and obligations agree at every
/// step.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ledger_and_obligations_agree_through_a_normal_catch_up() {
    let mut fixture = fixture().await;
    let app = fixture.storage.app_storage();
    let routes = routes(&fixture.client);
    assert_eq!(routes.len(), 2, "the inbox and the group's route");

    // Caught up: live boundaries prove every route, nothing is owed.
    let caught_up = report(&fixture).await;
    assert_eq!(caught_up.disagreements(), 0, "{caught_up:?}");
    for route in &routes {
        let live = app.recovery_coverage_ranges(route, &relay()).unwrap();
        assert!(
            live.iter()
                .any(|proved| proved.proof == RecoveryCoverageProof::LiveBoundary),
            "a live boundary covers each route"
        );
    }

    // A queue loss whose deliveries start at `floor`.
    let floor = unix_now_seconds().saturating_sub(30);
    app.record_account_delivery_loss_bounded("alice", 41, 3, unix_now_seconds(), Some(floor))
        .unwrap();
    let grant = authorize(&mut fixture.client).await;
    for route in &routes {
        assert!(
            app.recovery_coverage_ranges(route, &relay())
                .unwrap()
                .iter()
                .all(|proved| proved.range.until_seconds < floor),
            "the loss un-covers its routes from the floor"
        );
        assert!(app.recovery_coverage_goal(route).unwrap() <= Some(floor));
    }
    let pending = report(&fixture).await;
    assert!(pending.agree_owed >= 2, "{pending:?}");
    assert_eq!(pending.disagreements(), 0, "{pending:?}");

    // A certified pass settles the loss and covers its window again.
    fixture.client.test_comparison_results = Some(certified_routes(&grant));
    fixture
        .client
        .run_recovery_grant_for_test(grant)
        .await
        .unwrap();
    assert!(
        app.pending_recovery_demands()
            .unwrap()
            .iter()
            .all(|demand| demand.cause != RecoveryCause::QueueLoss),
        "certified routes complete the loss"
    );
    for route in &routes {
        assert!(
            app.recovery_coverage_ranges(route, &relay())
                .unwrap()
                .iter()
                .any(|proved| proved.proof == RecoveryCoverageProof::Comparison
                    && proved.range.since_seconds <= floor),
            "the certificate covers the loss window"
        );
    }
    // The loss ended the live tails it may have reached; the next
    // generation's EOSE proves the time since the certificate.
    reactivate(&mut fixture).await;
    let now = unix_now_seconds();
    for route in &routes {
        assert!(!owed(&fixture, route, now).await);
    }
    let settled = report(&fixture).await;
    assert_eq!(settled.disagreements(), 0, "{settled:?}");
}

/// While loss is pending, an unchanged live boundary does not re-cover what
/// the loss un-covered: queue loss drops deliveries the adapter had placed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_loss_keeps_live_boundaries_from_re_covering_it() {
    let fixture = fixture().await;
    let app = fixture.storage.app_storage();
    let floor = unix_now_seconds().saturating_sub(30);
    app.record_account_delivery_loss_bounded("alice", 41, 3, unix_now_seconds(), Some(floor))
        .unwrap();
    fixture.client.synchronize_recovery_loss(&app).unwrap();
    for route in routes(&fixture.client) {
        assert!(
            owed(&fixture, &route, unix_now_seconds()).await,
            "the loss stays owed"
        );
    }
}

/// Queue loss whose drops named their routes un-covers only those routes,
/// from their own bounds: the inbox, where nothing was dropped, stays covered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routed_queue_loss_uncovers_only_its_routes() {
    let fixture = fixture().await;
    let app = fixture.storage.app_storage();
    let routes = routes(&fixture.client);
    let group = routes
        .iter()
        .find(|route| matches!(route, TransportReconciliationRoute::Group(_)))
        .unwrap()
        .clone();
    let floor = unix_now_seconds().saturating_sub(30);
    app.record_account_recovery_loss_routed(
        "alice",
        storage_sqlite::RecoveryLossCause::Queue,
        41,
        3,
        unix_now_seconds(),
        Some(floor),
        Some(&[(group.clone(), floor)]),
    )
    .unwrap();
    fixture.client.synchronize_recovery_loss(&app).unwrap();
    let now = unix_now_seconds();
    for route in &routes {
        assert_eq!(
            owed(&fixture, route, now).await,
            *route == group,
            "only the group lost deliveries"
        );
    }
}

/// A restored generation's new drops arrive under a fresh token, so they
/// import as new loss and cost coverage: first the route they name, then
/// every route once a drop names none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restored_generations_new_loss_uncovers_its_routes() {
    let fixture = fixture().await;
    let app = fixture.storage.app_storage();
    let routes = routes(&fixture.client);
    let group = routes
        .iter()
        .find(|route| matches!(route, TransportReconciliationRoute::Group(_)))
        .unwrap()
        .clone();
    let inbox = TransportReconciliationRoute::Inbox;
    assert!(routes.contains(&inbox));
    let floor = unix_now_seconds().saturating_sub(30);
    let lose = |token, count, lost: Option<&[(TransportReconciliationRoute, u64)]>| {
        app.record_account_recovery_loss_routed(
            "alice",
            storage_sqlite::RecoveryLossCause::Queue,
            token,
            count,
            unix_now_seconds(),
            Some(floor),
            lost,
        )
        .unwrap();
        fixture.client.synchronize_recovery_loss(&app).unwrap();
    };
    let owed = async |route: &TransportReconciliationRoute| {
        owed(&fixture, route, unix_now_seconds()).await
    };
    lose(41, 50, Some(&[(group.clone(), floor)]));
    assert!(!owed(&inbox).await);

    // Restored after a restart: the plane counts new drops under a fresh
    // token.
    lose(42, 1, Some(&[(inbox.clone(), floor)]));
    assert!(owed(&inbox).await, "the restored generation lost the inbox");
    lose(42, 2, None);
    for route in &routes {
        assert!(
            owed(route).await,
            "a drop that named no route costs every route"
        );
    }
}

/// Loss imported after a grant was selected can lie inside the window its
/// pass certified, so settlement must not restore that window's coverage
/// from the loss's floor up; below the floor the certificate stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loss_imported_after_the_grant_froze_keeps_its_debt() {
    let mut fixture = fixture().await;
    let app = fixture.storage.app_storage();
    let floor = unix_now_seconds().saturating_sub(30);
    app.record_account_delivery_loss_bounded("alice", 41, 3, unix_now_seconds(), Some(floor))
        .unwrap();
    let grant = authorize(&mut fixture.client).await;
    // Newer loss, imported while the pass runs, before settlement.
    app.record_account_delivery_loss_bounded("alice", 42, 2, unix_now_seconds(), Some(floor))
        .unwrap();
    fixture.client.synchronize_recovery_loss(&app).unwrap();
    let certified = grant
        .inventory
        .iter()
        .map(|window| &window.route)
        .collect::<Vec<_>>();
    assert!(!certified.is_empty());
    fixture
        .client
        .record_comparison_coverage(&app, &grant, &certified, unix_now_seconds());
    for route in routes(&fixture.client) {
        assert!(
            app.recovery_coverage_ranges(&route, &relay())
                .unwrap()
                .iter()
                .all(|proved| proved.proof != RecoveryCoverageProof::Comparison
                    || proved.range.until_seconds < floor),
            "the stale pass records no certificate from the newer loss's floor up"
        );
        assert!(
            !app.recovery_coverage_covers(&route, &[relay()], floor, floor)
                .unwrap()
        );
    }
    // A pass frozen after that loss records its certificates.
    fixture
        .client
        .recovery_owner
        .test_advance_to_retry(&fixture.storage);
    drop(grant);
    let fresh = fixture
        .client
        .authorize_account_recovery(
            None,
            marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
        )
        .await
        .unwrap()
        .expect("the loss is still owed");
    let certified = fresh
        .inventory
        .iter()
        .map(|window| &window.route)
        .collect::<Vec<_>>();
    fixture
        .client
        .record_comparison_coverage(&app, &fresh, &certified, unix_now_seconds());
    assert!(
        routes(&fixture.client).iter().any(|route| app
            .recovery_coverage_ranges(route, &relay())
            .unwrap()
            .iter()
            .any(|proved| proved.proof == RecoveryCoverageProof::Comparison
                && proved.range.since_seconds <= floor
                && proved.range.until_seconds >= floor)),
        "a current pass records its certificates over the loss"
    );
}

/// Newer loss with a higher floor lands while a pass runs: the pass keeps its
/// certificates below that floor, and only the newer loss stays owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pass_keeps_its_certificates_below_newer_loss() {
    let mut fixture = fixture().await;
    let app = fixture.storage.app_storage();
    let older = unix_now_seconds().saturating_sub(300);
    app.record_account_delivery_loss_bounded("alice", 41, 3, unix_now_seconds(), Some(older))
        .unwrap();
    let grant = authorize(&mut fixture.client).await;
    let newer = unix_now_seconds().saturating_sub(60);
    app.record_account_delivery_loss_bounded("alice", 42, 2, unix_now_seconds(), Some(newer))
        .unwrap();
    fixture.client.synchronize_recovery_loss(&app).unwrap();
    let certified = grant
        .inventory
        .iter()
        .map(|window| &window.route)
        .collect::<Vec<_>>();
    fixture
        .client
        .record_comparison_coverage(&app, &grant, &certified, unix_now_seconds());
    let relays = [relay()];
    for route in routes(&fixture.client) {
        assert!(
            app.recovery_coverage_covers(&route, &relays, older, newer - 1)
                .unwrap(),
            "the pass's certificate stands below the newer loss"
        );
        assert!(
            !app.recovery_coverage_covers(&route, &relays, newer, newer)
                .unwrap(),
            "the newer loss stays owed"
        );
    }
}

/// A receipt released while a pass runs lets its event arrive again: the
/// pass's certificate leaves that second owed on the event's route, and the
/// account inbox keeps its whole window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_receipt_released_during_a_pass_stays_owed() {
    use cgka_traits::storage::MessageStorage;

    let mut fixture = fixture().await;
    let app = fixture.storage.app_storage();
    let floor = unix_now_seconds().saturating_sub(120);
    app.record_account_delivery_loss_bounded("alice", 41, 3, unix_now_seconds(), Some(floor))
        .unwrap();
    let grant = authorize(&mut fixture.client).await;
    let group_route = routes(&fixture.client)
        .into_iter()
        .find(|route| matches!(route, TransportReconciliationRoute::Group(_)))
        .expect("the group's route");
    let sent = unix_now_seconds().saturating_sub(60);
    let item = storage_sqlite::TransportReconciliationItem {
        event_id: [0xfd; 32],
        created_at: sent,
    };
    app.record_reconciliation_items(std::iter::once((&group_route, &item)))
        .unwrap();
    let record = cgka_traits::MessageRecord {
        id: cgka_traits::MessageId::new(item.event_id.to_vec()),
        group_id: fixture.group.clone(),
        epoch: cgka_traits::EpochId(0),
        state: cgka_traits::MessageState::PeelDeferred,
        payload: Vec::new(),
        deferred_peel: None,
    };
    fixture.storage.put_message(&record).unwrap();
    fixture.storage.release_message_for_replay(&record).unwrap();
    let certified = grant
        .inventory
        .iter()
        .map(|window| &window.route)
        .collect::<Vec<_>>();
    fixture
        .client
        .record_comparison_coverage(&app, &grant, &certified, unix_now_seconds());
    let relays = [relay()];
    assert!(
        !app.recovery_coverage_covers(&group_route, &relays, sent, sent)
            .unwrap(),
        "the released second stays owed"
    );
    assert!(
        app.recovery_coverage_covers(&group_route, &relays, floor, sent - 1)
            .unwrap()
    );
    assert!(
        app.recovery_coverage_covers(&TransportReconciliationRoute::Inbox, &relays, floor, sent)
            .unwrap(),
        "the inbox keeps its whole window"
    );
}

/// A receipt released while its live REQ stays open is not delivered again
/// by that REQ, so the next observation of the unchanged boundary leaves its
/// second owed, with no loss pending to hold the boundary back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_receipt_released_under_a_live_boundary_stays_owed() {
    use cgka_traits::storage::MessageStorage;

    let fixture = fixture().await;
    let app = fixture.storage.app_storage();
    fixture.client.record_native_coverage(&app).await;
    let group_route = routes(&fixture.client)
        .into_iter()
        .find(|route| matches!(route, TransportReconciliationRoute::Group(_)))
        .expect("the group's route");
    let sent = unix_now_seconds().saturating_sub(60);
    let relays = [relay()];
    assert!(
        app.recovery_coverage_covers(&group_route, &relays, sent - 1, sent + 1)
            .unwrap(),
        "the live boundary covers the event's second"
    );
    let item = storage_sqlite::TransportReconciliationItem {
        event_id: [0xfc; 32],
        created_at: sent,
    };
    app.record_reconciliation_items(std::iter::once((&group_route, &item)))
        .unwrap();
    let record = cgka_traits::MessageRecord {
        id: cgka_traits::MessageId::new(item.event_id.to_vec()),
        group_id: fixture.group.clone(),
        epoch: cgka_traits::EpochId(0),
        state: cgka_traits::MessageState::PeelDeferred,
        payload: Vec::new(),
        deferred_peel: None,
    };
    fixture.storage.put_message(&record).unwrap();
    fixture.storage.release_message_for_replay(&record).unwrap();
    report(&fixture).await;
    fixture.client.record_native_coverage(&app).await;
    assert!(
        !app.recovery_coverage_covers(&group_route, &relays, sent, sent)
            .unwrap(),
        "the released second stays owed"
    );
    assert!(
        app.recovery_coverage_covers(&group_route, &relays, sent - 1, sent - 1)
            .unwrap()
            && app
                .recovery_coverage_covers(&group_route, &relays, sent + 1, sent + 1)
                .unwrap(),
        "the rest of the window stays covered"
    );
}

/// A notification lag charges no delivery count, but it is loss. One whose
/// routes are unknown un-covers every current route from the lag's REQ floor,
/// and each owes from there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notification_lag_uncovers_every_route_from_its_floor() {
    let fixture = fixture().await;
    let app = fixture.storage.app_storage();
    let routes = routes(&fixture.client);
    // Caught up: every route holds a live boundary.
    assert_eq!(report(&fixture).await.disagreements(), 0);
    let floor = unix_now_seconds().saturating_sub(30);
    app.record_account_recovery_loss_bounded(
        "alice",
        storage_sqlite::RecoveryLossCause::NotificationConsumer,
        7,
        0,
        unix_now_seconds(),
        Some(floor),
    )
    .unwrap();
    fixture.client.synchronize_recovery_loss(&app).unwrap();
    for route in &routes {
        assert!(
            app.recovery_coverage_ranges(route, &relay())
                .unwrap()
                .iter()
                .all(|proved| proved.range.until_seconds < floor),
            "the lag un-covers its routes from the floor"
        );
        assert!(app.recovery_coverage_goal(route).unwrap() <= Some(floor));
        assert!(owed(&fixture, route, unix_now_seconds()).await);
    }
}

/// A lag on the account's own SDK context carries each route's REQ floor, and
/// the worker records it per route: each route owes from its own floor, so
/// the inbox REQ's wider window no longer drags the group's debt back with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notification_lag_uncovers_each_route_from_its_own_floor() {
    let mut fixture = fixture().await;
    let app = fixture.storage.app_storage();
    assert_eq!(report(&fixture).await.disagreements(), 0);
    let group = routes(&fixture.client)
        .into_iter()
        .find(|route| matches!(route, TransportReconciliationRoute::Group(_)))
        .unwrap();
    let TransportReconciliationRoute::Group(group_id) = group else {
        unreachable!()
    };
    let proved = app.recovery_coverage_ranges(&group, &relay()).unwrap();
    let since = proved.iter().map(|p| p.range.since_seconds).min().unwrap();
    let until = proved.iter().map(|p| p.range.until_seconds).max().unwrap();
    assert!(
        since < until
            && app
                .recovery_coverage_covers(&group, &[relay()], since, until)
                .unwrap()
    );
    let account = fixture.client.adapter.account_id().clone();
    fixture
        .client
        .app
        .relay_plane
        .simulate_routed_notification_lag_for_test(
            &account,
            1,
            transport_nostr_adapter::NostrNotificationLossBounds {
                floor: transport_nostr_adapter::NostrNotificationLossFloor::Since(since),
                routes: Some(std::collections::BTreeMap::from([
                    (transport_nostr::DeliveryRoute::Inbox, since),
                    (transport_nostr::DeliveryRoute::Group(group_id), until),
                ])),
            },
        );
    let received = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture.client.receive_next_delivery(),
    )
    .await
    .expect("the lag reaches the worker")
    .unwrap();
    assert!(matches!(
        received,
        transport_nostr::AccountDeliveryReceive::Overflow(_)
    ));
    assert!(
        app.recovery_coverage_ranges(&TransportReconciliationRoute::Inbox, &relay())
            .unwrap()
            .iter()
            .all(|proved| proved.range.until_seconds < since),
        "the inbox owes from its own floor"
    );
    assert!(
        app.recovery_coverage_covers(&group, &[relay()], since, until - 1)
            .unwrap(),
        "the group keeps what lies below its own floor"
    );
    assert!(
        !app.recovery_coverage_covers(&group, &[relay()], until, until)
            .unwrap(),
        "the group owes from its own floor"
    );
}

/// A certificate captured before newer loss no longer proves anything to the
/// obligation, and the import un-covered it in the ledger: both owe it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn newer_loss_voids_a_pending_obligations_certificates() {
    let mut fixture = fixture().await;
    let app = fixture.storage.app_storage();
    let floor = unix_now_seconds().saturating_sub(30);
    app.record_account_delivery_loss_bounded("alice", 41, 3, unix_now_seconds(), Some(floor))
        .unwrap();
    let grant = authorize(&mut fixture.client).await;
    // The inbox certifies; the group's relay fails, so the loss stays owed.
    fixture.client.test_comparison_results = Some(ScriptedComparisons::by_route(|route| {
        let failed = matches!(route, TransportReconciliationRoute::Group(_));
        Ok(Some((
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_succeeded: usize::from(!failed),
                relays_failed: usize::from(failed),
                failed_endpoints: if failed {
                    vec![cgka_traits::TransportEndpoint(RELAY.into())]
                } else {
                    Vec::new()
                },
                ..Default::default()
            },
            Vec::new(),
        )))
    }));
    fixture
        .client
        .run_recovery_grant_for_test(grant)
        .await
        .unwrap();
    assert!(
        app.pending_recovery_demands()
            .unwrap()
            .iter()
            .any(|demand| demand.cause == RecoveryCause::QueueLoss)
    );
    let partial = report(&fixture).await;
    assert!(partial.agree_covered >= 1, "{partial:?}");
    assert_eq!(partial.disagreements(), 0, "{partial:?}");

    // Newer loss from the same floor, inside the certified inbox window.
    app.record_account_delivery_loss_bounded("alice", 42, 2, unix_now_seconds(), Some(floor))
        .unwrap();
    fixture.client.synchronize_recovery_loss(&app).unwrap();
    let voided = report(&fixture).await;
    assert_eq!(voided.agree_covered, 0, "{voided:?}");
    assert!(voided.agree_owed >= 2, "{voided:?}");
    assert_eq!(voided.disagreements(), 0, "{voided:?}");
}

/// A loss with no known time, or one older than the retained window, owes
/// every retained second, not history the ledger has pruned: once the ledger
/// proves the retained window while the obligation still owes it, the report
/// says the ledger is ahead.
async fn retained_window_proof_puts_the_ledger_ahead(floor: Option<u64>) {
    let mut fixture = fixture().await;
    let app = fixture.storage.app_storage();
    app.record_account_delivery_loss_bounded("alice", 41, 3, unix_now_seconds(), floor)
        .unwrap();
    let _grant = authorize(&mut fixture.client).await;
    let loss = app
        .pending_recovery_demands()
        .unwrap()
        .into_iter()
        .find(|demand| demand.cause == RecoveryCause::QueueLoss)
        .expect("the loss is owed");
    let retained = unix_now_seconds() - TRANSPORT_RECONCILIATION_RETENTION_SECS;
    assert!(
        app.recovery_scope_snapshots(loss.ticket.id)
            .unwrap()
            .iter()
            .any(|scope| scope
                .plan
                .since_seconds
                .is_none_or(|since| since < retained)),
        "the loss's scopes start below the retained window"
    );
    let pending = report(&fixture).await;
    assert!(pending.agree_owed >= 2, "{pending:?}");
    assert_eq!(pending.disagreements(), 0, "{pending:?}");
    // What lies below the window is parked on every route, not dropped.
    let remainders = app.recovery_coverage_remainders().unwrap();
    for route in routes(&fixture.client) {
        let remainder = remainders
            .iter()
            .find(|remainder| remainder.route == route)
            .expect("the loss parks the rest of its range");
        assert!(remainder.range.since_seconds <= floor.unwrap_or(0));
        assert!(remainder.range.until_seconds + 1 >= retained);
    }

    let now = unix_now_seconds();
    let relay = relay();
    for route in routes(&fixture.client) {
        app.record_recovery_coverage(
            &[RecoveryCoverageSlice {
                route: &route,
                relay: &relay,
                since_seconds: now - TRANSPORT_RECONCILIATION_RETENTION_SECS,
                until_seconds: now,
                proof: RecoveryCoverageProof::Comparison,
            }],
            now,
        )
        .unwrap();
    }
    let ahead = report(&fixture).await;
    assert!(ahead.ledger_ahead >= 2, "{ahead:?}");
    assert_eq!(ahead.agree_owed, 0, "{ahead:?}");

    // Every report widens the pending loss's goals back below the floor, but
    // a prune settled what lies there, so a dismissal sticks.
    for remainder in app.recovery_coverage_remainders().unwrap() {
        assert!(
            app.dismiss_recovery_route_park(&remainder.route, remainder.revision)
                .unwrap()
        );
    }
    report(&fixture).await;
    assert!(app.recovery_coverage_remainders().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_loss_floor_is_owed_from_the_retention_floor() {
    retained_window_proof_puts_the_ledger_ahead(None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loss_floor_older_than_retention_is_owed_from_the_retention_floor() {
    let floor = unix_now_seconds() - TRANSPORT_RECONCILIATION_RETENTION_SECS - 86_400;
    retained_window_proof_puts_the_ledger_ahead(Some(floor)).await;
}

/// A group copy's Welcome time starts only its route's standing goal, never
/// below the retained window: loss below it still owes from its own floor,
/// and explicit repair wants the whole window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_copys_welcome_time_starts_only_its_standing_goal() {
    use cgka_traits::storage::GroupStorage;
    let fixture = fixture().await;
    let app = fixture.storage.app_storage();
    let now = unix_now_seconds();
    let welcome_at = now - 6 * 60 * 60;
    let mut record = fixture.storage.get_group(&fixture.group).unwrap();
    record.local_copy_welcome_created_at = Some(cgka_traits::transport::Timestamp(welcome_at));
    fixture.storage.put_group(&record).unwrap();
    let current = fixture.client.current_coverage_routes();
    let group_route = current
        .iter()
        .find(|current| current.group_id.as_deref() == Some(fixture.group.as_slice()))
        .expect("the group is subscribed")
        .route
        .clone();
    let welcome_floor = crate::history_floor(welcome_at).0;
    for current in &current {
        let expected = if current.route == group_route {
            welcome_floor
        } else {
            super::retention_floor(now)
        };
        assert_eq!(fixture.client.standing_floor(current, now), expected);
    }
    assert_eq!(
        app.recovery_coverage_goal(&group_route).unwrap(),
        None,
        "nothing wanted the new group's route yet"
    );

    fixture
        .client
        .record_coverage_request(RecoveryCause::IncrementalHistory);
    assert_eq!(
        app.recovery_coverage_goal(&group_route).unwrap(),
        Some(welcome_floor)
    );
    for route in routes(&fixture.client) {
        if route != group_route {
            assert!(
                app.recovery_coverage_goal(&route).unwrap() <= Some(super::retention_floor(now))
            );
        }
    }

    // Loss from before the Welcome owes from its own floor.
    let lost_from = welcome_at - 60 * 60;
    app.record_account_recovery_loss_bounded(
        "alice",
        storage_sqlite::RecoveryLossCause::NotificationConsumer,
        7,
        0,
        unix_now_seconds(),
        Some(lost_from),
    )
    .unwrap();
    fixture.client.synchronize_recovery_loss(&app).unwrap();
    assert_eq!(
        app.recovery_coverage_goal(&group_route).unwrap(),
        Some(lost_from)
    );

    // Explicit repair wants the whole window, and nothing below it.
    fixture
        .client
        .record_coverage_request(RecoveryCause::ExplicitHistory);
    let goal = app.recovery_coverage_goal(&group_route).unwrap().unwrap();
    assert!(goal >= super::retention_floor(now));
    assert!(goal <= super::retention_floor(unix_now_seconds()));

    // A Welcome older than the window starts nothing below it, and one still
    // ahead of now (the joining clock ran fast) is ignored, even inside the
    // allowance.
    for welcome_at in [
        now - TRANSPORT_RECONCILIATION_RETENTION_SECS - 60 * 60,
        now + 10 * 60,
        now + 60 * 60,
    ] {
        record.local_copy_welcome_created_at = Some(cgka_traits::transport::Timestamp(welcome_at));
        fixture.storage.put_group(&record).unwrap();
        for current in &fixture.client.current_coverage_routes() {
            assert_eq!(
                fixture.client.standing_floor(current, now),
                super::retention_floor(now)
            );
        }
    }
}
