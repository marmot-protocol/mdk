//! The shadow coverage ledger against the obligations, driven through the
//! real owner seams: native admission, loss import at authorization, and a
//! settled comparison pass.
use std::sync::Arc;

use storage_sqlite::{
    RecoveryCause, RecoveryCoverageProof, SqliteAccountStorage, TransportReconciliationRoute,
};

use super::CoverageShadowReport;
use crate::client::AppClient;
use crate::client::recovery::AttemptGrant;
use crate::tests::{
    ScriptedEosePump, ScriptedPushRelayClient, client_on_app_relay_plane, every_subscription,
    scripted_eose_pump,
};
use crate::unix_now_seconds;

const RELAY: &str = "wss://relay.example";

/// The ledger's spelling of the fixture relay.
fn relay() -> String {
    transport_nostr::canonical_relay(RELAY)
}

struct Fixture {
    _dir: tempfile::TempDir,
    _pump: ScriptedEosePump,
    client: AppClient,
    storage: SqliteAccountStorage,
}

/// One account with one group and a checkpointed cursor whose live
/// subscriptions have reached owner admission: the normal caught-up state.
async fn fixture() -> Fixture {
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
    let pump = scripted_eose_pump(app.relay_plane.clone(), relay.clone(), every_subscription);
    let mut state = app.load_state("alice").unwrap();
    state.last_transport_timestamp = Some(unix_now_seconds().saturating_sub(60));
    app.save_state(&state).unwrap();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    client.create_group("coverage ledger", &[]).await.unwrap();
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
        client,
        storage,
    }
}

fn routes(client: &AppClient) -> Vec<TransportReconciliationRoute> {
    client
        .current_coverage_routes()
        .into_iter()
        .map(|current| current.route)
        .collect()
}

async fn report(fixture: &Fixture) -> CoverageShadowReport {
    fixture
        .client
        .coverage_shadow_report(&fixture.storage.app_storage())
        .await
        .unwrap()
}

/// Every compared route's relay answers and certifies it.
fn certified_routes(grant: &AttemptGrant) -> crate::client::sync::ScriptedComparisons {
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
    let grant = fixture
        .client
        .authorize_account_recovery(
            None,
            marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
        )
        .await
        .unwrap()
        .expect("loss selects a grant");
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
    let owed = report(&fixture).await;
    assert!(owed.agree_owed >= 2, "{owed:?}");
    assert_eq!(owed.disagreements(), 0, "{owed:?}");

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
        assert!(
            app.recovery_coverage_debt(route, &[relay()], unix_now_seconds())
                .unwrap()
                .is_empty()
        );
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
    fixture.client.record_native_coverage(&app).await;
    for route in routes(&fixture.client) {
        assert!(
            !app.recovery_coverage_debt(&route, &[relay()], unix_now_seconds())
                .unwrap()
                .is_empty(),
            "the loss stays owed"
        );
    }
}

/// Loss imported after a grant froze can lie inside the window its pass
/// certified, so settlement must not restore that window's coverage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loss_imported_after_the_grant_froze_keeps_its_debt() {
    let mut fixture = fixture().await;
    let app = fixture.storage.app_storage();
    let floor = unix_now_seconds().saturating_sub(30);
    app.record_account_delivery_loss_bounded("alice", 41, 3, unix_now_seconds(), Some(floor))
        .unwrap();
    let grant = fixture
        .client
        .authorize_account_recovery(
            None,
            marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
        )
        .await
        .unwrap()
        .expect("loss selects a grant");
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
                .all(|proved| proved.proof != RecoveryCoverageProof::Comparison),
            "the stale pass records no certificate"
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
            .any(|proved| proved.proof == RecoveryCoverageProof::Comparison)),
        "a current pass records its certificates"
    );
}

/// A notification lag charges no delivery count, but it is loss: every
/// current route is un-covered from the lag's REQ floor and owes from there.
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
        assert!(
            !app.recovery_coverage_debt(route, &[relay()], unix_now_seconds())
                .unwrap()
                .is_empty()
        );
    }
}
