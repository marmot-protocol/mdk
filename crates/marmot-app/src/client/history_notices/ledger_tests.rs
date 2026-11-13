//! What the coverage ledger parks raises no notice (mdk#3308), and the
//! account's recovery status reads what the runner catches up (mdk#2660
//! phase 4).

use std::collections::BTreeSet;
use std::sync::Arc;

use cgka_traits::GroupId;
use storage_sqlite::{
    RecoveryDemandTicket, RecoveryUnitOutcome, RecoveryUnitState, SqliteAppStorage,
    TransportReconciliationRoute,
};

use crate::client::recovery_runner::{RecoveryRunnerPolicy, UnitKey};
use crate::history_notices::{encode_notice_id, ledger_route_tag};
use crate::tests::{ScriptedPushRelayClient, client_on_app_relay_plane};
use crate::{AccountRecoveryStatus, AppClient, MarmotApp};

const RELAY: &str = "wss://relay.example";
const DAY: u64 = 24 * 60 * 60;

fn app(dir: &tempfile::TempDir) -> MarmotApp {
    crate::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    MarmotApp::with_relay(dir.path(), RELAY)
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()))
}

/// One account with one group, its client opened directly, and the group's
/// current route.
async fn fixture(
    dir: &tempfile::TempDir,
) -> (
    AppClient,
    SqliteAppStorage,
    GroupId,
    TransportReconciliationRoute,
) {
    let (_, client, storage, group, route) = opened(app(dir)).await;
    (client, storage, group, route)
}

/// [`fixture`] recording audit v5, with its app to read the rows back.
async fn audited_fixture(
    dir: &tempfile::TempDir,
) -> (
    MarmotApp,
    AppClient,
    SqliteAppStorage,
    GroupId,
    TransportReconciliationRoute,
) {
    let app = app(dir);
    app.set_audit_log_settings(crate::AuditLogSettings { enabled: true })
        .unwrap();
    opened(app).await
}

async fn opened(
    app: MarmotApp,
) -> (
    MarmotApp,
    AppClient,
    SqliteAppStorage,
    GroupId,
    TransportReconciliationRoute,
) {
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group = client
        .create_group("ledger notices", &[])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    let route = client
        .recovery_runner_routes()
        .into_iter()
        .find(|route| route.group_id.as_deref() == Some(group.as_slice()))
        .unwrap()
        .route;
    let storage = app.account_storage("alice").unwrap().app_storage();
    (app, client, storage, group, route)
}

/// The `recovery_need_changed` rows recorded with `change`.
fn need_changed(app: &MarmotApp, change: &str) -> Vec<serde_json::Value> {
    crate::client::audit_recovery::recorded_v5_rows(app, "recovery_need_changed")
        .into_iter()
        .filter(|row| row["event"]["change"] == change)
        .collect()
}

/// Break `route`'s unit on the relay the way a refusing relay does.
fn park(app: &SqliteAppStorage, route: &TransportReconciliationRoute) {
    park_on(app, route, RELAY);
}

/// Break `route`'s unit on `relay` the way a refusing relay does.
fn park_on(app: &SqliteAppStorage, route: &TransportReconciliationRoute, relay: &str) {
    let now = crate::unix_now_seconds();
    app.begin_recovery_unit_attempt(route, relay, None, now)
        .unwrap();
    let unit = app
        .settle_recovery_unit(
            route,
            relay,
            RecoveryUnitOutcome::Refused,
            &RecoveryRunnerPolicy::default().unit,
            now,
        )
        .unwrap();
    assert!(matches!(unit.state, RecoveryUnitState::Broken(_)));
}

/// What the runner's survey would publish: these units catching up.
fn catching_up(client: &AppClient, units: &[&TransportReconciliationRoute]) {
    let units = units
        .iter()
        .map(|route| UnitKey {
            route: (*route).clone(),
            relay: RELAY.to_owned(),
        })
        .collect::<BTreeSet<_>>();
    client
        .routing
        .recovery_runner_catching_up()
        .send_replace(Some(units));
}

/// Neither a broken unit's park, on a group route or the inbox, nor a
/// remainder the retention floor overtook is evidence that messages are
/// missing, so none raises a notice, a notice change or a `notice_shown`
/// row, however caught up the runner is. A ledger notice id an earlier
/// release showed dismisses nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ledger_parks_and_remainders_raise_no_notice() {
    let dir = tempfile::tempdir().unwrap();
    let (app, mut client, storage, group, route) = audited_fixture(&dir).await;
    client.take_history_notice_changes();
    let now = crate::unix_now_seconds();
    storage
        .widen_recovery_coverage_goals(
            std::slice::from_ref(&route),
            now - 2 * DAY,
            storage_sqlite::CopyFloorReason::Clamp,
        )
        .unwrap();
    storage
        .prune_recovery_coverage(now - DAY, &[(route.clone(), vec![RELAY.to_owned()])])
        .unwrap();
    assert_eq!(storage.recovery_coverage_remainders().unwrap().len(), 1);
    park(&storage, &route);
    park(&storage, &TransportReconciliationRoute::Inbox);
    for surveyed in [&[][..], &[&route][..]] {
        catching_up(&client, surveyed);
        assert!(client.history_notices().unwrap().is_empty());
        let status = client.group_recovery_status(&group).unwrap();
        assert!(!status.history_may_be_incomplete && status.history_notice_ids.is_empty());
        assert!(client.account_recovery_status().unwrap().notices.is_empty());
    }
    assert_eq!(client.take_history_notice_changes(), None);
    assert!(need_changed(&app, "notice_shown").is_empty());

    let revision = storage.parked_recovery_routes().unwrap()[0].revision;
    let old = encode_notice_id(RecoveryDemandTicket {
        id: ledger_route_tag(&route),
        revision,
    });
    assert!(!client.dismiss_history_notice(&old).unwrap());
    assert!(matches!(
        storage.recovery_unit(&route, RELAY).unwrap().unwrap().state,
        RecoveryUnitState::Broken(_)
    ));
    assert_eq!(storage.recovery_coverage_remainders().unwrap().len(), 1);
    assert!(need_changed(&app, "notice_dismissed").is_empty());
}

/// The status reports the groups and inbox the runner's last survey found
/// catching up. A survey change the worker saw, or a notice change, owes
/// hosts one announcement.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_status_reports_what_the_runner_catches_up() {
    let dir = tempfile::tempdir().unwrap();
    let (mut client, _, group, route) = fixture(&dir).await;
    assert_eq!(
        client.account_recovery_status().unwrap(),
        AccountRecoveryStatus::default(),
        "nothing surveyed yet"
    );
    assert!(!client.take_recovery_status_changed(false));

    let gone = TransportReconciliationRoute::Group([0xee; 32]);
    catching_up(
        &client,
        &[&route, &TransportReconciliationRoute::Inbox, &gone],
    );
    let status = client.account_recovery_status().unwrap();
    assert_eq!(
        status.catching_up_group_ids_hex,
        vec![hex::encode(group.as_slice())],
        "a route no group holds now is not listed"
    );
    assert!(status.inbox_catching_up);
    assert!(status.notices.is_empty());
    client.recovery_status_owed = true;
    assert!(client.take_recovery_status_changed(false));
    assert!(
        !client.take_recovery_status_changed(false),
        "announced once"
    );

    // A notice change is a status change too.
    assert!(client.take_recovery_status_changed(true));

    catching_up(&client, &[]);
    let status = client.account_recovery_status().unwrap();
    assert!(status.catching_up_group_ids_hex.is_empty() && !status.inbox_catching_up);
}

/// A conversion that changed the notices is announced once, then
/// acknowledged: the account's parked loss, a notice, becomes its routes'
/// parks, which raise none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_conversion_that_changed_the_notices_is_announced_once() {
    let dir = tempfile::tempdir().unwrap();
    let (mut client, app, _, route) = fixture(&dir).await;
    client.take_history_notice_changes();
    park(&app, &route);
    // The old owner's parked account-wide queue loss, imported evidence and
    // all, as a build from before the conversion leaves it.
    let now = crate::unix_now_seconds();
    app.execute_batch_for_test(&format!(
        "INSERT INTO account_delivery_loss_evidence (account_label, cause, marker_token,
             pending_since, dropped_count, imported_count, bound_state, route_state)
         VALUES ('alice', 0, 42, {now}, 1, 1, 2, 0);
         INSERT INTO account_recovery_obligations (id, demand_key, cause, account_label,
             marker_token, pending_since, dropped_count, created_at_ms, updated_at_ms,
             eligibility, parked_at_ms)
         VALUES (x'{id}', 'overflow:alice', 0, 'alice', 42, {now}, 1, {ms}, {ms}, 4, {ms});",
        id = "42".repeat(16),
        ms = now * 1000,
    ))
    .unwrap();
    assert_eq!(
        client.take_history_notice_changes(),
        Some(Vec::new()),
        "the old owner's account-wide loss names no group"
    );

    // The old owner's parked loss above is what a build from before the
    // conversion leaves: rewind the conversion marker, as that build never
    // ran it. The fixture's own open converted, before any of it existed.
    let owner = client.app.clone();
    owner
        .relay_plane
        .deactivate_account_context(client.adapter.account_id())
        .await
        .unwrap();
    crate::client::recovery_coverage::scenario_tests::fault_connection(&client)
        .execute(
            "UPDATE account_recovery_conversion SET step = 0 WHERE singleton = 1",
            [],
        )
        .unwrap();
    drop(client);
    assert!(app.recovery_conversion_pending().unwrap());
    let mut client = client_on_app_relay_plane(&owner, "alice").await;
    assert!(!app.recovery_conversion_pending().unwrap());
    assert!(app.recovery_conversion_notices_changed().unwrap());
    assert!(client.history_notices().unwrap().is_empty());
    assert!(
        app.parked_recovery_routes()
            .unwrap()
            .iter()
            .any(|parked| parked.route == route)
    );

    assert_eq!(client.take_history_notice_changes(), Some(Vec::new()));
    assert!(!app.recovery_conversion_notices_changed().unwrap());
    assert_eq!(client.take_history_notice_changes(), None);
}
