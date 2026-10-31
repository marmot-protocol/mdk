//! Ledger-parked routes as notices, and the account's recovery status, behind
//! the internal `runner_owns_debt` gate (mdk#2660 phase 4): a parked group
//! route is a notice in that group's status, an inbox park only in the
//! account's list, a remainder only once nothing on its route catches up,
//! and dismissal retires the park, each shown and dismissed notice audited.
//! A suspended (Unrecoverable) group's routes give none, nor does a park on
//! a relay a route carries only as best effort. With the gate off none of it
//! shows.

use std::collections::BTreeSet;
use std::sync::Arc;

use cgka_traits::GroupId;
use storage_sqlite::{
    RecoveryCause, RecoveryConversionInput, RecoveryConversionRoute, RecoveryDemandTicket,
    RecoveryUnitOutcome, RecoveryUnitState, SqliteAppStorage, TransportReconciliationRoute,
};

use super::park_recovery_for_test;
use crate::client::recovery_runner::{RecoveryRunnerPolicy, UnitKey};
use crate::history_notices::{decode_notice_id, encode_notice_id, ledger_route_tag};
use crate::tests::{ScriptedPushRelayClient, client_on_app_relay_plane};
use crate::{AccountRecoveryStatus, AppClient, HistoryNoticeCause, MarmotApp};

const RELAY: &str = "wss://relay.example";
const DAY: u64 = 24 * 60 * 60;

fn app(dir: &tempfile::TempDir, gate: bool) -> MarmotApp {
    crate::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), RELAY)
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    if gate {
        app.with_recovery_runner_owning_debt()
    } else {
        app
    }
}

/// One account with one group, its client opened directly, and the group's
/// current route.
async fn fixture(
    dir: &tempfile::TempDir,
    gate: bool,
) -> (
    AppClient,
    SqliteAppStorage,
    GroupId,
    TransportReconciliationRoute,
) {
    let (_, client, storage, group, route) = opened(app(dir, gate)).await;
    (client, storage, group, route)
}

/// [`fixture`] recording audit v5, with its app to read the rows back.
async fn audited_fixture(
    dir: &tempfile::TempDir,
    gate: bool,
) -> (
    MarmotApp,
    AppClient,
    SqliteAppStorage,
    GroupId,
    TransportReconciliationRoute,
) {
    let app = app(dir, gate);
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
    let group = client.create_group("ledger notices", &[]).await.unwrap();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_parked_group_route_is_a_notice_in_its_groups_status_until_dismissed() {
    let dir = tempfile::tempdir().unwrap();
    let (mut client, app, group, route) = fixture(&dir, true).await;
    assert!(client.history_notices().unwrap().is_empty());
    client.take_history_notice_changes();
    park(&app, &route);

    let notices = client.history_notices().unwrap();
    assert_eq!(notices.len(), 1);
    let notice = notices[0].clone();
    assert_eq!(notice.cause, HistoryNoticeCause::UnprovenHistory);
    assert_eq!(notice.group_id_hex, Some(hex::encode(group.as_slice())));
    assert!(notice.parked_at_ms.is_some());
    assert_eq!(notice.notice_id.len(), 48);
    let ticket = decode_notice_id(&notice.notice_id).unwrap();
    assert_eq!(ticket.id, ledger_route_tag(&route), "the id names no route");
    let status = client.group_recovery_status(&group).unwrap();
    assert!(status.history_may_be_incomplete);
    assert_eq!(status.history_notice_ids, vec![notice.notice_id.clone()]);
    assert_eq!(
        client.take_history_notice_changes(),
        Some(vec![group.clone()])
    );
    assert_eq!(client.take_history_notice_changes(), None);

    // A stale revision retires nothing.
    let stale = encode_notice_id(RecoveryDemandTicket {
        revision: ticket.revision + 1,
        ..ticket
    });
    assert!(!client.dismiss_history_notice(&stale).unwrap());
    assert_eq!(client.history_notices().unwrap(), vec![notice.clone()]);

    assert!(client.dismiss_history_notice(&notice.notice_id).unwrap());
    assert!(client.history_notices().unwrap().is_empty());
    assert!(
        client
            .group_recovery_status(&group)
            .unwrap()
            .history_notice_ids
            .is_empty()
    );
    assert_eq!(
        app.recovery_unit(&route, RELAY).unwrap().unwrap().state,
        RecoveryUnitState::Retired
    );
    assert_eq!(
        client.take_history_notice_changes(),
        Some(vec![group.clone()])
    );
    assert!(
        !client.dismiss_history_notice(&notice.notice_id).unwrap(),
        "a dismissed park is stale"
    );

    // A re-arm and a later park are a new occurrence with a new id.
    app.rearm_all_recovery_units().unwrap();
    park(&app, &route);
    let again = client.history_notices().unwrap();
    assert_eq!(again.len(), 1);
    assert_ne!(again[0].notice_id, notice.notice_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_inbox_park_is_a_notice_in_the_account_list_only() {
    let dir = tempfile::tempdir().unwrap();
    let (mut client, app, group, _) = fixture(&dir, true).await;
    client.take_history_notice_changes();
    park(&app, &TransportReconciliationRoute::Inbox);

    let notices = client.history_notices().unwrap();
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].cause, HistoryNoticeCause::UnprovenHistory);
    assert_eq!(notices[0].group_id_hex, None);
    assert!(
        client
            .group_recovery_status(&group)
            .unwrap()
            .history_notice_ids
            .is_empty()
    );
    assert_eq!(client.take_history_notice_changes(), Some(Vec::new()));
    assert!(
        client
            .dismiss_history_notice(&notices[0].notice_id)
            .unwrap()
    );
    assert!(client.history_notices().unwrap().is_empty());
}

/// A shown ledger notice records one `notice_shown` row per occurrence, and
/// its dismissal one `notice_dismissed` row under the same reference; a
/// stale dismissal and a withdrawn notice record nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ledger_notices_are_audited_when_shown_and_dismissed() {
    let dir = tempfile::tempdir().unwrap();
    let (app, mut client, storage, group, route) = audited_fixture(&dir, true).await;
    client.take_history_notice_changes();
    park(&storage, &route);
    park(&storage, &TransportReconciliationRoute::Inbox);
    client.take_history_notice_changes();
    client.take_history_notice_changes();

    let shown = need_changed(&app, "notice_shown");
    assert_eq!(shown.len(), 2, "each notice is shown once, not per seam");
    let notices = client.history_notices().unwrap();
    let group_notice = notices
        .iter()
        .find(|notice| notice.group_id_hex.is_some())
        .unwrap();
    let group_ticket = decode_notice_id(&group_notice.notice_id).unwrap();
    let group_row = shown
        .iter()
        .find(|row| !row["group_ref"].is_null())
        .expect("the group route's notice names its group");
    let inbox_row = shown
        .iter()
        .find(|row| row["group_ref"].is_null())
        .expect("the inbox's notice is account-scoped");
    for row in [group_row, inbox_row] {
        assert_eq!(row["event"]["cause"], "unproven_history");
        assert!(row["event"]["charged"].is_null());
        assert!(row["event"]["bound"].is_null());
    }
    assert_ne!(
        group_row["event"]["obligation_ref"],
        inbox_row["event"]["obligation_ref"]
    );
    assert_eq!(
        group_row["event"]["obligation_revision"],
        group_ticket.revision
    );

    let stale = encode_notice_id(RecoveryDemandTicket {
        revision: group_ticket.revision + 1,
        ..group_ticket
    });
    assert!(!client.dismiss_history_notice(&stale).unwrap());
    assert!(need_changed(&app, "notice_dismissed").is_empty());

    assert!(
        client
            .dismiss_history_notice(&group_notice.notice_id)
            .unwrap()
    );
    let dismissed = need_changed(&app, "notice_dismissed");
    assert_eq!(dismissed.len(), 1);
    assert_eq!(dismissed[0]["event"]["cause"], "unproven_history");
    assert_eq!(
        dismissed[0]["event"]["obligation_ref"],
        group_row["event"]["obligation_ref"]
    );
    assert_eq!(dismissed[0]["group_ref"], group_row["group_ref"]);
    assert_eq!(
        client.take_history_notice_changes(),
        Some(vec![group.clone()])
    );
    assert!(
        need_changed(&app, "closed").is_empty(),
        "a dismissal is not coverage"
    );
    assert_eq!(need_changed(&app, "notice_shown").len(), 2);
}

/// A remainder the retention floor overtook is a notice only once the runner
/// has surveyed and catches up nothing on its route: before that, more of
/// the route's window may still be coming.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_remainder_is_a_notice_once_nothing_on_its_route_catches_up() {
    let dir = tempfile::tempdir().unwrap();
    let (mut client, app, group, route) = fixture(&dir, true).await;
    let now = crate::unix_now_seconds();
    app.widen_recovery_coverage_goals(std::slice::from_ref(&route), now - 2 * DAY)
        .unwrap();
    app.prune_recovery_coverage(now - DAY, &[(route.clone(), vec![RELAY.to_owned()])])
        .unwrap();
    assert_eq!(app.recovery_coverage_remainders().unwrap().len(), 1);

    assert!(client.history_notices().unwrap().is_empty(), "not surveyed");
    catching_up(&client, &[&route]);
    assert!(client.history_notices().unwrap().is_empty(), "catching up");
    catching_up(&client, &[&TransportReconciliationRoute::Inbox]);
    let notices = client.history_notices().unwrap();
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].group_id_hex, Some(hex::encode(group.as_slice())));
    assert_eq!(
        client
            .group_recovery_status(&group)
            .unwrap()
            .history_notice_ids,
        vec![notices[0].notice_id.clone()]
    );

    assert!(
        client
            .dismiss_history_notice(&notices[0].notice_id)
            .unwrap()
    );
    assert!(app.recovery_coverage_remainders().unwrap().is_empty());
    assert!(client.history_notices().unwrap().is_empty());
}

/// A suspended (Unrecoverable) group's park and remainder are no notices:
/// its recovery waits for the group's repair. Once the copy is repaired they
/// show again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_suspended_groups_park_and_remainder_are_no_notices() {
    use cgka_traits::storage::GroupStorage;
    let dir = tempfile::tempdir().unwrap();
    let (mut client, app, group, route) = fixture(&dir, true).await;
    let storage = client.app.account_storage("alice").unwrap();
    let suspend = |unrecoverable: bool| {
        let mut record = storage.get_group(&group).unwrap();
        record.unrecoverable = unrecoverable;
        storage.put_group(&record).unwrap();
    };
    let shown = |client: &AppClient| {
        let notices = client.history_notices().unwrap();
        assert_eq!(
            client
                .group_recovery_status(&group)
                .unwrap()
                .history_notice_ids,
            notices
                .iter()
                .map(|notice| notice.notice_id.clone())
                .collect::<Vec<_>>()
        );
        notices
    };

    park(&app, &route);
    assert_eq!(shown(&client).len(), 1);
    suspend(true);
    assert!(shown(&client).is_empty(), "a suspended park");
    suspend(false);
    let parked = shown(&client);
    assert_eq!(parked.len(), 1);
    assert!(client.dismiss_history_notice(&parked[0].notice_id).unwrap());

    let now = crate::unix_now_seconds();
    app.widen_recovery_coverage_goals(std::slice::from_ref(&route), now - 2 * DAY)
        .unwrap();
    app.prune_recovery_coverage(now - DAY, &[(route.clone(), vec![RELAY.to_owned()])])
        .unwrap();
    catching_up(&client, &[]);
    assert_eq!(shown(&client).len(), 1);
    suspend(true);
    assert!(shown(&client).is_empty(), "a suspended remainder");
    suspend(false);
    assert_eq!(shown(&client).len(), 1);
}

/// A broken unit on a relay the route carries only as best effort owes
/// nothing, so it raises no notice; one on the relay the route requires
/// does, and that notice is the route's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_park_on_a_relay_the_route_carries_only_as_best_effort_is_no_notice() {
    const OPERATED: &str = "wss://operated.example";
    const BEST_EFFORT: &str = "wss://best-effort.example";
    let dir = tempfile::tempdir().unwrap();
    crate::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relays_and_config(
        dir.path(),
        vec![RELAY.into()],
        crate::MarmotAppConfig::white_noise()
            .with_open_ranking_provider(None, Vec::new())
            .with_recovery_operated_relays(vec![OPERATED.into()]),
    )
    .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()))
    .with_recovery_runner_owning_debt();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group = client
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
    let route = client
        .recovery_runner_routes()
        .into_iter()
        .find(|route| route.group_id.as_deref() == Some(group.as_slice()))
        .unwrap();
    assert_eq!(route.required, vec![OPERATED.to_owned()]);
    assert_eq!(route.best_effort, vec![BEST_EFFORT.to_owned()]);
    let storage = app.account_storage("alice").unwrap().app_storage();

    park_on(&storage, &route.route, BEST_EFFORT);
    assert!(client.history_notices().unwrap().is_empty());
    park_on(&storage, &route.route, OPERATED);
    let notices = client.history_notices().unwrap();
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].group_id_hex, Some(hex::encode(group.as_slice())));

    // Dismissal retires what the notice showed, and only that.
    assert!(
        client
            .dismiss_history_notice(&notices[0].notice_id)
            .unwrap()
    );
    assert!(client.history_notices().unwrap().is_empty());
    let parked = storage.parked_recovery_routes().unwrap();
    assert_eq!(parked.len(), 1);
    assert_eq!(parked[0].relays, vec![BEST_EFFORT.to_owned()]);
}

/// A newer park on a relay the route carries only as best effort is outside
/// what a notice shows: it moves no notice's revision, so the remainder's
/// notice keeps its id and stays dismissable, and dismissing it leaves that
/// park as it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hidden_park_moves_no_notice_revision_and_is_never_dismissed() {
    const OPERATED: &str = "wss://operated.example";
    const BEST_EFFORT: &str = "wss://best-effort.example";
    let dir = tempfile::tempdir().unwrap();
    crate::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relays_and_config(
        dir.path(),
        vec![RELAY.into()],
        crate::MarmotAppConfig::white_noise()
            .with_open_ranking_provider(None, Vec::new())
            .with_recovery_operated_relays(vec![OPERATED.into()]),
    )
    .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()))
    .with_recovery_runner_owning_debt();
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group = client
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
    let route = client
        .recovery_runner_routes()
        .into_iter()
        .find(|route| route.group_id.as_deref() == Some(group.as_slice()))
        .unwrap()
        .route;
    let storage = app.account_storage("alice").unwrap().app_storage();
    let now = crate::unix_now_seconds();
    storage
        .widen_recovery_coverage_goals(std::slice::from_ref(&route), now - 2 * DAY)
        .unwrap();
    storage
        .prune_recovery_coverage(now - DAY, &[(route.clone(), vec![OPERATED.to_owned()])])
        .unwrap();
    catching_up(&client, &[]);
    let notices = client.history_notices().unwrap();
    assert_eq!(notices.len(), 1, "the remainder's notice");

    park_on(&storage, &route, BEST_EFFORT);
    assert_eq!(
        client.history_notices().unwrap(),
        notices,
        "the hidden park moves nothing"
    );
    assert!(
        client
            .dismiss_history_notice(&notices[0].notice_id)
            .unwrap()
    );
    assert!(client.history_notices().unwrap().is_empty());
    assert!(storage.recovery_coverage_remainders().unwrap().is_empty());
    let parked = storage.parked_recovery_routes().unwrap();
    assert_eq!(parked.len(), 1);
    assert_eq!(parked[0].relays, vec![BEST_EFFORT.to_owned()]);
}

/// The status reports the groups and inbox the runner's last survey found
/// catching up. A survey change the worker saw, or a notice change, owes
/// hosts one announcement.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_status_reports_what_the_runner_catches_up() {
    let dir = tempfile::tempdir().unwrap();
    let (mut client, app, group, route) = fixture(&dir, true).await;
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

    // A notice is a status change too.
    park(&app, &TransportReconciliationRoute::Inbox);
    let status = client.account_recovery_status().unwrap();
    assert_eq!(status.notices, client.history_notices().unwrap());
    assert_eq!(status.notices.len(), 1);
    assert!(client.take_history_notice_changes().is_some());
    assert!(client.take_recovery_status_changed(true));

    catching_up(&client, &[]);
    let status = client.account_recovery_status().unwrap();
    assert!(status.catching_up_group_ids_hex.is_empty() && !status.inbox_catching_up);
}

/// A conversion that changed the notices is announced once, then
/// acknowledged: the account's parked loss becomes its routes' parks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_conversion_that_changed_the_notices_is_announced_once() {
    let dir = tempfile::tempdir().unwrap();
    let (mut client, app, group, route) = fixture(&dir, true).await;
    client.take_history_notice_changes();
    park(&app, &route);
    app.mark_account_delivery_recovery("alice", 42, 1).unwrap();
    let loss = app
        .pending_recovery_demands()
        .unwrap()
        .into_iter()
        .find(|demand| demand.cause == RecoveryCause::QueueLoss)
        .unwrap()
        .ticket
        .id;
    park_recovery_for_test(&client.app.account_storage("alice").unwrap(), loss);
    assert_eq!(
        client.take_history_notice_changes(),
        Some(vec![group.clone()])
    );

    let now = crate::unix_now_seconds();
    let routes = client
        .recovery_runner_routes()
        .into_iter()
        .map(|route| RecoveryConversionRoute {
            route: route.route,
            required_relays: route.required,
            standing_floor_seconds: now - DAY,
        })
        .collect::<Vec<_>>();
    app.convert_recovery_obligations(&RecoveryConversionInput {
        routes: &routes,
        canonical_relay: &|relay| relay.to_owned(),
        retention_floor_seconds: now - DAY,
        now_seconds: now,
    })
    .unwrap();
    assert!(!app.recovery_conversion_pending().unwrap());
    assert!(app.recovery_conversion_notices_changed().unwrap());
    let notices = client.history_notices().unwrap();
    assert!(
        notices
            .iter()
            .all(|notice| notice.cause == HistoryNoticeCause::UnprovenHistory)
    );
    assert!(
        notices
            .iter()
            .any(|notice| notice.group_id_hex == Some(hex::encode(group.as_slice())))
    );

    assert_eq!(
        client.take_history_notice_changes(),
        Some(vec![group.clone()])
    );
    assert!(!app.recovery_conversion_notices_changed().unwrap());
    assert_eq!(client.take_history_notice_changes(), None);
}

/// With the gate off, a parked route, a parked inbox and a published survey
/// change no notice, no group's status, no announcement, no status and no
/// audit row, and a ledger notice id dismisses nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ledger_notices_and_the_status_stay_dormant_with_the_gate_off() {
    let dir = tempfile::tempdir().unwrap();
    let (audited, mut client, app, group, route) = audited_fixture(&dir, false).await;
    client.take_history_notice_changes();
    park(&app, &route);
    park(&app, &TransportReconciliationRoute::Inbox);
    catching_up(&client, &[&route, &TransportReconciliationRoute::Inbox]);

    assert!(client.history_notices().unwrap().is_empty());
    assert!(
        client
            .group_recovery_status(&group)
            .unwrap()
            .history_notice_ids
            .is_empty()
    );
    assert_eq!(client.take_history_notice_changes(), None);
    assert_eq!(
        client.account_recovery_status().unwrap(),
        AccountRecoveryStatus::default()
    );
    client.recovery_status_owed = true;
    assert!(!client.take_recovery_status_changed(true));

    let parked = app.parked_recovery_routes().unwrap();
    let revision = parked
        .iter()
        .find(|parked| parked.route == route)
        .unwrap()
        .revision;
    let id = encode_notice_id(RecoveryDemandTicket {
        id: ledger_route_tag(&route),
        revision,
    });
    assert!(!client.dismiss_history_notice(&id).unwrap());
    assert!(matches!(
        app.recovery_unit(&route, RELAY).unwrap().unwrap().state,
        RecoveryUnitState::Broken(_)
    ));
    client.take_history_notice_changes();
    assert!(
        crate::client::audit_recovery::recorded_v5_rows(&audited, "recovery_need_changed")
            .iter()
            .all(|row| row["event"]["cause"] != "unproven_history"
                && row["event"]["change"] == "recorded"),
        "only the account's own obligations are recorded",
    );
}
