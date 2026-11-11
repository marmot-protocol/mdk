//! A group copy that turns Unrecoverable and is replaced by the real
//! automatic rejoin, as the account's recovery runner serves it (mdk#2660
//! row 11): two direct clients on one relay that records every bounded
//! group-message request.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cgka_traits::storage::GroupStorage;
use nostr_relay_builder::prelude::{BoxedFuture, Filter as RelayFilter, PolicyResult, QueryPolicy};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use storage_sqlite::{
    RecoveryCopy, RecoveryLossCause, RecoverySpanRetirement, TransportReconciliationRoute,
};

use super::HOUR;
use crate::client::AppClient;
use crate::{HistoryNotice, HistoryNoticeCause, unix_now_seconds};

/// Every bounded group-message history request (a sweep's slice carries
/// `until`, a live REQ does not), as its `#h` values, `since` and `until`.
#[derive(Clone, Debug, Default)]
struct GroupSweeps(Arc<Mutex<Vec<GroupSweep>>>);

type GroupSweep = (Vec<String>, u64, u64);

impl GroupSweeps {
    fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    /// The `since` and `until` of each request for `route` after the first
    /// `skip`.
    fn bounds(&self, skip: usize, route: &str) -> Vec<(u64, u64)> {
        self.0.lock().unwrap()[skip..]
            .iter()
            .filter(|(routes, ..)| routes.iter().any(|tagged| tagged == route))
            .map(|(_, since, until)| (*since, *until))
            .collect()
    }
}

impl QueryPolicy for GroupSweeps {
    fn admit_query<'a>(
        &'a self,
        query: &'a RelayFilter,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            let query = serde_json::to_value(query).unwrap();
            let group_messages = query["kinds"]
                .as_array()
                .is_some_and(|kinds| kinds.contains(&445.into()));
            if let Some(until) = query["until"].as_u64()
                && group_messages
                && query.get("ids").is_none()
            {
                let routes = query["#h"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|route| route.as_str().map(str::to_owned))
                    .collect();
                let since = query["since"].as_u64().unwrap_or(0);
                self.0.lock().unwrap().push((routes, since, until));
            }
            PolicyResult::Accept
        })
    }
}

/// Close `client`, run `closed`, and open its account again on the app's
/// relay plane, as a restarted worker does.
async fn reopen(app: &crate::MarmotApp, client: AppClient, closed: impl FnOnce()) -> AppClient {
    let label = client.state.label.clone();
    let account = client.adapter.account_id().clone();
    drop(client);
    app.relay_plane
        .deactivate_account_context(&account)
        .await
        .unwrap();
    closed();
    crate::tests::client_on_app_relay_plane(app, &label).await
}

fn rejoin_notices(notices: &[HistoryNotice], group_hex: &str) -> Vec<String> {
    notices
        .iter()
        .filter(|notice| notice.group_id_hex.as_deref() == Some(group_hex))
        .inspect(|notice| assert_eq!(notice.cause, HistoryNoticeCause::BeforeRejoin))
        .map(|notice| notice.notice_id.clone())
        .collect()
}

/// While Bob's copy is Unrecoverable its route is never swept or charged,
/// though it owes six hours. Once the real automatic rejoin replaces the
/// copy, everything the route owed below the new copy's floor is retired as
/// before this copy and never asked for, the new copy's span is fetched from
/// that floor, and the group shows exactly one rejoin notice: a reopen raises
/// no second one, and its dismissal sticks across a reopen.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejoined_copy_owes_only_its_own_span_and_says_so_once() {
    let sweeps = GroupSweeps::default();
    let relay = LocalRelay::new(RelayBuilder::default().query_policy(sweeps.clone()));
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let home = crate::AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let app = crate::MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        crate::MarmotAppConfig::white_noise()
            .with_allow_loopback_relay_endpoints(true)
            .with_dev_settlement_quiescence_ms(0),
    );
    for account in [&alice, &bob] {
        crate::tests::remember_test_member_inbox(&app, &account.account_id_hex, &url);
    }
    // Bob runs as a worker does: a checkpointed cursor, and REQs rebuilt from
    // it less the runtime lookback, so no live REQ reaches back over his debt.
    let mut state = app.load_state(&bob.label).unwrap();
    state.last_transport_timestamp = Some(unix_now_seconds().saturating_sub(60));
    app.save_state(&state).unwrap();
    let mut bob_client = crate::tests::client_on_app_relay_plane(&app, &bob.label).await;
    bob_client.publish_key_package().await.unwrap();
    let mut alice_client = app.client(&alice.label).await.unwrap();
    let group = alice_client.create_group("rejoin", &["bob"]).await.unwrap();
    let group_hex = hex::encode(group.as_slice());
    bob_client.sync().await.unwrap();
    bob_client.accept_group_invite(&group).unwrap();
    bob_client.sync().await.unwrap();
    let route = bob_client
        .recovery_runner_routes()
        .into_iter()
        .find(|route| route.group_id.as_deref() == Some(group.as_slice()))
        .expect("Bob's copy is routed")
        .route;
    let TransportReconciliationRoute::Group(nostr_group_id) = &route else {
        unreachable!("a group's route");
    };
    let route_hex = hex::encode(nostr_group_id);
    let relay_name = transport_nostr::canonical_relay(&url);

    // History from before the halt that the copy never fetched.
    let storage = app.account_storage(&bob.label).unwrap();
    let ledger = storage.app_storage();
    let lost_from = unix_now_seconds() - 6 * HOUR;
    ledger
        .record_account_recovery_loss_bounded(
            &bob.label,
            RecoveryLossCause::NotificationConsumer,
            7,
            0,
            unix_now_seconds(),
            Some(lost_from),
        )
        .unwrap();
    bob_client.synchronize_recovery_loss(&ledger).unwrap();

    // Bob's copy halts as an already-pruned device opens it.
    let mut halted = storage.get_group(&group).unwrap();
    halted.unrecoverable = true;
    let halted_at = sweeps.len();
    let mut bob_client = reopen(&app, bob_client, || storage.put_group(&halted).unwrap()).await;
    let unit = ledger.recovery_unit(&route, &relay_name).unwrap();
    bob_client.sync().await.unwrap();
    assert!(
        sweeps.bounds(halted_at, &route_hex).is_empty(),
        "a suspended copy's route is never swept"
    );
    assert!(
        ledger.recovery_unit(&route, &relay_name).unwrap() == unit,
        "nor charged"
    );
    assert!(
        !ledger
            .recovery_unit_debt(&route, &relay_name, lost_from)
            .unwrap()
            .is_empty(),
        "though it owes"
    );
    assert!(bob_client.history_notices().unwrap().is_empty());

    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            bob_client.run_due_maintenance().await.unwrap();
            alice_client.sync().await.unwrap();
            alice_client.run_due_maintenance().await.unwrap();
            bob_client.sync().await.unwrap();
            let copy = storage.get_group(&group).unwrap();
            if !copy.unrecoverable
                && copy.local_copy_install_epoch > halted.local_copy_install_epoch
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the real automatic rejoin replaces Bob's copy");
    bob_client.sync().await.unwrap();
    let copy = storage.get_group(&group).unwrap();
    let floor = crate::history_floor(
        copy.local_copy_welcome_created_at
            .expect("a replacement Welcome has a time")
            .0,
    )
    .0;
    assert!(floor > lost_from);

    let asked = sweeps.bounds(halted_at, &route_hex);
    assert_eq!(
        asked.iter().map(|(since, _)| since).min(),
        Some(&floor),
        "the new copy's span is fetched from its floor, and nothing below it"
    );
    assert!(
        ledger
            .recovery_unit_debt(&route, &relay_name, floor)
            .unwrap()
            .is_empty(),
        "nothing below the floor is owed, and the floor itself is fetched"
    );
    let spans = ledger.recovery_unit_spans(&route, &relay_name).unwrap();
    assert!(
        spans
            .iter()
            .all(|span| span.range.until_seconds < floor && span.retired.is_some())
    );
    assert!(
        spans.iter().any(|span| {
            span.retired == Some(RecoverySpanRetirement::BeforeThisCopy)
                && span.range.since_seconds <= lost_from
                && lost_from <= span.range.until_seconds
        }),
        "what the old copy owed retires as before this copy"
    );
    assert_eq!(
        ledger.recovery_copy(group.as_slice()).unwrap(),
        Some(RecoveryCopy::Settled(copy.local_copy_install_epoch.0))
    );
    // Read at the floor, where the ledger still records the old copy's debt:
    // the seconds after it are proved as sweeps and, on a worker, the live
    // tail reach them.
    assert!(
        !ledger
            .recovery_coverage_debt(&route, std::slice::from_ref(&relay_name), floor)
            .unwrap()
            .is_empty()
    );
    assert!(
        bob_client
            .group_history_proved(group.as_slice(), floor)
            .await
            .unwrap(),
        "the new copy's history is proved: what lay before it is not its to prove"
    );
    let notices = bob_client.history_notices().unwrap();
    let ids = rejoin_notices(&notices, &group_hex);
    assert_eq!(ids.len(), 1, "exactly one notice, the rejoin's");
    assert_eq!(
        bob_client
            .group_recovery_status(&group)
            .unwrap()
            .history_notice_ids,
        ids
    );

    let mut bob_client = reopen(&app, bob_client, || {}).await;
    bob_client.sync().await.unwrap();
    assert_eq!(
        bob_client.history_notices().unwrap(),
        notices,
        "a reopen raises no second notice"
    );
    assert!(bob_client.dismiss_history_notice(&ids[0]).unwrap());
    assert!(rejoin_notices(&bob_client.history_notices().unwrap(), &group_hex).is_empty());

    let mut bob_client = reopen(&app, bob_client, || {}).await;
    bob_client.sync().await.unwrap();
    assert!(rejoin_notices(&bob_client.history_notices().unwrap(), &group_hex).is_empty());
    assert!(!bob_client.dismiss_history_notice(&ids[0]).unwrap());
    relay.shutdown();
}

/// A relay that joins a rejoined group's route after the rejoin settles it at
/// the next debt turn that carries it: what lay before the copy retires there
/// as before this copy too, and the relay owes only the new copy's span.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_added_after_a_rejoin_owes_only_the_new_copys_span() {
    use cgka_traits::{EpochId, TransportEndpoint};
    let (_dir, _relay, app, mut client) = super::direct_client().await;
    let group = client.create_group("later", &[]).await.unwrap();
    let account = app.account_storage("alice").unwrap();
    let ledger = account.app_storage();
    let installed = client
        .routing
        .snapshot()
        .group_routes
        .into_iter()
        .filter(|route| route.group_id == group)
        .collect::<Vec<_>>();
    let route = |client: &AppClient| {
        client
            .recovery_runner_routes()
            .into_iter()
            .find(|route| route.group_id.as_deref() == Some(group.as_slice()))
            .expect("the group is routed")
    };
    let runner_route = route(&client);
    let now = unix_now_seconds();
    ledger
        .widen_recovery_coverage_goals(
            std::slice::from_ref(&runner_route.route),
            now - 6 * HOUR,
            storage_sqlite::CopyFloorReason::Clamp,
        )
        .unwrap();

    // A replacement Welcome installed a new copy two hours ago.
    let mut copy = account.get_group(&group).unwrap();
    copy.join_epoch = EpochId(0);
    copy.local_copy_install_epoch = EpochId(copy.local_copy_install_epoch.0 + 1);
    copy.local_copy_welcome_created_at = Some(cgka_traits::transport::Timestamp(now - 2 * HOUR));
    account.put_group(&copy).unwrap();
    client.settle_recovery_rejoins(&ledger, now).unwrap();
    let floor = crate::history_floor(now - 2 * HOUR).0;
    let owes_from_floor = |relay: &str| {
        let debt = ledger
            .recovery_unit_debt(&runner_route.route, relay, now)
            .unwrap();
        debt.len() == 1 && debt[0].since_seconds == floor
    };
    assert!(owes_from_floor(&runner_route.required[0]));

    let mut added = installed;
    added[0]
        .endpoints
        .push(TransportEndpoint("wss://later.example".to_owned()));
    client.routing.replace_group_routes(&group, added);
    client.settle_recovery_route_changes(&ledger, now).unwrap();
    let carried = route(&client);
    let later = carried
        .required
        .iter()
        .chain(&carried.best_effort)
        .find(|relay| !runner_route.required.contains(relay))
        .expect("the route carries the added relay")
        .clone();
    client.settle_recovery_rejoins(&ledger, now).unwrap();
    assert!(
        owes_from_floor(&later),
        "the added relay owes only the new copy's span"
    );
    let spans = ledger
        .recovery_unit_spans(&runner_route.route, &later)
        .unwrap();
    assert!(!spans.is_empty());
    assert!(spans.iter().all(|span| {
        span.retired == Some(RecoverySpanRetirement::BeforeThisCopy)
            && span.range.until_seconds < floor
    }));
    assert_eq!(
        rejoin_notices(
            &client.history_notices().unwrap(),
            &hex::encode(group.as_slice())
        )
        .len(),
        1,
        "the added relay raises no second notice"
    );
}
