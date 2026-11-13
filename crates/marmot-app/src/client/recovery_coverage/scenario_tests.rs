//! The coverage ledger driven through the real client seams: native
//! admission, loss import and receipt release. Its fixture is the caught-up
//! account other coverage and recovery runner tests open.
use std::sync::Arc;

use storage_sqlite::{
    SqliteAccountStorage, TRANSPORT_RECONCILIATION_RETENTION_SECS, TransportReconciliationRoute,
};

use crate::client::AppClient;
use crate::tests::{ScriptedPushRelayClient, client_on_app_relay_plane};
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
    pub(in crate::client) relay: Arc<ScriptedPushRelayClient>,
    pub(in crate::client) client: AppClient,
    pub(in crate::client) storage: SqliteAccountStorage,
    pub(in crate::client) group: cgka_traits::GroupId,
}

/// One account with one group and a checkpointed cursor whose live
/// subscriptions have reached native boundary admission: the normal
/// caught-up input state. Runner-owned cursor permission can precede counts,
/// so it alone does not settle this fixture.
pub(in crate::client) async fn fixture() -> Fixture {
    fixture_with_stored(Some(STORED_AT)).await
}

/// [`fixture`], with the relay returning one stored event created at
/// `stored` before each EOSE, or none.
pub(super) async fn fixture_with_stored(stored: Option<u64>) -> Fixture {
    fixture_on(vec![RELAY.into()], stored, None).await
}

pub(in crate::client) async fn fixture_on(
    relays: Vec<String>,
    stored: Option<u64>,
    lookback: Option<std::time::Duration>,
) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    crate::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let endpoints = relays.clone();
    let mut app = crate::MarmotApp::with_relays_and_config(
        dir.path(),
        relays,
        crate::MarmotAppConfig::white_noise(),
    )
    .with_test_relay_client(relay.clone());
    app.relay_plane = transport_nostr::MarmotRelayPlane::new_with_directory_fetcher_for_test(
        lookback,
        relay.clone(),
        relay.clone(),
        app.config.allow_loopback_relay_endpoints,
    );
    *relay.stored_before_eose.lock().unwrap() = stored;
    let mut state = app.load_state("alice").unwrap();
    state.last_transport_timestamp = Some(unix_now_seconds().saturating_sub(60));
    app.save_state(&state).unwrap();
    relay
        .connect_relays(&endpoints.iter().map(String::as_str).collect::<Vec<_>>())
        .await;
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group = client
        .create_group("coverage ledger", &[])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            client.synchronize_native_replay().await.unwrap();
            let observation = client.adapter.replay_admission().await;
            if client
                .recovery_owner
                .native_replay_authorizes(observation.generation())
                && observation
                    .sources()
                    .all(|source| source.endpoints().all(|endpoint| endpoint.admitted()))
            {
                break;
            }
            drop(observation);
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the scripted native windows reach owner admission");
    release_held_live_frames(&client).await;
    let storage = app.account_storage("alice").unwrap();
    Fixture {
        _dir: dir,
        relay,
        client,
        storage,
        group,
    }
}

/// The runner's answer for an account with nothing owed behind its live
/// window: every group the live counts hold is released with no fence, as
/// the runner's fence turn does, and the boundaries that frees are recorded,
/// as its next read of the live tails does. A counted live REQ is held until
/// then.
pub(in crate::client) async fn release_held_live_frames(client: &AppClient) {
    let read = client.recovery_runner_live_counts().await;
    if read.held.is_empty() {
        return;
    }
    client.fence_live_frames(read.ticket, &[]).await;
    let storage = client.app.account_storage(&client.state.label).unwrap();
    client.record_native_coverage(&storage.app_storage()).await;
}

/// A second connection to the account's database, only to inject write
/// faults or set up durable state no seam writes.
pub(in crate::client) fn fault_connection(client: &AppClient) -> rusqlite::Connection {
    let app = &client.app;
    let label = &client.state.label;
    let path = app.account_storage_path(label);
    let keys = app.account_home().load_signing_keys(label).unwrap();
    let key = app
        .sqlcipher_key(label, &keys, &path, crate::SqlcipherDatabaseKind::Session)
        .unwrap();
    let connection = rusqlite::Connection::open(path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &key,
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    connection
}

/// Drop every route's coverage goal. Native replay gives each route a goal
/// from its REQ window as soon as the fixture's subscriptions are admitted;
/// a test of the first goal some other seam writes starts from none, as an
/// account opened from before the ledger did.
pub(in crate::client) fn clear_coverage_goals(client: &AppClient) {
    fault_connection(client)
        .execute("DELETE FROM account_recovery_coverage_goals", [])
        .unwrap();
}

/// Start the account's REQs again, as a reconnect does, wait until the new
/// generation's boundaries are admitted, and answer as the runner does with
/// nothing owed ([`release_held_live_frames`]).
pub(super) async fn reactivate(fixture: &mut Fixture) {
    reactivate_client(&mut fixture.client).await;
    release_held_live_frames(&fixture.client).await;
}

pub(in crate::client) async fn reactivate_client(client: &mut AppClient) {
    client.prepare_transport().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            client.synchronize_native_replay().await.unwrap();
            let observation = client.adapter.replay_admission().await;
            if client
                .recovery_owner
                .native_replay_authorizes(observation.generation())
                && observation
                    .sources()
                    .all(|source| source.endpoints().all(|endpoint| endpoint.admitted()))
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

/// While loss is pending, an unchanged live boundary does not re-cover what
/// the loss un-covered: queue loss drops deliveries the adapter had placed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_loss_keeps_live_boundaries_from_re_covering_it() {
    let fixture = fixture().await;
    let app = fixture.storage.app_storage();
    let floor = unix_now_seconds().saturating_sub(30);
    app.record_account_recovery_loss_bounded(
        "alice",
        storage_sqlite::RecoveryLossCause::Queue,
        41,
        3,
        unix_now_seconds(),
        Some(floor),
    )
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
    for route in &routes {
        assert!(!owed(&fixture, route, unix_now_seconds()).await);
    }
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

/// A notification lag whose REQ floor is unknown un-covers every current
/// route's whole window: nothing it proved survives, and each owes from its
/// standing goal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_notification_lag_with_no_floor_uncovers_every_routes_whole_window() {
    let fixture = fixture().await;
    let app = fixture.storage.app_storage();
    let routes = routes(&fixture.client);
    for route in &routes {
        assert!(!owed(&fixture, route, unix_now_seconds()).await);
        assert!(
            !app.recovery_coverage_ranges(route, &relay())
                .unwrap()
                .is_empty()
        );
    }
    app.record_account_recovery_loss_bounded(
        "alice",
        storage_sqlite::RecoveryLossCause::NotificationConsumer,
        7,
        0,
        unix_now_seconds(),
        None,
    )
    .unwrap();
    fixture.client.synchronize_recovery_loss(&app).unwrap();
    for route in &routes {
        assert!(
            app.recovery_coverage_ranges(route, &relay())
                .unwrap()
                .is_empty(),
            "an unknown floor un-covers the whole window"
        );
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
    for route in routes(&fixture.client) {
        assert!(!owed(&fixture, &route, unix_now_seconds()).await);
    }
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

/// A group copy's Welcome time starts only its route's standing goal, never
/// below the retained window: loss below it still owes from its own floor,
/// and explicit repair wants the whole window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_copys_welcome_time_starts_only_its_standing_goal() {
    use cgka_traits::storage::GroupStorage;
    let mut fixture = fixture().await;
    clear_coverage_goals(&fixture.client);
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
        assert_eq!(
            fixture.client.standing_floor(current, now).unwrap(),
            expected
        );
    }
    assert_eq!(
        app.recovery_coverage_goal(&group_route).unwrap(),
        None,
        "nothing wanted the new group's route yet"
    );

    fixture.client.record_open_coverage_goals();
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
                fixture.client.standing_floor(current, now).unwrap(),
                super::retention_floor(now)
            );
        }
    }
}

/// Runtime startup defers MLS hydration. Its standing goal must still use
/// the persisted Welcome hint, since a later goal cannot narrow it (#2862).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deferred_open_starts_the_goal_at_the_durable_welcome_floor() {
    use cgka_traits::storage::GroupStorage;
    let Fixture {
        client,
        storage,
        group,
        _dir,
        relay: _relay,
    } = fixture_on(
        vec![RELAY.into()],
        None,
        Some(std::time::Duration::from_secs(120)),
    )
    .await;
    clear_coverage_goals(&client);
    let app = client.app.clone();
    let route = client
        .current_coverage_routes()
        .into_iter()
        .find(|route| route.group_id.as_deref() == Some(group.as_slice()))
        .unwrap()
        .route;
    assert_eq!(
        storage
            .app_storage()
            .recovery_coverage_goal(&route)
            .unwrap(),
        None
    );
    let welcome_at = unix_now_seconds() - 60 * 60;
    let mut record = storage.get_group(&group).unwrap();
    record.local_copy_welcome_created_at = Some(cgka_traits::transport::Timestamp(welcome_at));
    storage.put_group(&record).unwrap();
    drop(client);

    let reopened = app
        .local_client_with_relay_plane_and_hydration("alice", &app.relay_plane, None, true, None)
        .await
        .unwrap();
    let error = crate::AppError::from(reopened.runtime.group_record(&group).unwrap_err());
    assert!(matches!(
        error.as_engine_error(),
        Some(cgka_traits::error::EngineError::GroupNotHydrated(_))
    ));
    assert_eq!(
        storage
            .app_storage()
            .recovery_coverage_goal(&route)
            .unwrap(),
        Some(welcome_at - 15 * 60),
        "deferred startup must not pin the group to the 30-day retention floor"
    );
}
