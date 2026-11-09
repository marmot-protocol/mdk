//! Tests that build a whole `MarmotApp` or runtime and drive it through the
//! relay plane. They live with the app rather than the plane, so the plane can
//! become its own crate (relay-plane brief, PR 2); they reach plane state only
//! through its `_for_test` accessors.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::{
    MemberId, TransportAdapterError, TransportEndpoint, TransportEndpointFailure,
    TransportEndpointReceipt,
};
use tokio::time::timeout;
use transport_nostr_adapter::{
    NostrNotificationLossFloor, NostrPublishOutcome, NostrRelayClient, NostrSubscription,
};
use transport_nostr_peeler::NostrTransportEvent;

use transport_nostr::{
    AccountDeliveryReceive, DirectoryFetchRequest, DirectoryRelayEventRecord, DirectoryRelayFetcher,
};

/// A relay client that records subscriptions, answers each REQ with EOSE on
/// each of its relays, and accepts no publish. A copy of the relay plane's own
/// test fake: once the plane is its own crate, its test module is not visible
/// here.
#[derive(Default)]
struct RecordingRelayClient {
    /// What its relays send the plane: an EOSE for each accepted REQ on each
    /// relay.
    messages: Arc<transport_nostr::test_support::ScriptedRelayMessages>,
    subscriptions: StdMutex<Vec<NostrSubscription>>,
    unsubscribed: StdMutex<Vec<NostrSubscription>>,
    unsubscribed_accounts: StdMutex<Vec<MemberId>>,
}

#[async_trait::async_trait]
impl DirectoryRelayFetcher for RecordingRelayClient {
    async fn fetch_directory_events(
        &self,
        _request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl NostrRelayClient for RecordingRelayClient {
    fn relay_notification_source(
        &self,
    ) -> Option<Arc<dyn transport_nostr_adapter::NostrRelayNotificationSource>> {
        Some(self.messages.clone())
    }

    async fn reply_sent_nothing(
        &self,
        _account: Option<&MemberId>,
        _endpoint: &TransportEndpoint,
        subscription_id: &str,
    ) -> bool {
        self.messages.reply_sent_nothing(subscription_id)
    }

    async fn publish_event_for_account(
        &self,
        _account_id: &MemberId,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        self.publish_event(endpoints, event, required_acks).await
    }
    async fn subscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        let id = subscription.subscription_id();
        for endpoint in subscription.endpoints() {
            self.messages.eose(endpoint, &id);
        }
        self.subscriptions.lock().unwrap().push(subscription);
        Ok(())
    }

    async fn unsubscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        self.unsubscribed.lock().unwrap().push(subscription);
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        account_id: &MemberId,
        _replacements: &[NostrSubscription],
    ) -> Result<(), TransportAdapterError> {
        self.unsubscribed_accounts
            .lock()
            .unwrap()
            .push(account_id.clone());
        Ok(())
    }

    async fn publish_event(
        &self,
        _endpoints: &[TransportEndpoint],
        _event: &NostrTransportEvent,
        _required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        Ok(NostrPublishOutcome {
            message_id: None,
            accepted: Vec::<TransportEndpointReceipt>::new(),
            failed: Vec::<TransportEndpointFailure>::new(),
        })
    }
}

impl RecordingRelayClient {
    /// These relays are connected, as a running app's are before its account
    /// subscribes: wait until the plane has heard each connection, so a REQ
    /// it issues there later counts from its own issue.
    async fn connect_relays(&self, endpoints: &[&str]) {
        for endpoint in endpoints {
            self.messages
                .connect(&TransportEndpoint((*endpoint).to_owned()));
        }
        self.messages.handled().await;
    }
}

fn inbox_subscription_count(relay: &RecordingRelayClient) -> usize {
    relay
        .subscriptions
        .lock()
        .unwrap()
        .iter()
        .filter(|subscription| matches!(subscription, NostrSubscription::AccountInbox { .. }))
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_account_worker_reopens_transport_after_notification_consumer_exit() {
    let dir = tempfile::tempdir().unwrap();
    marmot_account::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(RecordingRelayClient::default());
    let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    relay.connect_relays(&["wss://relay.example"]).await;
    let relay_plane = app.relay_plane.clone();
    let runtime = crate::MarmotAppRuntime::new(app);

    runtime.reconcile_accounts().await.unwrap();
    timeout(Duration::from_secs(5), async {
        while inbox_subscription_count(&relay) < 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the managed account worker should activate its initial inbox subscription");

    relay_plane.simulate_notification_consumer_exit_for_test();

    timeout(Duration::from_secs(5), async {
        while inbox_subscription_count(&relay) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("producer death should make the managed account worker reopen and resubscribe");

    runtime.shutdown().await;
}

/// The #2070 loop: a lag used to close the route, the worker reopened and
/// replayed the whole backlog from the loss-fenced cursor, and the replay
/// overflowed again. Now the worker keeps its session and persists the loss,
/// bounded by the REQ floor read at the lag, for comparison recovery.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_account_worker_keeps_its_session_through_notification_lag() {
    let dir = tempfile::tempdir().unwrap();
    let home = marmot_account::AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let account =
        MemberId::new(hex::decode(home.account("alice").unwrap().account_id_hex).unwrap());
    let relay = Arc::new(RecordingRelayClient::default());
    let app = crate::MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    relay.connect_relays(&["wss://relay.example"]).await;
    let relay_plane = app.relay_plane.clone();
    let storage = app.account_storage("alice").unwrap().app_storage();
    let runtime = crate::MarmotAppRuntime::new(app);

    runtime.reconcile_accounts().await.unwrap();
    timeout(Duration::from_secs(5), async {
        while inbox_subscription_count(&relay) < 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the managed account worker should activate its initial inbox subscription");
    let subscriptions = inbox_subscription_count(&relay);
    let before_loss = storage.recovery_coverage_mark().unwrap();
    let retained_since = crate::unix_now_seconds()
        .saturating_sub(storage_sqlite::TRANSPORT_RECONCILIATION_RETENTION_SECS);

    relay_plane.simulate_notification_lag_for_test(
        &account,
        3,
        NostrNotificationLossFloor::Since(1_700_000_000),
    );
    timeout(Duration::from_secs(5), async {
        while storage.recovery_coverage_mark().unwrap() == before_loss {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the worker persists the lag");
    // The new owner reclaims the raw watermark after durably importing it.
    // This old floor is outside retention: its owed history must be parked,
    // rather than silently dropped when that watermark goes away.
    assert!(storage.recovery_coverage_remainders().unwrap().iter().any(
        |remainder| remainder.route == storage_sqlite::TransportReconciliationRoute::Inbox
            && remainder.range.since_seconds <= 1_700_000_000
            && remainder.range.until_seconds >= retained_since.saturating_sub(1)
    ));
    for _ in 0..20 {
        assert!(
            !matches!(
                runtime.unhydrated_group_count_for_test("alice").await,
                Err(crate::AppError::TransportClosed)
            ),
            "commands never see a closed transport because of a lag"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        inbox_subscription_count(&relay),
        subscriptions,
        "a lag neither reopens the session nor re-subscribes"
    );
    assert_eq!(
        relay_plane.notification_forwarder_unexpected_exits_for_test(),
        0
    );

    runtime.shutdown().await;
}

/// A notification lag reaches the worker's receive boundary with its own
/// token and REQ floor, and its overflow identity survives a receiver
/// replacement. An unexpected consumer exit still closes the route, and a
/// later lag whose control record cannot reach the closed queue is received
/// before the closed queue is. What the ledger owes for a lag is the
/// recovery coverage scenario tests' (`notification_lag_*`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notification_lag_reaches_the_receive_boundary_and_survives_receiver_replacement() {
    use crate::tests::{ScriptedPushRelayClient, client_on_app_relay_plane};
    let dir = tempfile::tempdir().unwrap();
    crate::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = crate::MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        crate::MarmotAppConfig::white_noise(),
    )
    .with_test_relay_client(relay);
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let account = client.adapter.account_id().clone();
    app.relay_plane
        .set_account_delivery_recovery_marker_for_test(
            &account,
            Arc::new(|_, _, _, _| panic!("notification lag must never use the queue writer")),
        );
    app.relay_plane.simulate_notification_lag_for_test(
        &account,
        0,
        NostrNotificationLossFloor::Since(1_700_000_000),
    );
    let loss = client.adapter.pending_delivery_overflow().unwrap();
    assert_eq!(loss.dropped, 0);
    assert_eq!(loss.notification_losses, 1);
    assert_eq!(loss.notification_floor, Some(1_700_000_000));
    // The real worker receive boundary takes the typed lag, bounded by the
    // REQ floor read at the lag, and the route stays open.
    assert!(matches!(
        client.receive_next_delivery().await,
        Ok(AccountDeliveryReceive::Overflow(overflow))
            if overflow.notification_token == loss.notification_token
                && overflow.notification_floor == Some(1_700_000_000)
    ));
    let prior = client.adapter.delivery_overflow_identity_for_test();
    drop(client);
    let mut replacement = client_on_app_relay_plane(&app, "alice").await;
    assert!(prior.same_as(&replacement.adapter.delivery_overflow_identity_for_test()));
    // An unexpected consumer exit still closes the route.
    app.relay_plane
        .simulate_notification_consumer_exit_for_test();
    // A lag whose control record cannot reach the closed queue, and whose
    // floor is unknown.
    app.relay_plane.simulate_notification_lag_for_test(
        &account,
        1,
        NostrNotificationLossFloor::Unbounded,
    );
    let newer = replacement.adapter.pending_delivery_overflow().unwrap();
    assert_ne!(newer.notification_token, loss.notification_token);
    assert_eq!(newer.notification_floor, None);
    // Received without its control record, before the closed queue is seen.
    assert!(matches!(
        replacement.receive_next_delivery().await,
        Ok(AccountDeliveryReceive::Overflow(overflow))
            if overflow.notification_token == newer.notification_token
                && overflow.notification_floor.is_none()
    ));
    assert!(matches!(
        replacement.receive_next_delivery().await,
        Err(crate::AppError::TransportClosed)
    ));
    app.relay_plane.shutdown().await;
}

/// An unexpected notification consumer exit closes the account delivery
/// route and the managed worker reopens its session. The reopened session
/// registers a new signer with the SDK, which refuses while the previous
/// immutable account context is live, so the worker must retire that context
/// first. Otherwise every reopen fails and the account stays in reconnect
/// backoff, where commands fail with `transport_closed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk_account_worker_reopens_after_notification_consumer_exit() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let alice = marmot_account::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = crate::MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
    );
    let runtime = crate::MarmotAppRuntime::new(app);
    runtime.reconcile_accounts().await.unwrap();
    timeout(Duration::from_secs(30), runtime.catch_up_accounts())
        .await
        .expect("initial catch-up finishes")
        .unwrap();
    let group = runtime
        .create_group_with_options(
            &alice.label,
            "notification loss",
            &[],
            crate::AppCreateGroupOptions {
                relays: Some(vec![url]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    runtime.group_members(&alice.label, &group).await.unwrap();

    runtime
        .shared_services()
        .relay_plane()
        .simulate_notification_consumer_exit_for_test();
    // The first reconnect waits two seconds plus jitter; later ones double.
    timeout(Duration::from_secs(20), async {
        let mut reconnecting = false;
        loop {
            match runtime.group_members(&alice.label, &group).await {
                Ok(_) if reconnecting => break,
                Ok(_) => {}
                Err(crate::AppError::TransportClosed) => reconnecting = true,
                Err(error) => panic!("unexpected group read error: {error:?}"),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the reopened worker serves reads again");
    timeout(Duration::from_secs(30), runtime.catch_up_accounts())
        .await
        .expect("the reopened worker catches up")
        .unwrap();
    runtime.shutdown().await;
}

/// On the real SDK plane a lag keeps the account's context and session. The
/// loss is charged with the floor the account's SDK context reports for its
/// REQs, and commands keep being served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk_account_worker_keeps_serving_through_notification_lag() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let alice = marmot_account::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let account = MemberId::new(hex::decode(&alice.account_id_hex).unwrap());
    let app = crate::MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
    );
    let storage = app.account_storage(&alice.label).unwrap().app_storage();
    // Model a returning account with a settled cursor, not first-load history.
    let mut state = app.load_state(&alice.label).unwrap();
    state.last_transport_timestamp = Some(crate::unix_now_seconds());
    app.save_state(&state).unwrap();
    let runtime = crate::MarmotAppRuntime::new(app);
    runtime.reconcile_accounts().await.unwrap();
    timeout(Duration::from_secs(30), runtime.catch_up_accounts())
        .await
        .expect("initial catch-up finishes")
        .unwrap();
    let group = runtime
        .create_group_with_options(
            &alice.label,
            "notification lag",
            &[],
            crate::AppCreateGroupOptions {
                relays: Some(vec![url]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    runtime.group_members(&alice.label, &group).await.unwrap();
    let plane = runtime.shared_services().relay_plane().clone();
    let sdk = plane.sdk_relay_client_for_test().unwrap();
    let floor = sdk.notification_loss_floor_for_account(&account).await;
    assert!(
        matches!(floor, NostrNotificationLossFloor::Since(_)),
        "after catch-up every live REQ of the account carries a since"
    );

    let before_loss = storage.recovery_coverage_mark().unwrap();
    plane.simulate_notification_lag_for_test(&account, 1, floor);
    timeout(Duration::from_secs(10), async {
        while storage.recovery_coverage_mark().unwrap() == before_loss {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the worker persists the lag");
    // Raw watermarks are reclaimed after import; the durable un-cover fence
    // and goals now retain the lag even if the runner has already re-proved it.
    let since = floor.since_seconds().unwrap();
    let routes = storage.recovery_coverage_goal_routes().unwrap();
    assert!(
        routes.len() >= 2,
        "the inbox and group both retain their goals"
    );
    for route in routes {
        assert!(storage.recovery_coverage_goal(&route).unwrap().unwrap() <= since);
    }
    for _ in 0..20 {
        runtime
            .group_members(&alice.label, &group)
            .await
            .expect("a lag never closes the account's transport");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        sdk.notification_loss_for_account(&account).await.is_ok(),
        "the account keeps its SDK context"
    );
    assert_eq!(
        plane
            .relay_health()
            .await
            .notification_forwarder_unexpected_exits,
        0
    );
    runtime.shutdown().await;
}

/// A retained route stored before switch times were kept is stamped at the
/// first load after the upgrade, so its REQ is floored and a lag on an
/// account that has one stays bounded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notification_lag_with_a_legacy_retained_route_stays_bounded() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let alice = marmot_account::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let account = MemberId::new(hex::decode(&alice.account_id_hex).unwrap());
    let config = || crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true);

    // Before the upgrade: a group whose retained route has no switch time.
    {
        let app = crate::MarmotApp::with_relay_and_config(dir.path(), url.clone(), config());
        // The current route resumes a settled cursor; only the retained route
        // is missing its old switch-time floor.
        let mut state = app.load_state(&alice.label).unwrap();
        state.last_transport_timestamp = Some(crate::unix_now_seconds());
        app.save_state(&state).unwrap();
        let mut client = crate::tests::client_on_app_relay_plane(&app, &alice.label).await;
        client.prepare_transport().await.unwrap();
        client
            .create_group_with_options(
                "legacy retained route",
                &[],
                crate::AppCreateGroupOptions {
                    relays: Some(vec![url.clone()]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        drop(client);
        let storage = app.account_storage(&alice.label).unwrap().app_storage();
        let mut stored = storage
            .load_account_projection_state(&alice.label, crate::MAX_SEEN_EVENT_IDS)
            .unwrap();
        stored.groups[0]
            .prior_nostr_routes
            .push(storage_sqlite::StoredNostrRoute {
                nostr_group_id_hex: hex::encode([0x11; 32]),
                relays: vec![url.clone()],
                last_epoch: 0,
                replaced_at: None,
            });
        storage
            .save_account_projection_state(
                &stored,
                crate::MAX_SEEN_EVENT_IDS,
                crate::TRANSPORT_CURSOR_MAX_FUTURE_SKEW.as_secs(),
            )
            .unwrap();
        app.relay_plane.shutdown().await;
    }

    let app = crate::MarmotApp::with_relay_and_config(dir.path(), url, config());
    let mut client = crate::tests::client_on_app_relay_plane(&app, &alice.label).await;
    client.prepare_transport().await.unwrap();
    let sdk = app.relay_plane.sdk_relay_client_for_test().unwrap();
    let floor = sdk.notification_loss_floor_for_account(&account).await;
    assert!(
        matches!(floor, NostrNotificationLossFloor::Since(_)),
        "every REQ carries a floor, so a lag is bounded: {floor:?}"
    );
    let stamp = client.state.groups[0].prior_nostr_routes[0]
        .replaced_at
        .expect("the first load stamps the legacy route");
    let retained = client
        .routing
        .snapshot()
        .group_routes
        .into_iter()
        .find(|route| route.transport_group_id == vec![0x11; 32])
        .expect("the retained route is still routed");
    assert_eq!(retained.retained_since, Some(crate::history_floor(stamp)));
    app.relay_plane.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn liveness_manual_lifetime() {
    let receive = nostr_relay_builder::MockRelay::run().await.unwrap();
    let manual = nostr_relay_builder::MockRelay::run().await.unwrap();
    let unconfigured = nostr_relay_builder::MockRelay::run().await.unwrap();
    let receive_url = receive.url().await.to_string();
    let manual_url = manual.url().await.to_string();
    let unconfigured_url = unconfigured.url().await.to_string();
    let dir = tempfile::tempdir().unwrap();
    let account = marmot_account::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = crate::MarmotApp::with_relay_and_config(
        dir.path(),
        receive_url.clone(),
        crate::MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    let mut lists = crate::AccountRelayListStatus::empty();
    lists.nip65.created_at = crate::unix_now_seconds();
    lists.nip65.relays = vec![receive_url.clone()];
    lists.inbox.created_at = lists.nip65.created_at;
    lists.inbox.relays = vec![receive_url.clone()];
    lists.refresh();
    app.directory()
        .remember_directory_relay_lists(&account.account_id_hex, &lists)
        .unwrap();
    let account_id = MemberId::new(hex::decode(&account.account_id_hex).unwrap());
    let mut changes = app.relay_plane.relay_liveness_changes().unwrap();
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    let sdk = timeout(Duration::from_secs(5), async {
        loop {
            changes.borrow_and_update();
            if let Some(client) = app
                .relay_plane
                .account_history_relay_client(&account_id)
                .await
                && client.relay_liveness().await.iter().any(|row| {
                    row.url.trim_end_matches('/') == receive_url.trim_end_matches('/')
                        && row.status == crate::RelayLivenessStatus::Connected
                })
            {
                break client;
            }
            changes.changed().await.unwrap();
        }
    })
    .await
    .expect("the managed account activates its receive socket");

    // An existing pool socket outside the configured union is not a retry target.
    sdk.client().add_relay(&unconfigured_url).await.unwrap();
    sdk.reconnect_relay(&TransportEndpoint(unconfigured_url.clone()))
        .await
        .unwrap();
    let outside = sdk
        .client()
        .relay(&unconfigured_url)
        .await
        .unwrap()
        .unwrap();
    let attempts = outside.stats().attempts();
    assert!(
        runtime
            .reconnect_relay(&account.label, &unconfigured_url)
            .await
            .is_err()
    );
    assert_eq!(outside.stats().attempts(), attempts);

    lists.nip65.created_at += 1;
    lists.nip65.write_relays = vec![manual_url.clone()];
    lists.refresh();
    app.directory()
        .remember_directory_relay_lists(&account.account_id_hex, &lists)
        .unwrap();
    runtime
        .reconnect_relay(&account.label, &manual_url)
        .await
        .unwrap();
    let socket = sdk.client().relay(&manual_url).await.unwrap().unwrap();
    assert!(!socket.capabilities().can_read());
    assert!(!socket.capabilities().can_write());

    // No UI subscription or read drives cleanup after this configuration commit.
    lists.nip65.created_at += 1;
    lists.nip65.write_relays.clear();
    lists.refresh();
    app.directory()
        .remember_directory_relay_lists(&account.account_id_hex, &lists)
        .unwrap();
    timeout(Duration::from_secs(5), async {
        loop {
            changes.borrow_and_update();
            if sdk.client().relay(&manual_url).await.unwrap().is_none() {
                break;
            }
            changes.changed().await.unwrap();
        }
    })
    .await
    .expect("the account worker releases a no-longer-configured manual socket");
    assert!(sdk.relay_liveness().await.iter().any(|row| {
        row.url.trim_end_matches('/') == receive_url.trim_end_matches('/')
            && row.status == crate::RelayLivenessStatus::Connected
    }));
    runtime.shutdown().await;
    receive.shutdown();
    manual.shutdown();
    unconfigured.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn liveness_socket_watch() {
    async fn wait_for_status(
        subscription: &crate::RuntimeRelayLivenessSubscription,
        url: &str,
        status: crate::RelayLivenessStatus,
    ) -> crate::RelayLiveness {
        timeout(Duration::from_secs(5), async {
            let mut rows = subscription.snapshot.clone();
            loop {
                if let Some(row) = rows
                    .iter()
                    .find(|row| row.url == url && row.status == status)
                {
                    return row.clone();
                }
                rows = subscription
                    .recv()
                    .await
                    .unwrap()
                    .expect("live relay watch");
            }
        })
        .await
        .expect("the runtime observes the socket's status")
    }

    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let canonical = url.trim_end_matches('/').to_owned();
    let slash_url = format!("{canonical}/");
    let dir = tempfile::tempdir().unwrap();
    let alice = marmot_account::AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = crate::MarmotApp::with_relay_and_config(
        dir.path(),
        slash_url.clone(),
        crate::MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    let mut lists = crate::AccountRelayListStatus::empty();
    lists.nip65.created_at = crate::unix_now_seconds();
    lists.nip65.relays = vec![slash_url.clone()];
    lists.inbox.created_at = lists.nip65.created_at;
    lists.inbox.relays = vec![slash_url];
    lists.refresh();
    app.directory()
        .remember_directory_relay_lists(&alice.account_id_hex, &lists)
        .unwrap();
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let subscription = runtime
        .subscribe_relay_liveness(&alice.label)
        .await
        .unwrap();
    assert_eq!(subscription.snapshot.len(), 1);
    assert_eq!(subscription.snapshot[0].url, canonical);
    assert_eq!(
        subscription.snapshot[0].status,
        crate::RelayLivenessStatus::Unknown
    );

    runtime.reconcile_accounts().await.unwrap();
    let connected = wait_for_status(
        &subscription,
        &canonical,
        crate::RelayLivenessStatus::Connected,
    )
    .await;
    assert!(connected.last_attempt_unix.is_some());
    assert_eq!(connected.last_error, None);

    // Add a configured-only URL after activation so it never joins the pool.
    lists.nip65.created_at += 1;
    lists.nip65.write_relays = vec!["wss://configured-only.example".into()];
    lists.refresh();
    app.directory()
        .remember_directory_relay_lists(&alice.account_id_hex, &lists)
        .unwrap();
    let rows = runtime.account_relay_liveness(&alice.label).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows.iter().find(|row| row.url == canonical),
        Some(&connected)
    );
    let absent = rows
        .iter()
        .find(|row| row.url == "wss://configured-only.example")
        .unwrap();
    assert_eq!(absent.status, crate::RelayLivenessStatus::Unknown);
    assert_eq!(absent.last_attempt_unix, None);
    assert_eq!(absent.last_error, None);
    drop(subscription);

    // A host reconnects using the canonical row URL, not its slash-spelled
    // configuration, even when that account socket is already Connected.
    let retried = runtime
        .reconnect_relay(&alice.label, &connected.url)
        .await
        .unwrap();
    assert_eq!(retried.url, canonical);
    assert!(retried.last_attempt_unix.is_some());
    assert!(matches!(
        retried.status,
        crate::RelayLivenessStatus::Connecting | crate::RelayLivenessStatus::Connected
    ));
    let subscription = runtime
        .subscribe_relay_liveness(&alice.label)
        .await
        .unwrap();
    let reconnected = wait_for_status(
        &subscription,
        &canonical,
        crate::RelayLivenessStatus::Connected,
    )
    .await;
    assert!(reconnected.last_attempt_unix.is_some());
    assert_eq!(reconnected.last_error, None);

    relay.shutdown();
    let offline = wait_for_status(
        &subscription,
        &canonical,
        crate::RelayLivenessStatus::Offline,
    )
    .await;
    assert!(offline.last_attempt_unix.is_some());
    runtime.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_liveness_account_watch() {
    let dir = tempfile::tempdir().unwrap();
    let home = marmot_account::AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let app = crate::MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        crate::MarmotAppConfig::white_noise(),
    );
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let subscription = runtime
        .subscribe_relay_liveness(&alice.label)
        .await
        .unwrap();
    assert!(subscription.snapshot.is_empty());

    let mut lists = crate::AccountRelayListStatus::empty();
    lists.nip65.created_at = crate::unix_now_seconds();
    lists.nip65.relays = vec!["wss://relay.example/".into()];
    lists.nip65.read_relays = vec!["wss://read.example/path/".into()];
    lists.inbox.created_at = lists.nip65.created_at;
    lists.inbox.relays = vec!["wss://relay.example".into()];
    lists.refresh();
    app.directory()
        .remember_directory_relay_lists(&alice.account_id_hex, &lists)
        .unwrap();
    let rows = timeout(Duration::from_secs(2), subscription.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut urls = rows.iter().map(|row| row.url.as_str()).collect::<Vec<_>>();
    urls.sort_unstable();
    assert_eq!(
        urls,
        vec!["wss://read.example/path/", "wss://relay.example"]
    );
    assert!(
        rows.iter()
            .all(|row| row.status == crate::RelayLivenessStatus::Unknown
                && row.last_attempt_unix.is_none()
                && row.last_error.is_none())
    );
    assert!(
        runtime
            .account_relay_liveness(&bob.label)
            .await
            .unwrap()
            .is_empty()
    );
    // A cancelled receive must not consume the next configured-list replacement.
    {
        let receive = subscription.recv();
        tokio::pin!(receive);
        assert!(futures::poll!(receive.as_mut()).is_pending());
    }
    lists.nip65.created_at += 1;
    lists.nip65.relays = vec!["wss://replacement.example".into()];
    lists.nip65.read_relays.clear();
    lists.inbox.created_at += 1;
    lists.inbox.relays.clear();
    lists.refresh();
    app.directory()
        .remember_directory_relay_lists(&alice.account_id_hex, &lists)
        .unwrap();
    let rows = timeout(Duration::from_secs(2), subscription.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        rows.iter().map(|row| row.url.as_str()).collect::<Vec<_>>(),
        vec!["wss://replacement.example"]
    );
    runtime.shutdown().await;
    assert!(subscription.recv().await.unwrap().is_none());
}
