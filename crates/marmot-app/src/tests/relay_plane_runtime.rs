//! Tests that build a whole `MarmotApp` or runtime and drive it through the
//! relay plane. They live with the app rather than the plane, so the plane can
//! become its own crate (relay-plane brief, PR 2); they reach plane state only
//! through its `_for_test` accessors.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::transport::Timestamp;
use cgka_traits::{
    MemberId, MessageId, TransportAdapterError, TransportEndpoint, TransportEndpointFailure,
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

/// A relay client that records subscriptions and accepts nothing. A copy of
/// the relay plane's own test fake: once the plane is its own crate, its test
/// module is not visible here.
#[derive(Default)]
struct RecordingRelayClient {
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

    relay_plane.simulate_notification_lag_for_test(
        &account,
        3,
        NostrNotificationLossFloor::Since(1_700_000_000),
    );
    timeout(Duration::from_secs(5), async {
        while storage
            .recovery_loss_watermarks(
                "alice",
                storage_sqlite::RecoveryLossCause::NotificationConsumer,
            )
            .unwrap()
            .is_empty()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the worker persists the lag");
    assert_eq!(
        storage
            .recovery_loss_goal_floor(
                "alice",
                storage_sqlite::RecoveryLossCause::NotificationConsumer,
            )
            .unwrap(),
        Some(1_700_000_000)
    );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notification_loss_is_durable_and_survives_receiver_replacement() {
    use crate::tests::{ScriptedPushRelayClient, client_on_app_relay_plane};
    use storage_sqlite::RecoveryLossCause::NotificationConsumer;
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
    let storage = app.account_storage("alice").unwrap().app_storage();
    let account = client.adapter.account_id().clone();
    app.relay_plane
        .set_account_delivery_recovery_marker_for_test(
            &account,
            Arc::new(|_, _, _| panic!("notification lag must never use the queue writer")),
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
    assert!(
        storage
            .recovery_loss_watermarks("alice", NotificationConsumer)
            .unwrap()
            .is_empty()
    );
    // The real worker receive boundary persists the typed lag, bounded by
    // the REQ floor read at the lag, and the route stays open.
    assert!(matches!(
        client.receive_next_delivery().await,
        Ok(AccountDeliveryReceive::Overflow(overflow))
            if overflow.notification_token == loss.notification_token
    ));
    let evidence = storage
        .recovery_loss_watermarks("alice", NotificationConsumer)
        .unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(
        storage
            .recovery_loss_goal_floor("alice", NotificationConsumer)
            .unwrap(),
        Some(1_700_000_000)
    );
    assert!(
        storage
            .pending_recovery_demands()
            .unwrap()
            .iter()
            .any(|d| d.cause == storage_sqlite::RecoveryCause::NotificationLoss)
    );
    assert!(
        storage
            .account_delivery_recovery("alice")
            .unwrap()
            .is_none()
    );
    let prior = client.adapter.delivery_overflow_identity_for_test();
    drop(client);
    let mut replacement = client_on_app_relay_plane(&app, "alice").await;
    assert!(prior.same_as(&replacement.adapter.delivery_overflow_identity_for_test()));
    let attempt = replacement
        .adapter
        .start_delivery_overflow_recovery(loss.marker_token);
    // An unexpected consumer exit still closes the route.
    app.relay_plane
        .simulate_notification_consumer_exit_for_test();
    assert_eq!(replacement.adapter.notification_losses_for_test(), 1);
    // A lag whose control record cannot reach the closed queue, and whose
    // floor is unknown.
    app.relay_plane.simulate_notification_lag_for_test(
        &account,
        1,
        NostrNotificationLossFloor::Unbounded,
    );
    assert!(
        replacement
            .adapter
            .finish_delivery_overflow_recovery(attempt)
            .is_none()
    );
    replacement.adapter.fail_delivery_overflow_recovery();
    let newer = replacement.adapter.pending_delivery_overflow().unwrap();
    assert_eq!(newer.notification_losses, 2);
    assert_ne!(newer.notification_token, loss.notification_token);
    assert_eq!(newer.notification_floor, None);
    // Persisted without its control record, before the closed queue is seen.
    assert!(matches!(
        replacement.receive_next_delivery().await,
        Ok(AccountDeliveryReceive::Overflow(overflow))
            if overflow.notification_token == newer.notification_token
    ));
    assert_eq!(
        storage
            .recovery_loss_watermarks("alice", NotificationConsumer)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        storage
            .recovery_loss_goal_floor("alice", NotificationConsumer)
            .unwrap(),
        None,
        "an unknown floor leaves the whole goal unbounded"
    );
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

    plane.simulate_notification_lag_for_test(&account, 1, floor);
    timeout(Duration::from_secs(10), async {
        while storage
            .recovery_loss_watermarks(
                &alice.label,
                storage_sqlite::RecoveryLossCause::NotificationConsumer,
            )
            .unwrap()
            .is_empty()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the worker persists the lag");
    assert_eq!(
        storage
            .recovery_loss_goal_floor(
                &alice.label,
                storage_sqlite::RecoveryLossCause::NotificationConsumer,
            )
            .unwrap(),
        floor.since_seconds()
    );
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

/// A post-join maintenance REQ is floored at the Welcome that installed the
/// copy, so a lag while it is live still charges a bounded loss, which a
/// comparison can certify, instead of an unbounded one that parks as "history
/// may be incomplete". The Welcome here is older than every other REQ floor,
/// so the lag's floor is the maintenance REQ's own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notification_lag_while_post_join_maintenance_is_live_stays_bounded() {
    use cgka_traits::storage::{GroupStorage, MaintenanceStorage};
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
    let storage = app.account_storage(&alice.label).unwrap();
    // Other live REQs have a settled floor newer than the Welcome below.
    let mut state = app.load_state(&alice.label).unwrap();
    state.last_transport_timestamp = Some(crate::unix_now_seconds());
    app.save_state(&state).unwrap();
    let mut client = crate::tests::client_on_app_relay_plane(&app, &alice.label).await;
    client.prepare_transport().await.unwrap();
    let group = client
        .create_group_with_options(
            "maintenance lag",
            &[],
            crate::AppCreateGroupOptions {
                relays: Some(vec![url]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    // Model a copy installed from a Welcome five days old, still catching up.
    let welcome_at = crate::unix_now_seconds() - 5 * 86_400;
    let mut record = storage.get_group(&group).unwrap();
    record.local_copy_welcome_created_at = Some(Timestamp(welcome_at));
    storage.put_group(&record).unwrap();
    storage
        .put_maintenance_obligation(&cgka_traits::MaintenanceObligation {
            id: MessageId::new(vec![0x55; 32]),
            group_id: group.clone(),
            trigger: cgka_traits::MaintenanceTrigger::PostJoin,
            phase: cgka_traits::MaintenancePhase::CatchUp,
            created_at: Timestamp(crate::unix_now_seconds()),
            operational_target_at: None,
            overdue: false,
            eose_deadline_at: None,
            grace_until: None,
            quiet_since: None,
            own_leaf_baseline_hash: None,
            sampled_jitter_ms: 0,
            not_before: None,
            attempt_count: 0,
            semantic_rearm_count: 0,
            last_failure_code: None,
        })
        .unwrap();
    // Advance requests the boundary; the recovery job installs its REQ.
    client
        .advance_post_join_maintenance_subscriptions()
        .await
        .unwrap();
    let grant = client
        .authorize_account_recovery(
            None,
            marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
        )
        .await
        .unwrap()
        .unwrap();
    client.run_recovery_grant_for_test(grant).await.unwrap();
    assert!(
        client
            .post_join_maintenance_subscriptions
            .contains_key(&group),
        "the post-join maintenance REQ is live"
    );

    let plane = app.relay_plane.clone();
    let sdk = plane.sdk_relay_client_for_test().unwrap();
    let floor = sdk.notification_loss_floor_for_account(&account).await;
    assert_eq!(
        floor,
        NostrNotificationLossFloor::Since(crate::history_floor(welcome_at).0),
        "the lowest REQ floor is the maintenance REQ's Welcome floor"
    );
    plane.simulate_notification_lag_for_test(&account, 1, floor);
    assert_eq!(
        client
            .adapter
            .pending_delivery_overflow()
            .expect("the lag is pending loss")
            .notification_floor,
        Some(crate::history_floor(welcome_at).0)
    );
    plane.shutdown().await;
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

/// A member that was offline joins from a Welcome made before the group's
/// next commit. Its live group REQ resumes from the account cursor, after that
/// commit, so only the post-join maintenance REQ, floored at the Welcome, can
/// bring the commit back before the member's first self-update.
///
/// Test-policy builds settle convergence at once. A directly driven client has
/// no worker timer for the pinned quiescence window, so it needs that.
#[cfg(feature = "test-policy-overrides")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_member_post_join_catch_up_sees_the_commit_made_before_its_join() {
    use transport_nostr::MarmotRelayPlane;
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let config = || crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true);
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    marmot_account::AccountHome::open(alice_dir.path())
        .create_account("alice")
        .unwrap();
    let bob = marmot_account::AccountHome::open(bob_dir.path())
        .create_account("bob")
        .unwrap();

    // Bob publishes a KeyPackage, settles his cold-start history, and leaves.
    {
        let setup = crate::MarmotApp::with_relay_and_config(bob_dir.path(), url.clone(), config());
        let mut client = crate::tests::client_on_app_relay_plane(&setup, "bob").await;
        client.publish_key_package().await.unwrap();
        client.sync().await.unwrap();
        drop(client);
        setup.relay_plane.shutdown().await;
    }

    // Alice invites Bob, then renames the group before he is back.
    let alice_app =
        crate::MarmotApp::with_relay_and_config(alice_dir.path(), url.clone(), config());
    let mut alice = crate::tests::client_on_app_relay_plane(&alice_app, "alice").await;
    let group = alice
        .create_group_with_options(
            "before bob returns",
            &[bob.account_id_hex.as_str()],
            crate::AppCreateGroupOptions {
                relays: Some(vec![url.clone()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let rename = alice
        .update_group_profile(&group, Some("renamed while bob was away"), None)
        .await
        .unwrap();
    let renamed_at = crate::unix_now_seconds();
    let renamed_epoch = alice.runtime.group_record(&group).unwrap().epoch;
    assert!(!rename.message_ids.is_empty());

    // Bob returns with a one-second rebuild lookback and a cursor past the
    // rename, so his live REQs start after it.
    let resume_at = renamed_at + 2;
    while crate::unix_now_seconds() < resume_at + 1 {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut bob_app = crate::MarmotApp::with_relay_and_config(bob_dir.path(), url, config());
    bob_app.relay_plane =
        MarmotRelayPlane::runtime_default_with_loopback(Duration::from_secs(1), true);
    let mut state = bob_app.load_state("bob").unwrap();
    state.last_transport_timestamp = Some(resume_at);
    bob_app.save_state(&state).unwrap();
    let mut bob_client = crate::tests::client_on_app_relay_plane(&bob_app, "bob").await;
    bob_client.prepare_transport().await.unwrap();
    timeout(Duration::from_secs(20), async {
        while bob_client.runtime.group_record(&group).is_err() {
            bob_client.next_event().await.unwrap();
        }
    })
    .await
    .expect("Bob joins from the Welcome");
    let joined_epoch = bob_client.runtime.group_record(&group).unwrap().epoch;
    assert!(
        joined_epoch < renamed_epoch,
        "the Welcome predates the rename"
    );

    // Control: the live REQs, which resume after the rename, never bring it.
    while let Ok(summary) = timeout(Duration::from_millis(1_500), bob_client.next_event()).await {
        summary.unwrap();
    }
    assert_eq!(
        bob_client.runtime.group_record(&group).unwrap().epoch,
        joined_epoch,
        "no live REQ reaches back to the rename"
    );

    // The maintenance tick runs after the cold-start comparison's paced retry
    // deadline; move the owner clock there instead of waiting. Advance
    // requests the boundary; the recovery job installs its REQ.
    let bob_storage = bob_app.account_storage("bob").unwrap();
    bob_client
        .recovery_owner
        .test_advance_to_retry(&bob_storage);
    bob_client
        .advance_post_join_maintenance_subscriptions()
        .await
        .unwrap();
    let grant = bob_client
        .authorize_account_recovery(
            None,
            marmot_forensics::EpochBackfillExecutionSeam::Maintenance,
        )
        .await
        .unwrap()
        .unwrap();
    bob_client.run_recovery_grant_for_test(grant).await.unwrap();
    assert!(
        bob_client
            .post_join_maintenance_subscriptions
            .contains_key(&group)
    );
    let comparisons = bob_app
        .relay_telemetry()
        .await
        .metrics
        .reconciliation_attempts;
    timeout(Duration::from_secs(20), async {
        while bob_client.runtime.group_record(&group).unwrap().epoch < renamed_epoch {
            // Group replay is native-owned; next_event admits it only after
            // this maintenance source reaches its own relay boundary.
            bob_client.next_event().await.unwrap();
        }
    })
    .await
    .expect("the maintenance REQ admits the rename made before Bob joined");
    assert_eq!(
        bob_app
            .relay_telemetry()
            .await
            .metrics
            .reconciliation_attempts,
        comparisons,
        "no comparison stood in for the maintenance REQ"
    );
    assert_eq!(
        bob_app
            .group("bob", &hex::encode(group.as_slice()))
            .unwrap()
            .unwrap()
            .profile
            .name,
        "renamed while bob was away"
    );
    bob_app.relay_plane.shutdown().await;
    alice_app.relay_plane.shutdown().await;
}
