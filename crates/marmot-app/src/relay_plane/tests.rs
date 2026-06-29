use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use cgka_traits::transport::{TransportEnvelope, TransportMessage, TransportSource};
use cgka_traits::{
    GroupId, MessageId, TransportDeliveryPlane, TransportEndpoint, TransportEndpointFailure,
    TransportEndpointReceipt, TransportGroupSubscription,
};
use tokio::sync::Notify;
use transport_nostr_adapter::{NostrRelayEvent, NostrSubscription};
use transport_nostr_peeler::{KIND_MARMOT_GROUP_MESSAGE, NOSTR_SOURCE};

use crate::config::{RelayTelemetryResource, RelayTelemetryRuntimeConfig};

use super::*;

fn relay_telemetry_runtime_config() -> RelayTelemetryRuntimeConfig {
    RelayTelemetryRuntimeConfig {
        otlp_endpoint: Some("https://otlp.example.org/v1/metrics".to_owned()),
        authorization_bearer_token: Some("token".to_owned()),
        resource: Some(RelayTelemetryResource {
            service_version: "1.4.2".to_owned(),
            service_instance_id: "8e1ca50b-05a2-4c31-a31c-1e69c75a9366".to_owned(),
            deployment_environment: "staging".to_owned(),
            tenant: "darkmatter-ios".to_owned(),
            os_type: "ios".to_owned(),
            os_version: "17.5".to_owned(),
            device_model_identifier: None,
        }),
    }
}

#[test]
fn subscription_rebuild_since_treats_future_cursor_as_corrupted() {
    // A persisted cursor poisoned by a far-future sender-controlled
    // `created_at` must not push `since` past the present, or relays would
    // stop returning present-dated events and the account would silently
    // halt forever (darkmatter#182). A detectably-future cursor is
    // corrupted, not authoritative: rather than clamping it to
    // `now - lookback` (which would permanently skip valid backlog older
    // than the short production lookback), we treat it as untrusted and
    // request a full-history replay (`None`) so the catch-up range is never
    // dropped.
    let lookback = Duration::from_secs(30);
    let plane = MarmotRelayPlane::with_subscription_rebuild_lookback(lookback);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let poisoned = now + 10 * 365 * 24 * 60 * 60; // ~10 years in the future

    assert!(
        plane.subscription_rebuild_since(Some(poisoned)).is_none(),
        "a future (poisoned) cursor must trigger full-history replay, not a clamped future `since`"
    );
}

#[test]
fn subscription_rebuild_since_uses_trusted_past_cursor() {
    // A cursor at or behind wall-clock is trusted and used as-is: `since`
    // is the cursor minus the lookback margin.
    let lookback = Duration::from_secs(30);
    let plane = MarmotRelayPlane::with_subscription_rebuild_lookback(lookback);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let cursor = now - 10_000;

    let since = plane
        .subscription_rebuild_since(Some(cursor))
        .expect("a past cursor yields a concrete since")
        .0;

    assert_eq!(
        since,
        cursor.saturating_sub(lookback.as_secs()),
        "a trusted past cursor must produce since = cursor - lookback"
    );
    assert!(since < now, "since {since} must be in the past");
}

#[tokio::test]
async fn set_transport_signer_arms_the_sdk_client_for_nip42_auth() {
    let plane = MarmotRelayPlane::with_subscription_rebuild_lookback(Duration::from_secs(30));
    let sdk = plane
        .inner
        .transport
        .sdk_relay_client
        .as_ref()
        .expect("sdk-backed plane has a relay client");
    assert!(
        sdk.client().signer().await.is_err(),
        "a fresh plane must not have a signer"
    );

    plane.set_transport_signer(nostr::Keys::generate()).await;

    assert!(
        sdk.client().signer().await.is_ok(),
        "the transport client must hold a signer to answer NIP-42 AUTH"
    );
}

#[test]
fn account_deliveries_lock_helpers_recover_from_poisoned_guard() {
    let deliveries = RwLock::new(HashMap::new());
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = deliveries.write().unwrap();
        panic!("poison account deliveries lock");
    }));

    let (delivery_tx, _delivery_rx) = mpsc::channel(1);
    account_deliveries_write(&deliveries).insert(MemberId::new(vec![0x01; 32]), delivery_tx);

    assert_eq!(account_deliveries_read(&deliveries).len(), 1);
}

#[derive(Default)]
struct RecordingRelayClient {
    subscriptions: StdMutex<Vec<NostrSubscription>>,
    unsubscribed: StdMutex<Vec<NostrSubscription>>,
    unsubscribed_accounts: StdMutex<Vec<MemberId>>,
}

#[async_trait]
impl NostrRelayClient for RecordingRelayClient {
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

struct BlockingDirectoryFetcher {
    fetch_count: AtomicUsize,
    started: Notify,
    release: Notify,
    events: Vec<DirectoryRelayEventRecord>,
}

#[async_trait]
impl DirectoryRelayFetcher for BlockingDirectoryFetcher {
    async fn fetch_directory_events(
        &self,
        _request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        self.fetch_count.fetch_add(1, Ordering::SeqCst);
        self.started.notify_waiters();
        self.release.notified().await;
        Ok(self.events.clone())
    }
}

#[derive(Default)]
struct RecordingDirectoryFetcher {
    fetch_count: AtomicUsize,
    requests: StdMutex<Vec<DirectoryFetchRequest>>,
}

#[async_trait]
impl DirectoryRelayFetcher for RecordingDirectoryFetcher {
    async fn fetch_directory_events(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        self.fetch_count.fetch_add(1, Ordering::SeqCst);
        self.requests.lock().unwrap().push(request);
        Ok(Vec::new())
    }
}

fn relay_plane_with_directory_fetcher(
    relay: Arc<dyn NostrRelayClient>,
    directory_fetcher: Arc<dyn DirectoryRelayFetcher>,
) -> MarmotRelayPlane {
    MarmotRelayPlane::from_adapter(
        Some(Duration::from_secs(30)),
        NostrTransportAdapter::new(relay),
        None,
        None,
        directory_fetcher,
    )
}

#[tokio::test]
async fn relay_plane_rejects_invalid_relay_endpoints_before_subscribing() {
    let relay = Arc::new(RecordingRelayClient::default());
    let relay_plane = MarmotRelayPlane::new(Some(Duration::from_secs(30)), relay.clone());
    let alice = MemberId::new(vec![0xA1; 32]);
    let alice_adapter = relay_plane.account_adapter(alice.clone(), relay.clone());

    let err = alice_adapter
        .activate_account(TransportAccountActivation {
            account_id: alice,
            inbox_endpoints: vec![TransportEndpoint("https://relay.example".into())],
            group_subscriptions: Vec::new(),
            since: None,
        })
        .await
        .expect_err("invalid relay endpoint should be rejected");

    assert!(err.to_string().contains("invalid relay endpoint"));
    assert!(relay.subscriptions.lock().unwrap().is_empty());
}

#[tokio::test]
async fn relay_plane_deduplicates_canonical_relay_endpoints() {
    let relay = Arc::new(RecordingRelayClient::default());
    let relay_plane = MarmotRelayPlane::new(Some(Duration::from_secs(30)), relay.clone());
    let alice = MemberId::new(vec![0xA1; 32]);
    let group_id = GroupId::new(vec![0xC3; 32]);
    let alice_adapter = relay_plane.account_adapter(alice.clone(), relay.clone());

    alice_adapter
        .activate_account(TransportAccountActivation {
            account_id: alice,
            inbox_endpoints: vec![
                TransportEndpoint(" wss://relay.example ".into()),
                TransportEndpoint("wss://relay.example".into()),
            ],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id,
                transport_group_id: vec![0xD4; 32],
                endpoints: vec![
                    TransportEndpoint("wss://relay.example/".into()),
                    TransportEndpoint("wss://relay.example/".into()),
                ],
            }],
            since: None,
        })
        .await
        .unwrap();

    let subscriptions = relay.subscriptions.lock().unwrap().clone();
    assert!(subscriptions.iter().all(|subscription| match subscription {
        NostrSubscription::AccountInbox { endpoints, .. }
        | NostrSubscription::Group { endpoints, .. } => endpoints.len() == 1,
    }));
}

#[tokio::test]
async fn relay_telemetry_reflects_activation_through_the_plane() {
    let relay = Arc::new(RecordingRelayClient::default());
    let relay_plane = MarmotRelayPlane::new(Some(Duration::from_secs(30)), relay.clone());
    let alice = MemberId::new(vec![0xA1; 32]);
    let group_id = GroupId::new(vec![0xC3; 32]);
    let alice_adapter = relay_plane.account_adapter(alice.clone(), relay.clone());

    alice_adapter
        .activate_account(TransportAccountActivation {
            account_id: alice,
            inbox_endpoints: vec![TransportEndpoint("wss://relay.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id,
                transport_group_id: vec![0xD4; 32],
                endpoints: vec![TransportEndpoint("wss://relay.example".into())],
            }],
            since: None,
        })
        .await
        .unwrap();

    let telemetry = relay_plane.relay_telemetry().await;
    // The single shared adapter records subscription lifecycle and the
    // initial-sync gate as soon as an account activates, so the bundled
    // snapshot is populated without any relay traffic.
    assert_eq!(telemetry.metrics.active_accounts, 1);
    assert!(telemetry.metrics.subscriptions_created >= 2);
    assert!(telemetry.sync.tracked_subscriptions >= 2);
    // No SDK relay client is wired in this unit harness.
    assert!(!telemetry.health.sdk_backed);
    // No relay copies were observed, so spread stays empty (no URLs leak).
    assert_eq!(telemetry.delivery_spread.spread.sample_count(), 0);
}

#[test]
fn telemetry_rollup_reshapes_and_joins_per_relay_snapshots() {
    use transport_nostr_adapter::{HistogramBucket, RelayDeliveryStats, RelayLatencyStats};

    let hist = |count: u64| DurationHistogramSnapshot {
        buckets: vec![HistogramBucket {
            upper_bound_ms: 50,
            count,
        }],
        overflow_count: 0,
    };

    let spread = RelayDeliverySpread {
        observed: 5,
        corroborated: 4,
        single_source: 1,
        spread: hist(3),
        per_relay: vec![
            RelayDeliveryStats {
                relay_index: 0,
                delivered_first: 3,
                delivered_later: 1,
            },
            RelayDeliveryStats {
                relay_index: 1,
                delivered_first: 0,
                delivered_later: 2,
            },
        ],
    };
    let sync = RelaySyncSnapshot {
        tracked_subscriptions: 2,
        synced_subscriptions: 1,
        first_event: hist(2),
        eose: hist(2),
        per_relay: vec![
            RelayLatencyStats {
                relay_index: 0,
                first_event: hist(1),
                eose: hist(1),
            },
            RelayLatencyStats {
                relay_index: 2,
                first_event: hist(1),
                eose: hist(1),
            },
        ],
    };
    let metrics = NostrAdapterMetrics {
        publish_attempts: 4,
        publish_successes: 3,
        publish_failures: 1,
        ..NostrAdapterMetrics::default()
    };
    let health = RelayPlaneHealth {
        connection_attempts: 6,
        connection_successes: 5,
        ..RelayPlaneHealth::default()
    };

    let rollup = rollup_from_snapshots(spread, sync, metrics, health, None);

    // Union of per-relay indices {0,1,2}, ascending.
    assert_eq!(
        rollup
            .relays
            .iter()
            .map(|entry| entry.relay_index)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );

    // Index 0: both delivery and latency rows present.
    let relay0 = &rollup.relays[0];
    assert_eq!(relay0.delivery_count(), 4);
    assert_eq!(relay0.redundant_count(), 1);
    assert_eq!(relay0.first_deliverer_rate(), Some(0.75));
    assert_eq!(relay0.first_event_latency.sample_count(), 1);

    // Index 1: delivery only -> empty latency histograms.
    let relay1 = &rollup.relays[1];
    assert_eq!(relay1.delivery_count(), 2);
    assert_eq!(relay1.first_deliverer_rate(), Some(0.0));
    assert_eq!(relay1.eose_latency.sample_count(), 0);

    // Index 2: latency only -> zero delivery counts.
    let relay2 = &rollup.relays[2];
    assert_eq!(relay2.delivery_count(), 0);
    assert_eq!(relay2.first_deliverer_rate(), None);
    assert_eq!(relay2.eose_latency.sample_count(), 1);

    // Population-level and device-wide fields carry through.
    assert_eq!(rollup.cross_relay_spread.sample_count(), 3);
    assert_eq!(rollup.messages_corroborated, 4);
    assert_eq!(rollup.messages_single_source, 1);
    assert_eq!(rollup.connection_attempts, 6);
    assert_eq!(rollup.connection_successes, 5);
    assert_eq!(rollup.publish_successes, 3);
    assert_eq!(rollup.observed_reorg_rate(), None);
}

#[test]
fn rollup_observed_reorg_rate_uses_folded_engine_metrics() {
    let rollup = RelayTelemetryRollup {
        engine: Some(EngineReorgMetrics {
            settles: 8,
            post_settle_reorgs: 2,
            reorg_lateness_ms: DurationHistogramSnapshot::default(),
        }),
        ..RelayTelemetryRollup::default()
    };
    assert_eq!(rollup.observed_reorg_rate(), Some(0.25));

    // Engine present but with no settles yet: rate is undefined, not 0/0.
    let empty_engine = RelayTelemetryRollup {
        engine: Some(EngineReorgMetrics::default()),
        ..RelayTelemetryRollup::default()
    };
    assert_eq!(empty_engine.observed_reorg_rate(), None);
}

#[tokio::test]
async fn telemetry_rollup_is_empty_without_observed_relay_traffic() {
    let relay = Arc::new(RecordingRelayClient::default());
    let relay_plane = MarmotRelayPlane::new(Some(Duration::from_secs(30)), relay.clone());
    let rollup = relay_plane.telemetry_rollup(None).await;
    assert!(rollup.relays.is_empty());
    assert_eq!(rollup.cross_relay_spread.sample_count(), 0);
    assert!(rollup.engine.is_none());
}

#[tokio::test]
async fn relay_label_resolution_is_gated_behind_opt_in() {
    let relay = Arc::new(RecordingRelayClient::default());
    let relay_plane = MarmotRelayPlane::new(Some(Duration::from_secs(30)), relay.clone());
    let alice = MemberId::new(vec![0xA1; 32]);
    let endpoint = TransportEndpoint("wss://relay.example".into());
    let alice_adapter = relay_plane.account_adapter(alice.clone(), relay.clone());

    alice_adapter
        .activate_account(TransportAccountActivation {
            account_id: alice,
            inbox_endpoints: vec![endpoint.clone()],
            group_subscriptions: Vec::new(),
            since: None,
        })
        .await
        .unwrap();

    // Off by default: no opt-in means no relay-identity resolution at all.
    let disabled = RelayTelemetryExportConfig::disabled();
    assert!(relay_plane.resolve_relay_labels(&disabled).await.is_none());

    // Opted in but no endpoint: still no resolution (same gate as the
    // exporter).
    let no_endpoint = RelayTelemetryExportConfig {
        enabled: true,
        ..Default::default()
    };
    assert!(
        relay_plane
            .resolve_relay_labels(&no_endpoint)
            .await
            .is_none()
    );

    // Opted in with a TLS endpoint and runtime metadata: the export boundary
    // resolves the opaque index for the activated inbox endpoint back to its
    // relay URL.
    let enabled = RelayTelemetryExportConfig::enabled("https://otlp.example/v1/metrics")
        .with_runtime_config(relay_telemetry_runtime_config());
    let resolution = relay_plane
        .resolve_relay_labels(&enabled)
        .await
        .expect("opt-in resolves labels");
    assert!(!resolution.is_empty());
    assert!(
        resolution
            .label_for(transport_nostr_adapter::RelayIndex(0))
            .is_some()
    );
}

#[tokio::test]
async fn directory_fetches_coalesce_identical_inflight_requests() {
    let relay = Arc::new(RecordingRelayClient::default());
    let event = DirectoryRelayEventRecord {
        endpoints: vec![TransportEndpoint("wss://relay.example".into())],
        event: group_event("33", &[0x44; 32]),
    };
    let directory_fetcher = Arc::new(BlockingDirectoryFetcher {
        fetch_count: AtomicUsize::new(0),
        started: Notify::new(),
        release: Notify::new(),
        events: vec![event.clone()],
    });
    let relay_plane = relay_plane_with_directory_fetcher(relay, directory_fetcher.clone());
    let endpoints = vec![TransportEndpoint(" wss://relay.example ".into())];
    let query = DirectoryEventQuery::new(0, vec!["11".repeat(32)], 12);

    let first_plane = relay_plane.clone();
    let first_endpoints = endpoints.clone();
    let first_query = query.clone();
    let first = tokio::spawn(async move {
        first_plane
            .fetch_directory_events(first_endpoints, vec![first_query])
            .await
    });
    directory_fetcher.started.notified().await;

    let second_plane = relay_plane.clone();
    let second = tokio::spawn(async move {
        second_plane
            .fetch_directory_events(endpoints, vec![query])
            .await
    });
    tokio::task::yield_now().await;
    directory_fetcher.release.notify_waiters();

    assert_eq!(first.await.unwrap().unwrap(), vec![event.clone()]);
    assert_eq!(second.await.unwrap().unwrap(), vec![event]);
    assert_eq!(directory_fetcher.fetch_count.load(Ordering::SeqCst), 1);

    let health = relay_plane.relay_health().await;
    assert_eq!(health.directory_inflight_fetches, 0);
    assert_eq!(health.directory_completed_fetches, 1);
    assert_eq!(health.directory_coalesced_waiters, 1);
    assert_eq!(health.directory_failed_fetches, 0);
}

#[tokio::test]
async fn directory_fetch_owner_cancellation_does_not_orphan_waiters() {
    let relay = Arc::new(RecordingRelayClient::default());
    let event = DirectoryRelayEventRecord {
        endpoints: vec![TransportEndpoint("wss://relay.example".into())],
        event: group_event("44", &[0x55; 32]),
    };
    let directory_fetcher = Arc::new(BlockingDirectoryFetcher {
        fetch_count: AtomicUsize::new(0),
        started: Notify::new(),
        release: Notify::new(),
        events: vec![event.clone()],
    });
    let relay_plane = relay_plane_with_directory_fetcher(relay, directory_fetcher.clone());
    let endpoints = vec![TransportEndpoint("wss://relay.example".into())];
    let query = DirectoryEventQuery::new(0, vec!["11".repeat(32)], 12);

    let first_plane = relay_plane.clone();
    let first_endpoints = endpoints.clone();
    let first_query = query.clone();
    let first = tokio::spawn(async move {
        first_plane
            .fetch_directory_events(first_endpoints, vec![first_query])
            .await
    });
    directory_fetcher.started.notified().await;
    first.abort();

    let second_plane = relay_plane.clone();
    let second = tokio::spawn(async move {
        second_plane
            .fetch_directory_events(endpoints, vec![query])
            .await
    });
    tokio::task::yield_now().await;
    directory_fetcher.release.notify_waiters();

    assert_eq!(second.await.unwrap().unwrap(), vec![event]);
    assert_eq!(directory_fetcher.fetch_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        relay_plane.relay_health().await.directory_coalesced_waiters,
        1
    );
}

#[tokio::test]
async fn directory_fetches_reject_invalid_relay_endpoints_before_fetching() {
    let relay = Arc::new(RecordingRelayClient::default());
    let directory_fetcher = Arc::new(RecordingDirectoryFetcher::default());
    let relay_plane = relay_plane_with_directory_fetcher(relay, directory_fetcher.clone());

    let err = relay_plane
        .fetch_directory_events(
            vec![TransportEndpoint("https://relay.example".into())],
            vec![DirectoryEventQuery::new(0, vec!["11".repeat(32)], 12)],
        )
        .await
        .expect_err("invalid relay endpoint should be rejected");

    assert!(err.contains("invalid relay endpoint"));
    assert_eq!(directory_fetcher.fetch_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn group_subscriptions_remain_account_scoped_for_shared_group_routes() {
    let relay = Arc::new(RecordingRelayClient::default());
    let relay_plane = MarmotRelayPlane::new(Some(Duration::from_secs(30)), relay.clone());
    let alice = MemberId::new(vec![0xA1; 32]);
    let bob = MemberId::new(vec![0xB2; 32]);
    let group_id = GroupId::new(vec![0xC3; 32]);
    let transport_group_id = vec![0xD4; 32];
    let endpoint = TransportEndpoint("wss://relay.example".into());
    let alice_adapter = relay_plane.account_adapter(alice.clone(), relay.clone());
    let bob_adapter = relay_plane.account_adapter(bob.clone(), relay.clone());

    alice_adapter
        .activate_account(TransportAccountActivation {
            account_id: alice.clone(),
            inbox_endpoints: vec![endpoint.clone()],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: group_id.clone(),
                transport_group_id: transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
            }],
            since: Some(Timestamp(10)),
        })
        .await
        .unwrap();
    bob_adapter
        .activate_account(TransportAccountActivation {
            account_id: bob.clone(),
            inbox_endpoints: vec![endpoint.clone()],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: group_id.clone(),
                transport_group_id: transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
            }],
            since: Some(Timestamp(10)),
        })
        .await
        .unwrap();

    let subscriptions = relay.subscriptions.lock().unwrap().clone();
    let group_subscriptions = subscriptions
        .iter()
        .filter(|subscription| matches!(subscription, NostrSubscription::Group { .. }))
        .collect::<Vec<_>>();
    assert_eq!(group_subscriptions.len(), 2);
    assert!(group_subscriptions.iter().any(|subscription| matches!(
        subscription,
        NostrSubscription::Group { account_id, .. } if account_id == &alice
    )));
    assert!(group_subscriptions.iter().any(|subscription| matches!(
        subscription,
        NostrSubscription::Group { account_id, .. } if account_id == &bob
    )));
}

#[tokio::test]
async fn shared_group_event_is_delivered_to_each_matching_account_receiver() {
    let relay = Arc::new(RecordingRelayClient::default());
    let relay_plane = MarmotRelayPlane::new(Some(Duration::from_secs(30)), relay.clone());
    let alice = MemberId::new(vec![0xA1; 32]);
    let bob = MemberId::new(vec![0xB2; 32]);
    let group_id = GroupId::new(vec![0xC3; 32]);
    let transport_group_id = vec![0xD4; 32];
    let endpoint = TransportEndpoint("wss://relay.example".into());
    let alice_adapter = relay_plane.account_adapter(alice.clone(), relay.clone());
    let bob_adapter = relay_plane.account_adapter(bob.clone(), relay.clone());
    let subscription = TransportGroupSubscription {
        group_id: group_id.clone(),
        transport_group_id: transport_group_id.clone(),
        endpoints: vec![endpoint.clone()],
    };

    alice_adapter
        .activate_account(TransportAccountActivation {
            account_id: alice.clone(),
            inbox_endpoints: vec![endpoint.clone()],
            group_subscriptions: vec![subscription.clone()],
            since: None,
        })
        .await
        .unwrap();
    bob_adapter
        .activate_account(TransportAccountActivation {
            account_id: bob.clone(),
            inbox_endpoints: vec![endpoint.clone()],
            group_subscriptions: vec![subscription],
            since: None,
        })
        .await
        .unwrap();

    let delivered = relay_plane
        .handle_relay_event_for_test(NostrRelayEvent {
            endpoint,
            subscription_id: Some("group-sub".into()),
            event: group_event("11", &transport_group_id),
        })
        .await
        .unwrap();
    assert_eq!(delivered, 2);

    let alice_delivery = alice_adapter.receive().await.unwrap().unwrap();
    let bob_delivery = bob_adapter.receive().await.unwrap().unwrap();
    assert_eq!(alice_delivery.account_id, alice);
    assert_eq!(bob_delivery.account_id, bob);
    assert_eq!(alice_delivery.group_id_hint, Some(group_id.clone()));
    assert_eq!(bob_delivery.group_id_hint, Some(group_id));
    assert_eq!(alice_delivery.source.plane, TransportDeliveryPlane::Group);
    assert_eq!(bob_delivery.source.plane, TransportDeliveryPlane::Group);
}

#[tokio::test]
async fn published_group_event_is_fanned_out_to_matching_local_accounts() {
    let relay = Arc::new(RecordingRelayClient::default());
    let relay_plane = MarmotRelayPlane::new(Some(Duration::from_secs(30)), relay.clone());
    let alice = MemberId::new(vec![0xA1; 32]);
    let bob = MemberId::new(vec![0xB2; 32]);
    let group_id = GroupId::new(vec![0xC3; 32]);
    let transport_group_id = vec![0xD4; 32];
    let endpoint = TransportEndpoint("wss://relay.example".into());
    let alice_adapter = relay_plane.account_adapter(alice.clone(), relay.clone());
    let bob_adapter = relay_plane.account_adapter(bob.clone(), relay.clone());
    let subscription = TransportGroupSubscription {
        group_id: group_id.clone(),
        transport_group_id: transport_group_id.clone(),
        endpoints: vec![endpoint.clone()],
    };

    alice_adapter
        .activate_account(TransportAccountActivation {
            account_id: alice.clone(),
            inbox_endpoints: vec![endpoint.clone()],
            group_subscriptions: vec![subscription.clone()],
            since: None,
        })
        .await
        .unwrap();
    bob_adapter
        .activate_account(TransportAccountActivation {
            account_id: bob.clone(),
            inbox_endpoints: vec![endpoint.clone()],
            group_subscriptions: vec![subscription],
            since: None,
        })
        .await
        .unwrap();

    let message = group_event("33", &transport_group_id)
        .to_transport_message()
        .unwrap();
    alice_adapter
        .publish(TransportPublishRequest {
            account_id: alice,
            message: message.clone(),
            target: TransportPublishTarget::Group {
                group_id: group_id.clone(),
                transport_group_id,
                endpoints: vec![endpoint],
            },
            required_acks: 0,
        })
        .await
        .unwrap();

    let bob_delivery = bob_adapter.receive().await.unwrap().unwrap();
    assert_eq!(bob_delivery.account_id, bob);
    assert_eq!(bob_delivery.group_id_hint, Some(group_id));
    assert_eq!(bob_delivery.message, message);
    assert_eq!(
        bob_delivery.source.subscription_id.as_deref(),
        Some("local-publish")
    );
}

async fn directory_plane_with_active_subscription(
    subscription_id: &str,
    authors: Vec<String>,
    kinds: Vec<u64>,
) -> DirectoryRelayPlane {
    let directory = DirectoryRelayPlane::new(Arc::new(RecordingDirectoryFetcher::default()));
    let mut desired = HashMap::new();
    desired.insert(
        subscription_id.to_owned(),
        DirectorySubscriptionFilter::new(authors, kinds),
    );
    directory
        .replace_subscriptions(desired)
        .await
        .expect("active subscription is recorded");
    directory
}

#[tokio::test]
async fn directory_live_event_matching_active_subscription_is_accepted() {
    let author = "11".repeat(32);
    let directory = directory_plane_with_active_subscription(
        "directory_users_0_abc",
        vec![author.clone()],
        vec![0],
    )
    .await;

    assert!(
        directory
            .accepts_live_event("directory_users_0_abc", &author, 0)
            .await,
        "an event matching the active subscription id, author, and kind must be accepted"
    );
}

#[tokio::test]
async fn directory_live_event_with_unknown_subscription_id_is_rejected() {
    let author = "11".repeat(32);
    let directory = directory_plane_with_active_subscription(
        "directory_users_0_abc",
        vec![author.clone()],
        vec![0],
    )
    .await;

    assert!(
        !directory
            .accepts_live_event("directory_users_0_stale", &author, 0)
            .await,
        "an unknown/stale subscription id must be rejected even with a matching author and kind"
    );
}

#[tokio::test]
async fn directory_live_event_with_wrong_author_is_rejected() {
    let author = "11".repeat(32);
    let other_author = "22".repeat(32);
    let directory =
        directory_plane_with_active_subscription("directory_users_0_abc", vec![author], vec![0])
            .await;

    assert!(
        !directory
            .accepts_live_event("directory_users_0_abc", &other_author, 0)
            .await,
        "an author the subscription never requested must be rejected (darkmatter#709)"
    );
}

#[tokio::test]
async fn directory_live_event_with_wrong_kind_is_rejected() {
    let author = "11".repeat(32);
    let directory = directory_plane_with_active_subscription(
        "directory_users_0_abc",
        vec![author.clone()],
        vec![0],
    )
    .await;

    // Kind 3 (contact list) is the unsolicited write the issue calls out: a
    // subscription requesting only kind 0 must never admit a kind-3 event.
    assert!(
        !directory
            .accepts_live_event("directory_users_0_abc", &author, 3)
            .await,
        "a kind outside the subscription filter must be rejected (darkmatter#709)"
    );
}

#[tokio::test]
async fn directory_live_event_rejected_after_subscription_removed() {
    let author = "11".repeat(32);
    let directory = directory_plane_with_active_subscription(
        "directory_users_0_abc",
        vec![author.clone()],
        vec![0],
    )
    .await;
    directory
        .replace_subscriptions(HashMap::new())
        .await
        .expect("subscriptions can be cleared");

    assert!(
        !directory
            .accepts_live_event("directory_users_0_abc", &author, 0)
            .await,
        "once a subscription is no longer active, its events must not be admitted to the cache"
    );
}

fn group_event(id_prefix: &str, transport_group_id: &[u8]) -> NostrTransportEvent {
    NostrTransportEvent {
        id: id_prefix.repeat(32),
        pubkey: "22".repeat(32),
        created_at: 1_700_000_000,
        kind: KIND_MARMOT_GROUP_MESSAGE,
        tags: vec![vec!["h".into(), hex::encode(transport_group_id)]],
        content: "encrypted".into(),
        sig: None,
    }
}

#[test]
fn publish_report_preserves_fallback_message_id() {
    let request = TransportPublishRequest {
        account_id: MemberId::new(vec![0xA1; 32]),
        message: TransportMessage {
            id: MessageId::new(vec![0x55; 32]),
            payload: Vec::new(),
            timestamp: Timestamp(1),
            causal_deps: Vec::new(),
            source: TransportSource(NOSTR_SOURCE.into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: vec![0x11],
            },
        },
        target: cgka_traits::TransportPublishTarget::Group {
            group_id: GroupId::new(vec![0x22; 32]),
            transport_group_id: vec![0x11],
            endpoints: Vec::new(),
        },
        required_acks: 2,
    };
    let report = publish_report_from_outcome(
        NostrPublishOutcome {
            message_id: None,
            accepted: Vec::new(),
            failed: Vec::new(),
        },
        request,
    );
    assert_eq!(report.message_id.as_slice(), vec![0x55; 32].as_slice());
    assert_eq!(report.required_acks, 2);
}
