use std::collections::{HashSet, VecDeque};
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::transport::{Timestamp, TransportEnvelope};
use cgka_traits::{
    MemberId, TransportAccountActivation, TransportAdapter, TransportDeliveryPlane,
    TransportEndpoint, TransportEndpointRejectionCategory, TransportGroupSubscription,
    TransportGroupSync, TransportPublishRequest, TransportPublishTarget,
};
use nostr::nips::nip59::GiftWrapBuilder;
use nostr::prelude::{FinalizeEvent, FinalizeUnsignedEvent, Kind, RelayUrl};
use tokio::sync::{Barrier, Notify};
use transport_nostr_adapter::{
    GROUP_BATCH_ROUTES, GroupBatchRoute, NostrAcquisitionCancellation, NostrAcquisitionEnd,
    NostrAcquisitionEndpoint, NostrAcquisitionError, NostrAcquisitionRequest,
    NostrAcquisitionResult, NostrAcquisitionScope, NostrNotificationLossFloor, NostrPublishOutcome,
    NostrRelayClient, NostrRelayEvent, NostrSubscription, NostrTransportAdapter,
    RelayExportConsent, RelayIndex, ReplayCaptureOutcome, ReplayCapturePlan,
    SUBSCRIPTION_REFUSAL_REPORT_LIMIT, SubscriptionRefusal, SubscriptionRefusalDisposition,
    SubscriptionRefusalReport, SubscriptionRouteKind,
};
use transport_nostr_peeler::{KIND_MARMOT_GROUP_MESSAGE, NostrTransportEvent};

const DEFAULT_CONCURRENT_SUBSCRIBE_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
#[ignore = "unchanged subscription latency diagnostic"]
async fn unchanged_sync_latency() {
    for count in [1u32, 100, 1000] {
        let relay = Arc::new(FakeRelayClient::default());
        let adapter = NostrTransportAdapter::new(relay.clone());
        let account_id = MemberId::new(vec![0xA1; 32]);
        let groups = (0..count)
            .map(|index| TransportGroupSubscription {
                group_id: cgka_traits::GroupId::new(index.to_be_bytes().to_vec()),
                transport_group_id: [index.to_be_bytes().as_slice(), &[0; 28]].concat(),
                endpoints: vec![TransportEndpoint("wss://group.example".into())],
                retained_since: None,
            })
            .collect::<Vec<_>>();
        adapter
            .activate_account(TransportAccountActivation {
                account_id: account_id.clone(),
                inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
                group_subscriptions: groups.clone(),
                since: None,
            })
            .await
            .unwrap();
        let mut samples = Vec::new();
        for index in 0..110 {
            let request = TransportGroupSync {
                account_id: account_id.clone(),
                group_subscriptions: groups.clone(),
                since: Some(Timestamp(1_700_000_000 + index)),
            };
            let started = std::time::Instant::now();
            adapter.sync_account_groups(request).await.unwrap();
            if index >= 10 {
                samples.push(started.elapsed().as_secs_f64() * 1000.0);
            }
        }
        samples.sort_by(f64::total_cmp);
        println!(
            "groups={count} samples=100 median_ms={:.6} p95_ms={:.6}",
            samples[49], samples[94]
        );
        // The inbox plus one batch REQ per GROUP_BATCH_ROUTES groups.
        assert_eq!(
            relay.subscriptions.lock().unwrap().len(),
            (count as usize).div_ceil(GROUP_BATCH_ROUTES) + 1
        );
        assert!(relay.unsubscribed.lock().unwrap().is_empty());
    }
}

fn concurrent_subscribe_timeout() -> Duration {
    std::env::var("MARMOT_CONCURRENT_SUBSCRIBE_TEST_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_CONCURRENT_SUBSCRIBE_TIMEOUT)
}

struct ConcurrentSubscribeRelayClient {
    subscriptions: Mutex<Vec<transport_nostr_adapter::NostrSubscription>>,
    started: AtomicUsize,
    barrier: Mutex<Arc<Barrier>>,
}

impl Default for ConcurrentSubscribeRelayClient {
    fn default() -> Self {
        Self {
            subscriptions: Mutex::default(),
            started: AtomicUsize::new(0),
            barrier: Mutex::new(Arc::new(Barrier::new(1))),
        }
    }
}

impl ConcurrentSubscribeRelayClient {
    fn expect_concurrent_subscribes(&self, count: usize) {
        self.started.store(0, Ordering::SeqCst);
        *self.barrier.lock().unwrap() = Arc::new(Barrier::new(count));
    }
}

#[async_trait]
impl NostrRelayClient for ConcurrentSubscribeRelayClient {
    async fn subscribe(
        &self,
        subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.started.fetch_add(1, Ordering::SeqCst);
        let barrier = self.barrier.lock().unwrap().clone();

        tokio::time::timeout(concurrent_subscribe_timeout(), barrier.wait())
            .await
            .map_err(|_| {
                cgka_traits::TransportAdapterError::Subscription(
                    "subscription was not issued concurrently".into(),
                )
            })?;

        self.subscriptions.lock().unwrap().push(subscription);
        Ok(())
    }

    async fn unsubscribe(
        &self,
        _subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        _account_id: &MemberId,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        Ok(())
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        _event: &NostrTransportEvent,
        _required_acks: usize,
    ) -> Result<NostrPublishOutcome, cgka_traits::TransportAdapterError> {
        Ok(NostrPublishOutcome::accepted(endpoints.to_vec()))
    }
}

#[derive(Default)]
struct BlockingSubscribeRelayClient {
    block_subscribes: AtomicBool,
    started: Notify,
}

#[async_trait]
impl NostrRelayClient for BlockingSubscribeRelayClient {
    async fn subscribe(
        &self,
        _subscription: NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        if self.block_subscribes.load(Ordering::SeqCst) {
            self.started.notify_one();
            std::future::pending::<()>().await;
        }
        Ok(())
    }

    async fn unsubscribe(
        &self,
        _subscription: NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        _account_id: &MemberId,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        Ok(())
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        _event: &NostrTransportEvent,
        _required_acks: usize,
    ) -> Result<NostrPublishOutcome, cgka_traits::TransportAdapterError> {
        Ok(NostrPublishOutcome::accepted(endpoints.to_vec()))
    }
}

/// Simulates a relay holding stored events: the moment it sees a group REQ it
/// streams a matching stored event back through `handle_relay_event` for each
/// route the REQ carries, before `subscribe` returns — i.e. inside the
/// activation's subscribe window. The adapter owns the relay client, so the
/// back-reference used for the replay is attached after construction.
#[derive(Default)]
struct StoredReplayRelayClient {
    adapter: Mutex<Option<NostrTransportAdapter>>,
    additional_replay: Mutex<Option<NostrRelayEvent>>,
    replayed_deliveries: AtomicUsize,
}

impl StoredReplayRelayClient {
    fn attach(&self, adapter: &NostrTransportAdapter) {
        *self.adapter.lock().unwrap() = Some(adapter.clone());
    }

    fn replay_alongside_next_subscribe(&self, relay_event: NostrRelayEvent) {
        *self.additional_replay.lock().unwrap() = Some(relay_event);
    }
}

#[async_trait]
impl NostrRelayClient for StoredReplayRelayClient {
    async fn subscribe(
        &self,
        subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        let (transport_group_ids, endpoints) = match &subscription {
            NostrSubscription::Group {
                transport_group_id,
                endpoints,
                ..
            }
            | NostrSubscription::GroupMaintenance {
                transport_group_id,
                endpoints,
                ..
            } => (vec![transport_group_id.clone()], endpoints),
            NostrSubscription::GroupBatch {
                routes, endpoints, ..
            } => (
                routes
                    .iter()
                    .map(|route| route.transport_group_id.clone())
                    .collect(),
                endpoints,
            ),
            NostrSubscription::AccountInbox { .. } => return Ok(()),
        };
        let adapter = self
            .adapter
            .lock()
            .unwrap()
            .clone()
            .expect("adapter attached before subscribe");
        let endpoint = endpoints[0].clone();
        let subscription_id = subscription.subscription_id();
        let mut delivered = 0;
        for transport_group_id in &transport_group_ids {
            let relay_event = NostrRelayEvent {
                endpoint: endpoint.clone(),
                subscription_id: Some(subscription_id.clone()),
                event: group_event("30", transport_group_id),
            };
            adapter.observe_relay_event(&relay_event).await;
            delivered += adapter.handle_relay_event(relay_event).await?;
        }
        let additional_replay = self.additional_replay.lock().unwrap().take();
        if let Some(relay_event) = additional_replay {
            adapter.observe_relay_event(&relay_event).await;
            delivered += adapter.handle_relay_event(relay_event).await?;
        }
        self.replayed_deliveries
            .fetch_add(delivered, Ordering::SeqCst);
        adapter.handle_relay_eose(endpoint, subscription_id).await;
        Ok(())
    }

    async fn unsubscribe(
        &self,
        _subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        _account_id: &MemberId,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        Ok(())
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        _event: &NostrTransportEvent,
        _required_acks: usize,
    ) -> Result<NostrPublishOutcome, cgka_traits::TransportAdapterError> {
        Ok(NostrPublishOutcome::accepted(endpoints.to_vec()))
    }
}

/// Models the production shape the activation rollback comment admits: some
/// REQs of a failing activation already reached the relay. Records every
/// subscription it sees, then fails the group REQs while armed.
#[derive(Default)]
struct PartialFailureRelayClient {
    fail_group_subscribes: AtomicBool,
    subscriptions: Mutex<Vec<NostrSubscription>>,
}

impl PartialFailureRelayClient {
    fn take_issued_subscriptions(&self) -> Vec<NostrSubscription> {
        self.subscriptions.lock().unwrap().drain(..).collect()
    }
}

#[async_trait]
impl NostrRelayClient for PartialFailureRelayClient {
    async fn subscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.subscriptions
            .lock()
            .unwrap()
            .push(subscription.clone());
        if self.fail_group_subscribes.load(Ordering::SeqCst)
            && matches!(
                subscription,
                NostrSubscription::Group { .. }
                    | NostrSubscription::GroupBatch { .. }
                    | NostrSubscription::GroupMaintenance { .. }
            )
        {
            return Err(cgka_traits::TransportAdapterError::Subscription(
                "injected group subscribe failure".into(),
            ));
        }
        Ok(())
    }

    async fn unsubscribe(
        &self,
        _subscription: NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        _account_id: &MemberId,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        Ok(())
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        _event: &NostrTransportEvent,
        _required_acks: usize,
    ) -> Result<NostrPublishOutcome, cgka_traits::TransportAdapterError> {
        Ok(NostrPublishOutcome::accepted(endpoints.to_vec()))
    }
}

#[derive(Default)]
struct AcquisitionHold {
    captured: Notify,
    release: Notify,
    returned: Notify,
}

#[derive(Default)]
struct FakeRelayClient {
    scoped: Mutex<Vec<(String, NostrSubscription)>>,
    scoped_removed: Mutex<Vec<String>>,
    fail_scoped_remove: AtomicBool,
    pages: Mutex<VecDeque<(NostrAcquisitionEnd, Vec<NostrTransportEvent>)>>,
    retained: Mutex<Option<Vec<(MemberId, TransportEndpoint, NostrTransportEvent)>>>,
    acquisitions: Mutex<Vec<NostrAcquisitionRequest>>,
    active_acquisitions: Arc<AtomicUsize>,
    acquisition_delays: Mutex<VecDeque<Duration>>,
    acquisition_holds: Mutex<VecDeque<(TransportEndpoint, Arc<AcquisitionHold>)>>,
    hold_acquisition: AtomicBool,
    release_acquisition: Notify,
    subscriptions: Mutex<Vec<transport_nostr_adapter::NostrSubscription>>,
    unsubscribed: Mutex<Vec<transport_nostr_adapter::NostrSubscription>>,
    unsubscribed_accounts: Mutex<Vec<MemberId>>,
    published: Mutex<Vec<(Vec<TransportEndpoint>, NostrTransportEvent, usize)>>,
}

fn same_relay(a: &TransportEndpoint, b: &TransportEndpoint) -> bool {
    RelayUrl::parse(a.as_str()).expect("fixture relay URL parses")
        == RelayUrl::parse(b.as_str()).expect("fixture relay URL parses")
}

fn retained_in_scope(event: &NostrTransportEvent, scope: &NostrAcquisitionScope) -> bool {
    let matches_group = |id: &[u8; 32]| {
        event.kind == KIND_MARMOT_GROUP_MESSAGE
            && event.tags.iter().any(|tag| {
                tag.first().is_some_and(|name| name == "h")
                    && tag.get(1).is_some_and(|value| *value == hex::encode(id))
            })
    };
    match scope {
        NostrAcquisitionScope::KnownEventIds(ids) => {
            ids.iter().any(|id| event.id == hex::encode(id))
        }
        NostrAcquisitionScope::AccountInboxWindow { since, until } => {
            event.kind == 1059 && (*since..=*until).contains(&event.created_at)
        }
        NostrAcquisitionScope::GroupWindow {
            transport_group_id,
            since,
            until,
            ..
        } => matches_group(transport_group_id) && (*since..=*until).contains(&event.created_at),
        NostrAcquisitionScope::GroupsWindow {
            transport_group_ids,
            since,
            until,
        } => {
            transport_group_ids.iter().any(matches_group)
                && (*since..=*until).contains(&event.created_at)
        }
    }
}

impl FakeRelayClient {
    /// Subscriptions the adapter has actually put on the wire since the last
    /// call, in issue order. Tests read issued ids from here rather than
    /// re-deriving them from route state, because a subscription id is scoped
    /// to the activation attempt that issued it.
    fn take_issued_subscriptions(&self) -> Vec<NostrSubscription> {
        self.subscriptions.lock().unwrap().drain(..).collect()
    }
}

#[async_trait]
impl NostrRelayClient for FakeRelayClient {
    async fn acquire_history(
        &self,
        request: NostrAcquisitionRequest,
        _cancellation: NostrAcquisitionCancellation,
    ) -> Result<NostrAcquisitionResult, NostrAcquisitionError> {
        struct ActiveAcquisition(Arc<AtomicUsize>);
        impl Drop for ActiveAcquisition {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        self.active_acquisitions.fetch_add(1, Ordering::SeqCst);
        let _active = ActiveAcquisition(self.active_acquisitions.clone());
        let endpoint = request.endpoints[0].clone();
        self.acquisitions.lock().unwrap().push(request.clone());
        let delay = self.acquisition_delays.lock().unwrap().pop_front();
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        if self.hold_acquisition.load(Ordering::SeqCst) {
            self.release_acquisition.notified().await;
        }
        let page = self.pages.lock().unwrap().pop_front().or_else(|| {
            let retained = self.retained.lock().unwrap();
            let retained = retained.as_ref()?;
            let mut events = retained
                .iter()
                .filter(|(account, source, event)| {
                    *account == request.account_id
                        && same_relay(source, &endpoint)
                        && retained_in_scope(event, &request.scope)
                })
                .map(|(_, _, event)| event.clone())
                .collect::<Vec<_>>();
            events.sort_unstable_by(|a, b| (b.created_at, &b.id).cmp(&(a.created_at, &a.id)));
            Some((NostrAcquisitionEnd::RequestPolicySatisfied, events))
        });
        let Some((end, events)) = page else {
            return Err(NostrAcquisitionError::Unsupported);
        };
        let hold = {
            let mut holds = self.acquisition_holds.lock().unwrap();
            holds
                .iter()
                .position(|(source, _)| same_relay(source, &endpoint))
                .and_then(|index| holds.remove(index))
                .map(|(_, hold)| hold)
        };
        if let Some(hold) = hold {
            struct HeldSnapshot(Arc<AcquisitionHold>);
            impl Drop for HeldSnapshot {
                fn drop(&mut self) {
                    self.0.returned.notify_one();
                }
            }
            let _snapshot = HeldSnapshot(hold.clone());
            hold.captured.notify_one();
            hold.release.notified().await;
        }
        Ok(NostrAcquisitionResult {
            endpoints: vec![NostrAcquisitionEndpoint {
                endpoint,
                session_generation: None,
                stats: transport_nostr_adapter::NostrAcquisitionStats {
                    received_items: events.len(),
                    ..Default::default()
                },
                events,
                end,
            }],
        })
    }

    async fn publish_event_for_account(
        &self,
        _account_id: &MemberId,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, cgka_traits::TransportAdapterError> {
        self.publish_event(endpoints, event, required_acks).await
    }

    fn supports_scoped_subscriptions(&self) -> bool {
        true
    }
    async fn subscribe_scoped(
        &self,
        subscription: NostrSubscription,
        id: String,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.subscriptions
            .lock()
            .unwrap()
            .push(subscription.clone());
        self.scoped.lock().unwrap().push((id, subscription));
        Ok(())
    }
    async fn unsubscribe_scoped(
        &self,
        _subscription: NostrSubscription,
        id: String,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        if self.fail_scoped_remove.swap(false, Ordering::SeqCst) {
            return Err(cgka_traits::TransportAdapterError::Subscription(
                "injected teardown failure".into(),
            ));
        }
        self.scoped_removed.lock().unwrap().push(id);
        Ok(())
    }

    async fn subscribe(
        &self,
        subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.subscriptions.lock().unwrap().push(subscription);
        Ok(())
    }

    async fn unsubscribe(
        &self,
        subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.unsubscribed.lock().unwrap().push(subscription);
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        account_id: &MemberId,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.unsubscribed_accounts
            .lock()
            .unwrap()
            .push(account_id.clone());
        Ok(())
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, cgka_traits::TransportAdapterError> {
        self.published
            .lock()
            .unwrap()
            .push((endpoints.to_vec(), event.clone(), required_acks));
        Ok(NostrPublishOutcome::accepted(endpoints.to_vec()))
    }
}

struct FlakySubscribeRelayClient {
    fail_subscribes: AtomicBool,
    subscriptions: Mutex<Vec<NostrSubscription>>,
    unsubscribed_accounts: Mutex<Vec<MemberId>>,
}

impl Default for FlakySubscribeRelayClient {
    fn default() -> Self {
        Self {
            fail_subscribes: AtomicBool::new(true),
            subscriptions: Mutex::default(),
            unsubscribed_accounts: Mutex::default(),
        }
    }
}

#[async_trait]
impl NostrRelayClient for FlakySubscribeRelayClient {
    async fn subscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        if self.fail_subscribes.load(Ordering::SeqCst) {
            return Err(cgka_traits::TransportAdapterError::Subscription(
                "injected subscribe failure".into(),
            ));
        }
        self.subscriptions.lock().unwrap().push(subscription);
        Ok(())
    }

    async fn unsubscribe(
        &self,
        _subscription: NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        account_id: &MemberId,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.unsubscribed_accounts
            .lock()
            .unwrap()
            .push(account_id.clone());
        Ok(())
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        _event: &NostrTransportEvent,
        _required_acks: usize,
    ) -> Result<NostrPublishOutcome, cgka_traits::TransportAdapterError> {
        Ok(NostrPublishOutcome::accepted(endpoints.to_vec()))
    }
}

/// Like [`FakeRelayClient`], but `unsubscribe` fails (without recording) while
/// `fail_next_unsubscribes` decrements to zero, then records and succeeds.
#[derive(Default)]
struct FlakyUnsubscribeRelayClient {
    subscriptions: Mutex<Vec<transport_nostr_adapter::NostrSubscription>>,
    unsubscribed: Mutex<Vec<transport_nostr_adapter::NostrSubscription>>,
    unsubscribed_accounts: Mutex<Vec<MemberId>>,
    fail_next_unsubscribes: AtomicUsize,
}

#[async_trait]
impl NostrRelayClient for FlakyUnsubscribeRelayClient {
    async fn subscribe(
        &self,
        subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.subscriptions.lock().unwrap().push(subscription);
        Ok(())
    }

    async fn unsubscribe(
        &self,
        subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        if self
            .fail_next_unsubscribes
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |armed| {
                armed.checked_sub(1)
            })
            .is_ok()
        {
            return Err(cgka_traits::TransportAdapterError::Subscription(
                "injected unsubscribe failure".into(),
            ));
        }
        self.unsubscribed.lock().unwrap().push(subscription);
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        account_id: &MemberId,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.unsubscribed_accounts
            .lock()
            .unwrap()
            .push(account_id.clone());
        Ok(())
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        _event: &NostrTransportEvent,
        _required_acks: usize,
    ) -> Result<NostrPublishOutcome, cgka_traits::TransportAdapterError> {
        Ok(NostrPublishOutcome::accepted(endpoints.to_vec()))
    }
}

/// Like [`FakeRelayClient`], but `unsubscribe` blocks on the call numbered by
/// `block_on_call` (0 disables blocking). `unsubscribe_entered` increments when
/// each `unsubscribe` call begins.
#[derive(Default)]
struct BlockingUnsubscribeRelayClient {
    subscriptions: Mutex<Vec<transport_nostr_adapter::NostrSubscription>>,
    unsubscribed: Mutex<Vec<transport_nostr_adapter::NostrSubscription>>,
    unsubscribed_accounts: Mutex<Vec<MemberId>>,
    /// 1-based call index to block on; 0 means never block.
    block_on_call: AtomicUsize,
    unsubscribe_entered: AtomicUsize,
    unsubscribe_release: Notify,
}

impl BlockingUnsubscribeRelayClient {
    fn release_blocked_unsubscribe(&self) {
        self.block_on_call.store(0, Ordering::SeqCst);
        self.unsubscribe_release.notify_one();
    }
}

#[async_trait]
impl NostrRelayClient for BlockingUnsubscribeRelayClient {
    async fn subscribe(
        &self,
        subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.subscriptions.lock().unwrap().push(subscription);
        Ok(())
    }

    async fn unsubscribe(
        &self,
        subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        let call = self.unsubscribe_entered.fetch_add(1, Ordering::SeqCst) + 1;
        loop {
            let released = self.unsubscribe_release.notified();
            if self.block_on_call.load(Ordering::SeqCst) != call {
                break;
            }
            released.await;
        }
        self.unsubscribed.lock().unwrap().push(subscription);
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        account_id: &MemberId,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.unsubscribed_accounts
            .lock()
            .unwrap()
            .push(account_id.clone());
        Ok(())
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        _event: &NostrTransportEvent,
        _required_acks: usize,
    ) -> Result<NostrPublishOutcome, cgka_traits::TransportAdapterError> {
        Ok(NostrPublishOutcome::accepted(endpoints.to_vec()))
    }
}

/// Records the maximum number of `unsubscribe` calls observed in flight at
/// once. Each `unsubscribe` yields several times so that, absent serialization,
/// a concurrent lifecycle op's `unsubscribe` would be seen overlapping.
#[derive(Default)]
struct UnsubscribeOverlapProbeRelayClient {
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    subscriptions: Mutex<Vec<transport_nostr_adapter::NostrSubscription>>,
}

#[async_trait]
impl NostrRelayClient for UnsubscribeOverlapProbeRelayClient {
    async fn subscribe(
        &self,
        subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        self.subscriptions.lock().unwrap().push(subscription);
        Ok(())
    }

    async fn unsubscribe(
        &self,
        _subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        _account_id: &MemberId,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        Ok(())
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        _event: &NostrTransportEvent,
        _required_acks: usize,
    ) -> Result<NostrPublishOutcome, cgka_traits::TransportAdapterError> {
        Ok(NostrPublishOutcome::accepted(endpoints.to_vec()))
    }
}

/// Regression for the unsubscribe/re-add race: two group syncs on different
/// accounts, run concurrently, each remove their account's group and so each
/// drives an `unsubscribe`. The subscription-lifecycle lock must serialize
/// them, so the relay never sees two `unsubscribe` calls overlapping — the
/// window in which a concurrent re-add could tear down a freshly re-subscribed
/// deterministic subscription id.
#[tokio::test]
async fn concurrent_group_syncs_do_not_overlap_relay_unsubscribes() {
    let relay = Arc::new(UnsubscribeOverlapProbeRelayClient::default());
    let adapter = Arc::new(NostrTransportAdapter::new(relay.clone()));

    let alice = MemberId::new(vec![0xA1; 32]);
    let bob = MemberId::new(vec![0xB2; 32]);
    let alice_group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![0xC1; 32]),
        transport_group_id: vec![0xD1; 32],
        endpoints: vec![TransportEndpoint("wss://group-a.example".into())],
        retained_since: None,
    };
    let bob_group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![0xC2; 32]),
        transport_group_id: vec![0xD2; 32],
        endpoints: vec![TransportEndpoint("wss://group-b.example".into())],
        retained_since: None,
    };

    adapter
        .activate_account(TransportAccountActivation {
            account_id: alice.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://alice-inbox.example".into())],
            group_subscriptions: vec![alice_group],
            since: None,
        })
        .await
        .expect("alice activation succeeds");
    adapter
        .activate_account(TransportAccountActivation {
            account_id: bob.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://bob-inbox.example".into())],
            group_subscriptions: vec![bob_group],
            since: None,
        })
        .await
        .expect("bob activation succeeds");

    // Each sync drops its account's only group, so each drains one unsubscribe.
    let adapter_a = Arc::clone(&adapter);
    let adapter_b = Arc::clone(&adapter);
    let sync_a = tokio::spawn(async move {
        adapter_a
            .sync_account_groups(TransportGroupSync {
                account_id: alice,
                group_subscriptions: vec![],
                since: None,
            })
            .await
    });
    let sync_b = tokio::spawn(async move {
        adapter_b
            .sync_account_groups(TransportGroupSync {
                account_id: bob,
                group_subscriptions: vec![],
                since: None,
            })
            .await
    });
    sync_a.await.unwrap().expect("alice sync succeeds");
    sync_b.await.unwrap().expect("bob sync succeeds");

    assert_eq!(
        relay.max_in_flight.load(Ordering::SeqCst),
        1,
        "subscription-lifecycle ops must not run relay unsubscribes concurrently"
    );
    assert_eq!(
        adapter.metrics().await.subscriptions_removed,
        2,
        "both group unsubscribes should have been confirmed"
    );
}

#[tokio::test]
async fn group_replay_fans_out() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let alice = MemberId::new(vec![0xA1; 32]);
    let bob = MemberId::new(vec![0xB2; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xC3; 32]);
    let transport_group_id = vec![0xD4; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());
    let subscription = TransportGroupSubscription {
        group_id: group_id.clone(),
        transport_group_id: transport_group_id.clone(),
        endpoints: vec![endpoint.clone()],
        retained_since: None,
    };

    adapter
        .activate_account(TransportAccountActivation {
            account_id: alice.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://alice-inbox.example".into())],
            group_subscriptions: vec![subscription.clone()],
            since: None,
        })
        .await
        .expect("alice activation succeeds");
    adapter
        .activate_account(TransportAccountActivation {
            account_id: bob.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://bob-inbox.example".into())],
            group_subscriptions: vec![subscription.clone()],
            since: None,
        })
        .await
        .expect("bob activation succeeds");

    let alice_subscription_id = group_subscription_id(&adapter, &alice, &subscription).await;
    let bob_subscription_id = group_subscription_id(&adapter, &bob, &subscription).await;

    let delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: endpoint.clone(),
            subscription_id: Some(alice_subscription_id.clone()),
            event: group_event("20", &transport_group_id),
        })
        .await
        .expect("relay event handled");

    assert_eq!(delivered, 2);
    adapter
        .handle_relay_eose(endpoint.clone(), alice_subscription_id)
        .await;
    adapter
        .handle_relay_eose(endpoint.clone(), bob_subscription_id.clone())
        .await;
    let first = adapter.receive().await.unwrap().unwrap();
    let second = adapter.receive().await.unwrap().unwrap();
    let accounts = [first.account_id.clone(), second.account_id.clone()];
    assert!(accounts.contains(&alice));
    assert!(accounts.contains(&bob));
    assert_eq!(first.group_id_hint, Some(group_id.clone()));
    assert_eq!(second.group_id_hint, Some(group_id));
    assert_eq!(first.message.timestamp, Timestamp(1_700_000_010));
    assert_eq!(second.message.timestamp, Timestamp(1_700_000_010));
    assert_eq!(first.received_at, second.received_at);
    assert_ne!(first.received_at, first.message.timestamp);
}

#[tokio::test]
async fn reconciled_group_event_routes_only_to_the_compared_account() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let alice = MemberId::new(vec![0xA1; 32]);
    let bob = MemberId::new(vec![0xB2; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xC3; 32]);
    let transport_group_id = vec![0xD4; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());
    let subscription = TransportGroupSubscription {
        group_id: group_id.clone(),
        transport_group_id: transport_group_id.clone(),
        endpoints: vec![endpoint.clone()],
        retained_since: None,
    };

    for account_id in [alice, bob.clone()] {
        adapter
            .activate_account(TransportAccountActivation {
                account_id,
                inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
                group_subscriptions: vec![subscription.clone()],
                since: None,
            })
            .await
            .expect("account activation succeeds");
    }

    let delivered = adapter
        .handle_reconciled_event(
            &bob,
            NostrRelayEvent {
                endpoint,
                subscription_id: None,
                event: group_event("reconciled", &transport_group_id),
            },
        )
        .await
        .expect("reconciled event handled");

    assert_eq!(delivered, 1);
    let delivery = adapter.receive().await.unwrap().unwrap();
    assert_eq!(delivery.account_id, bob);
    assert_eq!(delivery.group_id_hint, Some(group_id));
    assert!(
        tokio::time::timeout(Duration::from_millis(10), adapter.receive())
            .await
            .is_err(),
        "another account sharing the route must not receive this account's reconciliation replay"
    );
}

#[tokio::test]
async fn activate_account_issues_inbox_and_group_subscriptions_concurrently() {
    let relay = Arc::new(ConcurrentSubscribeRelayClient::default());
    relay.expect_concurrent_subscribes(2);
    let adapter = NostrTransportAdapter::new(relay.clone());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: MemberId::new(vec![0xA1; 32]),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: cgka_traits::GroupId::new(vec![0xC3; 32]),
                transport_group_id: vec![0xD4; 32],
                endpoints: vec![TransportEndpoint("wss://group.example".into())],
                retained_since: None,
            }],
            since: None,
        })
        .await
        .expect("activation subscriptions are issued concurrently");

    assert_eq!(relay.started.load(Ordering::SeqCst), 2);
    assert_eq!(relay.subscriptions.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn failed_activation_rolls_back_routes_and_can_retry() {
    let relay = Arc::new(FlakySubscribeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let activation = TransportAccountActivation {
        account_id: account_id.clone(),
        inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
        group_subscriptions: vec![TransportGroupSubscription {
            group_id: cgka_traits::GroupId::new(vec![0xC3; 32]),
            transport_group_id: vec![0xD4; 32],
            endpoints: vec![TransportEndpoint("wss://group.example".into())],
            retained_since: None,
        }],
        since: None,
    };

    adapter
        .activate_account(activation.clone())
        .await
        .expect_err("the first activation should fail");
    let metrics = adapter.metrics().await;
    assert_eq!(metrics.active_accounts, 0);
    assert_eq!(metrics.active_group_subscriptions, 0);
    assert_eq!(
        relay.unsubscribed_accounts.lock().unwrap().as_slice(),
        &[account_id.clone(), account_id],
        "every activation opens with a blanket teardown; the rollback adds its own"
    );

    relay.fail_subscribes.store(false, Ordering::SeqCst);
    adapter
        .activate_account(activation)
        .await
        .expect("retry should activate the account cleanly");
    let metrics = adapter.metrics().await;
    assert_eq!(metrics.active_accounts, 1);
    assert_eq!(metrics.active_group_subscriptions, 1);
    assert_eq!(relay.subscriptions.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn sync_account_groups_issues_added_group_subscriptions_concurrently() {
    let relay = Arc::new(ConcurrentSubscribeRelayClient::default());
    relay.expect_concurrent_subscribes(1);
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .expect("activation succeeds");

    relay.expect_concurrent_subscribes(2);
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id,
            group_subscriptions: vec![
                TransportGroupSubscription {
                    group_id: cgka_traits::GroupId::new(vec![0xC3; 32]),
                    transport_group_id: vec![0xD4; 32],
                    endpoints: vec![TransportEndpoint("wss://group-one.example".into())],
                    retained_since: None,
                },
                TransportGroupSubscription {
                    group_id: cgka_traits::GroupId::new(vec![0xE5; 32]),
                    transport_group_id: vec![0xF6; 32],
                    endpoints: vec![TransportEndpoint("wss://group-two.example".into())],
                    retained_since: None,
                },
            ],
            since: None,
        })
        .await
        .expect("group sync subscriptions are issued concurrently");

    assert_eq!(relay.started.load(Ordering::SeqCst), 2);
    assert_eq!(relay.subscriptions.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn subscribed_group_event_becomes_account_scoped_delivery() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let transport_group_id = vec![0xC3; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: group_id.clone(),
                transport_group_id: transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
                retained_since: None,
            }],
            since: Some(Timestamp(1_700_000_000)),
        })
        .await
        .expect("activation succeeds");

    let event = group_event("11", &transport_group_id);

    let delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: endpoint.clone(),
            subscription_id: Some("group-sub".into()),
            event,
        })
        .await
        .expect("relay event handled");

    assert_eq!(delivered, 1);
    let delivery = adapter
        .receive()
        .await
        .expect("receive succeeds")
        .expect("delivery available");

    assert_eq!(delivery.account_id, account_id);
    assert_eq!(delivery.group_id_hint, Some(group_id));
    assert_eq!(delivery.source.plane, TransportDeliveryPlane::Group);
    assert_eq!(delivery.source.endpoint, Some(endpoint));
    assert_eq!(
        delivery.source.subscription_id.as_deref(),
        Some("group-sub")
    );
    assert_eq!(
        delivery.message.envelope,
        TransportEnvelope::GroupMessage { transport_group_id }
    );
}

// Regression for the cold-boot catch-up race: a relay may stream stored events
// the moment a REQ is issued, so a stored group event can arrive inside
// `activate_account`'s subscribe window. Routing state must already cover the
// account by then; an event arriving before the routes exist is dropped as
// unroutable, and that stored history is lost — nothing re-requests it.
#[tokio::test]
async fn stored_event_replayed_during_activation_subscribe_is_delivered() {
    let relay = Arc::new(StoredReplayRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    relay.attach(&adapter);
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let transport_group_id = vec![0xC3; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: group_id.clone(),
                transport_group_id: transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
                retained_since: None,
            }],
            since: Some(Timestamp(1_700_000_000)),
        })
        .await
        .expect("activation succeeds");

    assert_eq!(
        relay.replayed_deliveries.load(Ordering::SeqCst),
        1,
        "the stored event replayed during subscribe must route to the account"
    );
    let delivery = adapter
        .receive()
        .await
        .expect("receive succeeds")
        .expect("delivery available");
    assert_eq!(delivery.account_id, account_id);
    assert_eq!(delivery.group_id_hint, Some(group_id));
    assert_eq!(delivery.source.plane, TransportDeliveryPlane::Group);
    assert_eq!(delivery.source.endpoint, Some(endpoint));
    assert_eq!(
        delivery.message.envelope,
        TransportEnvelope::GroupMessage { transport_group_id }
    );
}

// Regression for mdk#910: group-sync REQs must not outrun routing and telemetry
// registration. A relay can replay stored events synchronously from subscribe;
// both the newly-added and still-live old routes must remain deliverable inside
// that window, and the new route must contribute first-event timing.
#[tokio::test]
async fn stored_events_replayed_during_group_sync_subscribe_are_delivered() {
    let relay = Arc::new(StoredReplayRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    relay.attach(&adapter);
    let account_id = MemberId::new(vec![0xA1; 32]);
    let old_group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let old_transport_group_id = vec![0xC3; 32];
    let new_group_id = cgka_traits::GroupId::new(vec![0xD4; 32]);
    let new_transport_group_id = vec![0xE5; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .expect("activation succeeds");
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id: account_id.clone(),
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: old_group_id.clone(),
                transport_group_id: old_transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
                retained_since: None,
            }],
            since: Some(Timestamp(1_700_000_000)),
        })
        .await
        .expect("initial group sync succeeds");
    let initial_delivery = adapter.receive().await.unwrap().unwrap();
    assert_eq!(initial_delivery.group_id_hint, Some(old_group_id.clone()));
    adapter
        .ack_replay_delivery(&account_id, &initial_delivery.message.id)
        .await;
    relay.replayed_deliveries.store(0, Ordering::SeqCst);
    relay.replay_alongside_next_subscribe(NostrRelayEvent {
        endpoint: endpoint.clone(),
        subscription_id: Some("still-live-old-group-sub".into()),
        event: group_event("31", &old_transport_group_id),
    });

    adapter
        .sync_account_groups(TransportGroupSync {
            account_id: account_id.clone(),
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: new_group_id.clone(),
                transport_group_id: new_transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
                retained_since: None,
            }],
            since: Some(Timestamp(1_700_000_100)),
        })
        .await
        .expect("replacement group sync succeeds");
    let deliveries = [
        adapter.receive().await.unwrap().unwrap(),
        adapter.receive().await.unwrap().unwrap(),
    ];
    let new_delivery = deliveries
        .iter()
        .find(|delivery| delivery.group_id_hint.as_ref() == Some(&new_group_id))
        .expect("the new route's catch-up is delivered");
    let old_delivery = deliveries
        .iter()
        .find(|delivery| delivery.group_id_hint.as_ref() == Some(&old_group_id))
        .expect("the old route stays deliverable while its replacement subscribes");
    assert_eq!(new_delivery.account_id, account_id);
    assert_eq!(new_delivery.source.plane, TransportDeliveryPlane::Group);
    assert_eq!(new_delivery.source.endpoint, Some(endpoint.clone()));
    assert_eq!(
        new_delivery.message.envelope,
        TransportEnvelope::GroupMessage {
            transport_group_id: new_transport_group_id
        }
    );
    assert_eq!(old_delivery.source.endpoint, Some(endpoint));
    assert_eq!(
        old_delivery.message.envelope,
        TransportEnvelope::GroupMessage {
            transport_group_id: old_transport_group_id
        }
    );
    for delivery in &deliveries {
        adapter
            .ack_replay_delivery(&account_id, &delivery.message.id)
            .await;
    }
    let coverage = adapter.account_subscription_eose(&account_id).await;
    assert_eq!((coverage.subscriptions, coverage.with_eose), (2, 1));
    let sync = adapter.relay_sync().await;
    assert_eq!(sync.tracked_subscriptions, 2);
    assert_eq!(sync.first_event.sample_count(), 2);
}

#[tokio::test]
async fn reissued_live_subscription_keeps_synchronous_callbacks() {
    let relay = Arc::new(StoredReplayRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    relay.attach(&adapter);
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let old_transport_group_id = vec![0xC3; 32];
    let new_transport_group_id = vec![0xD4; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());
    let old_group = TransportGroupSubscription {
        group_id: group_id.clone(),
        transport_group_id: old_transport_group_id.clone(),
        endpoints: vec![endpoint.clone()],
        retained_since: None,
    };

    // Floored, so the sync that retains the old route widens it to a full
    // backfill (its switch time is unknown) and reissues it.
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![old_group.clone()],
            since: Some(Timestamp(1_700_000_000)),
        })
        .await
        .expect("activation succeeds");
    let initial = adapter.receive().await.unwrap().unwrap();
    assert_eq!(initial.account_id, account_id);
    assert_eq!(initial.group_id_hint, Some(group_id.clone()));
    assert_eq!(initial.source.endpoint, Some(endpoint.clone()));
    assert_eq!(
        initial.message.id,
        cgka_traits::MessageId::new(
            hex::decode(group_event("30", &old_transport_group_id).id).unwrap()
        )
    );
    adapter
        .ack_replay_delivery(&account_id, &initial.message.id)
        .await;

    adapter
        .sync_account_groups(TransportGroupSync {
            account_id: account_id.clone(),
            group_subscriptions: vec![
                TransportGroupSubscription {
                    group_id: group_id.clone(),
                    transport_group_id: new_transport_group_id.clone(),
                    endpoints: vec![endpoint.clone()],
                    retained_since: None,
                },
                old_group,
            ],
            since: Some(Timestamp(1_700_000_000)),
        })
        .await
        .expect("group sync succeeds");

    // Both routes replay synchronously inside subscribe. Place their exact
    // deliveries before asking whether each request's history was admitted.
    let mut expected_routes = HashSet::from([
        old_transport_group_id.clone(),
        new_transport_group_id.clone(),
    ]);
    for _ in 0..2 {
        let delivery = adapter.receive().await.unwrap().unwrap();
        assert_eq!(delivery.account_id, account_id);
        assert_eq!(delivery.group_id_hint, Some(group_id.clone()));
        assert_eq!(delivery.source.plane, TransportDeliveryPlane::Group);
        assert_eq!(delivery.source.endpoint, Some(endpoint.clone()));
        let TransportEnvelope::GroupMessage { transport_group_id } = &delivery.message.envelope
        else {
            panic!("the synchronous replay must deliver a group message");
        };
        assert!(expected_routes.remove(transport_group_id));
        assert_eq!(
            delivery.message.id,
            cgka_traits::MessageId::new(
                hex::decode(group_event("30", transport_group_id).id).unwrap()
            )
        );
        adapter
            .ack_replay_delivery(&account_id, &delivery.message.id)
            .await;
    }
    assert!(expected_routes.is_empty());
    let old_subscription_id = adapter
        .group_route_subscription_id(&account_id, &old_transport_group_id)
        .await
        .expect("a live batch carries the old route");
    let new_subscription_id = adapter
        .group_route_subscription_id(&account_id, &new_transport_group_id)
        .await
        .expect("a live batch carries the new route");
    assert_eq!(
        adapter.subscription_synced(&old_subscription_id).await,
        Some(true),
        "the widening batch must retain EOSE observed before subscribe returned"
    );
    assert_eq!(
        adapter.subscription_synced(&new_subscription_id).await,
        Some(true)
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(25), adapter.receive())
            .await
            .is_err(),
        "each synchronous route replay is delivered exactly once"
    );
}

#[tokio::test]
async fn failed_group_sync_rolls_back_staged_routes_and_telemetry() {
    let relay = Arc::new(FlakySubscribeRelayClient::default());
    relay.fail_subscribes.store(false, Ordering::SeqCst);
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let old_transport_group_id = vec![0xC3; 32];
    let new_transport_group_id = vec![0xE5; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());
    let old_group = TransportGroupSubscription {
        group_id: group_id.clone(),
        transport_group_id: old_transport_group_id.clone(),
        endpoints: vec![endpoint.clone()],
        retained_since: None,
    };
    let group_sync = TransportGroupSync {
        account_id: account_id.clone(),
        group_subscriptions: vec![
            TransportGroupSubscription {
                group_id: group_id.clone(),
                transport_group_id: new_transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
                retained_since: None,
            },
            old_group.clone(),
        ],
        since: None,
    };

    // Floored, so the sync that retains the old route widens it to a full
    // backfill (its switch time is unknown) and reissues it.
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![old_group],
            since: Some(Timestamp(1_700_000_000)),
        })
        .await
        .expect("activation succeeds");
    let old_subscription_id = adapter
        .group_route_subscription_id(&account_id, &old_transport_group_id)
        .await
        .expect("a live batch carries the old route");
    adapter
        .handle_relay_eose(endpoint.clone(), old_subscription_id.clone())
        .await;
    assert_eq!(
        adapter.subscription_synced(&old_subscription_id).await,
        Some(true)
    );
    let relay_sync_before_failure = adapter.relay_sync().await;

    relay.fail_subscribes.store(true, Ordering::SeqCst);
    adapter
        .sync_account_groups(group_sync.clone())
        .await
        .expect_err("group sync fails when relay subscribe fails");

    let metrics = adapter.metrics().await;
    assert_eq!(metrics.active_group_subscriptions, 1);
    assert_eq!(metrics.subscriptions_created, 2);
    assert_eq!(adapter.relay_sync().await, relay_sync_before_failure);
    let old_delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: endpoint.clone(),
            subscription_id: Some(old_subscription_id),
            event: group_event("31", &old_transport_group_id),
        })
        .await
        .expect("old relay event handled");
    let failed_new_delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: endpoint.clone(),
            subscription_id: Some("failed-new-group-sub".into()),
            event: group_event("32", &new_transport_group_id),
        })
        .await
        .expect("new relay event handled");
    assert_eq!(old_delivered, 1, "failed sync must restore the old route");
    assert_eq!(
        failed_new_delivered, 0,
        "failed sync must not leave the staged route"
    );
    let delivery = adapter.receive().await.unwrap().unwrap();
    assert_eq!(delivery.group_id_hint, Some(group_id.clone()));

    relay.fail_subscribes.store(false, Ordering::SeqCst);
    adapter
        .sync_account_groups(group_sync)
        .await
        .expect("retry succeeds from the prior group set");
    // The retry repacks the new route and the widened old route, which share
    // a relay and a floor, into one batch, and closes the activation's batch.
    let metrics = adapter.metrics().await;
    assert_eq!(metrics.active_group_subscriptions, 2);
    assert_eq!(metrics.subscriptions_created, 3);
    assert_eq!(metrics.subscriptions_removed, 1);
    assert_eq!(adapter.relay_sync().await.tracked_subscriptions, 2);
    let delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint,
            subscription_id: Some("retried-group-sub".into()),
            event: group_event("33", &new_transport_group_id),
        })
        .await
        .expect("relay event handled");
    assert_eq!(delivered, 1);
    let delivery = adapter.receive().await.unwrap().unwrap();
    assert_eq!(delivery.account_id, account_id);
    assert_eq!(delivery.group_id_hint, Some(group_id));
}

#[tokio::test]
async fn cancelled_group_sync_rolls_back_staged_routes_and_telemetry() {
    let relay = Arc::new(BlockingSubscribeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let old_group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let old_transport_group_id = vec![0xC3; 32];
    let new_group_id = cgka_traits::GroupId::new(vec![0xD4; 32]);
    let new_transport_group_id = vec![0xE5; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());
    let old_group = TransportGroupSubscription {
        group_id: old_group_id.clone(),
        transport_group_id: old_transport_group_id.clone(),
        endpoints: vec![endpoint.clone()],
        retained_since: None,
    };

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![old_group.clone()],
            since: None,
        })
        .await
        .expect("activation succeeds");
    let old_subscription_id = group_subscription_id(&adapter, &account_id, &old_group).await;
    let relay_sync_before = adapter.relay_sync().await;
    // The sync repacks its one route into batch 1, after the activation's
    // batch 0.
    let new_subscription_id =
        batch_subscription_id(&adapter, &account_id, std::slice::from_ref(&endpoint), 1).await;

    relay.block_subscribes.store(true, Ordering::SeqCst);
    let cancelled_sync = tokio::spawn({
        let adapter = adapter.clone();
        let account_id = account_id.clone();
        let endpoint = endpoint.clone();
        let new_group_id = new_group_id.clone();
        let new_transport_group_id = new_transport_group_id.clone();
        async move {
            adapter
                .sync_account_groups(TransportGroupSync {
                    account_id,
                    group_subscriptions: vec![TransportGroupSubscription {
                        group_id: new_group_id,
                        transport_group_id: new_transport_group_id,
                        endpoints: vec![endpoint],
                        retained_since: None,
                    }],
                    since: None,
                })
                .await
        }
    });
    tokio::time::timeout(concurrent_subscribe_timeout(), relay.started.notified())
        .await
        .expect("relay subscribe started");
    let staged_event = NostrRelayEvent {
        endpoint: endpoint.clone(),
        subscription_id: Some(new_subscription_id.clone()),
        event: group_event("34", &new_transport_group_id),
    };
    adapter.observe_relay_event(&staged_event).await;
    assert_eq!(adapter.handle_relay_event(staged_event).await.unwrap(), 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), adapter.receive())
            .await
            .is_err(),
        "a staged replay cannot admit history before EOSE"
    );

    cancelled_sync.abort();
    assert!(cancelled_sync.await.unwrap_err().is_cancelled());
    relay.block_subscribes.store(false, Ordering::SeqCst);
    // This call waits for the detached cancellation guard to finish cleanup,
    // then proves no stale stage assertion/state survives into the next sync.
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id: account_id.clone(),
            group_subscriptions: vec![old_group],
            since: None,
        })
        .await
        .expect("sync after cancellation succeeds");

    assert_eq!(adapter.relay_sync().await, relay_sync_before);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), adapter.receive())
            .await
            .is_err(),
        "cancellation discards the abandoned route's staged history"
    );
    adapter
        .handle_relay_eose(endpoint.clone(), old_subscription_id.clone())
        .await;
    assert_eq!(
        adapter
            .handle_relay_event(NostrRelayEvent {
                endpoint: endpoint.clone(),
                subscription_id: Some(old_subscription_id),
                event: group_event("35", &old_transport_group_id),
            })
            .await
            .unwrap(),
        1
    );
    let kept = tokio::time::timeout(Duration::from_secs(1), adapter.receive())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(kept.group_id_hint, Some(old_group_id));
    assert_eq!(
        adapter
            .handle_relay_event(NostrRelayEvent {
                endpoint,
                subscription_id: Some(new_subscription_id),
                event: group_event("36", &new_transport_group_id),
            })
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn cancelled_reissues_preserve_live_gates_and_apply_eose_on_rollback() {
    let relay = Arc::new(BlockingSubscribeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    // One relay per group, so each old route is live on a batch of its own and
    // the two gates can differ.
    let synced_endpoint = TransportEndpoint("wss://group-a.example".into());
    let unsynced_endpoint = TransportEndpoint("wss://group-b.example".into());
    let synced_group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let unsynced_group_id = cgka_traits::GroupId::new(vec![0xB3; 32]);
    let synced_old = TransportGroupSubscription {
        group_id: synced_group_id.clone(),
        transport_group_id: vec![0xC2; 32],
        endpoints: vec![synced_endpoint.clone()],
        retained_since: None,
    };
    let unsynced_old = TransportGroupSubscription {
        group_id: unsynced_group_id.clone(),
        transport_group_id: vec![0xC3; 32],
        endpoints: vec![unsynced_endpoint.clone()],
        retained_since: None,
    };
    // Floored, so the sync that retains both old routes widens them to a full
    // backfill (their switch times are unknown) and issues them again.
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![synced_old.clone(), unsynced_old.clone()],
            since: Some(Timestamp(1_700_000_000)),
        })
        .await
        .expect("activation succeeds");
    let synced_old_subscription_id =
        group_subscription_id(&adapter, &account_id, &synced_old).await;
    let unsynced_old_subscription_id =
        group_subscription_id(&adapter, &account_id, &unsynced_old).await;
    assert_ne!(synced_old_subscription_id, unsynced_old_subscription_id);
    adapter
        .handle_relay_eose(synced_endpoint.clone(), synced_old_subscription_id.clone())
        .await;
    assert_eq!(
        adapter
            .subscription_synced(&synced_old_subscription_id)
            .await,
        Some(true)
    );
    assert_eq!(
        adapter
            .subscription_synced(&unsynced_old_subscription_id)
            .await,
        Some(false)
    );

    relay.block_subscribes.store(true, Ordering::SeqCst);
    let cancelled_sync = tokio::spawn({
        let adapter = adapter.clone();
        let account_id = account_id.clone();
        let synced_endpoint = synced_endpoint.clone();
        let unsynced_endpoint = unsynced_endpoint.clone();
        let synced_group_id = synced_group_id.clone();
        let unsynced_group_id = unsynced_group_id.clone();
        let synced_old = synced_old.clone();
        let unsynced_old = unsynced_old.clone();
        async move {
            adapter
                .sync_account_groups(TransportGroupSync {
                    account_id,
                    group_subscriptions: vec![
                        TransportGroupSubscription {
                            group_id: synced_group_id,
                            transport_group_id: vec![0xD2; 32],
                            endpoints: vec![synced_endpoint],
                            retained_since: None,
                        },
                        synced_old,
                        TransportGroupSubscription {
                            group_id: unsynced_group_id,
                            transport_group_id: vec![0xD3; 32],
                            endpoints: vec![unsynced_endpoint],
                            retained_since: None,
                        },
                        unsynced_old,
                    ],
                    since: Some(Timestamp(1_700_000_100)),
                })
                .await
        }
    });
    tokio::time::timeout(concurrent_subscribe_timeout(), relay.started.notified())
        .await
        .expect("widening relay subscribe started");

    // The sync repacks every route into fresh batches per relay and floor: 2
    // and 4 for the new routes, 3 and 5 for the widened old ones. The live
    // batches carrying the old routes stay open until the sync commits, which
    // would close them.
    let staged_unsynced_widening_id =
        batch_subscription_id(&adapter, &account_id, &unsynced_old.endpoints, 5).await;
    assert_eq!(
        adapter
            .subscription_synced(&synced_old_subscription_id)
            .await,
        Some(true),
        "staging a widening REQ must not regress an already-open live gate"
    );
    adapter
        .handle_relay_eose(
            unsynced_endpoint.clone(),
            unsynced_old_subscription_id.clone(),
        )
        .await;
    adapter
        .handle_relay_eose(unsynced_endpoint, staged_unsynced_widening_id.clone())
        .await;
    assert_eq!(
        adapter
            .subscription_synced(&unsynced_old_subscription_id)
            .await,
        Some(true),
        "the live batch's EOSE is final: the sync replaces it with new ids \
         rather than reissuing it under its own"
    );
    assert_eq!(
        adapter
            .subscription_synced(&staged_unsynced_widening_id)
            .await,
        Some(true),
        "the staged batch's callback is provisional until the batch outcome is known"
    );

    cancelled_sync.abort();
    assert!(cancelled_sync.await.unwrap_err().is_cancelled());
    relay.block_subscribes.store(false, Ordering::SeqCst);
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id,
            group_subscriptions: vec![synced_old, unsynced_old],
            since: None,
        })
        .await
        .expect("follow-up sync waits for cancellation rollback");

    assert_eq!(
        adapter
            .subscription_synced(&synced_old_subscription_id)
            .await,
        Some(true)
    );
    assert_eq!(
        adapter
            .subscription_synced(&unsynced_old_subscription_id)
            .await,
        Some(true),
        "EOSE observed during the failed sync must keep the retained live gate open"
    );
    assert_eq!(
        adapter
            .subscription_synced(&staged_unsynced_widening_id)
            .await,
        None,
        "the rollback discards the abandoned batch's progress"
    );
    // The two live batches' EOSE only: the abandoned batch's sample is
    // discarded with it.
    assert_eq!(adapter.relay_sync().await.eose.sample_count(), 2);
}

#[tokio::test]
async fn observe_relay_event_records_every_relay_copy_for_spread() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let transport_group_id = vec![0xC3; 32];
    let endpoints = [
        TransportEndpoint("wss://group-a.example".into()),
        TransportEndpoint("wss://group-b.example".into()),
        TransportEndpoint("wss://group-c.example".into()),
    ];

    // The same logical event seen from three relays on the raw per-relay tap.
    for endpoint in &endpoints {
        adapter
            .observe_relay_event(&NostrRelayEvent {
                endpoint: endpoint.clone(),
                subscription_id: Some("group-sub".into()),
                event: group_event("11", &transport_group_id),
            })
            .await;
    }

    let spread = adapter.delivery_spread().await;
    assert_eq!(spread.observed, 1, "one logical message observed");
    assert_eq!(spread.corroborated, 1, "corroborated by later relay copies");
    assert_eq!(
        spread.spread.sample_count(),
        2,
        "two laggard copies recorded as spread samples"
    );
    // Per-relay attribution: the first relay delivered first, the rest later.
    // Indices are assigned in first-seen order (a, b, c) and reported ascending.
    assert_eq!(spread.per_relay.len(), 3);
    assert_eq!(spread.per_relay[0].delivered_first, 1);
    assert_eq!(spread.per_relay[0].first_deliverer_rate(), Some(1.0));
    assert_eq!(spread.per_relay[1].delivered_later, 1);
    assert_eq!(spread.per_relay[2].delivered_later, 1);
}

#[tokio::test]
async fn resolve_relay_labels_maps_observed_indices_to_endpoints() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let transport_group_id = vec![0xC3; 32];
    let endpoints = [
        TransportEndpoint("wss://group-a.example".into()),
        TransportEndpoint("wss://group-b.example".into()),
    ];
    let canonical_endpoints = endpoints
        .clone()
        .map(|endpoint| TransportEndpoint(format!("{}/", endpoint.as_str().trim_end_matches('/'))));

    // Observing per-relay copies assigns opaque indices in first-seen order.
    for endpoint in &endpoints {
        adapter
            .observe_relay_event(&NostrRelayEvent {
                endpoint: endpoint.clone(),
                subscription_id: Some("group-sub".into()),
                event: group_event("11", &transport_group_id),
            })
            .await;
    }

    // The export boundary resolves those indices back to relay URLs, but only
    // when handed an explicit opt-in consent token.
    let resolution = adapter
        .resolve_relay_labels(RelayExportConsent::affirm())
        .await;
    assert_eq!(resolution.len(), 2);
    assert_eq!(
        resolution.label_for(RelayIndex(0)),
        Some(&canonical_endpoints[0])
    );
    assert_eq!(
        resolution.label_for(RelayIndex(1)),
        Some(&canonical_endpoints[1])
    );
    assert_eq!(resolution.label_for(RelayIndex(2)), None);
}

#[tokio::test]
async fn deduplicated_delivery_path_does_not_record_spread() {
    // The relay pool delivers one deduplicated `Event` per message, so the
    // delivery path must never feed cross-relay spread; otherwise the metric
    // would only ever see the first relay's copy.
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let transport_group_id = vec![0xC3; 32];

    adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: TransportEndpoint("wss://group.example".into()),
            subscription_id: Some("group-sub".into()),
            event: group_event("11", &transport_group_id),
        })
        .await
        .expect("relay event handled");

    let spread = adapter.delivery_spread().await;
    assert_eq!(spread.observed, 0, "delivery path must not feed spread");
    assert_eq!(spread.spread.sample_count(), 0);
}

#[tokio::test]
async fn forged_event_id_fails_closed_on_delivery_and_telemetry_paths() {
    // #351 — a subscribed, otherwise well-formed event whose self-reported id
    // does not match the event hash must neither be routed (no `wire_id`
    // poisoning) nor key per-relay telemetry on `observe_relay_event`.
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let transport_group_id = vec![0xC3; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id,
                transport_group_id: transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
                retained_since: None,
            }],
            since: None,
        })
        .await
        .expect("activation succeeds");

    let mut forged = group_event("11", &transport_group_id);
    forged.id = "77".repeat(32);

    let error = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: endpoint.clone(),
            subscription_id: Some("group-sub".into()),
            event: forged.clone(),
        })
        .await
        .expect_err("forged id must not map to a delivery");
    assert!(matches!(
        error,
        cgka_traits::TransportAdapterError::InvalidInboundSignature
    ));

    adapter
        .observe_relay_event(&NostrRelayEvent {
            endpoint,
            subscription_id: Some("group-sub".into()),
            event: forged,
        })
        .await;

    let spread = adapter.delivery_spread().await;
    assert_eq!(spread.observed, 0, "forged id must not enter telemetry");
    assert_eq!(spread.spread.sample_count(), 0);
    assert_eq!(spread.per_relay.len(), 0);
}

#[tokio::test]
async fn non_exact_kind_445_shape_is_typed_invalid_encoding() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let mut event = group_event("extra-tag", &[0xC3; 32]);
    event.tags.push(vec!["e".into(), "11".repeat(32)]);
    event.id = event.computed_id();

    let error = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: TransportEndpoint("wss://group.example".into()),
            subscription_id: Some("group-sub".into()),
            event: event.clone(),
        })
        .await
        .expect_err("extra kind-445 tag must fail before routing");
    assert!(matches!(
        error,
        cgka_traits::TransportAdapterError::InvalidInboundEncoding
    ));

    adapter
        .observe_relay_event(&NostrRelayEvent {
            endpoint: TransportEndpoint("wss://group.example".into()),
            subscription_id: Some("group-sub".into()),
            event,
        })
        .await;
    let spread = adapter.delivery_spread().await;
    assert_eq!(spread.observed, 0);
    assert_eq!(spread.per_relay.len(), 0);
}

#[tokio::test]
async fn initial_sync_gate_closes_only_after_every_endpoint_eoses() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let transport_group_id = vec![0xC3; 32];
    let endpoint_a = TransportEndpoint("wss://group-a.example".into());
    let endpoint_b = TransportEndpoint("wss://group-b.example".into());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: group_id.clone(),
                transport_group_id: transport_group_id.clone(),
                endpoints: vec![endpoint_a.clone(), endpoint_b.clone()],
                retained_since: None,
            }],
            since: None,
        })
        .await
        .expect("activation succeeds");

    // The id of the batch REQ the adapter issued for the group's route.
    let sub_id = adapter
        .group_route_subscription_id(&account_id, &transport_group_id)
        .await
        .expect("a live batch carries the route");

    // Tracked but not yet synced: no endpoint has reached EOSE.
    assert_eq!(adapter.subscription_synced(&sub_id).await, Some(false));

    // A first event (observed on the per-relay tap) then EOSE from endpoint A:
    // still draining endpoint B.
    adapter
        .observe_relay_event(&NostrRelayEvent {
            endpoint: endpoint_a.clone(),
            subscription_id: Some(sub_id.clone()),
            event: group_event("11", &transport_group_id),
        })
        .await;
    adapter.handle_relay_eose(endpoint_a, sub_id.clone()).await;
    assert_eq!(adapter.subscription_synced(&sub_id).await, Some(false));

    // EOSE from endpoint B closes the gate.
    adapter.handle_relay_eose(endpoint_b, sub_id.clone()).await;
    assert_eq!(adapter.subscription_synced(&sub_id).await, Some(true));

    let sync = adapter.relay_sync().await;
    // Inbox + group subscriptions are both tracked.
    assert_eq!(sync.tracked_subscriptions, 2);
    assert_eq!(sync.synced_subscriptions, 1);
    assert_eq!(sync.eose.sample_count(), 2);
    assert_eq!(sync.first_event.sample_count(), 1);

    // Unknown subscriptions report no sync state.
    assert_eq!(adapter.subscription_synced("nope").await, None);
}

#[tokio::test]
async fn synced_group_subscriptions_replace_old_routes() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let old_group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let old_transport_group_id = vec![0xC3; 32];
    let new_group_id = cgka_traits::GroupId::new(vec![0xD4; 32]);
    let new_transport_group_id = vec![0xE5; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: old_group_id,
                transport_group_id: old_transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
                retained_since: None,
            }],
            since: None,
        })
        .await
        .expect("activation succeeds");
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id,
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: new_group_id.clone(),
                transport_group_id: new_transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
                retained_since: None,
            }],
            since: Some(Timestamp(1_700_000_100)),
        })
        .await
        .expect("sync succeeds");

    let old_delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: endpoint.clone(),
            subscription_id: Some("old-group-sub".into()),
            event: group_event("12", &old_transport_group_id),
        })
        .await
        .expect("old relay event handled");
    let new_delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint,
            subscription_id: Some("new-group-sub".into()),
            event: group_event("13", &new_transport_group_id),
        })
        .await
        .expect("new relay event handled");

    assert_eq!(old_delivered, 0);
    assert_eq!(new_delivered, 1);
    let delivery = adapter.receive().await.unwrap().unwrap();
    assert_eq!(delivery.group_id_hint, Some(new_group_id));

    let attempt = adapter
        .account_subscription_attempt(&MemberId::new(vec![0xA1; 32]))
        .await
        .expect("the account is active");
    // The sync's repack replaces the activation's batch, so it closes.
    let unsubscribed = relay.unsubscribed.lock().unwrap();
    assert_eq!(
        unsubscribed.as_slice(),
        &[NostrSubscription::GroupBatch {
            account_id: MemberId::new(vec![0xA1; 32]),
            routes: vec![GroupBatchRoute {
                group_id: cgka_traits::GroupId::new(vec![0xB2; 32]),
                transport_group_id: old_transport_group_id,
            }],
            endpoints: vec![TransportEndpoint("wss://group.example".into())],
            since: None,
            attempt,
            batch: 0,
        }]
    );
}

#[tokio::test]
async fn restart_with_retained_route_backfills_and_routes_delayed_old_event() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 16]);
    let prior_transport_group_id = vec![0xC3; 32];
    let current_transport_group_id = vec![0xD4; 32];
    let prior_endpoint = TransportEndpoint("wss://prior.example".into());
    let current_endpoint = TransportEndpoint("wss://current.example".into());

    // A reopened account carries both the current and retained prior route.
    // The global cursor is deliberately newer than the delayed event below;
    // the retained route therefore must be subscribed without that cursor,
    // while the already-current route keeps the bounded restart cursor.
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![
                TransportGroupSubscription {
                    group_id: group_id.clone(),
                    transport_group_id: current_transport_group_id,
                    endpoints: vec![current_endpoint],
                    retained_since: None,
                },
                TransportGroupSubscription {
                    group_id: group_id.clone(),
                    transport_group_id: prior_transport_group_id.clone(),
                    endpoints: vec![prior_endpoint.clone()],
                    retained_since: None,
                },
            ],
            since: Some(Timestamp(1_800_000_000)),
        })
        .await
        .expect("restart activation succeeds");

    let group_subscriptions = relay
        .subscriptions
        .lock()
        .unwrap()
        .iter()
        .flat_map(|subscription| match subscription {
            NostrSubscription::Group { since, .. } => vec![*since],
            NostrSubscription::GroupBatch { routes, since, .. } => vec![*since; routes.len()],
            NostrSubscription::AccountInbox { .. } | NostrSubscription::GroupMaintenance { .. } => {
                Vec::new()
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        group_subscriptions,
        vec![Some(Timestamp(1_800_000_000)), None]
    );

    let delayed = group_event("12", &prior_transport_group_id);
    assert!(
        delayed.created_at < 1_800_000_000,
        "fixture must predate the global restart cursor"
    );
    let delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: prior_endpoint,
            subscription_id: Some("retained-prior-route".into()),
            event: delayed,
        })
        .await
        .expect("delayed prior-route event is accepted");
    assert_eq!(delivered, 1);
    assert_eq!(
        adapter
            .receive()
            .await
            .expect("receive succeeds")
            .expect("delivery is present")
            .group_id_hint,
        Some(group_id)
    );
}

#[tokio::test]
async fn rotating_current_route_reissues_the_displaced_route_for_full_backfill_once() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 16]);
    let route_a = TransportGroupSubscription {
        group_id: group_id.clone(),
        transport_group_id: vec![0xC3; 32],
        endpoints: vec![TransportEndpoint("wss://a.example".into())],
        retained_since: None,
    };
    let route_b = TransportGroupSubscription {
        group_id: group_id.clone(),
        transport_group_id: vec![0xD4; 32],
        endpoints: vec![TransportEndpoint("wss://b.example".into())],
        retained_since: None,
    };
    let since = Some(Timestamp(1_800_000_000));

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![route_a.clone()],
            since,
        })
        .await
        .expect("initial activation succeeds");

    adapter
        .sync_account_groups(TransportGroupSync {
            account_id: account_id.clone(),
            group_subscriptions: vec![route_b.clone(), route_a.clone()],
            since,
        })
        .await
        .expect("route rotation sync succeeds");

    // A sync amends the live activation rather than opening a new attempt, so
    // the re-issued routes carry the activation's own attempt.
    let attempt = adapter
        .account_subscription_attempt(&account_id)
        .await
        .expect("the account is active");
    // The sync repacks both routes into fresh batches, one each because their
    // relays and floors differ, replacing the activation's batch 0.
    let issued_after_rotation = relay
        .subscriptions
        .lock()
        .unwrap()
        .iter()
        .skip(2)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        issued_after_rotation,
        vec![
            NostrSubscription::GroupBatch {
                account_id: account_id.clone(),
                routes: vec![GroupBatchRoute {
                    group_id: group_id.clone(),
                    transport_group_id: route_b.transport_group_id.clone(),
                }],
                endpoints: route_b.endpoints.clone(),
                since,
                attempt,
                batch: 1,
            },
            NostrSubscription::GroupBatch {
                account_id: account_id.clone(),
                routes: vec![GroupBatchRoute {
                    group_id: group_id.clone(),
                    transport_group_id: route_a.transport_group_id.clone(),
                }],
                endpoints: route_a.endpoints.clone(),
                since: None,
                attempt,
                batch: 2,
            },
        ],
        "the new current route is bounded while the displaced route is reissued without a cursor"
    );

    adapter
        .sync_account_groups(TransportGroupSync {
            account_id,
            group_subscriptions: vec![route_b, route_a],
            since,
        })
        .await
        .expect("unchanged retained-route sync succeeds");
    assert_eq!(
        relay.subscriptions.lock().unwrap().len(),
        4,
        "an already-retained route is not repeatedly reissued"
    );
}

/// `(route id byte, since)` of each group REQ issued since the last call.
fn issued_group_floors(relay: &FakeRelayClient) -> Vec<(u8, Option<Timestamp>)> {
    relay
        .take_issued_subscriptions()
        .into_iter()
        .flat_map(|subscription| match subscription {
            NostrSubscription::Group {
                transport_group_id,
                since,
                ..
            } => vec![(transport_group_id[0], since)],
            NostrSubscription::GroupBatch { routes, since, .. } => routes
                .iter()
                .map(|route| (route.transport_group_id[0], since))
                .collect(),
            NostrSubscription::AccountInbox { .. } | NostrSubscription::GroupMaintenance { .. } => {
                Vec::new()
            }
        })
        .collect()
}

fn floored_route(
    group_id: &cgka_traits::GroupId,
    id: u8,
    retained_since: Option<u64>,
) -> TransportGroupSubscription {
    TransportGroupSubscription {
        group_id: group_id.clone(),
        transport_group_id: vec![id; 32],
        endpoints: vec![TransportEndpoint(format!("wss://route-{id}.example"))],
        retained_since: retained_since.map(Timestamp),
    }
}

#[tokio::test]
async fn retained_routes_resume_from_their_switch_floor_never_after_the_cursor() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 16]);
    let cursor = 1_800_000_000;
    let routes = vec![
        floored_route(&group_id, 1, None),
        // Replaced an hour before the cursor: members that had not applied the
        // switch kept sending here, below the cursor the new route drives.
        floored_route(&group_id, 2, Some(cursor - 3_600)),
        // Replaced after a stale cursor: it still resumes from the cursor.
        floored_route(&group_id, 3, Some(cursor + 60)),
        // Recorded before switch times were kept.
        floored_route(&group_id, 4, None),
    ];
    let activate = |since| TransportAccountActivation {
        account_id: account_id.clone(),
        inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
        group_subscriptions: routes.clone(),
        since,
    };

    adapter
        .activate_account(activate(Some(Timestamp(cursor))))
        .await
        .expect("activation succeeds");
    assert_eq!(
        issued_group_floors(&relay),
        vec![
            (1, Some(Timestamp(cursor))),
            (2, Some(Timestamp(cursor - 3_600))),
            (3, Some(Timestamp(cursor))),
            (4, None),
        ],
        "the current route keeps the cursor; a retained route resumes from its \
         switch floor, never later than the cursor, and a route without one \
         is backfilled in full"
    );

    // A retained floor marks a route as retained wherever it sits: ahead of
    // the current route, or with no current route at all.
    adapter
        .activate_account(TransportAccountActivation {
            group_subscriptions: vec![routes[1].clone(), routes[0].clone()],
            ..activate(Some(Timestamp(cursor)))
        })
        .await
        .expect("activation with a retained route first succeeds");
    assert_eq!(
        issued_group_floors(&relay),
        vec![
            (2, Some(Timestamp(cursor - 3_600))),
            (1, Some(Timestamp(cursor))),
        ]
    );
    adapter
        .activate_account(TransportAccountActivation {
            group_subscriptions: routes[1..3].to_vec(),
            ..activate(Some(Timestamp(cursor)))
        })
        .await
        .expect("activation without a current route succeeds");
    assert_eq!(
        issued_group_floors(&relay),
        vec![
            (2, Some(Timestamp(cursor - 3_600))),
            (3, Some(Timestamp(cursor))),
        ]
    );

    adapter
        .activate_account(activate(None))
        .await
        .expect("full-history activation succeeds");
    assert_eq!(
        issued_group_floors(&relay),
        vec![(1, None), (2, None), (3, None), (4, None)],
        "a full-history activation backfills every route in full"
    );
}

#[tokio::test]
async fn a_live_retained_route_is_reissued_only_to_widen_it() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 16]);
    let cursor = 1_800_000_000;
    let sync = |routes: Vec<TransportGroupSubscription>, since: u64| TransportGroupSync {
        account_id: account_id.clone(),
        group_subscriptions: routes,
        since: Some(Timestamp(since)),
    };
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![floored_route(&group_id, 1, None)],
            since: Some(Timestamp(cursor)),
        })
        .await
        .expect("activation succeeds");
    relay.take_issued_subscriptions();

    // Route 1 was replaced after the REQ it is live on was issued. That REQ
    // already reaches further back than the switch floor. The sync repacks
    // every route, so route 1 goes out again, but at the floor it is live at:
    // the activation's replay has not completed, so a narrower floor could
    // cut off history the replaced REQ was still returning.
    adapter
        .sync_account_groups(sync(
            vec![
                floored_route(&group_id, 2, None),
                floored_route(&group_id, 1, Some(cursor + 600)),
            ],
            cursor + 900,
        ))
        .await
        .expect("route change sync succeeds");
    assert_eq!(
        issued_group_floors(&relay),
        vec![
            (2, Some(Timestamp(cursor + 900))),
            (1, Some(Timestamp(cursor))),
        ],
        "the displaced route keeps its wider live floor"
    );

    // Route 2 is displaced in turn, with a switch floor below the cursor its
    // live REQ was issued with: the repack widens it. Route 1 keeps its floor.
    let rotated = vec![
        floored_route(&group_id, 3, None),
        floored_route(&group_id, 2, Some(cursor + 300)),
        floored_route(&group_id, 1, Some(cursor + 600)),
    ];
    adapter
        .sync_account_groups(sync(rotated.clone(), cursor + 1_200))
        .await
        .expect("second route change sync succeeds");
    assert_eq!(
        issued_group_floors(&relay),
        vec![
            (3, Some(Timestamp(cursor + 1_200))),
            (2, Some(Timestamp(cursor + 300))),
            (1, Some(Timestamp(cursor))),
        ]
    );

    adapter
        .sync_account_groups(sync(rotated, cursor + 1_500))
        .await
        .expect("unchanged sync succeeds");
    assert_eq!(
        issued_group_floors(&relay),
        Vec::new(),
        "an unchanged retained route is not reissued"
    );
}

// Regression for mdk#337: a failed relay unsubscribe must not fail the sync or
// leave the routing index serving the old group set. The removal takes effect
// in routing state immediately; the relay-side teardown is queued for retry.
#[tokio::test]
async fn sync_with_failed_unsubscribe_returns_ok_and_routes_reflect_intent() {
    let relay = Arc::new(FlakyUnsubscribeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let old_transport_group_id = vec![0xC3; 32];
    let new_group_id = cgka_traits::GroupId::new(vec![0xD4; 32]);
    let new_transport_group_id = vec![0xE5; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: cgka_traits::GroupId::new(vec![0xB2; 32]),
                transport_group_id: old_transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
                retained_since: None,
            }],
            since: None,
        })
        .await
        .expect("activation succeeds");
    relay.fail_next_unsubscribes.store(1, Ordering::SeqCst);
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id,
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: new_group_id.clone(),
                transport_group_id: new_transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
                retained_since: None,
            }],
            since: Some(Timestamp(1_700_000_100)),
        })
        .await
        .expect("sync succeeds despite the failed unsubscribe");

    let old_delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: endpoint.clone(),
            subscription_id: Some("old-group-sub".into()),
            event: group_event("21", &old_transport_group_id),
        })
        .await
        .expect("old relay event handled");
    let new_delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint,
            subscription_id: Some("new-group-sub".into()),
            event: group_event("22", &new_transport_group_id),
        })
        .await
        .expect("new relay event handled");

    assert_eq!(old_delivered, 0, "removed route must not deliver");
    assert_eq!(new_delivered, 1);
    let delivery = adapter.receive().await.unwrap().unwrap();
    assert_eq!(delivery.group_id_hint, Some(new_group_id));

    let metrics = adapter.metrics().await;
    assert_eq!(metrics.subscriptions_removed, 0);
    assert_eq!(metrics.unsubscribe_retries_pending, 1);
    // Telemetry tracks only live subscriptions: inbox + the new group.
    assert_eq!(adapter.relay_sync().await.tracked_subscriptions, 2);
}

#[tokio::test]
async fn failed_unsubscribe_is_retried_and_drained_on_next_sync() {
    let relay = Arc::new(FlakyUnsubscribeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let old_group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let old_transport_group_id = vec![0xC3; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());
    let new_group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![0xD4; 32]),
        transport_group_id: vec![0xE5; 32],
        endpoints: vec![endpoint.clone()],
        retained_since: None,
    };

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: old_group_id.clone(),
                transport_group_id: old_transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
                retained_since: None,
            }],
            since: None,
        })
        .await
        .expect("activation succeeds");
    relay.fail_next_unsubscribes.store(1, Ordering::SeqCst);
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id: account_id.clone(),
            group_subscriptions: vec![new_group.clone()],
            since: None,
        })
        .await
        .expect("sync succeeds despite the failed unsubscribe");
    assert_eq!(adapter.metrics().await.unsubscribe_retries_pending, 1);

    // Same desired set: an empty diff still drains the retry queue.
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id: account_id.clone(),
            group_subscriptions: vec![new_group],
            since: None,
        })
        .await
        .expect("retry sync succeeds");

    let attempt = adapter
        .account_subscription_attempt(&account_id)
        .await
        .expect("the account is active");
    {
        // The sync's repack replaces the activation's batch, so it closes.
        let unsubscribed = relay.unsubscribed.lock().unwrap();
        assert_eq!(
            unsubscribed.as_slice(),
            &[NostrSubscription::GroupBatch {
                account_id,
                routes: vec![GroupBatchRoute {
                    group_id: old_group_id,
                    transport_group_id: old_transport_group_id,
                }],
                endpoints: vec![endpoint],
                since: None,
                attempt,
                batch: 0,
            }],
            "the failed unsubscribe is replayed exactly once"
        );
    }
    let metrics = adapter.metrics().await;
    assert_eq!(metrics.subscriptions_removed, 1);
    assert_eq!(metrics.unsubscribe_retries_pending, 0);
}

// Regression for mdk#1389: cancelling `sync_account_groups` during the
// post-commit unsubscribe drain must retain confirmed progress and requeue only
// unresolved relay teardowns.
#[tokio::test]
async fn cancelled_sync_drain_retries_unsubscribe_and_metrics_converge() {
    let relay = Arc::new(BlockingUnsubscribeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let old_group_a = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![0xB2; 32]),
        transport_group_id: vec![0xC3; 32],
        endpoints: vec![TransportEndpoint("wss://group.example".into())],
        retained_since: None,
    };
    // On its own relay, so each old group is live on a batch of its own and
    // the sync that removes both has two batch REQs to close.
    let old_group_b = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![0xB3; 32]),
        transport_group_id: vec![0xC4; 32],
        endpoints: vec![TransportEndpoint("wss://group-b.example".into())],
        retained_since: None,
    };
    let new_group_id = cgka_traits::GroupId::new(vec![0xD4; 32]);
    let new_transport_group_id = vec![0xE5; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());
    let new_group = TransportGroupSubscription {
        group_id: new_group_id.clone(),
        transport_group_id: new_transport_group_id.clone(),
        endpoints: vec![endpoint.clone()],
        retained_since: None,
    };
    let expected_unsubscribes = |attempt| {
        [&old_group_a, &old_group_b]
            .into_iter()
            .zip(0..)
            .map(|(group, batch)| NostrSubscription::GroupBatch {
                account_id: account_id.clone(),
                routes: vec![GroupBatchRoute {
                    group_id: group.group_id.clone(),
                    transport_group_id: group.transport_group_id.clone(),
                }],
                endpoints: group.endpoints.clone(),
                since: None,
                attempt,
                batch,
            })
            .collect::<Vec<_>>()
    };

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![old_group_a.clone(), old_group_b.clone()],
            since: None,
        })
        .await
        .expect("activation succeeds");

    relay.block_on_call.store(2, Ordering::SeqCst);
    let adapter_for_sync = adapter.clone();
    let sync_account_id = account_id.clone();
    let sync_group = new_group.clone();
    let sync_task = tokio::spawn(async move {
        adapter_for_sync
            .sync_account_groups(TransportGroupSync {
                account_id: sync_account_id,
                group_subscriptions: vec![sync_group],
                since: None,
            })
            .await
    });

    tokio::time::timeout(concurrent_subscribe_timeout(), async {
        while relay.unsubscribe_entered.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("sync must enter the second relay unsubscribe");
    sync_task.abort();
    let join_err = sync_task
        .await
        .expect_err("aborted sync must not complete successfully");
    assert!(
        join_err.is_cancelled(),
        "aborted sync must be cancelled, got {join_err:?}"
    );

    let old_a_delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: endpoint.clone(),
            subscription_id: Some("old-group-a-sub".into()),
            event: group_event("24", &old_group_a.transport_group_id),
        })
        .await
        .expect("old group-a relay event handled");
    let old_b_delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: endpoint.clone(),
            subscription_id: Some("old-group-b-sub".into()),
            event: group_event("26", &old_group_b.transport_group_id),
        })
        .await
        .expect("old group-b relay event handled");
    let new_delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint,
            subscription_id: Some("new-group-sub".into()),
            event: group_event("25", &new_transport_group_id),
        })
        .await
        .expect("new relay event handled");
    assert_eq!(old_a_delivered, 0, "removed route A must not deliver");
    assert_eq!(old_b_delivered, 0, "removed route B must not deliver");
    assert_eq!(new_delivered, 1);
    let delivery = adapter.receive().await.unwrap().unwrap();
    assert_eq!(delivery.group_id_hint, Some(new_group_id));

    let metrics = adapter.metrics().await;
    assert_eq!(
        metrics.subscriptions_removed, 1,
        "first unsubscribe must be confirmed before cancellation"
    );
    assert_eq!(
        metrics.unsubscribe_retries_pending, 1,
        "cancelled drain must retain only the unresolved relay unsubscribe"
    );

    relay.release_blocked_unsubscribe();
    tokio::time::timeout(
        concurrent_subscribe_timeout(),
        adapter.sync_account_groups(TransportGroupSync {
            account_id: account_id.clone(),
            group_subscriptions: vec![new_group.clone()],
            since: None,
        }),
    )
    .await
    .expect("retry sync must complete before timeout")
    .expect("retry sync succeeds");

    let attempt = adapter
        .account_subscription_attempt(&account_id)
        .await
        .expect("the account is active");
    {
        let unsubscribed = relay.unsubscribed.lock().unwrap();
        assert_eq!(
            unsubscribed.as_slice(),
            expected_unsubscribes(attempt).as_slice(),
            "both old subscription teardowns are recorded exactly once in vector order"
        );
    }
    let metrics = adapter.metrics().await;
    assert_eq!(metrics.subscriptions_removed, 2);
    assert_eq!(metrics.unsubscribe_retries_pending, 0);

    tokio::time::timeout(
        concurrent_subscribe_timeout(),
        adapter.sync_account_groups(TransportGroupSync {
            account_id,
            group_subscriptions: vec![new_group],
            since: None,
        }),
    )
    .await
    .expect("follow-up sync must complete before timeout")
    .expect("follow-up sync must not deadlock the lifecycle mutex");
    assert_eq!(
        adapter.metrics().await.subscriptions_removed,
        2,
        "follow-up sync must not double-count removals"
    );
}

#[tokio::test]
async fn pending_unsubscribe_for_readded_group_is_discarded_not_replayed() {
    let relay = Arc::new(FlakyUnsubscribeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![0xB2; 32]),
        transport_group_id: vec![0xC3; 32],
        endpoints: vec![TransportEndpoint("wss://group.example".into())],
        retained_since: None,
    };

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![group.clone()],
            since: None,
        })
        .await
        .expect("activation succeeds");

    // Remove the group; the relay-side unsubscribe fails and is queued.
    relay.fail_next_unsubscribes.store(1, Ordering::SeqCst);
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id: account_id.clone(),
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .expect("removal sync succeeds despite the failed unsubscribe");
    assert_eq!(adapter.metrics().await.unsubscribe_retries_pending, 1);

    let removed_id = batch_subscription_id(&adapter, &account_id, &group.endpoints, 0).await;

    // Re-add the same group. The sync repacks its route into a fresh batch,
    // and batch numbers are never reused, so the queued unsubscribe cannot
    // carry the id the re-add just established. It still names a REQ no route
    // wants, so the re-add's drain sends it rather than discarding it.
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id: account_id.clone(),
            group_subscriptions: vec![group.clone()],
            since: None,
        })
        .await
        .expect("re-add sync succeeds");
    assert_eq!(
        relay.subscriptions.lock().unwrap().len(),
        3,
        "inbox + initial group + re-added group"
    );
    assert_eq!(adapter.metrics().await.unsubscribe_retries_pending, 0);
    let readded_id = group_subscription_id(&adapter, &account_id, &group).await;
    assert_ne!(readded_id, removed_id);

    // A further sync must not tear down the re-added group's subscription.
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id,
            group_subscriptions: vec![group.clone()],
            since: None,
        })
        .await
        .expect("follow-up sync succeeds");
    assert_eq!(
        relay
            .unsubscribed
            .lock()
            .unwrap()
            .iter()
            .map(NostrSubscription::subscription_id)
            .collect::<Vec<_>>(),
        vec![removed_id],
        "only the removed batch closes; the re-added group's subscription id \
         must never be unsubscribed"
    );

    let delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: TransportEndpoint("wss://group.example".into()),
            subscription_id: Some("group-sub".into()),
            event: group_event("23", &group.transport_group_id),
        })
        .await
        .expect("relay event handled");
    assert_eq!(delivered, 1, "the re-added group still delivers");
}

#[tokio::test]
async fn deactivate_account_clears_pending_unsubscribes() {
    let relay = Arc::new(FlakyUnsubscribeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: cgka_traits::GroupId::new(vec![0xB2; 32]),
                transport_group_id: vec![0xC3; 32],
                endpoints: vec![TransportEndpoint("wss://group.example".into())],
                retained_since: None,
            }],
            since: None,
        })
        .await
        .expect("activation succeeds");
    relay.fail_next_unsubscribes.store(1, Ordering::SeqCst);
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id: account_id.clone(),
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .expect("sync succeeds despite the failed unsubscribe");
    assert_eq!(adapter.metrics().await.unsubscribe_retries_pending, 1);

    // The blanket account teardown supersedes the queued per-subscription
    // entry.
    adapter
        .deactivate_account(&account_id)
        .await
        .expect("deactivation succeeds");
    assert_eq!(
        relay.unsubscribed_accounts.lock().unwrap().as_slice(),
        &[account_id.clone(), account_id.clone()],
        "the activation's opening teardown, then the deactivation's"
    );
    assert_eq!(adapter.metrics().await.unsubscribe_retries_pending, 0);
}

#[tokio::test]
async fn adapter_metrics_record_routing_publish_and_stale_cleanup() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let old_transport_group_id = vec![0xC3; 32];
    let new_transport_group_id = vec![0xD4; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: group_id.clone(),
                transport_group_id: old_transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
                retained_since: None,
            }],
            since: None,
        })
        .await
        .expect("activation succeeds");
    adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: endpoint.clone(),
            subscription_id: Some("matched".into()),
            event: group_event("15", &old_transport_group_id),
        })
        .await
        .expect("matched relay event handled");
    adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: endpoint.clone(),
            subscription_id: Some("dropped".into()),
            event: group_event("16", &[0xEE; 32]),
        })
        .await
        .expect("unmatched relay event handled");
    let message = group_event("17", &old_transport_group_id)
        .to_transport_message()
        .expect("event maps");
    adapter
        .publish(TransportPublishRequest {
            account_id: account_id.clone(),
            message,
            target: TransportPublishTarget::Group {
                group_id: group_id.clone(),
                transport_group_id: old_transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
            },
            required_acks: 1,
        })
        .await
        .expect("publish succeeds");
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id,
            group_subscriptions: vec![TransportGroupSubscription {
                group_id,
                transport_group_id: new_transport_group_id,
                endpoints: vec![endpoint],
                retained_since: None,
            }],
            since: None,
        })
        .await
        .expect("sync succeeds");

    let metrics = adapter.metrics().await;
    assert_eq!(metrics.active_accounts, 1);
    assert_eq!(metrics.active_group_subscriptions, 1);
    assert_eq!(metrics.subscriptions_created, 3);
    assert_eq!(metrics.subscriptions_removed, 1);
    assert_eq!(metrics.inbound_events_seen, 2);
    assert_eq!(metrics.inbound_events_delivered, 1);
    assert_eq!(metrics.inbound_events_dropped, 1);
    assert_eq!(metrics.publish_attempts, 1);
    assert_eq!(metrics.publish_successes, 1);
    assert_eq!(metrics.publish_failures, 0);
}

#[tokio::test]
async fn group_sync_treats_endpoint_order_as_the_same_subscription() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let transport_group_id = vec![0xC3; 32];
    let endpoint_a = TransportEndpoint("wss://a.example".into());
    let endpoint_b = TransportEndpoint("wss://b.example".into());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: group_id.clone(),
                transport_group_id: transport_group_id.clone(),
                endpoints: vec![endpoint_a.clone(), endpoint_b.clone()],
                retained_since: None,
            }],
            since: None,
        })
        .await
        .expect("activation succeeds");
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id,
            group_subscriptions: vec![TransportGroupSubscription {
                group_id,
                transport_group_id,
                endpoints: vec![endpoint_b, endpoint_a],
                retained_since: None,
            }],
            since: Some(Timestamp(1_700_000_100)),
        })
        .await
        .expect("sync succeeds");

    assert_eq!(relay.subscriptions.lock().unwrap().len(), 2);
    assert!(relay.unsubscribed.lock().unwrap().is_empty());
    let metrics = adapter.metrics().await;
    assert_eq!(metrics.subscriptions_created, 2);
    assert_eq!(metrics.subscriptions_removed, 0);
}

#[tokio::test]
async fn activating_existing_account_replaces_old_relay_state() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let old_group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let old_transport_group_id = vec![0xC3; 32];
    let new_group_id = cgka_traits::GroupId::new(vec![0xD4; 32]);
    let new_transport_group_id = vec![0xE5; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://old-inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: old_group_id,
                transport_group_id: old_transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
                retained_since: None,
            }],
            since: None,
        })
        .await
        .expect("first activation succeeds");
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://new-inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: new_group_id.clone(),
                transport_group_id: new_transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
                retained_since: None,
            }],
            since: Some(Timestamp(1_700_000_100)),
        })
        .await
        .expect("second activation succeeds");

    assert_eq!(
        relay.unsubscribed_accounts.lock().unwrap().as_slice(),
        &[account_id.clone(), account_id.clone()],
        "each activation opens with a blanket teardown of the account's REQs"
    );
    let old_delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: endpoint.clone(),
            subscription_id: Some("old-group-sub".into()),
            event: group_event("18", &old_transport_group_id),
        })
        .await
        .expect("old relay event handled");
    let new_delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint,
            subscription_id: Some("new-group-sub".into()),
            event: group_event("19", &new_transport_group_id),
        })
        .await
        .expect("new relay event handled");

    assert_eq!(old_delivered, 0);
    assert_eq!(new_delivered, 1);
    let delivery = adapter.receive().await.unwrap().unwrap();
    assert_eq!(delivery.group_id_hint, Some(new_group_id));
    let metrics = adapter.metrics().await;
    assert_eq!(metrics.active_accounts, 1);
    assert_eq!(metrics.active_group_subscriptions, 1);
    assert_eq!(metrics.subscriptions_created, 4);
    assert_eq!(metrics.subscriptions_removed, 2);
}

#[tokio::test]
async fn publish_group_message_sends_nostr_event_to_target_endpoints() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let transport_group_id = vec![0xC3; 32];
    let endpoint = TransportEndpoint("wss://group.example".into());
    let event = group_event("14", &transport_group_id);
    let message = event.to_transport_message().expect("event maps");

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: group_id.clone(),
                transport_group_id: transport_group_id.clone(),
                endpoints: vec![endpoint.clone()],
                retained_since: None,
            }],
            since: None,
        })
        .await
        .expect("activation succeeds");

    let report = adapter
        .publish(TransportPublishRequest {
            account_id,
            message,
            target: TransportPublishTarget::Group {
                group_id,
                transport_group_id,
                endpoints: vec![endpoint.clone()],
            },
            required_acks: 1,
        })
        .await
        .expect("publish succeeds");

    assert!(report.met_required_acks());
    assert_eq!(report.accepted[0].endpoint, endpoint);
    let published = relay.published.lock().unwrap();
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].0, vec![endpoint]);
    assert_eq!(published[0].1, event);
    assert_eq!(published[0].2, 1);
}

#[tokio::test]
async fn signed_welcome_event_becomes_account_inbox_delivery() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let sender = nostr::prelude::Keys::parse(
        "6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e",
    )
    .unwrap();
    let receiver = nostr::prelude::Keys::parse(
        "7b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e",
    )
    .unwrap();
    let account_id = MemberId::new(receiver.public_key().to_bytes().to_vec());
    let inbox_endpoint = TransportEndpoint("wss://inbox.example".into());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![inbox_endpoint.clone()],
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .expect("activation succeeds");

    let rumor = nostr::prelude::EventBuilder::new(Kind::TextNote, "not yet peeled here")
        .finalize_unsigned(sender.public_key());
    let gift_wrap = GiftWrapBuilder::new(receiver.public_key(), rumor)
        .finalize(&sender)
        .unwrap();
    let event = NostrTransportEvent::from_nostr_event(&gift_wrap).unwrap();

    let delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: inbox_endpoint.clone(),
            subscription_id: Some("inbox-sub".into()),
            event,
        })
        .await
        .expect("relay event handled");

    assert_eq!(delivered, 1);
    let delivery = adapter.receive().await.unwrap().unwrap();
    assert_eq!(delivery.account_id, account_id);
    assert_eq!(delivery.group_id_hint, None);
    assert_eq!(delivery.source.plane, TransportDeliveryPlane::AccountInbox);
    assert_eq!(delivery.source.endpoint, Some(inbox_endpoint));
    assert_eq!(
        delivery.source.subscription_id.as_deref(),
        Some("inbox-sub")
    );
    assert_eq!(
        delivery.message.envelope,
        TransportEnvelope::Welcome {
            recipient: account_id
        }
    );
}

#[tokio::test]
async fn inbox_subscription_since_is_widened_by_the_nip59_tweak_window() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let cursor = 1_700_000_000_u64;

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: cgka_traits::GroupId::new(vec![0xC3; 32]),
                transport_group_id: vec![0xD4; 32],
                endpoints: vec![TransportEndpoint("wss://group.example".into())],
                retained_since: None,
            }],
            since: Some(Timestamp(cursor)),
        })
        .await
        .expect("activation succeeds");

    let issued = relay.subscriptions.lock().unwrap().clone();
    let inbox_since = issued
        .iter()
        .find_map(|subscription| match subscription {
            NostrSubscription::AccountInbox { since, .. } => Some(*since),
            _ => None,
        })
        .expect("inbox subscription issued");
    let group_since = issued
        .iter()
        .find_map(|subscription| match subscription {
            NostrSubscription::GroupBatch { since, .. } => Some(*since),
            _ => None,
        })
        .expect("group subscription issued");

    // Welcomes arrive as NIP-59 gift wraps whose created_at is backdated up to
    // the full tweak range; the inbox window must reach that far back or
    // welcomes published while offline are skipped.
    assert_eq!(
        inbox_since,
        Some(Timestamp(
            cursor - transport_nostr_adapter::NIP59_TIMESTAMP_TWEAK_SECS
        ))
    );
    assert_eq!(group_since, Some(Timestamp(cursor)));
}

#[tokio::test]
async fn inbox_subscription_since_saturates_at_zero() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());

    adapter
        .activate_account(TransportAccountActivation {
            account_id: MemberId::new(vec![0xA1; 32]),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![],
            since: Some(Timestamp(1)),
        })
        .await
        .expect("activation succeeds");

    let issued = relay.subscriptions.lock().unwrap().clone();
    let inbox_since = issued
        .iter()
        .find_map(|subscription| match subscription {
            NostrSubscription::AccountInbox { since, .. } => Some(*since),
            _ => None,
        })
        .expect("inbox subscription issued");
    assert_eq!(inbox_since, Some(Timestamp(0)));
}

// Regression for mdk#482: routing must tolerate non-canonical relay-URL
// differences between the stored (verbatim, signed-routing) endpoint and the
// endpoint an inbound event arrives on (built from a parsed `RelayUrl`). A raw
// `==` silently dropped events that differed only by a trailing slash (or host
// case / default port). Here the group endpoint is stored slash-less while the
// event arrives with the trailing slash a parsed `RelayUrl` carries.
#[tokio::test]
async fn group_event_routes_despite_trailing_slash_mismatch() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
    let transport_group_id = vec![0xC3; 32];
    // Stored verbatim, NOT url-canonical (no trailing slash).
    let stored_endpoint = TransportEndpoint("wss://group.example".into());
    // Inbound endpoint as a parsed RelayUrl would serialize it (trailing slash).
    let inbound_endpoint = TransportEndpoint("wss://group.example/".into());
    assert_ne!(
        stored_endpoint, inbound_endpoint,
        "inputs must differ byte-wise"
    );

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: group_id.clone(),
                transport_group_id: transport_group_id.clone(),
                endpoints: vec![stored_endpoint],
                retained_since: None,
            }],
            since: Some(Timestamp(1_700_000_000)),
        })
        .await
        .expect("activation succeeds");

    let delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: inbound_endpoint.clone(),
            subscription_id: Some("group-sub".into()),
            event: group_event("11", &transport_group_id),
        })
        .await
        .expect("relay event handled");

    assert_eq!(
        delivered, 1,
        "event must route despite trailing-slash mismatch"
    );
    let delivery = adapter
        .receive()
        .await
        .expect("receive succeeds")
        .expect("delivery available");
    assert_eq!(delivery.account_id, account_id);
    assert_eq!(delivery.group_id_hint, Some(group_id));
    assert_eq!(delivery.source.plane, TransportDeliveryPlane::Group);
    assert_eq!(delivery.source.endpoint, Some(inbound_endpoint));
}

// Regression for mdk#482: welcome inbox routing must tolerate the same
// non-canonical relay-URL difference as group routing.
#[tokio::test]
async fn welcome_event_routes_despite_trailing_slash_mismatch() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let sender = nostr::prelude::Keys::parse(
        "6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e",
    )
    .unwrap();
    let receiver = nostr::prelude::Keys::parse(
        "7b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e",
    )
    .unwrap();
    let account_id = MemberId::new(receiver.public_key().to_bytes().to_vec());
    // Stored verbatim (no trailing slash); inbound carries the RelayUrl slash.
    let stored_inbox = TransportEndpoint("wss://inbox.example".into());
    let inbound_inbox = TransportEndpoint("wss://inbox.example/".into());
    assert_ne!(stored_inbox, inbound_inbox, "inputs must differ byte-wise");

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![stored_inbox],
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .expect("activation succeeds");

    let rumor = nostr::prelude::EventBuilder::new(Kind::TextNote, "not yet peeled here")
        .finalize_unsigned(sender.public_key());
    let gift_wrap = GiftWrapBuilder::new(receiver.public_key(), rumor)
        .finalize(&sender)
        .unwrap();
    let event = NostrTransportEvent::from_nostr_event(&gift_wrap).unwrap();

    let delivered = adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: inbound_inbox.clone(),
            subscription_id: Some("inbox-sub".into()),
            event,
        })
        .await
        .expect("relay event handled");

    assert_eq!(
        delivered, 1,
        "welcome must route despite trailing-slash mismatch"
    );
    let delivery = adapter.receive().await.unwrap().unwrap();
    assert_eq!(delivery.account_id, account_id);
    assert_eq!(delivery.source.plane, TransportDeliveryPlane::AccountInbox);
    assert_eq!(delivery.source.endpoint, Some(inbound_inbox));
}

#[tokio::test]
async fn sync_telemetry_tracks_only_live_subscriptions_across_churn() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let account_id = MemberId::new(vec![0xA1; 32]);
    let group_for = |index: u8| TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![index; 32]),
        transport_group_id: vec![index; 32],
        endpoints: vec![TransportEndpoint(format!("wss://relay-{index}.example"))],
        retained_since: None,
    };

    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![group_for(1)],
            since: None,
        })
        .await
        .expect("activation succeeds");
    assert_eq!(adapter.relay_sync().await.tracked_subscriptions, 2);
    let stale_group_id = group_subscription_id(&adapter, &account_id, &group_for(1)).await;

    // Group churn: every sync replaces the previous group with a new one
    // (join/leave, endpoint rotation). The telemetry map must track only the
    // live subscriptions, not one entry per historical subscription id.
    for index in 2..30 {
        adapter
            .sync_account_groups(TransportGroupSync {
                account_id: account_id.clone(),
                group_subscriptions: vec![group_for(index)],
                since: None,
            })
            .await
            .expect("group sync succeeds");
        assert_eq!(
            adapter.relay_sync().await.tracked_subscriptions,
            2,
            "churned-away group subscriptions must be evicted"
        );
    }
    assert_eq!(adapter.subscription_synced(&stale_group_id).await, None);

    // Reactivation with a rotated inbox endpoint set mints new subscription
    // ids; the previous ids must not linger.
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox-rotated.example".into())],
            group_subscriptions: vec![group_for(30)],
            since: None,
        })
        .await
        .expect("reactivation succeeds");
    assert_eq!(adapter.relay_sync().await.tracked_subscriptions, 2);

    // Deactivation drops the account's remaining subscriptions.
    adapter
        .deactivate_account(&account_id)
        .await
        .expect("deactivation succeeds");
    assert_eq!(adapter.relay_sync().await.tracked_subscriptions, 0);
}

/// The account-wide end-of-stored-events gate an unfloored history drain reads.
///
/// A new activation replaces the prior replay snapshot and requires every
/// re-issued subscription to be confirmed again rather than inheriting the
/// previous generation's confirmation. The tracked-subscription assertions pin
/// the separate telemetry eviction that keeps churned-away ids from
/// accumulating.
#[tokio::test]
async fn account_subscription_eose_follows_the_latest_activation_snapshot() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let account_id = MemberId::new(vec![0xB2; 32]);
    let inbox = TransportEndpoint("wss://inbox.example".to_owned());
    let group_for = |index: u8| TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![index; 32]),
        transport_group_id: vec![index; 32],
        endpoints: vec![TransportEndpoint(format!("wss://group-{index}.example"))],
        retained_since: None,
    };
    let group_endpoint = |index: u8| TransportEndpoint(format!("wss://group-{index}.example"));
    // Ids are scoped to the activation attempt that issued them, so both
    // reconstructions take the attempt they belong to.
    let inbox_id = |attempt| {
        NostrSubscription::AccountInbox {
            account_id: account_id.clone(),
            endpoints: vec![inbox.clone()],
            since: None,
            attempt,
        }
        .subscription_id()
    };
    // Each activation carries one group, so its route is the attempt's batch 0.
    let group_id_for = |index: u8, attempt| {
        NostrSubscription::GroupBatch {
            account_id: account_id.clone(),
            routes: Vec::new(),
            endpoints: vec![group_endpoint(index)],
            since: None,
            attempt,
            batch: 0,
        }
        .subscription_id()
    };
    let activate = |group: TransportGroupSubscription| {
        adapter.activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![inbox.clone()],
            group_subscriptions: vec![group],
            since: None,
        })
    };

    activate(group_for(1)).await.expect("activation succeeds");
    let first = adapter
        .account_subscription_attempt(&account_id)
        .await
        .expect("the account is active");
    let progress = adapter.account_subscription_eose(&account_id).await;
    assert_eq!(progress.subscriptions, 2);
    assert!(!progress.any(), "no relay has reported yet");
    assert!(!progress.complete());

    adapter
        .handle_relay_eose(inbox.clone(), inbox_id(first))
        .await;
    let progress = adapter.account_subscription_eose(&account_id).await;
    assert!(progress.any());
    assert!(
        !progress.complete(),
        "the group subscription has not been served"
    );

    adapter
        .handle_relay_eose(group_endpoint(1), group_id_for(1, first))
        .await;
    assert!(
        adapter
            .account_subscription_eose(&account_id)
            .await
            .complete(),
        "every issued subscription has been served"
    );

    // Reactivate with group 1 replaced by group 2. The retired subscription
    // must be evicted rather than left tracked, and both re-issued ids must be
    // confirmed again.
    activate(group_for(2)).await.expect("reactivation succeeds");
    let second = adapter
        .account_subscription_attempt(&account_id)
        .await
        .expect("the account is active");
    assert_ne!(first, second, "reactivation opens a new attempt");
    assert_eq!(
        adapter.relay_sync().await.tracked_subscriptions,
        2,
        "the retired group subscription must not stay tracked"
    );
    let progress = adapter.account_subscription_eose(&account_id).await;
    assert_eq!(progress.subscriptions, 2);
    assert!(
        !progress.any(),
        "a re-issued subscription must be confirmed again"
    );

    // A report for the retired route cannot stand in for the live one, and
    // neither can the superseded attempt's report for a route that survived.
    adapter
        .handle_relay_eose(group_endpoint(1), group_id_for(1, second))
        .await;
    // The retired route's genuinely-issued id does not count either.
    adapter
        .handle_relay_eose(group_endpoint(1), group_id_for(1, first))
        .await;
    adapter
        .handle_relay_eose(inbox.clone(), inbox_id(first))
        .await;
    let progress = adapter.account_subscription_eose(&account_id).await;
    assert_eq!(
        progress.with_eose, 0,
        "neither the retired route nor the superseded attempt may count"
    );
    adapter
        .handle_relay_eose(inbox.clone(), inbox_id(second))
        .await;
    let progress = adapter.account_subscription_eose(&account_id).await;
    assert_eq!(progress.with_eose, 1, "the retired route must not count");
    assert!(!progress.complete());

    adapter
        .handle_relay_eose(group_endpoint(2), group_id_for(2, second))
        .await;
    assert!(
        adapter
            .account_subscription_eose(&account_id)
            .await
            .complete()
    );

    adapter
        .deactivate_account(&account_id)
        .await
        .expect("deactivation succeeds");
    assert_eq!(adapter.relay_sync().await.tracked_subscriptions, 0);
    let progress = adapter.account_subscription_eose(&account_id).await;
    assert_eq!(progress.subscriptions, 0);
    assert!(
        !progress.complete(),
        "an account with nothing subscribed cannot have been served"
    );
}

/// A whole-account replay is complete only after every endpoint of every
/// still-wanted route has served the subscription carrying it. A fast, empty
/// relay must not stand in for a slower relay that holds the missing history,
/// and a mid-attempt group sync must not erase that obligation. Coverage is
/// no longer frozen across a changed sync: the sync's repack moves each
/// wanted route's obligation, on all of its relays, onto the batch that now
/// carries it. The name is kept for grep-ability.
#[tokio::test]
async fn account_subscription_eose_requires_the_frozen_relay_coverage() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let account_id = MemberId::new(vec![0xC3; 32]);
    let inbox_a = TransportEndpoint("wss://inbox-a.example".to_owned());
    let inbox_b = TransportEndpoint("wss://inbox-b.example".to_owned());
    let group_a = TransportEndpoint("wss://group-a.example".to_owned());
    let group_b = TransportEndpoint("wss://Group-B.Example:443/".to_owned());
    let group_b_inbound = TransportEndpoint("wss://group-b.example".to_owned());
    assert_ne!(
        group_b, group_b_inbound,
        "the test requires a verbatim route spelling that normalizes on inbound"
    );
    assert_eq!(
        RelayUrl::parse(group_b.as_str()).expect("route B parses"),
        RelayUrl::parse(group_b_inbound.as_str()).expect("inbound B parses"),
        "the spellings must identify the same relay"
    );
    let group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![0x33; 16]),
        transport_group_id: vec![0x44; 32],
        endpoints: vec![group_a.clone(), group_b.clone()],
        retained_since: None,
    };
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![inbox_a.clone(), inbox_b.clone()],
            group_subscriptions: vec![group.clone()],
            since: None,
        })
        .await
        .expect("activation succeeds");
    let attempt = adapter
        .account_subscription_attempt(&account_id)
        .await
        .expect("the account is active");
    let inbox_id = NostrSubscription::AccountInbox {
        account_id: account_id.clone(),
        endpoints: vec![inbox_a.clone(), inbox_b.clone()],
        since: None,
        attempt,
    }
    .subscription_id();
    let group_id = group_subscription_id(&adapter, &account_id, &group).await;

    // Relay A is fast but empty. Its EOSE covers neither subscription on B.
    adapter
        .handle_relay_eose(inbox_a.clone(), inbox_id.clone())
        .await;
    adapter
        .handle_relay_eose(group_a.clone(), group_id.clone())
        .await;
    let progress = adapter.account_subscription_eose(&account_id).await;
    assert_eq!(progress.subscriptions, 2);
    assert_eq!(progress.with_eose, 2);
    assert_eq!(progress.relay_subscription_attempts, 4);
    assert_eq!(progress.relay_subscription_attempts_with_eose, 2);
    assert!(progress.any());
    assert!(
        !progress.complete(),
        "EOSE from the fast, empty relay must not prove B served its history"
    );

    // Duplicate callbacks do not advance coverage. B can then serve the
    // missing event, but its observed history stays staged until its own EOSE.
    adapter
        .handle_relay_eose(group_a.clone(), group_id.clone())
        .await;
    let stored = group_event("relay-b-only", &group.transport_group_id);
    let stored_id = cgka_traits::MessageId::new(hex::decode(&stored.id).unwrap());
    assert_eq!(
        adapter
            .handle_relay_event(NostrRelayEvent {
                endpoint: group_b_inbound.clone(),
                subscription_id: Some(group_id.clone()),
                event: stored,
            })
            .await
            .expect("B's stored event is accepted"),
        1
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(25), adapter.receive())
            .await
            .is_err(),
        "A's empty and duplicate EOSE cannot release B's observed history"
    );
    adapter
        .handle_relay_eose(inbox_b.clone(), inbox_id.clone())
        .await;
    assert!(
        !adapter
            .account_subscription_eose(&account_id)
            .await
            .complete(),
        "the group subscription still lacks B's EOSE"
    );

    // Complete B's predecessor range before retiring its request. Leave the
    // delivery unplaced through repack to prove the fulfilled history survives.
    adapter
        .handle_relay_eose(group_b_inbound.clone(), group_id.clone())
        .await;

    // A sync that joins a group on relay A alone repacks every route. The
    // still-wanted group keeps both relays, so A answering the repacked
    // batches cannot substitute for B serving the successor request.
    let joined = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![0x55; 16]),
        transport_group_id: vec![0x66; 32],
        endpoints: vec![group_a.clone()],
        retained_since: None,
    };
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id: account_id.clone(),
            group_subscriptions: vec![group.clone(), joined.clone()],
            since: None,
        })
        .await
        .expect("group join succeeds");
    let repacked_group_id = group_subscription_id(&adapter, &account_id, &group).await;
    let joined_id = group_subscription_id(&adapter, &account_id, &joined).await;
    assert_ne!(repacked_group_id, group_id, "the sync repacks the route");
    adapter
        .handle_relay_eose(group_a.clone(), repacked_group_id.clone())
        .await;
    adapter.handle_relay_eose(group_a, joined_id).await;
    let delivery = adapter
        .receive()
        .await
        .expect("delivery receive succeeds")
        .expect("B's completed predecessor history survives repack");
    assert_eq!(delivery.account_id, account_id);
    assert_eq!(delivery.group_id_hint, Some(group.group_id.clone()));
    assert_eq!(delivery.message.id, stored_id);
    assert_eq!(delivery.source.plane, TransportDeliveryPlane::Group);
    assert_eq!(delivery.source.endpoint, Some(group_b_inbound.clone()));
    assert_eq!(
        delivery.message.envelope,
        TransportEnvelope::GroupMessage {
            transport_group_id: group.transport_group_id.clone()
        }
    );
    adapter
        .ack_replay_delivery(&account_id, &delivery.message.id)
        .await;
    let progress = adapter.account_subscription_eose(&account_id).await;
    assert!(
        !progress.complete(),
        "a group sync must not shrink the obligation of a route it still wants"
    );
    assert_eq!(
        adapter
            .subscription_endpoint_eose(&repacked_group_id, &group_b_inbound)
            .await,
        Some(false),
        "placing predecessor history does not certify B's successor wire boundary"
    );

    adapter
        .handle_relay_eose(group_b_inbound, repacked_group_id)
        .await;
    assert!(
        adapter
            .account_subscription_eose(&account_id)
            .await
            .complete(),
        "the coverage completes once B serves the batch now carrying the route"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(25), adapter.receive())
            .await
            .is_err(),
        "repack preserves B's exact history without duplicate delivery"
    );
}

/// The id of the issued batch REQ carrying a route of `group`.
fn issued_group_id(issued: &[NostrSubscription], group: &cgka_traits::GroupId) -> String {
    issued
        .iter()
        .find(|subscription| {
            matches!(
                subscription,
                NostrSubscription::GroupBatch { routes, .. }
                    if routes.iter().any(|route| route.group_id == *group)
            )
        })
        .expect("the group REQ was issued")
        .subscription_id()
}

/// Owner grants select exact live sources, never unrelated maintenance windows.
#[tokio::test]
async fn capture_keeps_original_window() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xE5; 32]);
    let mut group = sync_fixture_group(0x51);
    let a = group.endpoints[0].clone();
    let b = TransportEndpoint("wss://pending.example".into());
    group.endpoints.push(b.clone());
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let id = issued_group_id(&relay.take_issued_subscriptions(), &group.group_id);
    adapter.handle_relay_eose(a.clone(), id.clone()).await;
    let maintenance = adapter
        .install_group_maintenance_recovery_subscription(
            &account,
            &group,
            7,
            Some(Timestamp(floor + 100)),
        )
        .await
        .unwrap();
    relay.take_issued_subscriptions();
    let older = group_event_at("original floor only", &group, floor + 1);
    let newer = group_event_at("inside both windows", &group, floor + 101);
    let excluded = group_event_at("before original floor", &group, floor - 1);
    *relay.retained.lock().unwrap() = Some(vec![
        (account.clone(), b.clone(), newer.clone()),
        (account.clone(), b.clone(), older.clone()),
        (account.clone(), b.clone(), excluded),
    ]);
    let plan = capture_plan(&adapter, &account, 1).await;
    assert_eq!(
        plan.sources.len(),
        1,
        "only B's live source lacks admission"
    );
    let capture = spawn_capture(&adapter, &account, plan);
    // Empty maintenance is a separate source; retire it without granting it IO.
    adapter
        .remove_group_maintenance_recovery_subscription(&account, &maintenance)
        .await
        .unwrap();
    for event in [&older, &newer] {
        assert_group_delivery(&adapter, &account, event).await;
    }
    assert_eq!(capture.await.unwrap(), ReplayCaptureOutcome::Complete);
    wait_replay_eose(&adapter, &id).await;
    assert_no_delivery(&adapter).await;
    assert_replay_idle(&adapter, &account).await;
    assert!(adapter.take_replay_status(&account).await.loss.is_none());
    let requests = relay.acquisitions.lock().unwrap();
    assert!(
        requests
            .iter()
            .all(|request| request.endpoints.len() == 1 && same_relay(&request.endpoints[0], &b))
    );
    assert!(requests.iter().all(|request| matches!(&request.scope,
        NostrAcquisitionScope::GroupsWindow { since, .. } if *since == floor)));
    assert!(
        relay.take_issued_subscriptions().is_empty(),
        "capture never resends live REQs"
    );
    assert!(relay.unsubscribed.lock().unwrap().is_empty());
}

#[tokio::test]
async fn source_change_wakes_owner_and_rejects_frozen_old_capture() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xE1; 32]);
    let group = sync_fixture_group(0xE2);
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let old = capture_plan(&adapter, &account, 1).await;
    let mut changes = adapter.replay_changes(&account).await.unwrap();
    let before = *changes.borrow_and_update();
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id: account.clone(),
            group_subscriptions: vec![group, sync_fixture_group(0xE3)],
            since: Some(Timestamp(floor + 100)),
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), changes.changed())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        *changes.borrow(),
        before,
        "membership changes wake the owner with a new source generation"
    );
    assert_eq!(
        adapter
            .capture_replay(&account, old, NostrAcquisitionCancellation::new())
            .await
            .unwrap(),
        ReplayCaptureOutcome::Stale
    );
    assert!(
        relay.acquisitions.lock().unwrap().is_empty(),
        "stale grants cannot launch IO"
    );
    let status = adapter.take_replay_status(&account).await;
    assert!(status.sources().all(|source| !source.admitted()));
    assert!(
        status.loss.is_none(),
        "a new query is admission debt, not receiver loss"
    );
}

/// An abandoned initial range cannot poison an owner-granted full capture.
/// The same immutable attempt joins unexpired work and withholds newer suffixes.
#[tokio::test(start_paused = true)]
async fn capture_restores_old_range() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xD4; 32]);
    let group = sync_fixture_group(0x53);
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let id = issued_group_id(&relay.take_issued_subscriptions(), &group.group_id);
    let older = group_event_at("missing initial history", &group, floor + 1);
    let newer = group_event_at("abandoned initial prefix", &group, floor + 2);
    route_group_copy(&adapter, &group, &id, &newer).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(31)).await;
    assert_eq!(
        replay_loss(&adapter, &account).await,
        NostrNotificationLossFloor::Since(floor)
    );
    assert_no_delivery(&adapter).await;
    assert_replay_idle(&adapter, &account).await;
    assert_eq!(adapter.subscription_synced(&id).await, Some(false));

    *relay.retained.lock().unwrap() = Some(vec![
        (account.clone(), group.endpoints[0].clone(), newer.clone()),
        (account.clone(), group.endpoints[0].clone(), older.clone()),
        (
            account.clone(),
            group.endpoints[0].clone(),
            group_event_at("below floor", &group, floor - 1),
        ),
    ]);
    relay.hold_acquisition.store(true, Ordering::SeqCst);
    let plan = capture_plan(&adapter, &account, 1).await;
    let capture = spawn_capture(&adapter, &account, plan.clone());
    wait_until("fresh full-window acquisition starts", || {
        !relay.acquisitions.lock().unwrap().is_empty()
    })
    .await;
    assert!(
        adapter.take_replay_status(&account).await.loss.is_none(),
        "capture must not charge the already transferred source loss twice"
    );
    let joined = spawn_capture(&adapter, &account, plan);
    adapter
        .handle_relay_eose(group.endpoints[0].clone(), id.clone())
        .await;
    let live = group_event_at("live after physical boundary", &group, floor + 3);
    route_group_copy(&adapter, &group, &id, &live).await;
    assert_no_delivery(&adapter).await;
    assert_eq!(adapter.subscription_synced(&id).await, Some(false));
    relay.hold_acquisition.store(false, Ordering::SeqCst);
    relay.release_acquisition.notify_waiters();
    for event in [&older, &newer, &live] {
        assert_group_delivery(&adapter, &account, event).await;
    }
    wait_replay_eose(&adapter, &id).await;
    assert_eq!(capture.await.unwrap(), ReplayCaptureOutcome::Complete);
    assert_eq!(joined.await.unwrap(), ReplayCaptureOutcome::Complete);
    assert_no_delivery(&adapter).await;
    assert_replay_idle(&adapter, &account).await;
    assert!(
        relay.take_issued_subscriptions().is_empty(),
        "the original live REQ was not resent"
    );
    assert!(relay.unsubscribed.lock().unwrap().is_empty());
}

/// Owner grants preserve account isolation on a shared receiver, never capturing
/// a deactivated account even when its capability was frozen before retirement.
#[tokio::test]
async fn capture_keeps_accounts_apart() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let endpoint = TransportEndpoint("wss://shared.example".into());
    let floor = 1_700_000_000;
    let mut expected = HashSet::new();
    let mut owners = Vec::new();
    let mut retained = Vec::new();
    for byte in [0xA1, 0xB2, 0xC3] {
        let account = MemberId::new(vec![byte; 32]);
        let mut group = sync_fixture_group(byte);
        group.endpoints = vec![endpoint.clone()];
        adapter
            .activate_account(TransportAccountActivation {
                account_id: account.clone(),
                inbox_endpoints: vec![],
                group_subscriptions: vec![group.clone()],
                since: Some(Timestamp(floor)),
            })
            .await
            .unwrap();
        let id = issued_group_id(&relay.take_issued_subscriptions(), &group.group_id);
        let event = group_event_at("account-owned retained history", &group, floor + 1);
        if byte != 0xC3 {
            expected.insert((account.clone(), event.to_transport_message().unwrap().id));
        }
        retained.push((account.clone(), endpoint.clone(), event));
        owners.push((account, id));
    }
    *relay.retained.lock().unwrap() = Some(retained);
    let mut plans = Vec::new();
    for (account, _) in &owners {
        plans.push(capture_plan(&adapter, account, 1).await);
    }
    assert_eq!(
        adapter
            .capture_replay(
                &owners[0].0,
                plans[1].clone(),
                NostrAcquisitionCancellation::new()
            )
            .await
            .unwrap(),
        ReplayCaptureOutcome::Stale,
        "an account wrapper cannot spend another account's source capability"
    );
    assert!(relay.acquisitions.lock().unwrap().is_empty());
    adapter.deactivate_account(&owners[2].0).await.unwrap();
    assert_eq!(
        adapter
            .capture_replay(
                &owners[2].0,
                plans.pop().unwrap(),
                NostrAcquisitionCancellation::new()
            )
            .await
            .unwrap(),
        ReplayCaptureOutcome::Stale
    );
    let captures = plans
        .into_iter()
        .zip(&owners[..2])
        .map(|(plan, (account, _))| spawn_capture(&adapter, account, plan))
        .collect::<Vec<_>>();
    for _ in 0..2 {
        let delivery = tokio::time::timeout(Duration::from_secs(1), adapter.receive())
            .await
            .expect("active account history arrives")
            .unwrap()
            .unwrap();
        assert!(
            expected.remove(&(delivery.account_id.clone(), delivery.message.id.clone())),
            "only exact active-account history is released once"
        );
        adapter
            .ack_replay_delivery(&delivery.account_id, &delivery.message.id)
            .await;
    }
    assert!(expected.is_empty());
    for (account, id) in &owners[..2] {
        wait_replay_eose(&adapter, id).await;
        assert_replay_idle(&adapter, account).await;
    }
    assert_replay_idle(&adapter, &owners[2].0).await;
    assert_eq!(adapter.subscription_synced(&owners[2].1).await, None);
    assert_no_delivery(&adapter).await;
    for capture in captures {
        assert_eq!(capture.await.unwrap(), ReplayCaptureOutcome::Complete);
    }
    assert!(
        relay
            .acquisitions
            .lock()
            .unwrap()
            .iter()
            .all(|request| request.account_id != owners[2].0)
    );
    assert!(relay.take_issued_subscriptions().is_empty());
    assert!(relay.unsubscribed.lock().unwrap().is_empty());
}

/// A lag can precede the event worker's queued stored prefix. Recovery must
/// acquire and order the whole window, not release its newest prefix.
#[tokio::test]
async fn capture_orders_queued_history() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xF6; 32]);
    let group = sync_fixture_group(0xF7);
    let floor = 1_700_000_000;
    let mut history = (0..600)
        .map(|index| group_event_at(&format!("queued-{index}"), &group, floor + index / 3))
        .collect::<Vec<_>>();
    history.sort_unstable_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
    relay.pages.lock().unwrap().extend([
        (
            NostrAcquisitionEnd::RequestPolicySatisfied,
            history.iter().rev().cloned().collect(),
        ),
        (NostrAcquisitionEnd::RequestPolicySatisfied, Vec::new()),
    ]);
    relay.hold_acquisition.store(true, Ordering::SeqCst);
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let id = issued_group_id(&relay.take_issued_subscriptions(), &group.group_id);
    for event in history.iter().rev().take(12) {
        route_group_copy(&adapter, &group, &id, event).await;
    }
    let capture = spawn_capture(
        &adapter,
        &account,
        capture_plan(&adapter, &account, 1).await,
    );
    wait_until("full-window capture is held", || {
        !relay.acquisitions.lock().unwrap().is_empty()
    })
    .await;
    assert_no_delivery(&adapter).await;
    assert_eq!(adapter.subscription_synced(&id).await, Some(false));
    for event in history.iter().rev().skip(12) {
        route_group_copy(&adapter, &group, &id, event).await;
    }
    adapter
        .handle_relay_eose(group.endpoints[0].clone(), id.clone())
        .await;
    let live = group_event_at("live behind queued history", &group, floor + 1_000);
    route_group_copy(&adapter, &group, &id, &live).await;
    assert_no_delivery(&adapter).await;
    assert_eq!(adapter.subscription_synced(&id).await, Some(false));
    relay.hold_acquisition.store(false, Ordering::SeqCst);
    relay.release_acquisition.notify_waiters();
    for event in history.iter().chain(std::iter::once(&live)) {
        assert_group_delivery(&adapter, &account, event).await;
    }
    assert_eq!(capture.await.unwrap(), ReplayCaptureOutcome::Complete);
    wait_replay_eose(&adapter, &id).await;
    assert_no_delivery(&adapter).await;
    assert_replay_idle(&adapter, &account).await;
}

/// A superseded activation's end-of-stored-events report must not satisfy the
/// replay gate the next activation opened.
///
/// Reactivation tears the previous REQs down, zeroes the account's replay
/// coverage, and re-issues. A relay's EOSE for a torn-down attempt can still be
/// in flight and land after that reset. It answered a different REQ — here the
/// `since`-floored live subscription, superseded by an unfloored history replay
/// over the same routes — so it is no evidence that the replay reached the end
/// of the relay's stored history.
#[tokio::test]
async fn superseded_activation_eose_does_not_satisfy_the_replay_gate() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone() as Arc<dyn NostrRelayClient>);
    let account_id = MemberId::new(vec![0xD4; 32]);
    let inbox = TransportEndpoint("wss://inbox.example".to_owned());
    let group_endpoint = TransportEndpoint("wss://group.example".to_owned());
    let group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![0x55; 16]),
        transport_group_id: vec![0x66; 32],
        endpoints: vec![group_endpoint.clone()],
        retained_since: None,
    };
    let activate = |since: Option<Timestamp>| {
        adapter.activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![inbox.clone()],
            group_subscriptions: vec![group.clone()],
            since,
        })
    };

    activate(Some(Timestamp(1_700_000_000)))
        .await
        .expect("floored activation succeeds");
    let superseded = relay.take_issued_subscriptions();
    assert!(
        superseded
            .iter()
            .all(|subscription| subscription_since(subscription).is_some()),
        "the superseded attempt must be the floored one"
    );

    activate(None).await.expect("unfloored replay succeeds");
    let replay = relay.take_issued_subscriptions();
    assert!(
        replay
            .iter()
            .all(|subscription| subscription_since(subscription).is_none()),
        "the replay attempt must be unfloored"
    );

    assert!(
        superseded
            .iter()
            .zip(&replay)
            .all(|(old, new)| old.attempt() != new.attempt()),
        "reactivation must re-issue under a new attempt"
    );

    let progress = adapter.account_subscription_eose(&account_id).await;
    assert_eq!(progress.subscriptions, 2);
    assert!(!progress.any(), "the replay has not been served yet");

    // The superseded attempt's buffered EOSEs are delivered after the reset.
    for subscription in &superseded {
        adapter
            .handle_relay_eose(
                subscription.endpoints()[0].clone(),
                subscription.subscription_id(),
            )
            .await;
    }
    let progress = adapter.account_subscription_eose(&account_id).await;
    assert!(
        !progress.any(),
        "an EOSE answering the superseded REQ is not replay evidence"
    );
    assert!(
        !progress.complete(),
        "a stale EOSE must not complete the unfloored replay gate"
    );

    // The live attempt's own reports still complete the gate.
    for subscription in &replay {
        adapter
            .handle_relay_eose(
                subscription.endpoints()[0].clone(),
                subscription.subscription_id(),
            )
            .await;
    }
    assert!(
        adapter
            .account_subscription_eose(&account_id)
            .await
            .complete(),
        "the replay attempt's own EOSEs complete its coverage"
    );
}

/// Abandoning an uncompleted replay must discard its staged events, not mark
/// them delivered: the replacement attempt still needs to replay them once.
/// A second endpoint that never answers must not freeze the available replay,
/// while strict account coverage remains incomplete for cursor promotion.
#[tokio::test(start_paused = true)]
async fn superseded_replay_is_dropped() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xD5; 32]);
    let endpoint = TransportEndpoint("wss://group.example".into());
    let group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![0x56; 16]),
        transport_group_id: vec![0x67; 32],
        endpoints: vec![
            endpoint.clone(),
            TransportEndpoint("wss://unavailable.example".into()),
        ],
        retained_since: None,
    };
    let activation = TransportAccountActivation {
        account_id: account.clone(),
        inbox_endpoints: vec![],
        group_subscriptions: vec![group.clone()],
        since: None,
    };
    adapter.activate_account(activation.clone()).await.unwrap();
    let old = issued_group_id(&relay.take_issued_subscriptions(), &group.group_id);
    let event = group_event("staged before reactivation", &group.transport_group_id);
    let old_event = NostrRelayEvent {
        endpoint: endpoint.clone(),
        subscription_id: Some(old.clone()),
        event: event.clone(),
    };
    adapter.observe_relay_event(&old_event).await;
    adapter.handle_relay_event(old_event).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(25), adapter.receive())
            .await
            .is_err(),
        "stored history is held until its replay range is known"
    );

    adapter.activate_account(activation).await.unwrap();
    let fresh = issued_group_id(&relay.take_issued_subscriptions(), &group.group_id);
    assert_ne!(old, fresh);
    adapter.handle_relay_eose(endpoint.clone(), old).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(25), adapter.receive())
            .await
            .is_err(),
        "a stale EOSE cannot release an abandoned buffer"
    );
    let fresh_event = NostrRelayEvent {
        endpoint: endpoint.clone(),
        subscription_id: Some(fresh.clone()),
        event: event.clone(),
    };
    adapter.observe_relay_event(&fresh_event).await;
    adapter.handle_relay_event(fresh_event).await.unwrap();
    adapter.handle_relay_eose(endpoint, fresh).await;
    assert_no_delivery(&adapter).await;
    expire_admission().await;
    let delivery = tokio::time::timeout(Duration::from_secs(1), adapter.receive())
        .await
        .expect("the current attempt releases its own replay")
        .unwrap()
        .unwrap();
    assert!(delivery.account_id == account);
    assert!(delivery.message.id == event.to_transport_message().unwrap().id);
    assert!(
        !adapter.account_subscription_eose(&account).await.complete(),
        "empty-peer expiry releases available history without certifying that peer"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(25), adapter.receive())
            .await
            .is_err(),
        "the abandoned attempt must not produce a duplicate"
    );
}

/// Deactivation does not close the relay sockets, so an EOSE for the
/// deactivated attempt can still arrive after the account is brought back up.
/// Signing out and back in must not hand the new activation's replay gate the
/// old attempt's evidence.
#[tokio::test]
async fn eose_from_a_deactivated_attempt_does_not_satisfy_the_next_activation() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone() as Arc<dyn NostrRelayClient>);
    let account_id = MemberId::new(vec![0xD5; 32]);
    let inbox = TransportEndpoint("wss://inbox.example".to_owned());
    let group_endpoint = TransportEndpoint("wss://group.example".to_owned());
    let group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![0x57; 16]),
        transport_group_id: vec![0x67; 32],
        endpoints: vec![group_endpoint.clone()],
        retained_since: None,
    };
    let activate = |since: Option<Timestamp>| {
        adapter.activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![inbox.clone()],
            group_subscriptions: vec![group.clone()],
            since,
        })
    };

    activate(Some(Timestamp(1_700_000_000)))
        .await
        .expect("first activation succeeds");
    let superseded = relay.take_issued_subscriptions();
    assert_eq!(superseded.len(), 2);

    adapter
        .deactivate_account(&account_id)
        .await
        .expect("deactivation succeeds");

    activate(None).await.expect("reactivation succeeds");
    let replay = relay.take_issued_subscriptions();
    assert_eq!(replay.len(), 2);

    for subscription in &superseded {
        adapter
            .handle_relay_eose(
                subscription.endpoints()[0].clone(),
                subscription.subscription_id(),
            )
            .await;
    }
    let progress = adapter.account_subscription_eose(&account_id).await;
    assert!(
        !progress.any(),
        "an EOSE for the deactivated attempt is not evidence for the new one"
    );
    assert!(!progress.complete());

    for subscription in &replay {
        adapter
            .handle_relay_eose(
                subscription.endpoints()[0].clone(),
                subscription.subscription_id(),
            )
            .await;
    }
    assert!(
        adapter
            .account_subscription_eose(&account_id)
            .await
            .complete(),
        "the new activation's own EOSEs complete its coverage"
    );
}

/// A failed activation rolls its local routes back, but REQs that already
/// reached a relay keep streaming. The retry must not inherit their EOSEs.
#[tokio::test]
async fn eose_from_a_rolled_back_activation_does_not_satisfy_the_retry() {
    let relay = Arc::new(PartialFailureRelayClient::default());
    relay.fail_group_subscribes.store(true, Ordering::SeqCst);
    let adapter = NostrTransportAdapter::new(relay.clone() as Arc<dyn NostrRelayClient>);
    let account_id = MemberId::new(vec![0xD6; 32]);
    let inbox = TransportEndpoint("wss://inbox.example".to_owned());
    let group_endpoint = TransportEndpoint("wss://group.example".to_owned());
    let group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![0x58; 16]),
        transport_group_id: vec![0x68; 32],
        endpoints: vec![group_endpoint.clone()],
        retained_since: None,
    };
    let activate = |since: Option<Timestamp>| {
        adapter.activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![inbox.clone()],
            group_subscriptions: vec![group.clone()],
            since,
        })
    };

    activate(Some(Timestamp(1_700_000_000)))
        .await
        .expect_err("the group REQ fails, so the activation is rolled back");
    let rolled_back = relay.take_issued_subscriptions();
    let stranded_inbox = rolled_back
        .iter()
        .find(|subscription| matches!(subscription, NostrSubscription::AccountInbox { .. }))
        .cloned()
        .expect("the inbox REQ reached the relay before the group REQ failed");

    relay.fail_group_subscribes.store(false, Ordering::SeqCst);
    activate(None).await.expect("the retry succeeds");
    let replay = relay.take_issued_subscriptions();
    assert_eq!(replay.len(), 2);

    adapter
        .handle_relay_eose(inbox.clone(), stranded_inbox.subscription_id())
        .await;
    let progress = adapter.account_subscription_eose(&account_id).await;
    assert!(
        !progress.any(),
        "the rolled-back attempt's stranded REQ is not evidence for the retry"
    );

    for subscription in &replay {
        adapter
            .handle_relay_eose(
                subscription.endpoints()[0].clone(),
                subscription.subscription_id(),
            )
            .await;
    }
    assert!(
        adapter
            .account_subscription_eose(&account_id)
            .await
            .complete(),
        "the retry's own EOSEs complete its coverage"
    );
}

fn subscription_since(subscription: &NostrSubscription) -> Option<Timestamp> {
    match subscription {
        NostrSubscription::AccountInbox { since, .. }
        | NostrSubscription::Group { since, .. }
        | NostrSubscription::GroupBatch { since, .. } => *since,
        NostrSubscription::GroupMaintenance { .. } => None,
    }
}

/// Cancelling the public notification future cannot cancel its staged handoff.
#[tokio::test(start_paused = true)]
async fn cancelled_live_is_owned() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0x64; 32]);
    let group = sync_fixture_group(0x73);
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let id = issued_group_id(&relay.take_issued_subscriptions(), &group.group_id);
    adapter
        .handle_relay_eose(group.endpoints[0].clone(), id.clone())
        .await;

    // Fill the adapter's 1,024-entry delivery queue without consuming it.
    // Every body is live on a group whose original replay was admitted.
    let queued = (0..1_024)
        .map(|index| group_event_at("queued live body", &group, floor + index))
        .collect::<Vec<_>>();
    for event in &queued {
        route_group_copy(&adapter, &group, &id, event).await;
    }
    let cancelled = group_event_at("cancelled live handoff", &group, floor + 1_024);
    let copy = NostrRelayEvent {
        endpoint: group.endpoints[0].clone(),
        subscription_id: Some(id),
        event: cancelled.clone(),
    };
    adapter.observe_relay_event(&copy).await;
    // Give background owners a turn and replenish the task's cooperative
    // budget, so the next poll reaches handoff rather than a budget yield.
    tokio::task::yield_now().await;
    let mut notification = Box::pin(adapter.handle_group_relay_copy(copy, None));
    let polled = poll_fn(|cx| Poll::Ready(notification.as_mut().poll(cx))).await;
    if let Poll::Ready(result) = polled {
        // An independent owner may accept the handoff without waiting for the
        // full public queue. Dropping this completed caller is also harmless.
        assert_eq!(result.unwrap(), 1);
    }
    drop(notification);

    for event in queued.iter().chain(std::iter::once(&cancelled)) {
        assert_group_delivery(&adapter, &account, event).await;
    }
    assert_no_delivery(&adapter).await;
    assert_replay_idle(&adapter, &account).await;
}

#[tokio::test(start_paused = true)]
async fn cancelled_epoch_keeps_owner_fence() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0x65; 32]);
    let group = sync_fixture_group(0x74);
    let endpoint = &group.endpoints[0];
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let id = issued_group_id(&relay.take_issued_subscriptions(), &group.group_id);
    adapter
        .observe_replay_epoch(
            Some(&account),
            endpoint,
            [1, 1],
            transport_nostr_adapter::ReplayRestart::Connection,
        )
        .await;
    adapter
        .handle_relay_eose(endpoint.clone(), id.clone())
        .await;
    let missing = group_event_at("capture survives cancelled metadata", &group, floor + 1);
    *relay.retained.lock().unwrap() =
        Some(vec![(account.clone(), endpoint.clone(), missing.clone())]);

    // Queue the metadata writer before a second status reader. The fair lock
    // lets metadata commit once, then holds any later write behind that reader.
    let before = adapter.take_replay_status(&account).await;
    let mut metadata = Box::pin(adapter.observe_replay_epoch(
        Some(&account),
        endpoint,
        [2, 1],
        transport_nostr_adapter::ReplayRestart::ReceiverLoss,
    ));
    assert!(
        poll_fn(|cx| Poll::Ready(metadata.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    let mut after = Box::pin(adapter.take_replay_status(&account));
    assert!(
        poll_fn(|cx| Poll::Ready(after.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    drop(before);
    if let Poll::Ready(accepted) = poll_fn(|cx| Poll::Ready(metadata.as_mut().poll(cx))).await {
        assert!(accepted);
    }
    let after = after.await;
    assert!(
        after.loss.is_none(),
        "metadata alone is not discarded ciphertext"
    );
    drop(metadata);
    drop(after);

    assert!(
        relay.acquisitions.lock().unwrap().is_empty(),
        "receiver fencing cannot launch IO"
    );
    let capture = spawn_capture(
        &adapter,
        &account,
        capture_plan(&adapter, &account, 1).await,
    );
    assert_group_delivery(&adapter, &account, &missing).await;
    assert_eq!(capture.await.unwrap(), ReplayCaptureOutcome::Complete);
    wait_replay_eose(&adapter, &id).await;
    assert_no_delivery(&adapter).await;
    assert_replay_idle(&adapter, &account).await;
}

#[tokio::test]
async fn live_suffix_reuses_budget() {
    let adapter = NostrTransportAdapter::new(Arc::new(FakeRelayClient::default()));
    let account = MemberId::new(vec![0x63; 32]);
    let mut group = sync_fixture_group(0x71);
    group.endpoints = (0..65)
        .map(|index| TransportEndpoint(format!("wss://replay-{index}.example")))
        .collect();
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: None,
        })
        .await
        .unwrap();
    let id = group_subscription_id(&adapter, &account, &group).await;
    let mut expected = Vec::new();
    for index in 0..32_000u64 {
        let mut event = group_event("stored", &group.transport_group_id);
        event.created_at += index;
        event.id = event.computed_id();
        expected.push(event.to_transport_message().unwrap().id);
        let event = NostrRelayEvent {
            endpoint: group.endpoints[(index / 499) as usize].clone(),
            subscription_id: Some(id.clone()),
            event,
        };
        adapter.observe_relay_event(&event).await;
        adapter.handle_relay_event(event).await.unwrap();
    }
    for endpoint in &group.endpoints {
        adapter
            .handle_relay_eose(endpoint.clone(), id.clone())
            .await;
    }
    let first = tokio::time::timeout(Duration::from_secs(5), adapter.receive())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.message.id, expected[0]);

    // The full historical batch is still blocked on its delivery channel.
    // Its identifiers must not spend the pending live suffix's allowance.
    let mut event = group_event("live suffix", &group.transport_group_id);
    event.created_at += 32_000;
    event.id = event.computed_id();
    expected.push(event.to_transport_message().unwrap().id);
    let event = NostrRelayEvent {
        endpoint: group.endpoints[0].clone(),
        subscription_id: Some(id),
        event,
    };
    adapter.observe_relay_event(&event).await;
    adapter.handle_relay_event(event).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        for id in expected.into_iter().skip(1) {
            assert_eq!(adapter.receive().await.unwrap().unwrap().message.id, id);
        }
    })
    .await
    .expect("the exact full replay is followed by the live message");
}

#[tokio::test]
async fn overflow_keeps_live_order() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0x91; 32]);
    let mut group = sync_fixture_group(0x92);
    group.endpoints = (0..5)
        .map(|index| TransportEndpoint(format!("wss://ordered-{index}.example")))
        .collect();
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: None,
        })
        .await
        .unwrap();
    let id = issued_group_id(&relay.take_issued_subscriptions(), &group.group_id);
    let mut expected = Vec::new();
    for index in 0..2_200 {
        let event = group_event_at(
            &format!("stored {index}"),
            &group,
            1_700_000_000 + index as u64,
        );
        let copy = NostrRelayEvent {
            endpoint: group.endpoints[index / 499].clone(),
            subscription_id: Some(id.clone()),
            event: event.clone(),
        };
        adapter.observe_relay_event(&copy).await;
        adapter.handle_group_relay_copy(copy, None).await.unwrap();
        expected.push(event);
    }
    for endpoint in &group.endpoints {
        adapter
            .handle_relay_eose(endpoint.clone(), id.clone())
            .await;
    }
    assert_group_delivery(&adapter, &account, &expected[0]).await;

    // The older batch is blocked on the adapter queue. Overflow only the live
    // suffix, then verify the next live event cannot jump ahead of that batch.
    let body = "x".repeat(3 * 1024 * 1024);
    let mut retained_live = Vec::new();
    let mut lost_live = false;
    for index in 0..11 {
        let event = group_event_at(&body, &group, 1_700_003_000 + index);
        route_group_copy(&adapter, &group, &id, &event).await;
        let status = adapter.take_replay_status(&account).await;
        if let Some(loss) = status.loss {
            assert_eq!(loss, NostrNotificationLossFloor::Unbounded);
            lost_live = true;
        } else {
            retained_live.push(event);
        }
    }
    assert!(lost_live, "the live suffix crosses its payload allowance");
    let live = group_event_at("after overflow", &group, 1_700_004_000);
    route_group_copy(&adapter, &group, &id, &live).await;
    for event in expected
        .iter()
        .skip(1)
        .chain(retained_live.iter())
        .chain(std::iter::once(&live))
    {
        assert_group_delivery(&adapter, &account, event).await;
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(25), adapter.receive())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn overlapping_replay_keeps_copy() {
    for finish_old in [false, true] {
        let relay = Arc::new(FakeRelayClient::default());
        let adapter = NostrTransportAdapter::new(relay.clone());
        let account = MemberId::new(vec![0x93; 32]);
        let group = sync_fixture_group(0x94);
        adapter
            .activate_account(TransportAccountActivation {
                account_id: account.clone(),
                inbox_endpoints: vec![],
                group_subscriptions: vec![group.clone()],
                since: Some(Timestamp(1_700_000_500)),
            })
            .await
            .unwrap();
        let live = issued_group_id(&relay.take_issued_subscriptions(), &group.group_id);
        adapter
            .handle_relay_eose(group.endpoints[0].clone(), live)
            .await;
        let first = adapter
            .install_group_maintenance_recovery_subscription(
                &account,
                &group,
                1,
                Some(Timestamp(1_700_000_000)),
            )
            .await
            .unwrap();
        let second = adapter
            .install_group_maintenance_recovery_subscription(
                &account,
                &group,
                2,
                Some(Timestamp(1_700_000_000)),
            )
            .await
            .unwrap();
        let event = group_event_at("both requests hold this ciphertext", &group, 1_700_000_100);
        route_group_copy(&adapter, &group, &first, &event).await;
        route_group_copy(&adapter, &group, &second, &event).await;
        if finish_old {
            adapter
                .handle_relay_eose(group.endpoints[0].clone(), first.clone())
                .await;
        }
        adapter
            .remove_group_maintenance_recovery_subscription(&account, &first)
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(25), adapter.receive())
                .await
                .is_err()
        );
        adapter
            .handle_relay_eose(group.endpoints[0].clone(), second.clone())
            .await;
        assert_group_delivery(&adapter, &account, &event).await;
        wait_replay_eose(&adapter, &second).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(25), adapter.receive())
                .await
                .is_err()
        );
        let status = adapter.take_replay_status(&account).await;
        assert!(
            status.loss.is_none(),
            "retiring one source loses no bytes while the other retains its copy"
        );
    }
}

#[tokio::test]
async fn oversized_replay_is_withheld() {
    // Keep every relay below a full page, so incomplete paging cannot mask
    // either buffer limit. The item case also stays below the byte allowance.
    for (items, payload_bytes) in [(32_001u64, 0usize), (12, 3 * 1024 * 1024)] {
        let relay = Arc::new(FakeRelayClient::default());
        let adapter = NostrTransportAdapter::new(relay);
        let account = MemberId::new(vec![0x63; 32]);
        let mut large = sync_fixture_group(0x71);
        large.endpoints = (0..items.div_ceil(499))
            .map(|index| TransportEndpoint(format!("wss://replay-{index}.example")))
            .collect();
        let mut small = sync_fixture_group(0x72);
        small.endpoints = vec![TransportEndpoint("wss://healthy.example".into())];
        adapter
            .activate_account(TransportAccountActivation {
                account_id: account.clone(),
                inbox_endpoints: vec![],
                group_subscriptions: vec![large.clone(), small.clone()],
                since: None,
            })
            .await
            .unwrap();
        let large_id = group_subscription_id(&adapter, &account, &large).await;
        let small_id = group_subscription_id(&adapter, &account, &small).await;
        let body = "x".repeat(payload_bytes);
        let abandoned = &large.endpoints[((items - 1) / 499) as usize];
        let mut expected = HashSet::new();
        for index in 0..items {
            let mut event = group_event(&body, &large.transport_group_id);
            event.created_at += index;
            event.id = event.computed_id();
            let endpoint = &large.endpoints[(index / 499) as usize];
            if endpoint != abandoned {
                expected.insert(event.to_transport_message().unwrap().id);
            }
            let event = NostrRelayEvent {
                endpoint: endpoint.clone(),
                subscription_id: Some(large_id.clone()),
                event,
            };
            adapter.observe_relay_event(&event).await;
            adapter.handle_relay_event(event).await.unwrap();
        }
        let event = group_event("healthy peer group", &small.transport_group_id);
        expected.insert(event.to_transport_message().unwrap().id);
        let event = NostrRelayEvent {
            endpoint: small.endpoints[0].clone(),
            subscription_id: Some(small_id.clone()),
            event,
        };
        adapter.observe_relay_event(&event).await;
        adapter.handle_relay_event(event).await.unwrap();
        for endpoint in &large.endpoints {
            adapter
                .handle_relay_eose(endpoint.clone(), large_id.clone())
                .await;
        }
        adapter
            .handle_relay_eose(small.endpoints[0].clone(), small_id)
            .await;
        tokio::time::timeout(Duration::from_secs(10), async {
            while !expected.is_empty() {
                let delivery = adapter.receive().await.unwrap().unwrap();
                assert_eq!(delivery.account_id, account);
                assert!(
                    expected.remove(&delivery.message.id),
                    "only completed owners may release their historical claims"
                );
                adapter
                    .ack_replay_delivery(&account, &delivery.message.id)
                    .await;
            }
        })
        .await
        .expect("all healthy source histories survive another source's overflow");
        assert!(!adapter.account_subscription_eose(&account).await.complete());
        assert!(
            tokio::time::timeout(Duration::from_millis(25), adapter.receive())
                .await
                .is_err(),
            "an abandoned source cannot admit its newer partial suffix"
        );
        assert!(adapter.take_replay_status(&account).await.loss.is_some());
        let live = group_event_at("live after replay saturation", &large, 1_700_100_000);
        route_group_copy(&adapter, &large, &large_id, &live).await;
        assert_group_delivery(&adapter, &account, &live).await;
        {
            let status = adapter.take_replay_status(&account).await;
            assert!(!status.pending);
            assert!(status.loss.is_none());
        }
        assert!(!adapter.account_subscription_eose(&account).await.complete());
    }
}

fn group_event(id_byte: &str, transport_group_id: &[u8]) -> NostrTransportEvent {
    // `to_transport_message` verifies the id against the event hash (#351), so
    // the distinguishing byte lives in the content and the id is computed from
    // it — distinct `id_byte` values still yield distinct event ids.
    let mut event = NostrTransportEvent {
        id: String::new(),
        pubkey: "22".repeat(32),
        created_at: 1_700_000_010,
        kind: KIND_MARMOT_GROUP_MESSAGE,
        tags: vec![vec!["h".into(), hex::encode(transport_group_id)]],
        content: format!("outer encrypted body {id_byte}"),
        sig: None,
    };
    event.id = event.computed_id();
    event
}

#[tokio::test]
async fn maintenance_replays_on_join() {
    let relay = Arc::new(StoredReplayRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    relay.attach(&adapter);
    let account_id = MemberId::new(vec![1; 32]);
    let group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![2; 16]),
        transport_group_id: vec![3; 32],
        endpoints: vec![TransportEndpoint("wss://group.example".into())],
        retained_since: None,
    };
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .unwrap();
    adapter
        .install_group_maintenance_subscription(&account_id, &group)
        .await
        .unwrap();
    assert_eq!(relay.replayed_deliveries.load(Ordering::SeqCst), 1);
    let delivery = adapter.receive().await.unwrap().unwrap();
    assert_eq!(delivery.account_id, account_id);
    assert_eq!(delivery.group_id_hint, Some(group.group_id.clone()));
    // An ordinary rebuild must retain the independent maintenance route.
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id: account_id.clone(),
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .unwrap();
    let event = NostrRelayEvent {
        endpoint: group.endpoints[0].clone(),
        subscription_id: None,
        event: group_event("31", &group.transport_group_id),
    };
    assert_eq!(adapter.handle_relay_event(event.clone()).await.unwrap(), 1);
    adapter
        .remove_group_maintenance_subscription(NostrSubscription::GroupMaintenance {
            account_id,
            group_id: group.group_id,
            transport_group_id: group.transport_group_id,
            endpoints: group.endpoints,
            since: None,
        })
        .await
        .unwrap();
    assert_eq!(adapter.handle_relay_event(event).await.unwrap(), 0);
}

#[tokio::test]
async fn maintenance_failure_cleans_up() {
    let relay = Arc::new(PartialFailureRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![1; 32]);
    let group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![2; 16]),
        transport_group_id: vec![3; 32],
        endpoints: vec![TransportEndpoint("wss://group.example".into())],
        retained_since: None,
    };
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .unwrap();
    relay.fail_group_subscribes.store(true, Ordering::SeqCst);
    assert!(
        adapter
            .install_group_maintenance_subscription(&account_id, &group)
            .await
            .is_err()
    );
    let subscription_id = NostrSubscription::GroupMaintenance {
        account_id: account_id.clone(),
        group_id: group.group_id.clone(),
        transport_group_id: group.transport_group_id.clone(),
        endpoints: group.endpoints.clone(),
        since: None,
    }
    .subscription_id();
    let event = NostrRelayEvent {
        endpoint: group.endpoints[0].clone(),
        subscription_id: Some(subscription_id.clone()),
        event: group_event("31", &group.transport_group_id),
    };
    assert_eq!(adapter.handle_relay_event(event.clone()).await.unwrap(), 0);
    relay.fail_group_subscribes.store(false, Ordering::SeqCst);
    adapter
        .install_group_maintenance_subscription(&account_id, &group)
        .await
        .unwrap();
    adapter.observe_relay_event(&event).await;
    assert_eq!(adapter.handle_relay_event(event.clone()).await.unwrap(), 1);
    assert_no_delivery(&adapter).await;
    adapter
        .handle_relay_eose(group.endpoints[0].clone(), subscription_id.clone())
        .await;
    assert_group_delivery(&adapter, &account_id, &event.event).await;
    for group_subscriptions in [Some(vec![]), None] {
        adapter
            .install_group_maintenance_subscription(&account_id, &group)
            .await
            .unwrap();
        adapter
            .handle_relay_eose(group.endpoints[0].clone(), subscription_id.clone())
            .await;
        assert_eq!(
            adapter.subscription_synced(&subscription_id).await,
            Some(true)
        );
        if let Some(group_subscriptions) = group_subscriptions {
            adapter
                .activate_account(TransportAccountActivation {
                    account_id: account_id.clone(),
                    inbox_endpoints: vec![],
                    group_subscriptions,
                    since: None,
                })
                .await
                .unwrap();
        } else {
            adapter.deactivate_account(&account_id).await.unwrap();
        }
        assert_eq!(adapter.subscription_synced(&subscription_id).await, None);
        assert_eq!(adapter.subscription_any_eose(&subscription_id).await, None);
    }
    assert_eq!(adapter.handle_relay_event(event).await.unwrap(), 0);
}

#[tokio::test]
async fn maintenance_cancel_cleans_up() {
    let relay = Arc::new(BlockingSubscribeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![1; 32]);
    let group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![2; 16]),
        transport_group_id: vec![3; 32],
        endpoints: vec![TransportEndpoint("wss://group.example".into())],
        retained_since: None,
    };
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .unwrap();
    relay.block_subscribes.store(true, Ordering::SeqCst);
    let pending = tokio::spawn({
        let adapter = adapter.clone();
        let account = account_id.clone();
        let group = group.clone();
        async move {
            adapter
                .install_group_maintenance_subscription(&account, &group)
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), relay.started.notified())
        .await
        .unwrap();
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    relay.block_subscribes.store(false, Ordering::SeqCst);
    // Acquiring the lifecycle lock also waits for cancellation cleanup.
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id,
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .unwrap();
    assert_eq!(
        adapter
            .handle_relay_event(NostrRelayEvent {
                endpoint: group.endpoints[0].clone(),
                subscription_id: None,
                event: group_event("31", &group.transport_group_id),
            })
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn maintenance_teardown_retries() {
    let relay = Arc::new(FlakyUnsubscribeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![1; 32]);
    let group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![2; 16]),
        transport_group_id: vec![3; 32],
        endpoints: vec![TransportEndpoint("wss://group.example".into())],
        retained_since: None,
    };
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .unwrap();
    let subscription = NostrSubscription::GroupMaintenance {
        account_id: account_id.clone(),
        group_id: group.group_id.clone(),
        transport_group_id: group.transport_group_id.clone(),
        endpoints: group.endpoints.clone(),
        since: None,
    };
    // A plain retry drains the teardown; reinstalling first must preserve it.
    for reinstall in [None, Some(&group)] {
        let id = adapter
            .install_group_maintenance_subscription(&account_id, &group)
            .await
            .unwrap();
        relay.fail_next_unsubscribes.store(1, Ordering::SeqCst);
        assert!(
            adapter
                .remove_group_maintenance_subscription(subscription.clone())
                .await
                .is_err()
        );
        assert_eq!(adapter.subscription_synced(&id).await, None);
        assert_eq!(adapter.subscription_any_eose(&id).await, None);
        assert_eq!(adapter.metrics().await.unsubscribe_retries_pending, 1);
        let event = NostrRelayEvent {
            endpoint: group.endpoints[0].clone(),
            subscription_id: None,
            event: group_event("31", &group.transport_group_id),
        };
        assert_eq!(adapter.handle_relay_event(event.clone()).await.unwrap(), 0);
        if let Some(group) = reinstall {
            adapter
                .install_group_maintenance_subscription(&account_id, group)
                .await
                .unwrap();
        }
        adapter
            .sync_account_groups(TransportGroupSync {
                account_id: account_id.clone(),
                group_subscriptions: vec![],
                since: None,
            })
            .await
            .unwrap();
        assert_eq!(adapter.metrics().await.unsubscribe_retries_pending, 0);
        assert_eq!(
            relay.unsubscribed.lock().unwrap().as_slice(),
            std::slice::from_ref(&subscription)
        );
        assert_eq!(
            adapter.handle_relay_event(event).await.unwrap(),
            usize::from(reinstall.is_some())
        );
    }
}

#[tokio::test]
async fn recovery_maintenance_fences_late_eose_and_retries_exact_teardown() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![1; 32]);
    let first = TransportEndpoint("wss://first.example".into());
    let second = TransportEndpoint("wss://second.example".into());
    let group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![2; 16]),
        transport_group_id: vec![3; 32],
        endpoints: vec![first.clone(), second.clone()],
        retained_since: None,
    };
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .unwrap();
    let old = adapter
        .install_group_maintenance_recovery_subscription(&account, &group, 1, None)
        .await
        .unwrap();
    assert_eq!(relay.scoped.lock().unwrap()[0].0, old);
    adapter.handle_relay_eose(first.clone(), old.clone()).await;
    assert_eq!(
        adapter.subscription_endpoint_eose(&old, &first).await,
        Some(true)
    );
    assert_eq!(
        adapter.subscription_endpoint_eose(&old, &second).await,
        Some(false)
    );
    assert_eq!(
        adapter
            .subscription_endpoint_eose(&old, &TransportEndpoint("wss://unknown.example".into()))
            .await,
        None
    );
    relay.fail_scoped_remove.store(true, Ordering::SeqCst);
    assert!(
        adapter
            .remove_group_maintenance_recovery_subscription(&account, &old)
            .await
            .is_err()
    );
    assert_eq!(adapter.metrics().await.unsubscribe_retries_pending, 1);
    let fresh = adapter
        .install_group_maintenance_recovery_subscription(&account, &group, 2, None)
        .await
        .unwrap();
    assert_ne!(fresh, old);
    adapter.handle_relay_eose(second.clone(), old.clone()).await;
    assert_eq!(
        adapter.subscription_endpoint_eose(&fresh, &second).await,
        Some(false)
    );
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id: account.clone(),
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .unwrap();
    assert_eq!(adapter.metrics().await.unsubscribe_retries_pending, 0);
    assert_eq!(*relay.scoped_removed.lock().unwrap(), vec![old]);
    adapter
        .handle_relay_eose(second.clone(), fresh.clone())
        .await;
    assert_eq!(
        adapter.subscription_endpoint_eose(&fresh, &second).await,
        Some(true)
    );
    assert_eq!(
        adapter.subscription_endpoint_eose(&fresh, &first).await,
        Some(false)
    );
    assert!(
        adapter
            .remove_group_maintenance_recovery_subscription(&MemberId::new(vec![9; 32]), &fresh)
            .await
            .is_err()
    );
    assert_eq!(
        adapter.subscription_endpoint_eose(&fresh, &second).await,
        Some(true)
    );
    adapter
        .remove_group_maintenance_recovery_subscription(&account, &fresh)
        .await
        .unwrap();
    assert_eq!(
        adapter.subscription_endpoint_eose(&fresh, &second).await,
        None
    );
}

#[tokio::test]
async fn recovery_maintenance_req_carries_the_callers_history_floor() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![1; 32]);
    let group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![2; 16]),
        transport_group_id: vec![3; 32],
        endpoints: vec![TransportEndpoint("wss://group.example".into())],
        retained_since: None,
    };
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .unwrap();
    relay.take_issued_subscriptions();

    let floor = Some(Timestamp(1_700_000_000));
    let id = adapter
        .install_group_maintenance_recovery_subscription(&account, &group, 1, floor)
        .await
        .unwrap();
    let scoped = relay.scoped.lock().unwrap().clone();
    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0].0, id);
    assert!(
        matches!(
            &scoped[0].1,
            NostrSubscription::GroupMaintenance { since, .. } if *since == floor
        ),
        "the maintenance REQ is floored where the caller anchored it"
    );

    // The floor never reaches the id: the same session keeps its id.
    let base = NostrSubscription::GroupMaintenance {
        account_id: account.clone(),
        group_id: group.group_id.clone(),
        transport_group_id: group.transport_group_id.clone(),
        endpoints: group.endpoints.clone(),
        since: None,
    };
    assert_eq!(
        NostrSubscription::GroupMaintenance {
            account_id: account.clone(),
            group_id: group.group_id.clone(),
            transport_group_id: group.transport_group_id.clone(),
            endpoints: group.endpoints.clone(),
            since: floor,
        }
        .subscription_id(),
        base.subscription_id()
    );

    // The legacy install keeps its full-history request.
    adapter
        .install_group_maintenance_subscription(&account, &group)
        .await
        .unwrap();
    assert!(matches!(
        relay.take_issued_subscriptions().last(),
        Some(NostrSubscription::GroupMaintenance { since: None, .. })
    ));
}

#[tokio::test]
async fn unsupported_recovery_maintenance_never_stages_or_queues_teardown() {
    let relay = Arc::new(ConcurrentSubscribeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![1; 32]);
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![],
            since: None,
        })
        .await
        .unwrap();
    let group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![2; 16]),
        transport_group_id: vec![3; 32],
        endpoints: vec![TransportEndpoint("wss://relay.example".into())],
        retained_since: None,
    };
    let before = relay.started.load(Ordering::SeqCst);
    for attempt in 1..=3 {
        assert!(
            adapter
                .install_group_maintenance_recovery_subscription(&account, &group, attempt, None)
                .await
                .is_err()
        );
    }
    assert_eq!(relay.started.load(Ordering::SeqCst), before);
    assert_eq!(adapter.metrics().await.unsubscribe_retries_pending, 0);
}

#[tokio::test]
async fn recovery_maintenance_never_reopens_a_consumed_attempt() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![1; 32]);
    let endpoint = TransportEndpoint("wss://relay.example".into());
    let group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![2; 16]),
        transport_group_id: vec![3; 32],
        endpoints: vec![endpoint.clone()],
        retained_since: None,
    };
    let activation = TransportAccountActivation {
        account_id: account.clone(),
        inbox_endpoints: vec![],
        group_subscriptions: vec![],
        since: None,
    };
    adapter.activate_account(activation.clone()).await.unwrap();
    let id = adapter
        .install_group_maintenance_recovery_subscription(&account, &group, 7, None)
        .await
        .unwrap();
    assert!(id.starts_with("marmot:maintenance-recovery:"));
    assert!(id.len() <= 64);
    adapter
        .handle_relay_eose(endpoint.clone(), id.clone())
        .await;
    assert_eq!(
        adapter
            .install_group_maintenance_recovery_subscription(&account, &group, 7, None)
            .await
            .unwrap(),
        id
    );
    assert_eq!(
        relay.scoped.lock().unwrap().len(),
        1,
        "live join must not issue another REQ"
    );
    assert_eq!(
        adapter.subscription_endpoint_eose(&id, &endpoint).await,
        Some(true)
    );
    relay.fail_scoped_remove.store(true, Ordering::SeqCst);
    assert!(
        adapter
            .remove_group_maintenance_recovery_subscription(&account, &id)
            .await
            .is_err()
    );
    assert!(
        adapter
            .install_group_maintenance_recovery_subscription(&account, &group, 7, None)
            .await
            .is_err()
    );
    assert_eq!(
        adapter.metrics().await.unsubscribe_retries_pending,
        1,
        "failed reuse must preserve exact CLOSE intent"
    );
    adapter
        .handle_relay_eose(endpoint.clone(), id.clone())
        .await;
    assert_eq!(
        adapter.subscription_endpoint_eose(&id, &endpoint).await,
        None
    );
    adapter
        .remove_group_maintenance_recovery_subscription(&account, &id)
        .await
        .unwrap();
    assert!(
        adapter
            .install_group_maintenance_recovery_subscription(&account, &group, 7, None)
            .await
            .is_err()
    );
    adapter.activate_account(activation).await.unwrap();
    assert!(
        adapter
            .install_group_maintenance_recovery_subscription(&account, &group, 6, None)
            .await
            .is_err()
    );
    let fresh = adapter
        .install_group_maintenance_recovery_subscription(&account, &group, 8, None)
        .await
        .unwrap();
    adapter.handle_relay_eose(endpoint.clone(), id).await;
    assert_eq!(
        adapter.subscription_endpoint_eose(&fresh, &endpoint).await,
        Some(false)
    );
}

fn refusal(
    category: Option<TransportEndpointRejectionCategory>,
    disposition: SubscriptionRefusalDisposition,
) -> SubscriptionRefusal {
    SubscriptionRefusal {
        category,
        disposition,
    }
}

/// A relay that CLOSEs a live REQ answers it. A dropped refusal settles that
/// relay's attempt so a drain can stop waiting for it, but never completes
/// the replay: only EOSE is evidence that stored history was served. A
/// pending refusal is a REQ the relay client keeps and re-sends after AUTH,
/// so it still awaits EOSE, and that EOSE counts when it arrives.
#[tokio::test]
async fn relay_closed_settles_coverage_without_completing_it() {
    use SubscriptionRefusalDisposition::{Dropped, Pending};
    use TransportEndpointRejectionCategory::{AuthRequired, Restricted};

    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let account_id = MemberId::new(vec![0xD4; 32]);
    let inbox_a = TransportEndpoint("wss://inbox-a.example".to_owned());
    let inbox_b = TransportEndpoint("wss://inbox-b.example".to_owned());
    let group_endpoint = TransportEndpoint("wss://group.example".to_owned());
    let group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![0x55; 16]),
        transport_group_id: vec![0x66; 32],
        endpoints: vec![group_endpoint.clone()],
        retained_since: None,
    };
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![inbox_a.clone(), inbox_b.clone()],
            group_subscriptions: vec![group.clone()],
            since: None,
        })
        .await
        .expect("activation succeeds");
    let attempt = adapter
        .account_subscription_attempt(&account_id)
        .await
        .expect("the account is active");
    let inbox_id = NostrSubscription::AccountInbox {
        account_id: account_id.clone(),
        endpoints: vec![inbox_a.clone(), inbox_b.clone()],
        since: None,
        attempt,
    }
    .subscription_id();
    let group_id = group_subscription_id(&adapter, &account_id, &group).await;

    adapter
        .handle_relay_eose(inbox_a.clone(), inbox_id.clone())
        .await;
    // Relay B asks for AUTH. The relay client keeps the REQ, so B still owes
    // the replay.
    adapter
        .handle_relay_closed(
            inbox_b.clone(),
            inbox_id.clone(),
            refusal(Some(AuthRequired), Pending),
        )
        .await;
    let progress = adapter.account_subscription_eose(&account_id).await;
    assert_eq!(progress.relay_subscription_attempts_refused, 0);
    assert!(!progress.settled(), "a pending refusal still awaits EOSE");

    // After AUTH the client re-sends and B serves its history.
    adapter
        .handle_relay_eose(inbox_b.clone(), inbox_id.clone())
        .await;
    let progress = adapter.account_subscription_eose(&account_id).await;
    assert_eq!(progress.relay_subscription_attempts_with_eose, 2);
    assert!(!progress.settled(), "the group relay has not answered");

    // The group relay refuses for good.
    adapter
        .handle_relay_closed(
            group_endpoint.clone(),
            group_id.clone(),
            refusal(Some(Restricted), Dropped),
        )
        .await;
    let progress = adapter.account_subscription_eose(&account_id).await;
    assert_eq!(progress.relay_subscription_attempts, 3);
    assert_eq!(progress.relay_subscription_attempts_with_eose, 2);
    assert_eq!(progress.relay_subscription_attempts_refused, 1);
    assert_eq!(
        progress.subscriptions_refused, 1,
        "every relay of the group subscription refused it"
    );
    assert!(progress.settled(), "every relay has answered");
    assert!(
        !progress.complete(),
        "a refusal is not evidence that history was served"
    );

    // A late CLOSED after EOSE ends the live REQ but cannot take back the
    // replay that relay already served.
    adapter
        .handle_relay_closed(inbox_a.clone(), inbox_id.clone(), refusal(None, Dropped))
        .await;
    let progress = adapter.account_subscription_eose(&account_id).await;
    assert_eq!(progress.relay_subscription_attempts_with_eose, 2);
    assert_eq!(progress.relay_subscription_attempts_refused, 1);
}

/// A CLOSED for an id the adapter does not hold live, such as a superseded
/// attempt's REQ or a one-shot fetch, changes no coverage and is not
/// reported: one-shot fetches report their own closes.
#[tokio::test]
async fn relay_closed_for_an_unknown_subscription_is_ignored() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let account_id = MemberId::new(vec![0xD5; 32]);
    let inbox = TransportEndpoint("wss://inbox.example".to_owned());
    let activate = || {
        adapter.activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![inbox.clone()],
            group_subscriptions: Vec::new(),
            since: None,
        })
    };
    activate().await.expect("activation succeeds");
    let superseded = adapter
        .account_subscription_attempt(&account_id)
        .await
        .expect("the account is active");
    activate().await.expect("reactivation succeeds");
    let superseded_id = NostrSubscription::AccountInbox {
        account_id: account_id.clone(),
        endpoints: vec![inbox.clone()],
        since: None,
        attempt: superseded,
    }
    .subscription_id();

    for id in [superseded_id, "one-shot-fetch".to_owned()] {
        adapter
            .handle_relay_closed(
                inbox.clone(),
                id,
                refusal(
                    Some(TransportEndpointRejectionCategory::Blocked),
                    SubscriptionRefusalDisposition::Dropped,
                ),
            )
            .await;
    }
    let progress = adapter.account_subscription_eose(&account_id).await;
    assert_eq!(progress.relay_subscription_attempts_refused, 0);
    assert!(!progress.settled());
    assert!(
        adapter
            .take_subscription_refusals(&account_id)
            .reports
            .is_empty()
    );
    assert!(adapter.relay_sync().await.refusals.is_empty());
}

/// Refusals reach diagnostics two ways. Telemetry keeps cumulative counts
/// keyed by opaque relay index, route kind, category and disposition. The
/// forensic report is drained per account: repeats of one refusal coalesce
/// into one entry with a count, and the queue is bounded, counting what it
/// sheds.
#[tokio::test]
async fn relay_closed_reaches_telemetry_and_per_account_reports() {
    use SubscriptionRefusalDisposition::{Dropped, Pending};
    use TransportEndpointRejectionCategory::{AuthRequired, RateLimited};

    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay);
    let account_id = MemberId::new(vec![0xD6; 32]);
    let inbox = TransportEndpoint("wss://inbox.example".to_owned());
    let group_endpoint = TransportEndpoint("wss://group.example".to_owned());
    let group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![0x77; 16]),
        transport_group_id: vec![0x88; 32],
        endpoints: vec![group_endpoint.clone()],
        retained_since: None,
    };
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![inbox.clone()],
            group_subscriptions: vec![group.clone()],
            since: None,
        })
        .await
        .expect("activation succeeds");
    let attempt = adapter
        .account_subscription_attempt(&account_id)
        .await
        .expect("the account is active");
    let inbox_id = NostrSubscription::AccountInbox {
        account_id: account_id.clone(),
        endpoints: vec![inbox.clone()],
        since: None,
        attempt,
    }
    .subscription_id();
    let group_id = group_subscription_id(&adapter, &account_id, &group).await;

    for _ in 0..2 {
        adapter
            .handle_relay_closed(
                inbox.clone(),
                inbox_id.clone(),
                refusal(Some(AuthRequired), Pending),
            )
            .await;
    }
    adapter
        .handle_relay_closed(
            group_endpoint.clone(),
            group_id.clone(),
            refusal(Some(RateLimited), Pending),
        )
        .await;
    adapter
        .handle_relay_closed(
            group_endpoint.clone(),
            group_id.clone(),
            refusal(None, Dropped),
        )
        .await;

    let reports = adapter.take_subscription_refusals(&account_id);
    assert_eq!(reports.dropped, 0);
    assert_eq!(
        reports.reports,
        vec![
            SubscriptionRefusalReport {
                route_kind: SubscriptionRouteKind::Inbox,
                endpoint: inbox.clone(),
                category: Some(AuthRequired),
                disposition: Pending,
                count: 2,
            },
            SubscriptionRefusalReport {
                route_kind: SubscriptionRouteKind::Group,
                endpoint: group_endpoint.clone(),
                category: Some(RateLimited),
                disposition: Pending,
                count: 1,
            },
            SubscriptionRefusalReport {
                route_kind: SubscriptionRouteKind::Group,
                endpoint: group_endpoint.clone(),
                category: None,
                disposition: Dropped,
                count: 1,
            },
        ],
        "reports keep arrival order and coalesce repeats"
    );
    assert!(
        adapter
            .take_subscription_refusals(&account_id)
            .reports
            .is_empty(),
        "a drained report is not reported again"
    );

    let sync = adapter.relay_sync().await;
    let total: u64 = sync.refusals.iter().map(|stats| stats.count).sum();
    assert_eq!(total, 4, "telemetry counts every refusal");
    let inbox_stats = sync
        .refusals
        .iter()
        .find(|stats| stats.route_kind == SubscriptionRouteKind::Inbox)
        .expect("inbox refusals are counted");
    assert_eq!(inbox_stats.category, Some(AuthRequired));
    assert_eq!(inbox_stats.disposition, Pending);
    assert_eq!(inbox_stats.count, 2);
    let serialized = serde_json::to_string(&sync).expect("snapshot serializes");
    assert!(
        !serialized.contains("example"),
        "telemetry carries no relay endpoint"
    );

    // Many distinct refusals overflow the bounded queue; the excess is
    // counted rather than kept.
    for index in 0..(SUBSCRIPTION_REFUSAL_REPORT_LIMIT + 3) {
        let group = TransportGroupSubscription {
            group_id: cgka_traits::GroupId::new(vec![0x77; 16]),
            transport_group_id: vec![0x88; 32],
            endpoints: vec![TransportEndpoint(format!("wss://group-{index}.example"))],
            retained_since: None,
        };
        adapter
            .sync_account_groups(TransportGroupSync {
                account_id: account_id.clone(),
                group_subscriptions: vec![group.clone()],
                since: None,
            })
            .await
            .expect("group sync succeeds");
        let id = group_subscription_id(&adapter, &account_id, &group).await;
        adapter
            .handle_relay_closed(group.endpoints[0].clone(), id, refusal(None, Dropped))
            .await;
    }
    let reports = adapter.take_subscription_refusals(&account_id);
    assert_eq!(reports.reports.len(), SUBSCRIPTION_REFUSAL_REPORT_LIMIT);
    assert_eq!(reports.dropped, 3);
}

/// Refuses every group REQ with a dropped `CLOSED` before `subscribe`
/// returns, the way a fast relay answers while the rest of a batch is still
/// being sent.
#[derive(Default)]
struct RefusingGroupRelayClient {
    adapter: Mutex<Option<NostrTransportAdapter>>,
}

#[async_trait]
impl NostrRelayClient for RefusingGroupRelayClient {
    async fn subscribe(
        &self,
        subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        let (NostrSubscription::Group { endpoints, .. }
        | NostrSubscription::GroupBatch { endpoints, .. }) = &subscription
        else {
            return Ok(());
        };
        let adapter = self.adapter.lock().unwrap().clone();
        if let Some(adapter) = adapter {
            adapter
                .handle_relay_closed(
                    endpoints[0].clone(),
                    subscription.subscription_id(),
                    refusal(
                        Some(TransportEndpointRejectionCategory::Restricted),
                        SubscriptionRefusalDisposition::Dropped,
                    ),
                )
                .await;
        }
        Ok(())
    }

    async fn unsubscribe(
        &self,
        _subscription: transport_nostr_adapter::NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        _account_id: &MemberId,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        Ok(())
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        _event: &NostrTransportEvent,
        _required_acks: usize,
    ) -> Result<NostrPublishOutcome, cgka_traits::TransportAdapterError> {
        Ok(NostrPublishOutcome::accepted(endpoints.to_vec()))
    }
}

/// A group sync stages its new routes before the REQs go out and commits
/// them only after every subscribe returns. A relay that refuses a new group
/// REQ inside that window is still refusing a live REQ: the refusal must
/// reach telemetry and the account's reports, because a dropped REQ sends
/// nothing more once the batch commits.
#[tokio::test]
async fn relay_closed_during_group_sync_subscribe_is_recorded() {
    let relay = Arc::new(RefusingGroupRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    *relay.adapter.lock().unwrap() = Some(adapter.clone());
    let account_id = MemberId::new(vec![0xD7; 32]);
    let group_endpoint = TransportEndpoint("wss://group.example".to_owned());
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".to_owned())],
            group_subscriptions: Vec::new(),
            since: None,
        })
        .await
        .expect("activation succeeds");
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id: account_id.clone(),
            group_subscriptions: vec![TransportGroupSubscription {
                group_id: cgka_traits::GroupId::new(vec![0x99; 16]),
                transport_group_id: vec![0xAA; 32],
                endpoints: vec![group_endpoint.clone()],
                retained_since: None,
            }],
            since: None,
        })
        .await
        .expect("group sync succeeds");

    let reports = adapter.take_subscription_refusals(&account_id);
    assert_eq!(
        reports.reports,
        vec![SubscriptionRefusalReport {
            route_kind: SubscriptionRouteKind::Group,
            endpoint: group_endpoint,
            category: Some(TransportEndpointRejectionCategory::Restricted),
            disposition: SubscriptionRefusalDisposition::Dropped,
            count: 1,
        }]
    );
    let sync = adapter.relay_sync().await;
    assert_eq!(sync.refusals.len(), 1);
    assert_eq!(sync.refusals[0].route_kind, SubscriptionRouteKind::Group);
}

/// Subscribe calls that stay blocked until `release` fires while `hold` is set,
/// and records every per-subscription unsubscribe.
#[derive(Default)]
struct ReleasableSubscribeRelayClient {
    hold: AtomicBool,
    held: AtomicUsize,
    release: Notify,
    /// Held subscribes that have been released and returned.
    released: AtomicUsize,
    unsubscribed: Mutex<Vec<String>>,
    /// Every successful subscribe (`+id`) and unsubscribe (`-id`), in order.
    log: Mutex<Vec<String>>,
    /// While set, unsubscribes wait for `release_unsubscribes`.
    hold_unsubscribes: AtomicBool,
    unsubscribes_held: AtomicUsize,
    release_unsubscribes: Notify,
    /// When set, `unsubscribe_account` releases every held subscribe and
    /// waits until they have returned before it does.
    release_during_sweep: AtomicBool,
}

#[async_trait]
impl NostrRelayClient for ReleasableSubscribeRelayClient {
    async fn subscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        if self.hold.load(Ordering::SeqCst) {
            let released = self.release.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            self.held.fetch_add(1, Ordering::SeqCst);
            released.await;
            self.released.fetch_add(1, Ordering::SeqCst);
        }
        self.log
            .lock()
            .unwrap()
            .push(format!("+{}", subscription.subscription_id()));
        Ok(())
    }

    async fn unsubscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        if self.hold_unsubscribes.load(Ordering::SeqCst) {
            let released = self.release_unsubscribes.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            self.unsubscribes_held.fetch_add(1, Ordering::SeqCst);
            released.await;
        }
        let id = subscription.subscription_id();
        self.log.lock().unwrap().push(format!("-{id}"));
        self.unsubscribed.lock().unwrap().push(id);
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        _account_id: &MemberId,
    ) -> Result<(), cgka_traits::TransportAdapterError> {
        if self.release_during_sweep.swap(false, Ordering::SeqCst) {
            let held = self.held.load(Ordering::SeqCst);
            self.release.notify_waiters();
            while self.released.load(Ordering::SeqCst) < held {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        Ok(())
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        _event: &NostrTransportEvent,
        _required_acks: usize,
    ) -> Result<NostrPublishOutcome, cgka_traits::TransportAdapterError> {
        Ok(NostrPublishOutcome::accepted(endpoints.to_vec()))
    }
}

/// A dropped activation detaches its subscribe tasks. When one outlives the
/// next activation's straggler wait, that activation retires the barrier and
/// sweeps without it, so the task must close the REQ it registers afterwards
/// itself (#2262).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscribe_tasks_outliving_the_straggler_wait_close_their_reqs() {
    let relay = Arc::new(ReleasableSubscribeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let inbox = TransportEndpoint("wss://inbox.example".into());
    let group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![0xB2; 32]),
        transport_group_id: vec![0xC3; 32],
        endpoints: vec![TransportEndpoint("wss://group.example".into())],
        retained_since: None,
    };
    let activation = || TransportAccountActivation {
        account_id: account_id.clone(),
        inbox_endpoints: vec![inbox.clone()],
        group_subscriptions: vec![group.clone()],
        since: None,
    };

    relay.hold.store(true, Ordering::SeqCst);
    let dropped = tokio::spawn({
        let adapter = adapter.clone();
        let activation = activation();
        async move { adapter.activate_account(activation).await }
    });
    tokio::time::timeout(concurrent_subscribe_timeout(), async {
        while relay.held.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("both subscribes are held");
    dropped.abort();
    assert!(dropped.await.unwrap_err().is_cancelled());

    relay.hold.store(false, Ordering::SeqCst);
    adapter
        .activate_account(activation())
        .await
        .expect("the next activation proceeds after the straggler wait");
    assert!(relay.unsubscribed.lock().unwrap().is_empty());

    relay.release.notify_waiters();
    tokio::time::timeout(concurrent_subscribe_timeout(), async {
        while relay.unsubscribed.lock().unwrap().len() < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the late subscribes close their own REQs");

    let attempt = adapter
        .account_subscription_attempt(&account_id)
        .await
        .expect("the account is active");
    let live = [
        NostrSubscription::AccountInbox {
            account_id: account_id.clone(),
            endpoints: vec![inbox],
            since: None,
            attempt,
        }
        .subscription_id(),
        group_subscription_id(&adapter, &account_id, &group).await,
    ];
    let unsubscribed = relay.unsubscribed.lock().unwrap().clone();
    assert_eq!(unsubscribed.len(), 2, "{unsubscribed:?}");
    assert!(
        unsubscribed.iter().all(|id| !live.contains(id)),
        "only the superseded attempt's REQs are closed"
    );
}

async fn wait_until(what: &str, condition: impl Fn() -> bool) {
    tokio::time::timeout(concurrent_subscribe_timeout(), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting until {what}"));
}

fn sync_fixture_group(byte: u8) -> TransportGroupSubscription {
    TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![byte; 32]),
        transport_group_id: vec![byte.wrapping_add(1); 32],
        endpoints: vec![TransportEndpoint("wss://group.example".into())],
        retained_since: None,
    }
}

/// The id of the live batch REQ carrying `group`'s route.
async fn group_subscription_id(
    adapter: &NostrTransportAdapter,
    account_id: &MemberId,
    group: &TransportGroupSubscription,
) -> String {
    adapter
        .group_route_subscription_id(account_id, &group.transport_group_id)
        .await
        .expect("a live batch carries the group's route")
}

/// The id of the account's batch number `batch` over `endpoints` in its
/// current attempt. A batch id leaves out the routes and `since`, so it can be
/// predicted before the batch goes out.
async fn batch_subscription_id(
    adapter: &NostrTransportAdapter,
    account_id: &MemberId,
    endpoints: &[TransportEndpoint],
    batch: u32,
) -> String {
    NostrSubscription::GroupBatch {
        account_id: account_id.clone(),
        routes: Vec::new(),
        endpoints: endpoints.to_vec(),
        since: None,
        attempt: adapter
            .account_subscription_attempt(account_id)
            .await
            .expect("the account is active"),
        batch,
    }
    .subscription_id()
}

/// Start a group sync adding `added` while its subscribe is held, then cancel
/// it. Its subscribe task keeps running detached.
async fn cancel_held_group_sync(
    relay: &ReleasableSubscribeRelayClient,
    adapter: &NostrTransportAdapter,
    account_id: &MemberId,
    groups: Vec<TransportGroupSubscription>,
) {
    relay.hold.store(true, Ordering::SeqCst);
    let held_before = relay.held.load(Ordering::SeqCst);
    let sync = tokio::spawn({
        let adapter = adapter.clone();
        let sync = TransportGroupSync {
            account_id: account_id.clone(),
            group_subscriptions: groups,
            since: None,
        };
        async move { adapter.sync_account_groups(sync).await }
    });
    wait_until("the added group's subscribe is held", || {
        relay.held.load(Ordering::SeqCst) > held_before
    })
    .await;
    sync.abort();
    assert!(sync.await.unwrap_err().is_cancelled());
    relay.hold.store(false, Ordering::SeqCst);
}

/// A cancelled group sync's subscribe task keeps running and can register its
/// group after the sync rolled back. The rolled-back group is in no committed
/// route, so no later sync would close it: the sync's cleanup must (#2262).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_group_sync_closes_the_reqs_it_installed() {
    let relay = Arc::new(ReleasableSubscribeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA1; 32]);
    let (kept, added) = (sync_fixture_group(0xB2), sync_fixture_group(0xC3));
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![kept.clone()],
            since: None,
        })
        .await
        .expect("activation succeeds");
    // The sync repacks kept and added into batch 1, after the activation's
    // batch 0.
    let added_id = batch_subscription_id(&adapter, &account_id, &added.endpoints, 1).await;

    cancel_held_group_sync(&relay, &adapter, &account_id, vec![kept.clone(), added]).await;
    // Released within the straggler wait: the task registers under the
    // current barrier, so only the sync's own cleanup can close it.
    relay.release.notify_waiters();
    wait_until("the cancelled sync closes its REQ", || {
        relay.unsubscribed.lock().unwrap().contains(&added_id)
    })
    .await;

    adapter
        .sync_account_groups(TransportGroupSync {
            account_id: account_id.clone(),
            group_subscriptions: vec![kept],
            since: None,
        })
        .await
        .expect("the next sync proceeds");
    assert_eq!(*relay.unsubscribed.lock().unwrap(), vec![added_id]);
}

/// A cancelled sync's straggler that outlives the wait must not close a REQ
/// the retried sync has since made live, or the live route would stop
/// receiving. The retry repacks into fresh batch numbers and never reuses the
/// abandoned batch's id: numbers are spent when a sync stages them. So the
/// straggler closes only its own abandoned REQ, and the retry's batch stays
/// open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retired_subscribe_task_keeps_an_id_the_live_routes_want() {
    let relay = Arc::new(ReleasableSubscribeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA2; 32]);
    let (kept, added) = (sync_fixture_group(0xB4), sync_fixture_group(0xC5));
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![kept.clone()],
            since: None,
        })
        .await
        .expect("activation succeeds");
    // The cancelled sync repacks kept and added into batch 1, after the
    // activation's batch 0.
    let added_id = batch_subscription_id(&adapter, &account_id, &added.endpoints, 1).await;
    let closes_of = |id: &str| {
        relay
            .unsubscribed
            .lock()
            .unwrap()
            .iter()
            .filter(|closed| *closed == id)
            .count()
    };
    let closes_of_added = || closes_of(&added_id);

    cancel_held_group_sync(
        &relay,
        &adapter,
        &account_id,
        vec![kept.clone(), added.clone()],
    )
    .await;
    // The held task outlives the cancelled sync's cleanup wait, which retires
    // the barrier and closes the not-yet-registered id.
    wait_until("the cleanup closes the abandoned id", || {
        closes_of_added() == 1
    })
    .await;
    adapter
        .sync_account_groups(TransportGroupSync {
            account_id: account_id.clone(),
            group_subscriptions: vec![kept, added.clone()],
            since: None,
        })
        .await
        .expect("the retried sync makes the group live");
    let live_id = group_subscription_id(&adapter, &account_id, &added).await;
    assert_ne!(live_id, added_id, "the retry goes out in a new batch");

    relay.release.notify_waiters();
    wait_until("the straggler returns", || {
        relay.released.load(Ordering::SeqCst) == 1
    })
    .await;
    // The straggler registers the abandoned id, which no route wants, and
    // closes it again.
    wait_until("the straggler closes its abandoned REQ", || {
        closes_of_added() == 2
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(closes_of(&live_id), 0, "the live route's REQ stays open");
}

fn group_event_at(
    body: &str,
    group: &TransportGroupSubscription,
    second: u64,
) -> NostrTransportEvent {
    let mut event = group_event(body, &group.transport_group_id);
    event.created_at = second;
    event.id = event.computed_id();
    event
}

async fn route_group_copy(
    adapter: &NostrTransportAdapter,
    group: &TransportGroupSubscription,
    subscription_id: &str,
    event: &NostrTransportEvent,
) {
    let copy = NostrRelayEvent {
        endpoint: group.endpoints[0].clone(),
        subscription_id: Some(subscription_id.to_owned()),
        event: event.clone(),
    };
    adapter.observe_relay_event(&copy).await;
    adapter.handle_group_relay_copy(copy, None).await.unwrap();
}

async fn assert_group_delivery(
    adapter: &NostrTransportAdapter,
    account: &MemberId,
    event: &NostrTransportEvent,
) {
    let delivery = tokio::time::timeout(Duration::from_secs(1), adapter.receive())
        .await
        .expect("group event is admitted")
        .unwrap()
        .unwrap();
    assert_eq!(&delivery.account_id, account);
    assert_eq!(delivery.message, event.to_transport_message().unwrap());
    adapter
        .ack_replay_delivery(account, &delivery.message.id)
        .await;
}

#[tokio::test]
async fn capture_ignores_refused_peer() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xB1; 32]);
    let mut group = sync_fixture_group(0xB2);
    let refused = TransportEndpoint("wss://refused.example".into());
    group.endpoints.push(refused.clone());
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let id = relay
        .take_issued_subscriptions()
        .into_iter()
        .find(|source| matches!(source, NostrSubscription::GroupBatch { .. }))
        .unwrap()
        .subscription_id();
    adapter
        .handle_relay_closed(
            refused,
            id,
            refusal(None, SubscriptionRefusalDisposition::Dropped),
        )
        .await;
    let event = group_event_at("history from the surviving issued peer", &group, floor + 1);
    *relay.retained.lock().unwrap() = Some(vec![(
        account.clone(),
        group.endpoints[0].clone(),
        event.clone(),
    )]);
    let plan = capture_plan(&adapter, &account, 1).await;
    let capture = spawn_capture(&adapter, &account, plan);
    assert_group_delivery(&adapter, &account, &event).await;
    assert_eq!(capture.await.unwrap(), ReplayCaptureOutcome::Complete);
    assert_replay_idle(&adapter, &account).await;
}

async fn capture_plan(
    adapter: &NostrTransportAdapter,
    account: &MemberId,
    attempt_serial: u64,
) -> ReplayCapturePlan {
    let status = adapter.take_replay_status(account).await;
    let sources = status
        .sources()
        .flat_map(|source| {
            source
                .endpoints()
                .filter(|endpoint| !endpoint.admitted())
                .map(|endpoint| endpoint.capture_token())
                .collect::<Vec<_>>()
        })
        .collect();
    drop(status);
    ReplayCapturePlan {
        attempt_serial,
        sources,
        credit: Arc::new(
            Arc::new(tokio::sync::Semaphore::new(1))
                .acquire_owned()
                .await
                .unwrap(),
        ),
    }
}

fn spawn_capture(
    adapter: &NostrTransportAdapter,
    account: &MemberId,
    plan: ReplayCapturePlan,
) -> tokio::task::JoinHandle<ReplayCaptureOutcome> {
    let adapter = adapter.clone();
    let account = account.clone();
    tokio::spawn(async move {
        adapter
            .capture_replay(&account, plan, NostrAcquisitionCancellation::new())
            .await
            .unwrap()
    })
}

/// Dropping a caller cannot free a credit before its accepted IO is destroyed,
/// and cancellation must clean queued routes and a placement-blocked drain.
#[tokio::test]
async fn abort_keeps_capture_credit() {
    for blocked_placement in [false, true] {
        let relay = Arc::new(FakeRelayClient::default());
        let adapter = NostrTransportAdapter::new(relay.clone());
        let account = MemberId::new(vec![0xD1; 32]);
        let first = sync_fixture_group(0xD2);
        let second = sync_fixture_group(0xD3);
        let floor = 1_700_000_000;
        adapter
            .activate_account(TransportAccountActivation {
                account_id: account.clone(),
                inbox_endpoints: vec![],
                group_subscriptions: vec![second, first.clone()],
                since: Some(Timestamp(floor)),
            })
            .await
            .unwrap();
        let event = group_event_at("first captured route awaiting placement", &first, floor + 1);
        *relay.retained.lock().unwrap() = Some(vec![(
            account.clone(),
            first.endpoints[0].clone(),
            event.clone(),
        )]);
        relay
            .hold_acquisition
            .store(!blocked_placement, Ordering::SeqCst);
        let credits = Arc::new(tokio::sync::Semaphore::new(1));
        let mut plan = capture_plan(&adapter, &account, 1).await;
        plan.credit = Arc::new(credits.clone().acquire_owned().await.unwrap());
        let mut caller =
            Box::pin(adapter.capture_replay(&account, plan, NostrAcquisitionCancellation::new()));
        assert!(
            poll_fn(|cx| Poll::Ready(caller.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        wait_until("the accepted first route starts IO", || {
            !relay.acquisitions.lock().unwrap().is_empty()
        })
        .await;
        let placement = if blocked_placement {
            let delivery = tokio::time::timeout(Duration::from_secs(1), adapter.receive())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(delivery.account_id, account);
            assert_eq!(delivery.message, event.to_transport_message().unwrap());
            assert!(
                adapter.take_replay_status(&account).await.pending,
                "enqueue alone is not placement acknowledgment"
            );
            Some(delivery.message.id)
        } else {
            assert_eq!(relay.active_acquisitions.load(Ordering::SeqCst), 1);
            None
        };
        assert_eq!(credits.available_permits(), 0);
        let acquisitions_before_abort = relay.acquisitions.lock().unwrap().len();
        drop(caller);
        if !blocked_placement {
            // The held backend cannot have cleaned up without an executor turn.
            assert_eq!(
                credits.available_permits(),
                0,
                "caller destruction cannot release an accepted IO credit"
            );
            assert_eq!(relay.active_acquisitions.load(Ordering::SeqCst), 1);
        }
        wait_until("accepted IO and its credit are cleaned together", || {
            relay.active_acquisitions.load(Ordering::SeqCst) == 0
                && credits.available_permits() == 1
        })
        .await;
        if let Some(id) = placement {
            assert!(
                adapter.take_replay_status(&account).await.pending,
                "caller cancellation cannot erase an outstanding placement fence"
            );
            adapter.ack_replay_delivery(&account, &id).await;
        }
        assert_eq!(
            relay.acquisitions.lock().unwrap().len(),
            acquisitions_before_abort,
            "cancellation cannot start another queued acquisition"
        );
        assert_replay_idle(&adapter, &account).await;
        assert_no_delivery(&adapter).await;
    }
}

async fn wait_snapshot(hold: &AcquisitionHold) {
    tokio::time::timeout(Duration::from_secs(1), hold.captured.notified())
        .await
        .expect("the backend captured its held snapshot");
}

async fn release_snapshot(hold: &AcquisitionHold) {
    hold.release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), hold.returned.notified())
        .await
        .expect("the backend returned or discarded its captured snapshot");
}

async fn wait_replay_eose(adapter: &NostrTransportAdapter, id: &str) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while adapter.subscription_synced(id).await != Some(true) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the group's replay finishes releasing");
}

async fn replay_loss(
    adapter: &NostrTransportAdapter,
    account: &MemberId,
) -> NostrNotificationLossFloor {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Some(loss) = adapter.take_replay_status(account).await.loss {
                return loss;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("discarded history reports loss")
}

async fn assert_no_delivery(adapter: &NostrTransportAdapter) {
    assert!(
        tokio::time::timeout(Duration::from_millis(25), adapter.receive())
            .await
            .is_err(),
        "unavailable historical copies must not reach the consumer"
    );
}

async fn assert_replay_idle(adapter: &NostrTransportAdapter, account: &MemberId) {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            {
                let status = adapter.take_replay_status(account).await;
                assert!(status.loss.is_none(), "loss was already imported");
                if !status.pending {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("acknowledged available input leaves no permanent admission pin");
}

async fn expire_admission() {
    tokio::task::yield_now().await;
    // Exercise finite expiry without depending on the precise configured interval.
    tokio::time::advance(Duration::from_secs(24 * 60 * 60)).await;
}

async fn late_replay_keeps_proof(stored: usize) {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xC1; 32]);
    let mut group = sync_fixture_group(0xC2);
    group
        .endpoints
        .push(TransportEndpoint("wss://late.example".into()));
    let mut late = group.clone();
    late.endpoints.swap(0, 1);
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let id = issued_group_id(&relay.take_issued_subscriptions(), &group.group_id);
    let healthy = group_event_at("completed A history", &group, floor + 1);
    route_group_copy(&adapter, &group, &id, &healthy).await;
    adapter
        .handle_relay_eose(group.endpoints[0].clone(), id.clone())
        .await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(31)).await;
    assert_group_delivery(&adapter, &account, &healthy).await;
    let mut loss = adapter.take_replay_status(&account).await.loss;

    let mut history = (0..stored)
        .map(|index| {
            group_event_at(
                &format!("late B {index}"),
                &group,
                floor + 100 + index as u64,
            )
        })
        .collect::<Vec<_>>();
    if stored >= transport_nostr_adapter::RELAY_REPLAY_PAGE_LIMIT {
        let older = group_event_at("B history below its clamped prefix", &group, floor + 10);
        relay.pages.lock().unwrap().push_back((
            NostrAcquisitionEnd::RequestPolicySatisfied,
            vec![older.clone()],
        ));
        for event in history.iter().rev() {
            route_group_copy(&adapter, &late, &id, event).await;
        }
        history.insert(0, older);
    } else {
        for event in history.iter().rev() {
            route_group_copy(&adapter, &late, &id, event).await;
        }
    }
    assert_no_delivery(&adapter).await;
    adapter
        .handle_relay_eose(late.endpoints[0].clone(), id.clone())
        .await;
    let expected = history
        .iter()
        .map(|event| event.to_transport_message().unwrap())
        .collect::<Vec<_>>();
    let mut delivered = Vec::new();
    while delivered.len() < expected.len() {
        let Ok(delivery) = tokio::time::timeout(Duration::from_secs(1), adapter.receive()).await
        else {
            break;
        };
        let delivery = delivery.unwrap().unwrap();
        assert_eq!(delivery.account_id, account);
        assert_eq!(delivery.group_id_hint.as_ref(), Some(&group.group_id));
        adapter
            .ack_replay_delivery(&account, &delivery.message.id)
            .await;
        delivered.push(delivery.message);
    }
    {
        let status = adapter.take_replay_status(&account).await;
        loss = status.loss.or(loss);
    }
    if delivered != expected {
        assert!(
            delivered.is_empty(),
            "a late stored range cannot release only its newer suffix"
        );
        assert_eq!(loss, Some(NostrNotificationLossFloor::Since(floor)));
        assert_eq!(
            adapter
                .subscription_endpoint_eose(&id, &late.endpoints[0])
                .await,
            Some(false)
        );
        assert_eq!(adapter.subscription_synced(&id).await, Some(false));
        assert!(!adapter.account_subscription_eose(&account).await.complete());
    }
    assert_no_delivery(&adapter).await;
    let live = group_event_at("live after late B's actual boundary", &group, floor + 2_000);
    route_group_copy(&adapter, &late, &id, &live).await;
    assert_group_delivery(&adapter, &account, &live).await;
    assert_no_delivery(&adapter).await;
}

#[tokio::test(start_paused = true)]
async fn late_short_replay_keeps_proof() {
    late_replay_keeps_proof(3).await;
}

#[tokio::test(start_paused = true)]
async fn late_clamp_replay_keeps_proof() {
    late_replay_keeps_proof(transport_nostr_adapter::RELAY_REPLAY_PAGE_LIMIT).await;
}

#[tokio::test(start_paused = true)]
async fn newer_loss_needs_own_proof() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xC5; 32]);
    let group = sync_fixture_group(0xC6);
    let endpoint = &group.endpoints[0];
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let id = issued_group_id(&relay.take_issued_subscriptions(), &group.group_id);
    adapter
        .observe_replay_epoch(
            Some(&account),
            endpoint,
            [1, 1],
            transport_nostr_adapter::ReplayRestart::Connection,
        )
        .await;
    adapter
        .handle_relay_eose(endpoint.clone(), id.clone())
        .await;
    let older = group_event_at("first capture's complete snapshot", &group, floor + 1);
    let missing = group_event_at("lost after the first capture began", &group, floor + 2);
    relay.pages.lock().unwrap().extend([
        (
            NostrAcquisitionEnd::RequestPolicySatisfied,
            vec![older.clone()],
        ),
        (
            NostrAcquisitionEnd::RequestPolicySatisfied,
            vec![missing.clone(), older.clone()],
        ),
    ]);
    let first_snapshot = Arc::new(AcquisitionHold::default());
    let next_snapshot = Arc::new(AcquisitionHold::default());
    relay.acquisition_holds.lock().unwrap().extend([
        (endpoint.clone(), first_snapshot.clone()),
        (endpoint.clone(), next_snapshot.clone()),
    ]);
    adapter
        .observe_replay_epoch(
            Some(&account),
            endpoint,
            [2, 1],
            transport_nostr_adapter::ReplayRestart::ReceiverLoss,
        )
        .await;
    let first_capture = spawn_capture(
        &adapter,
        &account,
        capture_plan(&adapter, &account, 1).await,
    );
    wait_snapshot(&first_snapshot).await;
    assert!(adapter.take_replay_status(&account).await.loss.is_none());
    tokio::time::advance(Duration::from_secs(5)).await;
    adapter
        .observe_replay_epoch(
            Some(&account),
            endpoint,
            [3, 1],
            transport_nostr_adapter::ReplayRestart::ReceiverLoss,
        )
        .await;
    tokio::task::yield_now().await;
    assert_eq!(relay.acquisitions.lock().unwrap().len(), 1);
    release_snapshot(&first_snapshot).await;
    tokio::task::yield_now().await;
    assert_eq!(
        relay.acquisitions.lock().unwrap().len(),
        1,
        "a newer boundary never grants a follow-up"
    );
    let capture = spawn_capture(
        &adapter,
        &account,
        capture_plan(&adapter, &account, 2).await,
    );
    wait_snapshot(&next_snapshot).await;
    assert_eq!(
        adapter.subscription_endpoint_eose(&id, endpoint).await,
        Some(false)
    );
    assert!(!adapter.account_subscription_eose(&account).await.complete());
    {
        let status = adapter.take_replay_status(&account).await;
        assert!(
            status.pending,
            "newer demand remains an admission gate while its capture is held"
        );
        if let Some(loss) = status.loss {
            assert_eq!(loss, NostrNotificationLossFloor::Since(floor));
        }
    }
    release_snapshot(&next_snapshot).await;
    assert_group_delivery(&adapter, &account, &older).await;
    let next = tokio::time::timeout(Duration::from_secs(1), adapter.receive())
        .await
        .expect("the newer lost body is recovered")
        .unwrap()
        .unwrap();
    assert_eq!(next.account_id, account);
    adapter
        .ack_replay_delivery(&account, &next.message.id)
        .await;
    if next.message == older.to_transport_message().unwrap() {
        // A fresh owned history acquisition deliberately bypasses live-copy
        // dedup, so a serial full-window refetch may repeat its older body.
        assert_group_delivery(&adapter, &account, &missing).await;
    } else {
        assert_eq!(next.message, missing.to_transport_message().unwrap());
    }
    assert_eq!(capture.await.unwrap(), ReplayCaptureOutcome::Complete);
    let _ = first_capture.await.unwrap();
    assert!(relay.acquisitions.lock().unwrap().iter().all(|request| matches!(&request.scope, NostrAcquisitionScope::GroupsWindow { since, .. } if *since == floor)));
    wait_replay_eose(&adapter, &id).await;
    assert_no_delivery(&adapter).await;
    assert_replay_idle(&adapter, &account).await;
    assert_eq!(relay.acquisitions.lock().unwrap().len(), 2);
    assert!(relay.take_issued_subscriptions().is_empty());
}

/// A newer boundary needs a new owner grant and the original full window;
/// finishing an older capture cannot automatically start or certify its successor.
#[tokio::test(start_paused = true)]
async fn new_loss_needs_fresh_grant() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xCB; 32]);
    let group = sync_fixture_group(0xCC);
    let endpoint = &group.endpoints[0];
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let id = issued_group_id(&relay.take_issued_subscriptions(), &group.group_id);
    adapter
        .observe_replay_epoch(
            Some(&account),
            endpoint,
            [1, 1],
            transport_nostr_adapter::ReplayRestart::Connection,
        )
        .await;
    adapter
        .handle_relay_eose(endpoint.clone(), id.clone())
        .await;
    let original = group_event_at("first retained snapshot", &group, floor + 1);
    *relay.retained.lock().unwrap() =
        Some(vec![(account.clone(), endpoint.clone(), original.clone())]);
    let first = Arc::new(AcquisitionHold::default());
    let followup = Arc::new(AcquisitionHold::default());
    relay.acquisition_holds.lock().unwrap().extend([
        (endpoint.clone(), first.clone()),
        (endpoint.clone(), followup.clone()),
    ]);
    adapter
        .observe_replay_epoch(
            Some(&account),
            endpoint,
            [2, 1],
            transport_nostr_adapter::ReplayRestart::ReceiverLoss,
        )
        .await;
    let first_capture = spawn_capture(
        &adapter,
        &account,
        capture_plan(&adapter, &account, 1).await,
    );
    wait_snapshot(&first).await;
    assert!(adapter.take_replay_status(&account).await.loss.is_none());

    // The first result is already materialized. Only the next full-window
    // acquisition can see this tail; no live copy is sent to the adapter.
    let missing = group_event_at("tail lost after first snapshot", &group, floor + 2);
    relay.retained.lock().unwrap().as_mut().unwrap().push((
        account.clone(),
        endpoint.clone(),
        missing.clone(),
    ));
    adapter
        .observe_replay_epoch(
            Some(&account),
            endpoint,
            [3, 1],
            transport_nostr_adapter::ReplayRestart::ReceiverLoss,
        )
        .await;
    assert!(adapter.take_replay_status(&account).await.loss.is_none());
    release_snapshot(&first).await;
    tokio::task::yield_now().await;
    assert_eq!(
        relay.acquisitions.lock().unwrap().len(),
        1,
        "no autonomous follow-up"
    );
    let capture = spawn_capture(
        &adapter,
        &account,
        capture_plan(&adapter, &account, 2).await,
    );
    wait_snapshot(&followup).await;
    assert_eq!(relay.acquisitions.lock().unwrap().len(), 2);
    assert_eq!(
        adapter.subscription_endpoint_eose(&id, endpoint).await,
        Some(false),
        "the first snapshot cannot certify input lost after it was captured"
    );
    release_snapshot(&followup).await;

    let original_message = original.to_transport_message().unwrap();
    let missing_message = missing.to_transport_message().unwrap();
    let mut original_copies = 0;
    loop {
        let delivery = tokio::time::timeout(Duration::from_secs(1), adapter.receive())
            .await
            .expect("the owned follow-up delivers the actual lost tail")
            .unwrap()
            .unwrap();
        assert_eq!(delivery.account_id, account);
        assert_eq!(delivery.group_id_hint.as_ref(), Some(&group.group_id));
        adapter
            .ack_replay_delivery(&account, &delivery.message.id)
            .await;
        if delivery.message == missing_message {
            assert!(original_copies > 0, "history precedes the newer lost tail");
            break;
        }
        assert_eq!(delivery.message, original_message);
        original_copies += 1;
        // Historical refetches intentionally bypass live-copy dedup. Either
        // the first snapshot is withheld, or each full-window pass releases it.
        assert!(original_copies <= 2);
    }
    assert_eq!(capture.await.unwrap(), ReplayCaptureOutcome::Complete);
    let _ = first_capture.await.unwrap();
    assert!(relay.acquisitions.lock().unwrap().iter().all(|request| matches!(&request.scope, NostrAcquisitionScope::GroupsWindow { since, .. } if *since == floor)));
    wait_replay_eose(&adapter, &id).await;
    assert_no_delivery(&adapter).await;
    assert_replay_idle(&adapter, &account).await;
    assert_eq!(relay.acquisitions.lock().unwrap().len(), 2);
    assert!(relay.take_issued_subscriptions().is_empty());
}

#[tokio::test(start_paused = true)]
async fn batch_units_have_own_budget() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xC7; 32]);
    let groups = [
        sync_fixture_group(0xC8),
        sync_fixture_group(0xC9),
        sync_fixture_group(0xCA),
    ];
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![groups[2].clone(), groups[0].clone(), groups[1].clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let issued = relay.take_issued_subscriptions();
    let id = issued_group_id(&issued, &groups[0].group_id);
    let mut history = [Vec::new(), Vec::new(), Vec::new()];
    for index in (0..transport_nostr_adapter::RELAY_REPLAY_PAGE_LIMIT).rev() {
        let group_index = index % groups.len();
        let event = group_event_at(
            &format!("clamped group {group_index} event {index}"),
            &groups[group_index],
            floor + 1_000 * (3 - group_index) as u64 + index as u64,
        );
        route_group_copy(&adapter, &groups[group_index], &id, &event).await;
        history[group_index].push(event);
    }
    let mut retained = Vec::new();
    for (index, group) in groups.iter().enumerate() {
        let older = group_event_at(
            "older per-route page body",
            group,
            floor + 10 + index as u64,
        );
        retained.push((account.clone(), group.endpoints[0].clone(), older.clone()));
        history[index].push(older);
        history[index].sort_unstable_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
    }
    *relay.retained.lock().unwrap() = Some(retained);
    relay
        .acquisition_delays
        .lock()
        .unwrap()
        .extend([Duration::from_secs(12); 3]);
    let started = tokio::time::Instant::now();
    adapter
        .handle_relay_eose(groups[0].endpoints[0].clone(), id.clone())
        .await;
    for (index, events) in history.iter().enumerate() {
        wait_until("the next canonical group starts service", || {
            relay.acquisitions.lock().unwrap().len() == index + 1
        })
        .await;
        assert_eq!(
            adapter
                .subscription_endpoint_eose(&id, &groups[0].endpoints[0])
                .await,
            Some(false)
        );
        tokio::time::advance(Duration::from_secs(12)).await;
        for event in events {
            assert_group_delivery(&adapter, &account, event).await;
        }
        assert!(
            adapter.take_replay_status(&account).await.loss.is_none(),
            "queued groups do not spend their service allowance while an earlier group pages"
        );
    }
    assert!(started.elapsed() >= Duration::from_secs(36));
    wait_replay_eose(&adapter, &id).await;
    assert_no_delivery(&adapter).await;
    assert_replay_idle(&adapter, &account).await;
}

/// A's completed network work cannot spend its remaining service budget on B.
/// B starts later and finishes within its own unchanged thirty-second lease.
#[tokio::test(start_paused = true)]
async fn peer_wait_keeps_next_group() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xCD; 32]);
    let a = TransportEndpoint("wss://source-a.example".into());
    let b = TransportEndpoint("wss://source-b.example".into());
    let mut first_group = sync_fixture_group(0xCE);
    let mut next_group = sync_fixture_group(0xCF);
    first_group.endpoints = vec![a.clone(), b.clone()];
    next_group.endpoints = first_group.endpoints.clone();
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![next_group.clone(), first_group.clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let issued = relay.take_issued_subscriptions();
    let id = issued_group_id(&issued, &first_group.group_id);
    assert_eq!(id, issued_group_id(&issued, &next_group.group_id));
    for endpoint in [&a, &b] {
        adapter
            .observe_replay_epoch(
                Some(&account),
                endpoint,
                [1, 1],
                transport_nostr_adapter::ReplayRestart::Connection,
            )
            .await;
        adapter
            .handle_relay_eose(endpoint.clone(), id.clone())
            .await;
    }

    let shared = group_event_at("shared first-group history", &first_group, floor + 1);
    let unique = group_event_at("only A has the next group", &next_group, floor + 2);
    *relay.retained.lock().unwrap() = Some(vec![
        (account.clone(), a.clone(), shared.clone()),
        (account.clone(), b.clone(), shared.clone()),
        (account.clone(), a.clone(), unique.clone()),
    ]);
    let a_hold = Arc::new(AcquisitionHold::default());
    let b_hold = Arc::new(AcquisitionHold::default());
    relay
        .acquisition_holds
        .lock()
        .unwrap()
        .extend([(a.clone(), a_hold.clone()), (b.clone(), b_hold.clone())]);
    let a_started = tokio::time::Instant::now();
    adapter
        .observe_replay_epoch(
            Some(&account),
            &a,
            [2, 1],
            transport_nostr_adapter::ReplayRestart::ReceiverLoss,
        )
        .await;
    let mut a_plan = capture_plan(&adapter, &account, 1).await;
    {
        let status = adapter.take_replay_status(&account).await;
        a_plan.sources = status
            .sources()
            .flat_map(|source| {
                source
                    .endpoints()
                    .filter(|endpoint| same_relay(endpoint.endpoint(), &a))
                    .map(|endpoint| endpoint.capture_token())
                    .collect::<Vec<_>>()
            })
            .collect();
    }
    let a_capture = spawn_capture(&adapter, &account, a_plan);
    wait_snapshot(&a_hold).await;
    assert!(adapter.take_replay_status(&account).await.loss.is_none());

    tokio::time::advance(Duration::from_secs(10)).await;
    let b_started = tokio::time::Instant::now();
    adapter
        .observe_replay_epoch(
            Some(&account),
            &b,
            [2, 1],
            transport_nostr_adapter::ReplayRestart::ReceiverLoss,
        )
        .await;
    let mut b_plan = capture_plan(&adapter, &account, 2).await;
    {
        let status = adapter.take_replay_status(&account).await;
        b_plan.sources = status
            .sources()
            .flat_map(|source| {
                source
                    .endpoints()
                    .filter(|endpoint| same_relay(endpoint.endpoint(), &b))
                    .map(|endpoint| endpoint.capture_token())
                    .collect::<Vec<_>>()
            })
            .collect();
    }
    let b_capture = spawn_capture(&adapter, &account, b_plan);
    wait_snapshot(&b_hold).await;
    assert!(adapter.take_replay_status(&account).await.loss.is_none());

    tokio::time::advance(Duration::from_secs(10)).await;
    release_snapshot(&a_hold).await;
    assert!(a_started.elapsed() < Duration::from_secs(30));
    // A's complete G1 result is now held only by B's still-running G1. Pass
    // A's original deadline while B retains nine seconds of its own budget.
    tokio::time::advance(Duration::from_secs(11)).await;
    assert_no_delivery(&adapter).await;
    tokio::time::advance(Duration::from_secs(4)).await;
    assert!(a_started.elapsed() > Duration::from_secs(30));
    assert!(b_started.elapsed() < Duration::from_secs(30));
    release_snapshot(&b_hold).await;

    assert_group_delivery(&adapter, &account, &shared).await;
    assert_group_delivery(&adapter, &account, &unique).await;
    let _ = a_capture.await.unwrap();
    assert_eq!(b_capture.await.unwrap(), ReplayCaptureOutcome::Complete);
    wait_replay_eose(&adapter, &id).await;
    assert_no_delivery(&adapter).await;
    assert_replay_idle(&adapter, &account).await;
    assert!(relay.take_issued_subscriptions().is_empty());
}

#[tokio::test]
async fn refused_peer_releases_history() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0x81; 32]);
    let mut group = sync_fixture_group(0x82);
    let refused = TransportEndpoint("wss://refused.example".into());
    group.endpoints.push(refused.clone());
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(1_700_000_000)),
        })
        .await
        .unwrap();
    let id = issued_group_id(&relay.take_issued_subscriptions(), &group.group_id);
    let older = group_event_at("older", &group, 1_700_000_001);
    let newer = group_event_at("newer", &group, 1_700_000_002);
    route_group_copy(&adapter, &group, &id, &newer).await;
    route_group_copy(&adapter, &group, &id, &older).await;
    let copy = NostrRelayEvent {
        endpoint: refused.clone(),
        subscription_id: Some(id.clone()),
        event: newer.clone(),
    };
    adapter.observe_relay_event(&copy).await;
    adapter.handle_group_relay_copy(copy, None).await.unwrap();
    adapter
        .handle_relay_eose(group.endpoints[0].clone(), id.clone())
        .await;
    assert!(adapter.take_replay_status(&account).await.pending);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), adapter.receive())
            .await
            .is_err()
    );
    adapter
        .handle_relay_closed(
            refused,
            id,
            SubscriptionRefusal {
                category: None,
                disposition: SubscriptionRefusalDisposition::Dropped,
            },
        )
        .await;
    assert_group_delivery(&adapter, &account, &older).await;
    assert_group_delivery(&adapter, &account, &newer).await;
    let coverage = adapter.account_subscription_eose(&account).await;
    assert!(coverage.settled());
    assert!(!coverage.complete());
    assert!(!adapter.take_replay_status(&account).await.pending);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), adapter.receive())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn removed_page_never_leaks() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0x83; 32]);
    let group = sync_fixture_group(0x84);
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(1_700_000_500)),
        })
        .await
        .unwrap();
    let live_id = issued_group_id(&relay.take_issued_subscriptions(), &group.group_id);
    adapter
        .handle_relay_eose(group.endpoints[0].clone(), live_id.clone())
        .await;
    let before = group_event_at("ready live route", &group, 1_700_001_000);
    route_group_copy(&adapter, &group, &live_id, &before).await;
    assert_group_delivery(&adapter, &account, &before).await;

    let maintenance = adapter
        .install_group_maintenance_recovery_subscription(
            &account,
            &group,
            1,
            Some(Timestamp(1_700_000_000)),
        )
        .await
        .unwrap();
    let mut partial = Vec::new();
    for index in 0..transport_nostr_adapter::RELAY_REPLAY_PAGE_LIMIT {
        let event = group_event_at(
            &format!("partial {index}"),
            &group,
            1_700_000_500 + index as u64,
        );
        route_group_copy(&adapter, &group, &maintenance, &event).await;
        partial.push(event);
    }
    let staged_live = group_event_at("live while wider history is pending", &group, 1_700_001_001);
    route_group_copy(&adapter, &group, &live_id, &staged_live).await;
    assert!(adapter.take_replay_status(&account).await.pending);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), adapter.receive())
            .await
            .is_err()
    );
    let older = group_event_at("late acquisition result", &group, 1_700_000_001);
    relay.pages.lock().unwrap().push_back((
        NostrAcquisitionEnd::RequestPolicySatisfied,
        vec![older.clone()],
    ));
    relay.hold_acquisition.store(true, Ordering::SeqCst);
    adapter
        .handle_relay_eose(group.endpoints[0].clone(), maintenance.clone())
        .await;
    wait_until("maintenance page acquisition starts", || {
        !relay.acquisitions.lock().unwrap().is_empty()
    })
    .await;
    adapter
        .remove_group_maintenance_recovery_subscription(&account, &maintenance)
        .await
        .unwrap();
    assert_eq!(
        replay_loss(&adapter, &account).await,
        NostrNotificationLossFloor::Since(1_700_000_000)
    );
    relay.release_acquisition.notify_one();
    adapter
        .handle_relay_eose(group.endpoints[0].clone(), maintenance.clone())
        .await;
    for event in partial.iter().chain(std::iter::once(&older)) {
        route_group_copy(&adapter, &group, &maintenance, event).await;
    }
    assert_group_delivery(&adapter, &account, &staged_live).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(25), adapter.receive())
            .await
            .is_err()
    );
    let after = group_event_at("future live route", &group, 1_700_001_002);
    route_group_copy(&adapter, &group, &live_id, &after).await;
    assert_group_delivery(&adapter, &account, &after).await;
    wait_replay_eose(&adapter, &live_id).await;
    let status = adapter.take_replay_status(&account).await;
    assert!(!status.pending);
    assert!(status.loss.is_none());
}

#[tokio::test]
async fn page_retry_retains_events() {
    for end in [
        NostrAcquisitionEnd::Deadline,
        NostrAcquisitionEnd::Disconnected,
        NostrAcquisitionEnd::RelayClosed,
    ] {
        let relay = Arc::new(FakeRelayClient::default());
        let adapter = NostrTransportAdapter::new(relay.clone());
        let account = MemberId::new(vec![0x89; 32]);
        let group = sync_fixture_group(0x8A);
        adapter
            .activate_account(TransportAccountActivation {
                account_id: account.clone(),
                inbox_endpoints: vec![],
                group_subscriptions: vec![group.clone()],
                since: Some(Timestamp(1_700_000_000)),
            })
            .await
            .unwrap();
        let id = issued_group_id(&relay.take_issued_subscriptions(), &group.group_id);
        let oldest = group_event_at("retry reaches oldest history", &group, 1_700_000_050);
        let interrupted = group_event_at("retained interrupted response", &group, 1_700_000_100);
        relay.pages.lock().unwrap().extend([
            (end, vec![interrupted.clone()]),
            (
                NostrAcquisitionEnd::RequestPolicySatisfied,
                vec![interrupted.clone(), oldest.clone()],
            ),
        ]);
        let mut initial = Vec::new();
        for index in 0..transport_nostr_adapter::RELAY_REPLAY_PAGE_LIMIT {
            let event = group_event_at(
                &format!("initial {index}"),
                &group,
                1_700_000_500 + index as u64,
            );
            route_group_copy(&adapter, &group, &id, &event).await;
            initial.push(event);
        }
        adapter
            .handle_relay_eose(group.endpoints[0].clone(), id.clone())
            .await;
        for event in [&oldest, &interrupted].into_iter().chain(initial.iter()) {
            assert_group_delivery(&adapter, &account, event).await;
        }
        {
            let requests = relay.acquisitions.lock().unwrap();
            assert_eq!(requests.len(), 2);
            assert_eq!(requests[0].scope, requests[1].scope);
            assert!(matches!(
                requests[0].scope,
                NostrAcquisitionScope::GroupsWindow {
                    since: 1_700_000_000,
                    ..
                }
            ));
        }
        wait_replay_eose(&adapter, &id).await;
        {
            let status = adapter.take_replay_status(&account).await;
            assert!(!status.pending);
            assert!(status.loss.is_none());
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(25), adapter.receive())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn failed_paging_keeps_live() {
    for end in [
        NostrAcquisitionEnd::Rejected,
        NostrAcquisitionEnd::Deadline,
        NostrAcquisitionEnd::RequestPolicySatisfied,
    ] {
        let relay = Arc::new(FakeRelayClient::default());
        let adapter = NostrTransportAdapter::new(relay.clone());
        let account = MemberId::new(vec![0x8B; 32]);
        let group = sync_fixture_group(0x8C);
        adapter
            .activate_account(TransportAccountActivation {
                account_id: account.clone(),
                inbox_endpoints: vec![],
                group_subscriptions: vec![group.clone()],
                since: Some(Timestamp(1_700_000_000)),
            })
            .await
            .unwrap();
        let id = issued_group_id(&relay.take_issued_subscriptions(), &group.group_id);
        let events = if end == NostrAcquisitionEnd::RequestPolicySatisfied {
            // A full page stuck in the inclusive oldest second cannot prove
            // either the rest of that second or anything before it was served.
            (0..transport_nostr_adapter::RELAY_REPLAY_PAGE_LIMIT)
                .map(|index| group_event_at(&format!("same second {index}"), &group, 1_700_000_500))
                .collect()
        } else {
            vec![group_event_at("partial failed page", &group, 1_700_000_100)]
        };
        relay.pages.lock().unwrap().push_back((end, events.clone()));
        if end == NostrAcquisitionEnd::Deadline {
            relay.pages.lock().unwrap().push_back((end, events));
        }
        for index in 0..transport_nostr_adapter::RELAY_REPLAY_PAGE_LIMIT {
            let event = group_event_at(
                &format!("initial {index}"),
                &group,
                1_700_000_500 + index as u64,
            );
            route_group_copy(&adapter, &group, &id, &event).await;
        }
        adapter
            .handle_relay_eose(group.endpoints[0].clone(), id.clone())
            .await;
        assert_eq!(
            replay_loss(&adapter, &account).await,
            NostrNotificationLossFloor::Since(1_700_000_000)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(25), adapter.receive())
                .await
                .is_err()
        );
        let live = group_event_at("live after failed paging", &group, 1_700_001_001);
        route_group_copy(&adapter, &group, &id, &live).await;
        assert_group_delivery(&adapter, &account, &live).await;
        assert!(!adapter.account_subscription_eose(&account).await.complete());
        let status = adapter.take_replay_status(&account).await;
        assert!(!status.pending);
        assert!(status.loss.is_none());
        assert_eq!(
            relay.acquisitions.lock().unwrap().len(),
            if end == NostrAcquisitionEnd::Deadline {
                2
            } else {
                1
            }
        );
    }
}

#[tokio::test(start_paused = true)]
async fn batch_failure_is_local() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xA0; 32]);
    let busy = sync_fixture_group(0xA1);
    let quiet = sync_fixture_group(0xA3);
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![busy.clone(), quiet.clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let id = group_subscription_id(&adapter, &account, &busy).await;
    assert_eq!(id, group_subscription_id(&adapter, &account, &quiet).await);
    let failed = group_event_at("interrupted busy-route page", &busy, floor + 100);
    relay.pages.lock().unwrap().extend([
        (NostrAcquisitionEnd::Deadline, vec![failed.clone()]),
        (NostrAcquisitionEnd::Deadline, vec![failed]),
        (NostrAcquisitionEnd::RequestPolicySatisfied, vec![]),
    ]);
    for index in 0..transport_nostr_adapter::RELAY_REPLAY_PAGE_LIMIT {
        let event = group_event_at(
            &format!("busy initial {index}"),
            &busy,
            floor + 500 + index as u64,
        );
        route_group_copy(&adapter, &busy, &id, &event).await;
    }
    assert!(adapter.take_replay_status(&account).await.pending);
    adapter
        .handle_relay_eose(busy.endpoints[0].clone(), id.clone())
        .await;
    assert_eq!(
        replay_loss(&adapter, &account).await,
        NostrNotificationLossFloor::Since(floor)
    );
    assert_no_delivery(&adapter).await;
    let live = group_event_at("quiet sibling remains live", &quiet, floor + 2_000);
    route_group_copy(&adapter, &quiet, &id, &live).await;
    assert_group_delivery(&adapter, &account, &live).await;
    assert_no_delivery(&adapter).await;
    assert_replay_idle(&adapter, &account).await;
    assert!(!adapter.account_subscription_eose(&account).await.complete());
    let requests = relay.acquisitions.lock().unwrap();
    assert!(requests.len() >= 2, "the interrupted busy page was retried");
    assert_eq!(requests[0].scope, requests[1].scope);
}

#[tokio::test]
async fn forced_replay_holds_history() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xD8; 32]);
    let group = sync_fixture_group(0xD9);
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let id = issued_group_id(&relay.take_issued_subscriptions(), &group.group_id);
    assert!(
        adapter
            .observe_replay_epoch(
                Some(&account),
                &group.endpoints[0],
                [1, 1],
                transport_nostr_adapter::ReplayRestart::Connection
            )
            .await
    );
    assert!(
        adapter
            .observe_replay_epoch(
                Some(&account),
                &group.endpoints[0],
                [2, 1],
                transport_nostr_adapter::ReplayRestart::ReceiverLoss
            )
            .await
    );
    assert!(
        relay.acquisitions.lock().unwrap().is_empty(),
        "metadata does not grant IO"
    );
    let capture = spawn_capture(
        &adapter,
        &account,
        capture_plan(&adapter, &account, 1).await,
    );
    assert_eq!(capture.await.unwrap(), ReplayCaptureOutcome::Incomplete);
    let mut loss = None;
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let pending = {
                let status = adapter.take_replay_status(&account).await;
                if status.loss.is_some() {
                    loss = status.loss;
                }
                status.pending
            };
            if !pending {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("unsupported owned refetch terminates admission");
    assert_eq!(
        loss, None,
        "unsupported empty acquisition cannot invent discarded ciphertext"
    );

    // Reader loss is not the physical stream's EOSE. Its late stored suffix
    // still belongs to the failed historical owner, not the live queue.
    let history = group_event_at("stored after failed refetch", &group, floor + 1);
    route_group_copy(&adapter, &group, &id, &history).await;
    assert_no_delivery(&adapter).await;
    adapter
        .handle_relay_eose(group.endpoints[0].clone(), id.clone())
        .await;
    assert_eq!(adapter.subscription_synced(&id).await, Some(false));
    let live = group_event_at("live after actual EOSE", &group, floor + 2);
    route_group_copy(&adapter, &group, &id, &live).await;
    assert_group_delivery(&adapter, &account, &live).await;
    assert_no_delivery(&adapter).await;
    assert_eq!(
        replay_loss(&adapter, &account).await,
        NostrNotificationLossFloor::Since(floor)
    );
    assert_replay_idle(&adapter, &account).await;
}

#[tokio::test(start_paused = true)]
async fn full_overflow_drops_pages() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xA5; 32]);
    let mut group = sync_fixture_group(0xA6);
    group
        .endpoints
        .push(TransportEndpoint("wss://complete.example".into()));
    let mut complete = group.clone();
    complete.endpoints.swap(0, 1);
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let id = group_subscription_id(&adapter, &account, &group).await;
    let first = group_event_at("incomplete initial owner", &group, floor + 500);
    route_group_copy(&adapter, &group, &id, &first).await;
    let healthy = group_event_at("completed peer keeps its history", &group, floor + 100);
    route_group_copy(&adapter, &complete, &id, &healthy).await;
    adapter
        .handle_relay_eose(complete.endpoints[0].clone(), id.clone())
        .await;
    assert!(adapter.take_replay_status(&account).await.pending);
    assert_no_delivery(&adapter).await;
    // Cross the documented payload allowance, then continue the initial full page.
    let body = "x".repeat(3 * 1024 * 1024);
    for index in 1..transport_nostr_adapter::RELAY_REPLAY_PAGE_LIMIT {
        let body = if index <= 12 {
            body.as_str()
        } else {
            "later initial copy"
        };
        let event = group_event_at(body, &group, floor + 500 + index as u64);
        route_group_copy(&adapter, &group, &id, &event).await;
    }
    assert_eq!(
        replay_loss(&adapter, &account).await,
        NostrNotificationLossFloor::Since(floor)
    );
    let older = group_event_at("older page must never become live", &group, floor + 1);
    relay
        .pages
        .lock()
        .unwrap()
        .push_back((NostrAcquisitionEnd::RequestPolicySatisfied, vec![older]));
    adapter
        .handle_relay_eose(group.endpoints[0].clone(), id.clone())
        .await;
    assert_group_delivery(&adapter, &account, &healthy).await;
    assert_no_delivery(&adapter).await;
    let live = group_event_at("raw live after initial overflow", &group, floor + 2_000);
    route_group_copy(&adapter, &group, &id, &live).await;
    assert_group_delivery(&adapter, &account, &live).await;
    assert_no_delivery(&adapter).await;
    assert_replay_idle(&adapter, &account).await;
    assert_eq!(
        adapter
            .subscription_endpoint_eose(&id, &group.endpoints[0])
            .await,
        Some(false)
    );
    assert!(!adapter.account_subscription_eose(&account).await.complete());
}

#[tokio::test(start_paused = true)]
async fn page_overflow_keeps_peer() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xA8; 32]);
    let mut group = sync_fixture_group(0xA9);
    group
        .endpoints
        .push(TransportEndpoint("wss://complete.example".into()));
    let mut complete = group.clone();
    complete.endpoints.swap(0, 1);
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let id = group_subscription_id(&adapter, &account, &group).await;
    let initial_body = "i".repeat(8 * 1024);
    for index in 0..transport_nostr_adapter::RELAY_REPLAY_PAGE_LIMIT {
        let event = group_event_at(
            &format!("paging owner initial {index} {initial_body}"),
            &group,
            floor + 500 + index as u64,
        );
        route_group_copy(&adapter, &group, &id, &event).await;
    }
    let healthy = group_event_at("healthy older peer", &group, floor + 100);
    route_group_copy(&adapter, &complete, &id, &healthy).await;
    adapter
        .handle_relay_eose(complete.endpoints[0].clone(), id.clone())
        .await;
    let body = "x".repeat(3 * 1024 * 1024);
    // The acquired page itself fits its wire budget. Together with this
    // owner's initial history it exceeds the pending-body allowance.
    let mut page = (0..10)
        .map(|index| group_event_at(&body, &group, floor + 10 + index))
        .collect::<Vec<_>>();
    for index in page.len()..transport_nostr_adapter::RELAY_REPLAY_PAGE_LIMIT - 1 {
        page.push(group_event_at(
            &format!("small page tail {index}"),
            &group,
            floor + 30,
        ));
    }
    page.push(group_event_at(
        "small tail after overflow",
        &group,
        floor + 1,
    ));
    relay.pages.lock().unwrap().extend([
        (NostrAcquisitionEnd::RequestPolicySatisfied, page),
        (
            NostrAcquisitionEnd::RequestPolicySatisfied,
            vec![group_event_at("subsequent older page", &group, floor)],
        ),
    ]);
    relay.hold_acquisition.store(true, Ordering::SeqCst);
    adapter
        .handle_relay_eose(group.endpoints[0].clone(), id.clone())
        .await;
    wait_until("backward page is held", || {
        !relay.acquisitions.lock().unwrap().is_empty()
    })
    .await;
    let live = group_event_at("raw live during owned page", &group, floor + 2_000);
    route_group_copy(&adapter, &group, &id, &live).await;
    assert!(adapter.take_replay_status(&account).await.pending);
    assert_no_delivery(&adapter).await;
    relay.release_acquisition.notify_one();
    assert_eq!(
        replay_loss(&adapter, &account).await,
        NostrNotificationLossFloor::Since(floor)
    );
    assert_group_delivery(&adapter, &account, &healthy).await;
    assert_group_delivery(&adapter, &account, &live).await;
    assert_no_delivery(&adapter).await;
    let later = group_event_at("raw live after page overflow", &group, floor + 2_001);
    route_group_copy(&adapter, &group, &id, &later).await;
    assert_group_delivery(&adapter, &account, &later).await;
    assert_no_delivery(&adapter).await;
    assert_replay_idle(&adapter, &account).await;
    assert_eq!(
        relay.acquisitions.lock().unwrap().len(),
        1,
        "abandoning an overflowed page stops subsequent historical acquisitions"
    );
    assert_eq!(
        adapter
            .subscription_endpoint_eose(&id, &group.endpoints[0])
            .await,
        Some(false)
    );
    assert!(!adapter.account_subscription_eose(&account).await.complete());
}

#[tokio::test(start_paused = true)]
async fn waiting_peer_fences_payload() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xB5; 32]);
    let inbox_endpoint = TransportEndpoint("wss://inbox.example".into());
    let mut group = sync_fixture_group(0xB6);
    group
        .endpoints
        .push(TransportEndpoint("wss://slow.example".into()));
    let mut slow = group.clone();
    slow.endpoints.swap(0, 1);
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![inbox_endpoint.clone()],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let id = group_subscription_id(&adapter, &account, &group).await;
    let inbox_id = relay
        .take_issued_subscriptions()
        .into_iter()
        .find(|subscription| matches!(subscription, NostrSubscription::AccountInbox { .. }))
        .expect("activation issues its inbox REQ")
        .subscription_id();
    adapter.handle_relay_eose(inbox_endpoint, inbox_id).await;
    let newer = group_event_at("fast peer newer subset", &group, floor + 200);
    route_group_copy(&adapter, &group, &id, &newer).await;
    adapter
        .handle_relay_eose(group.endpoints[0].clone(), id.clone())
        .await;
    let live = group_event_at("fast peer live suffix", &group, floor + 300);
    route_group_copy(&adapter, &group, &id, &live).await;
    let untracked = group_event_at("untracked group suffix", &group, floor + 400);
    adapter
        .handle_relay_event(NostrRelayEvent {
            endpoint: group.endpoints[0].clone(),
            subscription_id: None,
            event: untracked.clone(),
        })
        .await
        .unwrap();
    assert_no_delivery(&adapter).await;
    tokio::time::advance(Duration::from_secs(1)).await;
    let older = group_event_at("slow peer older prefix", &slow, floor + 1);
    route_group_copy(&adapter, &slow, &id, &older).await;
    assert_no_delivery(&adapter).await;
    adapter
        .handle_relay_eose(slow.endpoints[0].clone(), id)
        .await;
    for event in [&older, &newer, &live, &untracked] {
        assert_group_delivery(&adapter, &account, event).await;
    }
    assert_replay_idle(&adapter, &account).await;
    assert!(adapter.account_subscription_eose(&account).await.complete());
}

#[tokio::test(start_paused = true)]
async fn empty_peer_expires_no_loss() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xB7; 32]);
    let mut group = sync_fixture_group(0xB8);
    group
        .endpoints
        .push(TransportEndpoint("wss://quiet.example".into()));
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let id = group_subscription_id(&adapter, &account, &group).await;
    let newer = group_event_at("available peer history", &group, floor + 200);
    route_group_copy(&adapter, &group, &id, &newer).await;
    adapter
        .handle_relay_eose(group.endpoints[0].clone(), id)
        .await;
    assert_no_delivery(&adapter).await;
    expire_admission().await;
    assert_group_delivery(&adapter, &account, &newer).await;
    assert_replay_idle(&adapter, &account).await;
    assert!(!adapter.account_subscription_eose(&account).await.complete());
    assert!(adapter.take_replay_status(&account).await.loss.is_none());
}

#[tokio::test(start_paused = true)]
async fn silent_route_expires() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xAB; 32]);
    let current = sync_fixture_group(0xAC);
    let mut retained = current.clone();
    retained.transport_group_id = vec![0xAE; 32];
    let floor = 1_700_000_000;
    retained.retained_since = Some(Timestamp(floor));
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![current.clone(), retained.clone()],
            since: Some(Timestamp(floor + 500)),
        })
        .await
        .unwrap();
    let current_id = group_subscription_id(&adapter, &account, &current).await;
    let retained_id = group_subscription_id(&adapter, &account, &retained).await;
    assert_ne!(
        current_id, retained_id,
        "the silent route owns a separate REQ"
    );
    let history = group_event_at("available current history", &current, floor + 600);
    route_group_copy(&adapter, &current, &current_id, &history).await;
    adapter
        .handle_relay_eose(current.endpoints[0].clone(), current_id.clone())
        .await;
    let live = group_event_at("current live awaits retained scope", &current, floor + 700);
    route_group_copy(&adapter, &current, &current_id, &live).await;
    assert!(adapter.take_replay_status(&account).await.pending);
    assert_no_delivery(&adapter).await;
    expire_admission().await;
    assert!(
        adapter.take_replay_status(&account).await.loss.is_none(),
        "an empty quiet source is durable admission debt, not dropped input"
    );
    assert_group_delivery(&adapter, &account, &history).await;
    assert_group_delivery(&adapter, &account, &live).await;
    assert_no_delivery(&adapter).await;
    assert_replay_idle(&adapter, &account).await;
    assert!(!adapter.account_subscription_eose(&account).await.complete());
    assert_eq!(
        adapter
            .subscription_endpoint_eose(&current_id, &current.endpoints[0])
            .await,
        Some(true)
    );
    assert_eq!(adapter.subscription_synced(&retained_id).await, Some(false));
    let late_history = group_event_at("expired retained history", &retained, floor + 1);
    route_group_copy(&adapter, &retained, &retained_id, &late_history).await;
    adapter
        .handle_relay_eose(retained.endpoints[0].clone(), retained_id.clone())
        .await;
    assert_eq!(adapter.subscription_synced(&retained_id).await, Some(false));
    assert_eq!(
        replay_loss(&adapter, &account).await,
        NostrNotificationLossFloor::Since(floor),
        "discarding an actual late stored copy does report loss"
    );
    assert_no_delivery(&adapter).await;
    assert_replay_idle(&adapter, &account).await;
}

#[tokio::test(start_paused = true)]
async fn partial_peer_expires() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xAF; 32]);
    let mut group = sync_fixture_group(0xB0);
    group
        .endpoints
        .push(TransportEndpoint("wss://partial.example".into()));
    let mut partial = group.clone();
    partial.endpoints.swap(0, 1);
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(floor)),
        })
        .await
        .unwrap();
    let id = group_subscription_id(&adapter, &account, &group).await;
    let failed = group_event_at("partial peer never reaches EOSE", &group, floor + 1);
    let healthy = group_event_at("completed peer history", &group, floor + 100);
    route_group_copy(&adapter, &partial, &id, &failed).await;
    route_group_copy(&adapter, &partial, &id, &healthy).await;
    route_group_copy(&adapter, &group, &id, &healthy).await;
    adapter
        .handle_relay_eose(group.endpoints[0].clone(), id.clone())
        .await;
    let live = group_event_at("completed peer live suffix", &group, floor + 200);
    route_group_copy(&adapter, &group, &id, &live).await;
    assert!(adapter.take_replay_status(&account).await.pending);
    assert_no_delivery(&adapter).await;
    expire_admission().await;
    assert_eq!(
        replay_loss(&adapter, &account).await,
        NostrNotificationLossFloor::Since(floor)
    );
    assert_group_delivery(&adapter, &account, &healthy).await;
    assert_group_delivery(&adapter, &account, &live).await;
    assert_no_delivery(&adapter).await;
    assert_replay_idle(&adapter, &account).await;
    let coverage = adapter.account_subscription_eose(&account).await;
    assert!(!coverage.complete());
    assert_eq!(coverage.relay_subscription_attempts_with_eose, 1);
    assert_eq!(
        adapter
            .subscription_endpoint_eose(&id, &group.endpoints[0])
            .await,
        Some(true)
    );
    assert_eq!(
        adapter
            .subscription_endpoint_eose(&id, &partial.endpoints[0])
            .await,
        Some(false)
    );
    let later = group_event_at("live after a peer expires", &group, floor + 201);
    route_group_copy(&adapter, &group, &id, &later).await;
    assert_group_delivery(&adapter, &account, &later).await;
    assert_replay_idle(&adapter, &account).await;
}

#[tokio::test(start_paused = true)]
async fn maintenance_after_failure() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account = MemberId::new(vec![0xB2; 32]);
    let group = sync_fixture_group(0xB3);
    let floor = 1_700_000_000;
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account.clone(),
            inbox_endpoints: vec![],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(floor + 1_000)),
        })
        .await
        .unwrap();
    let live_id = group_subscription_id(&adapter, &account, &group).await;
    adapter
        .handle_relay_eose(group.endpoints[0].clone(), live_id.clone())
        .await;
    let first = adapter
        .install_group_maintenance_recovery_subscription(
            &account,
            &group,
            1,
            Some(Timestamp(floor + 100)),
        )
        .await
        .unwrap();
    let reacquired = group_event_at("failed page later reacquired", &group, floor + 200);
    relay.pages.lock().unwrap().extend([
        (NostrAcquisitionEnd::Deadline, vec![reacquired.clone()]),
        (NostrAcquisitionEnd::Deadline, vec![reacquired.clone()]),
    ]);
    for index in 0..transport_nostr_adapter::RELAY_REPLAY_PAGE_LIMIT {
        let event = group_event_at(
            &format!("failed maintenance initial {index}"),
            &group,
            floor + 500 + index as u64,
        );
        route_group_copy(&adapter, &group, &first, &event).await;
    }
    assert!(adapter.take_replay_status(&account).await.pending);
    adapter
        .handle_relay_eose(group.endpoints[0].clone(), first.clone())
        .await;
    assert_eq!(
        replay_loss(&adapter, &account).await,
        NostrNotificationLossFloor::Since(floor + 100)
    );
    assert_no_delivery(&adapter).await;
    assert_replay_idle(&adapter, &account).await;
    let second = adapter
        .install_group_maintenance_recovery_subscription(
            &account,
            &group,
            2,
            Some(Timestamp(floor)),
        )
        .await
        .unwrap();
    assert_ne!(first, second);
    let older = group_event_at("fresh request reaches older history", &group, floor + 1);
    route_group_copy(&adapter, &group, &second, &reacquired).await;
    route_group_copy(&adapter, &group, &second, &older).await;
    let live = group_event_at("live held behind fresh maintenance", &group, floor + 2_000);
    route_group_copy(&adapter, &group, &live_id, &live).await;
    assert!(adapter.take_replay_status(&account).await.pending);
    assert_no_delivery(&adapter).await;
    adapter
        .handle_relay_eose(group.endpoints[0].clone(), second.clone())
        .await;
    for event in [&older, &reacquired, &live] {
        assert_group_delivery(&adapter, &account, event).await;
    }
    wait_replay_eose(&adapter, &second).await;
    assert_eq!(adapter.subscription_synced(&first).await, Some(false));
    assert_no_delivery(&adapter).await;
    assert_replay_idle(&adapter, &account).await;
}

#[tokio::test(start_paused = true)]
async fn wider_source_survives_failure() {
    for retire_complete in [false, true] {
        let relay = Arc::new(FakeRelayClient::default());
        let adapter = NostrTransportAdapter::new(relay.clone());
        let account = MemberId::new(vec![0xB5; 32]);
        let group = sync_fixture_group(0xB6);
        let floor = 1_700_000_000;
        adapter
            .activate_account(TransportAccountActivation {
                account_id: account.clone(),
                inbox_endpoints: vec![],
                group_subscriptions: vec![group.clone()],
                since: Some(Timestamp(floor + 1_000)),
            })
            .await
            .unwrap();
        let live_id = group_subscription_id(&adapter, &account, &group).await;
        adapter
            .handle_relay_eose(group.endpoints[0].clone(), live_id.clone())
            .await;
        let wide = adapter
            .install_group_maintenance_recovery_subscription(
                &account,
                &group,
                1,
                Some(Timestamp(floor)),
            )
            .await
            .unwrap();
        let narrow = adapter
            .install_group_maintenance_recovery_subscription(
                &account,
                &group,
                2,
                Some(Timestamp(floor + 500)),
            )
            .await
            .unwrap();
        let older = group_event_at(
            "only the healthy wider request owns this",
            &group,
            floor + 100,
        );
        let shared = group_event_at("both requests own this copy", &group, floor + 600);
        let failed = group_event_at(
            "only the failed narrow source owns this",
            &group,
            floor + 700,
        );
        route_group_copy(&adapter, &group, &wide, &shared).await;
        route_group_copy(&adapter, &group, &wide, &older).await;
        route_group_copy(&adapter, &group, &narrow, &failed).await;
        route_group_copy(&adapter, &group, &narrow, &shared).await;
        adapter
            .handle_relay_eose(group.endpoints[0].clone(), wide.clone())
            .await;
        if retire_complete {
            adapter
                .remove_group_maintenance_recovery_subscription(&account, &wide)
                .await
                .unwrap();
        }
        let live = group_event_at("live survives narrow-source failure", &group, floor + 2_000);
        route_group_copy(&adapter, &group, &live_id, &live).await;
        assert!(adapter.take_replay_status(&account).await.pending);
        assert_no_delivery(&adapter).await;
        adapter
            .handle_relay_closed(
                group.endpoints[0].clone(),
                narrow.clone(),
                refusal(None, SubscriptionRefusalDisposition::Dropped),
            )
            .await;
        assert_eq!(
            replay_loss(&adapter, &account).await,
            NostrNotificationLossFloor::Since(floor + 500),
            "the narrower loss floor is safe only because the older healthy claims survive"
        );
        for event in [&older, &shared, &live] {
            assert_group_delivery(&adapter, &account, event).await;
        }
        assert_eq!(adapter.subscription_synced(&narrow).await, Some(false));
        assert_no_delivery(&adapter).await;
        assert_replay_idle(&adapter, &account).await;
    }
}

#[tokio::test(start_paused = true)]
async fn failed_peer_keeps_loss() {
    for end in [
        NostrAcquisitionEnd::Deadline,
        NostrAcquisitionEnd::ByteLimitReached,
    ] {
        let relay = Arc::new(FakeRelayClient::default());
        let adapter = NostrTransportAdapter::new(relay.clone());
        let account = MemberId::new(vec![0xB8; 32]);
        let mut group = sync_fixture_group(0xB9);
        group
            .endpoints
            .push(TransportEndpoint("wss://paging.example".into()));
        let mut paging = group.clone();
        paging.endpoints.swap(0, 1);
        let floor = 1_700_000_000;
        adapter
            .activate_account(TransportAccountActivation {
                account_id: account.clone(),
                inbox_endpoints: vec![],
                group_subscriptions: vec![group.clone()],
                since: Some(Timestamp(floor)),
            })
            .await
            .unwrap();
        let id = group_subscription_id(&adapter, &account, &group).await;
        let healthy = group_event_at("healthy peer history", &group, floor + 100);
        let shared = group_event_at("healthy peer also owns this", &group, floor + 500);
        route_group_copy(&adapter, &group, &id, &shared).await;
        route_group_copy(&adapter, &group, &id, &healthy).await;
        route_group_copy(&adapter, &paging, &id, &shared).await;
        for index in 1..transport_nostr_adapter::RELAY_REPLAY_PAGE_LIMIT {
            let event = group_event_at(
                &format!("unavailable peer initial {index}"),
                &group,
                floor + 500 + index as u64,
            );
            route_group_copy(&adapter, &paging, &id, &event).await;
        }
        adapter
            .handle_relay_eose(group.endpoints[0].clone(), id.clone())
            .await;
        let live = group_event_at("healthy live while peer pages", &group, floor + 2_000);
        route_group_copy(&adapter, &group, &id, &live).await;
        let failed = group_event_at("failed page never admitted", &group, floor + 1);
        relay
            .pages
            .lock()
            .unwrap()
            .push_back((end, vec![failed.clone()]));
        if end == NostrAcquisitionEnd::Deadline {
            relay.pages.lock().unwrap().push_back((end, vec![failed]));
        }
        relay.hold_acquisition.store(true, Ordering::SeqCst);
        adapter
            .handle_relay_eose(paging.endpoints[0].clone(), id.clone())
            .await;
        wait_until("failed peer starts paging", || {
            !relay.acquisitions.lock().unwrap().is_empty()
        })
        .await;
        assert!(adapter.take_replay_status(&account).await.pending);
        assert_no_delivery(&adapter).await;
        relay.hold_acquisition.store(false, Ordering::SeqCst);
        relay.release_acquisition.notify_one();
        assert_eq!(
            replay_loss(&adapter, &account).await,
            NostrNotificationLossFloor::Since(floor),
            "a completed peer cannot erase an interrupted or saturated owner's loss"
        );
        for event in [&healthy, &shared, &live] {
            assert_group_delivery(&adapter, &account, event).await;
        }
        assert_no_delivery(&adapter).await;
        assert_replay_idle(&adapter, &account).await;
        assert!(!adapter.account_subscription_eose(&account).await.complete());
        assert_eq!(
            adapter
                .subscription_endpoint_eose(&id, &group.endpoints[0])
                .await,
            Some(true)
        );
        assert_eq!(
            adapter
                .subscription_endpoint_eose(&id, &paging.endpoints[0])
                .await,
            Some(false)
        );
    }
}

/// A replay that delivered a full page may have been clamped by the relay. A
/// backend that cannot page backwards cannot prove the older history was
/// served, so that relay's EOSE must not complete the coverage (#2263).
#[tokio::test]
async fn full_page_replay_stays_incomplete_when_paging_is_unsupported() {
    let relay = Arc::new(FakeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone() as Arc<dyn NostrRelayClient>);
    let account_id = MemberId::new(vec![0xF8; 32]);
    let group = TransportGroupSubscription {
        group_id: cgka_traits::GroupId::new(vec![0xB8; 32]),
        transport_group_id: vec![0xC8; 32],
        endpoints: vec![TransportEndpoint("wss://group.example".into())],
        retained_since: None,
    };
    let inbox = TransportEndpoint("wss://inbox.example".into());
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![inbox.clone()],
            group_subscriptions: vec![group.clone()],
            since: Some(Timestamp(1_700_000_000)),
        })
        .await
        .expect("activation succeeds");
    let issued = relay.take_issued_subscriptions();
    let inbox_id = issued
        .iter()
        .find(|subscription| matches!(subscription, NostrSubscription::AccountInbox { .. }))
        .expect("the inbox REQ was issued")
        .subscription_id();
    let group_id = issued_group_id(&issued, &group.group_id);
    let endpoint = group.endpoints[0].clone();
    for index in 0..transport_nostr_adapter::RELAY_REPLAY_PAGE_LIMIT {
        let event = group_event_at(
            &format!("{index:04x}"),
            &group,
            1_700_000_500 + index as u64,
        );
        route_group_copy(&adapter, &group, &group_id, &event).await;
    }
    adapter.handle_relay_eose(inbox, inbox_id).await;
    adapter.handle_relay_eose(endpoint, group_id.clone()).await;
    assert_eq!(
        replay_loss(&adapter, &account_id).await,
        NostrNotificationLossFloor::Since(1_700_000_000)
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(25), adapter.receive())
            .await
            .is_err()
    );
    let live = group_event_at("live after unsupported paging", &group, 1_700_001_001);
    route_group_copy(&adapter, &group, &group_id, &live).await;
    assert_group_delivery(&adapter, &account_id, &live).await;
    {
        let status = adapter.take_replay_status(&account_id).await;
        assert!(!status.pending);
        assert!(status.loss.is_none());
    }
    let eose = adapter.account_subscription_eose(&account_id).await;
    assert!(
        !eose.complete(),
        "a full page with no paging is not coverage"
    );
    assert!(
        !eose.settled(),
        "incomplete history cannot settle replay coverage"
    );
}

/// A straggler that registers while the next activation is still sweeping sees
/// the outgoing activation's routes, which list its id. Its check must wait
/// for that activation to install its new routes, then close the superseded
/// REQ (#2262).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn straggler_registering_during_the_next_sweep_closes_its_req() {
    let relay = Arc::new(ReleasableSubscribeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA3; 32]);
    let group = sync_fixture_group(0xB6);
    let activation = || TransportAccountActivation {
        account_id: account_id.clone(),
        inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
        group_subscriptions: vec![group.clone()],
        since: None,
    };
    adapter
        .activate_account(activation())
        .await
        .expect("activation succeeds");
    let superseded = group_subscription_id(&adapter, &account_id, &group).await;
    let held_before = relay.held.load(Ordering::SeqCst);

    relay.hold.store(true, Ordering::SeqCst);
    let dropped = tokio::spawn({
        let adapter = adapter.clone();
        let activation = activation();
        async move { adapter.activate_account(activation).await }
    });
    wait_until("both subscribes are held", || {
        relay.held.load(Ordering::SeqCst) >= held_before + 2
    })
    .await;
    dropped.abort();
    assert!(dropped.await.unwrap_err().is_cancelled());
    let dropped_group = {
        // The dropped activation issued under the next attempt.
        let attempt = adapter
            .account_subscription_attempt(&account_id)
            .await
            .expect("the account is active");
        let dropped_group = group_subscription_id(&adapter, &account_id, &group).await;
        assert_ne!(dropped_group, superseded);
        assert_eq!(
            dropped_group,
            NostrSubscription::GroupBatch {
                account_id: account_id.clone(),
                routes: Vec::new(),
                endpoints: group.endpoints.clone(),
                since: None,
                attempt,
                batch: 0,
            }
            .subscription_id()
        );
        dropped_group
    };

    relay.hold.store(false, Ordering::SeqCst);
    // The stragglers return inside the sweep, before the new routes exist.
    relay.release_during_sweep.store(true, Ordering::SeqCst);
    adapter
        .activate_account(activation())
        .await
        .expect("the next activation proceeds after the straggler wait");
    wait_until("the stragglers close their superseded REQs", || {
        relay.unsubscribed.lock().unwrap().contains(&dropped_group)
    })
    .await;
    let live = group_subscription_id(&adapter, &account_id, &group).await;
    assert!(
        !relay.unsubscribed.lock().unwrap().contains(&live),
        "the new activation's REQ stays open"
    );
}

/// A retired straggler's route check and CLOSE must not interleave with a
/// retry registering the same route: the retry's registration has to land
/// after the straggler's CLOSE, so the live route keeps its REQ. The retry
/// repacks the route into a fresh batch, so the straggler's CLOSE never names
/// it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retired_straggler_close_cannot_interleave_with_a_retry() {
    let relay = Arc::new(ReleasableSubscribeRelayClient::default());
    let adapter = NostrTransportAdapter::new(relay.clone());
    let account_id = MemberId::new(vec![0xA4; 32]);
    let (kept, added) = (sync_fixture_group(0xB7), sync_fixture_group(0xC9));
    adapter
        .activate_account(TransportAccountActivation {
            account_id: account_id.clone(),
            inbox_endpoints: vec![TransportEndpoint("wss://inbox.example".into())],
            group_subscriptions: vec![kept.clone()],
            since: None,
        })
        .await
        .expect("activation succeeds");
    // The cancelled sync repacks kept and added into batch 1, after the
    // activation's batch 0.
    let added_id = batch_subscription_id(&adapter, &account_id, &added.endpoints, 1).await;

    cancel_held_group_sync(
        &relay,
        &adapter,
        &account_id,
        vec![kept.clone(), added.clone()],
    )
    .await;
    // The cancelled sync's cleanup outlives the wait, retires the barrier and
    // closes the not-yet-registered id.
    wait_until("the cleanup closes the abandoned id", || {
        relay.unsubscribed.lock().unwrap().contains(&added_id)
    })
    .await;

    // The straggler registers, finds the id unwanted, and stalls in its CLOSE.
    relay.hold_unsubscribes.store(true, Ordering::SeqCst);
    relay.release.notify_waiters();
    wait_until("the straggler's CLOSE is in flight", || {
        relay.unsubscribes_held.load(Ordering::SeqCst) == 1
    })
    .await;
    let retry = tokio::spawn({
        let adapter = adapter.clone();
        let sync = TransportGroupSync {
            account_id: account_id.clone(),
            group_subscriptions: vec![kept, added.clone()],
            since: None,
        };
        async move { adapter.sync_account_groups(sync).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    relay.hold_unsubscribes.store(false, Ordering::SeqCst);
    relay.release_unsubscribes.notify_waiters();
    retry
        .await
        .unwrap()
        .expect("the retry makes the group live");
    // The straggler is detached: wait for its CLOSE to land as well.
    wait_until("the straggler's CLOSE lands", || {
        relay
            .unsubscribed
            .lock()
            .unwrap()
            .iter()
            .filter(|id| **id == added_id)
            .count()
            == 2
    })
    .await;

    let live_id = group_subscription_id(&adapter, &account_id, &added).await;
    assert_ne!(live_id, added_id, "the retry goes out in a new batch");
    let log = relay.log.lock().unwrap().clone();
    let last_close = log
        .iter()
        .rposition(|entry| *entry == format!("-{added_id}"))
        .expect("the abandoned id was closed");
    let registered = log
        .iter()
        .position(|entry| *entry == format!("+{live_id}"))
        .expect("the retry registered its batch");
    assert!(
        registered > last_close,
        "the retry registered after the straggler's CLOSE: {log:?}"
    );
    assert!(
        !log.contains(&format!("-{live_id}")),
        "the live route keeps its REQ: {log:?}"
    );
}
