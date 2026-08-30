use std::collections::{HashMap, HashSet};
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::{
    MemberId, TransportAdapterError, TransportEndpoint, TransportEndpointFailure,
    TransportEndpointFailureKind, TransportEndpointReceipt, TransportEndpointRejectionCategory,
    TransportPublishFailure, collapse_publish_failure_summaries,
};
use nostr_sdk::prelude::{
    Alphabet, Client, Event, EventBuilder, EventId, Filter, Kind, PublicKey, RelayMessage,
    RelayPoolNotification, RelayStatus, RelayUrl, SingleLetterTag, SubscriptionId, SyncDirection,
    SyncOptions, Tag, TagKind, Timestamp as NostrTimestamp,
};
use tokio::sync::{Mutex, RwLock};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{timeout, timeout_at};
use transport_nostr_peeler::{KIND_MARMOT_GROUP_MESSAGE, NostrTransportEvent};

use crate::{
    NostrEventPublishRequest, NostrPublishBatch, NostrPublishOutcome, NostrRelayClient,
    NostrRelayEvent, NostrSubscription, NostrTransportAdapter,
};

const SDK_RELAY_CONNECT_WAIT: Duration = Duration::from_secs(5);
/// Keep the SDK's own reconnect sleep aligned with MDK's durable transport
/// retry budget. The SDK default adaptively grows to 60 seconds, which leaves
/// queued messages idle long after mobile connectivity has returned.
const SDK_RELAY_RETRY_INTERVAL: Duration = Duration::from_secs(5);
// nostr-sdk 0.44 waits up to 10s for each relay's OK response. Keep this
// wrapper above that so SDK endpoint-level success/failure results surface
// instead of a MDK-level timeout masking them.
const SDK_RELAY_PUBLISH_WAIT: Duration = Duration::from_secs(12);
/// Publishing to relays is best-effort over a flaky network: retry the send a
/// few times (with a short backoff) before giving up, so a single slow relay
/// doesn't fail the whole publish.
const SDK_RELAY_PUBLISH_ATTEMPTS: usize = 3;
const SDK_RELAY_PUBLISH_RETRY_BACKOFF: Duration = Duration::from_millis(600);
/// Overall wall-clock ceiling for a single `publish_event` fan-out. The
/// per-relay connect/send/retry budget above still applies to each relay, but
/// the whole publish aborts and returns once this elapses. Without it, a publish
/// to relays that are all unreachable (or that cannot meet `required_acks`)
/// waits out every relay's full retry budget (~38s) before failing; this bounds
/// that degraded case. Sized to still allow a slow relay one full connect plus
/// send attempt (`SDK_RELAY_CONNECT_WAIT + SDK_RELAY_PUBLISH_WAIT`) with margin.
const SDK_RELAY_PUBLISH_OVERALL_WAIT: Duration = Duration::from_secs(20);
/// Whole-batch ceiling. Individual events retain the existing 20-second
/// ceiling, while a pathological multi-event teardown cannot multiply that
/// bound without limit.
const SDK_RELAY_BATCH_OVERALL_WAIT: Duration = Duration::from_secs(60);
/// Independent events in one bootstrap batch may publish concurrently, but a
/// caller-controlled batch must not create an unbounded number of relay-send
/// fan-outs. Four covers the generated-account bootstrap cohort while keeping
/// larger batches backpressured.
const SDK_RELAY_BATCH_MAX_IN_FLIGHT: usize = 4;
/// One route gets a strict pass-wide budget, including set comparison, replay
/// fetch, decoding, and materialization. The app rotates routes durably, so a
/// slow route cannot consume the whole account startup quantum.
const SDK_RECONCILIATION_WAIT: Duration = Duration::from_secs(2);
const SDK_RECONCILIATION_NEGOTIATION_WAIT: Duration = Duration::from_millis(500);
/// Fetch and materialize only this deterministic prefix of a remote-only set.
/// Durable app ingestion adds those ids to the next comparison, which makes a
/// large first-run difference converge across bounded passes.
const SDK_RECONCILIATION_REPLAY_BATCH: usize = 128;
/// Must match the storage inventory ceiling. The relay applies the same limit,
/// bounding the dry-run result even on first boot with an empty inventory.
const SDK_RECONCILIATION_SET_LIMIT: usize = 16_384;

fn bounded_reconciliation_remote_ids(remote: &HashSet<EventId>) -> Vec<EventId> {
    let mut ids = remote.iter().copied().collect::<Vec<_>>();
    ids.sort_unstable();
    ids.truncate(SDK_RECONCILIATION_REPLAY_BATCH);
    ids
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrReconciliationItem {
    pub event_id: [u8; 32],
    pub created_at: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NostrReconciliationSummary {
    pub relays_succeeded: usize,
    pub relays_failed: usize,
    pub remote_items: usize,
    pub received_items: usize,
}

/// Planned SDK subscription derived from a transport-adapter subscription.
#[derive(Clone, Debug)]
pub struct NostrSdkSubscriptionPlan {
    pub account_id: MemberId,
    pub subscription_id: SubscriptionId,
    pub endpoints: Vec<RelayUrl>,
    pub filter: Filter,
}

/// Redacted SDK relay health summary.
///
/// This intentionally reports only aggregate status and connection counters. It
/// does not expose relay URLs, subscription ids, group ids, pubkeys, or message
/// identifiers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NostrSdkRelayHealth {
    pub total_relays: usize,
    pub initialized: usize,
    pub pending: usize,
    pub connecting: usize,
    pub connected: usize,
    pub disconnected: usize,
    pub terminated: usize,
    pub banned: usize,
    pub sleeping: usize,
    pub connection_attempts: usize,
    pub connection_successes: usize,
}

/// One relay's subscription-registration outcome, surfaced to the app so it can
/// be recorded in the forensic audit log's `subscription_rebuild` row.
///
/// `relay_url` is the caller-supplied subscription endpoint (the app already
/// holds it — it is not a reverse-mapped [`crate::RelayIndex`], so this crosses
/// no new identity over the boundary); `accepted` is whether the relay pool
/// acknowledged the subscription registration. This is only returned to the
/// caller — the adapter never logs the URL (the privacy invariant applies to
/// tracing, not to this return value).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayRegistrationOutcome {
    pub relay_url: String,
    pub accepted: bool,
}

/// `nostr-sdk` backed implementation of [`NostrRelayClient`].
#[derive(Clone)]
pub struct NostrSdkRelayClient {
    client: Client,
    account_subscriptions: Arc<RwLock<HashMap<MemberId, Vec<SubscriptionId>>>>,
    publish_relay_refs: Arc<Mutex<HashMap<RelayUrl, usize>>>,
    #[cfg(test)]
    publish_connect_attempts: Arc<Mutex<HashMap<RelayUrl, usize>>>,
    #[cfg(test)]
    publish_release_attempts: Arc<Mutex<HashMap<RelayUrl, usize>>>,
    #[cfg(test)]
    publish_relay_pin_failure_stage: Arc<AtomicU8>,
    /// Relays that explicitly rejected NIP-77 are skipped for the rest of this
    /// process. Transient connection failures are never cached here.
    reconciliation_unsupported_relays: Arc<RwLock<HashSet<RelayUrl>>>,
    /// Per-account, per-relay subscription-registration outcomes accumulated
    /// since that account's last
    /// [`take_subscription_registrations`](Self::take_subscription_registrations)
    /// drain, bucketed by account then keyed by endpoint. Within an account's
    /// bucket a relay is merged monotonically (it counts as registered once any
    /// of that account's subscriptions lands on it) so the app can attribute one
    /// rebuild's registration results to a single audit row. Bucketing by
    /// account keeps concurrent account workers on the one shared relay plane
    /// from draining each other's registrations. Shared via `Arc` so the clone
    /// the adapter drives during activation and the clone the app holds observe
    /// the same log.
    registration_log: Arc<Mutex<HashMap<MemberId, HashMap<RelayUrl, bool>>>>,
}

struct ScopedPublishRelayLease {
    owner: NostrSdkRelayClient,
    endpoints: Vec<RelayUrl>,
}

impl ScopedPublishRelayLease {
    fn new(owner: NostrSdkRelayClient) -> Self {
        Self {
            owner,
            endpoints: Vec::new(),
        }
    }

    fn retain(&mut self, endpoint: RelayUrl) {
        self.endpoints.push(endpoint);
    }

    async fn release(mut self) {
        while let Some(endpoint) = self.endpoints.last().cloned() {
            if self.owner.release_publish_relay(endpoint).await.is_err() {
                tracing::warn!(
                    target: "transport_nostr_adapter::sdk_client",
                    method = "release_publish_batch",
                    "failed to clean up SDK publish relay"
                );
            }
            // Pop only after the awaited release. If this future is cancelled
            // during cleanup, Drop still owns this endpoint and delegates the
            // remaining cleanup to an independent task.
            self.endpoints.pop();
        }
    }
}

impl Drop for ScopedPublishRelayLease {
    fn drop(&mut self) {
        let endpoints = std::mem::take(&mut self.endpoints);
        if endpoints.is_empty() {
            return;
        }
        let owner = self.owner.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            // A dropped batch future is cancellation. Hand cleanup to an
            // independent task so transient write relays do not outlive the
            // cancelled scope.
            runtime.spawn(async move {
                owner.cleanup_publish_relays(endpoints).await;
            });
        }
    }
}

struct PreparedPublish {
    endpoints: Vec<RelayUrl>,
    event: Event,
    required_acks: usize,
}

impl NostrSdkRelayClient {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            account_subscriptions: Arc::new(RwLock::new(HashMap::new())),
            publish_relay_refs: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            publish_connect_attempts: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            publish_release_attempts: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            publish_relay_pin_failure_stage: Arc::new(AtomicU8::new(0)),
            reconciliation_unsupported_relays: Arc::new(RwLock::new(HashSet::new())),
            registration_log: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Reconcile the content-addressed event set in one route's gap below the
    /// ordinary subscription floor. NIP-77 compares event ids, so a
    /// late-published event is discoverable regardless of its authored
    /// timestamp without replaying current MLS traffic through a second path.
    pub async fn reconcile_subscription(
        &self,
        subscription: NostrSubscription,
        local_items: &[NostrReconciliationItem],
        reconcile_since: u64,
        reconcile_until: u64,
    ) -> Result<(NostrReconciliationSummary, Vec<NostrRelayEvent>), TransportAdapterError> {
        let mut plan = Self::plan_subscription(&subscription)?;
        // The ordinary subscription owns its inclusive timestamp window. The
        // correctness pass compares only the older gap, avoiding a second,
        // unordered delivery path for current MLS traffic while still finding
        // events that a fixed `since` floor can never see.
        plan.filter = plan
            .filter
            .since(NostrTimestamp::from_secs(reconcile_since))
            .until(NostrTimestamp::from_secs(reconcile_until))
            .limit(SDK_RECONCILIATION_SET_LIMIT);
        let unsupported = self.reconciliation_unsupported_relays.read().await;
        let endpoints = plan
            .endpoints
            .iter()
            .filter(|endpoint| !unsupported.contains(*endpoint))
            .cloned()
            .collect::<Vec<_>>();
        let unsupported_count = plan.endpoints.len().saturating_sub(endpoints.len());
        drop(unsupported);
        let Some(replay_endpoint) = endpoints.first().cloned() else {
            return Ok((
                NostrReconciliationSummary {
                    relays_failed: unsupported_count,
                    ..NostrReconciliationSummary::default()
                },
                Vec::new(),
            ));
        };
        let subscription_id = plan.subscription_id.to_string();
        let items = local_items
            .iter()
            .filter(|item| item.created_at >= reconcile_since && item.created_at <= reconcile_until)
            .map(|item| {
                (
                    EventId::from_byte_array(item.event_id),
                    NostrTimestamp::from_secs(item.created_at),
                )
            })
            .collect::<Vec<_>>();
        let targets = endpoints
            .iter()
            .cloned()
            .map(|endpoint| (endpoint, (plan.filter.clone(), items.clone())))
            .collect::<Vec<_>>();
        let options = SyncOptions::new()
            .initial_timeout(SDK_RECONCILIATION_NEGOTIATION_WAIT)
            .direction(SyncDirection::Down)
            .dry_run();
        let deadline = tokio::time::Instant::now() + SDK_RECONCILIATION_WAIT;
        let output = timeout_at(
            deadline,
            self.client.pool().sync_targeted(targets, &options),
        )
        .await
        .map_err(|_| {
            TransportAdapterError::Subscription("NIP-77 reconciliation timed out".to_owned())
        })?
        .map_err(|_| {
            TransportAdapterError::Subscription("NIP-77 reconciliation failed".to_owned())
        })?;
        let newly_unsupported = output
            .failed
            .iter()
            .filter(|(_, error)| {
                error.as_str() == "negentropy not supported"
                    || error.as_str() == "unsupported negentropy protocol version"
            })
            .map(|(endpoint, _)| endpoint.clone())
            .collect::<Vec<_>>();
        if !newly_unsupported.is_empty() {
            self.reconciliation_unsupported_relays
                .write()
                .await
                .extend(newly_unsupported);
        }
        // Compare without SDK-managed downloads: its download path returns
        // only after every 100-id REQ/EOSE batch, so an outer timeout discards
        // all useful progress. Instead, deterministically request a bounded
        // prefix and let durable app ingestion shrink the next dry-run diff.
        let remote_item_count = output.val.remote.len();
        let remote_ids = bounded_reconciliation_remote_ids(&output.val.remote);
        let mut sdk_events = Vec::new();
        let mut missing_ids = Vec::new();
        for event_id in remote_ids {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            match self
                .client
                .database()
                .event_by_id(&event_id)
                .await
                .map_err(|_| {
                    TransportAdapterError::Subscription(
                        "read reconciled event from SDK database failed".to_owned(),
                    )
                })? {
                Some(event) => sdk_events.push(event),
                None => missing_ids.push(event_id),
            }
        }
        let fetched_items = if missing_ids.is_empty() {
            0
        } else {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                0
            } else {
                // Fresh events also produce the SDK's ordinary pool
                // notification, which is already routed through the account
                // delivery queue. Count that bounded fetch here but do not
                // explicitly enqueue it a second time. Cache hits above emit
                // no pool notification and therefore use the account-scoped
                // materialization path below.
                self.client
                    .fetch_events_from(endpoints, Filter::new().ids(missing_ids), remaining)
                    .await
                    .map_err(|_| {
                        TransportAdapterError::Subscription(
                            "fetch reconciled event batch failed".to_owned(),
                        )
                    })?
                    .len()
            }
        };
        // Negentropy reports a set. MLS input is sequential, so replay the
        // materialized difference in the same authored-time/id order used by
        // stored-event catch-up instead of HashSet iteration order.
        sdk_events.sort_unstable_by_key(|event| (event.created_at, event.id));
        let mut remote_events = Vec::with_capacity(sdk_events.len());
        for event in sdk_events {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            remote_events.push(NostrRelayEvent {
                endpoint: TransportEndpoint(replay_endpoint.to_string()),
                subscription_id: Some(subscription_id.clone()),
                event: NostrTransportEvent::from_nostr_event(&event).map_err(|error| {
                    TransportAdapterError::Subscription(format!(
                        "decode reconciled SDK event: {error}"
                    ))
                })?,
            });
        }
        let summary = NostrReconciliationSummary {
            relays_succeeded: output.success.len(),
            relays_failed: output.failed.len().saturating_add(unsupported_count),
            remote_items: remote_item_count,
            received_items: remote_events.len().saturating_add(fetched_items),
        };
        Ok((summary, remote_events))
    }

    /// Summarize SDK-owned relay health without exposing relay URLs.
    pub async fn relay_health(&self) -> NostrSdkRelayHealth {
        let mut health = NostrSdkRelayHealth::default();
        for relay in self.client.relays().await.into_values() {
            health.total_relays += 1;
            health.connection_attempts += relay.stats().attempts();
            health.connection_successes += relay.stats().success();
            health.record_status(relay.status());
        }
        health
    }

    /// Drain the per-relay subscription-registration outcomes `account`
    /// accumulated since its previous drain, sorted by relay URL for stable
    /// audit output.
    ///
    /// Draining is account-scoped: it removes and returns only `account`'s
    /// bucket, so concurrent account workers sharing this one relay plane each
    /// attribute their own registrations to their own `subscription_rebuild`
    /// audit row. Each outcome lands on exactly one row for that account; a
    /// subsequent rebuild for the same account starts from an empty bucket.
    /// Returns an empty vec when `account` has registered no subscription since
    /// its last drain. A group shared across accounts registers once, attributed
    /// to whichever account's client subscribed (an acceptable diagnostic
    /// attribution).
    pub async fn take_subscription_registrations(
        &self,
        account: &MemberId,
    ) -> Vec<RelayRegistrationOutcome> {
        let mut log = self.registration_log.lock().await;
        let mut outcomes: Vec<RelayRegistrationOutcome> = log
            .remove(account)
            .unwrap_or_default()
            .into_iter()
            .map(|(relay, accepted)| RelayRegistrationOutcome {
                relay_url: relay.to_string(),
                accepted,
            })
            .collect();
        outcomes.sort_by(|a, b| a.relay_url.cmp(&b.relay_url));
        outcomes
    }

    /// Start forwarding `nostr-sdk` notifications into the adapter's delivery
    /// queue. The task exits when the relay pool shuts down.
    pub fn spawn_notification_forwarder(&self, adapter: NostrTransportAdapter) -> JoinHandle<()> {
        let client = self.client.clone();
        tokio::spawn(async move {
            let _ = client
                .handle_notifications(move |notification| {
                    let adapter = adapter.clone();
                    async move {
                        match notification {
                            RelayPoolNotification::Event {
                                relay_url,
                                subscription_id,
                                event,
                            } => {
                                if let Ok(event) = NostrTransportEvent::from_nostr_event(&event) {
                                    tracing::trace!(
                                        target: "transport_nostr_adapter::sdk_client",
                                        method = "spawn_notification_forwarder",
                                        "forwarding SDK relay event"
                                    );
                                    let _ = adapter
                                        .handle_relay_event(NostrRelayEvent {
                                            endpoint: TransportEndpoint(relay_url.to_string()),
                                            subscription_id: Some(subscription_id.to_string()),
                                            event,
                                        })
                                        .await;
                                }
                                Ok(false)
                            }
                            RelayPoolNotification::Message {
                                relay_url,
                                message:
                                    RelayMessage::Event {
                                        subscription_id,
                                        event,
                                    },
                            } => {
                                // Raw per-relay copy (not deduplicated): telemetry
                                // only, so cross-relay spread sees every relay's
                                // copy. Delivery happens on the deduplicated
                                // `Event` notification above.
                                if let Ok(event) = NostrTransportEvent::from_nostr_event(&event) {
                                    tracing::trace!(
                                        target: "transport_nostr_adapter::sdk_client",
                                        method = "spawn_notification_forwarder",
                                        "observing per-relay event copy"
                                    );
                                    adapter
                                        .observe_relay_event(NostrRelayEvent {
                                            endpoint: TransportEndpoint(relay_url.to_string()),
                                            subscription_id: Some(subscription_id.to_string()),
                                            event,
                                        })
                                        .await;
                                }
                                Ok(false)
                            }
                            RelayPoolNotification::Message {
                                relay_url,
                                message: RelayMessage::EndOfStoredEvents(subscription_id),
                            } => {
                                tracing::trace!(
                                    target: "transport_nostr_adapter::sdk_client",
                                    method = "spawn_notification_forwarder",
                                    "forwarding SDK relay EOSE"
                                );
                                adapter
                                    .handle_relay_eose(
                                        TransportEndpoint(relay_url.to_string()),
                                        subscription_id.to_string(),
                                    )
                                    .await;
                                Ok(false)
                            }
                            RelayPoolNotification::Shutdown => {
                                tracing::debug!(
                                    target: "transport_nostr_adapter::sdk_client",
                                    method = "spawn_notification_forwarder",
                                    "SDK relay pool shutdown observed"
                                );
                                Ok(true)
                            }
                            _ => Ok(false),
                        }
                    }
                })
                .await;
        })
    }

    pub fn plan_subscription(
        subscription: &NostrSubscription,
    ) -> Result<NostrSdkSubscriptionPlan, TransportAdapterError> {
        match subscription {
            NostrSubscription::AccountInbox {
                account_id,
                endpoints,
                since,
            } => {
                let pubkey = member_id_to_pubkey(account_id, "account inbox subscription")?;
                let mut filter = Filter::new().kind(Kind::GiftWrap).pubkey(pubkey);
                if let Some(since) = since {
                    filter = filter.since(NostrTimestamp::from_secs(since.0));
                }
                let subscription_id = SubscriptionId::new(subscription.subscription_id());
                Ok(NostrSdkSubscriptionPlan {
                    account_id: account_id.clone(),
                    subscription_id,
                    endpoints: parse_endpoints(endpoints, "account inbox subscription")?,
                    filter,
                })
            }
            NostrSubscription::Group {
                account_id,
                group_id: _,
                transport_group_id,
                endpoints,
                since,
            } => {
                let h_tag = hex::encode(transport_group_id);
                let mut filter = Filter::new()
                    .kind(Kind::MlsGroupMessage)
                    .custom_tags(SingleLetterTag::lowercase(Alphabet::H), [h_tag.clone()]);
                if let Some(since) = since {
                    filter = filter.since(NostrTimestamp::from_secs(since.0));
                }
                let subscription_id = SubscriptionId::new(subscription.subscription_id());
                Ok(NostrSdkSubscriptionPlan {
                    account_id: account_id.clone(),
                    subscription_id,
                    endpoints: parse_endpoints(endpoints, "group subscription")?,
                    filter,
                })
            }
            NostrSubscription::GroupMaintenance {
                account_id,
                group_id: _,
                transport_group_id,
                endpoints,
            } => {
                let h_tag = hex::encode(transport_group_id);
                let filter = Filter::new()
                    .kind(Kind::MlsGroupMessage)
                    .custom_tags(SingleLetterTag::lowercase(Alphabet::H), [h_tag.clone()]);
                let subscription_id = SubscriptionId::new(subscription.subscription_id());
                Ok(NostrSdkSubscriptionPlan {
                    account_id: account_id.clone(),
                    subscription_id,
                    endpoints: parse_endpoints(endpoints, "group maintenance subscription")?,
                    filter,
                })
            }
        }
    }

    async fn event_for_publish(
        &self,
        event: &NostrTransportEvent,
    ) -> Result<Event, TransportAdapterError> {
        if event.sig.is_some() {
            return event
                .to_verified_nostr_event()
                .map_err(|e| TransportAdapterError::Publish(format!("invalid signed event: {e}")));
        }

        // spec/transports/nostr.md:64-66 — a kind-445 group event's pubkey MUST
        // be a fresh per-event ephemeral key and MUST NOT be the sender's
        // account identity. The peeler signs every outbound 445 ephemerally at
        // wrap time, so a 445 that reaches publish without a sig is a caller
        // error. Fail closed rather than fall through to the account signer
        // below, which would stamp the account pubkey into the routing-visible
        // envelope (metadata/correlation leak).
        if event.kind == KIND_MARMOT_GROUP_MESSAGE {
            return Err(TransportAdapterError::Publish(
                "refusing to sign unsigned kind-445 group event with the account identity: \
                 kind-445 events must arrive pre-signed by the peeler's per-event ephemeral key"
                    .to_owned(),
            ));
        }

        let kind = u16::try_from(event.kind).map(Kind::from).map_err(|_| {
            TransportAdapterError::Publish(format!("unsupported kind {}", event.kind))
        })?;
        let tags = event
            .tags
            .iter()
            .map(|tag| nostr_tag_from_vec(tag))
            .collect::<Result<Vec<_>, _>>()?;
        let builder = EventBuilder::new(kind, event.content.clone())
            .tags(tags)
            .custom_created_at(NostrTimestamp::from_secs(event.created_at));
        self.client
            .sign_event_builder(builder)
            .await
            .map_err(|e| TransportAdapterError::Publish(format!("sign event: {e}")))
    }

    async fn connect_publish_relay(
        &self,
        endpoint: RelayUrl,
    ) -> Result<RelayUrl, TransportEndpointFailure> {
        #[cfg(test)]
        {
            *self
                .publish_connect_attempts
                .lock()
                .await
                .entry(endpoint.clone())
                .or_default() += 1;
        }
        let transport_endpoint = TransportEndpoint(endpoint.to_string());
        // `Client::connect_relay` only starts a background task and returns
        // before the WebSocket handshake completes. Sending immediately after
        // that call can therefore turn a proven offline connection failure
        // into `PossiblyExposed`, putting a message behind the conservative
        // ambiguity clock even though no relay could have received it. Await
        // the SDK's bounded connection attempt so pre-send failures remain
        // explicitly retryable and a host connectivity wake can replay them
        // immediately.
        match self
            .client
            .try_connect_relay(endpoint.clone(), SDK_RELAY_CONNECT_WAIT)
            .await
        {
            Ok(()) => Ok(endpoint),
            // Failure reasons never embed the nostr-sdk error Display: it
            // commonly carries the relay URL, and these reasons flow into
            // `TransportAdapterError::Publish` Display (see
            // `finish_publish_outcome`), which upper layers may log. The
            // endpoint stays available on the structured failure record.
            Err(_) => Err(TransportEndpointFailure {
                endpoint: transport_endpoint,
                reason: "connect relay failed".to_owned(),
                kind: TransportEndpointFailureKind::RetryableUnavailable,
                rejection_category: None,
            }),
        }
    }

    async fn send_event_to_relay(
        client: Client,
        endpoint: RelayUrl,
        event: Event,
    ) -> Result<TransportEndpointReceipt, TransportEndpointFailure> {
        let transport_endpoint = TransportEndpoint(endpoint.to_string());
        let mut last_failure = TransportEndpointFailure {
            endpoint: transport_endpoint.clone(),
            reason: "send event failed".to_owned(),
            kind: TransportEndpointFailureKind::PossiblyExposed,
            rejection_category: None,
        };
        for attempt in 1..=SDK_RELAY_PUBLISH_ATTEMPTS {
            match timeout(
                SDK_RELAY_PUBLISH_WAIT,
                client.send_event_to([endpoint.clone()], &event),
            )
            .await
            {
                Ok(Ok(output))
                    if relay_endpoint_publish_accepted(
                        output.success.contains(&endpoint),
                        output.failed.get(&endpoint).map(String::as_str),
                    ) =>
                {
                    return Ok(TransportEndpointReceipt {
                        endpoint: transport_endpoint,
                        accepted_at: None,
                    });
                }
                Ok(Ok(output)) => {
                    if output.failed.contains_key(&endpoint) {
                        let remote = output
                            .failed
                            .get(&endpoint)
                            .map(String::as_str)
                            .unwrap_or_default();
                        last_failure =
                            relay_rejection_endpoint_failure(transport_endpoint.clone(), remote);
                    } else {
                        last_failure.reason = "relay did not acknowledge event".to_owned();
                        last_failure.kind = TransportEndpointFailureKind::PossiblyExposed;
                        last_failure.rejection_category = None;
                    }
                }
                Ok(Err(_)) => {
                    // No sdk error Display here either — it can carry the
                    // relay URL.
                    last_failure.reason = "send event failed".to_owned();
                    last_failure.kind = TransportEndpointFailureKind::PossiblyExposed;
                    last_failure.rejection_category = None;
                }
                Err(_) => {
                    last_failure.reason = "send event timed out".to_owned();
                    last_failure.kind = TransportEndpointFailureKind::PossiblyExposed;
                    last_failure.rejection_category = None;
                }
            }
            if attempt < SDK_RELAY_PUBLISH_ATTEMPTS {
                tokio::time::sleep(SDK_RELAY_PUBLISH_RETRY_BACKOFF).await;
            }
        }

        Err(last_failure)
    }

    async fn publish_prepared_event(
        &self,
        request: PreparedPublish,
        unavailable: &HashMap<RelayUrl, TransportEndpointFailure>,
        connect_before_send: bool,
        deadline: tokio::time::Instant,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        // A configured threshold of zero relaxes the quorum but never permits
        // confirming work that no relay accepted.
        let ack_goal = request.required_acks.max(1);
        let message_id = cgka_traits::MessageId::new(request.event.id.to_bytes().to_vec());
        let attempted_endpoints = request
            .endpoints
            .iter()
            .map(|endpoint| TransportEndpoint(endpoint.to_string()))
            .collect::<Vec<_>>();
        let mut accepted = Vec::new();
        let mut failed = Vec::new();
        let mut publishes = JoinSet::new();
        for endpoint in request.endpoints {
            if let Some(failure) = unavailable.get(&endpoint) {
                failed.push(failure.clone());
                continue;
            }
            let sdk = self.clone();
            let event = request.event.clone();
            publishes.spawn(async move {
                if connect_before_send {
                    sdk.connect_publish_relay(endpoint.clone()).await?;
                }
                Self::send_event_to_relay(sdk.client.clone(), endpoint, event).await
            });
        }

        let mut aborted_publishes = false;
        let mut timed_out = false;
        let (accepted, failed, timed_out) = loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                publishes.abort_all();
                aborted_publishes = true;
                timed_out = true;
                append_missing_publish_failures(&mut failed, &accepted, &attempted_endpoints);
                break (accepted, failed, timed_out);
            }
            match timeout(remaining, publishes.join_next()).await {
                Err(_) => {
                    publishes.abort_all();
                    aborted_publishes = true;
                    timed_out = true;
                    append_missing_publish_failures(&mut failed, &accepted, &attempted_endpoints);
                    break (accepted, failed, timed_out);
                }
                Ok(None) => {
                    append_missing_publish_failures(&mut failed, &accepted, &attempted_endpoints);
                    break (accepted, failed, timed_out);
                }
                Ok(Some(result)) => match result {
                    Ok(Ok(receipt)) => {
                        accepted.push(receipt);
                        if accepted.len() >= ack_goal {
                            publishes.abort_all();
                            aborted_publishes = true;
                            break (accepted, failed, timed_out);
                        }
                    }
                    Ok(Err(failure)) => failed.push(failure),
                    Err(_) => {}
                },
            }
        };
        // `JoinSet::abort_all` is non-blocking. Drain aborted tasks before
        // releasing the batch lease so no send future can race cleanup.
        if aborted_publishes {
            while publishes.join_next().await.is_some() {}
        }
        self.reset_ambiguous_publish_relays(&failed).await;
        Self::finish_publish_outcome(
            message_id,
            accepted,
            failed,
            request.required_acks,
            timed_out,
        )
    }

    async fn publish_prepared_single(
        &self,
        request: PreparedPublish,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        let mut lease = ScopedPublishRelayLease::new(self.clone());
        let mut unavailable = HashMap::new();
        for endpoint in &request.endpoints {
            match self.retain_publish_relay(endpoint).await {
                Ok(retained) => {
                    if retained {
                        lease.retain(endpoint.clone());
                    }
                }
                Err(failure) => {
                    unavailable.insert(endpoint.clone(), failure);
                }
            }
        }

        // Preserve the original single-event latency behavior: each relay
        // races connect + send as one task, and reaching the acknowledgement
        // goal aborts relays that are still connecting. The multi-event path
        // below may pre-connect because it amortizes those connections across
        // the batch.
        let deadline = tokio::time::Instant::now() + SDK_RELAY_PUBLISH_OVERALL_WAIT;
        let outcome = self
            .publish_prepared_event(request, &unavailable, true, deadline)
            .await;
        lease.release().await;
        outcome
    }

    async fn publish_prepared_batch(
        &self,
        requests: Vec<Result<PreparedPublish, TransportAdapterError>>,
        batch_started_at: std::time::Instant,
    ) -> NostrPublishBatch {
        let publish_started_at = tokio::time::Instant::now();
        // The first concurrent request window starts before shared relay
        // connection. A bounded `try_connect_relay` must not silently extend
        // the existing end-to-end event budget from 20s to 25s.
        let mut request_window_deadline = publish_started_at + SDK_RELAY_PUBLISH_OVERALL_WAIT;
        let batch_deadline = publish_started_at + SDK_RELAY_BATCH_OVERALL_WAIT;
        let mut unique_endpoints = Vec::new();
        let mut seen_endpoints = HashSet::new();
        for request in requests.iter().filter_map(|request| request.as_ref().ok()) {
            for endpoint in &request.endpoints {
                if seen_endpoints.insert(endpoint.clone()) {
                    unique_endpoints.push(endpoint.clone());
                }
            }
        }

        let mut lease = ScopedPublishRelayLease::new(self.clone());
        let mut unavailable = HashMap::new();
        let mut connectable = Vec::new();
        for endpoint in unique_endpoints {
            match self.retain_publish_relay(&endpoint).await {
                Ok(retained) => {
                    if retained {
                        lease.retain(endpoint.clone());
                    }
                    connectable.push(endpoint);
                }
                Err(failure) => {
                    unavailable.insert(endpoint, failure);
                }
            }
        }

        // Connect the union once. Per-event sends below reuse these scoped
        // write-only relay connections and never install subscriptions.
        let mut connects = JoinSet::new();
        for endpoint in connectable {
            let client = self.clone();
            connects.spawn(async move { client.connect_publish_relay(endpoint).await });
        }
        loop {
            let remaining = batch_deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                connects.abort_all();
                break;
            }
            match timeout(remaining, connects.join_next()).await {
                Ok(Some(Ok(Err(failure)))) => {
                    if let Ok(endpoint) = RelayUrl::parse(failure.endpoint.as_str()) {
                        unavailable.insert(endpoint, failure);
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => {
                    connects.abort_all();
                    break;
                }
            }
        }
        while connects.join_next().await.is_some() {}

        let request_count = requests.len();
        let unavailable = Arc::new(unavailable);
        let mut pending = requests.into_iter().enumerate();
        let mut publishes = JoinSet::new();
        let mut outcomes = std::iter::repeat_with(|| None)
            .take(request_count)
            .collect::<Vec<Option<Result<NostrPublishOutcome, TransportAdapterError>>>>();
        let mut request_durations = vec![Duration::ZERO; request_count];
        let mut exhausted = false;
        loop {
            while publishes.len() < SDK_RELAY_BATCH_MAX_IN_FLIGHT && !exhausted {
                match pending.next() {
                    Some((index, Err(error))) => {
                        outcomes[index] = Some(Err(error));
                        request_durations[index] = batch_started_at.elapsed();
                    }
                    Some((index, Ok(request))) => {
                        let now = tokio::time::Instant::now();
                        if now >= batch_deadline {
                            outcomes[index] = Some(Err(TransportAdapterError::Publish(
                                "publish batch timed out".to_owned(),
                            )));
                            request_durations[index] = batch_started_at.elapsed();
                            continue;
                        }
                        // Requests admitted during one concurrency window share
                        // its deadline. Once that window expires, later
                        // backpressured requests receive the next bounded
                        // window, capped by the whole-batch deadline.
                        if now >= request_window_deadline {
                            request_window_deadline =
                                (now + SDK_RELAY_PUBLISH_OVERALL_WAIT).min(batch_deadline);
                        }
                        let request_deadline = request_window_deadline;
                        let client = self.clone();
                        let unavailable = unavailable.clone();
                        publishes.spawn(async move {
                            let outcome = match timeout_at(
                                batch_deadline,
                                client.publish_prepared_event(
                                    request,
                                    &unavailable,
                                    false,
                                    request_deadline,
                                ),
                            )
                            .await
                            {
                                Ok(outcome) => outcome,
                                Err(_) => Err(TransportAdapterError::Publish(
                                    "publish batch timed out".to_owned(),
                                )),
                            };
                            (index, batch_started_at.elapsed(), outcome)
                        });
                    }
                    None => exhausted = true,
                }
            }
            if publishes.is_empty() {
                if exhausted {
                    break;
                }
                continue;
            }
            match publishes.join_next().await {
                Some(Ok((index, elapsed, outcome))) => {
                    outcomes[index] = Some(outcome);
                    request_durations[index] = elapsed;
                }
                Some(Err(_)) => {}
                None => break,
            }
        }
        lease.release().await;
        let outcomes = outcomes
            .into_iter()
            .map(|outcome| {
                outcome.unwrap_or_else(|| {
                    Err(TransportAdapterError::Publish(
                        "publish batch task failed".to_owned(),
                    ))
                })
            })
            .collect();
        NostrPublishBatch {
            outcomes,
            request_durations,
        }
    }

    /// Recreate a just-added, not-yet-connected relay with all SDK-composed
    /// options preserved except for the reconnect interval. `Client` has no
    /// supported in-place relay-option update API, so this is intentionally
    /// limited to the caller that observed `add_*_relay == true` while holding
    /// `publish_relay_refs`, before any connection task can start.
    async fn pin_new_relay_retry_interval(&self, endpoint: &RelayUrl) -> Result<(), ()> {
        #[cfg(test)]
        if self.publish_relay_pin_failure_stage.load(Ordering::Relaxed) == 1 {
            return Err(());
        }
        let options = self
            .client
            .relays()
            .await
            .get(endpoint)
            .map(|relay| relay.opts().clone())
            .ok_or(())?
            .retry_interval(SDK_RELAY_RETRY_INTERVAL)
            .adjust_retry_interval(false);
        self.client
            .remove_relay(endpoint.clone())
            .await
            .map_err(|_| ())?;
        #[cfg(test)]
        if self.publish_relay_pin_failure_stage.load(Ordering::Relaxed) == 2 {
            return Err(());
        }
        match self
            .client
            .pool()
            .add_relay(endpoint.clone(), options)
            .await
        {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(()),
        }
    }

    async fn add_subscription_relay(
        &self,
        endpoint: RelayUrl,
    ) -> Result<(), TransportAdapterError> {
        let _relay_lifecycle = self.publish_relay_refs.lock().await;
        let added = self
            .client
            .add_relay(endpoint.clone())
            .await
            // The sdk error Display can carry the relay URL; keep the error
            // operation-only so `TransportAdapterError` Display stays URL-free.
            .map_err(|_| TransportAdapterError::Subscription("add relay failed".to_owned()))?;
        if added {
            self.pin_new_relay_retry_interval(&endpoint)
                .await
                .map_err(|_| {
                    TransportAdapterError::Subscription("configure relay failed".to_owned())
                })?;
        }
        Ok(())
    }

    async fn retain_publish_relay(
        &self,
        endpoint: &RelayUrl,
    ) -> Result<bool, TransportEndpointFailure> {
        let transport_endpoint = TransportEndpoint(endpoint.to_string());
        let mut publish_relay_refs = self.publish_relay_refs.lock().await;
        if let Some(ref_count) = publish_relay_refs.get_mut(endpoint) {
            *ref_count += 1;
            return Ok(true);
        }

        if self.client.relays().await.contains_key(endpoint) {
            return Ok(false);
        }

        // Publish targets are one-shot write relays. Do not use add_relay here:
        // READ relays inherit pool subscriptions in nostr-sdk, which would leak
        // account/group filters to a relay that was only selected for event
        // delivery.
        match self.client.add_write_relay(endpoint.clone()).await {
            Ok(true) => {
                if self.pin_new_relay_retry_interval(endpoint).await.is_err() {
                    if self.client.relays().await.contains_key(endpoint) {
                        tracing::warn!(
                            target: "transport_nostr_adapter::sdk_client",
                            method = "retain_publish_relay",
                            "new publish relay kept SDK retry defaults after configuration failed"
                        );
                        publish_relay_refs.insert(endpoint.clone(), 1);
                        return Ok(true);
                    }
                    return Err(TransportEndpointFailure {
                        endpoint: transport_endpoint,
                        reason: "configure publish relay failed".to_owned(),
                        kind: TransportEndpointFailureKind::RetryableUnavailable,
                        rejection_category: None,
                    });
                }
                publish_relay_refs.insert(endpoint.clone(), 1);
                Ok(true)
            }
            Ok(false) => Ok(false),
            Err(_) => Err(TransportEndpointFailure {
                endpoint: transport_endpoint,
                reason: "add publish relay failed".to_owned(),
                kind: TransportEndpointFailureKind::RetryableUnavailable,
                rejection_category: None,
            }),
        }
    }

    async fn cleanup_publish_relays(&self, endpoints: Vec<RelayUrl>) {
        for endpoint in endpoints {
            if self.release_publish_relay(endpoint).await.is_err() {
                tracing::warn!(
                    target: "transport_nostr_adapter::sdk_client",
                    method = "cleanup_publish_relays",
                    "failed to clean up SDK publish relay"
                );
            }
        }
    }

    async fn release_publish_relay(&self, endpoint: RelayUrl) -> Result<(), ()> {
        #[cfg(test)]
        {
            *self
                .publish_release_attempts
                .lock()
                .await
                .entry(endpoint.clone())
                .or_default() += 1;
        }
        let mut publish_relay_refs = self.publish_relay_refs.lock().await;
        match publish_relay_refs.get_mut(&endpoint) {
            Some(ref_count) if *ref_count > 1 => {
                *ref_count -= 1;
                return Ok(());
            }
            Some(_) => {
                publish_relay_refs.remove(&endpoint);
            }
            None => return Ok(()),
        }

        let relay_is_now_read = self
            .client
            .relays()
            .await
            .get(&endpoint)
            .is_some_and(|relay| relay.flags().has_read());
        if relay_is_now_read {
            return Ok(());
        }

        self.client.remove_relay(endpoint).await.map_err(|_| ())
    }

    /// Invalidate sockets whose publish result cannot establish whether the
    /// relay accepted the event. On iOS a network transition can leave an
    /// established WebSocket silently dead while the SDK still reports it as
    /// connected; a later `connect_relay` is then intentionally a no-op. Moving
    /// that relay to `Terminated` preserves its registration and subscriptions
    /// while ensuring the next publish starts a fresh connection (mdk#926).
    async fn reset_ambiguous_publish_relays(&self, failures: &[TransportEndpointFailure]) {
        let mut reset = HashSet::new();
        for failure in failures {
            if failure.kind != TransportEndpointFailureKind::PossiblyExposed {
                continue;
            }
            let Ok(endpoint) = RelayUrl::parse(failure.endpoint.as_str()) else {
                continue;
            };
            if !reset.insert(endpoint.clone()) {
                continue;
            }
            if self.client.disconnect_relay(endpoint).await.is_err() {
                tracing::warn!(
                    target: "transport_nostr_adapter::sdk_client",
                    method = "reset_ambiguous_publish_relays",
                    "failed to reset SDK relay after ambiguous publish failure"
                );
            }
        }
    }

    fn finish_publish_outcome(
        message_id: cgka_traits::MessageId,
        accepted: Vec<TransportEndpointReceipt>,
        failed: Vec<TransportEndpointFailure>,
        required_acks: usize,
        timed_out: bool,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        let required_acks = required_acks.max(1);
        if accepted.len() >= required_acks {
            return Ok(NostrPublishOutcome {
                message_id: Some(message_id),
                accepted,
                failed,
            });
        }

        let reason = if timed_out {
            format!(
                "publish timed out after {}s: accepted {} of required {}",
                SDK_RELAY_PUBLISH_OVERALL_WAIT.as_secs(),
                accepted.len(),
                required_acks
            )
        } else if accepted.is_empty() && !failed.is_empty() {
            collapse_publish_failure_summaries(failed.iter().map(|failure| failure.reason.as_str()))
        } else {
            format!(
                "insufficient publish acknowledgements: accepted {} of required {}",
                accepted.len(),
                required_acks
            )
        };
        if failed.is_empty() {
            Err(TransportAdapterError::Publish(reason))
        } else {
            Err(TransportAdapterError::PublishEndpoints(
                TransportPublishFailure::with_endpoint_failures(reason, failed)
                    .with_message_id(message_id),
            ))
        }
    }
}

#[async_trait]
impl NostrRelayClient for NostrSdkRelayClient {
    async fn subscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        let plan = Self::plan_subscription(&subscription)?;
        tracing::debug!(
            target: "transport_nostr_adapter::sdk_client",
            method = "subscribe",
            endpoint_count = plan.endpoints.len(),
            "subscribing SDK relay plan"
        );
        for endpoint in &plan.endpoints {
            self.add_subscription_relay(endpoint.clone()).await?;
        }

        // Let nostr-sdk own connection lifecycle for subscriptions. `connect()`
        // starts background connection tasks for any newly added relays and those
        // tasks keep retrying; the subscription below is queued/resubscribed as
        // relays become available instead of blocking activation on a per-relay
        // connection attempt.
        self.client.connect().await;

        let output = self
            .client
            .subscribe_with_id_to(
                plan.endpoints.clone(),
                plan.subscription_id.clone(),
                plan.filter,
                None,
            )
            .await
            .map_err(|_| TransportAdapterError::Subscription("subscribe failed".to_owned()))?;

        if output.success.is_empty() {
            return Err(TransportAdapterError::Subscription(format!(
                "subscribe registered on 0 of {} relays",
                plan.endpoints.len()
            )));
        }

        if !output.failed.is_empty() {
            tracing::warn!(
                target: "transport_nostr_adapter::sdk_client",
                method = "subscribe",
                registered_count = output.success.len(),
                failed_count = output.failed.len(),
                "SDK relay subscription partially registered"
            );
        }

        tracing::debug!(
            target: "transport_nostr_adapter::sdk_client",
            method = "subscribe",
            endpoint_count = plan.endpoints.len(),
            registered_count = output.success.len(),
            "SDK relay subscription registered"
        );

        // Record which of the requested endpoints acknowledged the registration
        // so the app can surface it in the `subscription_rebuild` audit row.
        // Only reached on the success path (>=1 relay registered): a total
        // failure returned above, aborting activation before any audit row.
        let outcomes = plan
            .endpoints
            .iter()
            .map(|endpoint| (endpoint.clone(), output.success.contains(endpoint)));
        merge_registration_log(
            self.registration_log
                .lock()
                .await
                .entry(plan.account_id.clone())
                .or_default(),
            outcomes,
        );

        self.account_subscriptions
            .write()
            .await
            .entry(plan.account_id)
            .or_default()
            .push_unique(plan.subscription_id);
        Ok(())
    }

    async fn unsubscribe(
        &self,
        subscription: NostrSubscription,
    ) -> Result<(), TransportAdapterError> {
        let plan = Self::plan_subscription(&subscription)?;
        tracing::debug!(
            target: "transport_nostr_adapter::sdk_client",
            method = "unsubscribe",
            "unsubscribing SDK relay plan"
        );
        self.client.unsubscribe(&plan.subscription_id).await;
        if let Some(ids) = self
            .account_subscriptions
            .write()
            .await
            .get_mut(&plan.account_id)
        {
            ids.retain(|id| id != &plan.subscription_id);
        }
        Ok(())
    }

    async fn unsubscribe_account(
        &self,
        account_id: &MemberId,
    ) -> Result<(), TransportAdapterError> {
        // Drop the account's undrained registration bucket along with its
        // subscriptions: a sign-out between a subscribe and the next sync's
        // drain would otherwise orphan the bucket, and a later reactivation
        // would OR-merge fresh registrations into the stale session's relays —
        // misstating the next `subscription_rebuild` audit row.
        self.registration_log.lock().await.remove(account_id);
        let ids = self
            .account_subscriptions
            .write()
            .await
            .remove(account_id)
            .unwrap_or_default();
        tracing::debug!(
            target: "transport_nostr_adapter::sdk_client",
            method = "unsubscribe_account",
            subscription_count = ids.len(),
            "unsubscribing SDK account subscriptions"
        );
        for id in ids {
            self.client.unsubscribe(&id).await;
        }
        Ok(())
    }

    async fn publish_event(
        &self,
        endpoints: &[TransportEndpoint],
        event: &NostrTransportEvent,
        required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        let request = NostrEventPublishRequest {
            endpoints: endpoints.to_vec(),
            event: event.clone(),
            required_acks,
        };
        self.publish_events(std::slice::from_ref(&request))
            .await
            .into_iter()
            .next()
            .expect("single-event batch returns one outcome")
    }

    async fn publish_events(
        &self,
        requests: &[NostrEventPublishRequest],
    ) -> Vec<Result<NostrPublishOutcome, TransportAdapterError>> {
        self.publish_events_with_timings(requests).await.outcomes
    }

    async fn publish_events_with_timings(
        &self,
        requests: &[NostrEventPublishRequest],
    ) -> NostrPublishBatch {
        let batch_started_at = std::time::Instant::now();
        let mut prepared = Vec::with_capacity(requests.len());
        for request in requests {
            let endpoints = match parse_endpoints(&request.endpoints, "publish") {
                Ok(endpoints) => {
                    let mut seen_endpoints = HashSet::new();
                    endpoints
                        .into_iter()
                        .filter(|endpoint| seen_endpoints.insert(endpoint.clone()))
                        .collect::<Vec<_>>()
                }
                Err(error) => {
                    prepared.push(Err(error));
                    continue;
                }
            };
            let event = match self.event_for_publish(&request.event).await {
                Ok(event) => event,
                Err(error) => {
                    prepared.push(Err(error));
                    continue;
                }
            };
            prepared.push(Ok(PreparedPublish {
                endpoints,
                event,
                required_acks: request.required_acks,
            }));
        }
        tracing::debug!(
            target: "transport_nostr_adapter::sdk_client",
            method = "publish_events",
            event_count = prepared.len(),
            "publishing SDK relay event batch"
        );
        if prepared.len() == 1 {
            let outcome = match prepared.pop().expect("one prepared publish") {
                Ok(request) => vec![self.publish_prepared_single(request).await],
                Err(error) => vec![Err(error)],
            };
            return NostrPublishBatch {
                request_durations: vec![batch_started_at.elapsed()],
                outcomes: outcome,
            };
        }
        self.publish_prepared_batch(prepared, batch_started_at)
            .await
    }
}

impl NostrSdkRelayHealth {
    fn record_status(&mut self, status: RelayStatus) {
        match status {
            RelayStatus::Initialized => self.initialized += 1,
            RelayStatus::Pending => self.pending += 1,
            RelayStatus::Connecting => self.connecting += 1,
            RelayStatus::Connected => self.connected += 1,
            RelayStatus::Disconnected => self.disconnected += 1,
            RelayStatus::Terminated => self.terminated += 1,
            RelayStatus::Banned => self.banned += 1,
            RelayStatus::Sleeping => self.sleeping += 1,
        }
    }
}

fn parse_endpoints(
    endpoints: &[TransportEndpoint],
    context: &str,
) -> Result<Vec<RelayUrl>, TransportAdapterError> {
    endpoints
        .iter()
        .map(|endpoint| {
            // Neither the endpoint nor the parse error (which echoes its
            // input) may appear here: this Display reaches upper-layer logs.
            RelayUrl::parse(endpoint.as_str()).map_err(|_| {
                TransportAdapterError::Subscription(format!("{context}: invalid relay endpoint"))
            })
        })
        .collect()
}

fn member_id_to_pubkey(
    member_id: &MemberId,
    context: &str,
) -> Result<PublicKey, TransportAdapterError> {
    PublicKey::from_slice(member_id.as_slice()).map_err(|e| {
        TransportAdapterError::Subscription(format!(
            "{context}: member id is not a Nostr pubkey: {e}"
        ))
    })
}

fn nostr_tag_from_vec(values: &[String]) -> Result<Tag, TransportAdapterError> {
    let Some(kind) = values.first() else {
        return Err(TransportAdapterError::Publish(
            "cannot publish Nostr event with empty tag".into(),
        ));
    };
    Ok(Tag::custom(
        TagKind::custom(kind.clone()),
        values.iter().skip(1).cloned(),
    ))
}

trait PushUnique<T> {
    fn push_unique(&mut self, value: T);
}

impl<T: PartialEq> PushUnique<T> for Vec<T> {
    fn push_unique(&mut self, value: T) {
        if !self.contains(&value) {
            self.push(value);
        }
    }
}

/// Fold one subscribe attempt's per-endpoint outcomes into one account's
/// registration bucket.
///
/// A relay counts as registered for that account's rebuild if it acknowledged
/// *any* of the account's subscriptions (monotonic OR), so a group subscription
/// that lands on a relay after a transient inbox miss still marks that relay
/// accepted for the rebuild as a whole. Kept as a free function operating on a
/// single account's bucket so the merge is unit-testable without a live relay
/// pool.
fn merge_registration_log(
    log: &mut HashMap<RelayUrl, bool>,
    outcomes: impl IntoIterator<Item = (RelayUrl, bool)>,
) {
    for (relay, accepted) in outcomes {
        let entry = log.entry(relay).or_insert(false);
        *entry = *entry || accepted;
    }
}

/// A relay `OK:false` with the NIP-01 `duplicate:` machine prefix proves the
/// exact event is already stored and counts as idempotent publication success.
fn relay_duplicate_acknowledgement(relay_failure: &str) -> bool {
    matches!(
        nostr::message::MachineReadablePrefix::parse(relay_failure),
        Some(nostr::message::MachineReadablePrefix::Duplicate)
    )
}

fn relay_endpoint_publish_accepted(success: bool, failure_reason: Option<&str>) -> bool {
    success || failure_reason.is_some_and(relay_duplicate_acknowledgement)
}

fn append_missing_publish_failures(
    failed: &mut Vec<TransportEndpointFailure>,
    accepted: &[TransportEndpointReceipt],
    attempted: &[TransportEndpoint],
) {
    for endpoint in attempted {
        if accepted.iter().any(|receipt| &receipt.endpoint == endpoint)
            || failed.iter().any(|failure| &failure.endpoint == endpoint)
        {
            continue;
        }
        failed.push(TransportEndpointFailure {
            endpoint: endpoint.clone(),
            reason: "publish acknowledgement unknown".into(),
            kind: TransportEndpointFailureKind::PossiblyExposed,
            rejection_category: None,
        });
    }
}

fn map_relay_rejection_category(
    prefix: nostr::message::MachineReadablePrefix,
) -> TransportEndpointRejectionCategory {
    use nostr::message::MachineReadablePrefix as Prefix;
    match prefix {
        Prefix::Duplicate => TransportEndpointRejectionCategory::Duplicate,
        Prefix::Pow => TransportEndpointRejectionCategory::Pow,
        Prefix::Blocked => TransportEndpointRejectionCategory::Blocked,
        Prefix::RateLimited => TransportEndpointRejectionCategory::RateLimited,
        Prefix::Invalid => TransportEndpointRejectionCategory::Invalid,
        Prefix::Error => TransportEndpointRejectionCategory::Error,
        Prefix::Unsupported => TransportEndpointRejectionCategory::Unsupported,
        Prefix::AuthRequired => TransportEndpointRejectionCategory::AuthRequired,
        Prefix::Restricted => TransportEndpointRejectionCategory::Restricted,
    }
}

fn relay_rejection_endpoint_failure(
    endpoint: TransportEndpoint,
    relay_message: &str,
) -> TransportEndpointFailure {
    if let Some(prefix) = nostr::message::MachineReadablePrefix::parse(relay_message) {
        let category = map_relay_rejection_category(prefix);
        // nostr-sdk also uses the generic `error:` prefix for local SDK/send
        // failures. Without a typed SDK distinction, that prefix is not proof
        // of a relay-level OK:false rejection and must remain conservative.
        let kind = match category {
            TransportEndpointRejectionCategory::Error => {
                TransportEndpointFailureKind::PossiblyExposed
            }
            TransportEndpointRejectionCategory::RateLimited
            | TransportEndpointRejectionCategory::AuthRequired => {
                TransportEndpointFailureKind::RetryableUnavailable
            }
            TransportEndpointRejectionCategory::Duplicate
            | TransportEndpointRejectionCategory::Pow
            | TransportEndpointRejectionCategory::Blocked
            | TransportEndpointRejectionCategory::Invalid
            | TransportEndpointRejectionCategory::Unsupported
            | TransportEndpointRejectionCategory::Restricted => {
                TransportEndpointFailureKind::TerminalRejected
            }
        };
        let reason = if kind == TransportEndpointFailureKind::PossiblyExposed {
            "publish acknowledgement unknown (error)".to_owned()
        } else {
            format!("relay rejected event ({})", category.as_str())
        };
        return TransportEndpointFailure {
            endpoint,
            reason,
            kind,
            rejection_category: Some(category),
        };
    }
    // `nostr-sdk` uses the same `output.failed` map for a relay's NIP-20
    // rejection and for local socket/pool failures such as a disconnected
    // relay. Only a machine-readable prefix proves the former. Treat an
    // unclassified value as ambiguous transport failure so upper layers keep
    // the durable send queued and retry it after connectivity returns. Keep
    // the SDK string out of the reason: it can contain relay URLs.
    TransportEndpointFailure {
        endpoint,
        reason: "publish acknowledgement unknown".to_owned(),
        kind: TransportEndpointFailureKind::PossiblyExposed,
        rejection_category: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NostrKeyPackagePublication;
    use cgka_traits::Timestamp;
    use cgka_traits::engine::KeyPackage;
    use futures::{SinkExt, StreamExt};
    use nostr_relay_builder::MockRelay;
    use nostr_sdk::prelude::{DatabaseEventStatus, EventBuilder, Keys, Kind, Tag};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, advance, timeout};
    use transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE;

    /// Build a kind-445 group event DTO pre-signed by a fresh ephemeral key,
    /// matching the production peeler wrap path (spec/transports/nostr.md:64-66).
    /// The publish path rejects unsigned 445s, so publish tests must pre-sign.
    fn signed_group_event_dto() -> NostrTransportEvent {
        let ephemeral = Keys::generate();
        let signed = EventBuilder::new(Kind::MlsGroupMessage, "outer encrypted body")
            .tags([Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::H)),
                ["cc".repeat(32)],
            )])
            .custom_created_at(NostrTimestamp::from_secs(1_700_000_010))
            .sign_with_keys(&ephemeral)
            .expect("sign ephemeral 445");
        NostrTransportEvent::from_nostr_event(&signed).expect("dto from signed event")
    }

    #[test]
    fn reconciliation_remote_batch_is_bounded_and_deterministic() {
        let remote = (0..SDK_RECONCILIATION_REPLAY_BATCH + 5)
            .rev()
            .map(|value| {
                let mut bytes = [0u8; 32];
                bytes[24..].copy_from_slice(&(value as u64).to_be_bytes());
                EventId::from_byte_array(bytes)
            })
            .collect::<HashSet<_>>();

        let selected = bounded_reconciliation_remote_ids(&remote);
        assert_eq!(selected.len(), SDK_RECONCILIATION_REPLAY_BATCH);
        assert!(selected.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(
            selected.last(),
            Some(&EventId::from_byte_array({
                let mut bytes = [0u8; 32];
                bytes[24..]
                    .copy_from_slice(&((SDK_RECONCILIATION_REPLAY_BATCH - 1) as u64).to_be_bytes());
                bytes
            }))
        );
    }

    #[test]
    fn relay_rejection_endpoint_failure_maps_machine_readable_prefix() {
        for (message, category, kind, summary) in [
            (
                "auth-required: account secret at https://evil.example/auth",
                TransportEndpointRejectionCategory::AuthRequired,
                TransportEndpointFailureKind::RetryableUnavailable,
                "relay rejected event (auth-required)",
            ),
            (
                "restricted: kind 5 disabled at https://evil.example/policy",
                TransportEndpointRejectionCategory::Restricted,
                TransportEndpointFailureKind::TerminalRejected,
                "relay rejected event (restricted)",
            ),
            (
                "invalid: leaked event payload",
                TransportEndpointRejectionCategory::Invalid,
                TransportEndpointFailureKind::TerminalRejected,
                "relay rejected event (invalid)",
            ),
            (
                "unsupported: kind 5",
                TransportEndpointRejectionCategory::Unsupported,
                TransportEndpointFailureKind::TerminalRejected,
                "relay rejected event (unsupported)",
            ),
        ] {
            let failure = relay_rejection_endpoint_failure(
                TransportEndpoint("wss://relay.example".into()),
                message,
            );
            assert_eq!(failure.rejection_category, Some(category));
            assert_eq!(failure.kind, kind);
            assert_eq!(failure.reason, summary);
            assert!(!failure.reason.contains("evil.example"));
            assert!(!failure.reason.contains("leaked event payload"));
        }
    }

    #[test]
    fn generic_error_prefix_is_not_treated_as_proof_of_terminal_rejection() {
        let failure = relay_rejection_endpoint_failure(
            TransportEndpoint("wss://relay.example".into()),
            "error: SDK send failed",
        );

        assert_eq!(failure.kind, TransportEndpointFailureKind::PossiblyExposed);
        assert_eq!(
            failure.rejection_category,
            Some(TransportEndpointRejectionCategory::Error)
        );
        assert_eq!(failure.reason, "publish acknowledgement unknown (error)");
    }

    #[test]
    fn finish_publish_outcome_collapses_duplicate_relay_rejection_summaries() {
        let message_id = cgka_traits::MessageId::new(vec![0xD6; 32]);
        let err = NostrSdkRelayClient::finish_publish_outcome(
            message_id,
            Vec::new(),
            vec![
                TransportEndpointFailure {
                    endpoint: TransportEndpoint("wss://first.example".into()),
                    reason: "relay rejected event (blocked)".to_owned(),
                    kind: TransportEndpointFailureKind::TerminalRejected,
                    rejection_category: Some(TransportEndpointRejectionCategory::Blocked),
                },
                TransportEndpointFailure {
                    endpoint: TransportEndpoint("wss://second.example".into()),
                    reason: "relay rejected event (blocked)".to_owned(),
                    kind: TransportEndpointFailureKind::TerminalRejected,
                    rejection_category: Some(TransportEndpointRejectionCategory::Blocked),
                },
            ],
            1,
            false,
        )
        .unwrap_err();

        let rendered = err.to_string();
        assert_eq!(rendered, "publish failed: relay rejected event (blocked)");
        assert!(!rendered.contains("first.example"));
        assert!(!rendered.contains("injected"));
        if let TransportAdapterError::PublishEndpoints(failure) = err {
            assert_eq!(failure.endpoint_failures.len(), 2);
            assert_eq!(
                failure.endpoint_failures[0].rejection_category,
                Some(TransportEndpointRejectionCategory::Blocked)
            );
        } else {
            panic!("expected publish failure");
        }
    }

    #[test]
    fn finish_publish_outcome_success_retains_failures_supplied_to_helper() {
        // Exercises `finish_publish_outcome` directly. Production fan-out stops
        // once quorum is met and does not append failures from aborted tasks;
        // see `publish_event_does_not_wait_for_silent_relays_once_required_acks_are_met`.
        let message_id = cgka_traits::MessageId::new(vec![0xD7; 32]);
        let accepted = vec![TransportEndpointReceipt {
            endpoint: TransportEndpoint("wss://good.example".into()),
            accepted_at: None,
        }];
        let failed = vec![TransportEndpointFailure {
            endpoint: TransportEndpoint("wss://bad.example".into()),
            reason: "relay rejected event (auth-required)".to_owned(),
            kind: TransportEndpointFailureKind::TerminalRejected,
            rejection_category: Some(TransportEndpointRejectionCategory::AuthRequired),
        }];
        let outcome = NostrSdkRelayClient::finish_publish_outcome(
            message_id,
            accepted,
            failed.clone(),
            1,
            false,
        )
        .unwrap();
        assert_eq!(outcome.failed, failed);
    }

    #[test]
    fn relay_duplicate_acknowledgement_accepts_only_duplicate_prefix() {
        assert!(relay_duplicate_acknowledgement(
            "duplicate: already have this event"
        ));
        assert!(!relay_duplicate_acknowledgement("blocked: policy"));
        assert!(!relay_duplicate_acknowledgement("relay rejected event"));
        assert!(!relay_duplicate_acknowledgement(""));
    }

    #[test]
    fn relay_endpoint_publish_accepted_treats_duplicate_failure_as_success() {
        assert!(relay_endpoint_publish_accepted(
            false,
            Some("duplicate: already have this event")
        ));
        assert!(!relay_endpoint_publish_accepted(
            false,
            Some("blocked: policy")
        ));
        assert!(!relay_endpoint_publish_accepted(
            false,
            Some("error: unknown")
        ));
        assert!(!relay_endpoint_publish_accepted(false, None));
        assert!(relay_endpoint_publish_accepted(true, None));
    }

    #[test]
    fn publish_failure_error_display_carries_no_relay_url() {
        // Per-endpoint failure reasons are joined into
        // `TransportAdapterError::Publish` Display, which upper layers may
        // log; the privacy invariant forbids relay URLs there. The endpoint
        // stays available on the structured failure record only.
        let endpoint = TransportEndpoint("wss://private-relay.example".into());
        let err = NostrSdkRelayClient::finish_publish_outcome(
            cgka_traits::MessageId::new(vec![0xD4; 32]),
            Vec::new(),
            vec![TransportEndpointFailure {
                endpoint: endpoint.clone(),
                reason: "connect relay failed".to_owned(),
                kind: TransportEndpointFailureKind::RetryableUnavailable,
                rejection_category: None,
            }],
            1,
            false,
        )
        .unwrap_err();

        let rendered = err.to_string();
        assert!(!rendered.contains("private-relay.example"), "{rendered}");
        assert!(rendered.contains("connect relay failed"), "{rendered}");
    }

    #[test]
    fn zero_required_acks_still_requires_one_acceptance() {
        let message_id = cgka_traits::MessageId::new(vec![0xD5; 32]);
        let no_acceptance = NostrSdkRelayClient::finish_publish_outcome(
            message_id.clone(),
            Vec::new(),
            Vec::new(),
            0,
            false,
        );
        assert!(matches!(
            no_acceptance,
            Err(TransportAdapterError::Publish(_))
        ));

        let accepted = vec![TransportEndpointReceipt {
            endpoint: TransportEndpoint("wss://relay.example".into()),
            accepted_at: None,
        }];
        let outcome = NostrSdkRelayClient::finish_publish_outcome(
            message_id,
            accepted.clone(),
            Vec::new(),
            0,
            false,
        )
        .unwrap();
        assert_eq!(outcome.accepted, accepted);
    }

    #[test]
    fn group_subscription_plan_uses_mls_group_kind_h_tag_and_since() {
        let account_id = MemberId::new(vec![0xA1; 32]);
        let group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
        let transport_group_id = vec![0xC3; 32];
        let endpoint = TransportEndpoint("wss://group.example".into());

        let subscription = NostrSubscription::Group {
            account_id: account_id.clone(),
            group_id: group_id.clone(),
            transport_group_id: transport_group_id.clone(),
            endpoints: vec![endpoint.clone()],
            since: Some(Timestamp(1_700_000_000)),
        };
        let expected_subscription_id = SubscriptionId::new(subscription.subscription_id());
        let plan = NostrSdkRelayClient::plan_subscription(&subscription).expect("plan");

        assert_eq!(plan.account_id, account_id);
        assert_eq!(plan.endpoints[0].to_string(), endpoint.0);
        assert_eq!(plan.subscription_id, expected_subscription_id);
        assert!(
            plan.subscription_id
                .to_string()
                .starts_with("marmot:group:")
        );
        assert!(plan.subscription_id.to_string().len() <= 64);
        let json = serde_json::to_value(&plan.filter).unwrap();
        assert_eq!(json["kinds"], serde_json::json!([445]));
        assert_eq!(
            json["#h"],
            serde_json::json!([hex::encode(&transport_group_id)])
        );
        assert_eq!(json["since"], serde_json::json!(1_700_000_000));
    }

    fn relay(url: &str) -> RelayUrl {
        RelayUrl::parse(url).expect("relay url")
    }

    #[test]
    fn registration_log_pairs_each_endpoint_with_its_acceptance() {
        let one = relay("wss://one.example");
        let two = relay("wss://two.example");
        let mut log = HashMap::new();
        // The requested endpoints are the authoritative key set: `two` failed
        // to register (absent from the success set), `one` succeeded.
        let success: HashSet<RelayUrl> = [one.clone()].into_iter().collect();
        merge_registration_log(
            &mut log,
            [&one, &two]
                .into_iter()
                .map(|endpoint| (endpoint.clone(), success.contains(endpoint))),
        );
        assert_eq!(log.get(&one), Some(&true));
        assert_eq!(log.get(&two), Some(&false));
    }

    #[test]
    fn registration_log_merge_is_monotonic_ok() {
        let one = relay("wss://one.example");
        let mut log = HashMap::new();
        // A first subscription misses the relay, a second lands on it: the
        // relay counts as registered for the rebuild as a whole.
        merge_registration_log(&mut log, [(one.clone(), false)]);
        merge_registration_log(&mut log, [(one.clone(), true)]);
        assert_eq!(log.get(&one), Some(&true));
        // A later miss must not flip an already-accepted relay back to failed.
        merge_registration_log(&mut log, [(one.clone(), false)]);
        assert_eq!(log.get(&one), Some(&true));
    }

    #[tokio::test]
    async fn take_subscription_registrations_drains_sorted_and_resets() {
        let client = Client::builder().build();
        let sdk = NostrSdkRelayClient::new(client);
        let account = MemberId::new(vec![0xA1; 32]);
        // Seed the log directly (the network subscribe path is exercised by the
        // MockRelay tests below); this pins the drain/sort/reset contract the
        // app relies on for one audit row per rebuild.
        merge_registration_log(
            sdk.registration_log
                .lock()
                .await
                .entry(account.clone())
                .or_default(),
            [
                (relay("wss://b.example"), true),
                (relay("wss://a.example"), false),
            ],
        );
        let outcomes = sdk.take_subscription_registrations(&account).await;
        assert_eq!(
            outcomes,
            vec![
                RelayRegistrationOutcome {
                    relay_url: "wss://a.example".into(),
                    accepted: false,
                },
                RelayRegistrationOutcome {
                    relay_url: "wss://b.example".into(),
                    accepted: true,
                },
            ]
        );
        // Draining resets: a subsequent rebuild starts from an empty log.
        assert!(
            sdk.take_subscription_registrations(&account)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn take_subscription_registrations_is_scoped_to_the_draining_account() {
        // The one relay plane per app shares this log across every account while
        // account workers subscribe concurrently. A drain must return only the
        // draining account's registrations: a global drain lets account A's
        // rebuild row absorb account B's relays and leaves B's own drain empty —
        // a misattribution in a trust-critical forensic channel (PR #825).
        let client = Client::builder().build();
        let sdk = NostrSdkRelayClient::new(client);
        let account_a = MemberId::new(vec![0xA1; 32]);
        let account_b = MemberId::new(vec![0xB2; 32]);
        // Interleave two accounts' subscribe outcomes, each landing on its own
        // relay, into the shared log.
        merge_registration_log(
            sdk.registration_log
                .lock()
                .await
                .entry(account_a.clone())
                .or_default(),
            [(relay("wss://a.example"), true)],
        );
        merge_registration_log(
            sdk.registration_log
                .lock()
                .await
                .entry(account_b.clone())
                .or_default(),
            [(relay("wss://b.example"), true)],
        );

        // A's drain returns only A's relay...
        assert_eq!(
            sdk.take_subscription_registrations(&account_a).await,
            vec![RelayRegistrationOutcome {
                relay_url: "wss://a.example".into(),
                accepted: true,
            }]
        );
        // ...leaving B's registration intact for B's own rebuild row.
        assert_eq!(
            sdk.take_subscription_registrations(&account_b).await,
            vec![RelayRegistrationOutcome {
                relay_url: "wss://b.example".into(),
                accepted: true,
            }]
        );
        // Each account's bucket resets independently on its own drain.
        assert!(
            sdk.take_subscription_registrations(&account_a)
                .await
                .is_empty()
        );
        assert!(
            sdk.take_subscription_registrations(&account_b)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn unsubscribe_account_drops_the_undrained_registration_bucket() {
        // A sign-out between a subscribe and the next sync's drain must not
        // orphan the bucket: a later reactivation would OR-merge fresh
        // registrations into the stale session's relays and misstate the next
        // `subscription_rebuild` audit row (PR #825 follow-up).
        let client = Client::builder().build();
        let sdk = NostrSdkRelayClient::new(client);
        let account = MemberId::new(vec![0xC3; 32]);
        merge_registration_log(
            sdk.registration_log
                .lock()
                .await
                .entry(account.clone())
                .or_default(),
            [(relay("wss://stale.example"), true)],
        );

        sdk.unsubscribe_account(&account).await.unwrap();

        assert!(
            sdk.take_subscription_registrations(&account)
                .await
                .is_empty(),
            "sign-out must drop the account's undrained registrations"
        );
    }

    #[test]
    fn account_inbox_subscription_plan_uses_giftwrap_p_tag() {
        let keys = Keys::generate();
        let account_id = MemberId::new(keys.public_key().to_bytes().to_vec());
        let endpoint = TransportEndpoint("wss://inbox.example".into());

        let subscription = NostrSubscription::AccountInbox {
            account_id: account_id.clone(),
            endpoints: vec![endpoint.clone()],
            since: None,
        };
        let expected_subscription_id = SubscriptionId::new(subscription.subscription_id());
        let plan = NostrSdkRelayClient::plan_subscription(&subscription).expect("plan");

        assert_eq!(plan.account_id, account_id);
        assert_eq!(plan.endpoints[0].to_string(), endpoint.0);
        assert_eq!(plan.subscription_id, expected_subscription_id);
        assert!(
            plan.subscription_id
                .to_string()
                .starts_with("marmot:inbox:")
        );
        assert!(plan.subscription_id.to_string().len() <= 64);
        let json = serde_json::to_value(&plan.filter).unwrap();
        assert_eq!(json["kinds"], serde_json::json!([1059]));
        assert_eq!(json["#p"], serde_json::json!([keys.public_key().to_hex()]));
    }

    #[test]
    fn subscription_plan_digest_is_endpoint_order_insensitive() {
        let account_id = MemberId::new(vec![0xA1; 32]);
        let group_id = cgka_traits::GroupId::new(vec![0xB2; 32]);
        let transport_group_id = vec![0xC3; 32];
        let endpoint_a = TransportEndpoint("wss://a.example".into());
        let endpoint_b = TransportEndpoint("wss://b.example".into());

        let first = NostrSdkRelayClient::plan_subscription(&NostrSubscription::Group {
            account_id: account_id.clone(),
            group_id: group_id.clone(),
            transport_group_id: transport_group_id.clone(),
            endpoints: vec![endpoint_a.clone(), endpoint_b.clone()],
            since: None,
        })
        .expect("first plan");
        let second = NostrSdkRelayClient::plan_subscription(&NostrSubscription::Group {
            account_id,
            group_id,
            transport_group_id,
            endpoints: vec![endpoint_b, endpoint_a],
            since: None,
        })
        .expect("second plan");

        assert_eq!(first.subscription_id, second.subscription_id);
    }

    #[tokio::test]
    async fn relay_health_summarizes_sdk_status_without_relay_urls() {
        let client = Client::builder().build();
        client.add_relay("wss://relay-one.example").await.unwrap();
        client.add_relay("wss://relay-two.example").await.unwrap();
        let sdk = NostrSdkRelayClient::new(client);

        let health = sdk.relay_health().await;

        assert_eq!(health.total_relays, 2);
        assert_eq!(health.initialized, 2);
        assert_eq!(health.connected, 0);
        assert_eq!(health.connection_attempts, 0);
        assert_eq!(health.connection_successes, 0);
        let debug = format!("{health:?}");
        assert!(!debug.contains("relay-one"));
        assert!(!debug.contains("relay-two"));
        assert!(!debug.contains("wss://"));
    }

    #[tokio::test]
    async fn unsigned_group_event_is_rejected_not_account_signed() {
        // spec/transports/nostr.md:64-66 — a kind-445 group event's pubkey MUST
        // be a fresh ephemeral key and MUST NOT be the sender's account
        // identity. event_for_publish must fail closed on an unsigned 445
        // rather than stamp the account signer onto the routing-visible
        // envelope.
        let keys = Keys::generate();
        let client = Client::builder().signer(keys.clone()).build();
        let sdk = NostrSdkRelayClient::new(client);
        let dto = NostrTransportEvent {
            id: "11".repeat(32),
            pubkey: "22".repeat(32),
            created_at: 1_700_000_010,
            kind: KIND_MARMOT_GROUP_MESSAGE,
            tags: vec![vec!["h".into(), "cc".repeat(32)]],
            content: "outer encrypted body".into(),
            sig: None,
        };

        let err = sdk
            .event_for_publish(&dto)
            .await
            .expect_err("unsigned kind-445 must be rejected");

        assert!(matches!(err, TransportAdapterError::Publish(_)));
        assert!(err.to_string().contains("kind-445"));
    }

    #[tokio::test]
    async fn unsigned_marmot_key_package_event_is_signed_as_kind_30443() {
        let keys = Keys::generate();
        let client = Client::builder().signer(keys.clone()).build();
        let sdk = NostrSdkRelayClient::new(client);
        let dto = NostrKeyPackagePublication {
            account_id: MemberId::new(keys.public_key().to_bytes().to_vec()),
            key_package: KeyPackage::new(vec![1, 2, 3, 4]),
            key_package_slot_id: "slot-1".into(),
            key_package_ref: "bb".repeat(32),
            mls_ciphersuite: "0x0001".into(),
            mls_extensions: vec!["0x0006".into(), "0xf2f1".into(), "0x000a".into()],
            mls_proposals: vec!["0x0008".into(), "0x000a".into()],
            app_components: vec!["0x8001".into(), "0x8003".into(), "0x8004".into()],
            publish_endpoints: vec![TransportEndpoint("wss://kp.example".into())],
        }
        .to_event()
        .expect("key package event");

        let event = sdk.event_for_publish(&dto).await.expect("event");

        event.verify().expect("signed event verifies");
        assert_eq!(event.pubkey, keys.public_key());
        assert_eq!(event.kind.as_u16(), 30_443);
        assert_eq!(event.content, dto.content);
    }

    #[tokio::test]
    async fn concurrent_batch_clients_keep_account_signers_isolated() {
        let keys_a = Keys::generate();
        let keys_b = Keys::generate();
        let sdk_a = NostrSdkRelayClient::new(Client::builder().signer(keys_a.clone()).build());
        let sdk_b = NostrSdkRelayClient::new(Client::builder().signer(keys_b.clone()).build());
        let event_a = NostrTransportEvent::new_unsigned(
            keys_a.public_key().to_hex(),
            5,
            vec![vec!["e".into(), "11".repeat(32)]],
            String::new(),
        );
        let event_b = NostrTransportEvent::new_unsigned(
            keys_b.public_key().to_hex(),
            5,
            vec![vec!["e".into(), "22".repeat(32)]],
            String::new(),
        );

        let (signed_a, signed_b) = tokio::join!(
            sdk_a.event_for_publish(&event_a),
            sdk_b.event_for_publish(&event_b)
        );

        assert_eq!(signed_a.unwrap().pubkey, keys_a.public_key());
        assert_eq!(signed_b.unwrap().pubkey, keys_b.public_key());
    }

    #[test]
    fn publish_timeout_exceeds_sdk_ok_wait() {
        assert!(SDK_RELAY_PUBLISH_WAIT > Duration::from_secs(10));
    }

    #[test]
    fn publish_overall_wait_bounds_degraded_publish_below_per_relay_budget() {
        // Worst case a single relay can occupy: one connect plus every send
        // attempt and the backoffs between them.
        let per_relay_worst = SDK_RELAY_CONNECT_WAIT
            + SDK_RELAY_PUBLISH_WAIT * SDK_RELAY_PUBLISH_ATTEMPTS as u32
            + SDK_RELAY_PUBLISH_RETRY_BACKOFF * (SDK_RELAY_PUBLISH_ATTEMPTS as u32 - 1);
        // The overall ceiling must cap the degraded fan-out below that budget...
        assert!(SDK_RELAY_PUBLISH_OVERALL_WAIT < per_relay_worst);
        // ...while still allowing a slow relay one full connect + send attempt.
        assert!(SDK_RELAY_PUBLISH_OVERALL_WAIT >= SDK_RELAY_CONNECT_WAIT + SDK_RELAY_PUBLISH_WAIT);
    }

    #[tokio::test]
    async fn publish_event_does_not_wait_for_silent_relays_once_required_acks_are_met() {
        let relay = MockRelay::run().await.unwrap();
        let reachable = TransportEndpoint(relay.url().await.to_string());
        let silent = TransportEndpoint(silent_relay_url().await);
        let keys = Keys::generate();
        let client = Client::builder().signer(keys).build();
        let sdk = NostrSdkRelayClient::new(client);
        // kind-445 events must arrive pre-signed by a fresh ephemeral key; the
        // publish path rejects unsigned 445s (spec/transports/nostr.md:64-66).
        let dto = signed_group_event_dto();

        let outcome = timeout(
            Duration::from_secs(2),
            sdk.publish_event(&[silent, reachable.clone()], &dto, 1),
        )
        .await
        .expect("publish should return as soon as the required ack arrives")
        .expect("one good relay should satisfy the publish");

        assert_eq!(outcome.accepted.len(), 1);
        assert_eq!(outcome.accepted[0].endpoint, reachable);
        assert!(
            outcome.failed.is_empty(),
            "aborted fan-out tasks must not add failures after quorum"
        );
        assert_eq!(sdk.relay_health().await.total_relays, 0);
    }

    #[tokio::test]
    async fn publish_event_does_not_wait_for_hung_connect_once_required_ack_is_met() {
        let relay = MockRelay::run().await.unwrap();
        let reachable = TransportEndpoint(relay.url().await.to_string());
        let hung_connect = TransportEndpoint(hanging_connect_relay_url().await);
        let keys = Keys::generate();
        let client = Client::builder().signer(keys).build();
        let sdk = NostrSdkRelayClient::new(client);
        let dto = signed_group_event_dto();

        let outcome = timeout(
            Duration::from_secs(2),
            sdk.publish_event(&[hung_connect, reachable.clone()], &dto, 1),
        )
        .await
        .expect("a hung relay connect must not delay a healthy acknowledgement")
        .expect("one healthy relay should satisfy the publish");

        assert_eq!(outcome.accepted.len(), 1);
        assert_eq!(outcome.accepted[0].endpoint, reachable);
        assert!(
            outcome.failed.is_empty(),
            "aborted fan-out tasks must not add failures after quorum"
        );
        assert_eq!(sdk.relay_health().await.total_relays, 0);
    }

    #[tokio::test]
    async fn publish_connection_failure_is_retryable_before_exposure() {
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = TransportEndpoint(format!("ws://{}", reservation.local_addr().unwrap()));
        drop(reservation);
        let sdk = NostrSdkRelayClient::new(Client::builder().signer(Keys::generate()).build());
        let dto = signed_group_event_dto();

        let error = timeout(
            Duration::from_secs(3),
            sdk.publish_event(std::slice::from_ref(&endpoint), &dto, 1),
        )
        .await
        .expect("a refused connection must fail promptly")
        .expect_err("an event cannot be published without a relay connection");

        let failures = error.publish_endpoint_failures();
        assert_eq!(failures.len(), 1);
        assert_eq!(
            failures[0].kind,
            TransportEndpointFailureKind::RetryableUnavailable,
            "a failed connection proves the event was never exposed to the relay",
        );
        assert_eq!(sdk.relay_health().await.total_relays, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn publish_event_cleans_one_shot_relay_after_overall_timeout() {
        let stored_ids = Arc::new(Mutex::new(Vec::new()));
        let endpoint = TransportEndpoint(storing_no_ack_relay_url(stored_ids.clone()).await);
        let keys = Keys::generate();
        let client = Client::builder().signer(keys).build();
        let sdk = NostrSdkRelayClient::new(client);
        // kind-445 events must arrive pre-signed by a fresh ephemeral key; the
        // publish path rejects unsigned 445s (spec/transports/nostr.md:64-66).
        let dto = signed_group_event_dto();
        let expected_id = dto.id.clone();
        let publish_sdk = sdk.clone();
        let publish_endpoint = endpoint.clone();
        let publish = tokio::spawn(async move {
            publish_sdk
                .publish_event(std::slice::from_ref(&publish_endpoint), &dto, 1)
                .await
        });

        for _ in 0..100 {
            if stored_ids.lock().await.contains(&expected_id) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            stored_ids.lock().await.contains(&expected_id),
            "the relay must receive the event before withholding OK"
        );
        advance(SDK_RELAY_PUBLISH_OVERALL_WAIT + Duration::from_secs(1)).await;
        let err = publish
            .await
            .expect("publish task must not panic")
            .expect_err("a relay withholding OK should miss the required ack deadline");

        assert!(err.to_string().contains("publish timed out"));
        assert_eq!(
            err.publish_message_id().unwrap().as_slice(),
            hex::decode(expected_id).unwrap()
        );
        assert!(
            err.publish_endpoint_failures()
                .iter()
                .all(|failure| { failure.kind == TransportEndpointFailureKind::PossiblyExposed })
        );
        assert_eq!(sdk.relay_health().await.total_relays, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn ambiguous_publish_timeout_resets_stale_durable_relay_before_retry() {
        let (relay_url, connection_count, stale_connection_closed) =
            stale_then_healthy_relay_url().await;
        let endpoint = TransportEndpoint(relay_url);
        let client = Client::builder().signer(Keys::generate()).build();
        client
            .add_relay(endpoint.as_str())
            .await
            .expect("add durable relay");
        let sdk = NostrSdkRelayClient::new(client);
        let dto = signed_group_event_dto();
        let first_sdk = sdk.clone();
        let first_endpoint = endpoint.clone();
        let first_dto = dto.clone();
        let first_publish = tokio::spawn(async move {
            first_sdk
                .publish_event(std::slice::from_ref(&first_endpoint), &first_dto, 1)
                .await
        });

        for _ in 0..100 {
            if *connection_count.lock().await == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            *connection_count.lock().await,
            1,
            "the first publish must reach the stale connection"
        );

        advance(SDK_RELAY_PUBLISH_OVERALL_WAIT + Duration::from_secs(1)).await;
        first_publish
            .await
            .expect("first publish task must not panic")
            .expect_err("the stale connection must miss the acknowledgement deadline");

        let health = sdk.relay_health().await;
        assert_eq!(
            health.terminated, 1,
            "an ambiguous timeout must invalidate the SDK's stale Connected status"
        );
        stale_connection_closed.notified().await;
        tokio::time::resume();

        let retry = sdk
            .publish_event(std::slice::from_ref(&endpoint), &dto, 1)
            .await
            .expect("the next publish must reconnect through a fresh socket");
        assert_eq!(retry.accepted.len(), 1);
        assert_eq!(*connection_count.lock().await, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn relay_that_stores_event_but_withholds_ok_is_possibly_exposed() {
        let stored_ids = Arc::new(Mutex::new(Vec::new()));
        let endpoint = TransportEndpoint(storing_no_ack_relay_url(stored_ids.clone()).await);
        let client = Client::builder().signer(Keys::generate()).build();
        let sdk = NostrSdkRelayClient::new(client);
        let dto = signed_group_event_dto();
        let expected_id = dto.id.clone();
        let publish_sdk = sdk.clone();
        let publish_endpoint = endpoint.clone();
        let publish = tokio::spawn(async move {
            publish_sdk
                .publish_event(std::slice::from_ref(&publish_endpoint), &dto, 1)
                .await
        });

        for _ in 0..100 {
            if stored_ids.lock().await.contains(&expected_id) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            stored_ids.lock().await.contains(&expected_id),
            "the relay must receive and retain the event before withholding OK"
        );

        advance(SDK_RELAY_PUBLISH_OVERALL_WAIT + Duration::from_secs(1)).await;
        let err = publish
            .await
            .expect("publish task must not panic")
            .expect_err("withheld OK must leave completion unresolved");
        assert_eq!(
            err.publish_message_id().unwrap().as_slice(),
            hex::decode(expected_id).unwrap()
        );
        assert_eq!(err.publish_endpoint_failures().len(), 1);
        assert_eq!(
            err.publish_endpoint_failures()[0].kind,
            TransportEndpointFailureKind::PossiblyExposed
        );
    }

    #[tokio::test(start_paused = true)]
    async fn publish_event_retains_relay_promoted_to_durable_during_publish() {
        let endpoint = TransportEndpoint(silent_relay_url().await);
        let keys = Keys::generate();
        let client = Client::builder().signer(keys).build();
        let sdk = NostrSdkRelayClient::new(client);
        // kind-445 events must arrive pre-signed by a fresh ephemeral key; the
        // publish path rejects unsigned 445s (spec/transports/nostr.md:64-66).
        let dto = signed_group_event_dto();
        let publish_sdk = sdk.clone();
        let publish_endpoint = endpoint.clone();
        let publish_dto = dto.clone();
        let publish = tokio::spawn(async move {
            publish_sdk
                .publish_event(std::slice::from_ref(&publish_endpoint), &publish_dto, 1)
                .await
        });

        let mut one_shot_relay_added = false;
        for _ in 0..100 {
            if sdk.relay_health().await.total_relays == 1 {
                one_shot_relay_added = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            one_shot_relay_added,
            "publish should add the one-shot relay"
        );

        sdk.client().add_relay(endpoint.as_str()).await.unwrap();

        advance(SDK_RELAY_PUBLISH_OVERALL_WAIT + Duration::from_secs(1)).await;
        let err = publish
            .await
            .expect("publish task should not panic")
            .expect_err("silent relay should miss the required ack deadline");

        assert!(err.to_string().contains("publish timed out"));
        assert_eq!(sdk.relay_health().await.total_relays, 1);
    }

    #[tokio::test]
    async fn publish_event_accepts_republishing_same_signed_replaceable_event() {
        let relay = MockRelay::run().await.unwrap();
        let endpoint = TransportEndpoint(relay.url().await.to_string());
        let keys = Keys::generate();
        let client = Client::builder().signer(keys.clone()).build();
        let sdk = NostrSdkRelayClient::new(client);
        let dto = NostrKeyPackagePublication {
            account_id: MemberId::new(keys.public_key().to_bytes().to_vec()),
            key_package: KeyPackage::new(vec![1, 2, 3, 4]),
            key_package_slot_id: "slot-1".into(),
            key_package_ref: "bb".repeat(32),
            mls_ciphersuite: "0x0001".into(),
            mls_extensions: vec!["0x0006".into(), "0xf2f1".into(), "0x000a".into()],
            mls_proposals: vec!["0x0008".into(), "0x000a".into()],
            app_components: vec!["0x8001".into(), "0x8003".into(), "0x8004".into()],
            publish_endpoints: vec![endpoint.clone()],
        }
        .to_event()
        .expect("key package event");

        timeout(
            Duration::from_secs(2),
            sdk.publish_event(std::slice::from_ref(&endpoint), &dto, 1),
        )
        .await
        .expect("first publish should complete")
        .expect("first publish should succeed");

        let republish = timeout(
            Duration::from_secs(2),
            sdk.publish_event(std::slice::from_ref(&endpoint), &dto, 1),
        )
        .await
        .expect("adapter republish should complete")
        .expect("republishing the exact signed key package must be accepted");

        assert_eq!(republish.accepted.len(), 1);
        assert_eq!(republish.accepted[0].endpoint, endpoint);
    }

    #[tokio::test]
    async fn publish_event_removes_one_shot_relay_after_publish() {
        let relay = MockRelay::run().await.unwrap();
        let endpoint = TransportEndpoint(relay.url().await.to_string());
        let keys = Keys::generate();
        let client = Client::builder().signer(keys).build();
        let sdk = NostrSdkRelayClient::new(client);
        // kind-445 events must arrive pre-signed by a fresh ephemeral key; the
        // publish path rejects unsigned 445s (spec/transports/nostr.md:64-66).
        let dto = signed_group_event_dto();

        let outcome = timeout(
            Duration::from_secs(2),
            sdk.publish_event(std::slice::from_ref(&endpoint), &dto, 1),
        )
        .await
        .expect("publish should complete")
        .expect("reachable relay should accept publish");

        assert_eq!(outcome.accepted.len(), 1);
        assert_eq!(outcome.accepted[0].endpoint, endpoint);
        assert_eq!(sdk.relay_health().await.total_relays, 0);
    }

    #[tokio::test]
    async fn publish_relay_pin_failure_tracks_only_a_relay_that_remains_registered() {
        let registered_endpoint = RelayUrl::parse("wss://registered-pin-failure.example").unwrap();
        let registered_sdk = NostrSdkRelayClient::new(Client::builder().build());
        registered_sdk
            .publish_relay_pin_failure_stage
            .store(1, Ordering::Relaxed);

        assert!(
            registered_sdk
                .retain_publish_relay(&registered_endpoint)
                .await
                .expect("an unpinned relay that remains registered must stay cleanup-tracked")
        );
        assert_eq!(
            registered_sdk
                .publish_relay_refs
                .lock()
                .await
                .get(&registered_endpoint),
            Some(&1)
        );
        registered_sdk
            .release_publish_relay(registered_endpoint.clone())
            .await
            .unwrap();
        assert!(
            !registered_sdk
                .client
                .relays()
                .await
                .contains_key(&registered_endpoint),
            "the tracked degraded relay must still be removed at lease release"
        );

        let removed_endpoint = RelayUrl::parse("wss://removed-pin-failure.example").unwrap();
        let removed_sdk = NostrSdkRelayClient::new(Client::builder().build());
        removed_sdk
            .publish_relay_pin_failure_stage
            .store(2, Ordering::Relaxed);

        removed_sdk
            .retain_publish_relay(&removed_endpoint)
            .await
            .expect_err("a pin failure that removed the relay must remain unavailable");
        assert!(removed_sdk.publish_relay_refs.lock().await.is_empty());
        assert!(
            !removed_sdk
                .client
                .relays()
                .await
                .contains_key(&removed_endpoint)
        );
    }

    #[tokio::test]
    async fn publish_event_retains_existing_relay_after_publish() {
        let relay = MockRelay::run().await.unwrap();
        let endpoint = TransportEndpoint(relay.url().await.to_string());
        let keys = Keys::generate();
        let client = Client::builder().signer(keys).build();
        client.add_relay(endpoint.as_str()).await.unwrap();
        let sdk = NostrSdkRelayClient::new(client);
        // kind-445 events must arrive pre-signed by a fresh ephemeral key; the
        // publish path rejects unsigned 445s (spec/transports/nostr.md:64-66).
        let dto = signed_group_event_dto();

        let outcome = timeout(
            Duration::from_secs(2),
            sdk.publish_event(std::slice::from_ref(&endpoint), &dto, 1),
        )
        .await
        .expect("publish should complete")
        .expect("reachable relay should accept publish");

        assert_eq!(outcome.accepted.len(), 1);
        assert_eq!(outcome.accepted[0].endpoint, endpoint);
        assert_eq!(sdk.relay_health().await.total_relays, 1);
    }

    #[tokio::test]
    async fn publish_event_counts_duplicate_endpoint_once_for_required_acks() {
        let relay = MockRelay::run().await.unwrap();
        let endpoint = TransportEndpoint(relay.url().await.to_string());
        let keys = Keys::generate();
        let client = Client::builder().signer(keys).build();
        let sdk = NostrSdkRelayClient::new(client);
        // kind-445 events must arrive pre-signed by a fresh ephemeral key; the
        // publish path rejects unsigned 445s (spec/transports/nostr.md:64-66).
        let dto = signed_group_event_dto();

        let err = sdk
            .publish_event(&[endpoint.clone(), endpoint], &dto, 2)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("accepted 1 of required 2"));
    }

    #[tokio::test]
    async fn publish_batch_connects_shared_relay_once_and_cleans_scope() {
        let relay = MockRelay::run().await.unwrap();
        let endpoint = TransportEndpoint(relay.url().await.to_string());
        let relay_url = RelayUrl::parse(endpoint.as_str()).unwrap();
        let client = Client::builder().signer(Keys::generate()).build();
        let sdk = NostrSdkRelayClient::new(client);
        let requests = [
            NostrEventPublishRequest {
                endpoints: vec![endpoint.clone()],
                event: signed_group_event_dto(),
                required_acks: 1,
            },
            NostrEventPublishRequest {
                endpoints: vec![endpoint],
                event: signed_group_event_dto(),
                required_acks: 1,
            },
        ];

        let outcomes = sdk.publish_events(&requests).await;

        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.into_iter().all(|outcome| outcome.is_ok()));
        assert_eq!(
            sdk.publish_connect_attempts.lock().await.get(&relay_url),
            Some(&1)
        );
        assert_eq!(
            sdk.publish_release_attempts.lock().await.get(&relay_url),
            Some(&1)
        );
        assert_eq!(sdk.relay_health().await.total_relays, 0);
    }

    #[tokio::test]
    async fn publish_batch_starts_healthy_request_while_another_request_is_stalled() {
        let healthy_relay = MockRelay::run().await.unwrap();
        let healthy_endpoint = TransportEndpoint(healthy_relay.url().await.to_string());
        let silent_endpoint = TransportEndpoint(silent_relay_url().await);

        let observer = Client::builder().build();
        let mut notifications = observer.notifications();
        observer.add_relay(healthy_endpoint.as_str()).await.unwrap();
        observer.connect().await;
        let subscription_id = SubscriptionId::new("concurrent-batch-observer");
        observer
            .subscribe_with_id_to(
                [healthy_endpoint.as_str()],
                subscription_id,
                Filter::new().kind(Kind::MlsGroupMessage),
                None,
            )
            .await
            .unwrap();

        let stalled_event = signed_group_event_dto();
        let healthy_event = signed_group_event_dto();
        let healthy_event_id = healthy_event.id.clone();
        let sdk = NostrSdkRelayClient::new(Client::builder().build());
        let publishing_sdk = sdk.clone();
        let publish = tokio::spawn(async move {
            publishing_sdk
                .publish_events(&[
                    NostrEventPublishRequest {
                        endpoints: vec![silent_endpoint],
                        event: stalled_event,
                        required_acks: 1,
                    },
                    NostrEventPublishRequest {
                        endpoints: vec![healthy_endpoint],
                        event: healthy_event,
                        required_acks: 1,
                    },
                ])
                .await
        });

        timeout(Duration::from_secs(2), async {
            loop {
                match notifications
                    .recv()
                    .await
                    .expect("observer notification channel remains open")
                {
                    RelayPoolNotification::Event { event, .. }
                        if event.id.to_hex() == healthy_event_id =>
                    {
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("a stalled request must not prevent an independent healthy publish");

        publish.abort();
        let _ = publish.await;
        observer.shutdown().await;
    }

    #[tokio::test]
    async fn publish_batch_preserves_request_order_after_partial_failure() {
        let healthy_relay = MockRelay::run().await.unwrap();
        let healthy_endpoint = TransportEndpoint(healthy_relay.url().await.to_string());
        let unavailable_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unavailable_endpoint = TransportEndpoint(format!(
            "ws://{}",
            unavailable_listener.local_addr().unwrap()
        ));
        drop(unavailable_listener);
        let sdk = NostrSdkRelayClient::new(Client::builder().build());

        let outcomes = sdk
            .publish_events(&[
                NostrEventPublishRequest {
                    endpoints: vec![unavailable_endpoint],
                    event: signed_group_event_dto(),
                    required_acks: 1,
                },
                NostrEventPublishRequest {
                    endpoints: vec![healthy_endpoint],
                    event: signed_group_event_dto(),
                    required_acks: 1,
                },
            ])
            .await;

        assert_eq!(outcomes.len(), 2);
        assert!(
            outcomes[0].is_err(),
            "unavailable request must fail in slot zero"
        );
        assert_eq!(
            outcomes[0]
                .as_ref()
                .unwrap_err()
                .publish_endpoint_failures()[0]
                .kind,
            TransportEndpointFailureKind::RetryableUnavailable
        );
        assert!(
            outcomes[1].is_ok(),
            "healthy request must remain successful in slot one"
        );
        assert_eq!(sdk.relay_health().await.total_relays, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn publish_batch_all_stalled_requests_share_one_deadline_window() {
        let first_silent = TransportEndpoint(silent_relay_url().await);
        let second_silent = TransportEndpoint(silent_relay_url().await);
        let sdk = NostrSdkRelayClient::new(Client::builder().build());
        let started_at = tokio::time::Instant::now();

        let outcomes = sdk
            .publish_events(&[
                NostrEventPublishRequest {
                    endpoints: vec![first_silent],
                    event: signed_group_event_dto(),
                    required_acks: 1,
                },
                NostrEventPublishRequest {
                    endpoints: vec![second_silent],
                    event: signed_group_event_dto(),
                    required_acks: 1,
                },
            ])
            .await;

        assert!(outcomes.iter().all(Result::is_err));
        assert!(
            started_at.elapsed() <= SDK_RELAY_PUBLISH_OVERALL_WAIT + Duration::from_secs(1),
            "all-unavailable latency {:?} must stay within one concurrent request window",
            started_at.elapsed(),
        );
        assert_eq!(sdk.relay_health().await.total_relays, 0);
    }

    #[tokio::test]
    async fn publish_batch_deduplicates_mixed_endpoint_sets() {
        let relay_a = MockRelay::run().await.unwrap();
        let relay_b = MockRelay::run().await.unwrap();
        let endpoint_a = TransportEndpoint(relay_a.url().await.to_string());
        let endpoint_b = TransportEndpoint(relay_b.url().await.to_string());
        let relay_url_a = RelayUrl::parse(endpoint_a.as_str()).unwrap();
        let relay_url_b = RelayUrl::parse(endpoint_b.as_str()).unwrap();
        let client = Client::builder().signer(Keys::generate()).build();
        let sdk = NostrSdkRelayClient::new(client);
        let requests = [
            NostrEventPublishRequest {
                endpoints: vec![endpoint_a.clone(), endpoint_b.clone(), endpoint_a],
                event: signed_group_event_dto(),
                required_acks: 1,
            },
            NostrEventPublishRequest {
                endpoints: vec![endpoint_b],
                event: signed_group_event_dto(),
                required_acks: 1,
            },
        ];

        let outcomes = sdk.publish_events(&requests).await;

        assert!(outcomes.into_iter().all(|outcome| outcome.is_ok()));
        let attempts = sdk.publish_connect_attempts.lock().await;
        assert_eq!(attempts.get(&relay_url_a), Some(&1));
        assert_eq!(attempts.get(&relay_url_b), Some(&1));
        drop(attempts);
        assert_eq!(sdk.relay_health().await.total_relays, 0);
    }

    #[tokio::test]
    async fn publish_batch_cleans_write_only_relay_after_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = TransportEndpoint(format!("ws://{}", listener.local_addr().unwrap()));
        drop(listener);
        let relay_url = RelayUrl::parse(endpoint.as_str()).unwrap();
        let client = Client::builder().signer(Keys::generate()).build();
        let sdk = NostrSdkRelayClient::new(client);

        let err = sdk
            .publish_events(&[NostrEventPublishRequest {
                endpoints: vec![endpoint],
                event: signed_group_event_dto(),
                required_acks: 1,
            }])
            .await
            .remove(0)
            .expect_err("unreachable relay must fail");

        assert!(!err.to_string().is_empty());
        assert_eq!(
            sdk.publish_release_attempts.lock().await.get(&relay_url),
            Some(&1)
        );
        assert_eq!(sdk.relay_health().await.total_relays, 0);
    }

    #[tokio::test]
    async fn cancelled_publish_batch_cleans_write_only_relay() {
        let endpoint = TransportEndpoint(silent_relay_url().await);
        let relay_url = RelayUrl::parse(endpoint.as_str()).unwrap();
        let client = Client::builder().signer(Keys::generate()).build();
        let sdk = NostrSdkRelayClient::new(client);
        let publish_sdk = sdk.clone();
        let publish = tokio::spawn(async move {
            publish_sdk
                .publish_events(&[NostrEventPublishRequest {
                    endpoints: vec![endpoint],
                    event: signed_group_event_dto(),
                    required_acks: 1,
                }])
                .await
        });

        for _ in 0..100 {
            if sdk
                .publish_connect_attempts
                .lock()
                .await
                .contains_key(&relay_url)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        let relay = sdk
            .client()
            .relays()
            .await
            .get(&relay_url)
            .cloned()
            .expect("batch must retain its transient relay");
        assert!(relay.flags().has_write());
        assert!(
            !relay.flags().has_read(),
            "publish-only relay must not inherit subscriptions"
        );

        publish.abort();
        let _ = publish.await;
        for _ in 0..100 {
            if sdk.relay_health().await.total_relays == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }

        assert_eq!(
            sdk.publish_release_attempts.lock().await.get(&relay_url),
            Some(&1)
        );
        assert_eq!(sdk.relay_health().await.total_relays, 0);
    }

    #[tokio::test]
    async fn sdk_does_not_cache_failed_signature_verification() {
        let transport_group_id = vec![0xCC; 32];
        let event = EventBuilder::new(Kind::MlsGroupMessage, "outer encrypted body")
            .tags([Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::H)),
                [hex::encode(&transport_group_id)],
            )])
            .sign_with_keys(&Keys::generate())
            .expect("sign test event");
        let mut first_invalid = event.clone();
        first_invalid.sig = EventBuilder::new(Kind::TextNote, "wrong signature")
            .sign_with_keys(&Keys::generate())
            .expect("sign replacement signature")
            .sig;
        let mut second_invalid = event.clone();
        second_invalid.sig = EventBuilder::new(Kind::TextNote, "another wrong signature")
            .sign_with_keys(&Keys::generate())
            .expect("sign second replacement signature")
            .sig;
        assert!(first_invalid.verify().is_err());
        assert!(second_invalid.verify().is_err());
        assert_eq!(first_invalid.id, second_invalid.id);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint_text = format!("ws://{}", listener.local_addr().unwrap());
        let endpoint = RelayUrl::parse(&endpoint_text).unwrap();
        let (relay_done_tx, relay_done_rx) = tokio::sync::oneshot::channel();
        let relay = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(message) = socket.next().await {
                let Ok(tokio_tungstenite::tungstenite::Message::Text(message)) = message else {
                    continue;
                };
                let request: serde_json::Value = serde_json::from_str(&message).unwrap();
                if request[0] != "REQ" {
                    continue;
                }
                let subscription_id = request[1].as_str().unwrap();
                for invalid in [&first_invalid, &second_invalid] {
                    socket
                        .send(
                            serde_json::json!(["EVENT", subscription_id, invalid])
                                .to_string()
                                .into(),
                        )
                        .await
                        .unwrap();
                }
                socket
                    .send(
                        serde_json::json!(["EOSE", subscription_id])
                            .to_string()
                            .into(),
                    )
                    .await
                    .unwrap();
                let _ = relay_done_rx.await;
                return;
            }
        });

        let client = Client::builder().build();
        // Subscribe before the relay connects: unlike `handle_notifications`,
        // this synchronous receiver is installed before the first event can
        // arrive and cannot race the test relay's immediate response.
        let mut notifications = client.notifications();

        client.add_relay(endpoint.clone()).await.unwrap();
        client.connect().await;
        let subscription_id = SubscriptionId::new("cache-poisoning-regression");
        client
            .subscribe_with_id_to(
                [endpoint],
                subscription_id,
                Filter::new().kind(Kind::MlsGroupMessage).custom_tags(
                    SingleLetterTag::lowercase(Alphabet::H),
                    [hex::encode(&transport_group_id)],
                ),
                None,
            )
            .await
            .unwrap();

        const RELAY_EOSE_TIMEOUT: Duration = Duration::from_secs(30);
        timeout(RELAY_EOSE_TIMEOUT, async {
            loop {
                match notifications
                    .recv()
                    .await
                    .expect("notification channel remains open")
                {
                    RelayPoolNotification::Event { .. } => {
                        panic!("failed signature verification must not emit a trusted event")
                    }
                    RelayPoolNotification::Message {
                        message: RelayMessage::EndOfStoredEvents(_),
                        ..
                    } => break,
                    _ => {}
                }
            }
        })
        .await
        .expect("the relay EOSE must arrive within the CI-safe timeout");
        assert_eq!(
            client.database().check_id(&event.id).await.unwrap(),
            DatabaseEventStatus::NotExistent,
            "events that fail verification must not be stored"
        );

        let _ = relay_done_tx.send(());
        timeout(Duration::from_secs(5), relay)
            .await
            .unwrap()
            .unwrap();
        client.shutdown().await;
    }

    #[test]
    fn invalid_endpoint_is_rejected_during_planning() {
        let err = NostrSdkRelayClient::plan_subscription(&NostrSubscription::Group {
            account_id: MemberId::new(vec![0xA1; 32]),
            group_id: cgka_traits::GroupId::new(vec![0xB2; 32]),
            transport_group_id: vec![0xC3; 32],
            endpoints: vec![TransportEndpoint("not a relay url".into())],
            since: None,
        })
        .unwrap_err();

        let rendered = err.to_string();
        assert!(rendered.contains("invalid relay endpoint"), "{rendered}");
        // The privacy invariant forbids relay URLs in error Display: the bad
        // endpoint itself must not be echoed back.
        assert!(!rendered.contains("not a relay url"), "{rendered}");
    }

    #[tokio::test]
    async fn subscription_relay_reconnects_within_durable_retry_budget() {
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = reservation.local_addr().unwrap();
        drop(reservation);

        let endpoint = RelayUrl::parse(&format!("ws://{addr}")).unwrap();
        let client = Client::builder().build();
        let sdk = NostrSdkRelayClient::new(client.clone());
        sdk.add_subscription_relay(endpoint.clone()).await.unwrap();
        client.connect_relay(endpoint.clone()).await.unwrap();

        timeout(Duration::from_secs(3), async {
            loop {
                let status = client
                    .relays()
                    .await
                    .get(&endpoint)
                    .expect("relay remains in the pool")
                    .status();
                if status == RelayStatus::Disconnected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the first unavailable connection attempt must fail promptly");

        let listener = TcpListener::bind(addr).await.unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            std::future::pending::<()>().await;
        });

        timeout(Duration::from_secs(8), async {
            loop {
                let status = client
                    .relays()
                    .await
                    .get(&endpoint)
                    .expect("relay remains in the pool")
                    .status();
                if status == RelayStatus::Connected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("relay must reconnect on the fixed five-second transport interval");

        server.abort();
        client.shutdown().await;
    }

    #[derive(Debug)]
    struct RejectAllWrites;

    impl nostr_relay_builder::prelude::WritePolicy for RejectAllWrites {
        fn admit_event<'a>(
            &'a self,
            _event: &'a nostr::Event,
            _addr: &'a std::net::SocketAddr,
        ) -> nostr_relay_builder::prelude::BoxedFuture<'a, nostr_relay_builder::prelude::PolicyResult>
        {
            Box::pin(async move {
                nostr_relay_builder::prelude::PolicyResult::Reject(
                    "injected write rejection".into(),
                )
            })
        }
    }

    #[tokio::test]
    async fn publish_event_nip42_write_relay_authenticates_kind5_key_package_deletion() {
        use crate::KIND_MARMOT_KEY_PACKAGE;
        use nostr_relay_builder::builder::{RelayBuilderNip42, RelayBuilderNip42Mode};
        use nostr_relay_builder::{LocalRelay, RelayBuilder};

        let relay = LocalRelay::new(RelayBuilder::default().nip42(RelayBuilderNip42 {
            mode: RelayBuilderNip42Mode::Write,
        }));
        relay.run().await.unwrap();
        let endpoint = TransportEndpoint(relay.url().await.to_string());
        let keys = Keys::generate();
        let client = Client::builder().signer(keys.clone()).build();
        let sdk = NostrSdkRelayClient::new(client);
        let deletion = NostrTransportEvent::new_unsigned(
            keys.public_key().to_hex(),
            5,
            vec![
                vec!["e".into(), "11".repeat(32)],
                vec!["k".into(), KIND_MARMOT_KEY_PACKAGE.to_string()],
            ],
            String::new(),
        );

        let outcome = sdk
            .publish_event(&[endpoint], &deletion, 1)
            .await
            .expect("signer-backed SDK client must complete NIP-42 auth and publish");

        assert_eq!(outcome.accepted.len(), 1);
        assert!(outcome.failed.is_empty());
    }

    #[tokio::test]
    async fn publish_event_reports_per_relay_rejection_categories_with_collapsed_display() {
        use crate::KIND_MARMOT_KEY_PACKAGE;
        use nostr_relay_builder::{LocalRelay, RelayBuilder};

        let relay_a = LocalRelay::new(RelayBuilder::default().write_policy(RejectAllWrites));
        relay_a.run().await.unwrap();
        let relay_b = LocalRelay::new(RelayBuilder::default().write_policy(RejectAllWrites));
        relay_b.run().await.unwrap();
        let endpoint_a = TransportEndpoint(relay_a.url().await.to_string());
        let endpoint_b = TransportEndpoint(relay_b.url().await.to_string());
        let keys = Keys::generate();
        let client = Client::builder().signer(keys.clone()).build();
        let sdk = NostrSdkRelayClient::new(client);
        let deletion = NostrTransportEvent::new_unsigned(
            keys.public_key().to_hex(),
            5,
            vec![
                vec!["e".into(), "11".repeat(32)],
                vec!["k".into(), KIND_MARMOT_KEY_PACKAGE.to_string()],
            ],
            String::new(),
        );

        let err = sdk
            .publish_event(&[endpoint_a, endpoint_b], &deletion, 1)
            .await
            .expect_err("both relays reject writes");

        let rendered = err.to_string();
        assert_eq!(rendered, "publish failed: relay rejected event (blocked)");
        assert!(!rendered.contains("injected write rejection"));
        if let TransportAdapterError::PublishEndpoints(failure) = err {
            assert_eq!(failure.endpoint_failures.len(), 2);
            assert!(failure.endpoint_failures.iter().all(|endpoint_failure| {
                endpoint_failure.rejection_category
                    == Some(TransportEndpointRejectionCategory::Blocked)
            }));
        } else {
            panic!("expected structured publish failure");
        }
    }

    async fn silent_relay_url() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    if tokio_tungstenite::accept_async(stream).await.is_ok() {
                        std::future::pending::<()>().await;
                    }
                });
            }
        });
        format!("ws://{addr}")
    }

    async fn storing_no_ack_relay_url(stored_ids: Arc<Mutex<Vec<String>>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let stored_ids = stored_ids.clone();
                tokio::spawn(async move {
                    let Ok(mut websocket) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    while let Some(Ok(message)) = websocket.next().await {
                        let Ok(text) = message.into_text() else {
                            continue;
                        };
                        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
                            continue;
                        };
                        let Some(items) = value.as_array() else {
                            continue;
                        };
                        if items.first().and_then(serde_json::Value::as_str) != Some("EVENT") {
                            continue;
                        }
                        if let Some(id) = items
                            .get(1)
                            .and_then(|event| event.get("id"))
                            .and_then(serde_json::Value::as_str)
                        {
                            stored_ids.lock().await.push(id.to_owned());
                        }
                    }
                });
            }
        });
        format!("ws://{addr}")
    }

    async fn stale_then_healthy_relay_url() -> (String, Arc<Mutex<usize>>, Arc<tokio::sync::Notify>)
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connection_count = Arc::new(Mutex::new(0));
        let server_connection_count = connection_count.clone();
        let stale_connection_closed = Arc::new(tokio::sync::Notify::new());
        let server_stale_connection_closed = stale_connection_closed.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let connection_number = {
                    let mut count = server_connection_count.lock().await;
                    *count += 1;
                    *count
                };
                let stale_connection_closed = server_stale_connection_closed.clone();
                tokio::spawn(async move {
                    let Ok(mut websocket) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    while let Some(Ok(message)) = websocket.next().await {
                        let Ok(text) = message.into_text() else {
                            continue;
                        };
                        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
                            continue;
                        };
                        let Some(items) = value.as_array() else {
                            continue;
                        };
                        if items.first().and_then(serde_json::Value::as_str) != Some("EVENT") {
                            continue;
                        }
                        let Some(id) = items
                            .get(1)
                            .and_then(|event| event.get("id"))
                            .and_then(serde_json::Value::as_str)
                        else {
                            continue;
                        };
                        // The first WebSocket models iOS's silently dead socket:
                        // writes appear to work but no OK or disconnect arrives.
                        // A fresh connection after MDK invalidates that socket is
                        // healthy and acknowledges the byte-identical retry.
                        if connection_number > 1 {
                            let ok = serde_json::json!(["OK", id, true, ""]);
                            if websocket.send(ok.to_string().into()).await.is_err() {
                                return;
                            }
                        }
                    }
                    if connection_number == 1 {
                        stale_connection_closed.notify_one();
                    }
                });
            }
        });
        (
            format!("ws://{addr}"),
            connection_count,
            stale_connection_closed,
        )
    }

    async fn hanging_connect_relay_url() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _stream = stream;
                    std::future::pending::<()>().await;
                });
            }
        });
        format!("ws://{addr}")
    }
}
