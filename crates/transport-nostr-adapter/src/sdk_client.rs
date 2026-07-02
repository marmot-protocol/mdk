use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::{
    MemberId, TransportAdapterError, TransportEndpoint, TransportEndpointFailure,
    TransportEndpointReceipt,
};
use nostr_sdk::prelude::{
    Alphabet, Client, Event, EventBuilder, Filter, Kind, PublicKey, RelayMessage,
    RelayPoolNotification, RelayStatus, RelayUrl, SingleLetterTag, SubscriptionId, Tag, TagKind,
    Timestamp as NostrTimestamp,
};
use tokio::sync::{Mutex, RwLock};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;
use transport_nostr_peeler::{KIND_MARMOT_GROUP_MESSAGE, NostrTransportEvent};

use crate::{
    NostrPublishOutcome, NostrRelayClient, NostrRelayEvent, NostrSubscription,
    NostrTransportAdapter,
};

const SDK_RELAY_CONNECT_WAIT: Duration = Duration::from_secs(5);
// nostr-sdk 0.44 waits up to 10s for each relay's OK response. Keep this
// wrapper above that so SDK endpoint-level success/failure results surface
// instead of a Darkmatter-level timeout masking them.
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

/// `nostr-sdk` backed implementation of [`NostrRelayClient`].
#[derive(Clone)]
pub struct NostrSdkRelayClient {
    client: Client,
    account_subscriptions: Arc<RwLock<HashMap<MemberId, Vec<SubscriptionId>>>>,
    publish_relay_refs: Arc<Mutex<HashMap<RelayUrl, usize>>>,
}

impl NostrSdkRelayClient {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            account_subscriptions: Arc::new(RwLock::new(HashMap::new())),
            publish_relay_refs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn client(&self) -> &Client {
        &self.client
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

    async fn publish_to_relay(
        client: Client,
        endpoint: RelayUrl,
        event: Event,
    ) -> Result<TransportEndpointReceipt, TransportEndpointFailure> {
        let transport_endpoint = TransportEndpoint(endpoint.to_string());
        match timeout(
            SDK_RELAY_CONNECT_WAIT,
            client.connect_relay(endpoint.clone()),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return Err(TransportEndpointFailure {
                    endpoint: transport_endpoint,
                    reason: format!("connect relay: {e}"),
                });
            }
            Err(_) => {
                return Err(TransportEndpointFailure {
                    endpoint: transport_endpoint,
                    reason: "connect relay timed out".to_owned(),
                });
            }
        }

        let mut last_error = "send event failed".to_owned();
        for attempt in 1..=SDK_RELAY_PUBLISH_ATTEMPTS {
            match timeout(
                SDK_RELAY_PUBLISH_WAIT,
                client.send_event_to([endpoint.clone()], &event),
            )
            .await
            {
                Ok(Ok(output)) if output.success.contains(&endpoint) => {
                    return Ok(TransportEndpointReceipt {
                        endpoint: transport_endpoint,
                        accepted_at: None,
                    });
                }
                Ok(Ok(output)) => {
                    last_error = output
                        .failed
                        .get(&endpoint)
                        .cloned()
                        .unwrap_or_else(|| "relay did not acknowledge event".to_owned());
                }
                Ok(Err(e)) => {
                    last_error = format!("send event: {e}");
                }
                Err(_) => {
                    last_error = "send event timed out".to_owned();
                }
            }
            if attempt < SDK_RELAY_PUBLISH_ATTEMPTS {
                tokio::time::sleep(SDK_RELAY_PUBLISH_RETRY_BACKOFF).await;
            }
        }

        Err(TransportEndpointFailure {
            endpoint: transport_endpoint,
            reason: last_error,
        })
    }

    async fn add_subscription_relay(
        &self,
        endpoint: RelayUrl,
    ) -> Result<(), TransportAdapterError> {
        let _relay_lifecycle = self.publish_relay_refs.lock().await;
        self.client
            .add_relay(endpoint)
            .await
            .map_err(|e| TransportAdapterError::Subscription(format!("add relay: {e}")))?;
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
                publish_relay_refs.insert(endpoint.clone(), 1);
                Ok(true)
            }
            Ok(false) => Ok(false),
            Err(e) => Err(TransportEndpointFailure {
                endpoint: transport_endpoint,
                reason: format!("add publish relay: {e}"),
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

    fn finish_publish_outcome(
        message_id: cgka_traits::MessageId,
        accepted: Vec<TransportEndpointReceipt>,
        failed: Vec<TransportEndpointFailure>,
        required_acks: usize,
        timed_out: bool,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        if required_acks == 0 || accepted.len() >= required_acks {
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
            failed
                .iter()
                .map(|failure| failure.reason.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        } else {
            format!(
                "insufficient publish acknowledgements: accepted {} of required {}",
                accepted.len(),
                required_acks
            )
        };
        Err(TransportAdapterError::Publish(reason))
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
            .map_err(|e| TransportAdapterError::Subscription(format!("subscribe: {e}")))?;

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
        let parsed_endpoints = parse_endpoints(endpoints, "publish")?;
        let mut seen_endpoints = HashSet::new();
        let parsed_endpoints = parsed_endpoints
            .into_iter()
            .filter(|endpoint| seen_endpoints.insert(endpoint.clone()))
            .collect::<Vec<_>>();
        let event = self.event_for_publish(event).await?;
        tracing::debug!(
            target: "transport_nostr_adapter::sdk_client",
            method = "publish_event",
            endpoint_count = parsed_endpoints.len(),
            "publishing SDK relay event"
        );
        let ack_goal = (required_acks > 0).then_some(required_acks);
        let message_id = cgka_traits::MessageId::new(event.id.to_bytes().to_vec());
        let mut accepted = Vec::new();
        let mut failed = Vec::new();
        let mut cleanup_endpoints = Vec::new();
        let mut publishes = JoinSet::new();
        for endpoint in parsed_endpoints {
            match self.retain_publish_relay(&endpoint).await {
                Ok(true) => cleanup_endpoints.push(endpoint.clone()),
                Ok(false) => {}
                Err(failure) => {
                    failed.push(failure);
                    continue;
                }
            }
            publishes.spawn(Self::publish_to_relay(
                self.client.clone(),
                endpoint,
                event.clone(),
            ));
        }

        // Drain completions, but bound the whole fan-out by an overall deadline
        // so a publish to unreachable (or under-acking) relays fails in bounded
        // time instead of waiting out every relay's full retry budget. Per-relay
        // early returns once `required_acks` is met are unaffected.
        let deadline = tokio::time::Instant::now() + SDK_RELAY_PUBLISH_OVERALL_WAIT;
        let mut aborted_publishes = false;
        let mut timed_out = false;
        let result = loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                publishes.abort_all();
                aborted_publishes = true;
                timed_out = true;
                break Self::finish_publish_outcome(
                    message_id,
                    accepted,
                    failed,
                    required_acks,
                    timed_out,
                );
            }
            match timeout(remaining, publishes.join_next()).await {
                Err(_elapsed) => {
                    publishes.abort_all();
                    aborted_publishes = true;
                    timed_out = true;
                    break Self::finish_publish_outcome(
                        message_id,
                        accepted,
                        failed,
                        required_acks,
                        timed_out,
                    );
                }
                Ok(None) => {
                    break Self::finish_publish_outcome(
                        message_id,
                        accepted,
                        failed,
                        required_acks,
                        timed_out,
                    );
                }
                Ok(Some(result)) => match result {
                    Ok(Ok(receipt)) => {
                        accepted.push(receipt);
                        if ack_goal.is_some_and(|goal| accepted.len() >= goal) {
                            publishes.abort_all();
                            aborted_publishes = true;
                            break Ok(NostrPublishOutcome {
                                message_id: Some(message_id),
                                accepted,
                                failed,
                            });
                        }
                    }
                    Ok(Err(failure)) => failed.push(failure),
                    Err(e) => {
                        publishes.abort_all();
                        aborted_publishes = true;
                        break Err(TransportAdapterError::Publish(format!(
                            "publish task failed: {e}"
                        )));
                    }
                },
            }
        };

        if aborted_publishes {
            while publishes.join_next().await.is_some() {}
        }
        self.cleanup_publish_relays(cleanup_endpoints).await;
        result
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
            RelayUrl::parse(endpoint.as_str()).map_err(|e| {
                TransportAdapterError::Subscription(format!(
                    "{context}: invalid endpoint {endpoint}: {e}"
                ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NostrKeyPackagePublication;
    use cgka_traits::Timestamp;
    use cgka_traits::engine::KeyPackage;
    use nostr_relay_builder::MockRelay;
    use nostr_sdk::prelude::Keys;
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
        assert_eq!(sdk.relay_health().await.total_relays, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn publish_event_cleans_one_shot_relay_after_overall_timeout() {
        let silent = TransportEndpoint(silent_relay_url().await);
        let keys = Keys::generate();
        let client = Client::builder().signer(keys).build();
        let sdk = NostrSdkRelayClient::new(client);
        // kind-445 events must arrive pre-signed by a fresh ephemeral key; the
        // publish path rejects unsigned 445s (spec/transports/nostr.md:64-66).
        let dto = signed_group_event_dto();

        let err = sdk
            .publish_event(std::slice::from_ref(&silent), &dto, 1)
            .await
            .expect_err("silent relay should miss the required ack deadline");

        assert!(err.to_string().contains("publish timed out"));
        assert_eq!(sdk.relay_health().await.total_relays, 0);
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

        assert!(err.to_string().contains("invalid endpoint"));
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
}
