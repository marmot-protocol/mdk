use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::{
    MemberId, TransportAdapterError, TransportEndpoint, TransportEndpointFailure,
    TransportEndpointReceipt,
};
use nostr_sdk::prelude::{
    Alphabet, Client, Event, EventBuilder, Filter, Kind, PublicKey, RelayPoolNotification,
    RelayStatus, RelayUrl, SingleLetterTag, SubscriptionId, Tag, TagKind,
    Timestamp as NostrTimestamp,
};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use transport_nostr_peeler::NostrTransportEvent;

use crate::{
    NostrPublishOutcome, NostrRelayClient, NostrRelayEvent, NostrSubscription,
    NostrTransportAdapter,
};

const SDK_RELAY_CONNECT_WAIT: Duration = Duration::from_secs(5);
const SDK_RELAY_PUBLISH_WAIT: Duration = Duration::from_secs(5);
/// Publishing to relays is best-effort over a flaky network: retry the send a
/// few times (with a short backoff) before giving up, so a single slow relay
/// doesn't fail the whole publish.
const SDK_RELAY_PUBLISH_ATTEMPTS: usize = 3;
const SDK_RELAY_PUBLISH_RETRY_BACKOFF: Duration = Duration::from_millis(600);

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
}

impl NostrSdkRelayClient {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            account_subscriptions: Arc::new(RwLock::new(HashMap::new())),
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
            self.client
                .add_relay(endpoint.clone())
                .await
                .map_err(|e| TransportAdapterError::Subscription(format!("add relay: {e}")))?;
            timeout(
                SDK_RELAY_CONNECT_WAIT,
                self.client.connect_relay(endpoint.clone()),
            )
            .await
            .map_err(|_| TransportAdapterError::Subscription("connect relay timed out".to_owned()))?
            .map_err(|e| TransportAdapterError::Subscription(format!("connect relay: {e}")))?;
        }
        self.client
            .subscribe_with_id_to(
                plan.endpoints.clone(),
                plan.subscription_id.clone(),
                plan.filter,
                None,
            )
            .await
            .map_err(|e| TransportAdapterError::Subscription(format!("subscribe: {e}")))?;

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
        _required_acks: usize,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        let parsed_endpoints = parse_endpoints(endpoints, "publish")?;
        let event = self.event_for_publish(event).await?;
        tracing::debug!(
            target: "transport_nostr_adapter::sdk_client",
            method = "publish_event",
            endpoint_count = parsed_endpoints.len(),
            "publishing SDK relay event"
        );
        for endpoint in &parsed_endpoints {
            self.client
                .add_relay(endpoint.clone())
                .await
                .map_err(|e| TransportAdapterError::Publish(format!("add relay: {e}")))?;
            timeout(
                SDK_RELAY_CONNECT_WAIT,
                self.client.connect_relay(endpoint.clone()),
            )
            .await
            .map_err(|_| TransportAdapterError::Publish("connect relay timed out".to_owned()))?
            .map_err(|e| TransportAdapterError::Publish(format!("connect relay: {e}")))?;
        }
        let mut last_error: Option<TransportAdapterError> = None;
        let mut send_output = None;
        for attempt in 1..=SDK_RELAY_PUBLISH_ATTEMPTS {
            match timeout(
                SDK_RELAY_PUBLISH_WAIT,
                self.client.send_event_to(parsed_endpoints.clone(), &event),
            )
            .await
            {
                Ok(Ok(output)) => {
                    send_output = Some(output);
                    break;
                }
                Ok(Err(e)) => {
                    last_error = Some(TransportAdapterError::Publish(format!("send event: {e}")));
                }
                Err(_) => {
                    last_error = Some(TransportAdapterError::Publish(
                        "send event timed out".to_owned(),
                    ));
                }
            }
            if attempt < SDK_RELAY_PUBLISH_ATTEMPTS {
                tokio::time::sleep(SDK_RELAY_PUBLISH_RETRY_BACKOFF).await;
            }
        }
        let output = send_output.ok_or_else(|| {
            last_error
                .unwrap_or_else(|| TransportAdapterError::Publish("send event failed".to_owned()))
        })?;

        Ok(NostrPublishOutcome {
            message_id: Some(cgka_traits::MessageId::new(event.id.to_bytes().to_vec())),
            accepted: output
                .success
                .into_iter()
                .map(|endpoint| TransportEndpointReceipt {
                    endpoint: TransportEndpoint(endpoint.to_string()),
                    accepted_at: None,
                })
                .collect(),
            failed: output
                .failed
                .into_iter()
                .map(|(endpoint, reason)| TransportEndpointFailure {
                    endpoint: TransportEndpoint(endpoint.to_string()),
                    reason,
                })
                .collect(),
        })
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
    use nostr_sdk::prelude::Keys;
    use transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE;

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
    async fn unsigned_group_event_is_signed_before_publish() {
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

        let event = sdk.event_for_publish(&dto).await.expect("event");

        event.verify().expect("signed event verifies");
        assert_eq!(event.pubkey, keys.public_key());
        assert_eq!(event.kind, Kind::MlsGroupMessage);
        assert_eq!(event.content, dto.content);
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
}
