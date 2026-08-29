use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::TransportEndpoint;
use nostr_sdk::prelude::{
    Client as NostrSdkClient, Event, Filter, Kind, PublicKey, RelayMessage, RelayPoolNotification,
    RelayUrl, SubscriptionId,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep, timeout};
use transport_nostr_peeler::NostrTransportEvent;

use super::DIRECTORY_RELAY_CONNECT_WAIT;

const DIRECTORY_RELAY_FETCH_WAIT: Duration = Duration::from_secs(3);
const STRICT_DIRECTORY_RELAY_FETCH_INACTIVITY_WAIT: Duration = Duration::from_secs(3);
const STRICT_DIRECTORY_RELAY_FETCH_OVERALL_WAIT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectoryRelayConnectOutcome {
    Connected,
    TimedOut,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DirectoryEventQuery {
    pub(crate) kind: u64,
    pub(crate) authors: Vec<String>,
    pub(crate) limit: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DirectoryRelayEventRecord {
    pub(crate) endpoints: Vec<TransportEndpoint>,
    pub(crate) event: NostrTransportEvent,
}

/// The `(authors, kinds)` an active directory subscription was issued with.
///
/// A live SDK relay event is only forwarded into the directory cache when its
/// `subscription_id` is still active and its author/kind match the filter that
/// subscription was created with. This prevents a malicious or buggy relay from
/// injecting unsolicited directory-shaped events (e.g. arbitrary kind-3 contact
/// lists) into the persistent directory search graph (mdk#709). Authors
/// and kinds are kept as the canonical hex / `u64` already present in the
/// [`DirectorySyncBatch`], so matching is a plain membership check.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DirectorySubscriptionFilter {
    authors: HashSet<String>,
    kinds: HashSet<u64>,
}

impl DirectorySubscriptionFilter {
    pub(crate) fn new(authors: Vec<String>, kinds: Vec<u64>) -> Self {
        Self {
            authors: authors.into_iter().collect(),
            kinds: kinds.into_iter().collect(),
        }
    }

    fn accepts(&self, author: &str, kind: u64) -> bool {
        self.authors.contains(author) && self.kinds.contains(&kind)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DirectoryFetchRequest {
    pub(crate) endpoints: Vec<TransportEndpoint>,
    pub(crate) queries: Vec<DirectoryEventQuery>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct DirectoryFetchKey {
    endpoints: Vec<TransportEndpoint>,
    queries: Vec<DirectoryEventQuery>,
}

#[derive(Clone)]
pub(crate) struct DirectoryRelayPlane {
    fetcher: Arc<dyn DirectoryRelayFetcher>,
    state: Arc<Mutex<DirectoryRelayPlaneState>>,
}

#[derive(Default)]
struct DirectoryRelayPlaneState {
    inflight: HashMap<DirectoryFetchKey, Vec<oneshot::Sender<DirectoryFetchResult>>>,
    active_subscriptions: HashMap<String, DirectorySubscriptionFilter>,
    completed_fetches: usize,
    coalesced_waiters: usize,
    failed_fetches: usize,
    completed_subscription_syncs: usize,
    subscriptions_created: usize,
    subscriptions_removed: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DirectoryRelayStats {
    pub(crate) inflight_fetches: usize,
    pub(crate) active_subscriptions: usize,
    pub(crate) completed_fetches: usize,
    pub(crate) coalesced_waiters: usize,
    pub(crate) failed_fetches: usize,
    pub(crate) completed_subscription_syncs: usize,
    pub(crate) subscriptions_created: usize,
    pub(crate) subscriptions_removed: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DirectorySubscriptionSyncSummary {
    pub(crate) active_subscriptions: usize,
    pub(crate) subscriptions_created: usize,
    pub(crate) subscriptions_removed: usize,
}

type DirectoryFetchResult = Result<Vec<DirectoryRelayEventRecord>, String>;

#[async_trait]
pub(crate) trait DirectoryRelayFetcher: Send + Sync {
    async fn fetch_directory_events(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String>;

    /// Fetch stored events only when every subscribed relay explicitly reports
    /// EOSE. Privacy cutover scans must not interpret SDK silence or an overall
    /// request timeout as a complete empty/short result.
    async fn fetch_directory_events_strict(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        #[cfg(test)]
        {
            // Unit-test fetchers model a complete finite response unless they
            // override this method with an explicit incomplete script.
            self.fetch_directory_events(request).await
        }
        #[cfg(not(test))]
        {
            let _ = request;
            Err("strict directory fetch completion is unsupported".to_owned())
        }
    }
}

#[derive(Clone)]
pub(crate) struct NostrSdkDirectoryRelayFetcher {
    client: NostrSdkClient,
}

impl DirectoryEventQuery {
    pub(crate) fn new(kind: u64, mut authors: Vec<String>, limit: usize) -> Self {
        authors.sort();
        authors.dedup();
        Self {
            kind,
            authors,
            limit,
        }
    }
}

impl DirectoryFetchRequest {
    pub(crate) fn new(
        mut endpoints: Vec<TransportEndpoint>,
        mut queries: Vec<DirectoryEventQuery>,
    ) -> Result<Self, String> {
        endpoints.sort();
        endpoints.dedup();
        queries.sort();
        queries.dedup();
        if endpoints.is_empty() {
            return Err("directory fetch: no relay endpoints".to_owned());
        }
        if queries.is_empty() {
            return Err("directory fetch: no queries".to_owned());
        }
        for query in &queries {
            if query.authors.is_empty() {
                return Err("directory fetch: no query authors".to_owned());
            }
            if query.limit == 0 {
                return Err("directory fetch: query limit must be greater than zero".to_owned());
            }
        }
        Ok(Self { endpoints, queries })
    }

    fn key(&self) -> DirectoryFetchKey {
        DirectoryFetchKey {
            endpoints: self.endpoints.clone(),
            queries: self.queries.clone(),
        }
    }
}

impl DirectoryRelayPlane {
    pub(crate) fn new(fetcher: Arc<dyn DirectoryRelayFetcher>) -> Self {
        Self {
            fetcher,
            state: Arc::new(Mutex::new(DirectoryRelayPlaneState::default())),
        }
    }

    pub(crate) async fn fetch_events(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        let key = request.key();
        let (rx, should_spawn) = {
            let (tx, rx) = oneshot::channel();
            let mut state = self.state.lock().await;
            if let Some(waiters) = state.inflight.get_mut(&key) {
                waiters.push(tx);
                state.coalesced_waiters += 1;
                (rx, false)
            } else {
                state.inflight.insert(key.clone(), vec![tx]);
                (rx, true)
            }
        };

        if should_spawn {
            let fetcher = self.fetcher.clone();
            let state = self.state.clone();
            tokio::spawn(async move {
                // Keep ownership of the inflight entry in this supervisor.
                // The child JoinHandle converts a fetcher panic into an error,
                // so cleanup and waiter notification still run.
                let result = match tokio::spawn(async move {
                    fetcher.fetch_directory_events(request).await
                })
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err("directory fetch task failed".to_owned()),
                };
                let mut state = state.lock().await;
                if result.is_ok() {
                    state.completed_fetches += 1;
                } else {
                    state.failed_fetches += 1;
                }
                if let Some(waiters) = state.inflight.remove(&key) {
                    for waiter in waiters {
                        let _ = waiter.send(result.clone());
                    }
                }
            });
        }

        rx.await
            .map_err(|_| "directory fetch owner dropped before completing".to_owned())?
    }

    /// Run a completion-sensitive fetch outside the ordinary coalescing map.
    /// A strict cutover caller must receive this invocation's own EOSE proof;
    /// sharing an in-flight ordinary fetch would erase that distinction.
    pub(crate) async fn fetch_events_strict(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        let (tx, rx) = oneshot::channel();
        let fetcher = self.fetcher.clone();
        let state = self.state.clone();
        tokio::spawn(async move {
            // The supervisor outlives caller cancellation, so the strict
            // fetcher can unsubscribe and the health counters still record its
            // eventual outcome. The inner task turns a fetcher panic into the
            // same explicit failure shape as ordinary directory fetches.
            let result =
                match tokio::spawn(
                    async move { fetcher.fetch_directory_events_strict(request).await },
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err("strict directory fetch task failed".to_owned()),
                };
            let mut state = state.lock().await;
            if result.is_ok() {
                state.completed_fetches += 1;
            } else {
                state.failed_fetches += 1;
            }
            let _ = tx.send(result);
        });

        rx.await
            .map_err(|_| "strict directory fetch owner dropped before completing".to_owned())?
    }

    pub(crate) async fn stats(&self) -> DirectoryRelayStats {
        let state = self.state.lock().await;
        DirectoryRelayStats {
            inflight_fetches: state.inflight.len(),
            active_subscriptions: state.active_subscriptions.len(),
            completed_fetches: state.completed_fetches,
            coalesced_waiters: state.coalesced_waiters,
            failed_fetches: state.failed_fetches,
            completed_subscription_syncs: state.completed_subscription_syncs,
            subscriptions_created: state.subscriptions_created,
            subscriptions_removed: state.subscriptions_removed,
        }
    }

    pub(crate) async fn subscription_diff(
        &self,
        desired_ids: &HashSet<String>,
    ) -> (HashSet<String>, HashSet<String>) {
        let state = self.state.lock().await;
        let active_ids = state
            .active_subscriptions
            .keys()
            .cloned()
            .collect::<HashSet<_>>();
        let to_add = desired_ids
            .difference(&active_ids)
            .cloned()
            .collect::<HashSet<_>>();
        let to_remove = active_ids
            .difference(desired_ids)
            .cloned()
            .collect::<HashSet<_>>();
        (to_add, to_remove)
    }

    /// Replace the active directory subscriptions with the supplied
    /// `(subscription_id, filter)` plan, returning the lifecycle summary.
    ///
    /// The filters are what [`Self::accepts_live_event`] later checks live SDK
    /// notifications against, so a subscription that is no longer in the plan
    /// can no longer admit events into the directory cache.
    pub(crate) async fn replace_subscriptions(
        &self,
        desired: HashMap<String, DirectorySubscriptionFilter>,
    ) -> Result<DirectorySubscriptionSyncSummary, String> {
        let mut state = self.state.lock().await;
        let created = desired
            .keys()
            .filter(|id| !state.active_subscriptions.contains_key(*id))
            .count();
        let removed = state
            .active_subscriptions
            .keys()
            .filter(|id| !desired.contains_key(*id))
            .count();
        state.completed_subscription_syncs += 1;
        state.subscriptions_created += created;
        state.subscriptions_removed += removed;
        state.active_subscriptions = desired;
        Ok(DirectorySubscriptionSyncSummary {
            active_subscriptions: state.active_subscriptions.len(),
            subscriptions_created: created,
            subscriptions_removed: removed,
        })
    }

    /// Decide whether a live SDK relay event may be forwarded into the
    /// directory cache.
    ///
    /// Only events whose `subscription_id` is still an active directory
    /// subscription, and whose author and kind match that subscription's
    /// issued filter, are accepted. An unknown/stale subscription id, an author
    /// the subscription never requested, or a kind outside its filter is
    /// rejected so a malicious or buggy relay cannot inject unsolicited
    /// directory-shaped events into the persistent search graph
    /// (mdk#709).
    pub(crate) async fn accepts_live_event(
        &self,
        subscription_id: &str,
        author: &str,
        kind: u64,
    ) -> bool {
        let state = self.state.lock().await;
        state
            .active_subscriptions
            .get(subscription_id)
            .is_some_and(|filter| filter.accepts(author, kind))
    }
}

impl NostrSdkDirectoryRelayFetcher {
    pub(crate) fn new(client: NostrSdkClient) -> Self {
        Self { client }
    }

    pub(crate) fn standalone() -> Self {
        Self::new(NostrSdkClient::builder().build())
    }

    async fn connected_relay_urls(
        &self,
        endpoints: &[TransportEndpoint],
        require_all: bool,
    ) -> Result<Vec<RelayUrl>, String> {
        let relay_urls = parsed_directory_relay_urls(endpoints)?;
        let requested_relay_count = relay_urls.len();
        let mut connect_candidates = Vec::new();
        let mut newly_added = vec![false; relay_urls.len()];
        let mut add_failure_count = 0usize;
        for (index, relay_url) in relay_urls.iter().cloned().enumerate() {
            match self.client.add_relay(relay_url.clone()).await {
                Ok(added) => {
                    newly_added[index] = added;
                    connect_candidates.push((index, relay_url));
                }
                Err(_) => add_failure_count += 1,
            }
        }
        let mut connects = JoinSet::new();
        for (index, relay_url) in connect_candidates {
            let client = self.client.clone();
            connects.spawn(async move {
                let outcome = match timeout(
                    DIRECTORY_RELAY_CONNECT_WAIT,
                    client.connect_relay(relay_url),
                )
                .await
                {
                    Ok(Ok(())) => DirectoryRelayConnectOutcome::Connected,
                    Ok(Err(_)) => DirectoryRelayConnectOutcome::Failed,
                    Err(_) => DirectoryRelayConnectOutcome::TimedOut,
                };
                (index, outcome)
            });
        }
        let mut connected = vec![false; relay_urls.len()];
        let mut connect_timeout_count = 0usize;
        let mut connect_failure_count = 0usize;
        let mut task_failure_count = 0usize;
        while let Some(result) = connects.join_next().await {
            match result {
                Ok((index, DirectoryRelayConnectOutcome::Connected)) => connected[index] = true,
                Ok((_index, DirectoryRelayConnectOutcome::TimedOut)) => {
                    connect_timeout_count += 1;
                }
                Ok((_index, DirectoryRelayConnectOutcome::Failed)) => {
                    connect_failure_count += 1;
                }
                Err(_) => task_failure_count += 1,
            }
        }
        for (index, relay_url) in relay_urls.iter().cloned().enumerate() {
            // Never remove a pre-existing relay owned by another subscription
            // merely because this fetch's connection attempt failed. Only a
            // relay inserted by this invocation is ours to clean up.
            if newly_added[index] && !connected[index] {
                let _ = self.client.remove_relay(relay_url).await;
            }
        }
        let relay_urls = relay_urls
            .into_iter()
            .zip(connected)
            .filter_map(|(relay_url, connected)| connected.then_some(relay_url))
            .collect::<Vec<_>>();
        if relay_urls.is_empty() {
            return Err(format!(
                "connect relays failed: add_failures={add_failure_count}, connect_timeouts={connect_timeout_count}, connect_failures={connect_failure_count}, task_failures={task_failure_count}"
            ));
        }
        if require_all && relay_urls.len() != requested_relay_count {
            return Err(format!(
                "strict directory connect completed on {} of {requested_relay_count} relays: add_failures={add_failure_count}, connect_timeouts={connect_timeout_count}, connect_failures={connect_failure_count}, task_failures={task_failure_count}",
                relay_urls.len()
            ));
        }
        Ok(relay_urls)
    }
}

fn validated_directory_event(
    event: &Event,
    query: &DirectoryEventQuery,
) -> Option<NostrTransportEvent> {
    if event.verify().is_err()
        || u64::from(event.kind.as_u16()) != query.kind
        || !query
            .authors
            .iter()
            .any(|author| author == &event.pubkey.to_hex())
    {
        return None;
    }
    NostrTransportEvent::from_nostr_event(event).ok()
}

async fn collect_strict_directory_query(
    mut notifications: tokio::sync::broadcast::Receiver<RelayPoolNotification>,
    request_id: &SubscriptionId,
    expected_relays: &HashSet<RelayUrl>,
    query: &DirectoryEventQuery,
    inactivity_wait: Duration,
    overall_wait: Duration,
) -> Result<Vec<DirectoryRelayEventRecord>, String> {
    let mut completed_relays = HashSet::new();
    let mut pre_eose_delivery_counts = HashMap::<RelayUrl, usize>::new();
    let mut accepted_event_ids = HashMap::<RelayUrl, HashSet<String>>::new();
    let mut records = Vec::new();
    let mut inactivity = Box::pin(sleep(inactivity_wait));
    let mut overall = Box::pin(sleep(overall_wait));
    loop {
        let relevant_activity = tokio::select! {
            // A constantly active relay that never sends EOSE must not keep a
            // completion-sensitive fetch alive forever. Check the absolute
            // bound before the resettable inactivity timer and notifications
            // when multiple branches become ready together.
            biased;
            _ = &mut overall => {
                return Err(
                    "strict directory fetch exceeded its overall deadline before EOSE".to_owned()
                );
            }
            _ = &mut inactivity => {
                return Err("strict directory fetch inactive before EOSE".to_owned());
            }
            notification = notifications.recv() => {
                match notification {
                Ok(RelayPoolNotification::Message {
                    relay_url,
                    message:
                        RelayMessage::Event {
                            subscription_id,
                            event,
                        },
                }) if subscription_id.as_ref() == request_id
                    && expected_relays.contains(&relay_url) =>
                {
                    // EOSE terminates the stored-event page for this relay.
                    // Live events received afterward belong to a different
                    // semantic window and must neither consume another relay's
                    // bounded result capacity nor extend its inactivity window.
                    if completed_relays.contains(&relay_url) {
                        false
                    } else {
                        // Any event delivered under this exact subscription is
                        // relevant relay activity and consumes one result-page
                        // position, including duplicate or malformed events.
                        // Reaching the requested limit is inconclusive: the
                        // relay may have more stored events, so a privacy
                        // cutover must remain gated rather than treating a
                        // deduplicated short result as complete.
                        let delivery_count = pre_eose_delivery_counts
                            .entry(relay_url.clone())
                            .or_default();
                        *delivery_count = delivery_count.saturating_add(1);
                        let event = validated_directory_event(event.as_ref(), query).ok_or_else(|| {
                            "strict directory exact subscription delivered an invalid or unrelated event"
                                .to_owned()
                        })?;
                        if *delivery_count >= query.limit {
                            return Err(
                                "strict directory fetch reached its bounded query capacity before EOSE"
                                    .to_owned(),
                            );
                        }
                        let relay_event_ids =
                            accepted_event_ids.entry(relay_url.clone()).or_default();
                        if relay_event_ids.insert(event.id.clone()) {
                            records.push(DirectoryRelayEventRecord {
                                endpoints: vec![TransportEndpoint(relay_url.to_string())],
                                event,
                            });
                        }
                        true
                    }
                }
                Ok(RelayPoolNotification::Message {
                    relay_url,
                    message: RelayMessage::EndOfStoredEvents(subscription_id),
                }) if subscription_id.as_ref() == request_id
                    && expected_relays.contains(&relay_url) =>
                {
                    let newly_completed = completed_relays.insert(relay_url);
                    if completed_relays.len() == expected_relays.len() {
                        return Ok(records);
                    }
                    newly_completed
                }
                Ok(RelayPoolNotification::Message {
                    relay_url,
                    message:
                        RelayMessage::Closed {
                            subscription_id, ..
                        },
                }) if subscription_id.as_ref() == request_id
                    && expected_relays.contains(&relay_url) =>
                {
                    return Err("strict directory subscription closed before EOSE".to_owned());
                }
                Ok(RelayPoolNotification::Shutdown) => {
                    return Err("relay pool shut down before strict directory EOSE".to_owned());
                }
                Ok(_) => false,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    return Err(
                        "strict directory notification stream lagged before EOSE".to_owned()
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return Err("strict directory notification stream ended before EOSE".to_owned());
                }
                }
            }
        };
        if relevant_activity {
            inactivity.as_mut().reset(Instant::now() + inactivity_wait);
        }
    }
}

#[async_trait]
impl DirectoryRelayFetcher for NostrSdkDirectoryRelayFetcher {
    async fn fetch_directory_events(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        let relay_urls = self.connected_relay_urls(&request.endpoints, false).await?;

        let mut records = Vec::new();
        for query in request.queries {
            let kind = u16::try_from(query.kind)
                .map(Kind::from)
                .map_err(|_| format!("unsupported Nostr kind {}", query.kind))?;
            let public_keys = query
                .authors
                .iter()
                .map(|author| PublicKey::parse(author).map_err(|_| "invalid query author"))
                .collect::<Result<Vec<_>, _>>()?;
            let filter = Filter::new()
                .authors(public_keys)
                .kind(kind)
                .limit(query.limit);
            let events = self
                .client
                .fetch_events_from(relay_urls.clone(), filter, DIRECTORY_RELAY_FETCH_WAIT)
                .await
                .map_err(|_| "fetch directory events failed".to_owned())?;
            for event in events {
                let Some(event) = validated_directory_event(&event, &query) else {
                    continue;
                };
                records.push(DirectoryRelayEventRecord {
                    endpoints: request.endpoints.clone(),
                    event,
                });
            }
        }
        Ok(records)
    }

    async fn fetch_directory_events_strict(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        let relay_urls = self.connected_relay_urls(&request.endpoints, true).await?;
        let mut records = Vec::new();
        for query in request.queries {
            let kind = u16::try_from(query.kind)
                .map(Kind::from)
                .map_err(|_| format!("unsupported Nostr kind {}", query.kind))?;
            let public_keys = query
                .authors
                .iter()
                .map(|author| PublicKey::parse(author).map_err(|_| "invalid query author"))
                .collect::<Result<Vec<_>, _>>()?;
            let filter = Filter::new()
                .authors(public_keys)
                .kind(kind)
                .limit(query.limit);
            let request_id = SubscriptionId::generate();
            // Subscribe the receiver first: a fast relay may return its event
            // and EOSE before subscribe_with_id_to finishes registering every
            // target, and broadcast retains those notifications for us.
            let notifications = self.client.notifications();
            let output = match self
                .client
                .subscribe_with_id_to(relay_urls.clone(), request_id.clone(), filter, None)
                .await
            {
                Ok(output) => output,
                Err(_) => {
                    self.client.unsubscribe(&request_id).await;
                    return Err("strict directory subscribe failed".to_owned());
                }
            };
            if output.success.len() != relay_urls.len() || !output.failed.is_empty() {
                self.client.unsubscribe(&request_id).await;
                return Err(format!(
                    "strict directory subscribe registered on {} of {} relays with {} failures",
                    output.success.len(),
                    relay_urls.len(),
                    output.failed.len()
                ));
            }
            let expected_relays = output.success;
            let completion = collect_strict_directory_query(
                notifications,
                &request_id,
                &expected_relays,
                &query,
                STRICT_DIRECTORY_RELAY_FETCH_INACTIVITY_WAIT,
                STRICT_DIRECTORY_RELAY_FETCH_OVERALL_WAIT,
            )
            .await;
            self.client.unsubscribe(&request_id).await;
            records.extend(completion?);
        }
        Ok(records)
    }
}

fn parsed_directory_relay_urls(endpoints: &[TransportEndpoint]) -> Result<Vec<RelayUrl>, String> {
    let mut relay_urls = endpoints
        .iter()
        .map(|endpoint| {
            RelayUrl::parse(endpoint.as_str()).map_err(|_| "invalid relay URL".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    // RelayUrl equality canonicalizes trailing slashes even though its display
    // form preserves them. Collapse equivalent candidates before concurrent
    // connection attempts so one failed twin cannot remove a successful one.
    relay_urls.sort();
    relay_urls.dedup();
    Ok(relay_urls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_event_validation_rejects_invalid_signatures_and_wrong_authors() {
        use nostr_sdk::prelude::{Event, EventBuilder, JsonUtil, Keys};

        let expected = Keys::generate();
        let wrong = Keys::generate();
        let query = DirectoryEventQuery::new(0, vec![expected.public_key().to_hex()], 1);
        let valid = EventBuilder::new(Kind::Metadata, r#"{"name":"agent"}"#)
            .sign_with_keys(&expected)
            .unwrap();
        assert!(validated_directory_event(&valid, &query).is_some());

        let wrong_author = EventBuilder::new(Kind::Metadata, r#"{"name":"other"}"#)
            .sign_with_keys(&wrong)
            .unwrap();
        assert!(validated_directory_event(&wrong_author, &query).is_none());

        let mut tampered = serde_json::to_value(&valid).unwrap();
        tampered["content"] = serde_json::Value::String(r#"{"name":"tampered"}"#.to_owned());
        let tampered = Event::from_json(tampered.to_string()).unwrap();
        assert!(tampered.verify().is_err());
        assert!(validated_directory_event(&tampered, &query).is_none());
    }

    #[tokio::test]
    async fn sdk_fetcher_errors_do_not_echo_invalid_relay_urls() {
        let secret_url = "not-a-relay-with-secret-token";
        let request = DirectoryFetchRequest::new(
            vec![TransportEndpoint(secret_url.to_owned())],
            vec![DirectoryEventQuery::new(0, vec!["11".repeat(32)], 1)],
        )
        .unwrap();

        let error = NostrSdkDirectoryRelayFetcher::standalone()
            .fetch_directory_events(request)
            .await
            .unwrap_err();

        assert_eq!(error, "invalid relay URL");
        assert!(!error.contains(secret_url));
    }

    #[tokio::test]
    async fn strict_sdk_fetcher_rejects_invalid_url_before_subscription() {
        let secret_url = "not-a-strict-relay-with-secret-token";
        let request = DirectoryFetchRequest::new(
            vec![TransportEndpoint(secret_url.to_owned())],
            vec![DirectoryEventQuery::new(0, vec!["11".repeat(32)], 1)],
        )
        .unwrap();

        let error = NostrSdkDirectoryRelayFetcher::standalone()
            .fetch_directory_events_strict(request)
            .await
            .unwrap_err();

        assert_eq!(error, "invalid relay URL");
        assert!(!error.contains(secret_url));
    }

    #[tokio::test]
    async fn strict_query_returns_only_pre_eose_per_relay_records() {
        use nostr_sdk::prelude::{EventBuilder, Keys};

        let alice = Keys::generate();
        let bob = Keys::generate();
        let alice_stored = EventBuilder::new(Kind::Metadata, r#"{"name":"alice-stored"}"#)
            .sign_with_keys(&alice)
            .unwrap();
        let alice_live = EventBuilder::new(Kind::Metadata, r#"{"name":"alice-live"}"#)
            .sign_with_keys(&alice)
            .unwrap();
        let bob_stored = EventBuilder::new(Kind::Metadata, r#"{"name":"bob-stored"}"#)
            .sign_with_keys(&bob)
            .unwrap();
        let query = DirectoryEventQuery::new(
            0,
            vec![alice.public_key().to_hex(), bob.public_key().to_hex()],
            2,
        );
        let relay_a = RelayUrl::parse("wss://a.relay.example").unwrap();
        let relay_b = RelayUrl::parse("wss://b.relay.example").unwrap();
        let expected_relays = HashSet::from([relay_a.clone(), relay_b.clone()]);
        let request_id = SubscriptionId::generate();
        let unrelated_id = SubscriptionId::generate();
        let (sender, receiver) = tokio::sync::broadcast::channel(16);
        let send = |relay_url: RelayUrl, message: RelayMessage<'static>| {
            sender
                .send(RelayPoolNotification::Message { relay_url, message })
                .unwrap();
        };

        send(
            relay_a.clone(),
            RelayMessage::event(unrelated_id, alice_live.clone()),
        );
        send(
            relay_a.clone(),
            RelayMessage::event(request_id.clone(), alice_stored.clone()),
        );
        send(relay_a.clone(), RelayMessage::eose(request_id.clone()));
        // This is a live event, not part of relay A's finite stored page.
        send(relay_a, RelayMessage::event(request_id.clone(), alice_live));
        send(
            relay_b.clone(),
            RelayMessage::event(request_id.clone(), bob_stored.clone()),
        );
        send(relay_b, RelayMessage::eose(request_id.clone()));

        let records = collect_strict_directory_query(
            receiver,
            &request_id,
            &expected_relays,
            &query,
            Duration::from_secs(1),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].event.id, alice_stored.id.to_hex());
        assert_eq!(records[1].event.id, bob_stored.id.to_hex());
        assert_ne!(records[0].endpoints, records[1].endpoints);
    }

    #[tokio::test]
    async fn strict_query_allows_slow_progress_beyond_one_inactivity_window() {
        use nostr_sdk::prelude::{EventBuilder, Keys};

        let author = Keys::generate();
        let first = EventBuilder::new(Kind::Metadata, r#"{"name":"first"}"#)
            .sign_with_keys(&author)
            .unwrap();
        let second = EventBuilder::new(Kind::Metadata, r#"{"name":"second"}"#)
            .sign_with_keys(&author)
            .unwrap();
        let query = DirectoryEventQuery::new(0, vec![author.public_key().to_hex()], 3);
        let relay = RelayUrl::parse("wss://slow.relay.example").unwrap();
        let expected_relays = HashSet::from([relay.clone()]);
        let request_id = SubscriptionId::generate();
        let (sender, receiver) = tokio::sync::broadcast::channel(8);
        let producer_request_id = request_id.clone();
        let producer_relay = relay.clone();
        let first_for_producer = first.clone();
        let second_for_producer = second.clone();
        let producer = tokio::spawn(async move {
            for event in [first_for_producer, second_for_producer] {
                sleep(Duration::from_millis(75)).await;
                sender
                    .send(RelayPoolNotification::Message {
                        relay_url: producer_relay.clone(),
                        message: RelayMessage::event(producer_request_id.clone(), event),
                    })
                    .expect("strict query receiver remains active");
            }
            sleep(Duration::from_millis(75)).await;
            sender
                .send(RelayPoolNotification::Message {
                    relay_url: producer_relay,
                    message: RelayMessage::eose(producer_request_id),
                })
                .expect("strict query receiver remains active");
        });
        let inactivity_wait = Duration::from_millis(200);
        let started_at = Instant::now();

        let records = collect_strict_directory_query(
            receiver,
            &request_id,
            &expected_relays,
            &query,
            inactivity_wait,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        producer.await.unwrap();

        assert!(
            started_at.elapsed() > inactivity_wait,
            "incremental relay activity must let a finite page outlive one idle interval"
        );
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].event.id, first.id.to_hex());
        assert_eq!(records[1].event.id, second.id.to_hex());
    }

    #[tokio::test]
    async fn strict_query_rejects_invalid_or_unrelated_exact_subscription_events() {
        use nostr_sdk::prelude::{Event, EventBuilder, JsonUtil, Keys};

        let expected = Keys::generate();
        let unexpected = Keys::generate();
        let valid = EventBuilder::new(Kind::Metadata, r#"{"name":"valid"}"#)
            .sign_with_keys(&expected)
            .unwrap();
        let wrong_author = EventBuilder::new(Kind::Metadata, r#"{"name":"wrong-author"}"#)
            .sign_with_keys(&unexpected)
            .unwrap();
        let wrong_kind = EventBuilder::new(Kind::from(3_u16), String::new())
            .sign_with_keys(&expected)
            .unwrap();
        let mut tampered = serde_json::to_value(&valid).unwrap();
        tampered["content"] = serde_json::Value::String(r#"{"name":"tampered"}"#.to_owned());
        let invalid_signature = Event::from_json(tampered.to_string()).unwrap();
        let query = DirectoryEventQuery::new(0, vec![expected.public_key().to_hex()], 4);
        let relay = RelayUrl::parse("wss://strict-validation.relay.example").unwrap();
        let expected_relays = HashSet::from([relay.clone()]);

        for event in [wrong_author, wrong_kind, invalid_signature] {
            let request_id = SubscriptionId::generate();
            let (sender, receiver) = tokio::sync::broadcast::channel(4);
            sender
                .send(RelayPoolNotification::Message {
                    relay_url: relay.clone(),
                    message: RelayMessage::event(request_id.clone(), event),
                })
                .unwrap();
            sender
                .send(RelayPoolNotification::Message {
                    relay_url: relay.clone(),
                    message: RelayMessage::eose(request_id.clone()),
                })
                .unwrap();

            let error = collect_strict_directory_query(
                receiver,
                &request_id,
                &expected_relays,
                &query,
                Duration::from_secs(1),
                Duration::from_secs(2),
            )
            .await
            .unwrap_err();

            assert_eq!(
                error,
                "strict directory exact subscription delivered an invalid or unrelated event"
            );
        }
    }

    #[tokio::test]
    async fn strict_query_counts_duplicate_deliveries_toward_capacity() {
        use nostr_sdk::prelude::{EventBuilder, Keys};

        let author = Keys::generate();
        let event = EventBuilder::new(Kind::Metadata, r#"{"name":"duplicate"}"#)
            .sign_with_keys(&author)
            .unwrap();
        let query = DirectoryEventQuery::new(0, vec![author.public_key().to_hex()], 2);
        let relay = RelayUrl::parse("wss://strict-capacity.relay.example").unwrap();
        let expected_relays = HashSet::from([relay.clone()]);
        let request_id = SubscriptionId::generate();
        let (sender, receiver) = tokio::sync::broadcast::channel(4);
        for delivered in [event.clone(), event] {
            sender
                .send(RelayPoolNotification::Message {
                    relay_url: relay.clone(),
                    message: RelayMessage::event(request_id.clone(), delivered),
                })
                .unwrap();
        }
        sender
            .send(RelayPoolNotification::Message {
                relay_url: relay,
                message: RelayMessage::eose(request_id.clone()),
            })
            .unwrap();

        let error = collect_strict_directory_query(
            receiver,
            &request_id,
            &expected_relays,
            &query,
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();

        assert_eq!(
            error,
            "strict directory fetch reached its bounded query capacity before EOSE"
        );
    }

    #[tokio::test]
    async fn strict_query_reports_closed_stream_and_inactivity_before_all_eose() {
        let relay_a = RelayUrl::parse("wss://a.relay.example").unwrap();
        let relay_b = RelayUrl::parse("wss://b.relay.example").unwrap();
        let expected_relays = HashSet::from([relay_a.clone(), relay_b.clone()]);
        let query = DirectoryEventQuery::new(0, vec!["11".repeat(32)], 1);
        let request_id = SubscriptionId::generate();
        let (sender, receiver) = tokio::sync::broadcast::channel(4);
        sender
            .send(RelayPoolNotification::Message {
                relay_url: relay_a,
                message: RelayMessage::eose(request_id.clone()),
            })
            .unwrap();
        sender
            .send(RelayPoolNotification::Message {
                relay_url: relay_b,
                message: RelayMessage::closed(request_id.clone(), "closed by relay"),
            })
            .unwrap();

        let error = collect_strict_directory_query(
            receiver,
            &request_id,
            &expected_relays,
            &query,
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert_eq!(error, "strict directory subscription closed before EOSE");

        let (_sender, receiver) = tokio::sync::broadcast::channel(1);
        let error = collect_strict_directory_query(
            receiver,
            &request_id,
            &expected_relays,
            &query,
            Duration::from_millis(10),
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert_eq!(error, "strict directory fetch inactive before EOSE");
    }

    #[tokio::test]
    async fn strict_query_overall_deadline_bounds_progress_without_eose() {
        use nostr_sdk::prelude::{EventBuilder, Keys};

        let author = Keys::generate();
        let events = (0..16)
            .map(|index| {
                EventBuilder::new(Kind::Metadata, format!(r#"{{"index":{index}}}"#))
                    .sign_with_keys(&author)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let query = DirectoryEventQuery::new(0, vec![author.public_key().to_hex()], events.len());
        let relay = RelayUrl::parse("wss://active-without-eose.relay.example").unwrap();
        let expected_relays = HashSet::from([relay.clone()]);
        let request_id = SubscriptionId::generate();
        let (sender, receiver) = tokio::sync::broadcast::channel(32);
        let producer_request_id = request_id.clone();
        let producer = tokio::spawn(async move {
            for event in events {
                sleep(Duration::from_millis(40)).await;
                if sender
                    .send(RelayPoolNotification::Message {
                        relay_url: relay.clone(),
                        message: RelayMessage::event(producer_request_id.clone(), event),
                    })
                    .is_err()
                {
                    break;
                }
            }
        });

        let error = timeout(
            Duration::from_secs(1),
            collect_strict_directory_query(
                receiver,
                &request_id,
                &expected_relays,
                &query,
                Duration::from_millis(120),
                Duration::from_millis(300),
            ),
        )
        .await
        .expect("the strict query must honor its absolute deadline")
        .unwrap_err();
        producer.abort();
        let _ = producer.await;

        assert_eq!(
            error,
            "strict directory fetch exceeded its overall deadline before EOSE"
        );
    }

    #[tokio::test]
    async fn strict_query_reports_notification_lag_before_eose() {
        let relay = RelayUrl::parse("wss://relay.example").unwrap();
        let expected_relays = HashSet::from([relay]);
        let query = DirectoryEventQuery::new(0, vec!["11".repeat(32)], 1);
        let request_id = SubscriptionId::generate();
        let (sender, receiver) = tokio::sync::broadcast::channel(1);
        sender
            .send(RelayPoolNotification::Shutdown)
            .expect("receiver is active");
        sender
            .send(RelayPoolNotification::Shutdown)
            .expect("receiver is active");

        let error = collect_strict_directory_query(
            receiver,
            &request_id,
            &expected_relays,
            &query,
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error,
            "strict directory notification stream lagged before EOSE"
        );
    }

    #[test]
    fn parsed_directory_relay_urls_deduplicate_trailing_slash_variants() {
        let relay_urls = parsed_directory_relay_urls(&[
            TransportEndpoint("wss://relay.example".to_owned()),
            TransportEndpoint("wss://relay.example/".to_owned()),
        ])
        .unwrap();

        assert_eq!(relay_urls.len(), 1);
    }
}
