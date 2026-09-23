use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::TransportEndpoint;
use futures::StreamExt;
use nostr_sdk::NotificationUpdate;
use nostr_sdk::prelude::{
    Client as NostrSdkClient, Event, Filter, Kind, PublicKey, RelayMessage, RelayNotification,
    RelayStatus, RelayUrl, ReqTarget, SubscribeAutoCloseOptions, SubscriptionId,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinSet;
use tokio::time::timeout;
use transport_nostr_peeler::{NostrTransportEvent, SdkSigner};

use super::DIRECTORY_RELAY_CONNECT_WAIT;

const DIRECTORY_RELAY_FETCH_WAIT: Duration = Duration::from_secs(3);

/// Stable errors for a bounded, isolated relay inspection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectoryInspectionError {
    Unreachable,
    TimedOut,
    #[allow(dead_code)] // Retained for the onboarding inspection contract.
    AuthenticationRequired,
    #[allow(dead_code)] // Retained for the onboarding inspection contract.
    PaymentRequired,
    Restricted,
    InvalidRequest,
}

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
    inflight_completion:
        HashMap<DirectoryFetchKey, Vec<oneshot::Sender<DirectoryCompletionResult>>>,
    active_subscriptions: HashMap<String, DirectorySubscriptionFilter>,
    active_endpoints: HashSet<String>,
    auth_required: HashSet<(String, String)>,
    pending_rebuild: HashSet<String>,
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
    pub(crate) auth_required_routes: usize,
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DirectoryFetchOutcome {
    pub(crate) records: Vec<DirectoryRelayEventRecord>,
    pub(crate) complete: bool,
}

type DirectoryFetchResult = Result<Vec<DirectoryRelayEventRecord>, String>;
type DirectoryCompletionResult = Result<DirectoryFetchOutcome, String>;

#[async_trait]
pub(crate) trait DirectoryRelayFetcher: Send + Sync {
    async fn fetch_directory_events(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String>;

    async fn fetch_directory_events_with_completion(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<DirectoryFetchOutcome, String> {
        self.fetch_directory_events(request)
            .await
            .map(|records| DirectoryFetchOutcome {
                records,
                complete: false,
            })
    }

    /// A single-relay read that must reach EOSE. Pool fetches may silently
    /// aggregate partial results and cannot establish absence for onboarding.
    async fn inspect_directory_events(
        &self,
        _request: DirectoryFetchRequest,
        _signer: Option<Arc<dyn transport_nostr_peeler::MarmotNostrSigner>>,
    ) -> Result<Vec<DirectoryRelayEventRecord>, DirectoryInspectionError> {
        Err(DirectoryInspectionError::Unreachable)
    }
}

#[derive(Clone)]
pub(crate) struct NostrSdkDirectoryRelayFetcher {
    client: NostrSdkClient,
}

struct ScopedInspectionClient(NostrSdkClient);
impl Drop for ScopedInspectionClient {
    fn drop(&mut self) {
        let client = self.0.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = client.shutdown().await;
            });
        }
    }
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
    pub(crate) async fn inspect_events(
        &self,
        request: DirectoryFetchRequest,
        signer: Option<Arc<dyn transport_nostr_peeler::MarmotNostrSigner>>,
    ) -> Result<Vec<DirectoryRelayEventRecord>, DirectoryInspectionError> {
        self.fetcher.inspect_directory_events(request, signer).await
    }
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

    pub(crate) async fn fetch_events_with_completion(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<DirectoryFetchOutcome, String> {
        let key = request.key();
        let (tx, rx) = oneshot::channel();
        let should_spawn = {
            let mut state = self.state.lock().await;
            if let Some(waiters) = state.inflight_completion.get_mut(&key) {
                waiters.push(tx);
                state.coalesced_waiters += 1;
                false
            } else {
                state.inflight_completion.insert(key.clone(), vec![tx]);
                true
            }
        };
        if should_spawn {
            let fetcher = self.fetcher.clone();
            let state = self.state.clone();
            tokio::spawn(async move {
                let result = match tokio::spawn(async move {
                    fetcher
                        .fetch_directory_events_with_completion(request)
                        .await
                })
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err("directory fetch task failed".to_owned()),
                };
                let mut state = state.lock().await;
                if matches!(&result, Ok(outcome) if outcome.complete) {
                    state.completed_fetches += 1;
                } else {
                    state.failed_fetches += 1;
                }
                if let Some(waiters) = state.inflight_completion.remove(&key) {
                    for waiter in waiters {
                        let _ = waiter.send(result.clone());
                    }
                }
            });
        }
        rx.await
            .map_err(|_| "directory fetch owner dropped before completing".to_owned())?
    }

    pub(crate) async fn stats(&self) -> DirectoryRelayStats {
        let state = self.state.lock().await;
        DirectoryRelayStats {
            inflight_fetches: state.inflight.len() + state.inflight_completion.len(),
            active_subscriptions: state
                .active_subscriptions
                .keys()
                .filter(|id| {
                    !state.pending_rebuild.contains(*id)
                        && state.active_endpoints.iter().any(|endpoint| {
                            !state
                                .auth_required
                                .contains(&((*id).clone(), endpoint.clone()))
                        })
                })
                .count(),
            auth_required_routes: state.auth_required.len(),
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
            .chain(desired_ids.intersection(&state.pending_rebuild).cloned())
            .collect::<HashSet<_>>();
        let to_remove = active_ids
            .difference(desired_ids)
            .cloned()
            .collect::<HashSet<_>>();
        (to_add, to_remove)
    }

    pub(crate) async fn set_subscription_endpoints(&self, endpoints: &[RelayUrl]) -> bool {
        let mut state = self.state.lock().await;
        let next = endpoints.iter().map(ToString::to_string).collect();
        let changed = !state.active_subscriptions.is_empty() && state.active_endpoints != next;
        state.active_endpoints = next;
        let active_endpoints = state.active_endpoints.clone();
        state
            .auth_required
            .retain(|(_, endpoint)| active_endpoints.contains(endpoint));
        changed
    }

    pub(crate) async fn clear_auth_required(&self, subscription_id: &str) {
        self.state
            .lock()
            .await
            .auth_required
            .retain(|(id, _)| id != subscription_id);
    }

    pub(crate) async fn mark_rebuild_pending(&self, ids: &HashSet<String>) {
        self.state
            .lock()
            .await
            .pending_rebuild
            .extend(ids.iter().cloned());
    }

    pub(crate) async fn mark_subscription_installed(&self, subscription_id: &str) {
        self.state
            .lock()
            .await
            .pending_rebuild
            .remove(subscription_id);
    }

    pub(crate) async fn mark_auth_required(&self, subscription_id: &str, endpoint: &str) -> bool {
        let mut state = self.state.lock().await;
        if !state.active_endpoints.contains(endpoint)
            || !state.active_subscriptions.contains_key(subscription_id)
        {
            return false;
        }
        state
            .auth_required
            .insert((subscription_id.to_owned(), endpoint.to_owned()))
    }

    /// Record the validation filter before issuing the SDK subscription so an
    /// immediate EVENT cannot race ahead of local admission. A failed subscribe
    /// restores the previous filter or removes a newly created one.
    pub(crate) async fn record_subscription_filter(
        &self,
        subscription_id: String,
        filter: DirectorySubscriptionFilter,
    ) -> Option<DirectorySubscriptionFilter> {
        let mut state = self.state.lock().await;
        let previous = state.active_subscriptions.insert(subscription_id, filter);
        if previous.is_none() {
            state.subscriptions_created += 1;
        }
        previous
    }

    pub(crate) async fn restore_failed_subscription_filter(
        &self,
        subscription_id: &str,
        previous: Option<DirectorySubscriptionFilter>,
    ) {
        let mut state = self.state.lock().await;
        if let Some(previous) = previous {
            state
                .active_subscriptions
                .insert(subscription_id.to_owned(), previous);
        } else if state.active_subscriptions.remove(subscription_id).is_some() {
            state.subscriptions_created -= 1;
        }
    }

    /// Complete a subscription sync whose newly created filters were already
    /// recorded as their SDK subscriptions succeeded.
    pub(crate) async fn complete_subscription_sync(
        &self,
        desired: HashMap<String, DirectorySubscriptionFilter>,
        subscriptions_created: usize,
    ) -> Result<DirectorySubscriptionSyncSummary, String> {
        let mut state = self.state.lock().await;
        let removed = state
            .active_subscriptions
            .keys()
            .filter(|id| !desired.contains_key(*id))
            .count();
        state.completed_subscription_syncs += 1;
        state.subscriptions_removed += removed;
        state.active_subscriptions = desired;
        let active_ids = state
            .active_subscriptions
            .keys()
            .cloned()
            .collect::<HashSet<_>>();
        state
            .auth_required
            .retain(|(id, _)| active_ids.contains(id));
        state.pending_rebuild.retain(|id| active_ids.contains(id));
        Ok(DirectorySubscriptionSyncSummary {
            active_subscriptions: state.active_subscriptions.len(),
            subscriptions_created,
            subscriptions_removed: removed,
        })
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
        let active_ids = state
            .active_subscriptions
            .keys()
            .cloned()
            .collect::<HashSet<_>>();
        state
            .auth_required
            .retain(|(id, _)| active_ids.contains(id));
        state.pending_rebuild.retain(|id| active_ids.contains(id));
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
    #[cfg(test)]
    pub(crate) async fn accepts_live_event(
        &self,
        subscription_id: &str,
        author: &str,
        kind: u64,
    ) -> bool {
        self.state
            .lock()
            .await
            .active_subscriptions
            .get(subscription_id)
            .is_some_and(|filter| filter.accepts(author, kind))
    }

    pub(crate) async fn accepts_live_event_from(
        &self,
        subscription_id: &str,
        endpoint: &str,
        author: &str,
        kind: u64,
    ) -> bool {
        let state = self.state.lock().await;
        // Pending rebuild means coverage is unknown and a retry is still owed.
        // A signed, filter-matching EVENT can arrive before SDK subscribe
        // returns; retain that positive observation without claiming coverage.
        state.active_endpoints.contains(endpoint)
            && !state
                .auth_required
                .contains(&(subscription_id.to_owned(), endpoint.to_owned()))
            && state
                .active_subscriptions
                .get(subscription_id)
                .is_some_and(|filter| filter.accepts(author, kind))
    }
}

// Public directory reads have no account signer. An optional NIP-42
// challenge must not trigger a failed authentication attempt that
// closes the SDK's active fetch before its events arrive.
pub(super) fn anonymous_directory_client() -> NostrSdkClient {
    NostrSdkClient::builder().build()
}

impl NostrSdkDirectoryRelayFetcher {
    pub(crate) fn new(client: NostrSdkClient) -> Self {
        Self { client }
    }

    pub(crate) fn standalone() -> Self {
        Self::new(anonymous_directory_client())
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

impl NostrSdkDirectoryRelayFetcher {
    async fn fetch_request_events(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        let relay_urls = parsed_directory_relay_urls(&request.endpoints)?;
        let mut connect_candidates = Vec::new();
        let mut added = vec![false; relay_urls.len()];
        let mut add_failure_count = 0usize;
        for (index, relay_url) in relay_urls.iter().cloned().enumerate() {
            if self.client.add_relay(relay_url.clone()).await.is_ok() {
                added[index] = true;
                connect_candidates.push((index, relay_url));
            } else {
                add_failure_count += 1;
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
        // A task that panics or is cancelled never flips its index to
        // connected, so this also removes relays from failed JoinSet tasks.
        for (index, relay_url) in relay_urls.iter().cloned().enumerate() {
            if added[index] && !connected[index] {
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
                .fetch_events(ReqTarget::manual(
                    relay_urls
                        .iter()
                        .cloned()
                        .map(|url| (url, vec![filter.clone()])),
                ))
                .timeout(DIRECTORY_RELAY_FETCH_WAIT)
                .max_events(query.limit)
                .with_outcomes()
                .await
                .map_err(|_| "fetch directory events failed".to_owned())?;
            for event in events.events {
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
}

#[async_trait]
impl DirectoryRelayFetcher for NostrSdkDirectoryRelayFetcher {
    async fn inspect_directory_events(
        &self,
        request: DirectoryFetchRequest,
        signer: Option<Arc<dyn transport_nostr_peeler::MarmotNostrSigner>>,
    ) -> Result<Vec<DirectoryRelayEventRecord>, DirectoryInspectionError> {
        use DirectoryInspectionError::*;
        use nostr_sdk::prelude::ReqExitPolicy;
        // The signer belongs to this request only, never to a shared mutable
        // directory client that could authenticate as another account.
        let builder = NostrSdkClient::builder();
        let client = ScopedInspectionClient(match signer {
            Some(signer) => builder
                .authenticator(nostr_sdk::authenticator::SignerAuthenticator::new(
                    SdkSigner(signer),
                ))
                .build(),
            None => builder.build(),
        });
        let client = &client.0;
        let urls = parsed_directory_relay_urls(&request.endpoints).map_err(|_| InvalidRequest)?;
        if urls.len() != 1 {
            return Err(InvalidRequest);
        }
        let url = urls[0].clone();
        client
            .add_relay(url.clone())
            .await
            .map_err(|_| Unreachable)?;
        timeout(
            DIRECTORY_RELAY_CONNECT_WAIT,
            client.connect_relay(url.clone()),
        )
        .await
        .map_err(|_| TimedOut)?
        .map_err(|_| Unreachable)?;
        let relay = client
            .relay(url)
            .await
            .map_err(|_| Unreachable)?
            .ok_or(Unreachable)?;
        let mut records = Vec::new();
        for query in request.queries {
            let keys = query
                .authors
                .iter()
                .map(|key| PublicKey::parse(key))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| InvalidRequest)?;
            let kind = u16::try_from(query.kind).map_err(|_| InvalidRequest)?;
            let filter = if query.kind == 1059 {
                Filter::new().pubkeys(keys)
            } else {
                Filter::new().authors(keys)
            }
            .kind(Kind::from(kind))
            .limit(query.limit);
            let events = relay
                .fetch_events(filter)
                .timeout(DIRECTORY_RELAY_FETCH_WAIT)
                .policy(ReqExitPolicy::ExitOnEOSE)
                .await
                .map_err(|error| {
                    use nostr_sdk::prelude::ErrorKind;
                    match error.kind() {
                        ErrorKind::Timeout => TimedOut,
                        ErrorKind::Rejected | ErrorKind::Policy => Restricted,
                        _ => Unreachable,
                    }
                })?;
            if query.kind == 1059 {
                continue;
            } // Read probe only; do not retain inbox payloads.
            for event in events {
                if let Some(event) = validated_directory_event(&event, &query) {
                    records.push(DirectoryRelayEventRecord {
                        endpoints: request.endpoints.clone(),
                        event,
                    });
                }
            }
        }
        Ok(records)
    }

    async fn fetch_directory_events(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        let owned = Self::standalone();
        let result = owned.fetch_request_events(request).await;
        owned.client.shutdown().await;
        result
    }

    async fn fetch_directory_events_with_completion(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<DirectoryFetchOutcome, String> {
        let relay_urls = parsed_directory_relay_urls(&request.endpoints)?;
        // Discovered targets belong to this bounded read, not the long-lived
        // client pool. Closing the owned client also stops reconnects for
        // failed relays without removing another caller's active relay.
        let client = anonymous_directory_client();
        let mut tasks = JoinSet::new();
        for relay_url in relay_urls.iter().cloned() {
            let client = client.clone();
            let queries = request.queries.clone();
            tasks.spawn(async move { strict_fetch_endpoint(client, relay_url, queries).await });
        }

        let mut outcome = DirectoryFetchOutcome {
            records: Vec::new(),
            complete: true,
        };
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(endpoint) => {
                    outcome.complete &= endpoint.complete;
                    outcome.records.extend(endpoint.records);
                }
                Err(_) => outcome.complete = false,
            }
        }
        if relay_urls.is_empty() {
            outcome.complete = false;
        }
        client.shutdown().await;
        Ok(outcome)
    }
}

async fn strict_fetch_endpoint(
    client: NostrSdkClient,
    relay_url: RelayUrl,
    queries: Vec<DirectoryEventQuery>,
) -> DirectoryFetchOutcome {
    let endpoint = TransportEndpoint(relay_url.to_string());
    if !matches!(client.relay(&relay_url).await, Ok(Some(_)))
        && client.add_relay(relay_url.clone()).await.is_err()
    {
        return DirectoryFetchOutcome::default();
    }
    if !matches!(
        timeout(
            DIRECTORY_RELAY_CONNECT_WAIT,
            client.connect_relay(relay_url.clone()),
        )
        .await,
        Ok(Ok(()))
    ) {
        return DirectoryFetchOutcome::default();
    }
    let Ok(Some(relay)) = client.relay(relay_url).await else {
        return DirectoryFetchOutcome::default();
    };
    let mut filters = Vec::with_capacity(queries.len());
    for query in &queries {
        let Ok(kind) = u16::try_from(query.kind).map(Kind::from) else {
            return DirectoryFetchOutcome::default();
        };
        let Ok(public_keys) = query
            .authors
            .iter()
            .map(|author| PublicKey::parse(author))
            .collect::<Result<Vec<_>, _>>()
        else {
            return DirectoryFetchOutcome::default();
        };
        filters.push(
            Filter::new()
                .authors(public_keys)
                .kind(kind)
                .limit(query.limit),
        );
    }

    let max_records = queries.iter().map(|query| query.limit).sum::<usize>();
    let subscription_id = SubscriptionId::generate();
    let mut notifications = relay.notifications_with_gaps();
    if relay
        .subscribe(filters)
        .with_id(subscription_id.clone())
        .close_on(
            SubscribeAutoCloseOptions::default()
                .timeout(Some(DIRECTORY_RELAY_FETCH_WAIT))
                .idle_timeout(Some(DIRECTORY_RELAY_FETCH_WAIT)),
        )
        .await
        .is_err()
    {
        return DirectoryFetchOutcome::default();
    }

    let mut records = Vec::new();
    let mut seen_event_ids = HashSet::new();
    let mut query_counts = vec![0usize; queries.len()];
    let complete = timeout(DIRECTORY_RELAY_FETCH_WAIT, async {
        loop {
            let received = match notifications.next().await {
                Some(NotificationUpdate::Notification(RelayNotification::Event {
                    subscription_id: received_id,
                    event,
                })) if received_id == subscription_id => Some(*event),
                Some(NotificationUpdate::Notification(RelayNotification::Message { message })) => {
                    match *message {
                        RelayMessage::Event {
                            subscription_id: received_id,
                            event,
                        } if received_id.as_ref() == &subscription_id => Some(event.into_owned()),
                        RelayMessage::EndOfStoredEvents(received_id)
                            if received_id.as_ref() == &subscription_id =>
                        {
                            // A filter that reaches its limit cannot establish absence.
                            break queries
                                .iter()
                                .zip(&query_counts)
                                .all(|(query, count)| *count < query.limit);
                        }
                        RelayMessage::Closed {
                            subscription_id: received_id,
                            ..
                        } if received_id.as_ref() == &subscription_id => break false,
                        _ => None,
                    }
                }
                Some(NotificationUpdate::Notification(RelayNotification::AuthenticationFailed)) => {
                    break false;
                }
                Some(NotificationUpdate::Notification(RelayNotification::RelayStatus {
                    status:
                        RelayStatus::Disconnected | RelayStatus::Terminated | RelayStatus::Banned,
                })) => {
                    break false;
                }
                // Lag may have dropped an inbox EVENT immediately before
                // EOSE. Continuing cannot establish absence safely.
                Some(NotificationUpdate::Lagged { .. }) | None => break false,
                _ => None,
            };
            if let Some(event) = received
                && let Some(event) = queries
                    .iter()
                    .find_map(|query| validated_directory_event(&event, query))
                && seen_event_ids.insert(event.id.clone())
            {
                for (query, count) in queries.iter().zip(&mut query_counts) {
                    if query.kind == event.kind && query.authors.contains(&event.pubkey) {
                        *count += 1;
                    }
                }
                if records.len() < max_records {
                    records.push(DirectoryRelayEventRecord {
                        endpoints: vec![endpoint.clone()],
                        event,
                    });
                } else {
                    break false;
                }
            }
        }
    })
    .await
    .unwrap_or(false);
    let _ = relay.unsubscribe(&subscription_id).await;
    DirectoryFetchOutcome { records, complete }
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
    use nostr_sdk::prelude::FinalizeEvent;

    #[tokio::test]
    async fn anonymous_directory_fetch_accepts_profiles_after_optional_auth_challenge() {
        assert_anonymous_profiles_after_optional_auth_challenge(false).await;
    }

    #[tokio::test]
    async fn anonymous_directory_fetch_completes_after_optional_auth_challenge() {
        assert_anonymous_profiles_after_optional_auth_challenge(true).await;
    }

    async fn assert_anonymous_profiles_after_optional_auth_challenge(with_completion: bool) {
        use futures::{SinkExt, StreamExt};
        use nostr_sdk::prelude::{EventBuilder, Keys};
        use tokio::net::TcpListener;
        use tokio_tungstenite::{accept_async, tungstenite::Message};

        let keys = Keys::generate();
        let profile = EventBuilder::new(Kind::Metadata, r#"{"name":"jack"}"#)
            .finalize(&keys)
            .unwrap();
        let expected_id = profile.id.to_hex();
        let fetcher = NostrSdkDirectoryRelayFetcher::standalone();
        // Pin the anonymous policy independently of AUTH/event scheduling.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = TransportEndpoint(format!("ws://{}", listener.local_addr().unwrap()));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = socket.next().await {
                let Message::Text(text) = message else {
                    continue;
                };
                let request: serde_json::Value = serde_json::from_str(&text).unwrap();
                if request[0] != "REQ" {
                    continue;
                }
                let subscription = request[1].as_str().unwrap();
                socket
                    .send(Message::Text(r#"["AUTH","optional-challenge"]"#.into()))
                    .await
                    .unwrap();
                for response in [
                    serde_json::json!(["EVENT", subscription, profile]),
                    serde_json::json!(["EOSE", subscription]),
                ] {
                    if socket
                        .send(Message::Text(response.to_string().into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                // Keep the connection alive until the bounded fetch shuts down.
            }
        });
        let request = DirectoryFetchRequest::new(
            vec![endpoint],
            vec![DirectoryEventQuery::new(
                0,
                vec![keys.public_key().to_hex()],
                4,
            )],
        )
        .unwrap();
        let result = timeout(Duration::from_secs(5), async {
            if with_completion {
                let outcome = fetcher
                    .fetch_directory_events_with_completion(request)
                    .await?;
                assert!(outcome.complete, "public read must reach EOSE after AUTH");
                Ok(outcome.records)
            } else {
                fetcher.fetch_directory_events(request).await
            }
        })
        .await;
        server.abort();
        let _ = server.await;
        let records = result.unwrap().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].event.id, expected_id);
    }

    #[tokio::test]
    async fn signerless_inspection_never_retains_relays_in_the_shared_client() {
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let endpoint = TransportEndpoint(relay.url().await.to_string());
        let fetcher = NostrSdkDirectoryRelayFetcher::standalone();
        let author = nostr::prelude::Keys::generate().public_key().to_hex();
        for (author, succeeds) in [(author, true), ("invalid-author".into(), false)] {
            let result = fetcher
                .inspect_directory_events(
                    DirectoryFetchRequest::new(
                        vec![endpoint.clone()],
                        vec![DirectoryEventQuery::new(0, vec![author], 1)],
                    )
                    .unwrap(),
                    None,
                )
                .await;
            assert_eq!(result.is_ok(), succeeds);
            assert!(fetcher.client.relays().await.is_empty());
        }
    }

    #[test]
    fn directory_event_validation_rejects_invalid_signatures_and_wrong_authors() {
        use nostr_sdk::prelude::{Event, EventBuilder, FinalizeEvent, Keys};

        let expected = Keys::generate();
        let wrong = Keys::generate();
        let query = DirectoryEventQuery::new(0, vec![expected.public_key().to_hex()], 1);
        let valid = EventBuilder::new(Kind::Metadata, r#"{"name":"agent"}"#)
            .finalize(&expected)
            .unwrap();
        assert!(validated_directory_event(&valid, &query).is_some());

        let wrong_author = EventBuilder::new(Kind::Metadata, r#"{"name":"other"}"#)
            .finalize(&wrong)
            .unwrap();
        assert!(validated_directory_event(&wrong_author, &query).is_none());

        let mut tampered = serde_json::to_value(&valid).unwrap();
        tampered["content"] = serde_json::Value::String(r#"{"name":"tampered"}"#.to_owned());
        let tampered = Event::from_json(tampered.to_string()).unwrap();
        assert!(tampered.verify().is_err());
        assert!(validated_directory_event(&tampered, &query).is_none());
    }

    #[tokio::test]
    async fn strict_directory_exact_filter_limit_keeps_records_but_not_absence_proof() {
        use nostr_sdk::local_relay::MockRelay;
        use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys};

        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let client = NostrSdkClient::default();
        client.add_relay(url.clone()).await.unwrap();
        client.connect_relay(url.clone()).await.unwrap();
        client
            .send_event(
                &EventBuilder::new(Kind::Metadata, "{}")
                    .finalize(&keys)
                    .unwrap(),
            )
            .await
            .unwrap();
        let request = DirectoryFetchRequest::new(
            vec![TransportEndpoint(url.to_string())],
            vec![
                DirectoryEventQuery::new(0, vec![keys.public_key().to_hex()], 1),
                DirectoryEventQuery::new(10050, vec![keys.public_key().to_hex()], 12),
            ],
        )
        .unwrap();
        let result = NostrSdkDirectoryRelayFetcher::standalone()
            .fetch_directory_events_with_completion(request)
            .await
            .unwrap();
        client.shutdown().await;
        assert_eq!(result.records.len(), 1);
        assert!(
            !result.complete,
            "one saturated filter must not be hidden by the combined limit"
        );
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
