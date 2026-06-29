use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::TransportEndpoint;
use nostr_sdk::prelude::{Client as NostrSdkClient, Filter, Kind, PublicKey, RelayUrl};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, oneshot};
use tokio::time::timeout;
use transport_nostr_peeler::NostrTransportEvent;

use super::DIRECTORY_RELAY_CONNECT_WAIT;

const DIRECTORY_RELAY_FETCH_WAIT: Duration = Duration::from_secs(3);

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
/// lists) into the persistent directory search graph (darkmatter#709). Authors
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
    endpoints: Vec<TransportEndpoint>,
    queries: Vec<DirectoryEventQuery>,
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
                let result = fetcher.fetch_directory_events(request).await;
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
    /// (darkmatter#709).
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
}

#[async_trait]
impl DirectoryRelayFetcher for NostrSdkDirectoryRelayFetcher {
    async fn fetch_directory_events(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        let relay_urls = request
            .endpoints
            .iter()
            .map(|endpoint| {
                RelayUrl::parse(endpoint.as_str())
                    .map_err(|e| format!("invalid relay URL {}: {e}", endpoint.as_str()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for relay_url in &relay_urls {
            self.client
                .add_relay(relay_url.clone())
                .await
                .map_err(|e| format!("add relay: {e}"))?;
            timeout(
                DIRECTORY_RELAY_CONNECT_WAIT,
                self.client.connect_relay(relay_url.clone()),
            )
            .await
            .map_err(|_| "connect relay timed out".to_owned())?
            .map_err(|e| format!("connect relay: {e}"))?;
        }

        let mut records = Vec::new();
        for query in request.queries {
            let public_keys = query
                .authors
                .iter()
                .map(|author| PublicKey::parse(author).map_err(|_| "invalid query author"))
                .collect::<Result<Vec<_>, _>>()?;
            let kind = u16::try_from(query.kind)
                .map(Kind::from)
                .map_err(|_| format!("unsupported Nostr kind {}", query.kind))?;
            let filter = Filter::new()
                .authors(public_keys)
                .kind(kind)
                .limit(query.limit);
            let events = self
                .client
                .fetch_events_from(relay_urls.clone(), filter, DIRECTORY_RELAY_FETCH_WAIT)
                .await
                .map_err(|e| format!("fetch directory events: {e}"))?;
            for event in events {
                let event = NostrTransportEvent::from_nostr_event(&event)
                    .map_err(|e| format!("map directory event: {e}"))?;
                records.push(DirectoryRelayEventRecord {
                    endpoints: request.endpoints.clone(),
                    event,
                });
            }
        }
        Ok(records)
    }
}
