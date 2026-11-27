use std::collections::{BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::TransportEndpoint;
use futures::StreamExt;
use nostr_sdk::authenticator::{Authenticator, SignerAuthenticator};
use nostr_sdk::prelude::{
    Client as NostrSdkClient, Event, EventId, Filter, Kind, PublicKey, RelayMessage, RelayUrl,
    SingleLetterTag, Timestamp,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinSet;
use tokio::time::timeout;
use transport_nostr_adapter::{
    FiniteEnd, FiniteLimits, FiniteReply, FiniteRequests, KIND_MARMOT_KEY_PACKAGE,
    NostrAcquisitionCancellation as CancellationToken, RELAY_REPLAY_PAGE_LIMIT,
};
use transport_nostr_peeler::{NostrTransportEvent, SdkSigner};

use super::DIRECTORY_RELAY_CONNECT_WAIT;

const DIRECTORY_RELAY_FETCH_WAIT: Duration = Duration::from_secs(3);

/// How long an onboarding inspection waits, once connected, for its REQs to
/// reach EOSE, including a retry after NIP-42 authentication. Longer than the
/// pooled directory reads: an inspection is onboarding's only proof that a
/// declared route works, and a healthy relay has been measured taking over
/// 7 s to finish a gift-wrap query with a handful of matching events
/// (mdk#3439).
const DIRECTORY_INSPECTION_EOSE_WAIT: Duration = Duration::from_secs(8);

/// The longest one onboarding inspection takes: its connect wait, then its
/// EOSE window. A caller's per-relay budget must be longer, or it reports a
/// slow healthy relay as timed out before the inspection does.
pub const DIRECTORY_INSPECTION_WAIT: Duration =
    match DIRECTORY_RELAY_CONNECT_WAIT.checked_add(DIRECTORY_INSPECTION_EOSE_WAIT) {
        Some(wait) => wait,
        None => panic!("directory inspection wait overflows"),
    };
const DIRECTORY_QUERY_CONCURRENCY: usize = 4;
/// Serialized event JSON one relay's reply to one directory read may carry.
const DIRECTORY_REPLY_MAX_BYTES: usize = 16 * 1024 * 1024;

/// A plain directory lookup a relay's reply cut: past the byte budget, at a
/// frame that could not be read, or deferred by local queue backpressure.
const DIRECTORY_READ_OVER_BUDGET: &str = "directory read exceeded its byte budget";
const DIRECTORY_READ_UNREADABLE: &str = "directory read stopped at an unreadable frame";
const DIRECTORY_READ_LOCAL_BUSY: &str = "directory read deferred by local queue backpressure";

/// The most filters one strict directory REQ carries. strfry allows 3 per
/// REQ and refuses more with `CLOSED invalid:`, so a request with more
/// queries is split into several REQs on the same connection (mdk#2269).
const DIRECTORY_MAX_FILTERS_PER_REQ: usize = 3;

/// The addressable kinds (NIP-01), whose events one `d` value addresses.
const ADDRESSABLE_KINDS: std::ops::Range<u64> = 30_000..40_000;

/// Stable errors for a bounded, isolated relay inspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectoryInspectionError {
    Unreachable,
    TimedOut,
    AuthenticationRequired,
    /// A requested NIP-42 signature was still pending when the read expired.
    AuthenticationTimedOut,
    /// The signer failed to produce a valid NIP-42 event during inbox onboarding.
    AuthenticationSignerFailed,
    /// The relay rejected the matching signed AUTH event for a policy reason.
    AuthenticationRejected,
    PaymentRequired,
    RateLimited,
    Restricted,
    InvalidRequest,
    /// The relay answered but said it holds more than it sent.
    Incomplete,
    /// Local finite-request queue capacity stayed full before any REQ went out;
    /// the relay was never asked.
    LocalBusy,
    /// Relay health's inbox check only ([`DirectoryFetchRequest::verifying_inbox`]):
    /// the relay ended the read without naming a refusal (a CLOSED reason
    /// other than `restricted:`, `blocked:`, `payment-required:`,
    /// `rate-limited:` or `auth-required:`), or sent more than asked.
    Unexplained,
    /// Relay health's inbox check only: the relay asked for authentication
    /// and refused the signer's AUTH only as `rate-limited:`.
    AuthenticationRateLimited,
    /// Relay health's inbox check only: the relay asked for authentication,
    /// and what it then answered the signer's AUTH names no policy: it
    /// accepted it and still refused or withheld, refused it for an
    /// unexplained or `error:` reason, never answered it or never completed
    /// the challenge, or the notifications that could hold its reply were
    /// dropped.
    AuthenticationUnconfirmed,
    /// The relay returned one or more verified records before failing or ending
    /// incompletely.
    Partial {
        records: Vec<DirectoryRelayEventRecord>,
        cause: Box<DirectoryInspectionError>,
    },
}

impl DirectoryInspectionError {
    /// Wrap `cause` with any verified records returned before it failed.
    pub fn partial(records: Vec<DirectoryRelayEventRecord>, cause: Self) -> Self {
        if records.is_empty() {
            cause
        } else {
            Self::Partial {
                records,
                cause: Box::new(cause),
            }
        }
    }

    /// Unpack a partial inspection failure into any verified records it
    /// returned before failing and its underlying cause.
    pub fn into_parts(self) -> (Vec<DirectoryRelayEventRecord>, Self) {
        match self {
            Self::Partial { records, cause } => (records, *cause),
            cause => (Vec::new(), cause),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectoryRelayConnectOutcome {
    Connected,
    TimedOut,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DirectoryEventQuery {
    pub kind: u64,
    pub authors: Vec<String>,
    pub limit: usize,
    pub reference: Option<(char, String)>,
    pub(crate) since: Option<u64>,
    external_inbox_auth: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryRelayEventRecord {
    pub endpoints: Vec<TransportEndpoint>,
    pub event: NostrTransportEvent,
}

/// The directory subscriptions the plane keeps live: the relays to read and
/// one batch per REQ. The app decides the batching policy and builds it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DirectorySyncPlan {
    pub endpoints: Vec<TransportEndpoint>,
    pub watched_user_count: usize,
    pub batches: Vec<DirectorySyncBatch>,
}

/// One directory REQ: its subscription id, authors, kinds and floor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectorySyncBatch {
    pub subscription_id: String,
    pub authors: Vec<String>,
    pub kinds: Vec<u64>,
    pub reference: Option<(char, String)>,
    pub since: Option<u64>,
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
pub struct DirectorySubscriptionFilter {
    authors: HashSet<String>,
    kinds: HashSet<u64>,
    pub(crate) reference: Option<(char, String)>,
}

impl DirectorySubscriptionFilter {
    pub fn new(authors: Vec<String>, kinds: Vec<u64>) -> Self {
        Self {
            authors: authors.into_iter().collect(),
            kinds: kinds.into_iter().collect(),
            reference: None,
        }
    }

    #[cfg(test)]
    fn accepts(&self, author: &str, kind: u64) -> bool {
        self.accepts_event(author, kind, &[])
    }

    fn accepts_event(&self, author: &str, kind: u64, tags: &[Vec<String>]) -> bool {
        self.authors.contains(author)
            && self.kinds.contains(&kind)
            && self.reference.as_ref().is_none_or(|(name, value)| {
                tags.iter().any(|tag| {
                    tag.first().and_then(|tag| tag.parse::<char>().ok()) == Some(*name)
                        && tag.get(1) == Some(value)
                })
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryFetchRequest {
    pub endpoints: Vec<TransportEndpoint>,
    pub queries: Vec<DirectoryEventQuery>,
    /// Optional total deadline for one-shot `inspect_directory_events`, so a
    /// caller with a shorter remaining budget gets `Partial { records, TimedOut }`
    /// from the collector instead of cancelling it from outside.
    pub(crate) inspection_budget: Option<Duration>,
    /// Relay health's inbox check: classify the answer strictly (see
    /// [`Self::verifying_inbox`]).
    pub(crate) verify_inbox: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct DirectoryFetchKey {
    endpoints: Vec<TransportEndpoint>,
    queries: Vec<DirectoryEventQuery>,
}

#[derive(Clone)]
pub struct DirectoryRelayPlane {
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
pub struct DirectoryRelayStats {
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
pub struct DirectorySubscriptionSyncSummary {
    pub active_subscriptions: usize,
    pub subscriptions_created: usize,
    pub subscriptions_removed: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DirectoryFetchOutcome {
    pub records: Vec<DirectoryRelayEventRecord>,
    /// Every requested relay reached its end of stored events for every
    /// query, and no page came back full.
    pub complete: bool,
    /// The relays whose own read finished that way, whether or not the
    /// others did: what one of them did not return, it does not serve.
    pub complete_endpoints: Vec<TransportEndpoint>,
}

type DirectoryFetchResult = Result<Vec<DirectoryRelayEventRecord>, String>;
type DirectoryCompletionResult = Result<DirectoryFetchOutcome, String>;

#[async_trait]
pub trait DirectoryRelayFetcher: Send + Sync {
    async fn fetch_directory_events(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String>;

    /// Per-relay failures produce incomplete outcomes. Return an error for
    /// invalid requests or failures of the fetch resource itself.
    async fn fetch_directory_events_with_completion(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<DirectoryFetchOutcome, String> {
        self.fetch_directory_events(request)
            .await
            .map(|records| DirectoryFetchOutcome {
                records,
                ..DirectoryFetchOutcome::default()
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
pub struct NostrSdkDirectoryRelayFetcher {
    client: NostrSdkClient,
    finite: FiniteRequests,
}

/// A client owned by one bounded read. Dropped, it stops the relay it holds
/// at once (`Relay::shutdown` ends its dial, socket and AUTH handling before
/// it returns), so a cancelled read leaves no connection behind, and then
/// shuts the client down.
struct ScopedInspectionClient(NostrSdkClient, Option<nostr_sdk::prelude::Relay>);
impl Drop for ScopedInspectionClient {
    fn drop(&mut self) {
        if let Some(relay) = &self.1 {
            relay.shutdown();
        }
        let client = self.0.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = client.shutdown().await;
            });
        }
    }
}

impl DirectoryEventQuery {
    pub fn new(kind: u64, mut authors: Vec<String>, limit: usize) -> Self {
        authors.sort();
        authors.dedup();
        Self {
            kind,
            authors,
            limit,
            reference: None,
            since: None,
            external_inbox_auth: false,
        }
    }

    /// Use the external-signer AUTH policy for a standalone inbox inspection.
    /// Once a signature is requested, another challenge waits for the next
    /// inspection. An AUTH-hinted EOSE cannot verify this signed inbox route.
    pub fn with_external_inbox_auth(mut self) -> Self {
        self.external_inbox_auth = true;
        self
    }

    pub fn deletion_reference(
        account: &str,
        name: char,
        value: String,
        since: Option<u64>,
    ) -> Self {
        let mut query = Self::new(5, vec![account.to_owned()], 1);
        query.reference = Some((name, value));
        query.since = since;
        query
    }

    /// The authors' kind 5 deletion requests that name kind `30443` in a `k`
    /// tag, read alongside their KeyPackages. `k` is only a fetch filter: a
    /// request without it is still honoured when another lookup finds it.
    pub fn key_package_deletions(authors: Vec<String>, limit: usize) -> Self {
        let mut query = Self::new(5, authors, limit);
        query.reference = Some(('k', KIND_MARMOT_KEY_PACKAGE.to_string()));
        query
    }

    /// One author's publications in one KeyPackage slot, the `d` value of
    /// kind `30443`.
    pub fn key_package_slot(author: &str, slot: String, limit: usize) -> Self {
        Self::address(KIND_MARMOT_KEY_PACKAGE, author, slot, limit)
    }

    /// One author's publications at one address: the `d` value `d` of the
    /// addressable kind `kind`. Unlike a read of the author's whole account,
    /// a busy account cannot page the address out.
    pub fn address(kind: u64, author: &str, d: String, limit: usize) -> Self {
        let mut query = Self::new(kind, vec![author.to_owned()], limit);
        query.reference = Some(('d', d));
        query
    }

    fn validate_reference(&self) -> Result<(), String> {
        let Some((name, value)) = &self.reference else {
            return if self.since.is_none() {
                Ok(())
            } else {
                Err("invalid directory since constraint".into())
            };
        };
        if ADDRESSABLE_KINDS.contains(&self.kind) && *name == 'd' {
            return if self.authors.len() == 1 && self.since.is_none() && !value.is_empty() {
                Ok(())
            } else {
                Err("invalid address query".into())
            };
        }
        if self.kind == 5
            && *name == 'k'
            && self.since.is_none()
            && *value == KIND_MARMOT_KEY_PACKAGE.to_string()
        {
            return Ok(());
        }
        if self.kind != 5 || self.authors.len() != 1 {
            return Err("invalid deletion query scope".into());
        }
        let author = PublicKey::parse(&self.authors[0])
            .map_err(|_| "invalid query author")?
            .to_hex();
        match name {
            'e' if self.since.is_none()
                && value.len() == 64
                && value
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) =>
            {
                Ok(())
            }
            'a' if self.since.is_some() => {
                let mut parts = value.splitn(3, ':');
                if parts.next() == Some("30443")
                    && parts.next() == Some(author.as_str())
                    && parts.next().is_some_and(|slot| !slot.is_empty())
                {
                    Ok(())
                } else {
                    Err("invalid deletion coordinate".into())
                }
            }
            _ => Err("invalid deletion reference".into()),
        }
    }

    pub fn matches(&self, event: &NostrTransportEvent) -> bool {
        self.kind == event.kind
            && self.authors.contains(&event.pubkey)
            && self.since.is_none_or(|since| event.created_at >= since)
            && self.reference.as_ref().is_none_or(|(name, value)| {
                event
                    .tag_values(&name.to_string())
                    .contains(&value.as_str())
            })
    }
}

impl DirectoryFetchRequest {
    pub fn new(
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
            query.validate_reference()?;
            if query.authors.is_empty() {
                return Err("directory fetch: no query authors".to_owned());
            }
            if query.limit == 0 {
                return Err("directory fetch: query limit must be greater than zero".to_owned());
            }
        }
        Ok(Self {
            endpoints,
            queries,
            inspection_budget: None,
            verify_inbox: false,
        })
    }

    /// Classify an inbox read (kind 1059) for relay health: only a refusal the
    /// relay names (`restricted:`, `blocked:`, `payment-required:`, or an AUTH
    /// refused for one of those reasons) stays a refusal; an answer that
    /// cannot be verified (an auth-gated EOSE, an AUTH whose outcome names no
    /// policy or never completes) is [`DirectoryInspectionError::AuthenticationUnconfirmed`],
    /// and any other close [`DirectoryInspectionError::Unexplained`].
    pub fn verifying_inbox(mut self) -> Self {
        self.verify_inbox = true;
        self
    }

    /// Bound one-shot `inspect_directory_events` to at most `budget` across
    /// connect and EOSE so the collector returns any verified prefix on expiry.
    pub fn with_inspection_budget(mut self, budget: Duration) -> Self {
        self.inspection_budget = Some(budget);
        self
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
    pub fn new(fetcher: Arc<dyn DirectoryRelayFetcher>) -> Self {
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
        tags: &[Vec<String>],
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
                .is_some_and(|filter| filter.accepts_event(author, kind, tags))
    }
}

// Public directory reads have no account signer. An optional NIP-42
// challenge must not trigger a failed authentication attempt that
// closes the SDK's active fetch before its events arrive.
pub(super) fn anonymous_directory_client() -> NostrSdkClient {
    super::nostr_builder().build()
}

impl NostrSdkDirectoryRelayFetcher {
    /// An owned anonymous client whose reads are finite requests.
    pub fn standalone() -> Self {
        let (builder, finite) = FiniteRequests::install(super::nostr_builder());
        Self {
            client: builder.build(),
            finite,
        }
    }

    /// Each of `relay_urls`' finite reply to `filters`, in order; `None` for
    /// a relay missing from the pool. A relay's every EVENT frame would count
    /// toward an item cap, matching or not, so none is set: one relay that
    /// ignores the filter cannot crowd out the events asked for. The relays
    /// share one byte budget for the events they keep, however their replies
    /// divide it, and the deadline bounds them. Frames not yet read are
    /// bounded per relay request, as for every finite request: its queue holds
    /// at most that budget plus one frame and drains as it is read, so with
    /// the batch its collector is reading, at most twice that is held.
    async fn fetch_each(
        &self,
        relay_urls: &[RelayUrl],
        filters: &[Filter],
    ) -> Vec<Option<FiniteReply>> {
        let limits = FiniteLimits {
            max_items: usize::MAX,
            max_event_bytes: DIRECTORY_REPLY_MAX_BYTES,
            timeout: DIRECTORY_RELAY_FETCH_WAIT,
        };
        let cancel = CancellationToken::new();
        let finite = &self.finite.sharing(DIRECTORY_REPLY_MAX_BYTES);
        futures::future::join_all(relay_urls.iter().map(|url| {
            let cancel = &cancel;
            async move {
                let relay = self.client.relay(url.clone()).await.ok().flatten()?;
                Some(finite.fetch(&relay, filters.to_vec(), limits, cancel).await)
            }
        }))
        .await
    }
}

fn validated_directory_event(
    event: &Event,
    query: &DirectoryEventQuery,
) -> Option<NostrTransportEvent> {
    if event.verify().is_err() {
        return None;
    }
    let event = NostrTransportEvent::from_nostr_event(event).ok()?;
    query.matches(&event).then_some(event)
}

/// Shared wire-filter construction, including the inbox inspection probe.
fn directory_query_filter(query: &DirectoryEventQuery, recipient: bool) -> Result<Filter, String> {
    query.validate_reference()?;
    let kind = u16::try_from(query.kind)
        .map(Kind::from)
        .map_err(|_| "unsupported Nostr kind")?;
    let keys = query
        .authors
        .iter()
        .map(|author| PublicKey::parse(author).map_err(|_| "invalid query author"))
        .collect::<Result<Vec<_>, _>>()?;
    let mut filter = if recipient {
        Filter::new().pubkeys(keys)
    } else {
        Filter::new().authors(keys)
    }
    .kind(kind)
    .limit(query.limit);
    if let Some((name, value)) = &query.reference {
        filter = filter.custom_tag(
            SingleLetterTag::from_char(*name).map_err(|_| "invalid reference tag")?,
            value.clone(),
        );
    }
    if let Some(since) = query.since {
        filter = filter.since(Timestamp::from_secs(since));
    }
    Ok(filter)
}

impl NostrSdkDirectoryRelayFetcher {
    /// Add and connect `relay_urls`, returning those that connected within
    /// the connect wait. Relays that did not connect are removed again.
    async fn connect_relays(&self, relay_urls: Vec<RelayUrl>) -> Result<Vec<RelayUrl>, String> {
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
        Ok(relay_urls)
    }

    async fn fetch_request_events(
        &self,
        request: DirectoryFetchRequest,
    ) -> Result<Vec<DirectoryRelayEventRecord>, String> {
        let relay_urls = self
            .connect_relays(parsed_directory_relay_urls(&request.endpoints)?)
            .await?;

        let mut queries = futures::stream::iter(request.queries)
            .map(|query| {
                let relay_urls = &relay_urls;
                async move {
                    let filter = directory_query_filter(&query, false)?;
                    let replies = self
                        .fetch_each(relay_urls, std::slice::from_ref(&filter))
                        .await;
                    // A plain lookup cannot say it is partial, and a record a
                    // cut relay never sent would read as absent: the lookup
                    // fails instead, which callers treat as unresolved. The
                    // SDK's own reads skipped an unreadable frame and went on;
                    // a finite request stops at it, so it cuts the same way.
                    for reply in replies.iter().flatten() {
                        match reply.end {
                            FiniteEnd::ByteLimit => {
                                return Err(DIRECTORY_READ_OVER_BUDGET.to_owned());
                            }
                            FiniteEnd::InvalidMessage => {
                                return Err(DIRECTORY_READ_UNREADABLE.to_owned());
                            }
                            // Plain lookups have no partial-result signal; fail
                            // explicitly on local deferral rather than silently
                            // skipping a relay whose records could then read as
                            // absent.
                            FiniteEnd::Busy => {
                                return Err(DIRECTORY_READ_LOCAL_BUSY.to_owned());
                            }
                            _ => {}
                        }
                    }
                    // The newest `limit` distinct events any relay sent.
                    let events = replies
                        .into_iter()
                        .flatten()
                        .flat_map(|reply| reply.events)
                        .collect::<BTreeSet<_>>();
                    Ok::<_, String>((query, events))
                }
            })
            .buffered(DIRECTORY_QUERY_CONCURRENCY);
        let mut records = Vec::new();
        while let Some(result) = queries.next().await {
            let (query, events) = result?;
            for event in events.into_iter().take(query.limit) {
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

/// Verified events from one public-event read, whether every requested relay
/// connected and reached its end of stored events, and which relays sent each
/// event.
pub struct PublicEventFetch {
    pub events: Vec<Event>,
    pub complete: bool,
    /// The relays that sent each verified event, by event id, in their parsed
    /// relay-URL spelling. A relay that sent only a copy failing signature
    /// verification is not listed.
    pub sources: HashMap<EventId, Vec<TransportEndpoint>>,
}

impl PublicEventFetch {
    /// The relays that sent `id`, or none for an event this read did not
    /// return.
    pub fn sources_of(&self, id: &EventId) -> &[TransportEndpoint] {
        self.sources.get(id).map_or(&[], Vec::as_slice)
    }
}

/// One bounded, anonymous read of public events matching `filters`.
///
/// Uses an owned client like [`DirectoryRelayFetcher::fetch_directory_events`],
/// so hint relays never join a long-lived pool. Each relay's reply is its own
/// finite request, verified as it arrives, so the relay behind each copy is
/// known and a relay's forged copy can neither displace a genuine copy from
/// another relay nor count toward `max_events`; callers still match every
/// event against the reference they asked for.
///
/// It returns at most `max_events` distinct events, the newest first. A read
/// with more than that, or a relay that did not connect, did not reach its end
/// of stored events or said it has more, is incomplete; one relay's failure
/// does not stop the others.
pub async fn fetch_public_events(
    endpoints: &[TransportEndpoint],
    filters: Vec<Filter>,
    max_events: usize,
) -> Result<PublicEventFetch, String> {
    let fetcher = NostrSdkDirectoryRelayFetcher::standalone();
    let result = async {
        let requested = parsed_directory_relay_urls(endpoints)?;
        let requested_count = requested.len();
        let relay_urls = fetcher.connect_relays(requested).await?;
        let replies = fetcher.fetch_each(&relay_urls, &filters).await;
        let mut complete = relay_urls.len() == requested_count;
        let mut events = BTreeSet::new();
        let mut sources: HashMap<EventId, Vec<TransportEndpoint>> = HashMap::new();
        for (url, reply) in relay_urls.iter().zip(replies) {
            let Some(reply) = reply else {
                complete = false;
                continue;
            };
            // NIP-67 `more` or `auth`: the relay cut its own answer short, or
            // holds events back until the client authenticates.
            complete &= reply.end == FiniteEnd::Eose && !reply.more && !reply.auth;
            for event in reply.events {
                let from = sources.entry(event.id).or_default();
                let relay = TransportEndpoint(url.to_string());
                if !from.contains(&relay) {
                    from.push(relay);
                }
                events.insert(event);
            }
        }
        if events.len() > max_events {
            complete = false;
            events = events.into_iter().take(max_events).collect();
            let kept = events.iter().map(|event| event.id).collect::<HashSet<_>>();
            sources.retain(|id, _| kept.contains(id));
        }
        Ok(PublicEventFetch {
            events: events.into_iter().collect(),
            complete,
            sources,
        })
    }
    .await;
    fetcher.client.shutdown().await;
    result
}

const SIGNATURE_IDLE: u8 = 0;
const SIGNATURE_PENDING: u8 = 1;
const SIGNATURE_SIGNED: u8 = 2;
const SIGNATURE_FAILED: u8 = 3;

#[derive(Debug)]
struct InspectionAuthenticator {
    signer: SignerAuthenticator<SdkSigner>,
    signing: Arc<AtomicU8>,
    single_signature: bool,
    /// The AUTH events it signed, so a relay's reply is matched to them.
    signed: Arc<std::sync::Mutex<Vec<EventId>>>,
}

impl Authenticator for InspectionAuthenticator {
    fn make_auth_event<'a>(
        &'a self,
        relay_url: &'a RelayUrl,
        challenge: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Event, nostr_sdk::prelude::Error>> + Send + 'a>> {
        Box::pin(async move {
            struct PendingSignature<'a> {
                state: &'a AtomicU8,
                cancelled: u8,
            }
            impl Drop for PendingSignature<'_> {
                fn drop(&mut self) {
                    let _ = self.state.compare_exchange(
                        SIGNATURE_PENDING,
                        self.cancelled,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    );
                }
            }

            if self.single_signature {
                if self
                    .signing
                    .compare_exchange(
                        SIGNATURE_IDLE,
                        SIGNATURE_PENDING,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    )
                    .is_err()
                {
                    return Err(nostr_sdk::prelude::Error::other(
                        "inbox inspection already requested an AUTH signature",
                    ));
                }
            } else {
                self.signing.store(SIGNATURE_PENDING, Ordering::Relaxed);
            }
            let _pending = PendingSignature {
                state: &self.signing,
                cancelled: if self.single_signature {
                    SIGNATURE_FAILED
                } else {
                    SIGNATURE_IDLE
                },
            };
            let result = self.signer.make_auth_event(relay_url, challenge).await;
            let state = if let Ok(event) = &result
                && nostr::nips::nip42::is_valid_auth_event(event, relay_url, challenge)
            {
                self.signed
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(event.id);
                SIGNATURE_SIGNED
            } else {
                SIGNATURE_FAILED
            };
            self.signing.store(state, Ordering::Relaxed);
            result
        })
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
        // The signer belongs to this request only, never to a shared mutable
        // directory client that could authenticate as another account.
        let signing = Arc::new(AtomicU8::new(SIGNATURE_IDLE));
        let auth_signed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let signed = signer.is_some();
        let external_inbox_auth = signed
            && !request.verify_inbox
            && matches!(request.queries.as_slice(), [query] if query.kind == 1059 && query.external_inbox_auth);
        let builder = match signer {
            Some(signer) => super::nostr_builder().authenticator(InspectionAuthenticator {
                signer: SignerAuthenticator::new(SdkSigner(signer)),
                signing: signing.clone(),
                single_signature: external_inbox_auth,
                signed: auth_signed.clone(),
            }),
            None => super::nostr_builder(),
        };
        let (builder, finite) = FiniteRequests::install(builder);
        let mut scoped = ScopedInspectionClient(builder.build(), None);
        let client = scoped.0.clone();
        let urls = parsed_directory_relay_urls(&request.endpoints).map_err(|_| InvalidRequest)?;
        if urls.len() != 1 {
            return Err(InvalidRequest);
        }
        let url = urls[0].clone();
        client
            .add_relay(url.clone())
            .await
            .map_err(|_| Unreachable)?;
        let relay = client
            .relay(url.clone())
            .await
            .map_err(|_| Unreachable)?
            .ok_or(Unreachable)?;
        scoped.1 = Some(relay.clone());
        // Relay health reads the relay's own answers to the signer's AUTH,
        // watched from before the dial too.
        let mut auth_replies = relay.notifications().with_gaps();
        // Watched before the dial, so an authentication a challenge on
        // connect starts is seen however early it ends. Opt into the short
        // challenge grace so a bare `auth-required:` CLOSED with no AUTH
        // challenge ends as `AuthenticationRequired` rather than waiting out
        // the whole EOSE window (mdk#3724). One retry per inspection: the watch
        // goes with it.
        let mut auth = finite
            .watch_auth(&relay)
            .map(|watch| watch.with_challenge_wait(transport_nostr_adapter::AUTH_CHALLENGE_WAIT));
        // `connect_relay` only queues the dial. Await the handshake, so the
        // EOSE window below is the relay's answer time alone.
        let started = tokio::time::Instant::now();
        let overall_deadline = request.inspection_budget.map(|budget| started + budget);
        let connect_wait = match overall_deadline {
            Some(overall) => {
                DIRECTORY_RELAY_CONNECT_WAIT.min(overall.saturating_duration_since(started))
            }
            None => DIRECTORY_RELAY_CONNECT_WAIT,
        };
        if connect_wait.is_zero() {
            return Err(TimedOut);
        }
        match timeout(
            connect_wait,
            client.try_connect_relay(url.clone()).timeout(connect_wait),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) if error.kind() == nostr_sdk::prelude::ErrorKind::Timeout => {
                return Err(TimedOut);
            }
            Ok(Err(_)) => return Err(Unreachable),
            Err(_) => return Err(TimedOut),
        }
        let eose_deadline = tokio::time::Instant::now() + DIRECTORY_INSPECTION_EOSE_WAIT;
        let deadline = match overall_deadline {
            Some(overall) => eose_deadline.min(overall),
            None => eose_deadline,
        };
        let cancel = CancellationToken::new();
        let mut records = Vec::new();
        for query in request.queries {
            let filter =
                directory_query_filter(&query, query.kind == 1059).map_err(|_| InvalidRequest)?;
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(DirectoryInspectionError::partial(records, TimedOut));
            }
            // A successful empty read can hide a CLOSED terminal; the finite
            // reply keeps its wire reason. With a signer, a relay that
            // requires NIP-42 is asked once more after the SDK authenticates,
            // whether or not its reason is wrapped (mdk#3439).
            let limits = FiniteLimits {
                max_items: query.limit.saturating_add(1).max(1),
                max_event_bytes: DIRECTORY_REPLY_MAX_BYTES,
                timeout: remaining,
            };
            let auth_watch_available = auth.is_some();
            let result = finite
                .fetch_watching(&relay, vec![filter], limits, &cancel, &mut auth)
                .await;
            let waited_for_auth = auth_watch_available && auth.is_none();
            let preserve_partial = matches!(query.kind, 10002 | 10050);
            let collect_verified = |target: &mut Vec<DirectoryRelayEventRecord>| {
                if query.kind == 1059 {
                    return;
                }
                for event in &result.events {
                    if let Some(event) = validated_directory_event(event, &query) {
                        target.push(DirectoryRelayEventRecord {
                            endpoints: request.endpoints.clone(),
                            event,
                        });
                    }
                }
            };
            if request.verify_inbox {
                let evidence = signed.then(|| auth_evidence(&mut auth_replies, &auth_signed));
                return verified_inbox_answer(
                    &result,
                    evidence,
                    signing.load(Ordering::Relaxed) == SIGNATURE_PENDING,
                );
            }
            match &result.end {
                FiniteEnd::Eose if !result.auth && !result.more => {
                    collect_verified(&mut records);
                }
                end => {
                    // NIP-67 `auth`: `FiniteRequests` already retried once after
                    // authenticating when a signer was available; a persistent
                    // `auth` hint means the relay still withholds events behind
                    // authentication. NIP-67 `more`: the relay cut its answer.
                    // Legacy inbox probes use EOSE for reachability. An
                    // external-signer probe must see the auth gate clear.
                    let use_auth_evidence = match end {
                        FiniteEnd::Eose => external_inbox_auth && waited_for_auth && result.auth,
                        FiniteEnd::Closed(reason) => {
                            waited_for_auth
                                && directory_closed_reason(reason) == AuthenticationRequired
                        }
                        // A relay can challenge on connect and then leave the
                        // inbox request unanswered. The finite read never takes
                        // its watch in that case, but still has AUTH evidence.
                        FiniteEnd::TimedOut => auth_watch_available,
                        _ => false,
                    };
                    let signing_state = signing.load(Ordering::Relaxed);
                    if query.kind == 1059 && use_auth_evidence && !result.retried {
                        match signing_state {
                            SIGNATURE_PENDING => return Err(AuthenticationTimedOut),
                            SIGNATURE_FAILED => return Err(AuthenticationSignerFailed),
                            _ => {}
                        }
                        let evidence = auth_evidence(&mut auth_replies, &auth_signed);
                        match evidence.reply {
                            AuthReply::Refused => return Err(AuthenticationRejected),
                            AuthReply::RateLimited => return Err(RateLimited),
                            _ => {}
                        }
                    }
                    let cause = match end {
                        FiniteEnd::Eose
                            if result.auth && (query.kind != 1059 || external_inbox_auth) =>
                        {
                            AuthenticationRequired
                        }
                        FiniteEnd::Eose if result.more && query.kind != 1059 => Incomplete,
                        FiniteEnd::Eose => continue,
                        FiniteEnd::Closed(reason) => directory_closed_reason(reason),
                        FiniteEnd::TimedOut if signing_state == SIGNATURE_PENDING => {
                            AuthenticationTimedOut
                        }
                        FiniteEnd::TimedOut => TimedOut,
                        FiniteEnd::ItemLimit | FiniteEnd::ByteLimit if query.kind == 1059 => {
                            Incomplete
                        }
                        FiniteEnd::ItemLimit | FiniteEnd::ByteLimit => Restricted,
                        FiniteEnd::Busy => LocalBusy,
                        _ => Unreachable,
                    };
                    if preserve_partial {
                        collect_verified(&mut records);
                        return Err(DirectoryInspectionError::partial(records, cause));
                    }
                    return Err(cause);
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
        let mut tasks = JoinSet::new();
        for relay_url in relay_urls.iter().cloned() {
            let queries = request.queries.clone();
            tasks.spawn(async move { strict_fetch_endpoint(relay_url, queries).await });
        }

        let mut outcome = DirectoryFetchOutcome {
            complete: true,
            ..DirectoryFetchOutcome::default()
        };
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(endpoint) => {
                    outcome.complete &= endpoint.complete;
                    outcome.records.extend(endpoint.records);
                    outcome
                        .complete_endpoints
                        .extend(endpoint.complete_endpoints);
                }
                Err(_) => return Err("directory relay fetch task failed".to_owned()),
            }
        }
        if relay_urls.is_empty() {
            outcome.complete = false;
        }
        Ok(outcome)
    }
}

/// What the signer's AUTH met, from the relay's messages read so far.
struct AuthEvidence {
    /// The relay sent an AUTH challenge.
    challenged: bool,
    /// What it answered the latest AUTH this read signed.
    reply: AuthReply,
}

enum AuthReply {
    /// No reply to an AUTH this read signed was read, or the notifications
    /// that could hold one were dropped.
    Unread,
    Accepted,
    /// Refused for a policy reason it names: `restricted:`, `blocked:` or
    /// `payment-required:`.
    Refused,
    /// Refused as `rate-limited:` (behind one `error:` wrapper or none).
    RateLimited,
    /// Refused for a reason that names no policy.
    Unexplained,
}

/// The relay's challenges and its latest reply to an AUTH in `signed` among
/// the messages already buffered: the SDK reports an authentication's end
/// after its OK, and an OK for any other event is not this AUTH's answer.
fn auth_evidence<Gap>(
    replies: &mut (
             impl futures::Stream<Item = Result<nostr_sdk::prelude::RelayNotification, Gap>> + Unpin
         ),
    signed: &std::sync::Mutex<Vec<EventId>>,
) -> AuthEvidence {
    use futures::FutureExt;
    use nostr_sdk::prelude::RelayNotification;
    let signed = signed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let (mut challenged, mut dropped, mut reply) = (false, false, AuthReply::Unread);
    while let Some(Some(notification)) = replies.next().now_or_never() {
        let Ok(notification) = notification else {
            dropped = true;
            continue;
        };
        let RelayNotification::Message { message } = notification else {
            continue;
        };
        match *message {
            RelayMessage::Auth { .. } => challenged = true,
            RelayMessage::Ok {
                event_id,
                status,
                message,
            } if signed.contains(&event_id) => {
                reply = if status {
                    AuthReply::Accepted
                } else if unwrapped_reason(&message).starts_with("rate-limited:") {
                    AuthReply::RateLimited
                } else if ["restricted:", "blocked:", "payment-required:"]
                    .iter()
                    .any(|policy| message.starts_with(policy))
                {
                    AuthReply::Refused
                } else {
                    AuthReply::Unexplained
                };
            }
            _ => {}
        }
    }
    if dropped {
        reply = AuthReply::Unread;
    }
    AuthEvidence { challenged, reply }
}

/// Relay health's reading of an inbox read's end: a refusal only where the
/// relay named one, an answer it withheld or could not verify as
/// `AuthenticationUnconfirmed`, never `Ok`.
fn verified_inbox_answer(
    result: &transport_nostr_adapter::FiniteReply,
    evidence: Option<AuthEvidence>,
    signing_pending: bool,
) -> Result<Vec<DirectoryRelayEventRecord>, DirectoryInspectionError> {
    use DirectoryInspectionError::*;
    let challenged = evidence
        .as_ref()
        .is_some_and(|evidence| evidence.challenged);
    Err(match &result.end {
        // An EOSE still saying it withholds events until authentication
        // proves the relay answered, not that it serves the inbox.
        FiniteEnd::Eose if result.auth => AuthenticationUnconfirmed,
        FiniteEnd::Eose => return Ok(Vec::new()),
        FiniteEnd::Closed(reason) => match inbox_closed_reason(reason) {
            AuthenticationRequired => match evidence.map(|evidence| evidence.reply) {
                // No signer answered: nothing about this account's key.
                None => AuthenticationUnconfirmed,
                Some(AuthReply::Refused) => AuthenticationRequired,
                Some(AuthReply::RateLimited) => AuthenticationRateLimited,
                Some(AuthReply::Unread | AuthReply::Accepted | AuthReply::Unexplained) => {
                    AuthenticationUnconfirmed
                }
            },
            error => error,
        },
        FiniteEnd::TimedOut if signing_pending => AuthenticationTimedOut,
        // A challenge the relay sent and never saw through: it answered.
        FiniteEnd::TimedOut if challenged => AuthenticationUnconfirmed,
        FiniteEnd::TimedOut => TimedOut,
        FiniteEnd::ItemLimit | FiniteEnd::ByteLimit => Unexplained,
        FiniteEnd::Busy => LocalBusy,
        _ => Unreachable,
    })
}

/// A CLOSED reason as relay health reads it: only a refusal the relay names
/// is one (behind one `error:` wrapper or none).
fn inbox_closed_reason(reason: &str) -> DirectoryInspectionError {
    use DirectoryInspectionError::*;
    let reason = unwrapped_reason(reason);
    if reason.starts_with("auth-required:") {
        AuthenticationRequired
    } else if reason.starts_with("payment-required:") {
        PaymentRequired
    } else if reason.starts_with("rate-limited:") {
        RateLimited
    } else if reason.starts_with("restricted:") || reason.starts_with("blocked:") {
        Restricted
    } else {
        Unexplained
    }
}

/// `reason` without one leading `error:` wrapper (mdk#3439).
fn unwrapped_reason(reason: &str) -> &str {
    reason
        .get(..6)
        .filter(|wrapper| wrapper.eq_ignore_ascii_case("error:"))
        .map_or(reason, |_| reason[6..].trim_start())
}

/// Classifies a relay's CLOSED reason by its NIP-01 machine-readable prefix.
/// Some relays put that prefix behind one `error:` wrapper (`ERROR:
/// auth-required: ...`, mdk#3439); that wrapper alone is looked through.
/// `rate-limited:` and bare `error: <other>` are transient (`RateLimited` and
/// `Unreachable`); permanent policy prefixes stay `Restricted`.
fn has_closed_prefix(reason: &str, prefix: &str) -> bool {
    reason == prefix
        || reason
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with(':'))
}

fn directory_closed_reason(reason: &str) -> DirectoryInspectionError {
    use DirectoryInspectionError::*;
    let wrapped = reason
        .get(..6)
        .filter(|wrapper| wrapper.eq_ignore_ascii_case("error:"))
        .map(|_| reason[6..].trim_start());
    let unwrapped = wrapped.unwrap_or(reason);
    if has_closed_prefix(unwrapped, "auth-required") {
        AuthenticationRequired
    } else if has_closed_prefix(unwrapped, "payment-required") {
        PaymentRequired
    } else if has_closed_prefix(unwrapped, "rate-limited") {
        RateLimited
    } else if wrapped.is_some()
        && !has_closed_prefix(unwrapped, "blocked")
        && !has_closed_prefix(unwrapped, "restricted")
        && !has_closed_prefix(unwrapped, "invalid")
        && !has_closed_prefix(unwrapped, "bad req")
        && !unwrapped
            .get(..6)
            .is_some_and(|nested| nested.eq_ignore_ascii_case("error:"))
    {
        Unreachable
    } else {
        Restricted
    }
}

async fn strict_fetch_endpoint(
    relay_url: RelayUrl,
    queries: Vec<DirectoryEventQuery>,
) -> DirectoryFetchOutcome {
    // One isolated client owns this connection and its per-REQ finite
    // requests; cancellation or early return closes the relay immediately
    // through `ScopedInspectionClient`.
    let (builder, finite) = FiniteRequests::install(super::nostr_builder());
    let mut owned = ScopedInspectionClient(builder.build(), None);
    let client = &owned.0;
    let endpoint = TransportEndpoint(relay_url.to_string());
    if client.add_relay(relay_url.clone()).await.is_err() {
        return DirectoryFetchOutcome::default();
    }
    let Ok(Some(relay)) = client.relay(relay_url.clone()).await else {
        return DirectoryFetchOutcome::default();
    };
    owned.1 = Some(relay.clone());
    if !matches!(
        timeout(
            DIRECTORY_RELAY_CONNECT_WAIT,
            client
                .try_connect_relay(relay_url)
                .timeout(DIRECTORY_RELAY_CONNECT_WAIT),
        )
        .await,
        Ok(Ok(()))
    ) {
        return DirectoryFetchOutcome::default();
    }
    let mut filters = Vec::with_capacity(queries.len());
    for query in &queries {
        let Ok(filter) = directory_query_filter(query, false) else {
            return DirectoryFetchOutcome::default();
        };
        filters.push(filter);
    }

    let max_records = queries.iter().map(|query| query.limit).sum::<usize>();
    let cancel = CancellationToken::new();
    let limits = FiniteLimits {
        max_items: usize::MAX,
        max_event_bytes: DIRECTORY_REPLY_MAX_BYTES,
        timeout: DIRECTORY_RELAY_FETCH_WAIT,
    };
    let mut records = Vec::new();
    let mut seen_event_ids = HashSet::new();
    let mut complete = true;
    for (queries, filters) in queries
        .chunks(DIRECTORY_MAX_FILTERS_PER_REQ)
        .zip(filters.chunks(DIRECTORY_MAX_FILTERS_PER_REQ))
    {
        let reply = finite
            .fetch(&relay, filters.to_vec(), limits, &cancel)
            .await;
        // Counted per REQ: an event an earlier chunk already returned still
        // fills this chunk's queries toward their limits. Only the returned
        // records are deduplicated across chunks.
        let mut query_counts = vec![0usize; queries.len()];
        let mut converted_all_matched = true;
        let mut record_cap_hit = false;
        for event in &reply.events {
            let Ok(converted) = NostrTransportEvent::from_nostr_event(event) else {
                converted_all_matched = false;
                continue;
            };
            if !queries.iter().any(|query| query.matches(&converted)) {
                converted_all_matched = false;
                continue;
            }
            for (query, count) in queries.iter().zip(&mut query_counts) {
                if query.matches(&converted) {
                    *count += 1;
                }
            }
            if !seen_event_ids.insert(converted.id.clone()) {
                continue;
            }
            if records.len() < max_records {
                records.push(DirectoryRelayEventRecord {
                    endpoints: vec![endpoint.clone()],
                    event: converted,
                });
            } else {
                record_cap_hit = true;
            }
        }
        // A chunk establishes absence only when:
        // - it ended at EOSE without NIP-67 `more` or `auth` withholding hints,
        // - every wire EVENT frame for the REQ passed SDK limits, signature
        //   verification, and filter matching (`raw_items == received_items`),
        // - every kept event converted and matched one of this chunk's queries
        //   without overflowing `max_records`, and
        // - no query reached its requested limit or the silent relay clamp.
        let chunk_complete = reply.end == FiniteEnd::Eose
            && !reply.more
            && !reply.auth
            && reply.raw_items == reply.received_items
            && converted_all_matched
            && !record_cap_hit
            && queries
                .iter()
                .zip(&query_counts)
                .all(|(query, count)| *count < query.limit.min(RELAY_REPLAY_PAGE_LIMIT));
        complete &= chunk_complete;
        if reply.end == FiniteEnd::Disconnected {
            break;
        }
    }
    DirectoryFetchOutcome {
        records,
        complete,
        complete_endpoints: if complete { vec![endpoint] } else { Vec::new() },
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
    use std::sync::atomic::AtomicUsize;

    use super::*;
    use nostr_sdk::prelude::FinalizeEvent;

    enum QueryRelayEnd {
        Eose,
        /// EOSE with NIP-67's `more`: the relay cut its answer short.
        More,
        /// EOSE with NIP-67's `auth` and `finish`: the relay holds events back
        /// until the client authenticates.
        Auth,
        Stalled,
    }

    async fn spawn_query_relay(
        stored: Vec<Event>,
        completion: QueryRelayEnd,
    ) -> (TransportEndpoint, tokio::task::JoinHandle<()>) {
        use futures::SinkExt;
        use tokio::net::TcpListener;
        use tokio_tungstenite::{accept_async, tungstenite::Message};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = TransportEndpoint(format!("ws://{}", listener.local_addr().unwrap()));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = socket.next().await {
                let request: serde_json::Value = match message {
                    Message::Text(text) => serde_json::from_str(&text).unwrap(),
                    Message::Binary(bytes) => serde_json::from_slice(&bytes).unwrap(),
                    Message::Ping(payload) => {
                        socket.send(Message::Pong(payload)).await.unwrap();
                        continue;
                    }
                    _ => continue,
                };
                if request[0] != "REQ" {
                    continue;
                }
                if matches!(completion, QueryRelayEnd::Stalled) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                let kind = request[2]["kinds"][0].as_u64().unwrap();
                let mut replies = stored
                    .iter()
                    .filter(|event| u64::from(event.kind.as_u16()) == kind)
                    .map(|event| serde_json::json!(["EVENT", request[1], event]))
                    .collect::<Vec<_>>();
                match completion {
                    QueryRelayEnd::Eose => replies.push(serde_json::json!(["EOSE", request[1]])),
                    QueryRelayEnd::More => {
                        replies.push(serde_json::json!(["EOSE", request[1], ["more"]]));
                    }
                    QueryRelayEnd::Auth => {
                        replies.push(serde_json::json!(["EOSE", request[1], ["auth", "finish"]]));
                    }
                    QueryRelayEnd::Stalled => {}
                }
                for reply in replies {
                    if socket
                        .send(Message::Text(reply.to_string().into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        });
        (endpoint, server)
    }

    // mdk#1813: two independent three-second reads share the relay wait,
    // retaining delayed events instead of returning the first relay's answer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn query_waits_overlap() {
        use nostr_sdk::prelude::{EventBuilder, Keys};

        let keys = Keys::generate();
        let events = ["healthy", "stalled"]
            .into_iter()
            .flat_map(|content| {
                [1_u16, 7]
                    .into_iter()
                    .map(move |kind| EventBuilder::new(Kind::from(kind), content))
            })
            .map(|builder| builder.finalize(&keys).unwrap())
            .collect::<Vec<_>>();
        let mut expected = events
            .iter()
            .map(|event| event.id.to_hex())
            .collect::<Vec<_>>();
        expected.sort();
        let (healthy, healthy_server) =
            spawn_query_relay(events[..2].to_vec(), QueryRelayEnd::Eose).await;
        let (stalled, stalled_server) =
            spawn_query_relay(events[2..].to_vec(), QueryRelayEnd::Stalled).await;
        let request = DirectoryFetchRequest::new(
            vec![healthy, stalled],
            [1_u64, 7]
                .into_iter()
                .map(|kind| DirectoryEventQuery::new(kind, vec![keys.public_key().to_hex()], 4))
                .collect(),
        )
        .unwrap();
        let result = timeout(
            Duration::from_secs(5),
            NostrSdkDirectoryRelayFetcher::standalone().fetch_directory_events(request),
        )
        .await;
        healthy_server.abort();
        stalled_server.abort();
        let _ = healthy_server.await;
        let _ = stalled_server.await;
        let mut actual = result
            .expect("independent query waits must overlap")
            .unwrap()
            .into_iter()
            .map(|record| record.event.id)
            .collect::<Vec<_>>();
        actual.sort();
        assert_eq!(actual, expected);
    }

    // A public read names every relay that sent each event, so a caller can
    // tell the relays holding a pack from the ones merely queried. A relay
    // that sent a forged copy is never named, and its copy never displaces
    // the genuine one another relay sent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn public_fetch_names_the_relays_behind_each_verified_event() {
        use nostr_sdk::prelude::{EventBuilder, Keys};

        let keys = Keys::generate();
        let [only_a, shared, only_b] = ["a", "shared", "b"].map(|content| {
            EventBuilder::new(Kind::from(1), content)
                .finalize(&keys)
                .unwrap()
        });
        let mut forged = only_b.clone();
        forged.sig = only_a.sig;
        let (relay_a, server_a) = spawn_query_relay(
            vec![only_a.clone(), shared.clone(), forged],
            QueryRelayEnd::Eose,
        )
        .await;
        let (relay_b, server_b) =
            spawn_query_relay(vec![shared.clone(), only_b.clone()], QueryRelayEnd::Eose).await;
        let fetched = timeout(
            Duration::from_secs(5),
            fetch_public_events(
                &[relay_a.clone(), relay_b.clone()],
                vec![Filter::new().kind(Kind::from(1)).author(keys.public_key())],
                16,
            ),
        )
        .await
        .expect("both relays answer")
        .unwrap();
        server_a.abort();
        server_b.abort();
        let _ = server_a.await;
        let _ = server_b.await;

        let spelled = |endpoint: &TransportEndpoint| {
            TransportEndpoint(RelayUrl::parse(endpoint.as_str()).unwrap().to_string())
        };
        let (a, b) = (spelled(&relay_a), spelled(&relay_b));
        let mut ids = fetched
            .events
            .iter()
            .map(|event| event.id)
            .collect::<Vec<_>>();
        ids.sort();
        let mut expected = vec![only_a.id, shared.id, only_b.id];
        expected.sort();
        assert_eq!(ids, expected);
        assert!(
            fetched.events.iter().all(|event| event.verify().is_ok()),
            "the genuine copy is kept"
        );
        assert!(fetched.complete);
        assert_eq!(fetched.sources_of(&only_a.id), std::slice::from_ref(&a));
        let mut shared_from = fetched.sources_of(&shared.id).to_vec();
        shared_from.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        let mut both = vec![a, b.clone()];
        both.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        assert_eq!(shared_from, both);
        assert_eq!(
            fetched.sources_of(&only_b.id),
            [b],
            "the relay that sent a forged copy is not a source"
        );
    }

    // More distinct events than the read may return: it keeps the bound,
    // names sources only for what it kept, and is not complete.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_public_fetch_past_its_bound_is_incomplete() {
        use nostr_sdk::prelude::{EventBuilder, Keys};

        let keys = Keys::generate();
        let events = (0..3)
            .map(|n| {
                EventBuilder::new(Kind::from(1), n.to_string())
                    .custom_created_at(Timestamp::from_secs(1_700_000_000 + n))
                    .finalize(&keys)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let (relay, server) = spawn_query_relay(events.clone(), QueryRelayEnd::Eose).await;
        let fetched = timeout(
            Duration::from_secs(5),
            fetch_public_events(
                std::slice::from_ref(&relay),
                vec![Filter::new().kind(Kind::from(1)).author(keys.public_key())],
                2,
            ),
        )
        .await
        .expect("the relay answers")
        .unwrap();
        server.abort();
        let _ = server.await;
        let kept = fetched
            .events
            .iter()
            .map(|event| event.id)
            .collect::<HashSet<_>>();
        assert_eq!(
            kept,
            HashSet::from([events[1].id, events[2].id]),
            "the newest"
        );
        assert!(!fetched.complete);
        assert_eq!(
            fetched.sources.keys().copied().collect::<HashSet<_>>(),
            kept
        );
    }

    // A relay that sends events the filter does not match before the one it
    // asks for still delivers it, and the read is complete: those frames count
    // toward no cap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_public_fetch_finds_its_event_behind_ones_it_did_not_ask_for() {
        use nostr_sdk::prelude::{EventBuilder, Keys};

        let (other, keys) = (Keys::generate(), Keys::generate());
        let mut stored = (0..2)
            .map(|n| {
                EventBuilder::new(Kind::from(1), n.to_string())
                    .finalize(&other)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let wanted = EventBuilder::new(Kind::from(1), "wanted")
            .finalize(&keys)
            .unwrap();
        stored.push(wanted.clone());
        let (relay, server) = spawn_query_relay(stored, QueryRelayEnd::Eose).await;
        let fetched = timeout(
            Duration::from_secs(5),
            fetch_public_events(
                std::slice::from_ref(&relay),
                vec![
                    Filter::new()
                        .kind(Kind::from(1))
                        .author(keys.public_key())
                        .limit(1),
                ],
                1,
            ),
        )
        .await
        .expect("the relay answers")
        .unwrap();
        server.abort();
        let _ = server.await;
        assert_eq!(fetched.events, vec![wanted]);
        assert!(fetched.complete);
    }

    // The relays of one read share its byte budget: one relay may take more
    // than an even share while the others send nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_public_fetch_lets_one_relay_use_the_read_budget() {
        use nostr_sdk::prelude::{EventBuilder, Keys};

        let keys = Keys::generate();
        let page = (0..30)
            .map(|n| {
                EventBuilder::new(Kind::from(1), format!("{n}{}", "x".repeat(100 * 1024)))
                    .finalize(&keys)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let relays = 8;
        assert!(
            page.iter().map(|e| e.as_json().len()).sum::<usize>()
                > DIRECTORY_REPLY_MAX_BYTES / relays
        );
        let (mut endpoints, mut servers) = (Vec::new(), Vec::new());
        for n in 0..relays {
            let stored = if n == 0 { page.clone() } else { Vec::new() };
            let (endpoint, server) = spawn_query_relay(stored, QueryRelayEnd::Eose).await;
            endpoints.push(endpoint);
            servers.push(server);
        }
        let fetched = timeout(
            Duration::from_secs(10),
            fetch_public_events(
                &endpoints,
                vec![Filter::new().kind(Kind::from(1)).author(keys.public_key())],
                page.len(),
            ),
        )
        .await
        .expect("the relays answer")
        .unwrap();
        for server in servers {
            server.abort();
        }
        assert_eq!(fetched.events.len(), page.len());
        assert!(fetched.complete);
    }

    // A relay that says it has more cut its own answer: what it sent is kept,
    // and the read does not prove it has nothing else.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_public_fetch_a_relay_cut_short_is_incomplete() {
        use nostr_sdk::prelude::{EventBuilder, Keys};

        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::from(1), "kept")
            .finalize(&keys)
            .unwrap();
        // `auth` too: the relay may hold events back from an anonymous read.
        for end in [QueryRelayEnd::More, QueryRelayEnd::Auth] {
            let (relay, server) = spawn_query_relay(vec![event.clone()], end).await;
            let fetched = timeout(
                Duration::from_secs(5),
                fetch_public_events(
                    std::slice::from_ref(&relay),
                    vec![Filter::new().kind(Kind::from(1)).author(keys.public_key())],
                    8,
                ),
            )
            .await
            .expect("the relay answers")
            .unwrap();
            server.abort();
            let _ = server.await;
            assert_eq!(fetched.events, vec![event.clone()]);
            assert!(!fetched.complete);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn anonymous_directory_fetch_accepts_profiles_after_optional_auth_challenge() {
        assert_anonymous_profiles_after_optional_auth_challenge(false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inspection_preserves_auth_and_payment_closed_reasons() {
        use futures::{SinkExt, StreamExt};
        use tokio::net::TcpListener;
        use tokio_tungstenite::{accept_async, tungstenite::Message};

        for (reason, expected) in [
            (
                "auth-required: sign in",
                DirectoryInspectionError::AuthenticationRequired,
            ),
            (
                "payment-required: pay",
                DirectoryInspectionError::PaymentRequired,
            ),
            // mdk#3439: a public relay wraps the NIP-01 prefix in `ERROR: `.
            (
                "ERROR: auth-required: requested filter requires auth",
                DirectoryInspectionError::AuthenticationRequired,
            ),
            (
                "error: payment-required: pay",
                DirectoryInspectionError::PaymentRequired,
            ),
            (
                "rate-limited: slow down",
                DirectoryInspectionError::RateLimited,
            ),
            (
                "error: rate-limited: slow down",
                DirectoryInspectionError::RateLimited,
            ),
            // Unwrapped permanent prefixes stay Restricted; bare `error: <other>`
            // is a transient relay error, while `error:` wrapping a permanent
            // prefix keeps that classification.
            (
                "error: shutting down",
                DirectoryInspectionError::Unreachable,
            ),
            (
                "error: internal failure",
                DirectoryInspectionError::Unreachable,
            ),
            (
                "blocked: auth-required: sign in",
                DirectoryInspectionError::Restricted,
            ),
            (
                "restricted: members only",
                DirectoryInspectionError::Restricted,
            ),
            (
                "bad req: kind not allowed: 10050",
                DirectoryInspectionError::Restricted,
            ),
            (
                "invalid: filter rejected",
                DirectoryInspectionError::Restricted,
            ),
            ("error: blocked: no", DirectoryInspectionError::Restricted),
            ("error: restricted", DirectoryInspectionError::Restricted),
            ("error: blocked", DirectoryInspectionError::Restricted),
            (
                "error: error: auth-required: sign in",
                DirectoryInspectionError::Restricted,
            ),
        ] {
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
                    if request[0] == "REQ" {
                        let closed = serde_json::json!(["CLOSED", request[1], reason]);
                        socket
                            .send(Message::Text(closed.to_string().into()))
                            .await
                            .unwrap();
                    }
                }
            });
            let author = nostr::prelude::Keys::generate().public_key().to_hex();
            let request = DirectoryFetchRequest::new(
                vec![endpoint],
                vec![DirectoryEventQuery::new(0, vec![author], 1)],
            )
            .unwrap();
            let result = timeout(
                Duration::from_secs(5),
                NostrSdkDirectoryRelayFetcher::standalone().inspect_directory_events(request, None),
            )
            .await
            .expect("inspection completes");
            server.abort();
            assert_eq!(result, Err(expected));
        }
    }

    /// How [`spawn_inspection_relay`] answers each REQ.
    #[derive(Clone, Copy)]
    enum InspectionRelay {
        /// Close every REQ until the client authenticates, the way a relay
        /// that wraps the NIP-01 prefix does, sending its challenge (if
        /// `challenge`) after the CLOSED. Answer EOSE once authenticated.
        WrappedAuthRequired { challenge: bool },
        /// Challenge on connect and refuse the client's AUTH, then answer a
        /// REQ with EOSE once it has refused, and either close an inbox REQ
        /// as `auth-required:` or leave it unanswered.
        RefusesAuthOnConnect { closes_inbox: bool },
        /// Answer each REQ with an EOSE carrying this NIP-67 hint.
        SaysHint(&'static str),
        /// After the first authenticated retry, challenge again and hold its REQ open.
        RepeatsChallenge,
        /// After accepting AUTH, answer the retried inbox REQ with an auth hint.
        AuthHintAfterAuthentication,
        /// Accept the WebSocket handshake after the first delay, then answer
        /// each REQ's EOSE after the second.
        Slow { handshake: Duration, eose: Duration },
    }

    /// A loopback relay for one inspection. Returns its endpoint and the
    /// number of REQs it received.
    async fn spawn_inspection_relay(
        script: InspectionRelay,
    ) -> (
        TransportEndpoint,
        Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        use futures::{SinkExt, StreamExt};
        use std::sync::atomic::Ordering;
        use tokio::net::TcpListener;
        use tokio_tungstenite::{accept_async, tungstenite::Message};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = TransportEndpoint(format!("ws://{}", listener.local_addr().unwrap()));
        let reqs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = reqs.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            if let InspectionRelay::Slow { handshake, .. } = script {
                tokio::time::sleep(handshake).await;
            }
            let mut socket = accept_async(stream).await.unwrap();
            let mut authenticated = false;
            let (mut refused, mut held) = (false, Vec::new());
            if matches!(script, InspectionRelay::RefusesAuthOnConnect { .. }) {
                let challenge = serde_json::json!(["AUTH", "connect-challenge"]);
                let _ = socket
                    .send(Message::Text(challenge.to_string().into()))
                    .await;
            }
            while let Some(Ok(message)) = socket.next().await {
                let Message::Text(text) = message else {
                    continue;
                };
                let request: serde_json::Value = serde_json::from_str(&text).unwrap();
                let replies = match (request[0].as_str(), script) {
                    (Some("AUTH"), InspectionRelay::RefusesAuthOnConnect { .. }) => {
                        refused = true;
                        let mut replies = vec![serde_json::json!([
                            "OK",
                            request[1]["id"],
                            false,
                            "restricted: no"
                        ])];
                        replies.append(&mut held);
                        replies
                    }
                    (Some("REQ"), InspectionRelay::RefusesAuthOnConnect { closes_inbox }) => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        if request[2]["kinds"][0] == 1059 {
                            if !closes_inbox {
                                continue;
                            }
                            vec![serde_json::json!([
                                "CLOSED",
                                request[1],
                                "auth-required: sign in"
                            ])]
                        } else if refused {
                            vec![serde_json::json!(["EOSE", request[1]])]
                        } else {
                            held.push(serde_json::json!(["EOSE", request[1]]));
                            continue;
                        }
                    }
                    (Some("AUTH"), _) => {
                        authenticated = true;
                        vec![serde_json::json!(["OK", request[1]["id"], true, ""])]
                    }
                    (Some("REQ"), InspectionRelay::AuthHintAfterAuthentication) => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        if authenticated {
                            vec![serde_json::json!(["EOSE", request[1], ["auth"]])]
                        } else {
                            vec![
                                serde_json::json!(["CLOSED", request[1], "auth-required: sign in"]),
                                serde_json::json!(["AUTH", "inspection-challenge"]),
                                serde_json::json!(["AUTH", "inspection-challenge"]),
                            ]
                        }
                    }
                    (Some("REQ"), InspectionRelay::RepeatsChallenge) => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        if authenticated {
                            vec![serde_json::json!(["AUTH", "second-challenge"])]
                        } else {
                            vec![
                                serde_json::json!(["CLOSED", request[1], "auth-required: sign in"]),
                                serde_json::json!(["AUTH", "first-challenge"]),
                            ]
                        }
                    }
                    (Some("REQ"), InspectionRelay::WrappedAuthRequired { challenge })
                        if !authenticated =>
                    {
                        counted.fetch_add(1, Ordering::SeqCst);
                        let mut replies = vec![serde_json::json!([
                            "CLOSED",
                            request[1],
                            "ERROR: auth-required: requested filter requires auth"
                        ])];
                        if challenge {
                            replies.push(serde_json::json!(["AUTH", "inspection-challenge"]));
                        }
                        replies
                    }
                    (Some("REQ"), InspectionRelay::SaysHint(hint)) => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        vec![serde_json::json!(["EOSE", request[1], [hint]])]
                    }
                    (Some("REQ"), script) => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        if let InspectionRelay::Slow { eose, .. } = script {
                            tokio::time::sleep(eose).await;
                        }
                        vec![serde_json::json!(["EOSE", request[1]])]
                    }
                    _ => continue,
                };
                for reply in replies {
                    if socket
                        .send(Message::Text(reply.to_string().into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        });
        (endpoint, reqs, server)
    }

    async fn inspect_inbox(
        endpoint: TransportEndpoint,
        signer: Option<Arc<dyn transport_nostr_peeler::MarmotNostrSigner>>,
        external_inbox_auth: bool,
    ) -> Result<Vec<DirectoryRelayEventRecord>, DirectoryInspectionError> {
        let recipient = nostr::prelude::Keys::generate().public_key().to_hex();
        let mut query = DirectoryEventQuery::new(1059, vec![recipient], 32);
        if external_inbox_auth {
            query = query.with_external_inbox_auth();
        }
        let request = DirectoryFetchRequest::new(vec![endpoint], vec![query]).unwrap();
        timeout(
            DIRECTORY_INSPECTION_WAIT + Duration::from_secs(1),
            NostrSdkDirectoryRelayFetcher::standalone().inspect_directory_events(request, signer),
        )
        .await
        .expect("inspection ends within its own budget")
    }

    // mdk#3439: the SDK re-sends a REQ after NIP-42 only for a CLOSED whose
    // reason starts with `auth-required:`. The inspection must authenticate
    // and retry a wrapped one itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn signed_inspection_retries_a_wrapped_auth_required_close_after_authenticating() {
        let (endpoint, reqs, server) =
            spawn_inspection_relay(InspectionRelay::WrappedAuthRequired { challenge: true }).await;
        let signer: Arc<dyn transport_nostr_peeler::MarmotNostrSigner> =
            Arc::new(nostr::prelude::Keys::generate());
        let result = inspect_inbox(endpoint.clone(), Some(signer), false).await;
        server.abort();
        assert_eq!(result, Ok(Vec::new()));
        assert_eq!(reqs.load(std::sync::atomic::Ordering::SeqCst), 2);

        // Without a signer there is nothing to retry with.
        let (endpoint, reqs, server) =
            spawn_inspection_relay(InspectionRelay::WrappedAuthRequired { challenge: true }).await;
        let result = inspect_inbox(endpoint, None, false).await;
        server.abort();
        assert_eq!(
            result,
            Err(DirectoryInspectionError::AuthenticationRequired)
        );
        assert_eq!(reqs.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    // mdk#3724: a bare `auth-required:` CLOSED without any AUTH challenge
    // ends as `AuthenticationRequired` after the short challenge grace instead
    // of waiting out the whole EOSE window as `TimedOut`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn signed_inspection_refuses_quickly_when_no_auth_challenge_arrives() {
        let (endpoint, reqs, server) =
            spawn_inspection_relay(InspectionRelay::WrappedAuthRequired { challenge: false }).await;
        let signer: Arc<dyn transport_nostr_peeler::MarmotNostrSigner> =
            Arc::new(nostr::prelude::Keys::generate());
        let started = tokio::time::Instant::now();
        let result = inspect_inbox(endpoint, Some(signer), true).await;
        server.abort();
        assert_eq!(
            result,
            Err(DirectoryInspectionError::AuthenticationRequired)
        );
        assert_eq!(reqs.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            started.elapsed() < DIRECTORY_INSPECTION_EOSE_WAIT / 2,
            "no-challenge auth-required waited {:?}",
            started.elapsed()
        );
    }

    // Verified kind-10002 / kind-10050 records returned before an incomplete
    // NIP-67 hint or CLOSED end are preserved in `Partial { records, cause }`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inspection_preserves_verified_records_returned_before_incomplete_or_closed_end() {
        use futures::{SinkExt, StreamExt};
        use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};
        use tokio::net::TcpListener;
        use tokio_tungstenite::{accept_async, tungstenite::Message};

        let keys = Keys::generate();
        let author = keys.public_key().to_hex();
        let event = EventBuilder::new(Kind::from(10002u16), "")
            .tags([Tag::parse(["r", "wss://relay.example"]).unwrap()])
            .finalize(&keys)
            .unwrap();
        let event_id = event.id.to_hex();

        for (end_frame, budget, expected_cause) in [
            (
                Some(serde_json::json!(["EOSE", "SUB", ["more"]])),
                None,
                DirectoryInspectionError::Incomplete,
            ),
            (
                Some(serde_json::json!(["EOSE", "SUB", ["auth"]])),
                None,
                DirectoryInspectionError::AuthenticationRequired,
            ),
            (
                Some(serde_json::json!([
                    "CLOSED",
                    "SUB",
                    "rate-limited: slow down"
                ])),
                None,
                DirectoryInspectionError::RateLimited,
            ),
            (
                None,
                Some(Duration::from_millis(250)),
                DirectoryInspectionError::TimedOut,
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = TransportEndpoint(format!("ws://{}", listener.local_addr().unwrap()));
            let event_json = serde_json::to_value(&event).unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = accept_async(stream).await.unwrap();
                while let Some(Ok(message)) = socket.next().await {
                    let Message::Text(text) = message else {
                        continue;
                    };
                    let request: serde_json::Value = serde_json::from_str(&text).unwrap();
                    if request[0] == "REQ" {
                        let sub_id = request[1].clone();
                        let ev = serde_json::json!(["EVENT", sub_id, event_json]);
                        socket
                            .send(Message::Text(ev.to_string().into()))
                            .await
                            .unwrap();
                        if let Some(mut end) = end_frame.clone() {
                            end[1] = sub_id;
                            socket
                                .send(Message::Text(end.to_string().into()))
                                .await
                                .unwrap();
                        }
                    }
                }
            });
            let mut request = DirectoryFetchRequest::new(
                vec![endpoint],
                vec![DirectoryEventQuery::new(10002, vec![author.clone()], 4)],
            )
            .unwrap();
            if let Some(budget) = budget {
                request = request.with_inspection_budget(budget);
            }
            let result = timeout(
                Duration::from_secs(5),
                NostrSdkDirectoryRelayFetcher::standalone().inspect_directory_events(request, None),
            )
            .await
            .expect("inspection completes");
            server.abort();
            let (records, cause) = result.unwrap_err().into_parts();
            assert_eq!(cause, expected_cause);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].event.id, event_id);
        }
    }

    // A relay that says it holds more may hold a newer declaration than it sent:
    // `more` is incomplete, while a persistent NIP-67 `auth` hint is an
    // authentication refusal. The inbox probe needs only an answer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inspection_of_a_relay_that_withholds_events_is_incomplete() {
        let author = nostr::prelude::Keys::generate().public_key().to_hex();
        for (hint, expected) in [
            ("more", DirectoryInspectionError::Incomplete),
            ("auth", DirectoryInspectionError::AuthenticationRequired),
        ] {
            let (endpoint, _, server) =
                spawn_inspection_relay(InspectionRelay::SaysHint(hint)).await;
            let request = DirectoryFetchRequest::new(
                vec![endpoint],
                vec![DirectoryEventQuery::new(10002, vec![author.clone()], 4)],
            )
            .unwrap();
            let result = timeout(
                Duration::from_secs(5),
                NostrSdkDirectoryRelayFetcher::standalone().inspect_directory_events(request, None),
            )
            .await
            .expect("inspection completes");
            server.abort();
            assert_eq!(result, Err(expected), "{hint}");

            let (endpoint, _, server) =
                spawn_inspection_relay(InspectionRelay::SaysHint(hint)).await;
            let result = inspect_inbox(endpoint, None, false).await;
            server.abort();
            assert_eq!(result, Ok(Vec::new()), "{hint}");
        }
    }

    use nostr::prelude::UnsignedEvent;
    use transport_nostr_peeler::{MarmotNostrSigner, MarmotSignerError, SignerFuture};

    type SignatureReply<'a, T> = SignerFuture<'a, Result<T, MarmotSignerError>>;

    #[derive(Debug)]
    struct InspectionTestSigner {
        keys: nostr::prelude::Keys,
        calls: std::sync::atomic::AtomicUsize,
        rejects: bool,
    }

    impl MarmotNostrSigner for InspectionTestSigner {
        fn get_public_key(&self) -> SignatureReply<'_, PublicKey> {
            MarmotNostrSigner::get_public_key(&self.keys)
        }

        fn sign_event(&self, event: UnsignedEvent) -> SignatureReply<'_, Event> {
            assert_eq!(event.kind, Kind::from(22242));
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.rejects {
                Box::pin(std::future::ready(Err("signature rejected".into())))
            } else {
                MarmotNostrSigner::sign_event(&self.keys, event)
            }
        }

        fn nip04_encrypt<'a>(&'a self, _: &'a PublicKey, _: &'a str) -> SignatureReply<'a, String> {
            unreachable!("NIP-42 does not encrypt")
        }

        fn nip04_decrypt<'a>(&'a self, _: &'a PublicKey, _: &'a str) -> SignatureReply<'a, String> {
            unreachable!("NIP-42 does not decrypt")
        }

        fn nip44_encrypt<'a>(&'a self, _: &'a PublicKey, _: &'a str) -> SignatureReply<'a, String> {
            unreachable!("NIP-42 does not encrypt")
        }

        fn nip44_decrypt<'a>(&'a self, _: &'a PublicKey, _: &'a str) -> SignatureReply<'a, String> {
            unreachable!("NIP-42 does not decrypt")
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn signed_inspection_reports_a_rejected_signer_request() {
        for relay in [
            InspectionRelay::WrappedAuthRequired { challenge: true },
            InspectionRelay::RefusesAuthOnConnect {
                closes_inbox: false,
            },
        ] {
            let (endpoint, requests, server) = spawn_inspection_relay(relay).await;
            let signer = InspectionTestSigner {
                keys: nostr::prelude::Keys::generate(),
                calls: Default::default(),
                rejects: true,
            };
            let result = inspect_inbox(endpoint, Some(Arc::new(signer)), true).await;
            server.abort();
            assert_eq!(
                result,
                Err(DirectoryInspectionError::AuthenticationSignerFailed)
            );
            assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn signed_inspection_reports_a_matching_auth_refusal_on_timeout() {
        let (endpoint, requests, server) =
            spawn_inspection_relay(InspectionRelay::RefusesAuthOnConnect {
                closes_inbox: false,
            })
            .await;
        let signer = Arc::new(nostr::prelude::Keys::generate());
        let result = inspect_inbox(endpoint, Some(signer), true).await;
        server.abort();
        assert_eq!(
            result,
            Err(DirectoryInspectionError::AuthenticationRejected)
        );
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn signed_inspection_requests_one_signature_when_the_relay_challenges_again() {
        use std::sync::atomic::Ordering;

        let (endpoint, requests, server) =
            spawn_inspection_relay(InspectionRelay::RepeatsChallenge).await;
        let signer = Arc::new(InspectionTestSigner {
            keys: nostr::prelude::Keys::generate(),
            calls: Default::default(),
            rejects: false,
        });
        let result = inspect_inbox(endpoint, Some(signer.clone()), true).await;
        server.abort();
        assert_eq!(result, Err(DirectoryInspectionError::TimedOut));
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        assert_eq!(signer.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inbox_inspection_checks_auth_hints_for_external_signers_only() {
        use std::sync::atomic::Ordering;

        for (external, expected) in [
            (false, Ok(Vec::new())),
            (true, Err(DirectoryInspectionError::AuthenticationRequired)),
        ] {
            let (endpoint, requests, server) =
                spawn_inspection_relay(InspectionRelay::AuthHintAfterAuthentication).await;
            let signer = Arc::new(nostr::prelude::Keys::generate());
            let result = inspect_inbox(endpoint, Some(signer), external).await;
            server.abort();
            assert_eq!(result, expected);
            assert_eq!(requests.load(Ordering::SeqCst), 2);
        }
    }

    // An authentication the relay refused while the client connected, before
    // any query, still decides a later `auth-required:` close: the route is
    // refused, not undecided.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn signed_inspection_sees_an_authentication_refused_on_connect() {
        let (endpoint, reqs, server) =
            spawn_inspection_relay(InspectionRelay::RefusesAuthOnConnect { closes_inbox: true })
                .await;
        let keys = nostr::prelude::Keys::generate();
        let request = DirectoryFetchRequest::new(
            vec![endpoint],
            vec![
                DirectoryEventQuery::new(0, vec![keys.public_key().to_hex()], 1),
                DirectoryEventQuery::new(1059, vec![keys.public_key().to_hex()], 32),
            ],
        )
        .unwrap();
        let result = timeout(
            DIRECTORY_INSPECTION_EOSE_WAIT / 2,
            NostrSdkDirectoryRelayFetcher::standalone()
                .inspect_directory_events(request, Some(Arc::new(keys))),
        )
        .await
        .expect("a refused authentication is not waited out");
        server.abort();
        assert_eq!(
            result,
            Err(DirectoryInspectionError::AuthenticationRejected)
        );
        assert_eq!(reqs.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    // mdk#3439: a healthy relay can take several seconds to finish a gift-wrap
    // query. Onboarding inspection waits longer than the pooled directory
    // reads, and its EOSE window starts once the slow handshake is done.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inspection_waits_past_the_directory_read_window_for_a_slow_eose() {
        // Real time: paused time auto-advances past the connect wait while
        // the loopback handshake is still in flight. Each bound keeps a
        // second or more of slack for a loaded machine.
        let handshake = (DIRECTORY_INSPECTION_EOSE_WAIT - DIRECTORY_RELAY_FETCH_WAIT) * 2 / 5;
        let eose = DIRECTORY_INSPECTION_EOSE_WAIT - handshake / 2;
        assert!(handshake < DIRECTORY_RELAY_CONNECT_WAIT);
        assert!(eose > DIRECTORY_RELAY_FETCH_WAIT);
        assert!(handshake + eose > DIRECTORY_INSPECTION_EOSE_WAIT);
        let (endpoint, _, server) =
            spawn_inspection_relay(InspectionRelay::Slow { handshake, eose }).await;
        let result = inspect_inbox(endpoint, None, false).await;
        server.abort();
        assert_eq!(result, Ok(Vec::new()));
    }

    /// A loopback relay that enforces strfry's REQ shape: it refuses a REQ
    /// with more than `max_filters` filters with `CLOSED invalid:`, and
    /// otherwise answers with `stored` and EOSE. Returns its endpoint and the
    /// filter count of every REQ it received.
    async fn spawn_filter_limited_relay(
        max_filters: usize,
        stored: Vec<serde_json::Value>,
    ) -> (
        TransportEndpoint,
        std::sync::Arc<std::sync::Mutex<Vec<usize>>>,
        tokio::task::JoinHandle<()>,
    ) {
        use futures::{SinkExt, StreamExt};
        use tokio::net::TcpListener;
        use tokio_tungstenite::{accept_async, tungstenite::Message};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = TransportEndpoint(format!("ws://{}", listener.local_addr().unwrap()));
        let filter_counts = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = filter_counts.clone();
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
                let filters = request.as_array().unwrap().len() - 2;
                seen.lock().unwrap().push(filters);
                let mut replies = Vec::new();
                if filters > max_filters {
                    replies.push(serde_json::json!([
                        "CLOSED",
                        request[1],
                        "invalid: too many filters"
                    ]));
                } else {
                    for event in &stored {
                        replies.push(serde_json::json!(["EVENT", request[1], event]));
                    }
                    replies.push(serde_json::json!(["EOSE", request[1]]));
                }
                for reply in replies {
                    if socket
                        .send(Message::Text(reply.to_string().into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        });
        (endpoint, filter_counts, server)
    }

    /// A lookup whose relays send more than its byte budget fails rather than
    /// return what fit: a record past the cut would read as absent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_directory_read_past_its_byte_budget_fails() {
        use nostr_sdk::prelude::{EventBuilder, Keys};

        let keys = Keys::generate();
        let filler = "x".repeat(1024 * 1024);
        let stored = (0..17)
            .map(|n| {
                let event = EventBuilder::new(Kind::Metadata, format!("{n}{filler}"))
                    .custom_created_at(Timestamp::from_secs(1_700_000_000 + n))
                    .finalize(&keys)
                    .unwrap();
                serde_json::to_value(event).unwrap()
            })
            .collect::<Vec<_>>();
        let (endpoint, _, server) = spawn_filter_limited_relay(3, stored).await;
        let request = DirectoryFetchRequest::new(
            vec![endpoint],
            vec![DirectoryEventQuery::new(
                0,
                vec![keys.public_key().to_hex()],
                1,
            )],
        )
        .unwrap();
        let result = timeout(
            Duration::from_secs(10),
            NostrSdkDirectoryRelayFetcher::standalone().fetch_directory_events(request),
        )
        .await
        .expect("the relay answers");
        server.abort();
        assert_eq!(result.unwrap_err(), DIRECTORY_READ_OVER_BUDGET);
    }

    /// A relay that sends an unreadable EVENT before the record asked for
    /// fails the lookup: the record would otherwise read as absent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_directory_read_stopped_by_an_unreadable_frame_fails() {
        use nostr_sdk::prelude::{EventBuilder, Keys};

        let keys = Keys::generate();
        let relays = EventBuilder::new(Kind::RelayList, "")
            .finalize(&keys)
            .unwrap();
        let stored = vec![
            serde_json::json!({"id": "not an event"}),
            serde_json::to_value(&relays).unwrap(),
        ];
        let (endpoint, _, server) = spawn_filter_limited_relay(3, stored).await;
        let request = DirectoryFetchRequest::new(
            vec![endpoint],
            vec![DirectoryEventQuery::new(
                10002,
                vec![keys.public_key().to_hex()],
                1,
            )],
        )
        .unwrap();
        let result = timeout(
            Duration::from_secs(5),
            NostrSdkDirectoryRelayFetcher::standalone().fetch_directory_events(request),
        )
        .await
        .expect("the relay answers");
        server.abort();
        assert_eq!(result.unwrap_err(), DIRECTORY_READ_UNREADABLE);
    }

    /// A relay that ignores the filter and sends other events first still
    /// delivers the event asked for: they count toward no cap of the read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_directory_read_finds_its_event_behind_ones_it_did_not_ask_for() {
        use nostr_sdk::prelude::{EventBuilder, Keys};

        let keys = Keys::generate();
        let mut stored = (0..12)
            .map(|n| {
                let note = EventBuilder::new(Kind::from(1), n.to_string());
                serde_json::to_value(note.finalize(&keys).unwrap()).unwrap()
            })
            .collect::<Vec<_>>();
        let relays = EventBuilder::new(Kind::RelayList, "")
            .finalize(&keys)
            .unwrap();
        stored.push(serde_json::to_value(&relays).unwrap());
        let (endpoint, _, server) = spawn_filter_limited_relay(3, stored).await;
        let request = DirectoryFetchRequest::new(
            vec![endpoint],
            vec![DirectoryEventQuery::new(
                10002,
                vec![keys.public_key().to_hex()],
                1,
            )],
        )
        .unwrap();
        let records = timeout(
            Duration::from_secs(5),
            NostrSdkDirectoryRelayFetcher::standalone().fetch_directory_events(request),
        )
        .await
        .expect("the relay answers")
        .unwrap();
        server.abort();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].event.id, relays.id.to_hex());
    }

    /// Production relays allow at most 3 filters per REQ and refuse more with
    /// `invalid: too many filters`. The strict directory fetch splits a
    /// request's queries into REQs of at most 3 filters on one connection, so
    /// a request with more queries still completes (mdk#2269).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn strict_directory_fetch_splits_queries_into_reqs_of_three_filters() {
        let author = nostr::prelude::Keys::generate().public_key().to_hex();
        for (query_count, expected_reqs) in [
            (2_usize, vec![2_usize]),
            (4, vec![3, 1]),
            (7, vec![3, 3, 1]),
        ] {
            let (endpoint, filter_counts, server) = spawn_filter_limited_relay(3, Vec::new()).await;
            let queries = [0_u64, 3, 10002, 10050, 10000, 10019, 30000]
                .into_iter()
                .take(query_count)
                .map(|kind| DirectoryEventQuery::new(kind, vec![author.clone()], 4))
                .collect();
            let request = DirectoryFetchRequest::new(vec![endpoint], queries).unwrap();
            let outcome = timeout(
                Duration::from_secs(20),
                NostrSdkDirectoryRelayFetcher::standalone()
                    .fetch_directory_events_with_completion(request),
            )
            .await
            .expect("strict fetch completes")
            .unwrap();
            server.abort();
            assert_eq!(*filter_counts.lock().unwrap(), expected_reqs);
            assert!(
                outcome.complete,
                "{query_count} queries split under the filter limit establish absence"
            );
        }
    }

    /// An event an earlier REQ already returned still counts toward a later
    /// REQ's queries. Three `[A]` queries fill the first REQ; an `[A, X]` query
    /// with limit 1 sorts into the second. The relay returns A's one event for
    /// both, so the second REQ's query reaches its limit and cannot establish
    /// absence (mdk#2269).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn strict_directory_fetch_counts_events_shared_across_reqs_per_req() {
        use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys};

        let author = Keys::generate();
        let author_hex = author.public_key().to_hex();
        // Authors are sorted inside a query, so `other` must sort after
        // `author` for `[author, other]` to sort after `[author]` and land in
        // the second REQ.
        let other = loop {
            let candidate = Keys::generate().public_key().to_hex();
            if candidate > author_hex {
                break candidate;
            }
        };
        let event = EventBuilder::new(Kind::TextNote, "shared")
            .finalize(&author)
            .unwrap();
        let (endpoint, filter_counts, server) =
            spawn_filter_limited_relay(3, vec![serde_json::to_value(&event).unwrap()]).await;
        let author = author_hex;
        let mut queries = [10, 11, 12]
            .into_iter()
            .map(|limit| DirectoryEventQuery::new(1, vec![author.clone()], limit))
            .collect::<Vec<_>>();
        queries.push(DirectoryEventQuery::new(1, vec![author, other], 1));
        let request = DirectoryFetchRequest::new(vec![endpoint], queries).unwrap();
        assert_eq!(
            request.queries[3].limit, 1,
            "the limit-1 query sorts into the second REQ"
        );
        let outcome = timeout(
            Duration::from_secs(20),
            NostrSdkDirectoryRelayFetcher::standalone()
                .fetch_directory_events_with_completion(request),
        )
        .await
        .expect("strict fetch completes")
        .unwrap();
        server.abort();
        assert_eq!(*filter_counts.lock().unwrap(), vec![3, 1]);
        assert_eq!(outcome.records.len(), 1, "records stay deduplicated");
        assert!(
            !outcome.complete,
            "the second REQ's query reached its limit"
        );
    }

    /// strfry silently clamps every REQ to 500 stored events and then sends
    /// EOSE. A query whose limit is above the clamp and that receives exactly
    /// the clamp's worth of events may have been cut short, so it cannot
    /// establish absence; one event fewer can (mdk#2269).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn strict_directory_fetch_treats_a_clamp_sized_answer_as_incomplete() {
        use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys};

        let keys = Keys::generate();
        let events = (0..RELAY_REPLAY_PAGE_LIMIT)
            .map(|index| {
                let event = EventBuilder::new(Kind::TextNote, format!("note {index}"))
                    .finalize(&keys)
                    .unwrap();
                serde_json::to_value(&event).unwrap()
            })
            .collect::<Vec<_>>();
        for (stored, expect_complete) in [
            (RELAY_REPLAY_PAGE_LIMIT, false),
            (RELAY_REPLAY_PAGE_LIMIT - 1, true),
        ] {
            let (endpoint, _, server) =
                spawn_filter_limited_relay(3, events[..stored].to_vec()).await;
            let query = DirectoryEventQuery::new(
                1,
                vec![keys.public_key().to_hex()],
                RELAY_REPLAY_PAGE_LIMIT + 100,
            );
            let request = DirectoryFetchRequest::new(vec![endpoint], vec![query]).unwrap();
            let outcome = timeout(
                Duration::from_secs(20),
                NostrSdkDirectoryRelayFetcher::standalone()
                    .fetch_directory_events_with_completion(request),
            )
            .await
            .expect("strict fetch completes")
            .unwrap();
            server.abort();
            assert_eq!(outcome.records.len(), stored);
            assert_eq!(outcome.complete, expect_complete, "{stored} stored events");
        }
    }

    /// Each relay's read is judged on its own: one that reached its end of
    /// stored events is named even when another was cut short, so a caller
    /// can tell what the finished relay does not serve (mdk#2628 3.4).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn strict_directory_fetch_names_each_relay_that_finished() {
        use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys};

        let keys = Keys::generate();
        let events = (0..RELAY_REPLAY_PAGE_LIMIT)
            .map(|index| {
                let event = EventBuilder::new(Kind::TextNote, format!("note {index}"))
                    .finalize(&keys)
                    .unwrap();
                serde_json::to_value(&event).unwrap()
            })
            .collect::<Vec<_>>();
        let (cut_short, _, cut_short_server) = spawn_filter_limited_relay(3, events.clone()).await;
        let (finished, _, finished_server) =
            spawn_filter_limited_relay(3, events[..1].to_vec()).await;
        let query = DirectoryEventQuery::new(
            1,
            vec![keys.public_key().to_hex()],
            RELAY_REPLAY_PAGE_LIMIT + 100,
        );
        let request =
            DirectoryFetchRequest::new(vec![cut_short, finished.clone()], vec![query]).unwrap();
        let outcome = timeout(
            Duration::from_secs(20),
            NostrSdkDirectoryRelayFetcher::standalone()
                .fetch_directory_events_with_completion(request),
        )
        .await
        .expect("strict fetch completes")
        .unwrap();
        cut_short_server.abort();
        finished_server.abort();
        assert!(!outcome.complete);
        let [named] = outcome.complete_endpoints.as_slice() else {
            panic!("{:?}", outcome.complete_endpoints);
        };
        assert!(crate::same_relay(named.as_str(), finished.as_str()));
    }

    /// A relay whose EOSE says NIP-67 `more` or `auth` may not have sent all
    /// it holds: its records are kept, but it does not establish absence.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn strict_directory_fetch_does_not_count_a_relay_that_withholds_events() {
        use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys};

        let keys = Keys::generate();
        let note = EventBuilder::new(Kind::TextNote, "kept")
            .finalize(&keys)
            .unwrap();
        for end in [QueryRelayEnd::More, QueryRelayEnd::Auth] {
            // Only the withholding relay holds the note, so it survives only if
            // that relay's partial page is kept.
            let (partial, partial_server) = spawn_query_relay(vec![note.clone()], end).await;
            let (finished, finished_server) =
                spawn_query_relay(Vec::new(), QueryRelayEnd::Eose).await;
            let query = DirectoryEventQuery::new(1, vec![keys.public_key().to_hex()], 4);
            let request =
                DirectoryFetchRequest::new(vec![partial.clone(), finished.clone()], vec![query])
                    .unwrap();
            let outcome = timeout(
                Duration::from_secs(20),
                NostrSdkDirectoryRelayFetcher::standalone()
                    .fetch_directory_events_with_completion(request),
            )
            .await
            .expect("strict fetch completes")
            .unwrap();
            partial_server.abort();
            finished_server.abort();
            assert!(!outcome.complete);
            let [named] = outcome.complete_endpoints.as_slice() else {
                panic!("{:?}", outcome.complete_endpoints);
            };
            assert!(crate::same_relay(named.as_str(), finished.as_str()));
            let [record] = outcome.records.as_slice() else {
                panic!("{} records", outcome.records.len());
            };
            assert_eq!(record.event.id, note.id.to_hex());
            let [source] = record.endpoints.as_slice() else {
                panic!("{:?}", record.endpoints);
            };
            assert!(crate::same_relay(source.as_str(), partial.as_str()));
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn strict_directory_sdk_tag_drop_cannot_certify_deletion_absence() {
        use futures::{SinkExt, StreamExt};
        use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Tag};
        use tokio::net::TcpListener;
        use tokio_tungstenite::{accept_async, tungstenite::Message};

        let keys = Keys::generate();
        let target = "ab".repeat(32);
        let mut tags = vec![Tag::custom("e", [target.clone()])];
        tags.extend((0..2000).map(|_| Tag::custom("x", ["padding"])));
        let deletion = EventBuilder::new(Kind::from(5), "")
            .tags(tags)
            .finalize(&keys)
            .unwrap();
        assert!(deletion.verify().is_ok());
        assert_eq!(deletion.tags.len(), 2001);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = TransportEndpoint(format!("ws://{}", listener.local_addr().unwrap()));
        let reqs_seen = Arc::new(AtomicUsize::new(0));
        let reqs_seen_server = reqs_seen.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = socket.next().await {
                let text = match message {
                    Message::Text(text) => text,
                    Message::Ping(payload) => {
                        let _ = socket.send(Message::Pong(payload)).await;
                        continue;
                    }
                    _ => continue,
                };
                let request: serde_json::Value = serde_json::from_str(&text).unwrap();
                if request[0] != "REQ" {
                    continue;
                }
                reqs_seen_server.fetch_add(1, Ordering::Relaxed);
                for response in [
                    serde_json::json!(["EVENT", request[1], deletion]),
                    serde_json::json!(["EOSE", request[1]]),
                ] {
                    if socket
                        .send(Message::Text(response.to_string().into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        });
        let request = DirectoryFetchRequest::new(
            vec![endpoint],
            vec![DirectoryEventQuery::deletion_reference(
                &keys.public_key().to_hex(),
                'e',
                target,
                None,
            )],
        )
        .unwrap();
        let outcome = timeout(
            Duration::from_secs(8),
            NostrSdkDirectoryRelayFetcher::standalone()
                .fetch_directory_events_with_completion(request),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(reqs_seen.load(Ordering::Relaxed), 1);
        assert!(
            outcome.records.is_empty(),
            "SDK tag admission limit stays enabled"
        );
        assert!(
            !outcome.complete,
            "a discarded signed deletion cannot become complete empty evidence"
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn strict_directory_invalid_signature_frame_keeps_valid_records_but_not_absence_proof() {
        use futures::{SinkExt, StreamExt};
        use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys};
        use tokio::net::TcpListener;
        use tokio_tungstenite::{accept_async, tungstenite::Message};

        let keys = Keys::generate();
        let valid = EventBuilder::new(Kind::Metadata, r#"{"name":"ok"}"#)
            .finalize(&keys)
            .unwrap();
        let mut forged = serde_json::to_value(
            EventBuilder::new(Kind::Metadata, r#"{"name":"forged"}"#)
                .finalize(&keys)
                .unwrap(),
        )
        .unwrap();
        forged["content"] = serde_json::Value::String(r#"{"name":"tampered"}"#.to_owned());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = TransportEndpoint(format!("ws://{}", listener.local_addr().unwrap()));
        let reqs_seen = Arc::new(AtomicUsize::new(0));
        let reqs_seen_server = reqs_seen.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = socket.next().await {
                let text = match message {
                    Message::Text(text) => text,
                    Message::Ping(payload) => {
                        let _ = socket.send(Message::Pong(payload)).await;
                        continue;
                    }
                    _ => continue,
                };
                let request: serde_json::Value = serde_json::from_str(&text).unwrap();
                if request[0] != "REQ" {
                    continue;
                }
                reqs_seen_server.fetch_add(1, Ordering::Relaxed);
                for response in [
                    serde_json::json!(["EVENT", request[1], valid]),
                    serde_json::json!(["EVENT", request[1], forged]),
                    serde_json::json!(["EOSE", request[1]]),
                ] {
                    if socket
                        .send(Message::Text(response.to_string().into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
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
        let outcome = timeout(
            Duration::from_secs(8),
            NostrSdkDirectoryRelayFetcher::standalone()
                .fetch_directory_events_with_completion(request),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(reqs_seen.load(Ordering::Relaxed), 1);
        assert_eq!(outcome.records.len(), 1);
        assert!(
            !outcome.complete,
            "an invalid-signature EVENT frame must prevent establishing absence"
        );
        assert!(outcome.complete_endpoints.is_empty());
        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    #[test]
    fn scoped_deletion_queries_match_full_predicate_and_keep_distinct_keys() {
        use nostr_sdk::prelude::{EventBuilder, Keys, Tag, Timestamp};
        let keys = Keys::generate();
        let author = keys.public_key().to_hex();
        let id = "12".repeat(32);
        let coordinate = format!("30443:{author}:slot:with:colons");
        let exact = DirectoryEventQuery::deletion_reference(&author, 'e', id.clone(), None);
        let address =
            DirectoryEventQuery::deletion_reference(&author, 'a', coordinate.clone(), Some(100));
        let later =
            DirectoryEventQuery::deletion_reference(&author, 'a', coordinate.clone(), Some(101));
        let endpoint = vec![TransportEndpoint("wss://relay.example".into())];
        assert_ne!(
            DirectoryFetchRequest::new(endpoint.clone(), vec![address.clone()])
                .unwrap()
                .key(),
            DirectoryFetchRequest::new(endpoint.clone(), vec![later.clone()])
                .unwrap()
                .key()
        );
        assert_ne!(
            DirectoryFetchRequest::new(endpoint.clone(), vec![exact.clone()])
                .unwrap()
                .key(),
            DirectoryFetchRequest::new(
                endpoint.clone(),
                vec![DirectoryEventQuery::deletion_reference(
                    &author,
                    'e',
                    "13".repeat(32),
                    None
                )]
            )
            .unwrap()
            .key()
        );
        for timestamp in [99, 100, 101] {
            let event = EventBuilder::new(Kind::from(5), "")
                .tags([
                    Tag::custom("e", [id.clone()]),
                    Tag::custom("a", [coordinate.clone()]),
                ])
                .custom_created_at(Timestamp::from_secs(timestamp))
                .finalize(&keys)
                .unwrap();
            assert!(validated_directory_event(&event, &exact).is_some());
            assert_eq!(
                validated_directory_event(&event, &address).is_some(),
                timestamp >= 100
            );
            assert_eq!(
                validated_directory_event(&event, &later).is_some(),
                timestamp >= 101
            );
        }
        for invalid in [
            DirectoryEventQuery::deletion_reference(&author, 'p', id.clone(), None),
            DirectoryEventQuery::deletion_reference(&author, 'e', id.clone(), Some(1)),
            DirectoryEventQuery::deletion_reference(&author, 'e', "invalid".into(), None),
            DirectoryEventQuery::deletion_reference(
                &author,
                'a',
                format!("30443:{}:slot", "55".repeat(32)),
                Some(1),
            ),
        ] {
            assert!(DirectoryFetchRequest::new(endpoint.clone(), vec![invalid]).is_err());
        }
    }

    #[test]
    fn an_address_query_matches_only_its_author_kind_and_address() {
        use nostr_sdk::prelude::{EventBuilder, Keys, Tag};
        let (alice, bob) = (Keys::generate(), Keys::generate());
        let author = alice.public_key().to_hex();
        let slot = "ab".repeat(32);
        let query = DirectoryEventQuery::key_package_slot(&author, slot.clone(), 4);
        let endpoint = vec![TransportEndpoint("wss://relay.example".into())];
        assert!(DirectoryFetchRequest::new(endpoint.clone(), vec![query.clone()]).is_ok());
        let publication = |keys: &Keys, kind: u16, slot: &str| {
            EventBuilder::new(Kind::from(kind), "")
                .tags([Tag::custom("d", [slot])])
                .finalize(keys)
                .unwrap()
        };
        assert!(validated_directory_event(&publication(&alice, 30443, &slot), &query).is_some());
        let other_slot = "cd".repeat(32);
        assert!(
            validated_directory_event(&publication(&alice, 30443, &other_slot), &query).is_none()
        );
        assert!(validated_directory_event(&publication(&bob, 30443, &slot), &query).is_none());
        assert!(validated_directory_event(&publication(&alice, 1, &slot), &query).is_none());
        let app_data = DirectoryEventQuery::address(30078, &author, slot.clone(), 4);
        assert!(DirectoryFetchRequest::new(endpoint.clone(), vec![app_data.clone()]).is_ok());
        assert!(validated_directory_event(&publication(&alice, 30078, &slot), &app_data).is_some());
        assert!(validated_directory_event(&publication(&alice, 30443, &slot), &app_data).is_none());
        let mut two_authors = query.clone();
        two_authors.authors.push(bob.public_key().to_hex());
        let mut bounded = query.clone();
        bounded.since = Some(1);
        let empty = DirectoryEventQuery::key_package_slot(&author, String::new(), 4);
        let not_addressable = DirectoryEventQuery::address(10002, &author, slot.clone(), 4);
        for invalid in [two_authors, bounded, empty, not_addressable] {
            assert!(DirectoryFetchRequest::new(endpoint.clone(), vec![invalid]).is_err());
        }
    }

    #[test]
    fn key_package_deletion_query_spans_authors_and_matches_only_kind_tagged_requests() {
        use nostr_sdk::prelude::{EventBuilder, Keys, Tag};
        let (alice, bob) = (Keys::generate(), Keys::generate());
        let authors = vec![alice.public_key().to_hex(), bob.public_key().to_hex()];
        let query = DirectoryEventQuery::key_package_deletions(authors, 8);
        let endpoint = vec![TransportEndpoint("wss://relay.example".into())];
        assert!(DirectoryFetchRequest::new(endpoint.clone(), vec![query.clone()]).is_ok());
        let deletion = |keys: &Keys, kind: &str| {
            EventBuilder::new(Kind::from(5), "")
                .tags([
                    Tag::custom("e", ["12".repeat(32)]),
                    Tag::custom("k", [kind]),
                ])
                .finalize(keys)
                .unwrap()
        };
        assert!(validated_directory_event(&deletion(&alice, "30443"), &query).is_some());
        assert!(validated_directory_event(&deletion(&bob, "30443"), &query).is_some());
        assert!(validated_directory_event(&deletion(&bob, "1"), &query).is_none());
        let stranger = deletion(&Keys::generate(), "30443");
        assert!(validated_directory_event(&stranger, &query).is_none());
        let mut other_kind = query.clone();
        other_kind.reference = Some(('k', "1".into()));
        let mut bounded = query;
        bounded.since = Some(1);
        for invalid in [other_kind, bounded] {
            assert!(DirectoryFetchRequest::new(endpoint.clone(), vec![invalid]).is_err());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scoped_deletion_filters_reach_all_sdk_fetch_paths() {
        use futures::{SinkExt, StreamExt};
        use nostr_sdk::prelude::{EventBuilder, Keys, Tag, Timestamp};
        use tokio::net::TcpListener;
        use tokio_tungstenite::{accept_async, tungstenite::Message};
        // Fresh clients for each single filter avoid satisfying a second read
        // from the SDK's local copy instead of inspecting its actual wire REQ.
        for (mode, scope) in [
            (0, 'e'),
            (0, 'a'),
            (1, 'e'),
            (1, 'a'),
            (2, 'e'),
            (2, 'a'),
            (2, 'b'),
            (3, 'b'),
        ] {
            let keys = Keys::generate();
            let author = keys.public_key().to_hex();
            let target = "22".repeat(32);
            let coordinate = format!("30443:{author}:slot");
            let deletion = EventBuilder::new(Kind::from(5), "")
                .tags([
                    Tag::custom(
                        "e",
                        [if mode == 3 {
                            "33".repeat(32)
                        } else {
                            target.clone()
                        }],
                    ),
                    Tag::custom(
                        "a",
                        [if mode == 3 {
                            format!("30443:{author}:other-slot")
                        } else {
                            coordinate.clone()
                        }],
                    ),
                ])
                .custom_created_at(Timestamp::from_secs(100))
                .finalize(&keys)
                .unwrap();
            let expected_id = deletion.id.to_hex();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = TransportEndpoint(format!("ws://{}", listener.local_addr().unwrap()));
            let (sender, mut received) = tokio::sync::mpsc::channel(4);
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
                    sender.send(request.clone()).await.unwrap();
                    let mut responses = vec![serde_json::json!(["EVENT", request[1], deletion])];
                    if mode >= 2 {
                        responses.push(serde_json::json!(["EVENT", request[1], deletion]));
                    }
                    responses.push(serde_json::json!(["EOSE", request[1]]));
                    for response in responses {
                        if socket
                            .send(Message::Text(response.to_string().into()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            });
            let queries = [
                DirectoryEventQuery::deletion_reference(&author, 'e', target.clone(), None),
                DirectoryEventQuery::deletion_reference(
                    &author,
                    'a',
                    coordinate.clone(),
                    Some(100),
                ),
            ]
            .into_iter()
            .filter(|query| scope == 'b' || query.reference.as_ref().unwrap().0 == scope)
            .collect();
            let request = DirectoryFetchRequest::new(vec![endpoint], queries).unwrap();
            let fetcher = NostrSdkDirectoryRelayFetcher::standalone();
            let records = timeout(Duration::from_secs(8), async {
                match mode {
                    0 => fetcher.fetch_directory_events(request).await.unwrap(),
                    1 => fetcher
                        .inspect_directory_events(request, None)
                        .await
                        .unwrap(),
                    _ => {
                        let outcome = fetcher
                            .fetch_directory_events_with_completion(request)
                            .await
                            .unwrap();
                        assert!(
                            !outcome.complete,
                            "positive limit or ignored scoped filter cannot prove absence"
                        );
                        assert_eq!(
                            outcome.records.len(),
                            if mode == 3 { 0 } else { 1 },
                            "duplicates retained once; unrelated records rejected"
                        );
                        outcome.records
                    }
                }
            })
            .await
            .unwrap();
            assert!(records.iter().all(|record| record.event.id == expected_id));
            assert_eq!(records.is_empty(), mode == 3);
            let wire = timeout(Duration::from_secs(1), received.recv())
                .await
                .unwrap()
                .unwrap();
            let filters = &wire.as_array().unwrap()[2..];
            assert_eq!(filters.len(), if scope == 'b' { 2 } else { 1 });
            for filter in filters {
                assert_eq!(filter["limit"], 1);
                assert_eq!(filter["authors"], serde_json::json!([author]));
                if let Some(value) = filter.get("#e") {
                    assert_eq!(*value, serde_json::json!([target]));
                    assert!(filter.get("#a").is_none() && filter.get("since").is_none());
                } else {
                    assert_eq!(filter["#a"], serde_json::json!([coordinate]));
                    assert_eq!(filter["since"], 100);
                }
            }
            fetcher.client.shutdown().await;
            server.abort();
            let _ = server.await;
        }
    }

    /// How [`spawn_inbox_relay`] answers.
    #[derive(Clone, Copy)]
    struct InboxRelay {
        /// Every REQ: CLOSED with this reason, or `None` for an EOSE carrying
        /// NIP-67 `auth`.
        req: Option<&'static str>,
        /// An AUTH challenge after each answer.
        challenge: bool,
        /// The OKs answering each AUTH, in order: whether it names the AUTH
        /// (else some other event), and `None` to accept or the refusal.
        auth_replies: &'static [(bool, Option<&'static str>)],
    }

    async fn spawn_inbox_relay(
        script: InboxRelay,
    ) -> (TransportEndpoint, tokio::task::JoinHandle<()>) {
        use futures::{SinkExt, StreamExt};
        use tokio::net::TcpListener;
        use tokio_tungstenite::{accept_async, tungstenite::Message};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = TransportEndpoint(format!("ws://{}", listener.local_addr().unwrap()));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = socket.next().await {
                let Message::Text(text) = message else {
                    continue;
                };
                let frame: serde_json::Value = serde_json::from_str(&text).unwrap();
                let mut replies = Vec::new();
                match frame[0].as_str() {
                    Some("REQ") => {
                        replies.push(match script.req {
                            Some(reason) => serde_json::json!(["CLOSED", frame[1], reason]),
                            None => serde_json::json!(["EOSE", frame[1], ["auth"]]),
                        });
                        if script.challenge {
                            replies.push(serde_json::json!(["AUTH", "inbox-challenge"]));
                        }
                    }
                    Some("AUTH") => {
                        let other = serde_json::json!("0".repeat(64));
                        for (names_auth, refusal) in script.auth_replies {
                            let id = if *names_auth { &frame[1]["id"] } else { &other };
                            replies.push(match refusal {
                                None => serde_json::json!(["OK", id, true, ""]),
                                Some(reason) => serde_json::json!(["OK", id, false, reason]),
                            });
                        }
                    }
                    _ => {}
                }
                for reply in replies {
                    if socket
                        .send(Message::Text(reply.to_string().into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        });
        (endpoint, server)
    }

    async fn inspect_inbox_strictly(
        endpoint: TransportEndpoint,
    ) -> Result<Vec<DirectoryRelayEventRecord>, DirectoryInspectionError> {
        let keys = nostr::prelude::Keys::generate();
        let request = DirectoryFetchRequest::new(
            vec![endpoint],
            vec![DirectoryEventQuery::new(
                1059,
                vec![keys.public_key().to_hex()],
                1,
            )],
        )
        .unwrap()
        .verifying_inbox();
        timeout(
            DIRECTORY_INSPECTION_WAIT + Duration::from_secs(1),
            NostrSdkDirectoryRelayFetcher::standalone()
                .inspect_directory_events(request, Some(Arc::new(keys))),
        )
        .await
        .expect("an inbox check ends within its own budget")
    }

    /// Relay health's inbox check calls a relay's answer a refusal only where
    /// the relay names one about this account, and never calls an answer it
    /// could not verify served: a close that names no refusal is
    /// `Unexplained`; an AUTH refused for no named policy, an unrelated
    /// refusal before the AUTH's own answer, and an auth-gated EOSE whose AUTH
    /// was refused are all `AuthenticationUnconfirmed`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_inbox_check_names_a_refusal_only_when_the_relay_does() {
        use DirectoryInspectionError::*;
        const NONE: &[(bool, Option<&str>)] = &[];
        let cases: [(&str, InboxRelay, Result<(), DirectoryInspectionError>); 11] = [
            (
                "a close that names nothing",
                InboxRelay {
                    req: Some("ignored"),
                    challenge: false,
                    auth_replies: NONE,
                },
                Err(Unexplained),
            ),
            (
                "restricted",
                InboxRelay {
                    req: Some("restricted: members only"),
                    challenge: false,
                    auth_replies: NONE,
                },
                Err(Restricted),
            ),
            (
                "blocked, wrapped",
                InboxRelay {
                    req: Some("ERROR: blocked: no"),
                    challenge: false,
                    auth_replies: NONE,
                },
                Err(Restricted),
            ),
            (
                "payment",
                InboxRelay {
                    req: Some("payment-required: pay"),
                    challenge: false,
                    auth_replies: NONE,
                },
                Err(PaymentRequired),
            ),
            (
                "rate limit",
                InboxRelay {
                    req: Some("rate-limited: slow down"),
                    challenge: false,
                    auth_replies: NONE,
                },
                Err(RateLimited),
            ),
            (
                "invalid",
                InboxRelay {
                    req: Some("invalid: bad filter"),
                    challenge: false,
                    auth_replies: NONE,
                },
                Err(Unexplained),
            ),
            (
                "AUTH refused for a policy",
                InboxRelay {
                    req: Some("ERROR: auth-required: sign in"),
                    challenge: true,
                    auth_replies: &[(true, Some("restricted: not a member"))],
                },
                Err(AuthenticationRequired),
            ),
            (
                "AUTH rate-limited",
                InboxRelay {
                    req: Some("ERROR: auth-required: sign in"),
                    challenge: true,
                    auth_replies: &[(true, Some("ERROR: rate-limited: slow down"))],
                },
                Err(AuthenticationRateLimited),
            ),
            (
                "AUTH refused for no named policy",
                InboxRelay {
                    req: Some("ERROR: auth-required: sign in"),
                    challenge: true,
                    auth_replies: &[(true, Some("error: temporary backend failure"))],
                },
                Err(AuthenticationUnconfirmed),
            ),
            (
                "an unrelated refusal before the AUTH's own answer",
                InboxRelay {
                    req: Some("ERROR: auth-required: sign in"),
                    challenge: true,
                    auth_replies: &[
                        (false, Some("restricted: not a member")),
                        (true, Some("error: temporary backend failure")),
                    ],
                },
                Err(AuthenticationUnconfirmed),
            ),
            (
                "an auth-gated EOSE whose AUTH was refused",
                InboxRelay {
                    req: None,
                    challenge: true,
                    auth_replies: &[(true, Some("restricted: not a member"))],
                },
                Err(AuthenticationUnconfirmed),
            ),
        ];
        for (case, script, expected) in cases {
            let (endpoint, server) = spawn_inbox_relay(script).await;
            let result = inspect_inbox_strictly(endpoint).await.map(drop);
            server.abort();
            assert_eq!(result, expected, "{case}");
        }
    }

    /// An AUTH challenge the relay sends and never sees through leaves the
    /// read `AuthenticationUnconfirmed` at its deadline: the relay answered,
    /// so the check must not read it as offline. Real time, as for the
    /// slow-EOSE test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_inbox_check_whose_challenge_never_completes_is_unconfirmed() {
        let (endpoint, server) = spawn_inbox_relay(InboxRelay {
            req: Some("ERROR: auth-required: sign in"),
            challenge: true,
            auth_replies: &[],
        })
        .await;
        let result = inspect_inbox_strictly(endpoint).await.map(drop);
        server.abort();
        assert_eq!(
            result,
            Err(DirectoryInspectionError::AuthenticationUnconfirmed)
        );
    }

    /// The latest reply to an AUTH this read signed decides, and a reply to
    /// any other event, or a dropped notification, is no evidence. The SDK
    /// acts on the first reply to an AUTH, so a relay that refuses and then
    /// accepts the same AUTH cannot be ordered deterministically on the wire;
    /// this reads the notification stream directly.
    #[test]
    fn the_latest_reply_to_a_signed_auth_decides() {
        use nostr_sdk::prelude::RelayNotification;
        let auth = EventId::from_slice(&[0; 32]).unwrap();
        let other = EventId::from_slice(&[1; 32]).unwrap();
        let ok = |event_id: EventId, status: bool, reason: &'static str| {
            Ok(RelayNotification::Message {
                message: Box::new(RelayMessage::Ok {
                    event_id,
                    status,
                    message: std::borrow::Cow::Borrowed(reason),
                }),
            })
        };
        let signed = std::sync::Mutex::new(vec![auth]);
        // `Err` is a dropped notification.
        let read = |items: Vec<Result<RelayNotification, ()>>| {
            auth_evidence(&mut futures::stream::iter(items), &signed).reply
        };
        assert!(matches!(
            read(vec![ok(auth, false, "restricted: no"), ok(auth, true, "")]),
            AuthReply::Accepted
        ));
        assert!(matches!(
            read(vec![ok(auth, true, ""), ok(auth, false, "restricted: no")]),
            AuthReply::Refused
        ));
        assert!(matches!(
            read(vec![ok(other, false, "restricted: no")]),
            AuthReply::Unread
        ));
        assert!(matches!(
            read(vec![ok(auth, false, "restricted: no"), Err(()),]),
            AuthReply::Unread
        ));
    }

    /// Local finite-request queue backpressure (`FiniteEnd::Busy`) maps to
    /// `DirectoryInspectionError::LocalBusy`, never `Unreachable` or `TimedOut`.
    #[test]
    fn finite_busy_maps_to_local_busy_not_unreachable() {
        let reply = FiniteReply {
            events: Vec::new(),
            raw_items: 0,
            retried: false,
            received_items: 0,
            duplicates: 0,
            event_bytes: 0,
            kept_event_bytes: 0,
            fetched_bytes: 0,
            more: false,
            auth: false,
            end: FiniteEnd::Busy,
        };
        assert_eq!(
            verified_inbox_answer(&reply, None, false),
            Err(DirectoryInspectionError::LocalBusy)
        );
    }
}
