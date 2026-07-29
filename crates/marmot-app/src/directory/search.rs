//! Streaming user-directory search over the live web of trust.
//!
//! [`MarmotApp::search_users`] answers "who do I know called *foo*" by walking
//! the searcher's own social graph outward and streaming matches as each layer
//! resolves, while a bounded Open Ranking request supplies off-graph discovery.
//! Graph results retain priority and social provenance; only remaining ranked
//! pubkeys are hydrated from signed Nostr profile events.
//!
//! Traversal is bounded by construction, as `AGENTS.md` requires: the radius is
//! capped, relay work per radius is batched author-scoped fetches under a
//! timeout, and the producer stops the moment its consumer drops the
//! subscription. Nothing here writes `directory_users` — strangers surfaced by
//! search stay un-promoted so they can never become live per-author
//! subscriptions (mdk#418).
//!
//! The synchronous [`MarmotApp::search_user_directory`] remains the offline
//! path over already-cached follow edges; this module is the live one.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use cgka_traits::TransportEndpoint;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::cache::{DirectoryCache, DirectorySearchGraphRecord, SEARCH_GRAPH_PROFILE_TTL_SECONDS};
use super::open_ranking::{RankedPubkey, search_ranked_pubkeys};
use super::records::{
    UserDirectoryRecord, UserDirectorySearchResult, latest_follow_list_from_records,
    latest_fresh_profiles_from_records, profile_from_record, user_record_match,
};
use crate::error::AppError;
use crate::ids::{npub_for_account_id_lossy, parse_account_id_hex};
use crate::relay_plane::DirectoryRelayEventRecord as RelayEventRecord;
use crate::runtime::blocking_app_task;
use crate::{
    KIND_NIP65_RELAY_LIST, KIND_NOSTR_CONTACT_LIST, KIND_NOSTR_METADATA, MarmotApp,
    relay_list_state_from_event,
};

/// Deepest radius the traversal producer currently answers.
///
/// Radius 0 is the searcher, 1 their direct follows, 2 follows-of-follows.
///
/// Each layer beyond the first is bounded on both axes the traversal can grow
/// along: [`SEARCH_MAX_CANDIDATES_PER_RADIUS`] caps how many accounts a layer
/// may contribute, and contact lists are read from the device first and
/// otherwise fetched `SEARCH_PUBKEY_BATCH_SIZE` authors at a time, so relay
/// work grows with batches rather than with accounts. Radius 3 is rejected
/// rather than silently answered shallow: it needs the outbox-model tiers
/// (NIP-65 relay lists, per-user write relays) to resolve profiles that far
/// out with acceptable recall.
const MAX_SUPPORTED_SEARCH_RADIUS: u8 = 2;

/// Ceiling on the candidates one radius may contribute to the next layer.
///
/// Follows-of-follows multiplies: a frontier of a few hundred accounts each
/// following a few hundred more reaches six figures. The cap keeps one search
/// bounded by construction; hitting it emits
/// [`SearchUpdateTrigger::RadiusTruncated`] so a short list is never passed
/// off as a complete one.
const SEARCH_MAX_CANDIDATES_PER_RADIUS: usize = 25_000;

/// Updates buffered before the producer waits on a slow consumer.
///
/// Backpressure is deliberate: every update carries results found nowhere
/// else, so the producer must never race ahead and drop them.
const SEARCH_UPDATE_CHANNEL_CAPACITY: usize = 500;

/// Candidate pubkeys resolved per author-scoped relay fetch.
const SEARCH_PUBKEY_BATCH_SIZE: usize = 200;

/// Ceiling on the relay work a single radius may spend.
const SEARCH_RADIUS_TIMEOUT: Duration = Duration::from_secs(300);

/// Reported distance for matches that are not on the searcher's graph at all.
///
/// Every consumer renders `radius` as provenance -- "via someone you follow".
/// When a search falls back to a configured seed, or a discovery provider finds
/// someone outside the graph, that person is not a measurable distance from
/// the searcher. Labelling them radius 1 would make that provenance a lie, so
/// they are reported as off-graph. `u8::MAX` also sorts last, which is where an
/// off-graph match belongs.
pub const OFF_GRAPH_SEARCH_RADIUS: u8 = u8::MAX;

/// How far a layer has walked, and how that distance is reported.
///
/// The two diverge exactly once: after a search falls back to a configured
/// seed, the traversal keeps counting hops so the radius window still bounds
/// it, while every match reports as off-graph because those hops are measured
/// from the seed rather than from the searcher. Carrying them together keeps
/// the pair from being transposed at a call site.
#[derive(Clone, Copy)]
struct LayerDepth {
    /// Hops from the traversal's starting point. Drives loop and window logic.
    hop: u8,
    /// Distance reported to the consumer.
    reported: u8,
}

/// Write relays honoured from any one account's published NIP-65 list.
///
/// A relay list is attacker-controlled, so an account advertising hundreds of
/// relays must not turn one profile lookup into hundreds of connections.
const SEARCH_MAX_WRITE_RELAYS_PER_AUTHOR: usize = 4;

/// Distinct write relays queried while resolving one batch.
///
/// Bounds the outbox tier to a fixed number of round trips no matter how many
/// distinct relays a layer's accounts name between them.
const SEARCH_MAX_WRITE_RELAYS_PER_BATCH: usize = 8;

/// What a search is looking for, and how far out to look.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserSearchParams {
    pub searcher_account_id_hex: String,
    pub query: String,
    /// First radius whose matches are emitted, inclusive.
    pub radius_start: u8,
    /// Last radius whose matches are emitted, inclusive.
    pub radius_end: u8,
    /// Accounts to treat as radius 1 alongside the searcher's own follows.
    ///
    /// The follow graph is not the only evidence that two people know each
    /// other: sharing a group is social proximity even when neither has
    /// followed the other. That membership is live MLS state owned by the
    /// account runtime, not by the directory, so it arrives here as an input
    /// rather than search reaching across the boundary to read it. Callers
    /// without a running runtime simply pass none.
    ///
    /// The searcher is radius 0; naming them here does not move them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub radius_one_seeds: Vec<String>,
}

impl UserSearchParams {
    /// Check the request and return the searcher's canonical pubkey hex.
    fn validate(&self) -> Result<String, AppError> {
        if self.radius_start > self.radius_end {
            return Err(AppError::InvalidDirectorySearch(
                "radius_start must be less than or equal to radius_end".into(),
            ));
        }
        if self.radius_end > MAX_SUPPORTED_SEARCH_RADIUS {
            return Err(AppError::InvalidDirectorySearch(format!(
                "radius_end must be at most {MAX_SUPPORTED_SEARCH_RADIUS}"
            )));
        }
        // Seeds reach an author-scoped fetch that rejects its whole batch on
        // one unparseable id, so a malformed seed would cost the entire
        // traversal rather than itself. This field is public API: rejecting it
        // here tells the caller which input was wrong instead of surfacing a
        // failed search.
        for seed in &self.radius_one_seeds {
            parse_account_id_hex(seed)?;
        }
        parse_account_id_hex(&self.searcher_account_id_hex)
    }
}

/// Why an update was emitted.
///
/// Each variant carries the radius it describes so a consumer can report
/// progress ("searching your follows…") without tracking the traversal itself.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SearchUpdateTrigger {
    /// Traversal began resolving this radius.
    RadiusStarted { radius: u8 },
    /// A batch of matches resolved at this radius.
    ResultsFound { radius: u8 },
    /// A batch produced by the optional off-graph discovery tier after graph
    /// traversal. Individual results retain any graph radius already observed,
    /// but this trigger never reopens a completed radius bucket.
    DiscoveryResultsFound,
    /// This radius finished resolving.
    RadiusCompleted { radius: u8 },
    /// This radius ran out of time; traversal stops here.
    RadiusTimeout { radius: u8 },
    /// Expanding this radius hit the per-radius candidate cap, so the layer
    /// beyond it is a prefix and deeper results are incomplete. Matches
    /// already delivered stay valid.
    RadiusTruncated { radius: u8 },
    /// Terminal: no further updates follow.
    SearchCompleted,
    /// Traversal failed. Always followed by [`Self::SearchCompleted`].
    Error { message: String },
}

/// One incremental step of a running search.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct UserSearchUpdate {
    pub trigger: SearchUpdateTrigger,
    /// Matches discovered by this step, pre-sorted within the batch. Ordering
    /// *across* graph updates is radius order; an optional discovery batch
    /// follows graph traversal and may contain results retaining graph
    /// provenance. Flat-list consumers should re-sort the aggregate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub new_results: Vec<UserDirectorySearchResult>,
    /// Running total emitted by this search so far, including `new_results`.
    pub total_result_count: usize,
}

/// A live search. Dropping it cancels the traversal.
#[derive(Debug)]
pub struct UserSearchSubscription {
    updates: mpsc::Receiver<UserSearchUpdate>,
}

impl UserSearchSubscription {
    /// Await the next update, or `None` once the search is over.
    ///
    /// `None` follows [`SearchUpdateTrigger::SearchCompleted`]; a consumer may
    /// stop at either signal.
    pub async fn next_update(&mut self) -> Option<UserSearchUpdate> {
        self.updates.recv().await
    }
}

impl MarmotApp {
    /// Start a streaming search across the searcher's web of trust.
    ///
    /// Returns as soon as the traversal is spawned; matches arrive through
    /// [`UserSearchSubscription::next_update`]. Dropping the subscription stops
    /// the traversal at its next checkpoint.
    pub async fn search_users(
        &self,
        params: UserSearchParams,
    ) -> Result<UserSearchSubscription, AppError> {
        let searcher_account_id_hex = params.validate()?;
        let (updates_tx, updates) = mpsc::channel(SEARCH_UPDATE_CHANNEL_CAPACITY);
        let app = self.clone();
        tokio::spawn(async move {
            run_search(app, searcher_account_id_hex, params, updates_tx).await;
        });
        Ok(UserSearchSubscription { updates })
    }
}

/// Drive one search to completion, reporting a failure as an update rather
/// than losing it: the caller holds a subscription, not a `Result`.
async fn run_search(
    app: MarmotApp,
    searcher_account_id_hex: String,
    params: UserSearchParams,
    updates_tx: mpsc::Sender<UserSearchUpdate>,
) {
    let mut emitter = SearchEmitter::new(updates_tx);
    // An empty query would match every candidate through `contains`, so it
    // finds nobody by definition rather than everybody.
    let query = params.query.trim().to_lowercase();
    if !query.is_empty() {
        let open_ranking_search_endpoint =
            app.service_endpoints().open_ranking_search_endpoint.clone();
        let open_ranking_profile_relays = app
            .service_endpoints()
            .open_ranking_profile_relays
            .iter()
            .cloned()
            .map(TransportEndpoint)
            .collect::<Vec<_>>();
        let open_ranking_search_endpoint =
            open_ranking_search_endpoint.filter(|_| !open_ranking_profile_relays.is_empty());
        // Start the independent discovery request with the graph walk, but
        // merge its results afterwards. That gives a graph result precedence
        // when both sources return the same identity, without holding a
        // mutable emitter across concurrent tasks.
        let discovery_updates_tx = emitter.updates_tx.clone();
        let (graph_result, ranked_pubkeys) = tokio::join!(
            traverse_graph(
                &app,
                &searcher_account_id_hex,
                &query,
                &params,
                &mut emitter,
            ),
            fetch_open_ranking_pubkeys(
                &query,
                open_ranking_search_endpoint.as_deref(),
                discovery_updates_tx,
            ),
        );
        if let Err(error) = graph_result {
            emitter
                .emit(SearchUpdateTrigger::Error {
                    message: error.to_string(),
                })
                .await;
        }
        let remaining = emitter.remaining_ranked_pubkeys(ranked_pubkeys, params.radius_start);
        if !remaining.is_empty() && !emitter.is_cancelled() {
            let hydration_updates_tx = emitter.updates_tx.clone();
            let hydration = tokio::select! {
                _ = hydration_updates_tx.closed() => None,
                result = hydrate_open_ranking_profiles(
                    &app,
                    remaining,
                    &open_ranking_profile_relays,
                ) => Some(result),
            };
            match hydration {
                None => {}
                Some(Ok(records)) => {
                    emitter.tally.resolved_from_open_ranking(records.len());
                    emitter.emit_ranked_matches(records, &query).await;
                }
                Some(Err(_)) => {
                    tracing::debug!(
                        target: "marmot_app::directory",
                        method = "search_users_open_ranking_hydrate",
                        outcome = "fetch_failed",
                        "Open Ranking profile hydration unavailable"
                    );
                }
            }
        }
    }
    emitter.emit(SearchUpdateTrigger::SearchCompleted).await;
    emitter.report_tally(&params);
}

/// Fetch ranked identities from Vertex without exposing failures to the graph
/// traversal or logging the query.
async fn fetch_open_ranking_pubkeys(
    query: &str,
    endpoint: Option<&str>,
    updates_tx: mpsc::Sender<UserSearchUpdate>,
) -> Vec<RankedPubkey> {
    let Some(endpoint) = endpoint else {
        return Vec::new();
    };
    let result = tokio::select! {
        _ = updates_tx.closed() => return Vec::new(),
        result = search_ranked_pubkeys(endpoint, query) => result,
    };
    match result {
        Ok(ranked_pubkeys) => ranked_pubkeys,
        Err(_) => {
            tracing::debug!(
                target: "marmot_app::directory",
                method = "search_users_open_ranking",
                outcome = "fetch_failed",
                "Open Ranking user discovery unavailable"
            );
            Vec::new()
        }
    }
}

/// Hydrate ranked pubkeys in one bounded, author-scoped kind-0 query against
/// Vertex's directory relay.
///
/// The ranked response itself is derived data. Profiles still come from signed
/// Nostr events and pass through the relay-plane safety, signature, kind, and
/// freshness checks. Nothing in this path is persisted.
async fn hydrate_open_ranking_profiles(
    app: &MarmotApp,
    ranked_pubkeys: Vec<RankedPubkey>,
    profile_relays: &[TransportEndpoint],
) -> Result<Vec<RankedDirectoryRecord>, AppError> {
    let account_ids = ranked_pubkeys
        .iter()
        .map(|ranked| ranked.account_id_hex.clone())
        .collect::<Vec<_>>();
    let records = app
        .fetch_events_for_account_ids(&account_ids, KIND_NOSTR_METADATA, profile_relays)
        .await?;
    let mut profiles = latest_fresh_profiles_from_records(records, app.directory_freshness()).value;
    Ok(ranked_pubkeys
        .into_iter()
        .filter_map(|ranked| {
            let profile = profiles.remove(&ranked.account_id_hex)?;
            let mut record = app.empty_directory_record(&ranked.account_id_hex);
            record.profile = Some(profile);
            Some(RankedDirectoryRecord {
                record,
                rank: ranked.rank,
            })
        })
        .collect())
}

struct RankedDirectoryRecord {
    record: UserDirectoryRecord,
    rank: f64,
}

/// Walk outward from the searcher, emitting each radius as it resolves.
async fn traverse_graph(
    app: &MarmotApp,
    searcher_account_id_hex: &str,
    query: &str,
    params: &UserSearchParams,
    emitter: &mut SearchEmitter,
) -> Result<(), AppError> {
    let mut frontier = vec![searcher_account_id_hex.to_owned()];
    let mut seen: HashSet<String> = frontier.iter().cloned().collect();
    // Set once the traversal leaves the searcher's own graph for a configured
    // seed. From then on every layer reports as off-graph, however many hops
    // it has walked: the hop count is a distance from the seed, not from the
    // searcher, and only the latter is what `radius` promises.
    let mut off_graph = false;

    for radius in 0..=params.radius_end {
        if frontier.is_empty() || emitter.is_cancelled() {
            break;
        }
        let depth = LayerDepth {
            hop: radius,
            reported: if off_graph {
                OFF_GRAPH_SEARCH_RADIUS
            } else {
                radius
            },
        };
        emitter
            .emit(SearchUpdateTrigger::RadiusStarted {
                radius: depth.reported,
            })
            .await;
        emitter.remember_graph_accounts(depth.reported, &frontier);

        // One timeout per radius, covering every relay round trip the radius
        // makes: resolving its profiles and reading the follow lists that
        // become the next layer.
        let advance = advance_radius(app, &frontier, query, depth, params, &mut seen, emitter);
        frontier = match timeout(SEARCH_RADIUS_TIMEOUT, advance).await {
            Ok(result) => result?,
            Err(_elapsed) => {
                emitter
                    .emit(SearchUpdateTrigger::RadiusTimeout {
                        radius: depth.reported,
                    })
                    .await;
                return Ok(());
            }
        };
        emitter
            .emit(SearchUpdateTrigger::RadiusCompleted {
                radius: depth.reported,
            })
            .await;

        // The searcher's own graph is exhausted at its first layer: they follow
        // nobody and share no group. Fall back to the configured seeds rather
        // than answering "nothing" forever -- but only here, so a searcher with
        // any graph of their own is never given a stranger's.
        if radius == 0 && frontier.is_empty() {
            frontier = fallback_seed_frontier(app, &mut seen);
            off_graph = !frontier.is_empty();
        }
    }
    Ok(())
}

/// The configured fallback seeds that are usable and not already visited.
///
/// Malformed entries are skipped rather than failing the search: a seed list is
/// deployment configuration for a best-effort last resort, and a typo in it
/// should cost that one seed, not every search on the device.
fn fallback_seed_frontier(app: &MarmotApp, seen: &mut HashSet<String>) -> Vec<String> {
    app.directory_search_fallback_seeds()
        .iter()
        .filter_map(|seed| parse_account_id_hex(seed).ok())
        .filter(|seed| seen.insert(seed.clone()))
        .collect()
}

/// Emit one radius's matches and return the layer beyond it.
async fn advance_radius(
    app: &MarmotApp,
    frontier: &[String],
    query: &str,
    depth: LayerDepth,
    params: &UserSearchParams,
    seen: &mut HashSet<String>,
    emitter: &mut SearchEmitter,
) -> Result<Vec<String>, AppError> {
    // Radii below the requested window are traversed but not reported: they
    // are only the path to the layers the caller did ask for, so resolving
    // their profiles would be relay traffic for results nobody receives.
    if depth.hop >= params.radius_start {
        resolve_layer(app, frontier, query, depth.reported, emitter).await?;
    }
    if depth.hop == params.radius_end {
        return Ok(Vec::new());
    }

    let mut layer = NextLayer::default();
    // Seeded accounts are radius 1 alongside the searcher's own follows, and
    // are admitted first: sharing a group is at least as strong a signal of
    // closeness as a follow, so a long follow list must not crowd them out of
    // the per-radius cap.
    if depth.hop == 0 {
        layer.admit(params.radius_one_seeds.clone(), seen);
    }
    extend_with_follows(app, frontier, seen, &mut layer).await?;
    if layer.truncated {
        emitter
            .emit(SearchUpdateTrigger::RadiusTruncated {
                radius: depth.reported,
            })
            .await;
    }
    Ok(layer.candidates)
}

/// Resolve one layer's profiles and emit its matches.
///
/// On-device records are matched first so cached hits stream immediately; only
/// the remainder costs a relay round trip. Neither pass promotes anybody into
/// `directory_users`.
async fn resolve_layer(
    app: &MarmotApp,
    frontier: &[String],
    query: &str,
    radius: u8,
    emitter: &mut SearchEmitter,
) -> Result<(), AppError> {
    let now = crate::unix_now_seconds() as i64;
    let (local, missing) = partition_locally_known(app, frontier, now).await?;
    emitter.tally.resolved_from_cache(local.len());
    emitter.emit_matches(radius, local, query).await;

    for batch in missing.chunks(SEARCH_PUBKEY_BATCH_SIZE) {
        if emitter.is_cancelled() {
            return Ok(());
        }
        let fetched = fetch_profile_records(app, batch).await?;
        let (resolved, mut pending): (Vec<_>, Vec<_>) = fetched
            .into_iter()
            .partition(|record| record.profile.is_some());
        emitter.tally.resolved_from_relays(resolved.len());
        cache_resolved_profiles(app, &resolved, now).await?;
        emitter.emit_matches(radius, resolved, query).await;

        // Everyone still unresolved publishes nowhere the searcher reads. Ask
        // the relays they say they write to -- the outbox model, and the only
        // way to reach someone whose profile never leaves their own relays.
        //
        // Held back rather than emitted alongside the resolved ones: the
        // matcher also matches npub and pubkey hex, so a profile-less record
        // can match a query on its own and would then be reported twice, once
        // empty and once resolved. One person is one result, however many tiers
        // it took.
        if !pending.is_empty() && !emitter.is_cancelled() {
            let account_ids = pending
                .iter()
                .map(|record| record.account_id_hex.clone())
                .collect::<Vec<_>>();
            let outboxed = resolve_from_write_relays(app, &account_ids).await?;
            emitter.tally.resolved_from_write_relays(outboxed.len());
            cache_resolved_profiles(app, &outboxed, now).await?;
            replace_resolved_profiles(&mut pending, outboxed);
        }

        // Still profile-less, and emitted anyway: the matcher can match their
        // npub or pubkey hex, so dropping them would make a search for a
        // follow's npub miss somebody whose profile simply is not published.
        emitter
            .tally
            .unresolved(pending.iter().filter(|r| r.profile.is_none()).count());
        emitter.emit_matches(radius, pending, query).await;
    }
    Ok(())
}

/// Fold outbox-resolved profiles back into the records awaiting them, so each
/// account is carried by exactly one record.
fn replace_resolved_profiles(
    pending: &mut [UserDirectoryRecord],
    outboxed: Vec<UserDirectoryRecord>,
) {
    let mut profiles = outboxed
        .into_iter()
        .filter_map(|record| {
            record
                .profile
                .map(|profile| (record.account_id_hex, profile))
        })
        .collect::<HashMap<_, _>>();
    for record in pending {
        if let Some(profile) = profiles.remove(&record.account_id_hex) {
            record.profile = Some(profile);
        }
    }
}

/// Resolve profiles from the authors' own NIP-65 write relays.
///
/// Each relay is asked only about the authors who published it, so a relay
/// learns nothing about accounts that never named it. Bounded on both axes
/// that could otherwise grow with the graph: at most
/// [`SEARCH_MAX_WRITE_RELAYS_PER_AUTHOR`] relays are taken from any one list,
/// and at most [`SEARCH_MAX_WRITE_RELAYS_PER_BATCH`] relays are queried per
/// batch, widest coverage first.
async fn resolve_from_write_relays(
    app: &MarmotApp,
    account_ids: &[String],
) -> Result<Vec<UserDirectoryRecord>, AppError> {
    let mut authors_by_relay: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for record in app
        .fetch_events_for_account_ids(account_ids, KIND_NIP65_RELAY_LIST, &[])
        .await?
    {
        let Some((account_id_hex, relays)) = write_relays_from_record(app, record) else {
            continue;
        };
        for relay in relays.into_iter().take(SEARCH_MAX_WRITE_RELAYS_PER_AUTHOR) {
            authors_by_relay
                .entry(relay)
                .or_default()
                .push(account_id_hex.clone());
        }
    }
    if authors_by_relay.is_empty() {
        return Ok(Vec::new());
    }

    // Widest coverage first, so a per-batch cap keeps the relays that answer
    // for the most people rather than an arbitrary few.
    let mut by_coverage = authors_by_relay.into_iter().collect::<Vec<_>>();
    by_coverage.sort_by_key(|(relay, authors)| (Reverse(authors.len()), relay.clone()));

    let mut resolved = Vec::new();
    for (relay, authors) in by_coverage
        .into_iter()
        .take(SEARCH_MAX_WRITE_RELAYS_PER_BATCH)
    {
        let endpoint = vec![TransportEndpoint(relay)];
        let profiles = app
            .fetch_events_for_account_ids(&authors, KIND_NOSTR_METADATA, &endpoint)
            .await?
            .into_iter()
            .filter_map(profile_from_record)
            .collect::<HashMap<_, _>>();
        for (account_id_hex, profile) in profiles {
            let mut record = app.empty_directory_record(&account_id_hex);
            record.profile = Some(profile);
            resolved.push(record);
        }
    }
    Ok(resolved)
}

/// The safe write relays a `kind:10002` record publishes, if any.
///
/// Relay URLs here are another account's data, so they are filtered through
/// the same host-safety rule configured endpoints face; one unusable entry
/// drops itself rather than the whole list.
fn write_relays_from_record(
    app: &MarmotApp,
    record: RelayEventRecord,
) -> Option<(String, Vec<String>)> {
    let account_id_hex = record.event.pubkey.clone();
    let relay_list = relay_list_state_from_event(&record.event)?;
    let safe = app.retain_safe_discovered_endpoints(
        relay_list
            .write_relays
            .into_iter()
            .map(TransportEndpoint)
            .collect(),
    );
    (!safe.is_empty()).then(|| {
        (
            account_id_hex,
            safe.into_iter().map(|endpoint| endpoint.0).collect(),
        )
    })
}

/// Keep the profiles this layer resolved so the next search for the same
/// people is warm.
///
/// Writes to the un-promoted search-graph tier only, never `directory_users`:
/// answering a search is not a relationship, and a promoted stranger would
/// become a live per-author subscription (mdk#418).
///
/// Only records that actually carry a profile are written. A pubkey that came
/// back empty is left uncached rather than recorded as "has no profile" --
/// see [`SEARCH_GRAPH_PROFILE_TTL_SECONDS`] for why that absence is not
/// trustworthy enough to persist.
async fn cache_resolved_profiles(
    app: &MarmotApp,
    records: &[UserDirectoryRecord],
    now: i64,
) -> Result<(), AppError> {
    let resolved = records
        .iter()
        .filter(|record| record.profile.is_some())
        .map(|record| DirectorySearchGraphRecord {
            account_id_hex: record.account_id_hex.clone(),
            npub: record.npub.clone(),
            profile: record.profile.clone(),
            // This layer resolved profiles, not contact lists. `None` leaves
            // any follow edges already recorded for them untouched.
            follows: None,
            metadata_updated_at: record.profile.as_ref().map(|profile| profile.created_at),
            metadata_expires_at: Some((now + SEARCH_GRAPH_PROFILE_TTL_SECONDS) as u64),
        })
        .collect::<Vec<_>>();
    if resolved.is_empty() {
        return Ok(());
    }

    let app = app.clone();
    blocking_app_task(move || {
        for cache in app.directory_caches()? {
            for record in &resolved {
                cache.put_search_graph_record(record, now)?;
            }
        }
        Ok(())
    })
    .await
}

/// Split a layer into records the device can already match and pubkeys that
/// still need a profile fetched. A cached record without a profile counts as
/// needing one.
///
/// Reads both tiers: the promoted directory for accounts the user has actually
/// interacted with, then the un-promoted search graph for strangers an earlier
/// search resolved. The second tier is what makes a repeat search warm; its
/// profiles expire, so a hit here is fresh by construction.
async fn partition_locally_known(
    app: &MarmotApp,
    frontier: &[String],
    now: i64,
) -> Result<(Vec<UserDirectoryRecord>, Vec<String>), AppError> {
    let app = app.clone();
    let frontier = frontier.to_vec();
    blocking_app_task(move || {
        let caches = app.directory_caches()?;
        let shared_storage = app.shared_storage()?;
        let mut known = Vec::new();
        let mut missing = Vec::new();
        for account_id_hex in frontier {
            let promoted = app.directory_entry_for_account_id_with_handles(
                &account_id_hex,
                &caches,
                &shared_storage,
            )?;
            let record = match promoted {
                Some(record) if record.profile.is_some() => Some(record),
                _ => search_graph_profile(&caches, &account_id_hex, now)?,
            };
            match record {
                Some(record) => known.push(record),
                None => missing.push(account_id_hex),
            }
        }
        Ok((known, missing))
    })
    .await
}

/// The first un-promoted search-graph record carrying an unexpired profile.
///
/// Reads the search graph directly rather than through
/// [`DirectoryCache::search_record`]. That helper answers from the promoted
/// directory first, and the only callers who reach here have already found a
/// promoted row without a profile -- so going through it would hand the same
/// profile-less row straight back and hide the cached profile behind it.
fn search_graph_profile(
    caches: &[DirectoryCache],
    account_id_hex: &str,
    now: i64,
) -> Result<Option<UserDirectoryRecord>, AppError> {
    for cache in caches {
        if let Some(record) = cache.search_graph_record(account_id_hex, now)?
            && record.profile.is_some()
        {
            return Ok(Some(record));
        }
    }
    Ok(None)
}

/// Fetch `kind:0` profiles for one batch of pubkeys and shape the batch into
/// in-memory records.
///
/// Every pubkey yields a record, whether or not a profile came back: the
/// matcher also matches on npub and pubkey hex, so dropping the unresolved
/// ones would make an npub search miss a follow whose profile simply is not
/// published anywhere. Deliberately ephemeral — nothing is persisted, so a
/// stranger surfaced by search cannot enter the promoted directory tier.
async fn fetch_profile_records(
    app: &MarmotApp,
    batch: &[String],
) -> Result<Vec<UserDirectoryRecord>, AppError> {
    let mut profiles = app
        .fetch_events_for_account_ids(batch, KIND_NOSTR_METADATA, &[])
        .await?
        .into_iter()
        .filter_map(profile_from_record)
        .collect::<HashMap<_, _>>();
    Ok(batch
        .iter()
        .map(|account_id_hex| {
            let mut record = app.empty_directory_record(account_id_hex);
            record.profile = profiles.remove(account_id_hex);
            record
        })
        .collect())
}

/// Add the follow lists of the current layer into the next one, skipping
/// anybody already visited.
async fn extend_with_follows(
    app: &MarmotApp,
    frontier: &[String],
    seen: &mut HashSet<String>,
    layer: &mut NextLayer,
) -> Result<(), AppError> {
    let (cached, unknown) = partition_cached_follows(app, frontier).await?;

    // Pass 1: contact lists already on the device. No relay round trip, so the
    // next layer starts forming immediately.
    for follows in cached {
        if !layer.admit(follows, seen) {
            return Ok(());
        }
    }

    // Pass 2: everyone whose contact list has never been seen, one batched
    // author-scoped fetch per `SEARCH_PUBKEY_BATCH_SIZE` rather than a round
    // trip each. What comes back is cached, so the next search skips this pass.
    for batch in unknown.chunks(SEARCH_PUBKEY_BATCH_SIZE) {
        let fetched = fetch_follow_lists(app, batch).await?;
        cache_resolved_follows(app, &fetched).await?;
        for (_, follows) in fetched {
            if !layer.admit(follows, seen) {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Where one search's profiles came from.
///
/// The caches exist on the claim that a warm search avoids relay work; this is
/// how that claim gets checked in the field instead of assumed. Counts only --
/// never an account id, a relay, or the query, per the privacy invariant in
/// `AGENTS.md`.
#[derive(Default)]
struct SearchTally {
    /// Answered from the device: the promoted directory or the search graph.
    from_cache: usize,
    /// Needed a `kind:0` fetch from the searcher's own relays.
    from_relays: usize,
    /// Reachable only through the author's advertised write relays.
    from_write_relays: usize,
    /// Hydrated from the bounded, ephemeral Open Ranking discovery request.
    from_open_ranking: usize,
    /// No tier produced a profile. Still matchable by npub or pubkey.
    unresolved: usize,
}

impl SearchTally {
    fn resolved_from_cache(&mut self, count: usize) {
        self.from_cache += count;
    }

    fn resolved_from_relays(&mut self, count: usize) {
        self.from_relays += count;
    }

    fn resolved_from_write_relays(&mut self, count: usize) {
        self.from_write_relays += count;
    }

    fn resolved_from_open_ranking(&mut self, count: usize) {
        self.from_open_ranking += count;
    }

    fn unresolved(&mut self, count: usize) {
        self.unresolved += count;
    }
}

/// The candidates one radius contributes to the next, and whether the
/// per-radius cap cut them short.
#[derive(Default)]
struct NextLayer {
    candidates: Vec<String>,
    /// The cap was reached, so this layer is a prefix of the real one and
    /// everything beyond it is incomplete. Reported rather than swallowed: a
    /// caller shown a short list should know it is short.
    truncated: bool,
}

impl NextLayer {
    /// Take `follows` into the layer, skipping anyone already visited. Returns
    /// `false` once the cap is reached and nothing further can be admitted.
    fn admit(&mut self, follows: Vec<String>, seen: &mut HashSet<String>) -> bool {
        for follow in follows {
            if self.candidates.len() >= SEARCH_MAX_CANDIDATES_PER_RADIUS {
                self.truncated = true;
                return false;
            }
            if seen.insert(follow.clone()) {
                self.candidates.push(follow);
            }
        }
        true
    }
}

/// Split a layer into the contact lists already cached and the accounts whose
/// contact list has never been observed.
async fn partition_cached_follows(
    app: &MarmotApp,
    frontier: &[String],
) -> Result<(Vec<Vec<String>>, Vec<String>), AppError> {
    let app = app.clone();
    let frontier = frontier.to_vec();
    blocking_app_task(move || {
        let caches = app.directory_caches()?;
        let mut cached = Vec::new();
        let mut unknown = Vec::new();
        for account_id_hex in frontier {
            let mut follows = None;
            for cache in &caches {
                if let Some(known) = cache.search_graph_follows(&account_id_hex)? {
                    follows = Some(known);
                    break;
                }
            }
            match follows {
                Some(follows) => cached.push(follows),
                None => unknown.push(account_id_hex),
            }
        }
        Ok((cached, unknown))
    })
    .await
}

/// Fetch one batch of contact lists in a single author-scoped request and pick
/// each author's latest list.
///
/// Only authors a contact list actually came back for are returned. An author
/// the relays said nothing about is omitted rather than reported as following
/// nobody: the two are indistinguishable here, and recording the guess would
/// make a relay hiccup a permanent dead end in the graph. A list that came back
/// carrying no `p` tags *is* an authoritative "follows nobody" and is kept.
async fn fetch_follow_lists(
    app: &MarmotApp,
    batch: &[String],
) -> Result<Vec<(String, Vec<String>)>, AppError> {
    let records = app
        .fetch_events_for_account_ids(batch, KIND_NOSTR_CONTACT_LIST, &[])
        .await?;
    let mut by_author: HashMap<String, Vec<RelayEventRecord>> = HashMap::new();
    for record in records {
        by_author
            .entry(record.event.pubkey.clone())
            .or_default()
            .push(record);
    }
    let freshness = app.directory_freshness();
    Ok(batch
        .iter()
        .filter_map(|account_id_hex| {
            let records = by_author.remove(account_id_hex)?;
            let follows = latest_follow_list_from_records(account_id_hex, records, freshness)
                .value?
                .follows;
            Some((account_id_hex.clone(), follows))
        })
        .collect())
}

/// Keep the contact lists this layer fetched, so the next search expands from
/// the device instead of the network.
///
/// Un-promoted, exactly like [`cache_resolved_profiles`]: recording that
/// somebody follows somebody is graph data, not a relationship of the user's.
async fn cache_resolved_follows(
    app: &MarmotApp,
    fetched: &[(String, Vec<String>)],
) -> Result<(), AppError> {
    let fetched = fetched.to_vec();
    let app = app.clone();
    blocking_app_task(move || {
        for cache in app.directory_caches()? {
            for (account_id_hex, follows) in &fetched {
                cache.remember_search_graph_follows(
                    account_id_hex,
                    &npub_for_account_id_lossy(account_id_hex),
                    follows,
                )?;
            }
        }
        Ok(())
    })
    .await
}

/// Sends updates to the subscription and keeps the running result total.
struct SearchEmitter {
    updates_tx: mpsc::Sender<UserSearchUpdate>,
    total_result_count: usize,
    emitted_account_ids: HashSet<String>,
    graph_radii: HashMap<String, u8>,
    tally: SearchTally,
}

impl SearchEmitter {
    fn new(updates_tx: mpsc::Sender<UserSearchUpdate>) -> Self {
        Self {
            updates_tx,
            total_result_count: 0,
            emitted_account_ids: HashSet::new(),
            graph_radii: HashMap::new(),
            tally: SearchTally::default(),
        }
    }

    /// Whether the consumer has dropped the subscription, which is how a
    /// search is cancelled.
    fn is_cancelled(&self) -> bool {
        self.updates_tx.is_closed()
    }

    fn remember_graph_accounts(&mut self, radius: u8, account_ids: &[String]) {
        for account_id in account_ids {
            self.graph_radii.entry(account_id.clone()).or_insert(radius);
        }
    }

    fn remaining_ranked_pubkeys(
        &self,
        ranked_pubkeys: Vec<RankedPubkey>,
        radius_start: u8,
    ) -> Vec<RankedPubkey> {
        ranked_pubkeys
            .into_iter()
            .filter(|ranked| {
                !self.emitted_account_ids.contains(&ranked.account_id_hex)
                    && self
                        .graph_radii
                        .get(&ranked.account_id_hex)
                        .is_none_or(|radius| *radius >= radius_start)
            })
            .collect()
    }

    /// Match a resolved layer against the query and emit whatever hit.
    async fn emit_matches(&mut self, radius: u8, records: Vec<UserDirectoryRecord>, query: &str) {
        let mut results = records
            .into_iter()
            .filter_map(|record| {
                let search_match = user_record_match(&record, query)?;
                Some(UserDirectorySearchResult {
                    account_id_hex: record.account_id_hex,
                    npub: record.npub,
                    radius,
                    matched_field: search_match.field,
                    match_quality: search_match.quality,
                    provider_rank: None,
                    profile: record.profile,
                })
            })
            .collect::<Vec<_>>();
        results.retain(|result| {
            self.emitted_account_ids
                .insert(result.account_id_hex.clone())
        });
        if results.is_empty() {
            return;
        }
        sort_user_search_results(&mut results);
        self.emit_results(SearchUpdateTrigger::ResultsFound { radius }, results)
            .await;
    }

    /// Emit hydrated Open Ranking matches, retaining graph provenance for any
    /// ranked identity already encountered during traversal.
    async fn emit_ranked_matches(&mut self, records: Vec<RankedDirectoryRecord>, query: &str) {
        let mut results = Vec::new();
        for ranked in records {
            let Some(search_match) = user_record_match(&ranked.record, query) else {
                continue;
            };
            let radius = self
                .graph_radii
                .get(&ranked.record.account_id_hex)
                .copied()
                .unwrap_or(OFF_GRAPH_SEARCH_RADIUS);
            let provider_rank = (radius == OFF_GRAPH_SEARCH_RADIUS).then_some(ranked.rank);
            let result = UserDirectorySearchResult {
                account_id_hex: ranked.record.account_id_hex,
                npub: ranked.record.npub,
                radius,
                matched_field: search_match.field,
                match_quality: search_match.quality,
                provider_rank,
                profile: ranked.record.profile,
            };
            if self
                .emitted_account_ids
                .insert(result.account_id_hex.clone())
            {
                results.push(result);
            }
        }
        if !results.is_empty() {
            sort_user_search_results(&mut results);
            self.emit_results(SearchUpdateTrigger::DiscoveryResultsFound, results)
                .await;
        }
    }

    /// Report where this search's profiles came from, once, at the end.
    ///
    /// The point is to make the caching claim falsifiable in the field: if
    /// `from_cache` stays near zero on repeat searches, the warm path is not
    /// working. Counts and the requested radii only — no account id, relay, or
    /// query text, per the privacy invariant.
    fn report_tally(&self, params: &UserSearchParams) {
        tracing::debug!(
            target: "marmot_app::directory",
            method = "search_users",
            radius_start = params.radius_start,
            radius_end = params.radius_end,
            from_cache = self.tally.from_cache,
            from_relays = self.tally.from_relays,
            from_write_relays = self.tally.from_write_relays,
            from_open_ranking = self.tally.from_open_ranking,
            unresolved = self.tally.unresolved,
            matches = self.total_result_count,
            "user search finished"
        );
    }

    async fn emit(&mut self, trigger: SearchUpdateTrigger) {
        self.emit_results(trigger, Vec::new()).await;
    }

    /// Awaits the send so a slow consumer applies backpressure instead of
    /// losing results. A closed channel means the consumer is gone; the next
    /// cancellation checkpoint winds the traversal down, so that send failing
    /// is the expected end of a cancelled search rather than an error.
    async fn emit_results(
        &mut self,
        trigger: SearchUpdateTrigger,
        new_results: Vec<UserDirectorySearchResult>,
    ) {
        self.total_result_count += new_results.len();
        let _ = self
            .updates_tx
            .send(UserSearchUpdate {
                trigger,
                new_results,
                total_result_count: self.total_result_count,
            })
            .await;
    }
}

/// Rank results best-first: nearest radius, then provider rank for discovery
/// results, then local match strength, matched field, and pubkey for stability.
///
/// Public because a streaming consumer has to re-rank for itself. Updates
/// arrive pre-sorted *within* a batch, but a search emits several batches per
/// radius (cached first, then fetched), so anything that accumulates the whole
/// stream must sort the aggregate to recover this order.
pub fn sort_user_search_results(results: &mut [UserDirectorySearchResult]) {
    results.sort_by(|a, b| {
        a.radius
            .cmp(&b.radius)
            .then_with(|| match (a.provider_rank, b.provider_rank) {
                (Some(left), Some(right)) => right.total_cmp(&left),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            })
            .then_with(|| a.match_quality.cmp(&b.match_quality))
            .then_with(|| a.matched_field.cmp(&b.matched_field))
            .then_with(|| a.account_id_hex.cmp(&b.account_id_hex))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AccountRelayListStatus;
    use crate::ids::npub_for_account_id_lossy;
    use crate::{MatchQuality, MatchedField, UserProfileMetadata};
    use marmot_account::AccountHome;

    /// A cached directory record for `account_id_hex` whose profile name is
    /// `name`, so it resolves entirely on-device.
    fn record_named(account_id_hex: &str, name: &str) -> UserDirectoryRecord {
        UserDirectoryRecord {
            account_id_hex: account_id_hex.to_owned(),
            npub: npub_for_account_id_lossy(account_id_hex),
            local_account: None,
            profile: Some(crate::UserProfileMetadata {
                name: Some(name.to_owned()),
                ..Default::default()
            }),
            follows: Vec::new(),
            follow_source_relays: Vec::new(),
            relay_lists: AccountRelayListStatus::empty(),
            key_package: None,
        }
    }

    fn params(searcher_account_id_hex: &str, query: &str, radii: (u8, u8)) -> UserSearchParams {
        UserSearchParams {
            searcher_account_id_hex: searcher_account_id_hex.to_owned(),
            query: query.to_owned(),
            radius_start: radii.0,
            radius_end: radii.1,
            radius_one_seeds: Vec::new(),
        }
    }

    /// Drain a subscription into every update it emits.
    async fn drain(mut subscription: UserSearchSubscription) -> Vec<UserSearchUpdate> {
        let mut updates = Vec::new();
        while let Some(update) = subscription.next_update().await {
            updates.push(update);
        }
        updates
    }

    #[tokio::test]
    async fn rejects_a_radius_deeper_than_the_producer_answers() {
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let searcher = format!("{:064x}", 1);

        let error = app
            .search_users(params(
                &searcher,
                "needle",
                (0, MAX_SUPPORTED_SEARCH_RADIUS + 1),
            ))
            .await
            .expect_err("a radius past the supported depth must not be answered shallowly");

        assert!(matches!(error, AppError::InvalidDirectorySearch(_)));
    }

    #[tokio::test]
    async fn rejects_an_inverted_radius_window() {
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let searcher = format!("{:064x}", 1);

        let error = app
            .search_users(params(&searcher, "needle", (1, 0)))
            .await
            .expect_err("radius_start past radius_end is not a searchable window");

        assert!(matches!(error, AppError::InvalidDirectorySearch(_)));
    }

    #[tokio::test]
    async fn an_empty_query_completes_without_matching_everybody() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let cache = app.directory_cache_for_account(&account).unwrap();
        cache
            .put(&record_named(&account.account_id_hex, "alice"))
            .unwrap();

        let subscription = app
            .search_users(params(&account.account_id_hex, "   ", (0, 0)))
            .await
            .unwrap();
        let updates = drain(subscription).await;

        // A blank query is a `contains` match against every record, so it must
        // short-circuit to completion rather than stream the whole directory.
        assert_eq!(
            updates
                .iter()
                .map(|update| update.trigger.clone())
                .collect::<Vec<_>>(),
            vec![SearchUpdateTrigger::SearchCompleted]
        );
        assert_eq!(updates[0].total_result_count, 0);
    }

    #[tokio::test]
    async fn streams_a_cached_radius_zero_match_through_the_full_update_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        assert!(
            app.service_endpoints()
                .open_ranking_search_endpoint
                .is_none(),
            "dev/test convenience constructors must never call a live provider"
        );
        let cache = app.directory_cache_for_account(&account).unwrap();
        cache
            .put(&record_named(&account.account_id_hex, "needle"))
            .unwrap();

        // Radius 0..0 resolves the searcher from cache and expands no frontier,
        // so the whole search completes without contacting a relay.
        let subscription = app
            .search_users(params(&account.account_id_hex, "needle", (0, 0)))
            .await
            .unwrap();
        let updates = drain(subscription).await;

        assert_eq!(
            updates
                .iter()
                .map(|update| update.trigger.clone())
                .collect::<Vec<_>>(),
            vec![
                SearchUpdateTrigger::RadiusStarted { radius: 0 },
                SearchUpdateTrigger::ResultsFound { radius: 0 },
                SearchUpdateTrigger::RadiusCompleted { radius: 0 },
                SearchUpdateTrigger::SearchCompleted,
            ]
        );

        let found = updates
            .iter()
            .find(|update| !update.new_results.is_empty())
            .expect("the cached match must be streamed");
        assert_eq!(found.new_results.len(), 1);
        assert_eq!(found.new_results[0].account_id_hex, account.account_id_hex);
        assert_eq!(found.new_results[0].radius, 0);
        assert_eq!(found.new_results[0].matched_field, MatchedField::Name);
        assert_eq!(found.new_results[0].match_quality, MatchQuality::Exact);
        // The running total is cumulative and survives to the terminal update.
        assert_eq!(found.total_result_count, 1);
        assert_eq!(updates.last().unwrap().total_result_count, 1);
    }

    /// The whole point of Phase 2: a stranger resolved by an earlier search
    /// lives only in the un-promoted search-graph tier, and a later search must
    /// match them from there rather than paying for the relay round trip again.
    /// `MarmotApp::with_relay` points at an address nothing answers, so a
    /// result here can only have come from the cache.
    #[tokio::test]
    async fn a_search_matches_a_stranger_cached_in_the_un_promoted_tier() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let stranger = format!("{:064x}", 77);
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.invalid");
        let cache = app.directory_cache_for_account(&account).unwrap();
        let now = crate::unix_now_seconds() as i64;

        // The searcher's own follow list is promoted (it is the local account's
        // own contact list, not a stranger's), so radius 1 expands offline.
        // What is deliberately *not* promoted is the stranger's profile.
        cache
            .put(&UserDirectoryRecord {
                follows: vec![stranger.clone()],
                ..record_named(&account.account_id_hex, "alice")
            })
            .unwrap();
        cache
            .put_search_graph_record(
                &DirectorySearchGraphRecord {
                    account_id_hex: stranger.clone(),
                    npub: npub_for_account_id_lossy(&stranger),
                    profile: Some(UserProfileMetadata {
                        name: Some("needle".to_owned()),
                        ..UserProfileMetadata::default()
                    }),
                    follows: None,
                    metadata_updated_at: Some(now as u64),
                    metadata_expires_at: Some((now + SEARCH_GRAPH_PROFILE_TTL_SECONDS) as u64),
                },
                now,
            )
            .unwrap();

        let subscription = app
            .search_users(params(&account.account_id_hex, "needle", (1, 1)))
            .await
            .unwrap();
        let updates = drain(subscription).await;

        let matched = updates
            .iter()
            .flat_map(|update| &update.new_results)
            .find(|result| result.account_id_hex == stranger)
            .expect("the un-promoted cached profile must be searchable");
        assert_eq!(matched.radius, 1);
        assert_eq!(matched.matched_field, MatchedField::Name);
    }

    /// A profile resolved from a relay to answer a search is kept, so the next
    /// search for the same person is warm -- and it is kept in the un-promoted
    /// tier only. Caching a stranger must never turn them into a directory
    /// entry, because that is what feeds live per-author subscriptions
    /// (mdk#418). The `entry` assertion is the guard on that.
    #[tokio::test]
    async fn a_profile_resolved_from_a_relay_is_cached_without_promoting_the_stranger() {
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let relay_url = relay.url().await.to_string();

        // The stranger publishes a profile from their own device. This needs a
        // real signing identity, not a bare account row -- the profile is a
        // signed kind:0 the searcher will fetch back off the relay.
        let endpoint = cgka_traits::TransportEndpoint(relay_url.clone());
        let stranger_dir = tempfile::tempdir().unwrap();
        let stranger_app = MarmotApp::with_relay(stranger_dir.path(), relay_url.clone());
        let stranger = stranger_app
            .runtime()
            .create_identity(crate::AccountSetupRequest {
                default_relays: vec![endpoint.clone()],
                bootstrap_relays: vec![endpoint.clone()],
                publish_missing_relay_lists: true,
                ..crate::AccountSetupRequest::default()
            })
            .await
            .expect("create the stranger's identity")
            .account;
        stranger_app
            .publish_user_profile(
                &stranger.account_id_hex,
                UserProfileMetadata {
                    name: Some("needle".to_owned()),
                    ..UserProfileMetadata::default()
                },
                crate::AccountRelayListBootstrap::new(vec![endpoint.clone()], Vec::new()),
            )
            .await
            .expect("publish the stranger's profile");

        // The searcher follows them but has never cached their profile.
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), relay_url);
        let cache = app.directory_cache_for_account(&account).unwrap();
        cache
            .put(&UserDirectoryRecord {
                follows: vec![stranger.account_id_hex.clone()],
                ..record_named(&account.account_id_hex, "alice")
            })
            .unwrap();

        let subscription = app
            .search_users(params(&account.account_id_hex, "needle", (1, 1)))
            .await
            .unwrap();
        let updates = drain(subscription).await;
        assert!(
            updates
                .iter()
                .flat_map(|update| &update.new_results)
                .any(|result| result.account_id_hex == stranger.account_id_hex),
            "the search must resolve the stranger from the relay: {updates:?}"
        );

        let now = crate::unix_now_seconds() as i64;
        let cached = cache
            .search_record(&stranger.account_id_hex, now)
            .unwrap()
            .expect("the resolved profile must be cached for the next search");
        assert_eq!(
            cached.profile.and_then(|profile| profile.name),
            Some("needle".to_owned())
        );
        assert!(
            cache.entry(&stranger.account_id_hex).unwrap().is_none(),
            "caching a search result must not promote them into directory_users"
        );
    }

    /// Radius 2 is follows-of-follows. Both hops here are already on the
    /// device, so the whole traversal must complete against an unreachable
    /// relay -- that is what "Pass 1 reads cached follows" buys, and it is the
    /// only reason a second radius is affordable.
    #[tokio::test]
    async fn radius_two_expands_through_cached_follow_edges_without_a_relay() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let friend = format!("{:064x}", 61);
        let stranger = format!("{:064x}", 62);
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.invalid");
        let cache = app.directory_cache_for_account(&account).unwrap();
        let now = crate::unix_now_seconds() as i64;

        // alice -> friend (promoted, her own contact list)
        cache
            .put(&UserDirectoryRecord {
                follows: vec![friend.clone()],
                ..record_named(&account.account_id_hex, "alice")
            })
            .unwrap();
        // friend -> stranger, cached un-promoted by an earlier traversal.
        cache
            .remember_search_graph_follows(
                &friend,
                &npub_for_account_id_lossy(&friend),
                std::slice::from_ref(&stranger),
            )
            .unwrap();
        cache
            .put_search_graph_record(
                &DirectorySearchGraphRecord {
                    account_id_hex: stranger.clone(),
                    npub: npub_for_account_id_lossy(&stranger),
                    profile: Some(UserProfileMetadata {
                        name: Some("needle".to_owned()),
                        ..UserProfileMetadata::default()
                    }),
                    follows: None,
                    metadata_updated_at: Some(now as u64),
                    metadata_expires_at: Some((now + SEARCH_GRAPH_PROFILE_TTL_SECONDS) as u64),
                },
                now,
            )
            .unwrap();

        let subscription = app
            .search_users(params(&account.account_id_hex, "needle", (2, 2)))
            .await
            .unwrap();
        let updates = drain(subscription).await;

        let matched = updates
            .iter()
            .flat_map(|update| &update.new_results)
            .find(|result| result.account_id_hex == stranger)
            .expect("a follow-of-a-follow must be reachable at radius 2");
        assert_eq!(matched.radius, 2);
    }

    /// An account whose contact list the relays never returned must stay
    /// *unknown*, not be recorded as following nobody. Recording the guess
    /// turns a relay hiccup into a permanent dead end, because cached follow
    /// edges do not expire.
    #[tokio::test]
    async fn an_unanswered_contact_list_is_not_cached_as_following_nobody() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let friend = format!("{:064x}", 71);
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.invalid");
        let cache = app.directory_cache_for_account(&account).unwrap();

        cache
            .put(&UserDirectoryRecord {
                follows: vec![friend.clone()],
                ..record_named(&account.account_id_hex, "alice")
            })
            .unwrap();

        // Radius 2 makes the traversal ask for the friend's contact list. The
        // relay is unreachable, so nothing comes back for them.
        let subscription = app
            .search_users(params(&account.account_id_hex, "needle", (2, 2)))
            .await
            .unwrap();
        drain(subscription).await;

        assert_eq!(
            cache.search_graph_follows(&friend).unwrap(),
            None,
            "an unanswered contact list must stay re-fetchable"
        );
    }

    /// The tally exists to answer one question -- do the caches earn their
    /// keep -- so it has to attribute each resolution to the tier that actually
    /// produced it, and count the people no tier could resolve.
    #[test]
    fn the_tally_attributes_each_profile_to_the_tier_that_resolved_it() {
        let mut tally = SearchTally::default();

        tally.resolved_from_cache(3);
        tally.resolved_from_relays(2);
        tally.resolved_from_write_relays(1);
        tally.resolved_from_open_ranking(5);
        tally.unresolved(4);
        // A second layer accumulates rather than replacing.
        tally.resolved_from_cache(1);

        assert_eq!(tally.from_cache, 4);
        assert_eq!(tally.from_relays, 2);
        assert_eq!(tally.from_write_relays, 1);
        assert_eq!(tally.from_open_ranking, 5);
        assert_eq!(tally.unresolved, 4);
    }

    #[tokio::test]
    async fn discovery_does_not_repeat_a_graph_result() {
        let (updates_tx, mut updates_rx) = mpsc::channel(2);
        let mut emitter = SearchEmitter::new(updates_tx);
        let account_id_hex = format!("{:064x}", 97);
        let record = record_named(&account_id_hex, "needle");

        emitter
            .emit_matches(1, vec![record.clone()], "needle")
            .await;
        let remaining = emitter.remaining_ranked_pubkeys(
            vec![RankedPubkey {
                account_id_hex,
                rank: 1.0,
            }],
            0,
        );
        assert!(
            remaining.is_empty(),
            "an emitted graph identity must be removed before hydration"
        );
        drop(emitter);

        let update = updates_rx
            .recv()
            .await
            .expect("the graph result should be emitted");
        assert_eq!(update.new_results.len(), 1);
        assert_eq!(update.new_results[0].radius, 1);
        assert!(
            updates_rx.recv().await.is_none(),
            "discovery must not emit the identity already found in the graph"
        );
    }

    #[test]
    fn discovery_does_not_reintroduce_a_graph_radius_below_the_requested_window() {
        let (updates_tx, _updates_rx) = mpsc::channel(1);
        let mut emitter = SearchEmitter::new(updates_tx);
        let searcher = format!("{:064x}", 96);
        emitter.remember_graph_accounts(0, std::slice::from_ref(&searcher));

        let remaining = emitter.remaining_ranked_pubkeys(
            vec![RankedPubkey {
                account_id_hex: searcher,
                rank: 1.0,
            }],
            1,
        );

        assert!(
            remaining.is_empty(),
            "discovery must preserve the requested graph radius window"
        );
    }

    #[tokio::test]
    async fn open_ranking_profiles_keep_graph_provenance_and_stay_ephemeral() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.invalid");
        let account_id_hex = format!("{:064x}", 98);
        let (updates_tx, mut updates_rx) = mpsc::channel(2);
        let mut emitter = SearchEmitter::new(updates_tx);
        emitter.remember_graph_accounts(1, std::slice::from_ref(&account_id_hex));
        emitter
            .emit_ranked_matches(
                vec![RankedDirectoryRecord {
                    record: record_named(&account_id_hex, "needle"),
                    rank: 0.75,
                }],
                "needle",
            )
            .await;

        let update = updates_rx.recv().await.expect("ranked result");
        assert_eq!(update.trigger, SearchUpdateTrigger::DiscoveryResultsFound);
        assert_eq!(update.new_results[0].radius, 1);
        assert_eq!(
            update.new_results[0].provider_rank, None,
            "graph provenance wins over provider ranking metadata"
        );
        assert!(
            app.directory_entries().unwrap().is_empty(),
            "an Open Ranking result must remain an ephemeral search candidate"
        );
    }

    /// A layer that overflows the candidate cap is a prefix of the real one.
    /// The traversal must say so rather than let a short result list pass for a
    /// complete one.
    #[test]
    fn an_overflowing_layer_is_reported_as_truncated() {
        let mut seen = HashSet::new();
        let mut layer = NextLayer::default();

        let admitted = layer.admit(
            (0..SEARCH_MAX_CANDIDATES_PER_RADIUS + 1)
                .map(|index| format!("{index:064x}"))
                .collect(),
            &mut seen,
        );

        assert!(!admitted, "the cap must stop admitting candidates");
        assert!(layer.truncated);
        assert_eq!(layer.candidates.len(), SEARCH_MAX_CANDIDATES_PER_RADIUS);
    }

    /// Already-visited accounts are skipped rather than counted, so revisiting
    /// a dense graph cannot exhaust the cap on duplicates alone.
    #[test]
    fn a_layer_admits_each_account_once() {
        let mut seen = HashSet::new();
        let mut layer = NextLayer::default();
        let repeated = format!("{:064x}", 9);

        assert!(layer.admit(vec![repeated.clone(), repeated.clone()], &mut seen));
        assert!(layer.admit(vec![repeated], &mut seen));

        assert_eq!(layer.candidates.len(), 1);
        assert!(!layer.truncated);
    }

    /// Someone you share a group with is socially close even if neither of you
    /// has followed the other, so a caller can seed them into radius 1. The
    /// seeded account here is in no follow list at all -- only the seed puts
    /// them within reach.
    #[tokio::test]
    async fn a_seeded_account_is_searchable_at_radius_one_without_being_followed() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let co_member = format!("{:064x}", 81);
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.invalid");
        let cache = app.directory_cache_for_account(&account).unwrap();
        let now = crate::unix_now_seconds() as i64;

        cache
            .put_search_graph_record(
                &DirectorySearchGraphRecord {
                    account_id_hex: co_member.clone(),
                    npub: npub_for_account_id_lossy(&co_member),
                    profile: Some(UserProfileMetadata {
                        name: Some("needle".to_owned()),
                        ..UserProfileMetadata::default()
                    }),
                    follows: None,
                    metadata_updated_at: Some(now as u64),
                    metadata_expires_at: Some((now + SEARCH_GRAPH_PROFILE_TTL_SECONDS) as u64),
                },
                now,
            )
            .unwrap();

        let subscription = app
            .search_users(UserSearchParams {
                radius_one_seeds: vec![co_member.clone()],
                ..params(&account.account_id_hex, "needle", (1, 1))
            })
            .await
            .unwrap();
        let updates = drain(subscription).await;

        let matched = updates
            .iter()
            .flat_map(|update| &update.new_results)
            .find(|result| result.account_id_hex == co_member)
            .expect("a seeded account must be reachable at radius 1");
        assert_eq!(matched.radius, 1);
    }

    /// The searcher is radius 0. A seed naming them must not re-report them a
    /// layer out, and must not make the traversal revisit them.
    #[tokio::test]
    async fn seeding_the_searcher_does_not_duplicate_them_at_radius_one() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.invalid");
        let cache = app.directory_cache_for_account(&account).unwrap();
        cache
            .put(&record_named(&account.account_id_hex, "needle"))
            .unwrap();

        let subscription = app
            .search_users(UserSearchParams {
                radius_one_seeds: vec![account.account_id_hex.clone()],
                ..params(&account.account_id_hex, "needle", (0, 1))
            })
            .await
            .unwrap();
        let updates = drain(subscription).await;

        let radii: Vec<u8> = updates
            .iter()
            .flat_map(|update| &update.new_results)
            .filter(|result| result.account_id_hex == account.account_id_hex)
            .map(|result| result.radius)
            .collect();
        assert_eq!(radii, vec![0], "the searcher is radius 0 and only radius 0");
    }

    /// The outbox model: a profile published only to its author's own relays
    /// is unreachable from the searcher's relay set, and the author's NIP-65
    /// list is the map to it. Here the searcher and the stranger share no relay
    /// at all, so the only route to the profile is via the published write
    /// relay -- if the search finds them, tier 5 did the work.
    #[tokio::test]
    async fn a_profile_only_on_its_authors_write_relay_is_still_found() {
        let searcher_relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let searcher_relay_url = searcher_relay.url().await.to_string();
        let author_relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let author_relay_url = author_relay.url().await.to_string();

        // The stranger writes to their own relay only, but publishes that fact
        // where it can be found -- which is exactly what NIP-65 asks for: the
        // relay list is the discoverable map, the content behind it is not.
        let author_endpoint = cgka_traits::TransportEndpoint(author_relay_url.clone());
        let searcher_endpoint = cgka_traits::TransportEndpoint(searcher_relay_url.clone());
        let stranger_dir = tempfile::tempdir().unwrap();
        let stranger_app = MarmotApp::with_relay(stranger_dir.path(), author_relay_url.clone());
        let stranger = stranger_app
            .runtime()
            .create_identity(crate::AccountSetupRequest {
                default_relays: vec![author_endpoint.clone()],
                bootstrap_relays: vec![author_endpoint.clone(), searcher_endpoint],
                publish_missing_relay_lists: true,
                ..crate::AccountSetupRequest::default()
            })
            .await
            .expect("create the stranger's identity")
            .account;
        stranger_app
            .publish_user_profile(
                &stranger.account_id_hex,
                UserProfileMetadata {
                    name: Some("needle".to_owned()),
                    ..UserProfileMetadata::default()
                },
                crate::AccountRelayListBootstrap::new(vec![author_endpoint], Vec::new()),
            )
            .await
            .expect("publish the stranger's profile");

        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), searcher_relay_url.clone());
        let cache = app.directory_cache_for_account(&account).unwrap();
        cache
            .put(&UserDirectoryRecord {
                follows: vec![stranger.account_id_hex.clone()],
                ..record_named(&account.account_id_hex, "alice")
            })
            .unwrap();

        let subscription = app
            .search_users(params(&account.account_id_hex, "needle", (1, 1)))
            .await
            .unwrap();
        let updates = drain(subscription).await;

        assert!(
            updates
                .iter()
                .flat_map(|update| &update.new_results)
                .any(|result| result.account_id_hex == stranger.account_id_hex),
            "the profile must be resolved from the author's own write relay: {updates:?}"
        );
    }

    /// A brand-new account follows nobody and shares no group, so its own web
    /// of trust can only ever answer "nothing". A configured seed gives the
    /// traversal somewhere to start -- but those people are not one hop from
    /// the searcher, they are not on the searcher's graph at all, so they are
    /// reported off-graph rather than dressed up as follows.
    #[tokio::test]
    async fn an_empty_graph_falls_back_to_the_configured_seed_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let seed = format!("{:064x}", 91);
        let stranger = format!("{:064x}", 92);
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.invalid",
            crate::MarmotAppConfig::default()
                .with_directory_search_fallback_seeds(vec![seed.clone()])
                .with_open_ranking_provider(None, Vec::new()),
        );
        let cache = app.directory_cache_for_account(&account).unwrap();
        let now = crate::unix_now_seconds() as i64;

        // Alice follows nobody. The seed follows someone worth finding.
        cache
            .remember_search_graph_follows(
                &seed,
                &npub_for_account_id_lossy(&seed),
                std::slice::from_ref(&stranger),
            )
            .unwrap();
        cache
            .put_search_graph_record(
                &DirectorySearchGraphRecord {
                    account_id_hex: stranger.clone(),
                    npub: npub_for_account_id_lossy(&stranger),
                    profile: Some(UserProfileMetadata {
                        name: Some("needle".to_owned()),
                        ..UserProfileMetadata::default()
                    }),
                    follows: None,
                    metadata_updated_at: Some(now as u64),
                    metadata_expires_at: Some((now + SEARCH_GRAPH_PROFILE_TTL_SECONDS) as u64),
                },
                now,
            )
            .unwrap();

        let subscription = app
            .search_users(params(&account.account_id_hex, "needle", (0, 2)))
            .await
            .unwrap();
        let updates = drain(subscription).await;

        let matched = updates
            .iter()
            .flat_map(|update| &update.new_results)
            .find(|result| result.account_id_hex == stranger)
            .expect("the seed's network must be reachable when the graph is empty");
        assert_eq!(
            matched.radius, OFF_GRAPH_SEARCH_RADIUS,
            "a fallback match is not a measurable distance from the searcher"
        );
    }

    /// The seed is a last resort, not a supplement. Someone with a real graph
    /// must never have a stranger's network folded into their results.
    #[tokio::test]
    async fn a_searcher_with_follows_never_reaches_the_fallback_seed() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let friend = format!("{:064x}", 93);
        let seed = format!("{:064x}", 94);
        let seeded_stranger = format!("{:064x}", 95);
        let app = MarmotApp::with_relay_and_config(
            dir.path(),
            "wss://relay.invalid",
            crate::MarmotAppConfig::default()
                .with_directory_search_fallback_seeds(vec![seed.clone()])
                .with_open_ranking_provider(None, Vec::new()),
        );
        let cache = app.directory_cache_for_account(&account).unwrap();
        let now = crate::unix_now_seconds() as i64;

        cache
            .put(&UserDirectoryRecord {
                follows: vec![friend.clone()],
                ..record_named(&account.account_id_hex, "alice")
            })
            .unwrap();
        cache
            .remember_search_graph_follows(
                &seed,
                &npub_for_account_id_lossy(&seed),
                std::slice::from_ref(&seeded_stranger),
            )
            .unwrap();
        cache
            .put_search_graph_record(
                &DirectorySearchGraphRecord {
                    account_id_hex: seeded_stranger.clone(),
                    npub: npub_for_account_id_lossy(&seeded_stranger),
                    profile: Some(UserProfileMetadata {
                        name: Some("needle".to_owned()),
                        ..UserProfileMetadata::default()
                    }),
                    follows: None,
                    metadata_updated_at: Some(now as u64),
                    metadata_expires_at: Some((now + SEARCH_GRAPH_PROFILE_TTL_SECONDS) as u64),
                },
                now,
            )
            .unwrap();

        let subscription = app
            .search_users(params(&account.account_id_hex, "needle", (0, 2)))
            .await
            .unwrap();
        let updates = drain(subscription).await;

        assert!(
            !updates
                .iter()
                .flat_map(|update| &update.new_results)
                .any(|result| result.account_id_hex == seeded_stranger),
            "a searcher with their own graph must not be given a stranger's"
        );
    }

    /// A promoted row without a profile must not hide the profile the search
    /// graph has cached for the same account.
    ///
    /// Accounts get promoted rows for reasons that carry no profile at all --
    /// being a message sender, for one -- so this is the ordinary state, not a
    /// corner case. If the profile-less row masks the cached one, every search
    /// re-fetches those people from relays and the warm path never fires for
    /// exactly the accounts the user interacts with most.
    #[tokio::test]
    async fn a_promoted_row_without_a_profile_does_not_mask_the_cached_one() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let stranger = format!("{:064x}", 101);
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.invalid");
        let cache = app.directory_cache_for_account(&account).unwrap();
        let now = crate::unix_now_seconds() as i64;

        cache
            .put(&UserDirectoryRecord {
                follows: vec![stranger.clone()],
                ..record_named(&account.account_id_hex, "alice")
            })
            .unwrap();
        // Promoted, but profile-less: the shape `remember_directory_user_with_reason`
        // leaves behind for a message sender.
        cache
            .put(&UserDirectoryRecord {
                profile: None,
                ..record_named(&stranger, "ignored")
            })
            .unwrap();
        // The profile an earlier search resolved, cached un-promoted.
        cache
            .put_search_graph_record(
                &DirectorySearchGraphRecord {
                    account_id_hex: stranger.clone(),
                    npub: npub_for_account_id_lossy(&stranger),
                    profile: Some(UserProfileMetadata {
                        name: Some("needle".to_owned()),
                        ..UserProfileMetadata::default()
                    }),
                    follows: None,
                    metadata_updated_at: Some(now as u64),
                    metadata_expires_at: Some((now + SEARCH_GRAPH_PROFILE_TTL_SECONDS) as u64),
                },
                now,
            )
            .unwrap();

        let subscription = app
            .search_users(params(&account.account_id_hex, "needle", (1, 1)))
            .await
            .unwrap();
        let updates = drain(subscription).await;

        assert!(
            updates
                .iter()
                .flat_map(|update| &update.new_results)
                .any(|result| result.account_id_hex == stranger),
            "the cached profile must be reachable despite the profile-less promoted row"
        );
    }

    /// A query that matches an account's npub or pubkey matches it whether or
    /// not a profile was ever found -- that is deliberate, so an npub search
    /// still finds a follow who publishes no profile. It must not mean the
    /// account is reported twice when the outbox tier later supplies the
    /// profile: one person, one result, however many tiers it took to resolve.
    #[tokio::test]
    async fn an_npub_match_resolved_by_the_outbox_tier_is_reported_once() {
        let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let relay_url = relay.url().await.to_string();
        let author_relay = nostr_relay_builder::MockRelay::run().await.unwrap();
        let author_relay_url = author_relay.url().await.to_string();

        let author_endpoint = cgka_traits::TransportEndpoint(author_relay_url.clone());
        let searcher_endpoint = cgka_traits::TransportEndpoint(relay_url.clone());
        let stranger_dir = tempfile::tempdir().unwrap();
        let stranger_app = MarmotApp::with_relay(stranger_dir.path(), author_relay_url.clone());
        let stranger = stranger_app
            .runtime()
            .create_identity(crate::AccountSetupRequest {
                default_relays: vec![author_endpoint.clone()],
                bootstrap_relays: vec![author_endpoint.clone(), searcher_endpoint],
                publish_missing_relay_lists: true,
                ..crate::AccountSetupRequest::default()
            })
            .await
            .expect("create the stranger's identity")
            .account;
        stranger_app
            .publish_user_profile(
                &stranger.account_id_hex,
                UserProfileMetadata {
                    name: Some("bob".to_owned()),
                    ..UserProfileMetadata::default()
                },
                crate::AccountRelayListBootstrap::new(vec![author_endpoint], Vec::new()),
            )
            .await
            .expect("publish the stranger's profile");

        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), relay_url);
        let cache = app.directory_cache_for_account(&account).unwrap();
        cache
            .put(&UserDirectoryRecord {
                follows: vec![stranger.account_id_hex.clone()],
                ..record_named(&account.account_id_hex, "alice")
            })
            .unwrap();

        // Query the stranger's own pubkey hex: it matches before any profile is
        // known, and still matches after the outbox tier resolves one.
        let subscription = app
            .search_users(params(
                &account.account_id_hex,
                &stranger.account_id_hex,
                (1, 1),
            ))
            .await
            .unwrap();
        let updates = drain(subscription).await;

        let hits: Vec<&UserDirectorySearchResult> = updates
            .iter()
            .flat_map(|update| &update.new_results)
            .filter(|result| result.account_id_hex == stranger.account_id_hex)
            .collect();
        assert_eq!(hits.len(), 1, "one person, one result: {hits:?}");
        assert!(
            hits[0].profile.is_some(),
            "the surviving result must be the resolved one, not the empty first pass"
        );
    }

    /// `radius_one_seeds` is public API, and a seed reaches an author-scoped
    /// fetch that rejects its whole batch on one unparseable id. Rejecting the
    /// request names the bad input instead of failing the search for reasons a
    /// caller cannot see.
    #[tokio::test]
    async fn a_malformed_seed_is_rejected_rather_than_failing_the_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.invalid");

        let error = app
            .search_users(UserSearchParams {
                radius_one_seeds: vec!["not-a-pubkey".to_owned()],
                ..params(&account.account_id_hex, "needle", (0, 1))
            })
            .await
            .expect_err("a malformed seed is a bad request, not a silent skip");

        assert!(matches!(error, AppError::InvalidPublicKey), "{error:?}");
    }

    #[tokio::test]
    async fn a_cached_searcher_outside_the_radius_window_reports_no_matches() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let cache = app.directory_cache_for_account(&account).unwrap();
        // The searcher matches the query, but sits at radius 0 with an empty
        // follow list, so a radius 1..1 search must report nothing about them.
        cache
            .put(&record_named(&account.account_id_hex, "needle"))
            .unwrap();

        let subscription = app
            .search_users(params(&account.account_id_hex, "needle", (1, 1)))
            .await
            .unwrap();
        let updates = drain(subscription).await;

        assert!(
            updates.iter().all(|update| update.new_results.is_empty()),
            "radius 0 is traversed to reach radius 1, never reported as a match"
        );
        assert_eq!(updates.last().unwrap().total_result_count, 0);
    }

    #[test]
    fn a_batch_ranks_match_quality_before_matched_field() {
        let mut results = vec![
            UserDirectorySearchResult {
                account_id_hex: format!("{:064x}", 1),
                npub: "npub-contains-name".into(),
                radius: 1,
                matched_field: MatchedField::Name,
                match_quality: MatchQuality::Contains,
                provider_rank: None,
                profile: None,
            },
            UserDirectorySearchResult {
                account_id_hex: format!("{:064x}", 2),
                npub: "npub-exact-about".into(),
                radius: 1,
                matched_field: MatchedField::About,
                match_quality: MatchQuality::Exact,
                provider_rank: None,
                profile: None,
            },
            UserDirectorySearchResult {
                account_id_hex: format!("{:064x}", 3),
                npub: "npub-exact-name".into(),
                radius: 1,
                matched_field: MatchedField::Name,
                match_quality: MatchQuality::Exact,
                provider_rank: None,
                profile: None,
            },
        ];

        sort_user_search_results(&mut results);

        assert_eq!(
            results
                .iter()
                .map(|result| result.npub.as_str())
                .collect::<Vec<_>>(),
            vec!["npub-exact-name", "npub-exact-about", "npub-contains-name"]
        );
    }

    #[test]
    fn discovery_results_preserve_provider_rank() {
        let mut results = vec![
            UserDirectorySearchResult {
                account_id_hex: format!("{:064x}", 4),
                npub: "npub-lower-provider-rank".into(),
                radius: OFF_GRAPH_SEARCH_RADIUS,
                matched_field: MatchedField::Name,
                match_quality: MatchQuality::Exact,
                provider_rank: Some(0.25),
                profile: None,
            },
            UserDirectorySearchResult {
                account_id_hex: format!("{:064x}", 5),
                npub: "npub-higher-provider-rank".into(),
                radius: OFF_GRAPH_SEARCH_RADIUS,
                matched_field: MatchedField::About,
                match_quality: MatchQuality::Contains,
                provider_rank: Some(0.75),
                profile: None,
            },
        ];

        sort_user_search_results(&mut results);

        assert_eq!(results[0].npub, "npub-higher-provider-rank");
    }
}
