//! Streaming user-directory search over the live web of trust.
//!
//! [`MarmotApp::search_users`] answers "who do I know called *foo*" by walking
//! the searcher's own social graph outward and streaming matches as each layer
//! resolves, so on-device hits appear immediately instead of after the slowest
//! relay. Results are ranked by social distance (`radius`): radius 0 is the
//! searcher, radius 1 their direct follows.
//!
//! Traversal is bounded by construction, as `AGENTS.md` requires: the radius is
//! capped, relay work per radius is batched author-scoped fetches under a
//! timeout, and the producer stops the moment its consumer drops the
//! subscription. Nothing here writes `directory_users` — strangers surfaced by
//! search stay un-promoted so they can never become live per-author
//! subscriptions (mdk#687).
//!
//! The synchronous [`MarmotApp::search_user_directory`] remains the offline
//! path over already-cached follow edges; this module is the live one.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::records::{
    UserDirectoryRecord, UserDirectorySearchResult, profile_from_record, user_record_match,
};
use crate::error::AppError;
use crate::ids::parse_account_id_hex;
use crate::runtime::blocking_app_task;
use crate::{KIND_NOSTR_METADATA, MarmotApp};

/// Deepest radius the traversal producer currently answers.
///
/// Radius 0 is the searcher and radius 1 their direct follows, which needs a
/// single author-scoped follow-list fetch. Reaching radius 2 means fetching a
/// follow list for every account at radius 1, which only stays inside the
/// bounded-traversal invariant once the per-radius candidate cap and bounded
/// fetch concurrency land alongside it. Until then a deeper request is
/// rejected rather than silently answered with a shallower search.
const MAX_SUPPORTED_SEARCH_RADIUS: u8 = 1;

/// Updates buffered before the producer waits on a slow consumer.
///
/// Backpressure is deliberate: every update carries results found nowhere
/// else, so the producer must never race ahead and drop them.
const SEARCH_UPDATE_CHANNEL_CAPACITY: usize = 500;

/// Candidate pubkeys resolved per author-scoped relay fetch.
const SEARCH_PUBKEY_BATCH_SIZE: usize = 200;

/// Ceiling on the relay work a single radius may spend.
const SEARCH_RADIUS_TIMEOUT: Duration = Duration::from_secs(300);

/// What a search is looking for, and how far out to look.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserSearchParams {
    pub searcher_account_id_hex: String,
    pub query: String,
    /// First radius whose matches are emitted, inclusive.
    pub radius_start: u8,
    /// Last radius whose matches are emitted, inclusive.
    pub radius_end: u8,
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
    /// This radius finished resolving.
    RadiusCompleted { radius: u8 },
    /// This radius ran out of time; traversal stops here.
    RadiusTimeout { radius: u8 },
    /// Terminal: no further updates follow.
    SearchCompleted,
    /// Traversal failed. Always followed by [`Self::SearchCompleted`].
    Error { message: String },
}

/// One incremental step of a running search.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserSearchUpdate {
    pub trigger: SearchUpdateTrigger,
    /// Matches discovered by this step, pre-sorted within the batch. Ordering
    /// *across* updates is the radius order they arrive in.
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
    if !query.is_empty()
        && let Err(error) = traverse_graph(
            &app,
            &searcher_account_id_hex,
            &query,
            &params,
            &mut emitter,
        )
        .await
    {
        emitter
            .emit(SearchUpdateTrigger::Error {
                message: error.to_string(),
            })
            .await;
    }
    emitter.emit(SearchUpdateTrigger::SearchCompleted).await;
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

    for radius in 0..=params.radius_end {
        if frontier.is_empty() || emitter.is_cancelled() {
            break;
        }
        emitter
            .emit(SearchUpdateTrigger::RadiusStarted { radius })
            .await;

        // One timeout per radius, covering every relay round trip the radius
        // makes: resolving its profiles and reading the follow lists that
        // become the next layer.
        let advance = advance_radius(app, &frontier, query, radius, params, &mut seen, emitter);
        frontier = match timeout(SEARCH_RADIUS_TIMEOUT, advance).await {
            Ok(result) => result?,
            Err(_elapsed) => {
                emitter
                    .emit(SearchUpdateTrigger::RadiusTimeout { radius })
                    .await;
                return Ok(());
            }
        };
        emitter
            .emit(SearchUpdateTrigger::RadiusCompleted { radius })
            .await;
    }
    Ok(())
}

/// Emit one radius's matches and return the layer beyond it.
async fn advance_radius(
    app: &MarmotApp,
    frontier: &[String],
    query: &str,
    radius: u8,
    params: &UserSearchParams,
    seen: &mut HashSet<String>,
    emitter: &mut SearchEmitter,
) -> Result<Vec<String>, AppError> {
    // Radii below the requested window are traversed but not reported: they
    // are only the path to the layers the caller did ask for, so resolving
    // their profiles would be relay traffic for results nobody receives.
    if radius >= params.radius_start {
        resolve_layer(app, frontier, query, radius, emitter).await?;
    }
    if radius == params.radius_end {
        return Ok(Vec::new());
    }
    next_frontier(app, frontier, seen).await
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
    let (local, missing) = partition_locally_known(app, frontier).await?;
    emitter.emit_matches(radius, local, query).await;

    for batch in missing.chunks(SEARCH_PUBKEY_BATCH_SIZE) {
        if emitter.is_cancelled() {
            return Ok(());
        }
        let fetched = fetch_profile_records(app, batch).await?;
        emitter.emit_matches(radius, fetched, query).await;
    }
    Ok(())
}

/// Split a layer into records the device can already match and pubkeys that
/// still need a profile fetched. A cached record without a profile counts as
/// needing one.
async fn partition_locally_known(
    app: &MarmotApp,
    frontier: &[String],
) -> Result<(Vec<UserDirectoryRecord>, Vec<String>), AppError> {
    let app = app.clone();
    let frontier = frontier.to_vec();
    blocking_app_task(move || {
        let caches = app.directory_caches()?;
        let shared_storage = app.shared_storage()?;
        let mut known = Vec::new();
        let mut missing = Vec::new();
        for account_id_hex in frontier {
            match app.directory_entry_for_account_id_with_handles(
                &account_id_hex,
                &caches,
                &shared_storage,
            )? {
                Some(record) if record.profile.is_some() => known.push(record),
                _ => missing.push(account_id_hex),
            }
        }
        Ok((known, missing))
    })
    .await
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

/// Collect the follow lists of the current layer into the next one, skipping
/// anybody already visited.
async fn next_frontier(
    app: &MarmotApp,
    frontier: &[String],
    seen: &mut HashSet<String>,
) -> Result<Vec<String>, AppError> {
    let mut next = Vec::new();
    for account_id_hex in frontier {
        let follow_list = app
            .fetch_follow_list_for_account_id(account_id_hex, &[])
            .await?;
        for follow in follow_list.follows {
            if seen.insert(follow.clone()) {
                next.push(follow);
            }
        }
    }
    Ok(next)
}

/// Sends updates to the subscription and keeps the running result total.
struct SearchEmitter {
    updates_tx: mpsc::Sender<UserSearchUpdate>,
    total_result_count: usize,
}

impl SearchEmitter {
    fn new(updates_tx: mpsc::Sender<UserSearchUpdate>) -> Self {
        Self {
            updates_tx,
            total_result_count: 0,
        }
    }

    /// Whether the consumer has dropped the subscription, which is how a
    /// search is cancelled.
    fn is_cancelled(&self) -> bool {
        self.updates_tx.is_closed()
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
                    profile: record.profile,
                })
            })
            .collect::<Vec<_>>();
        if results.is_empty() {
            return;
        }
        sort_user_search_results(&mut results);
        self.emit_results(SearchUpdateTrigger::ResultsFound { radius }, results)
            .await;
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

/// Rank results best-first: nearest radius, then match strength, then which
/// field matched, then pubkey so equally good matches keep a stable order.
///
/// Public because a streaming consumer has to re-rank for itself. Updates
/// arrive pre-sorted *within* a batch, but a search emits several batches per
/// radius (cached first, then fetched), so anything that accumulates the whole
/// stream must sort the aggregate to recover this order.
pub fn sort_user_search_results(results: &mut [UserDirectorySearchResult]) {
    results.sort_by(|a, b| {
        a.radius
            .cmp(&b.radius)
            .then_with(|| a.match_quality.cmp(&b.match_quality))
            .then_with(|| a.matched_field.cmp(&b.matched_field))
            .then_with(|| a.account_id_hex.cmp(&b.account_id_hex))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MatchQuality, MatchedField};
    use crate::AccountRelayListStatus;
    use crate::ids::npub_for_account_id_lossy;
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
                profile: None,
            },
            UserDirectorySearchResult {
                account_id_hex: format!("{:064x}", 2),
                npub: "npub-exact-about".into(),
                radius: 1,
                matched_field: MatchedField::About,
                match_quality: MatchQuality::Exact,
                profile: None,
            },
            UserDirectorySearchResult {
                account_id_hex: format!("{:064x}", 3),
                npub: "npub-exact-name".into(),
                radius: 1,
                matched_field: MatchedField::Name,
                match_quality: MatchQuality::Exact,
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
}
