//! Set-oriented group-member KeyPackage resolution.
//!
//! The create and invite paths know the whole requested roster before they
//! mutate MLS state. Resolve that set as a set: canonicalize aliases, collapse
//! duplicate account ids, reuse discovery routes, and fetch current KeyPackages
//! and their deletion requests from relays before every invitation. Each
//! account contributes one KeyPackage per selected device. Cached packages are
//! discovery hints, not evidence that a recipient still owns the private
//! bundle. Unsupported batch queries fall back to bounded single-author relay
//! requests.

use crate::error::{DirectoryError, MissingKeyPackageReason};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cgka_engine::key_package::key_package_metadata;
use cgka_traits::TransportEndpoint;
use cgka_traits::engine::KeyPackage;
use cgka_traits::group::ProtocolProfile;
use futures::{Stream, StreamExt, future, stream};
use nostr_sdk::prelude::PublicKey;
use transport_nostr_adapter::{KIND_MARMOT_INBOX_RELAY_LIST, KIND_NIP65_RELAY_LIST};

use super::Directory;
use super::observer::{DirectoryObservation, DirectoryObserver, ObservedFamily, ObservedUnit};
use super::resources::DirectoryResources;
use crate::published_records::{
    KeyPackageRecoveryEvidence, MAX_KEY_PACKAGES_PER_ACCOUNT, fresh_relay_list_status_from_records,
    key_package_queries, key_package_read_page_full, merge_relay_list_status,
    select_key_packages_with_evidence,
};
use crate::{AccountRelayListStatus, FetchedKeyPackage};
use transport_nostr::{DirectoryEventQuery, DirectoryFetchOutcome};

/// Maximum authors placed in one Nostr directory filter.
pub(crate) const MEMBER_RESOLUTION_AUTHORS_PER_QUERY: usize = 32;
/// Concurrent endpoint-group/chunk requests within one resolution pass.
const MEMBER_RESOLUTION_RELAY_CONCURRENCY: usize = 4;
/// Existing per-member fallback concurrency, retained for incompatible relays.
const MEMBER_RESOLUTION_FALLBACK_CONCURRENCY: usize = 8;
/// One complete set resolution is bounded even when several relay sets stall.
// Relay-list discovery, normal reads, supplementary recovery and candidate-
// scoped deletion proof share one deadline. No per-route or candidate retry
// renews it; slow/incomplete coverage remains retryable rather than absence.
const MEMBER_RESOLUTION_DEADLINE: Duration = Duration::from_secs(50);
/// The longest one directory read waits: transport-nostr opens a connection
/// for each read (at most 5 s) and waits at most 3 s for a REQ's EOSE.
/// Relay-list and KeyPackage reads each send one REQ.
const MEMBER_RESOLUTION_READ_WORST: Duration = Duration::from_secs(8);
/// Under Partial, how long after the start each step that waits for the whole
/// set may wait. At its cut-off the members that cleared the step go on and
/// the rest report `Incomplete`. A step that ends sooner leaves its time to
/// the steps after it. Each cut-off leaves every later step one wave at its
/// worst: a discovery hop is a batch read and its single-author retry, a
/// KeyPackage batch is one read, and the single-author read that decides a
/// member is one more. Atomic resolution has no cut-offs.
const PARTIAL_KEY_PACKAGE_BATCH_CUT_OFF: Duration =
    MEMBER_RESOLUTION_DEADLINE.saturating_sub(MEMBER_RESOLUTION_READ_WORST);
const PARTIAL_OUTBOX_HOP_CUT_OFF: Duration =
    PARTIAL_KEY_PACKAGE_BATCH_CUT_OFF.saturating_sub(MEMBER_RESOLUTION_READ_WORST);
const PARTIAL_FIRST_HOP_CUT_OFF: Duration =
    PARTIAL_OUTBOX_HOP_CUT_OFF.saturating_sub(MEMBER_RESOLUTION_READ_WORST.saturating_mul(2));
const RELAY_LIST_EVENTS_PER_AUTHOR: usize = 4;
const MEMBER_PREWARM_CACHE_LIMIT: usize = 256;
pub const MEMBER_PREWARM_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
struct MemberKeyPackagePrewarmEntry {
    relay_lists: AccountRelayListStatus,
    inserted_at: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composition_prewarm_cache_is_bounded_and_expires_entries() {
        let mut cache = MemberKeyPackagePrewarmCache::default();
        for index in 0..=MEMBER_PREWARM_CACHE_LIMIT {
            cache.insert(format!("{index:064x}"), AccountRelayListStatus::empty());
        }
        assert_eq!(cache.entries.len(), MEMBER_PREWARM_CACHE_LIMIT);
        assert!(cache.get(&format!("{:064x}", 0)).is_none());

        let newest = format!("{:064x}", MEMBER_PREWARM_CACHE_LIMIT);
        cache.set_inserted_at(
            &newest,
            Instant::now() - MEMBER_PREWARM_CACHE_TTL - Duration::from_secs(1),
        );
        assert!(cache.get(&newest).is_none());
        assert!(!cache.order.contains(&newest));
    }

    #[test]
    fn discarding_a_reused_prewarm_snapshot_preserves_its_replacement() {
        let mut cache = MemberKeyPackagePrewarmCache::default();
        let account = "01".repeat(32);
        cache.insert(account.clone(), AccountRelayListStatus::empty());
        let used = cache.snapshot(&account).unwrap();

        let mut updated_routes = AccountRelayListStatus::empty();
        updated_routes
            .nip65
            .relays
            .push("wss://new-outbox.example".into());
        cache.insert(account.clone(), updated_routes.clone());
        cache.remove_if_current(&account, &used);
        assert_eq!(cache.get(&account), Some(updated_routes));

        let current = cache.snapshot(&account).unwrap();
        cache.remove_if_current(&account, &current);
        assert!(cache.snapshot(&account).is_none());
        assert!(!cache.order.contains(&account));
    }

    /// A read queued behind one that answers at the cut-off never starts,
    /// however the stream is polled once the cut-off has passed.
    #[tokio::test(start_paused = true)]
    async fn no_read_starts_after_its_cut_off() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let cut_off = tokio::time::Instant::now() + Duration::from_secs(1);
        let started = Arc::new(AtomicUsize::new(0));
        let reads = (0..2).map(|_| {
            let started = Arc::clone(&started);
            started_before(Some(cut_off), async move {
                started.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep_until(cut_off).await;
            })
        });
        let mut reads = stream::iter(reads).buffer_unordered(1);

        assert_eq!(reads.next().await, Some(Some(())));
        assert_eq!(reads.next().await, Some(None));
        assert_eq!(started.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn partial_errors_keep_internal() {
        use cgka_traits::error::EngineError;

        assert_eq!(
            recipient_resolution_status(&DirectoryError::TransportClosed),
            None
        );
        let incompatible =
            DirectoryError::KeyPackageRequirements(EngineError::InvalidKeyPackageCapabilities {
                member: cgka_traits::MemberId::new(vec![1; 32]),
            });
        assert_eq!(
            recipient_resolution_status(&incompatible),
            Some(MemberResolutionStatus::IncompatibleKeyPackage)
        );
        for error in [
            EngineError::Backend("key package provider failed".into()),
            EngineError::Other("unexpected admission failure".into()),
        ] {
            assert_eq!(
                recipient_resolution_status(&DirectoryError::KeyPackageRequirements(error)),
                None
            );
        }
        assert_eq!(
            recipient_resolution_status(&DirectoryError::MissingKeyPackage {
                account: "01".repeat(32),
                reason: MissingKeyPackageReason::ObsoleteOnly,
            }),
            Some(MemberResolutionStatus::ObsoleteKeyPackage)
        );
    }
}

#[derive(Default)]
pub struct MemberKeyPackagePrewarmCache {
    entries: HashMap<String, Arc<MemberKeyPackagePrewarmEntry>>,
    order: VecDeque<String>,
}

impl MemberKeyPackagePrewarmCache {
    /// When `account_id_hex`'s entry was cached.
    #[cfg(any(test, feature = "test-support"))]
    pub fn inserted_at(&self, account_id_hex: &str) -> Option<Instant> {
        self.entries
            .get(account_id_hex)
            .map(|entry| entry.inserted_at)
    }

    /// Backdate `account_id_hex`'s entry, to test expiry and reuse.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_inserted_at(&mut self, account_id_hex: &str, inserted_at: Instant) {
        if let Some(entry) = self.entries.get_mut(account_id_hex) {
            Arc::make_mut(entry).inserted_at = inserted_at;
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn get(&mut self, account_id_hex: &str) -> Option<AccountRelayListStatus> {
        self.snapshot(account_id_hex)
            .map(|entry| entry.relay_lists.clone())
    }

    fn snapshot(&mut self, account_id_hex: &str) -> Option<Arc<MemberKeyPackagePrewarmEntry>> {
        self.remove_expired();
        self.entries.get(account_id_hex).cloned()
    }

    fn remove_if_current(
        &mut self,
        account_id_hex: &str,
        used: &Arc<MemberKeyPackagePrewarmEntry>,
    ) {
        if self
            .entries
            .get(account_id_hex)
            .is_some_and(|current| Arc::ptr_eq(current, used))
        {
            self.entries.remove(account_id_hex);
            self.order.retain(|existing| existing != account_id_hex);
        }
    }

    /// Insert freshly discovered routes, never a package-refresh result.
    fn insert(&mut self, account_id_hex: String, relay_lists: AccountRelayListStatus) {
        self.remove_expired();
        self.order.retain(|existing| existing != &account_id_hex);
        self.order.push_back(account_id_hex.clone());
        self.entries.insert(
            account_id_hex,
            Arc::new(MemberKeyPackagePrewarmEntry {
                relay_lists,
                inserted_at: Instant::now(),
            }),
        );
        while self.entries.len() > MEMBER_PREWARM_CACHE_LIMIT {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }

    fn remove_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| {
            now.saturating_duration_since(entry.inserted_at) <= MEMBER_PREWARM_CACHE_TTL
        });
        self.order
            .retain(|account_id| self.entries.contains_key(account_id));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberResolutionPurpose {
    Commit,
    CommitFresh,
    Prewarm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberResolutionStatus {
    /// Fresh, compatible devices and a safe inbox route are available.
    /// This does not mean the account joined or received a Welcome.
    Selected,
    MissingKeyPackage,
    ObsoleteKeyPackage,
    InvalidKeyPackage,
    IncompatibleKeyPackage,
    MissingInboxRoute,
    Incomplete,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemberResolutionOutcome {
    pub account_id_hex: String,
    pub status: MemberResolutionStatus,
    /// Number of eligible devices, zero for every unavailable status.
    pub selected_device_count: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberResolutionPolicy {
    Atomic,
    #[default]
    Partial,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemberKeyPackagePrewarmSummary {
    /// Number of member references supplied by the host.
    pub requested_members: u64,
    /// Canonical account ids after aliases and duplicates are collapsed.
    pub unique_members: u64,
    /// Retained for API compatibility; always zero because packages must be
    /// fetched from relays. Discovery routes may still be reused.
    pub reused_members: u64,
    /// Packages that required relay resolution during this call.
    pub network_resolved_members: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemberKeyPackageResolutionStats {
    pub(crate) requested_members: usize,
    pub unique_members: usize,
}

impl From<MemberKeyPackageResolutionStats> for MemberKeyPackagePrewarmSummary {
    fn from(stats: MemberKeyPackageResolutionStats) -> Self {
        Self {
            requested_members: stats.requested_members as u64,
            unique_members: stats.unique_members as u64,
            reused_members: 0,
            network_resolved_members: stats.unique_members as u64,
        }
    }
}

#[derive(Clone)]
struct MemberTarget {
    account_id_hex: String,
    relay_lists: AccountRelayListStatus,
    cached_relay_lists: AccountRelayListStatus,
    relay_records: Vec<transport_nostr::DirectoryRelayEventRecord>,
}

#[derive(Default)]
struct RelayListResolution {
    completed: HashSet<usize>,
    errors: Vec<(usize, DirectoryError)>,
    /// Members a cut-off stopped before their discovery finished. Their relay
    /// lists may be a discovery-only snapshot.
    unfinished: HashSet<usize>,
}

/// What one metadata hop settled.
#[derive(Default)]
struct HopProgress {
    /// Members whose result arrived before the hop's cut-off.
    cleared: HashSet<usize>,
    /// Cleared members whose read was complete and not from the future.
    completed: HashSet<usize>,
}

/// Under [`MemberResolutionPolicy::Partial`], when each step that waits for
/// the whole set stops waiting.
#[derive(Clone, Copy)]
struct PartialCutOffs {
    first_hop: tokio::time::Instant,
    outbox_hop: tokio::time::Instant,
    key_package_batches: tokio::time::Instant,
}

impl PartialCutOffs {
    fn after(started: tokio::time::Instant) -> Self {
        Self {
            first_hop: started + PARTIAL_FIRST_HOP_CUT_OFF,
            outbox_hop: started + PARTIAL_OUTBOX_HOP_CUT_OFF,
            key_package_batches: started + PARTIAL_KEY_PACKAGE_BATCH_CUT_OFF,
        }
    }
}

struct MemberLookup<'a> {
    purpose: MemberResolutionPurpose,
    requirements: Option<&'a cgka_engine::key_package::KeyPackageRequirements>,
    deadline: tokio::time::Instant,
    cut_offs: Option<PartialCutOffs>,
}

#[derive(Default)]
struct MemberLookupCoverage {
    relay_lists_completed: HashSet<usize>,
    relay_lists_unfinished: HashSet<usize>,
    incompatible_evidence: HashMap<usize, KeyPackageRecoveryEvidence>,
}

/// The stream's next item, or `None` once it ends or `cut_off` passes. An
/// item already waiting at the cut-off is still taken: its read had started
/// before the cut-off, and no read starts after it ([`started_before`]).
async fn next_before<S: Stream + Unpin>(
    stream: &mut S,
    cut_off: Option<tokio::time::Instant>,
) -> Option<S::Item> {
    match cut_off {
        Some(cut_off) => tokio::time::timeout_at(cut_off, stream.next())
            .await
            .ok()
            .flatten(),
        None => stream.next().await,
    }
}

/// `read`'s result, or `None` without starting it once `cut_off` has passed.
/// Every read of a step with a cut-off goes through this, so a read queued in
/// a buffered stream never starts late, however late the stream is polled.
async fn started_before<T>(
    cut_off: Option<tokio::time::Instant>,
    read: impl Future<Output = T>,
) -> Option<T> {
    if cut_off.is_some_and(|cut_off| tokio::time::Instant::now() >= cut_off) {
        return None;
    }
    Some(read.await)
}

pub struct ResolvedMemberKeyPackages {
    /// Each account's selected KeyPackages, best first, accounts in input
    /// order. An account with several devices contributes several.
    pub key_packages: Vec<KeyPackage>,
    pub stats: MemberKeyPackageResolutionStats,
    /// One result per canonical account, in first-input order.
    pub member_outcomes: Vec<MemberResolutionOutcome>,
}

impl<R: DirectoryResources + DirectoryObserver> Directory<R> {
    /// Resolve a roster as one deterministic set.
    ///
    /// Account aliases are canonicalized and duplicate account ids collapse to
    /// their first input position. Each account yields every KeyPackage
    /// [`select_key_packages_with_evidence`] selects, best first, from what its
    /// relays returned. Every device is sought, not guaranteed (mdk#2628,
    /// D12): packages a read returned are selected even when the read was
    /// incomplete, so a device whose package no relay returned is left out,
    /// and inviting the account again adds it. A read that yields nothing
    /// usable still fails the lookup rather than deciding on nothing. Every package
    /// is fetched from relays; cached packages are never a fallback if that
    /// lookup fails. On error, the error belonging to the first unresolved
    /// canonical member is returned even if later relay work completed earlier.
    pub async fn resolve_member_key_packages(
        &self,
        member_refs: &[&str],
    ) -> Result<Vec<KeyPackage>, DirectoryError> {
        let member_refs = member_refs
            .iter()
            .map(|member_ref| (*member_ref).to_owned())
            .collect::<Vec<_>>();
        Ok(self
            .resolve_member_key_packages_with_stats(member_refs)
            .await?
            .key_packages)
    }

    /// Resolve fresh packages against the operation's admission requirements.
    /// Partial resolution keeps eligible accounts and reports recipient-local
    /// failures, including when no account is eligible. Invalid requests and
    /// resource, storage or internal failures still fail the whole operation.
    /// Atomic resolution returns the first unresolved account's error instead.
    pub async fn resolve_compatible_member_key_packages(
        &self,
        member_refs: Vec<String>,
        requirements: &cgka_engine::key_package::KeyPackageRequirements,
        purpose: MemberResolutionPurpose,
        policy: MemberResolutionPolicy,
    ) -> Result<ResolvedMemberKeyPackages, DirectoryError> {
        self.resolve_members_with_policy(member_refs, purpose, Some(requirements), policy)
            .await
    }

    /// Prewarm group composition without reserving or consuming any package.
    /// Success reports relay/metadata readiness only; final Create/Invite
    /// re-fetches packages and enforces the engine's membership policy.
    ///
    /// The roster must also resolve a safe Marmot inbox route for every member;
    /// missing routes return [`DirectoryError::MissingMemberInboxRoute`]. Successfully
    /// discovered routes remain cached even when another member fails readiness.
    /// A malformed current slot publication suppresses older packages here too;
    /// return an error rather than report readiness from superseded material.
    /// Every call fetches packages for a fresh readiness signal; hosts should
    /// debounce composition changes. A later create call can reuse discovery routes,
    /// but fetches KeyPackages again because prewarmed material may have been
    /// consumed in the meantime.
    pub async fn prewarm_group_member_key_packages(
        &self,
        member_refs: &[&str],
    ) -> Result<MemberKeyPackagePrewarmSummary, DirectoryError> {
        let member_refs = member_refs
            .iter()
            .map(|member_ref| (*member_ref).to_owned())
            .collect::<Vec<_>>();
        self.resolve_member_key_packages_for_purpose(
            member_refs,
            MemberResolutionPurpose::Prewarm,
            None,
        )
        .await
        .map(|resolved| resolved.stats.into())
    }

    pub(crate) async fn resolve_member_key_packages_with_stats(
        &self,
        member_refs: Vec<String>,
    ) -> Result<ResolvedMemberKeyPackages, DirectoryError> {
        self.resolve_member_key_packages_for_purpose(
            member_refs,
            MemberResolutionPurpose::Commit,
            None,
        )
        .await
    }

    pub(crate) async fn resolve_member_key_packages_for_purpose(
        &self,
        member_refs: Vec<String>,
        purpose: MemberResolutionPurpose,
        requirements: Option<&cgka_engine::key_package::KeyPackageRequirements>,
    ) -> Result<ResolvedMemberKeyPackages, DirectoryError> {
        self.resolve_members_with_policy(
            member_refs,
            purpose,
            requirements,
            MemberResolutionPolicy::Atomic,
        )
        .await
    }

    async fn resolve_members_with_policy(
        &self,
        member_refs: Vec<String>,
        purpose: MemberResolutionPurpose,
        requirements: Option<&cgka_engine::key_package::KeyPackageRequirements>,
        policy: MemberResolutionPolicy,
    ) -> Result<ResolvedMemberKeyPackages, DirectoryError> {
        let observation =
            self.resources
                .begin(ObservedFamily::KeyPackage, "lookup", ObservedUnit::Action);
        let started = tokio::time::Instant::now();
        let deadline = started + MEMBER_RESOLUTION_DEADLINE;
        let cut_offs =
            (policy == MemberResolutionPolicy::Partial).then(|| PartialCutOffs::after(started));
        let result = self
            .resolve_member_key_packages_inner(
                &member_refs,
                MemberLookup {
                    purpose,
                    requirements,
                    deadline,
                    cut_offs,
                },
                policy,
            )
            .await;
        if let Some(observation) = observation {
            observation.finish(match &result {
                Ok(_) => "usable",
                Err(DirectoryError::MissingKeyPackage { .. }) => "absent",
                Err(DirectoryError::InvalidKeyPackageEvent(_)) => "invalid",
                Err(_) => "unavailable",
            });
        }
        result
    }

    /// Both network stages share `deadline`. A member whose lookup had not
    /// finished when it passed reports `DirectoryLookupIncomplete`; members
    /// already decided keep their outcome. Under Partial, each step that
    /// waits for the whole set also stops at its cut-off, and the members it
    /// had not cleared report `DirectoryLookupIncomplete`.
    async fn resolve_member_key_packages_inner(
        &self,
        member_refs: &[String],
        lookup: MemberLookup<'_>,
        policy: MemberResolutionPolicy,
    ) -> Result<ResolvedMemberKeyPackages, DirectoryError> {
        let purpose = lookup.purpose;
        let directory_observation = self
            .resources
            .begin(
                ObservedFamily::Directory,
                "key_package",
                ObservedUnit::Attempt,
            )
            .map(DirectoryObservation::counts_only);
        let mut seen = HashSet::new();
        let mut targets = Vec::new();
        let local_accounts = if member_refs.is_empty() {
            HashMap::new()
        } else {
            self.resources
                .local_accounts()?
                .into_iter()
                .map(|account| (account.label, account.account_id_hex))
                .collect::<HashMap<_, _>>()
        };
        for member_ref in member_refs {
            let account_id_hex = match local_accounts.get(member_ref) {
                Some(account_id_hex) => account_id_hex.clone(),
                None => PublicKey::parse(member_ref)
                    .map_err(|_| DirectoryError::InvalidPublicKey)?
                    .to_hex(),
            };
            if !seen.insert(account_id_hex.clone()) {
                continue;
            }
            let relay_lists = self
                .directory_entry(&account_id_hex)?
                .map(|entry| entry.relay_lists)
                .unwrap_or_else(AccountRelayListStatus::empty);
            targets.push(MemberTarget {
                account_id_hex,
                relay_lists: relay_lists.clone(),
                cached_relay_lists: relay_lists,
                relay_records: Vec::new(),
            });
        }

        let mut outcomes = (0..targets.len())
            .map(|_| None)
            .collect::<Vec<Option<Result<Vec<KeyPackage>, DirectoryError>>>>();
        // Even a valid, unexpired cached package may have been consumed on
        // another device. Every purpose, including composition prewarm, must
        // fetch current relay publications; only discovery routes are reused.
        let mut reused_prewarmed_routes = HashMap::new();
        for (index, target) in targets.iter_mut().enumerate() {
            // Recovery deliberately refreshes routes as well as packages.
            if purpose == MemberResolutionPurpose::CommitFresh {
                continue;
            }
            let prefetched = self
                .state
                .member_key_package_prewarm_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .snapshot(&target.account_id_hex);
            if let Some(snapshot) = prefetched {
                target.relay_lists = merge_relay_list_status(
                    target.relay_lists.clone(),
                    snapshot.relay_lists.clone(),
                );
                if !target.relay_lists.nip65.relays.is_empty()
                    && !self
                        .relay_plane
                        .retain_safe_discovered_endpoints(
                            target
                                .relay_lists
                                .inbox
                                .relays
                                .iter()
                                .cloned()
                                .map(TransportEndpoint)
                                .collect(),
                            "member prewarm inbox readiness",
                        )
                        .is_empty()
                {
                    reused_prewarmed_routes.insert(index, snapshot);
                } else {
                    target.cached_relay_lists = target.relay_lists.clone();
                }
            }
        }

        // Durable projections have unknown observation age and need a bounded
        // refresh. Process-local prewarm entries have an enforced TTL and were
        // already resolved through the outbox path during composition.
        let members = (0..targets.len()).collect::<Vec<_>>();
        let relay_list_unresolved = members
            .iter()
            .copied()
            .filter(|index| !reused_prewarmed_routes.contains_key(index))
            .collect::<Vec<_>>();
        let mut coverage = self
            .resolve_member_lookup_pass(
                &mut targets,
                &relay_list_unresolved,
                &members,
                &mut outcomes,
                &lookup,
                &HashMap::new(),
            )
            .await?;

        if purpose == MemberResolutionPurpose::Commit {
            let refresh = members
                .into_iter()
                .filter(|index| {
                    reused_prewarmed_routes.contains_key(index)
                        && coverage.incompatible_evidence.contains_key(index)
                })
                .collect::<Vec<_>>();
            if !refresh.is_empty() {
                {
                    let mut cache = self
                        .state
                        .member_key_package_prewarm_cache
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    for &index in &refresh {
                        // A composition request may have replaced the hint
                        // while the first pass was on the network.
                        cache.remove_if_current(
                            &targets[index].account_id_hex,
                            &reused_prewarmed_routes[&index],
                        );
                        // Discover again from the durable baseline, without
                        // letting an equal-timestamp prewarm hint win.
                        targets[index].relay_lists = targets[index].cached_relay_lists.clone();
                        outcomes[index] = None;
                    }
                }
                let refreshed = self
                    .resolve_member_lookup_pass(
                        &mut targets,
                        &refresh,
                        &refresh,
                        &mut outcomes,
                        &lookup,
                        &coverage.incompatible_evidence,
                    )
                    .await?;
                for index in refresh {
                    if !refreshed.relay_lists_completed.contains(&index)
                        && matches!(
                            &outcomes[index],
                            Some(Err(error)) if recipient_resolution_status(error).is_some()
                        )
                    {
                        outcomes[index] = Some(Err(DirectoryError::DirectoryLookupIncomplete(
                            targets[index].account_id_hex.clone(),
                        )));
                    }
                }
                coverage
                    .relay_lists_completed
                    .extend(refreshed.relay_lists_completed);
                coverage
                    .relay_lists_unfinished
                    .extend(refreshed.relay_lists_unfinished);
            }
        }

        if let Some(observation) = directory_observation {
            for outcome in &outcomes {
                let outcome = match outcome {
                    Some(Ok(_)) => "success",
                    Some(Err(DirectoryError::MissingKeyPackage { .. })) | None => "empty",
                    Some(Err(_)) => "failure",
                };
                observation.directory_sample(outcome, "network", 1);
            }
        }
        for (index, (target, outcome)) in targets.iter().zip(&mut outcomes).enumerate() {
            let Some(result) = outcome.take() else {
                continue;
            };
            // An incompatibility verdict needs current outbox discovery as
            // well as complete KeyPackage reads. Reused routes are hints.
            let result = match result {
                Err(DirectoryError::KeyPackageRequirements(error))
                    if !coverage.relay_lists_completed.contains(&index)
                        && key_package_requirements_are_incompatible(&error) =>
                {
                    Err(DirectoryError::DirectoryLookupIncomplete(
                        target.account_id_hex.clone(),
                    ))
                }
                result => result,
            };
            *outcome = Some(result.and_then(|packages| {
                if packages.is_empty() {
                    return Err(DirectoryError::MissingKeyPackage {
                        account: target.account_id_hex.clone(),
                        reason: MissingKeyPackageReason::NotFound,
                    });
                }
                let safe_inbox = self.relay_plane.retain_safe_discovered_endpoints(
                    target
                        .relay_lists
                        .inbox
                        .relays
                        .iter()
                        .cloned()
                        .map(TransportEndpoint)
                        .collect(),
                    "member invite inbox readiness",
                );
                if safe_inbox.is_empty() {
                    return Err(DirectoryError::MissingMemberInboxRoute(
                        target.account_id_hex.clone(),
                    ));
                }
                self.relay_plane
                    .sanitize_relay_endpoints(safe_inbox, "member invite inbox admission")
                    .map_err(|_| {
                        DirectoryError::DirectoryLookupIncomplete(target.account_id_hex.clone())
                    })?;
                Ok(packages)
            }));
        }
        match purpose {
            // A cancelled relay-list stage may hold a discovery-only snapshot,
            // and so may a member a cut-off stopped.
            MemberResolutionPurpose::Commit | MemberResolutionPurpose::CommitFresh => {
                for (index, target) in targets.iter().enumerate() {
                    if coverage.relay_lists_unfinished.contains(&index) {
                        continue;
                    }
                    if !target.relay_lists.nip65.relays.is_empty()
                        || !target.relay_lists.inbox.relays.is_empty()
                        || target.relay_lists.nip65.created_at > 0
                        || target.relay_lists.inbox.created_at > 0
                    {
                        self.remember_directory_relay_lists(
                            &target.account_id_hex,
                            &target.relay_lists,
                        )?;
                    }
                }
            }
            MemberResolutionPurpose::Prewarm => {
                let mut cache = self
                    .state
                    .member_key_package_prewarm_cache
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                for (index, target) in targets.iter().enumerate() {
                    // Only completed discovery renews the route deadline.
                    // A usable package can arrive after an incomplete metadata
                    // hop retained an older durable inbox/outbox projection.
                    if coverage.relay_lists_completed.contains(&index)
                        && matches!(outcomes[index], Some(Ok(_)))
                    {
                        cache.insert(target.account_id_hex.clone(), target.relay_lists.clone());
                    }
                }
            }
        }

        let unique_members = targets.len();
        let mut key_packages = Vec::with_capacity(unique_members);
        let mut member_outcomes = Vec::with_capacity(unique_members);
        for (target, outcome) in targets.into_iter().zip(outcomes) {
            let outcome = outcome.unwrap_or_else(|| {
                Err(DirectoryError::MissingKeyPackage {
                    account: target.account_id_hex.clone(),
                    reason: MissingKeyPackageReason::NotFound,
                })
            });
            let (status, selected_device_count) = match outcome {
                Ok(packages) => {
                    let device_count = packages.len() as u32;
                    key_packages.extend(packages);
                    (MemberResolutionStatus::Selected, device_count)
                }
                Err(error) => {
                    let status = match policy {
                        MemberResolutionPolicy::Atomic => return Err(error),
                        MemberResolutionPolicy::Partial => recipient_resolution_status(&error),
                    };
                    let Some(status) = status else {
                        return Err(error);
                    };
                    (status, 0)
                }
            };
            member_outcomes.push(MemberResolutionOutcome {
                account_id_hex: target.account_id_hex,
                status,
                selected_device_count,
            });
        }
        Ok(ResolvedMemberKeyPackages {
            key_packages,
            member_outcomes,
            stats: MemberKeyPackageResolutionStats {
                requested_members: member_refs.len(),
                unique_members,
            },
        })
    }

    /// Revalidate one account's selection on the real clock, best first. A
    /// package that expired since selection drops out; the account fails only
    /// when none is left. Commits remember the best one in the directory cache.
    fn accept_fetched_key_packages(
        &self,
        purpose: MemberResolutionPurpose,
        selected: Vec<FetchedKeyPackage>,
        relay_lists: &AccountRelayListStatus,
    ) -> Result<Vec<KeyPackage>, DirectoryError> {
        let mut accepted = Vec::with_capacity(selected.len());
        let mut first_error = None;
        for mut fetched in selected {
            match self.validate_member_key_package_current(
                &fetched.account_id_hex,
                fetched.key_package.clone(),
            ) {
                Ok(key_package) => {
                    if accepted.is_empty()
                        && matches!(
                            purpose,
                            MemberResolutionPurpose::Commit | MemberResolutionPurpose::CommitFresh
                        )
                    {
                        fetched.relay_lists = relay_lists.clone();
                        self.remember_directory_key_package(&fetched)?;
                    }
                    accepted.push(key_package);
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        match first_error {
            Some(error) if accepted.is_empty() => Err(error),
            _ => Ok(accepted),
        }
    }

    fn validate_member_key_package_current(
        &self,
        account_id_hex: &str,
        key_package: KeyPackage,
    ) -> Result<KeyPackage, DirectoryError> {
        let observation =
            self.resources
                .begin(ObservedFamily::KeyPackage, "lookup", ObservedUnit::Attempt);
        let (result, outcome) = validate_current_member_key_package(account_id_hex, key_package);
        if let Some(observation) = observation {
            observation.count(outcome, ObservedUnit::Attempt, 1);
            observation.discard();
        }
        result
    }

    fn relay_lists_from_records(
        &self,
        target: &MemberTarget,
        records: Vec<transport_nostr::DirectoryRelayEventRecord>,
        endpoints: &[TransportEndpoint],
    ) -> AccountRelayListStatus {
        let mut status = fresh_relay_list_status_from_records(
            &target.account_id_hex,
            records,
            self.directory_freshness(),
        )
        .value;
        if status.bootstrap_relays.is_empty() {
            status.bootstrap_relays = endpoints
                .iter()
                .map(|endpoint| endpoint.0.clone())
                .collect();
        }
        merge_relay_list_status(target.cached_relay_lists.clone(), status)
    }

    /// Run one metadata hop with identical batching, partial-record retention,
    /// and bounded per-author fallback on both discovery and advertised relays.
    /// Completion belongs to this hop only; callers reconcile hops separately.
    /// Each member's result is kept as it arrives, and at `cut_off` the hop
    /// stops waiting for the rest.
    async fn resolve_relay_list_hop(
        &self,
        targets: &mut [MemberTarget],
        groups: Vec<(Vec<TransportEndpoint>, Vec<usize>)>,
        cut_off: Option<tokio::time::Instant>,
    ) -> Result<HopProgress, DirectoryError> {
        let specs = groups
            .into_iter()
            .flat_map(|(endpoints, indices)| {
                indices
                    .chunks(MEMBER_RESOLUTION_AUTHORS_PER_QUERY)
                    .map(|chunk| {
                        let members = chunk
                            .iter()
                            .map(|index| (*index, targets[*index].account_id_hex.clone()))
                            .collect::<Vec<_>>();
                        (endpoints.clone(), members)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let directory = self.clone();
        // One item per reply: a batch that answered, or one member's
        // single-author retry. A read that would start after the cut-off does
        // not start, and its members are left uncleared.
        let work = specs.into_iter().map(move |(endpoints, members)| {
            let directory = directory.clone();
            Box::pin(
                stream::once(started_before(cut_off, async move {
                    let authors = members.iter().map(|(_, id)| id.clone()).collect::<Vec<_>>();
                    let queries = [KIND_NIP65_RELAY_LIST, KIND_MARMOT_INBOX_RELAY_LIST]
                        .into_iter()
                        .map(|kind| {
                            DirectoryEventQuery::new(
                                kind,
                                authors.clone(),
                                authors.len() * RELAY_LIST_EVENTS_PER_AUTHOR,
                            )
                        })
                        .collect();
                    let outcome = directory
                        .relay_plane
                        .fetch_directory_events_with_completion(endpoints.clone(), queries)
                        .await
                        .map_err(DirectoryError::RelayDirectory);
                    (directory, endpoints, members, outcome)
                }))
                .filter_map(future::ready)
                .flat_map(move |(directory, endpoints, members, outcome)| {
                    let outcome = match outcome {
                        Ok(outcome) => outcome,
                        Err(error) => return stream::iter(vec![Err(error)]).left_stream(),
                    };
                    if members.len() == 1 || outcome.complete {
                        let reply = members
                            .into_iter()
                            .map(|(index, _)| (index, endpoints.clone(), outcome.clone()))
                            .collect::<Vec<_>>();
                        return stream::iter(vec![Ok(reply)]).left_stream();
                    }
                    // CLOSED and other incomplete outcomes need the same
                    // fallback as a rejected batch. Retain positive records
                    // when the single-author retry is also incomplete.
                    stream::iter(members.into_iter().map(move |(index, account_id)| {
                        let directory = directory.clone();
                        let endpoints = endpoints.clone();
                        let mut records = outcome
                            .records
                            .iter()
                            .filter(|record| record.event.pubkey == account_id)
                            .cloned()
                            .collect::<Vec<_>>();
                        started_before(cut_off, async move {
                            let queries = [KIND_NIP65_RELAY_LIST, KIND_MARMOT_INBOX_RELAY_LIST]
                                .into_iter()
                                .map(|kind| {
                                    DirectoryEventQuery::new(
                                        kind,
                                        vec![account_id.clone()],
                                        RELAY_LIST_EVENTS_PER_AUTHOR,
                                    )
                                })
                                .collect();
                            let retry = directory
                                .relay_plane
                                .fetch_directory_events_with_completion(endpoints.clone(), queries)
                                .await
                                .map_err(DirectoryError::RelayDirectory)?;
                            records.extend(retry.records);
                            Ok::<_, DirectoryError>(vec![(
                                index,
                                endpoints,
                                DirectoryFetchOutcome {
                                    records,
                                    complete: retry.complete,
                                    complete_endpoints: retry.complete_endpoints,
                                },
                            )])
                        })
                    }))
                    .buffer_unordered(MEMBER_RESOLUTION_FALLBACK_CONCURRENCY)
                    .filter_map(future::ready)
                    .right_stream()
                }),
            )
        });
        let mut results = stream::iter(work).flatten_unordered(MEMBER_RESOLUTION_RELAY_CONCURRENCY);
        // Keep each reply as it arrives, and judge them all when the hop ends,
        // as Atomic always has: a relay list's freshness is read then.
        let mut received = Vec::new();
        while let Some(reply) = next_before(&mut results, cut_off).await {
            received.extend(reply?);
        }
        drop(results);
        let mut progress = HopProgress::default();
        for (index, endpoints, outcome) in received {
            let account_id = targets[index].account_id_hex.clone();
            targets[index].relay_records.extend(
                outcome
                    .records
                    .into_iter()
                    .filter(|record| record.event.pubkey == account_id),
            );
            targets[index].relay_lists = self.relay_lists_from_records(
                &targets[index],
                targets[index].relay_records.clone(),
                &endpoints,
            );
            progress.cleared.insert(index);
            if outcome.complete
                && !fresh_relay_list_status_from_records(
                    &account_id,
                    targets[index].relay_records.clone(),
                    self.directory_freshness(),
                )
                .rejected_future
            {
                progress.completed.insert(index);
            }
        }
        Ok(progress)
    }

    async fn resolve_missing_relay_lists(
        &self,
        targets: &mut [MemberTarget],
        unresolved: &[usize],
        cut_offs: Option<PartialCutOffs>,
    ) -> Result<RelayListResolution, DirectoryError> {
        let needs_discovery = unresolved.to_vec();
        if needs_discovery.is_empty() {
            return Ok(RelayListResolution::default());
        }
        let endpoints = self.directory_source_relays(&[]);
        if endpoints.is_empty() {
            return Ok(RelayListResolution::default());
        }
        let first_hop = self
            .resolve_relay_list_hop(
                targets,
                vec![(endpoints.clone(), needs_discovery.clone())],
                cut_offs.map(|cut_offs| cut_offs.first_hop),
            )
            .await?;
        let completed_discovery = first_hop.completed;
        // Only Partial resolution has cut-offs, so only it leaves members
        // unfinished. They go no further.
        let mut unfinished = needs_discovery
            .iter()
            .copied()
            .filter(|index| !first_hop.cleared.contains(index))
            .collect::<HashSet<_>>();
        let incomplete_discovery = needs_discovery
            .iter()
            .copied()
            .filter(|index| !completed_discovery.contains(index))
            .collect::<HashSet<_>>();

        // Group the same safe outbox sets before querying. This remains pure:
        // only commit-purpose resolution persists the observed metadata.
        let mut by_outboxes = BTreeMap::<Vec<TransportEndpoint>, Vec<usize>>::new();
        for index in needs_discovery.iter().copied() {
            if unfinished.contains(&index) {
                continue;
            }
            let outbox_endpoints = self.relay_plane.retain_safe_discovered_endpoints(
                targets[index]
                    .relay_lists
                    .nip65
                    .relays
                    .iter()
                    .cloned()
                    .map(TransportEndpoint)
                    .collect(),
                "member inbox outbox discovery",
            );
            let mut outbox_endpoints = outbox_endpoints
                .into_iter()
                .filter(|endpoint| {
                    !completed_discovery.contains(&index) || !endpoints.contains(endpoint)
                })
                .collect::<Vec<_>>();
            outbox_endpoints.sort();
            if !outbox_endpoints.is_empty() {
                by_outboxes.entry(outbox_endpoints).or_default().push(index);
            }
        }
        let attempted_outbox = by_outboxes
            .values()
            .flatten()
            .copied()
            .collect::<HashSet<_>>();
        let mut invalid_outboxes = HashSet::new();
        let outbox_groups: Vec<_> = by_outboxes
            .into_iter()
            .filter_map(|(endpoints, indices)| {
                match self
                    .relay_plane
                    .sanitize_relay_endpoints(endpoints, "member inbox outbox admission")
                {
                    Ok(endpoints) => Some((endpoints, indices)),
                    Err(_) => {
                        invalid_outboxes.extend(indices);
                        None
                    }
                }
            })
            .collect();
        let outbox_hop = self
            .resolve_relay_list_hop(
                targets,
                outbox_groups,
                cut_offs.map(|cut_offs| cut_offs.outbox_hop),
            )
            .await?;
        unfinished.extend(attempted_outbox.iter().copied().filter(|index| {
            !invalid_outboxes.contains(index) && !outbox_hop.cleared.contains(index)
        }));
        let completed_outbox = outbox_hop.completed;
        let completed = completed_discovery
            .iter()
            .copied()
            .filter(|index| !attempted_outbox.contains(index) || completed_outbox.contains(index))
            .collect();
        let errors = needs_discovery
            .into_iter()
            .filter(|index| {
                if unfinished.contains(index) || invalid_outboxes.contains(index) {
                    return true;
                }
                let has_inbox = !self
                    .relay_plane
                    .retain_safe_discovered_endpoints(
                        targets[*index]
                            .relay_lists
                            .inbox
                            .relays
                            .iter()
                            .cloned()
                            .map(TransportEndpoint)
                            .collect(),
                        "member invite inbox completion",
                    )
                    .is_empty();
                !has_inbox
                    && (incomplete_discovery.contains(index)
                        || (attempted_outbox.contains(index) && !completed_outbox.contains(index)))
            })
            // The known list may be a stale cache or partial snapshot, so a
            // retry can still find usable relays; claim no verdict. Completed
            // lookups report MissingMemberInboxRoute.
            .map(|index| {
                let account = targets[index].account_id_hex.clone();
                (index, DirectoryError::DirectoryLookupIncomplete(account))
            })
            .collect();
        Ok(RelayListResolution {
            completed,
            errors,
            unfinished,
        })
    }

    // Reuse the original deadline and Partial cut-offs for each pass. The
    // refresh only clears the affected members' outcomes.
    async fn resolve_member_lookup_pass(
        &self,
        targets: &mut [MemberTarget],
        relay_list_members: &[usize],
        package_candidates: &[usize],
        outcomes: &mut [Option<Result<Vec<KeyPackage>, DirectoryError>>],
        lookup: &MemberLookup<'_>,
        prior_evidence: &HashMap<usize, KeyPackageRecoveryEvidence>,
    ) -> Result<MemberLookupCoverage, DirectoryError> {
        let mut coverage = MemberLookupCoverage {
            // A cancelled metadata pass can leave discovery-only snapshots.
            relay_lists_unfinished: package_candidates.iter().copied().collect(),
            ..MemberLookupCoverage::default()
        };
        let result = started_before(
            Some(lookup.deadline),
            tokio::time::timeout_at(lookup.deadline, async {
                let RelayListResolution {
                    completed,
                    errors,
                    unfinished,
                } = self
                    .resolve_missing_relay_lists(targets, relay_list_members, lookup.cut_offs)
                    .await?;
                coverage.relay_lists_completed = completed;
                coverage.relay_lists_unfinished = unfinished;
                for (index, error) in errors {
                    outcomes[index] = Some(Err(error));
                }
                let unresolved = package_candidates
                    .iter()
                    .copied()
                    .filter(|index| outcomes[*index].is_none())
                    .collect::<Vec<_>>();
                self.resolve_missing_key_packages(
                    targets,
                    &unresolved,
                    outcomes,
                    lookup,
                    prior_evidence,
                    &mut coverage.incompatible_evidence,
                )
                .await
            }),
        )
        .await;
        match result {
            Some(Ok(result)) => result?,
            _ => {
                for &index in package_candidates {
                    outcomes[index].get_or_insert_with(|| {
                        Err(DirectoryError::DirectoryLookupIncomplete(
                            targets[index].account_id_hex.clone(),
                        ))
                    });
                }
            }
        }
        Ok(coverage)
    }

    async fn resolve_missing_key_packages(
        &self,
        targets: &[MemberTarget],
        unresolved: &[usize],
        outcomes: &mut [Option<Result<Vec<KeyPackage>, DirectoryError>>],
        lookup: &MemberLookup<'_>,
        prior_evidence: &HashMap<usize, KeyPackageRecoveryEvidence>,
        incompatible_evidence: &mut HashMap<usize, KeyPackageRecoveryEvidence>,
    ) -> Result<(), DirectoryError> {
        let purpose = lookup.purpose;
        let requirements = lookup.requirements;
        let batch_cut_off = lookup.cut_offs.map(|cut_offs| cut_offs.key_package_batches);
        let defaults = self.directory_source_relays(&[]);
        let mut by_endpoints = BTreeMap::<Vec<TransportEndpoint>, Vec<usize>>::new();
        for index in unresolved.iter().copied() {
            let endpoints = self.relay_plane.retain_safe_discovered_endpoints(
                targets[index]
                    .relay_lists
                    .nip65
                    .relays
                    .iter()
                    .cloned()
                    .map(TransportEndpoint)
                    .collect(),
                "member KeyPackage batch fetch",
            );
            let mut endpoints = match self
                .relay_plane
                .sanitize_relay_endpoints(endpoints, "member KeyPackage route admission")
            {
                Ok(endpoints) => endpoints,
                Err(_) => {
                    outcomes[index] = Some(Err(DirectoryError::DirectoryLookupIncomplete(
                        targets[index].account_id_hex.clone(),
                    )));
                    continue;
                }
            };
            if endpoints.is_empty() {
                endpoints.clone_from(&defaults);
            }
            endpoints.sort();
            endpoints.dedup();
            if endpoints.is_empty() {
                outcomes[index] = Some(Err(DirectoryError::MissingRelayLists(vec![
                    crate::MissingRelayListKind::Nip65,
                ])));
            } else {
                by_endpoints.entry(endpoints).or_default().push(index);
            }
        }

        let request_specs = by_endpoints
            .into_iter()
            .flat_map(|(endpoints, indices)| {
                indices
                    .chunks(MEMBER_RESOLUTION_AUTHORS_PER_QUERY)
                    .map(|chunk| (endpoints.clone(), chunk.to_vec()))
                    .collect::<Vec<_>>()
            })
            .map(|(endpoints, indices)| {
                let authors = indices
                    .iter()
                    .map(|index| targets[*index].account_id_hex.clone())
                    .collect::<Vec<_>>();
                (indices, endpoints, key_package_queries(authors))
            })
            .collect::<Vec<_>>();
        let directory = self.clone();
        let requests = request_specs
            .into_iter()
            .map(move |(indices, endpoints, queries)| {
                let directory = directory.clone();
                started_before(batch_cut_off, async move {
                    let result = directory
                        .relay_plane
                        .fetch_directory_events_with_completion(endpoints, queries)
                        .await
                        .map(|outcome| outcome.records)
                        .map_err(DirectoryError::RelayDirectory);
                    (indices, result)
                })
            });
        // Record each outcome as it arrives: when the shared deadline cancels
        // this stage, members already decided keep their outcome. A batch
        // that would start after the cut-off does not start.
        let mut batches = stream::iter(requests)
            .buffer_unordered(MEMBER_RESOLUTION_RELAY_CONCURRENCY)
            .filter_map(future::ready);

        // Members whose batch read could not decide them, with what it saw.
        let mut fallback_records = BTreeMap::new();
        while let Some((indices, result)) = next_before(&mut batches, batch_cut_off).await {
            let records = result?;
            let multiple_authors = indices.len() > 1;
            let mut records_by_author = BTreeMap::<_, Vec<_>>::new();
            for record in records {
                records_by_author
                    .entry(record.event.pubkey.clone())
                    .or_default()
                    .push(record);
            }
            for index in &indices {
                let account_id = &targets[*index].account_id_hex;
                if let Some(records) = records_by_author.get(account_id) {
                    self.journal_key_package_records(account_id, records)
                        .await?;
                }
            }
            for index in indices {
                let account_id = &targets[index].account_id_hex;
                let account_records = records_by_author.remove(account_id).unwrap_or_default();
                let selected = select_key_packages_with_evidence(
                    account_id,
                    &account_records,
                    self.directory_freshness(),
                    requirements,
                    prior_evidence.get(&index),
                )
                .map(|selection| selection.value);
                // Batch results prove no coverage; every absence or rejection
                // is decided by the per-member recovery below. A single-author
                // batch that selects is used as is (D12).
                match selected {
                    Ok(selected)
                        if !selected.is_empty()
                            && (purpose == MemberResolutionPurpose::Prewarm
                                || !multiple_authors)
                            && !key_package_read_page_full(account_id, &account_records) =>
                    {
                        outcomes[index] = Some(self.accept_fetched_key_packages(
                            purpose,
                            selected,
                            &targets[index].relay_lists,
                        ));
                    }
                    // Bounded multi-author results can hide some of an
                    // account's slots or their deletion requests. Relays may
                    // cap below our requested limit, so even a short batch
                    // does not prove completeness. Prewarm only needs
                    // existence, while commits seek every device's slot from
                    // a single-author read. Neither path can detect a newer
                    // publication omitted from a non-prefix response. A full
                    // page of KeyPackages or deletion requests falls back
                    // too, and recovery reports it incomplete. Keep observed slot replacements
                    // when combining the refetch.
                    _ => {
                        fallback_records.insert(index, account_records);
                    }
                }
            }
        }

        drop(batches);
        // Every member asked for has an outcome or a fallback once its batch
        // answers, so a member with neither is in a batch the Partial cut-off
        // left unanswered.
        for &index in unresolved {
            if outcomes[index].is_none() && !fallback_records.contains_key(&index) {
                outcomes[index] = Some(Err(DirectoryError::DirectoryLookupIncomplete(
                    targets[index].account_id_hex.clone(),
                )));
            }
        }

        let fallback_specs = fallback_records
            .into_iter()
            .filter_map(|(index, observed_records)| {
                let target = targets[index].clone();
                let mut endpoints = self.relay_plane.retain_safe_discovered_endpoints(
                    target
                        .relay_lists
                        .nip65
                        .relays
                        .iter()
                        .cloned()
                        .map(TransportEndpoint)
                        .collect(),
                    "member KeyPackage fallback fetch",
                );
                if endpoints.is_empty() {
                    endpoints.clone_from(&defaults);
                }
                (!endpoints.is_empty()).then_some((index, target, endpoints, observed_records))
            })
            .collect::<Vec<_>>();
        let directory = self.clone();
        let work =
            fallback_specs
                .into_iter()
                .map(move |(index, target, endpoints, observed_records)| {
                    let directory = directory.clone();
                    async move {
                        let queries = key_package_queries(vec![target.account_id_hex.clone()]);
                        let mut observed_incompatibility = None;
                        let prior_evidence = prior_evidence.get(&index);
                        let result = async {
                            let fetched = directory
                                .relay_plane
                                .fetch_directory_events_with_completion(endpoints.clone(), queries)
                                .await
                                .map_err(DirectoryError::RelayDirectory)?;
                            let mut records = fetched.records;
                            // This supplementary lookup must not discard a
                            // valid package observed in this call's batch.
                            // Never load a previously cached package here.
                            records.extend(observed_records);
                            directory
                                .journal_key_package_records(&target.account_id_hex, &records)
                                .await?;
                            let records = directory
                                .recover_key_package_records(
                                    super::key_package_recovery::KeyPackageRecoveryRequest {
                                        account: &target.account_id_hex,
                                        searched: &endpoints,
                                        observed: records,
                                        primary_complete: fetched.complete,
                                        discovery: &directory.directory_source_relays(&[]),
                                        requirements,
                                        prior_evidence,
                                        incompatible_evidence: Some(&mut observed_incompatibility),
                                        cached_target: None,
                                        wanted: MAX_KEY_PACKAGES_PER_ACCOUNT,
                                    },
                                )
                                .await?;
                            directory
                                .journal_key_package_records(
                                    &target.account_id_hex,
                                    &records.records,
                                )
                                .await?;
                            select_key_packages_with_evidence(
                                &target.account_id_hex,
                                &records.records,
                                records.freshness,
                                requirements,
                                prior_evidence,
                            )?
                            // Recovery returned: an empty selection is a
                            // complete negative, while a non-empty one may
                            // still leave out a device (D12).
                            .into_value_or_missing(&target.account_id_hex)
                        }
                        .await;
                        (index, result, observed_incompatibility)
                    }
                });
        let mut fallback_results =
            stream::iter(work).buffer_unordered(MEMBER_RESOLUTION_FALLBACK_CONCURRENCY);
        while let Some((index, result, observed_incompatibility)) = fallback_results.next().await {
            if let Some(evidence) = observed_incompatibility {
                incompatible_evidence.insert(index, evidence);
            }
            outcomes[index] = Some(result.and_then(|selected| {
                self.accept_fetched_key_packages(purpose, selected, &targets[index].relay_lists)
            }));
        }
        Ok(())
    }
}

/// Whether a recipient's KeyPackage failed a group compatibility requirement.
pub fn key_package_requirements_are_incompatible(error: &cgka_traits::error::EngineError) -> bool {
    use cgka_traits::error::EngineError;

    match error {
        EngineError::MissingRequiredCapabilities { .. }
        | EngineError::InvalidKeyPackageCapabilities { .. } => true,
        EngineError::Other(message) => {
            message == "KeyPackage does not match target group profile or ciphersuite"
        }
        _ => false,
    }
}

fn recipient_resolution_status(error: &DirectoryError) -> Option<MemberResolutionStatus> {
    use MemberResolutionStatus as Status;
    use cgka_traits::error::EngineError;

    match error {
        DirectoryError::MissingKeyPackage {
            reason: MissingKeyPackageReason::NotFound,
            ..
        } => Some(Status::MissingKeyPackage),
        DirectoryError::MissingKeyPackage {
            reason: MissingKeyPackageReason::ObsoleteOnly,
            ..
        } => Some(Status::ObsoleteKeyPackage),
        DirectoryError::InvalidKeyPackageEvent(_) => Some(Status::InvalidKeyPackage),
        DirectoryError::MissingMemberInboxRoute(_) => Some(Status::MissingInboxRoute),
        DirectoryError::DirectoryLookupIncomplete(_) | DirectoryError::MissingRelayLists(_) => {
            Some(Status::Incomplete)
        }
        DirectoryError::KeyPackageRequirements(error)
            if key_package_requirements_are_incompatible(error) =>
        {
            Some(Status::IncompatibleKeyPackage)
        }
        DirectoryError::KeyPackageRequirements(
            EngineError::InvalidKeyPackageLifetime { .. }
            | EngineError::InvalidAccountIdentityProof(_)
            | EngineError::Serialize(_),
        ) => Some(Status::InvalidKeyPackage),
        _ => None,
    }
}

// The closed outcome accompanies the result without storing mutable flags in a closure.
fn validate_current_member_key_package(
    account_id_hex: &str,
    key_package: KeyPackage,
) -> (Result<KeyPackage, DirectoryError>, &'static str) {
    let metadata = match key_package_metadata(&key_package) {
        Ok(metadata) => metadata,
        Err(error) => {
            return (
                Err(DirectoryError::InvalidKeyPackageEvent(error.to_string())),
                "invalid",
            );
        }
    };
    if metadata.protocol_profile != ProtocolProfile::Current
        || metadata.credential_identity_hex != account_id_hex
    {
        return (
            Err(DirectoryError::InvalidKeyPackageEvent(
                "member KeyPackage identity or profile is invalid".to_owned(),
            )),
            "invalid",
        );
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now < metadata.not_before || now > metadata.not_after {
        return (
            Err(DirectoryError::InvalidKeyPackageEvent(
                "member KeyPackage is outside its current lifetime".to_owned(),
            )),
            if now > metadata.not_after {
                "expired"
            } else {
                "unavailable"
            },
        );
    }
    (Ok(key_package), "usable")
}
