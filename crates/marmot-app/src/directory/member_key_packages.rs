//! Set-oriented group-member KeyPackage resolution.
//!
//! The create and invite paths know the whole requested roster before they
//! mutate MLS state. Resolve that set as a set: canonicalize aliases, collapse
//! duplicate account ids, reuse validated local/directory entries, and batch
//! cold relay work by compatible endpoint set. The legacy one-member resolver
//! remains the bounded fallback for relay/query shapes that do not support a
//! multi-author request.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cgka_engine::key_package::key_package_metadata;
use cgka_traits::TransportEndpoint;
use cgka_traits::engine::KeyPackage;
use cgka_traits::group::ProtocolProfile;
use futures::{StreamExt, stream};
use nostr_sdk::prelude::PublicKey;
use transport_nostr_adapter::{
    KIND_MARMOT_INBOX_RELAY_LIST, KIND_MARMOT_KEY_PACKAGE, KIND_NIP65_RELAY_LIST,
};

use crate::key_package_records::{
    fresh_or_cached_key_package, fresh_relay_list_status_from_records,
    latest_fresh_key_package_from_records, validated_cached_key_package,
};
use crate::relay_plane::DirectoryEventQuery;
use crate::{AccountRelayListStatus, AppError, FetchedKeyPackage, MarmotApp, push_unique_strings};

/// Maximum authors placed in one Nostr directory filter.
pub(crate) const MEMBER_RESOLUTION_AUTHORS_PER_QUERY: usize = 32;
/// Concurrent endpoint-group/chunk requests within one resolution pass.
const MEMBER_RESOLUTION_RELAY_CONCURRENCY: usize = 4;
/// Existing per-member fallback concurrency, retained for incompatible relays.
const MEMBER_RESOLUTION_FALLBACK_CONCURRENCY: usize = 8;
/// One complete set resolution is bounded even when several relay sets stall.
const MEMBER_RESOLUTION_DEADLINE: Duration = Duration::from_secs(10);
const KEY_PACKAGE_EVENTS_PER_AUTHOR: usize = 12;
const RELAY_LIST_EVENTS_PER_AUTHOR: usize = 4;
const MEMBER_PREWARM_CACHE_LIMIT: usize = 256;
const MEMBER_PREWARM_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
struct MemberKeyPackagePrewarmEntry {
    fetched: FetchedKeyPackage,
    inserted_at: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fetched(account_id_hex: String) -> FetchedKeyPackage {
        FetchedKeyPackage {
            account_id_hex,
            key_package: KeyPackage::new(vec![1]),
            key_package_id: "slot".to_owned(),
            key_package_ref_hex: "ref".to_owned(),
            key_package_event_id: String::new(),
            created_at: 1,
            source_relays: Vec::new(),
            relay_lists: AccountRelayListStatus::empty(),
        }
    }

    #[test]
    fn composition_prewarm_cache_is_bounded_and_expires_entries() {
        let mut cache = MemberKeyPackagePrewarmCache::default();
        for index in 0..=MEMBER_PREWARM_CACHE_LIMIT {
            cache.insert(fetched(format!("{index:064x}")));
        }
        assert_eq!(cache.entries.len(), MEMBER_PREWARM_CACHE_LIMIT);
        assert!(cache.get(&format!("{:064x}", 0)).is_none());

        let newest = format!("{:064x}", MEMBER_PREWARM_CACHE_LIMIT);
        cache.entries.get_mut(&newest).unwrap().inserted_at =
            Instant::now() - MEMBER_PREWARM_CACHE_TTL - Duration::from_secs(1);
        assert!(cache.get(&newest).is_none());
        assert!(!cache.order.contains(&newest));
    }
}

#[derive(Default)]
pub(crate) struct MemberKeyPackagePrewarmCache {
    entries: HashMap<String, MemberKeyPackagePrewarmEntry>,
    order: VecDeque<String>,
}

impl MemberKeyPackagePrewarmCache {
    fn get(&mut self, account_id_hex: &str) -> Option<FetchedKeyPackage> {
        self.remove_expired();
        self.entries
            .get(account_id_hex)
            .map(|entry| entry.fetched.clone())
    }

    fn insert(&mut self, fetched: FetchedKeyPackage) {
        self.remove_expired();
        let account_id_hex = fetched.account_id_hex.clone();
        self.order.retain(|existing| existing != &account_id_hex);
        self.order.push_back(account_id_hex.clone());
        self.entries.insert(
            account_id_hex,
            MemberKeyPackagePrewarmEntry {
                fetched,
                inserted_at: Instant::now(),
            },
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
enum MemberResolutionPurpose {
    Commit,
    Prewarm,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemberKeyPackagePrewarmSummary {
    /// Number of member references supplied by the host.
    pub requested_members: u64,
    /// Canonical account ids after aliases and duplicates are collapsed.
    pub unique_members: u64,
    /// Packages satisfied by validated local state, durable directory state,
    /// or the process-local prewarm cache.
    pub reused_members: u64,
    /// Packages that required relay resolution during this call.
    pub network_resolved_members: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MemberKeyPackageResolutionStats {
    pub(crate) requested_members: usize,
    pub(crate) unique_members: usize,
    pub(crate) reused_members: usize,
    pub(crate) network_resolved_members: usize,
}

impl From<MemberKeyPackageResolutionStats> for MemberKeyPackagePrewarmSummary {
    fn from(stats: MemberKeyPackageResolutionStats) -> Self {
        Self {
            requested_members: stats.requested_members as u64,
            unique_members: stats.unique_members as u64,
            reused_members: stats.reused_members as u64,
            network_resolved_members: stats.network_resolved_members as u64,
        }
    }
}

#[derive(Clone)]
struct MemberTarget {
    account_id_hex: String,
    local_label: Option<String>,
    relay_lists: AccountRelayListStatus,
}

#[allow(dead_code)]
fn member_resolution_future_is_send(app: &MarmotApp) {
    fn assert_send<T: Send>(_: T) {}
    assert_send(app.resolve_member_key_packages(&[]));
}

pub(crate) struct ResolvedMemberKeyPackages {
    pub(crate) key_packages: Vec<KeyPackage>,
    pub(crate) stats: MemberKeyPackageResolutionStats,
}

impl MarmotApp {
    /// Resolve a roster as one deterministic set.
    ///
    /// Account aliases are canonicalized and duplicate account ids collapse to
    /// their first input position. On error, the error belonging to the first
    /// unresolved canonical member is returned even if later relay work
    /// completed earlier.
    pub async fn resolve_member_key_packages(
        &self,
        member_refs: &[&str],
    ) -> Result<Vec<KeyPackage>, AppError> {
        let member_refs = member_refs
            .iter()
            .map(|member_ref| (*member_ref).to_owned())
            .collect::<Vec<_>>();
        Ok(self
            .resolve_member_key_packages_with_stats(member_refs)
            .await?
            .key_packages)
    }

    /// Prewarm group composition without reserving or consuming any package.
    /// A later create call re-reads and validates the cached bytes, and the MLS
    /// mutation boundary still performs its ordinary lifetime/single-use
    /// validation.
    pub async fn prewarm_group_member_key_packages(
        &self,
        member_refs: &[&str],
    ) -> Result<MemberKeyPackagePrewarmSummary, AppError> {
        let member_refs = member_refs
            .iter()
            .map(|member_ref| (*member_ref).to_owned())
            .collect::<Vec<_>>();
        self.resolve_member_key_packages_for_purpose(member_refs, MemberResolutionPurpose::Prewarm)
            .await
            .map(|resolved| resolved.stats.into())
    }

    pub(crate) async fn resolve_member_key_packages_with_stats(
        &self,
        member_refs: Vec<String>,
    ) -> Result<ResolvedMemberKeyPackages, AppError> {
        self.resolve_member_key_packages_for_purpose(member_refs, MemberResolutionPurpose::Commit)
            .await
    }

    async fn resolve_member_key_packages_for_purpose(
        &self,
        member_refs: Vec<String>,
        purpose: MemberResolutionPurpose,
    ) -> Result<ResolvedMemberKeyPackages, AppError> {
        match tokio::time::timeout(
            MEMBER_RESOLUTION_DEADLINE,
            self.resolve_member_key_packages_inner(&member_refs, purpose),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(AppError::RelayDirectory(
                "member KeyPackage resolution deadline exceeded".to_owned(),
            )),
        }
    }

    async fn resolve_member_key_packages_inner(
        &self,
        member_refs: &[String],
        purpose: MemberResolutionPurpose,
    ) -> Result<ResolvedMemberKeyPackages, AppError> {
        let mut seen = HashSet::new();
        let mut targets = Vec::new();
        for member_ref in member_refs {
            let local = self.account_home().account(member_ref).ok();
            let account_id_hex = match &local {
                Some(account) => account.account_id_hex.clone(),
                None => PublicKey::parse(member_ref)
                    .map_err(|_| AppError::InvalidPublicKey)?
                    .to_hex(),
            };
            if !seen.insert(account_id_hex.clone()) {
                continue;
            }
            let relay_lists = self
                .directory_entry_for_account_id(&account_id_hex)?
                .map(|entry| entry.relay_lists)
                .unwrap_or_else(AccountRelayListStatus::empty);
            targets.push(MemberTarget {
                account_id_hex,
                local_label: local.map(|account| account.label),
                relay_lists,
            });
        }

        let mut outcomes = (0..targets.len())
            .map(|_| None)
            .collect::<Vec<Option<Result<KeyPackage, AppError>>>>();
        let mut unresolved = Vec::new();
        let mut reused_members = 0usize;
        for (index, target) in targets.iter().enumerate() {
            if let Some(label) = &target.local_label
                && let Some(key_package) = self.validated_current_local_key_package(label)
                && let Ok(key_package) =
                    self.validate_member_key_package_current(&target.account_id_hex, key_package)
            {
                outcomes[index] = Some(Ok(key_package));
                reused_members += 1;
                continue;
            }
            let cached = self.directory_entry_for_account_id(&target.account_id_hex)?;
            if let Some(key_package) = cached.and_then(|entry| entry.key_package)
                && let Ok(key_package) =
                    validated_cached_key_package(&target.account_id_hex, &key_package)
                && let Ok(key_package) =
                    self.validate_member_key_package_current(&target.account_id_hex, key_package)
            {
                outcomes[index] = Some(Ok(key_package));
                reused_members += 1;
                continue;
            }
            let prefetched = self
                .member_key_package_prewarm_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(&target.account_id_hex);
            if let Some(fetched) = prefetched
                && let Ok(key_package) = self.accept_prefetched_key_package(purpose, fetched)
            {
                outcomes[index] = Some(Ok(key_package));
                reused_members += 1;
                continue;
            }
            unresolved.push(index);
        }

        if !unresolved.is_empty() {
            for (index, error) in self
                .resolve_missing_relay_lists(&mut targets, &unresolved)
                .await
            {
                outcomes[index] = Some(Err(error));
            }
            let key_package_unresolved = unresolved
                .iter()
                .copied()
                .filter(|index| outcomes[*index].is_none())
                .collect::<Vec<_>>();
            self.resolve_missing_key_packages(
                &targets,
                &key_package_unresolved,
                &mut outcomes,
                purpose,
            )
            .await;
        }

        let mut key_packages = Vec::with_capacity(targets.len());
        for (index, outcome) in outcomes.into_iter().enumerate() {
            match outcome.unwrap_or_else(|| {
                Err(AppError::MissingKeyPackage(
                    targets[index].account_id_hex.clone(),
                ))
            }) {
                Ok(key_package) => key_packages.push(key_package),
                Err(error) => return Err(error),
            }
        }
        Ok(ResolvedMemberKeyPackages {
            key_packages,
            stats: MemberKeyPackageResolutionStats {
                requested_members: member_refs.len(),
                unique_members: targets.len(),
                reused_members,
                network_resolved_members: unresolved.len(),
            },
        })
    }

    fn accept_prefetched_key_package(
        &self,
        purpose: MemberResolutionPurpose,
        fetched: FetchedKeyPackage,
    ) -> Result<KeyPackage, AppError> {
        let key_package = self.validate_member_key_package_current(
            &fetched.account_id_hex,
            fetched.key_package.clone(),
        )?;
        match purpose {
            MemberResolutionPurpose::Commit => self.remember_directory_key_package(&fetched)?,
            MemberResolutionPurpose::Prewarm => self
                .member_key_package_prewarm_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(fetched),
        }
        Ok(key_package)
    }

    fn validate_member_key_package_current(
        &self,
        account_id_hex: &str,
        key_package: KeyPackage,
    ) -> Result<KeyPackage, AppError> {
        let metadata = key_package_metadata(&key_package)
            .map_err(|error| AppError::InvalidKeyPackageEvent(error.to_string()))?;
        if metadata.protocol_profile != ProtocolProfile::Current
            || metadata.credential_identity_hex != account_id_hex
        {
            return Err(AppError::InvalidKeyPackageEvent(
                "member KeyPackage identity or profile is invalid".to_owned(),
            ));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now < metadata.not_before || now > metadata.not_after {
            return Err(AppError::InvalidKeyPackageEvent(
                "member KeyPackage is outside its current lifetime".to_owned(),
            ));
        }
        Ok(key_package)
    }

    fn relay_lists_from_records(
        &self,
        target: &MemberTarget,
        records: Vec<crate::relay_plane::DirectoryRelayEventRecord>,
        endpoints: &[TransportEndpoint],
    ) -> AccountRelayListStatus {
        let freshness = self.directory_freshness();
        let observed_nip65 = records
            .iter()
            .any(|record| record.event.kind == KIND_NIP65_RELAY_LIST && freshness.accepts(record));
        let observed_inbox = records.iter().any(|record| {
            record.event.kind == KIND_MARMOT_INBOX_RELAY_LIST && freshness.accepts(record)
        });
        let mut status =
            fresh_relay_list_status_from_records(&target.account_id_hex, records, freshness).value;
        if !observed_nip65 {
            status.nip65 = target.relay_lists.nip65.clone();
        }
        if !observed_inbox {
            status.inbox = target.relay_lists.inbox.clone();
        }
        push_unique_strings(
            &mut status.bootstrap_relays,
            target.relay_lists.bootstrap_relays.clone(),
        );
        if status.bootstrap_relays.is_empty() {
            status.bootstrap_relays = endpoints
                .iter()
                .map(|endpoint| endpoint.0.clone())
                .collect();
        }
        status.refresh();
        status
    }

    async fn resolve_missing_relay_lists(
        &self,
        targets: &mut [MemberTarget],
        unresolved: &[usize],
    ) -> Vec<(usize, AppError)> {
        let needs_discovery = unresolved
            .iter()
            .copied()
            .filter(|index| targets[*index].relay_lists.nip65.relays.is_empty())
            .collect::<Vec<_>>();
        if needs_discovery.is_empty() {
            return Vec::new();
        }
        let endpoints = self.directory_source_relays(&[]);
        if endpoints.is_empty() {
            return Vec::new();
        }

        let request_specs = needs_discovery
            .chunks(MEMBER_RESOLUTION_AUTHORS_PER_QUERY)
            .map(|chunk| {
                let indices = chunk.to_vec();
                let authors = chunk
                    .iter()
                    .map(|index| targets[*index].account_id_hex.clone())
                    .collect::<Vec<_>>();
                let queries = [KIND_NIP65_RELAY_LIST, KIND_MARMOT_INBOX_RELAY_LIST]
                    .into_iter()
                    .map(|kind| {
                        DirectoryEventQuery::new(
                            kind,
                            authors.clone(),
                            authors.len() * RELAY_LIST_EVENTS_PER_AUTHOR,
                        )
                    })
                    .collect::<Vec<_>>();
                (indices, endpoints.clone(), queries)
            })
            .collect::<Vec<_>>();
        let app = self.clone();
        let requests = request_specs
            .into_iter()
            .map(move |(indices, endpoints, queries)| {
                let app = app.clone();
                async move {
                    let records = app
                        .relay_plane
                        .fetch_directory_events(endpoints.clone(), queries)
                        .await
                        .map_err(|error| {
                            AppError::RelayDirectory(format!("fetch relay lists: {error}"))
                        });
                    (indices, endpoints, records)
                }
            });
        let batches = stream::iter(requests)
            .buffered(MEMBER_RESOLUTION_RELAY_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;

        let mut failures = Vec::new();
        for (indices, endpoints, result) in batches {
            match result {
                Ok(records) => {
                    for index in indices {
                        let account_id = &targets[index].account_id_hex;
                        let account_records = records
                            .iter()
                            .filter(|record| record.event.pubkey == *account_id)
                            .cloned()
                            .collect::<Vec<_>>();
                        targets[index].relay_lists = self.relay_lists_from_records(
                            &targets[index],
                            account_records,
                            &endpoints,
                        );
                    }
                }
                Err(_) => {
                    // Preserve the established single-author behavior for
                    // relays that reject multi-author query shapes without
                    // promoting composition-only strangers into durable cache.
                    let specs = indices
                        .into_iter()
                        .map(|index| (index, targets[index].account_id_hex.clone()))
                        .collect::<Vec<_>>();
                    let app = self.clone();
                    let work = specs.into_iter().map(move |(index, account_id)| {
                        let app = app.clone();
                        let endpoints = endpoints.clone();
                        async move {
                            let queries = [KIND_NIP65_RELAY_LIST, KIND_MARMOT_INBOX_RELAY_LIST]
                                .into_iter()
                                .map(|kind| {
                                    DirectoryEventQuery::new(
                                        kind,
                                        vec![account_id.clone()],
                                        RELAY_LIST_EVENTS_PER_AUTHOR,
                                    )
                                })
                                .collect::<Vec<_>>();
                            let records = app
                                .relay_plane
                                .fetch_directory_events(endpoints.clone(), queries)
                                .await
                                .map_err(|error| {
                                    AppError::RelayDirectory(format!("fetch relay lists: {error}"))
                                });
                            (index, endpoints, records)
                        }
                    });
                    let results = stream::iter(work)
                        .buffered(MEMBER_RESOLUTION_FALLBACK_CONCURRENCY)
                        .collect::<Vec<_>>()
                        .await;
                    for (index, endpoints, records) in results {
                        match records {
                            Ok(records) => {
                                targets[index].relay_lists = self.relay_lists_from_records(
                                    &targets[index],
                                    records,
                                    &endpoints,
                                );
                            }
                            Err(error) => failures.push((index, error)),
                        }
                    }
                }
            }
        }
        failures
    }

    async fn resolve_missing_key_packages(
        &self,
        targets: &[MemberTarget],
        unresolved: &[usize],
        outcomes: &mut [Option<Result<KeyPackage, AppError>>],
        purpose: MemberResolutionPurpose,
    ) {
        let defaults = self.directory_source_relays(&[]);
        let mut by_endpoints = BTreeMap::<Vec<TransportEndpoint>, Vec<usize>>::new();
        for index in unresolved.iter().copied() {
            let mut endpoints = self.retain_safe_discovered_endpoints(
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
            if endpoints.is_empty() {
                endpoints.clone_from(&defaults);
            }
            endpoints.sort();
            endpoints.dedup();
            if endpoints.is_empty() {
                outcomes[index] = Some(Err(AppError::MissingRelayLists(vec![
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
                let query = DirectoryEventQuery::new(
                    KIND_MARMOT_KEY_PACKAGE,
                    authors.clone(),
                    authors.len() * KEY_PACKAGE_EVENTS_PER_AUTHOR,
                );
                (indices, endpoints, query)
            })
            .collect::<Vec<_>>();
        let app = self.clone();
        let requests = request_specs
            .into_iter()
            .map(move |(indices, endpoints, query)| {
                let app = app.clone();
                async move {
                    let result = app
                        .relay_plane
                        .fetch_directory_events(endpoints, vec![query])
                        .await
                        .map_err(|error| {
                            AppError::RelayDirectory(format!("fetch key packages: {error}"))
                        });
                    (indices, result)
                }
            });
        let batches = stream::iter(requests)
            .buffered(MEMBER_RESOLUTION_RELAY_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;

        let mut fallback = Vec::new();
        for (indices, result) in batches {
            let Ok(records) = result else {
                fallback.extend(indices);
                continue;
            };
            for index in indices {
                let account_id = &targets[index].account_id_hex;
                let account_records = records
                    .iter()
                    .filter(|record| record.event.pubkey == *account_id)
                    .cloned()
                    .collect::<Vec<_>>();
                let cached = self
                    .directory_entry_for_account_id(account_id)
                    .ok()
                    .flatten();
                let selected = latest_fresh_key_package_from_records(
                    account_id,
                    account_records,
                    self.directory_freshness(),
                )
                .and_then(|selection| fresh_or_cached_key_package(account_id, selection, cached));
                match selected {
                    Ok(mut fetched) => {
                        fetched.relay_lists = targets[index].relay_lists.clone();
                        outcomes[index] =
                            Some(self.accept_prefetched_key_package(purpose, fetched));
                    }
                    Err(_) => fallback.push(index),
                }
            }
        }

        fallback.sort_unstable();
        fallback.dedup();
        let fallback_specs = fallback
            .into_iter()
            .filter_map(|index| {
                let target = targets[index].clone();
                let mut endpoints = self.retain_safe_discovered_endpoints(
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
                (!endpoints.is_empty()).then_some((index, target, endpoints))
            })
            .collect::<Vec<_>>();
        let app = self.clone();
        let work = fallback_specs
            .into_iter()
            .map(move |(index, target, endpoints)| {
                let app = app.clone();
                async move {
                    let query = DirectoryEventQuery::new(
                        KIND_MARMOT_KEY_PACKAGE,
                        vec![target.account_id_hex.clone()],
                        KEY_PACKAGE_EVENTS_PER_AUTHOR,
                    );
                    let result = async {
                        let records = app
                            .relay_plane
                            .fetch_directory_events(endpoints, vec![query])
                            .await
                            .map_err(|error| {
                                AppError::RelayDirectory(format!("fetch key packages: {error}"))
                            })?;
                        let cached = app.directory_entry_for_account_id(&target.account_id_hex)?;
                        let mut fetched = fresh_or_cached_key_package(
                            &target.account_id_hex,
                            latest_fresh_key_package_from_records(
                                &target.account_id_hex,
                                records,
                                app.directory_freshness(),
                            )?,
                            cached,
                        )?;
                        fetched.relay_lists = target.relay_lists;
                        Ok::<_, AppError>(fetched)
                    }
                    .await;
                    (index, result)
                }
            });
        let fallback_results = stream::iter(work)
            .buffered(MEMBER_RESOLUTION_FALLBACK_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;
        for (index, result) in fallback_results {
            outcomes[index] = Some(
                result.and_then(|fetched| self.accept_prefetched_key_package(purpose, fetched)),
            );
        }
    }
}
