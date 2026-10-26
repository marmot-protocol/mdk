//! Network-free public-profile search across every connected account's caches.

use crate::error::DirectoryError;
use std::collections::{BTreeMap, HashSet, btree_map::Entry};

use super::Directory;
use super::ids::parse_account_id_hex;
use super::records::user_record_match;
use super::resources::DirectoryResources;
use crate::{
    OFF_GRAPH_SEARCH_RADIUS, UserDirectoryRecord, UserDirectorySearchResult,
    sort_user_search_results,
};

/// Defensive materialization cap, matching the shared public directory's bound.
pub(crate) const CACHED_SEARCH_MAX_RECORDS: usize = 10_000;

impl<R: DirectoryResources> Directory<R> {
    /// Search all cached public identities, independent of social-graph reachability.
    /// This does no relay work or group-membership reads. Follow attribution is
    /// relative to `searcher_account_id_hex`; local labels and private nicknames
    /// never participate. A zero limit returns no results. Call off the UI thread.
    pub fn search_cached_users(
        &self,
        searcher_account_id_hex: &str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<UserDirectorySearchResult>, DirectoryError> {
        self.cached_search_snapshot(searcher_account_id_hex, query, limit)
            .map(|(_, results)| results)
    }

    pub(crate) fn cached_search_snapshot(
        &self,
        searcher_account_id_hex: &str,
        query: &str,
        limit: usize,
    ) -> Result<(HashSet<String>, Vec<UserDirectorySearchResult>), DirectoryError> {
        let searcher = parse_account_id_hex(searcher_account_id_hex)?;
        let query = query.trim().to_lowercase();
        if query.is_empty() || limit == 0 {
            return Ok((HashSet::new(), Vec::new()));
        }
        let follows = self.cached_search_follows(&searcher)?;
        let mut records = BTreeMap::<String, UserDirectoryRecord>::new();
        let mut insert = |mut record: UserDirectoryRecord| {
            if let Some(profile) = &mut record.profile {
                profile.source_relays.clear();
            }
            match records.entry(record.account_id_hex.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(record);
                }
                Entry::Occupied(mut entry) => {
                    if record.profile.as_ref().map(|p| p.created_at)
                        > entry.get().profile.as_ref().map(|p| p.created_at)
                    {
                        entry.insert(record);
                    }
                }
            }
        };
        let now = crate::unix_now_seconds() as i64;
        for cache in self.resources.current_caches()? {
            for record in cache.public_search_records(now)? {
                insert(record);
            }
        }
        for record in self
            .resources
            .shared_storage()?
            .public_directory_profiles()?
        {
            insert(UserDirectoryRecord {
                account_id_hex: record.account_id_hex,
                npub: record.npub,
                profile: record
                    .profile_json
                    .map(|json| serde_json::from_str(&json))
                    .transpose()?,
                local_account: None,
                follows: Vec::new(),
                follow_source_relays: Vec::new(),
                relay_lists: crate::AccountRelayListStatus::empty(),
                key_package: None,
            });
        }
        let mut results = records
            .into_values()
            .filter_map(|record| {
                let found = user_record_match(&record, &query)?;
                let is_followed_by_searcher = follows.contains(&record.account_id_hex);
                let radius = if record.account_id_hex == searcher {
                    0
                } else if is_followed_by_searcher {
                    1
                } else {
                    OFF_GRAPH_SEARCH_RADIUS
                };
                Some(UserDirectorySearchResult {
                    account_id_hex: record.account_id_hex,
                    npub: record.npub,
                    radius,
                    is_followed_by_searcher,
                    matched_field: found.field,
                    match_quality: found.quality,
                    provider_rank: None,
                    profile: record.profile,
                })
            })
            .collect::<Vec<_>>();
        sort_user_search_results(&mut results);
        results.truncate(limit.min(CACHED_SEARCH_MAX_RECORDS));
        Ok((follows, results))
    }

    pub(crate) fn cached_search_follows(
        &self,
        searcher: &str,
    ) -> Result<HashSet<String>, DirectoryError> {
        Ok(self
            .cached_search_follow_list(searcher)?
            .unwrap_or_default()
            .into_iter()
            .collect())
    }

    /// Prefer a connected searcher's own contact-list cache. Other accounts may
    /// hold older copies of its public kind-3 and cannot override its follow badge.
    /// `None` retains the distinction between unknown and explicitly empty lists.
    pub(crate) fn cached_search_follow_list(
        &self,
        searcher: &str,
    ) -> Result<Option<Vec<String>>, DirectoryError> {
        let account = self
            .resources
            .local_accounts()?
            .into_iter()
            .find(|account| account.account_id_hex == searcher && account.active_signing);
        let caches = if let Some(account) = account {
            vec![self.resources.cache_for_account(&account)?]
        } else {
            // The Rust API also supports a public, non-connected graph root.
            self.resources.current_caches()?
        };
        for cache in &caches {
            if let Some(follows) = cache.search_graph_follows(searcher)? {
                return Ok(Some(follows));
            }
        }
        for cache in &caches {
            if let Some(record) = cache.entry(searcher)?
                && !record.follows.is_empty()
            {
                return Ok(Some(record.follows));
            }
        }
        Ok(None)
    }
}
