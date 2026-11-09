//! Network-free public-profile search across every connected account's caches.

use crate::error::DirectoryError;
use std::collections::{BTreeMap, HashSet, btree_map::Entry};

use super::Directory;
use super::cache::DirectoryCache;
use super::ids::parse_account_id_hex;
use super::records::user_record_match;
use super::resources::DirectoryResources;
use crate::{
    OFF_GRAPH_SEARCH_RADIUS, UserDirectoryRecord, UserDirectorySearchResult,
    sort_user_search_results,
};
use storage_sqlite::{PublicDirectoryProfileRecord, SqliteSharedStorage};

/// Defensive materialization cap, matching the shared public directory's bound.
pub(crate) const CACHED_SEARCH_MAX_RECORDS: usize = 10_000;

type SearchProfile = (PublicDirectoryProfileRecord, Option<u64>, u8);

#[cfg(test)]
thread_local! {
    static PROFILE_DECODES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn cached_profiles(
    caches: &[DirectoryCache],
    shared: &SqliteSharedStorage,
    query: &str,
    now: i64,
) -> Result<Vec<SearchProfile>, DirectoryError> {
    let mut ids = HashSet::new();
    for cache in caches {
        ids.extend(
            cache
                .public_search_records(now, query, &[])?
                .into_iter()
                .map(|row| row.0.account_id_hex),
        );
    }
    ids.extend(
        shared
            .public_directory_profiles(query, &[])?
            .into_iter()
            .map(|row| row.0.account_id_hex),
    );
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let ids = ids.into_iter().collect::<Vec<_>>();
    let mut profiles = BTreeMap::<String, SearchProfile>::new();
    let mut insert = |row: SearchProfile| match profiles.entry(row.0.account_id_hex.clone()) {
        Entry::Vacant(entry) => {
            entry.insert(row);
        }
        Entry::Occupied(mut entry) => {
            if row.1 > entry.get().1 {
                entry.insert(row);
            }
        }
    };
    // A newer profile in another cache can remove a match. Resolve every
    // candidate against all stores before ranking, without decoding JSON.
    for cache in caches {
        for row in cache.public_search_records(now, query, &ids)? {
            insert(row);
        }
    }
    for row in shared.public_directory_profiles(query, &ids)? {
        insert(row);
    }
    Ok(profiles.into_values().filter(|row| row.2 < 18).collect())
}

fn cached_results(
    mut profiles: Vec<SearchProfile>,
    searcher: &str,
    follows: &HashSet<String>,
    query: &str,
    limit: usize,
) -> Result<Vec<UserDirectorySearchResult>, DirectoryError> {
    profiles.sort_unstable_by(|a, b| {
        let key = |row: &SearchProfile| {
            (
                row.0.account_id_hex != searcher,
                !follows.contains(&row.0.account_id_hex),
                row.2,
            )
        };
        key(a)
            .cmp(&key(b))
            .then_with(|| a.0.account_id_hex.cmp(&b.0.account_id_hex))
    });
    profiles.truncate(limit.min(CACHED_SEARCH_MAX_RECORDS));
    let mut results = Vec::with_capacity(profiles.len());
    for (raw, _, _) in profiles {
        let profile = raw
            .profile_json
            .map(|json| {
                #[cfg(test)]
                PROFILE_DECODES.set(PROFILE_DECODES.get() + 1);
                serde_json::from_str::<crate::UserProfileMetadata>(&json)
            })
            .transpose()?;
        let mut record = UserDirectoryRecord {
            account_id_hex: raw.account_id_hex,
            npub: raw.npub,
            profile,
            local_account: None,
            follows: Vec::new(),
            follow_source_relays: Vec::new(),
            relay_lists: crate::AccountRelayListStatus::empty(),
            key_package: None,
        };
        if let Some(profile) = &mut record.profile {
            profile.source_relays.clear();
        }
        let Some(found) = user_record_match(&record, query) else {
            continue;
        };
        let is_followed_by_searcher = follows.contains(&record.account_id_hex);
        let radius = if record.account_id_hex == searcher {
            0
        } else if is_followed_by_searcher {
            1
        } else {
            OFF_GRAPH_SEARCH_RADIUS
        };
        results.push(UserDirectorySearchResult {
            account_id_hex: record.account_id_hex,
            npub: record.npub,
            radius,
            is_followed_by_searcher,
            matched_field: found.field,
            match_quality: found.quality,
            provider_rank: None,
            profile: record.profile,
        });
    }
    sort_user_search_results(&mut results);
    Ok(results)
}

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
        let query = storage_sqlite::normalize_search_text(query);
        if query.is_empty() || limit == 0 {
            return Ok((HashSet::new(), Vec::new()));
        }
        let follows = self.cached_search_follows(&searcher)?;
        let now = crate::unix_now_seconds() as i64;
        let profiles = cached_profiles(
            &self.resources.current_caches()?,
            &self.resources.shared_storage()?,
            &query,
            now,
        )?;
        let results = cached_results(profiles, &searcher, &follows, &query, limit)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use storage_sqlite::SqlCipherKey;

    fn cache(root: &std::path::Path, name: &str) -> DirectoryCache {
        DirectoryCache::open(root.join(name), &SqlCipherKey::raw([7; 32])).unwrap()
    }

    #[test]
    fn cached_search_decodes_only_ranked_candidates() {
        let root = tempfile::tempdir().unwrap();
        let cache = cache(root.path(), "cache.sqlite3");
        cache.lock().unwrap().execute_batch(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<5000)
             INSERT INTO directory_users(account_id_hex,npub,profile_json,relay_lists_json,updated_at)
             SELECT printf('%064x',x), 'npub',
                 json_object('name', CASE
                     WHEN x=4998 THEN 'xyz'
                     WHEN x=4997 THEN 'xyz suffix'
                     WHEN x<=500 OR x>=4999 THEN 'a xyz'
                     ELSE 'unrelated' END, 'created_at', 1), '{}', 0 FROM n;",
        ).unwrap();
        let shared = SqliteSharedStorage::in_memory().unwrap();
        let searcher = format!("{:064x}", 5000);
        let follows = HashSet::from([format!("{:064x}", 4999)]);
        PROFILE_DECODES.set(0);
        let profiles = cached_profiles(&[cache], &shared, "xyz", 0).unwrap();
        let limit = 5;
        let results = cached_results(profiles, &searcher, &follows, "xyz", limit).unwrap();
        assert_eq!(
            results
                .iter()
                .map(|row| row.account_id_hex.clone())
                .collect::<Vec<_>>(),
            [5000, 4999, 4998, 4997, 1].map(|id| format!("{id:064x}"))
        );
        assert_eq!(PROFILE_DECODES.get(), limit);
        assert!(PROFILE_DECODES.get() <= limit * 4);
    }

    #[test]
    fn cached_search_newer_nonmatches_suppress_stale_matches() {
        let root = tempfile::tempdir().unwrap();
        let first = cache(root.path(), "first.sqlite3");
        let second = cache(root.path(), "second.sqlite3");
        first.lock().unwrap().execute_batch(
            "INSERT INTO directory_users(account_id_hex,npub,profile_json,relay_lists_json,updated_at)
             VALUES ('a','npub','{\"name\":\"xyz\",\"created_at\":1}','{}',0),
                    ('b','npub','{\"name\":\"xyz\",\"created_at\":1}','{}',0),
                    ('c','npub','{\"name\":\"xyz\",\"created_at\":1}','{}',0);",
        ).unwrap();
        second.lock().unwrap().execute_batch(
            "INSERT INTO directory_users(account_id_hex,npub,profile_json,relay_lists_json,updated_at)
             VALUES ('a','npub','{\"name\":\"renamed\",\"created_at\":2}','{}',0);",
        ).unwrap();
        let shared = SqliteSharedStorage::in_memory().unwrap();
        shared
            .put_public_directory_user(&storage_sqlite::PublicDirectoryUserRecord {
                account_id_hex: "b".into(),
                npub: "npub".into(),
                profile_json: Some(r#"{"name":"renamed","created_at":2}"#.into()),
                relay_lists_json: "{}".into(),
                key_package_json: None,
                event_id_hex: None,
                event_kind: None,
                event_created_at: None,
                follows: Vec::new(),
            })
            .unwrap();
        let profiles = cached_profiles(&[first, second], &shared, "xyz", 0).unwrap();
        let results = cached_results(profiles, "searcher", &HashSet::new(), "xyz", 1).unwrap();
        assert_eq!(
            results
                .iter()
                .map(|row| row.account_id_hex.as_str())
                .collect::<Vec<_>>(),
            vec!["c"]
        );
    }
}
