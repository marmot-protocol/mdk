//! Network-free public-profile search across every connected account's caches.

use std::collections::{BTreeMap, HashSet};

use super::records::{user_directory_record_from_public, user_record_match};
use crate::{
    AppError, MarmotApp, OFF_GRAPH_SEARCH_RADIUS, UserDirectoryRecord, UserDirectorySearchResult,
    parse_account_id_hex, sort_user_search_results,
};

impl MarmotApp {
    /// Search all cached public identities, independent of social-graph reachability.
    /// This does no relay work or group-membership reads. Follow attribution is
    /// relative to `searcher_account_id_hex`; local labels and private nicknames
    /// never participate. A zero limit returns no results. Call off the UI thread.
    pub fn search_cached_users(
        &self,
        searcher_account_id_hex: &str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<UserDirectorySearchResult>, AppError> {
        self.cached_search_snapshot(searcher_account_id_hex, query, limit)
            .map(|(_, results)| results)
    }

    pub(crate) fn cached_search_snapshot(
        &self,
        searcher_account_id_hex: &str,
        query: &str,
        limit: usize,
    ) -> Result<(HashSet<String>, Vec<UserDirectorySearchResult>), AppError> {
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
            let current = records
                .entry(record.account_id_hex.clone())
                .or_insert_with(|| record.clone());
            if record.profile.as_ref().map(|p| p.created_at)
                > current.profile.as_ref().map(|p| p.created_at)
            {
                *current = record;
            }
        };
        let now = crate::unix_now_seconds() as i64;
        for cache in self.directory_caches()? {
            for record in cache.public_search_records(now)? {
                insert(record);
            }
        }
        for record in self.shared_storage()?.public_directory_users()? {
            insert(user_directory_record_from_public(record)?);
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
        results.truncate(limit);
        Ok((follows, results))
    }

    pub(crate) fn cached_search_follows(
        &self,
        searcher: &str,
    ) -> Result<HashSet<String>, AppError> {
        // A previous search may have learned the selected account's kind-3
        // without promoting its profile into the directory.
        for cache in self.directory_caches()? {
            if let Some(follows) = cache.search_graph_follows(searcher)? {
                return Ok(follows.into_iter().collect());
            }
        }
        Ok(self
            .directory_entry_for_account_id(searcher)?
            .map(|record| record.follows.into_iter().collect())
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::cache::DirectorySearchGraphRecord;
    use crate::directory::records::public_directory_user_record;
    use crate::{UserDirectoryLocalAccount, UserProfileMetadata};

    #[test]
    fn public_cache_spans_accounts_but_follow_labels_do_not() {
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.invalid");
        let alice = app
            .account_home()
            .create_account("private-alice-label")
            .unwrap();
        let bob = app
            .account_home()
            .create_account("private-bob-label")
            .unwrap();
        let alice_cache = app.directory_cache_for_account(&alice).unwrap();
        let bob_cache = app.directory_cache_for_account(&bob).unwrap();
        let peer = "11".repeat(32);
        let shared_peer = "22".repeat(32);
        let search_peer = "33".repeat(32);
        let expired_peer = "44".repeat(32);
        let mut record = app.empty_directory_record(&peer);
        record.profile = Some(UserProfileMetadata {
            name: Some("Needle".into()),
            created_at: 1,
            ..Default::default()
        });
        record.local_account = Some(UserDirectoryLocalAccount {
            label: "private-peer-label".into(),
            local_signing: false,
        });
        alice_cache.put(&record).unwrap();
        record.profile.as_mut().unwrap().created_at = 2;
        record.profile.as_mut().unwrap().display_name = Some("Newer needle".into());
        bob_cache.put(&record).unwrap();
        // Alice's contact list was learned by search only; Bob's was promoted.
        alice_cache
            .remember_search_graph_follows(
                &alice.account_id_hex,
                &crate::ids::npub_for_account_id_lossy(&alice.account_id_hex),
                std::slice::from_ref(&peer),
            )
            .unwrap();
        let mut bob_record = app.empty_directory_record(&bob.account_id_hex);
        bob_record.follows = vec![shared_peer.clone()];
        bob_cache.put(&bob_record).unwrap();
        record.account_id_hex = shared_peer.clone();
        record.npub = crate::ids::npub_for_account_id_lossy(&shared_peer);
        app.shared_storage()
            .unwrap()
            .put_public_directory_user(&public_directory_user_record(&record).unwrap())
            .unwrap();
        let now = crate::unix_now_seconds() as i64;
        for (id, expires) in [(&search_peer, now + 100), (&expired_peer, now)] {
            bob_cache
                .put_search_graph_record(
                    &DirectorySearchGraphRecord {
                        account_id_hex: id.clone(),
                        npub: crate::ids::npub_for_account_id_lossy(id),
                        profile: record.profile.clone(),
                        follows: None,
                        metadata_updated_at: Some(2),
                        metadata_expires_at: Some(expires as u64),
                    },
                    now,
                )
                .unwrap();
        }
        let results = app
            .search_cached_users(&alice.account_id_hex, " needle ", 100)
            .unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].account_id_hex, peer);
        assert!(results[0].is_followed_by_searcher);
        assert_eq!(results[0].profile.as_ref().unwrap().created_at, 2);
        assert!(
            results[1..]
                .iter()
                .all(|r| !r.is_followed_by_searcher && r.radius == OFF_GRAPH_SEARCH_RADIUS)
        );
        let other = app
            .search_cached_users(&bob.account_id_hex, "needle", 100)
            .unwrap();
        assert_eq!(other[0].account_id_hex, shared_peer);
        assert!(other[0].is_followed_by_searcher);
        assert!(
            !other
                .iter()
                .find(|r| r.account_id_hex == peer)
                .unwrap()
                .is_followed_by_searcher
        );
        assert!(
            app.search_cached_users(&alice.account_id_hex, "private-", 100)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            app.search_cached_users(&alice.account_id_hex, "needle", 1)
                .unwrap()
                .len(),
            1
        );
        assert!(
            app.search_cached_users(&alice.account_id_hex, "needle", 0)
                .unwrap()
                .is_empty()
        );
        assert!(
            app.search_cached_users(&alice.account_id_hex, "   ", 100)
                .unwrap()
                .is_empty()
        );
        assert!(
            bob_cache.entry(&search_peer).unwrap().is_none(),
            "cache search must never promote strangers"
        );
        assert!(app.search_cached_users("invalid", "needle", 100).is_err());
    }
}
