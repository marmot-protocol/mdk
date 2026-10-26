//! Network-free cached search across a real `MarmotApp`'s accounts and their
//! per-account caches.

use std::collections::BTreeMap;

use crate::OFF_GRAPH_SEARCH_RADIUS;
use crate::{MarmotApp, UserDirectoryLocalAccount, UserProfileMetadata};
use nostr_directory::DirectorySearchGraphRecord;
use nostr_directory::public_directory_user_record;

/// Wall-clock seconds for fixture timestamps.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connected_searcher_ignores_another_accounts_stale_follows() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.invalid",
        crate::MarmotAppConfig::white_noise().with_open_ranking_provider(None, Vec::new()),
    );
    let other = app.account_home().create_account("a-other").unwrap();
    let searcher = app.account_home().create_account("z-searcher").unwrap();
    let own_cache = app.directory_cache_for_account(&searcher).unwrap();
    let other_cache = app.directory_cache_for_account(&other).unwrap();
    let followed = "11".repeat(32);
    let stale = "22".repeat(32);
    for id in [&searcher.account_id_hex, &followed, &stale] {
        let mut record = app.directory().empty_directory_record_for_test(id);
        record.profile = Some(UserProfileMetadata {
            name: Some("needle".into()),
            created_at: 1,
            ..Default::default()
        });
        own_cache.put(&record).unwrap();
    }
    own_cache
        .remember_search_graph_follows_for_test(
            &searcher.account_id_hex,
            &nostr_directory::npub_for_account_id_lossy(&searcher.account_id_hex),
            std::slice::from_ref(&followed),
        )
        .unwrap();
    other_cache
        .remember_search_graph_follows_for_test(
            &searcher.account_id_hex,
            &nostr_directory::npub_for_account_id_lossy(&searcher.account_id_hex),
            std::slice::from_ref(&stale),
        )
        .unwrap();
    let cached = app
        .directory()
        .search_cached_users(&searcher.account_id_hex, "needle", 100)
        .unwrap();
    assert_eq!(
        cached[0].account_id_hex, searcher.account_id_hex,
        "self ranks first"
    );
    assert_eq!(
        cached
            .iter()
            .filter(|r| r.is_followed_by_searcher)
            .map(|r| r.account_id_hex.clone())
            .collect::<Vec<_>>(),
        vec![followed.clone()]
    );
    let offline = app
        .directory()
        .search_user_directory(crate::UserDirectorySearch {
            searcher_account_id_hex: searcher.account_id_hex.clone(),
            query: "needle".into(),
            radius_start: 1,
            radius_end: 1,
            limit: None,
        })
        .unwrap();
    assert_eq!(offline.len(), 1);
    assert_eq!(offline[0].account_id_hex, followed);
    assert!(offline[0].is_followed_by_searcher);
    let mut stream = app
        .directory()
        .search_users(crate::UserSearchParams {
            searcher_account_id_hex: searcher.account_id_hex.clone(),
            query: "needle".into(),
            radius_start: 0,
            radius_end: 1,
            radius_one_seeds: Vec::new(),
        })
        .await
        .unwrap();
    let mut latest = BTreeMap::new();
    while let Some(update) =
        tokio::time::timeout(std::time::Duration::from_secs(5), stream.next_update())
            .await
            .unwrap()
    {
        assert!(!matches!(
            update.trigger,
            crate::SearchUpdateTrigger::Error { .. }
        ));
        for row in update.new_results.into_iter().chain(update.updated_results) {
            latest.insert(row.account_id_hex.clone(), row);
        }
    }
    assert!(latest[&followed].is_followed_by_searcher);
    assert!(!latest[&stale].is_followed_by_searcher);
    assert_eq!(latest[&stale].radius, OFF_GRAPH_SEARCH_RADIUS);

    // The refresh path's explicit empty kind-3 clears stale graph edges too.
    app.directory()
        .remember_directory_follow_list_for_test(
            &searcher.account_id_hex,
            &nostr_directory::FetchedFollowList {
                follows: Vec::new(),
                source_relays: Vec::new(),
            },
        )
        .unwrap();
    assert!(
        app.directory()
            .search_cached_users(&searcher.account_id_hex, "needle", 100)
            .unwrap()
            .iter()
            .all(|row| !row.is_followed_by_searcher)
    );
}

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
    let mut record = app.directory().empty_directory_record_for_test(&peer);
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
        .remember_search_graph_follows_for_test(
            &alice.account_id_hex,
            &nostr_directory::npub_for_account_id_lossy(&alice.account_id_hex),
            std::slice::from_ref(&peer),
        )
        .unwrap();
    let mut bob_record = app
        .directory()
        .empty_directory_record_for_test(&bob.account_id_hex);
    bob_record.follows = vec![shared_peer.clone()];
    bob_cache.put(&bob_record).unwrap();
    record.account_id_hex = shared_peer.clone();
    record.npub = nostr_directory::npub_for_account_id_lossy(&shared_peer);
    app.shared_storage()
        .unwrap()
        .put_public_directory_user(&public_directory_user_record(&record).unwrap())
        .unwrap();
    let now = unix_now();
    for (id, expires) in [(&search_peer, now + 100), (&expired_peer, now)] {
        bob_cache
            .put_search_graph_record_for_test(
                &DirectorySearchGraphRecord {
                    account_id_hex: id.clone(),
                    npub: nostr_directory::npub_for_account_id_lossy(id),
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
        .directory()
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
        .directory()
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
        app.directory()
            .search_cached_users(&alice.account_id_hex, "private-", 100)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        app.directory()
            .search_cached_users(&alice.account_id_hex, "needle", 1)
            .unwrap()
            .len(),
        1
    );
    assert!(
        app.directory()
            .search_cached_users(&alice.account_id_hex, "needle", 0)
            .unwrap()
            .is_empty()
    );
    assert!(
        app.directory()
            .search_cached_users(&alice.account_id_hex, "   ", 100)
            .unwrap()
            .is_empty()
    );
    assert!(
        bob_cache.entry(&search_peer).unwrap().is_none(),
        "cache search must never promote strangers"
    );
    assert!(
        app.directory()
            .search_cached_users("invalid", "needle", 100)
            .is_err()
    );
}
