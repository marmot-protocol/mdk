//! Whole-roster KeyPackage resolution over a real `MarmotApp` and its relay
//! fixtures. The directory's own resolution tests stay with the directory.

use std::time::{Duration, Instant};

use nostr_directory::MEMBER_PREWARM_CACHE_TTL;
use nostr_directory::MemberResolutionPurpose;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discovery_recovery_refreshes_routes_for_fresh_commit_resolution() {
    let (_directory, app, accounts, fetcher) =
        crate::tests::invite_recovery::discovery_fixture(1).await;
    app.directory()
        .prewarm_group_member_key_packages(&[&accounts[0].account_id_hex])
        .await
        .unwrap();
    fetcher.requests.lock().unwrap().clear();
    let result = app
        .directory()
        .resolve_member_key_packages_for_purpose_for_test(
            vec![accounts[0].account_id_hex.clone()],
            MemberResolutionPurpose::CommitFresh,
            None,
        )
        .await
        .unwrap();
    assert_eq!(result.key_packages.len(), 1);
    assert!(fetcher.requests.lock().unwrap().iter().any(|r| {
        r.queries
            .iter()
            .any(|q| q.kind == transport_nostr_adapter::KIND_NIP65_RELAY_LIST)
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn composition_prewarm_route_reuse_preserves_original_freshness_deadline() {
    let (_directory, app, accounts, _fetcher) =
        crate::tests::member_resolution_fixture(1, false).await;
    let id = &accounts[0].account_id_hex;
    app.directory()
        .prewarm_group_member_key_packages(&[id.as_str()])
        .await
        .unwrap();
    let original = Instant::now() - Duration::from_secs(240);
    app.directory_state
        .member_key_package_prewarm_cache_for_test()
        .lock()
        .unwrap()
        .set_inserted_at(id, original);
    for _ in 0..3 {
        app.directory()
            .prewarm_group_member_key_packages(&[id.as_str()])
            .await
            .unwrap();
        app.directory()
            .resolve_member_key_packages(&[id.as_str()])
            .await
            .unwrap();
    }
    let mut cache = app
        .directory_state
        .member_key_package_prewarm_cache_for_test()
        .lock()
        .unwrap();
    assert_eq!(cache.inserted_at(id), Some(original));
    cache.set_inserted_at(
        id,
        Instant::now() - MEMBER_PREWARM_CACHE_TTL - Duration::from_secs(1),
    );
    assert!(cache.get(id).is_none());
}
