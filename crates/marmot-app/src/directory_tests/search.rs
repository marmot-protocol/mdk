//! Streaming search over a real `MarmotApp`: its caches, relay plane and
//! runtime. The directory's own search tests stay with the directory.

use std::collections::BTreeMap;
use std::time::Duration;

use marmot_account::AccountHome;
use tokio::time::timeout;

use crate::{AccountRelayListStatus, MarmotApp};
use crate::{MatchQuality, MatchedField, UserProfileMetadata};
use crate::{UserDirectoryRecord, UserDirectorySearchResult};
use nostr_directory::error::DirectoryError;
use nostr_directory::npub_for_account_id_lossy;
use nostr_directory::{DirectorySearchGraphRecord, SEARCH_GRAPH_PROFILE_TTL_SECONDS};
use nostr_directory::{
    MAX_SUPPORTED_SEARCH_RADIUS, OFF_GRAPH_SEARCH_RADIUS, SearchUpdateTrigger, UserSearchParams,
    UserSearchSubscription, UserSearchUpdate,
};

/// Wall-clock seconds for fixture timestamps.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

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

async fn wait_for_network_ready(runtime: &crate::MarmotAppRuntime, account_ref: &str) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if runtime.account_setup_readiness(account_ref).unwrap()
                == crate::AccountSetupReadiness::NetworkReady
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("generated identity bootstrap must become network-ready");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_membership_keeps_cached_results_and_completes_graph() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.invalid",
        crate::MarmotAppConfig::white_noise().with_open_ranking_provider(None, Vec::new()),
    );
    let account = app.account_home().create_account("alice").unwrap();
    app.directory_cache_for_account(&account)
        .unwrap()
        .put(&record_named(&account.account_id_hex, "needle"))
        .unwrap();
    let subscription = app
        .directory()
        .search_users_with_seeds(
            params(&account.account_id_hex, "needle", (0, 0)),
            std::future::ready(Err(DirectoryError::RelayDirectory(
                "membership unavailable".into(),
            ))),
        )
        .await
        .unwrap();
    let updates = drain(subscription).await;
    assert_eq!(updates[0].trigger, SearchUpdateTrigger::CachedResultsFound);
    assert_eq!(updates[0].new_results.len(), 1);
    assert!(
        updates
            .iter()
            .any(|u| u.trigger == SearchUpdateTrigger::RadiusCompleted { radius: 0 })
    );
    assert!(updates.iter().all(|u| !matches!(
        u.trigger,
        SearchUpdateTrigger::Error { .. } | SearchUpdateTrigger::RadiusTimeout { .. }
    )));
    assert_eq!(
        updates.last().unwrap().trigger,
        SearchUpdateTrigger::SearchCompleted
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cached_matches_arrive_before_blocked_membership_and_cancel_it() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.invalid",
        crate::MarmotAppConfig::white_noise().with_open_ranking_provider(None, Vec::new()),
    );
    let account = app.account_home().create_account("alice").unwrap();
    let cache = app.directory_cache_for_account(&account).unwrap();
    let peer = "11".repeat(32);
    cache.put(&record_named(&peer, "needle")).unwrap();
    let (seed_started_tx, seed_started_rx) = tokio::sync::oneshot::channel();
    let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for DropSignal {
        fn drop(&mut self) {
            let _ = self.0.take().unwrap().send(());
        }
    }
    let mut subscription = app
        .directory()
        .search_users_with_seeds(
            params(&account.account_id_hex, "needle", (1, 2)),
            async move {
                let _guard = DropSignal(Some(dropped_tx));
                let _ = seed_started_tx.send(());
                std::future::pending::<Result<Vec<String>, DirectoryError>>().await
            },
        )
        .await
        .unwrap();
    let update = timeout(Duration::from_secs(5), subscription.next_update())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(update.trigger, SearchUpdateTrigger::CachedResultsFound);
    assert_eq!(update.new_results[0].account_id_hex, peer);
    assert!(!update.new_results[0].is_followed_by_searcher);
    timeout(Duration::from_secs(5), seed_started_rx)
        .await
        .unwrap()
        .unwrap();
    drop(subscription);
    timeout(Duration::from_secs(5), dropped_rx)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_a_radius_deeper_than_the_producer_answers() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let searcher = format!("{:064x}", 1);

    let error = app
        .directory()
        .search_users(params(
            &searcher,
            "needle",
            (0, MAX_SUPPORTED_SEARCH_RADIUS + 1),
        ))
        .await
        .expect_err("a radius past the supported depth must not be answered shallowly");

    assert!(matches!(error, DirectoryError::InvalidDirectorySearch(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_an_inverted_radius_window() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let searcher = format!("{:064x}", 1);

    let error = app
        .directory()
        .search_users(params(&searcher, "needle", (1, 0)))
        .await
        .expect_err("radius_start past radius_end is not a searchable window");

    assert!(matches!(error, DirectoryError::InvalidDirectorySearch(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        .directory()
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

/// `deployment` is a public field, so a struct literal can skip
/// `with_deployment`. A provider with no profile relay must still be off,
/// whichever constructor stores the config, or every query would reach it.
#[test]
fn open_ranking_without_profile_relays_is_disabled_when_set_through_the_field() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = crate::MarmotAppConfig::white_noise();
    config.deployment.open_ranking = Some(crate::OpenRankingProvider {
        search_endpoint: "https://rank.example".into(),
        profile_relays: vec!["  ".into()],
    });
    let relay_only = MarmotApp::with_relays_and_config(
        dir.path().join("relay-only"),
        vec!["wss://relay.example".into()],
        config.clone(),
    );
    assert_eq!(relay_only.deployment().open_ranking, None);
    let with_home = MarmotApp::with_relays_and_account_home_and_config(
        dir.path().join("with-home"),
        vec!["wss://relay.example".into()],
        AccountHome::open(dir.path().join("with-home")),
        config,
    );
    assert_eq!(with_home.deployment().open_ranking, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streams_a_cached_radius_zero_match_through_the_full_update_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    assert!(
        app.deployment().open_ranking.is_none(),
        "dev/test convenience constructors must never call a live provider"
    );
    let cache = app.directory_cache_for_account(&account).unwrap();
    cache
        .put(&record_named(&account.account_id_hex, "needle"))
        .unwrap();

    // Radius 0..0 resolves the searcher from cache and expands no frontier,
    // so the whole search completes without contacting a relay.
    let subscription = app
        .directory()
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
            SearchUpdateTrigger::CachedResultsFound,
            SearchUpdateTrigger::RadiusStarted { radius: 0 },
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_search_matches_a_stranger_cached_in_the_un_promoted_tier() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let stranger = format!("{:064x}", 77);
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.invalid");
    let cache = app.directory_cache_for_account(&account).unwrap();
    let now = unix_now();

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
        .put_search_graph_record_for_test(
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
        .directory()
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

/// Hostile kind:0 extensions on a relay-resolved stranger must inherit the
/// shared ingest bounds in both the streamed result and the un-promoted
/// search-graph cache. The stranger must not be promoted into directory_users
/// or its per-author subscriptions (mdk#418).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_profile_resolved_from_a_relay_is_cached_without_promoting_the_stranger() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let endpoint = cgka_traits::TransportEndpoint(relay_url.clone());
    let stranger_dir = tempfile::tempdir().unwrap();
    let stranger_app = MarmotApp::with_relay(stranger_dir.path(), relay_url.clone());
    let stranger_runtime = stranger_app.runtime();
    let stranger = stranger_runtime
        .create_identity(crate::AccountSetupRequest {
            default_relays: vec![endpoint.clone()],
            bootstrap_relays: vec![endpoint.clone()],
            publish_missing_relay_lists: true,
            ..crate::AccountSetupRequest::default()
        })
        .await
        .expect("create the stranger's identity")
        .account;
    wait_for_network_ready(&stranger_runtime, &stranger.account_id_hex).await;
    stranger_app
        .publish_user_profile(
            &stranger.account_id_hex,
            UserProfileMetadata {
                name: Some("needle".to_owned()),
                extra: BTreeMap::from([
                    (
                        "website".to_owned(),
                        serde_json::json!("https://example.test"),
                    ),
                    ("bot".to_owned(), serde_json::json!(false)),
                    (
                        "custom_blob".to_owned(),
                        serde_json::json!("x".repeat(8000)),
                    ),
                ]),
                ..UserProfileMetadata::default()
            },
            crate::AccountRelayListBootstrap::new(vec![endpoint.clone()], Vec::new()),
        )
        .await
        .expect("publish the stranger's hostile profile");

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
        .directory()
        .search_users(params(&account.account_id_hex, "needle", (1, 1)))
        .await
        .unwrap();
    let updates = drain(subscription).await;
    let matched = updates
        .iter()
        .flat_map(|update| &update.new_results)
        .find(|result| result.account_id_hex == stranger.account_id_hex)
        .expect("the search must resolve the stranger from the relay");
    let result_profile = matched.profile.as_ref().expect("search result profile");
    assert_eq!(result_profile.name.as_deref(), Some("needle"));
    assert_eq!(
        result_profile.extra.get("website"),
        Some(&serde_json::json!("https://example.test"))
    );
    assert_eq!(
        result_profile.extra.get("bot"),
        Some(&serde_json::json!(false))
    );
    assert!(!result_profile.extra.contains_key("custom_blob"));
    assert_eq!(result_profile.extra.len(), 2);

    let now = unix_now();
    let cached = cache
        .search_record_for_test(&stranger.account_id_hex, now)
        .unwrap()
        .expect("the resolved profile must be cached for the next search");
    let cached_profile = cached.profile.expect("un-promoted cached profile");
    assert_eq!(cached_profile.extra, result_profile.extra);
    assert!(!cached_profile.extra.contains_key("custom_blob"));
    assert!(
        cache.entry(&stranger.account_id_hex).unwrap().is_none(),
        "caching a search result must not promote them into directory_users"
    );
}

/// Radius 2 is follows-of-follows. Both hops here are already on the
/// device, so the whole traversal must complete against an unreachable
/// relay -- that is what "Pass 1 reads cached follows" buys, and it is the
/// only reason a second radius is affordable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn radius_two_expands_through_cached_follow_edges_without_a_relay() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let friend = format!("{:064x}", 61);
    let stranger = format!("{:064x}", 62);
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.invalid");
    let cache = app.directory_cache_for_account(&account).unwrap();
    let now = unix_now();

    // alice -> friend (promoted, her own contact list)
    cache
        .put(&UserDirectoryRecord {
            follows: vec![friend.clone()],
            ..record_named(&account.account_id_hex, "alice")
        })
        .unwrap();
    // friend -> stranger, cached un-promoted by an earlier traversal.
    cache
        .remember_search_graph_follows_for_test(
            &friend,
            &npub_for_account_id_lossy(&friend),
            std::slice::from_ref(&stranger),
        )
        .unwrap();
    cache
        .put_search_graph_record_for_test(
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
        .directory()
        .search_users(params(&account.account_id_hex, "needle", (2, 2)))
        .await
        .unwrap();
    let updates = drain(subscription).await;

    let matched = updates
        .iter()
        .rev()
        .flat_map(|update| update.updated_results.iter().chain(&update.new_results))
        .find(|result| result.account_id_hex == stranger)
        .expect("a follow-of-a-follow must be reachable at radius 2");
    assert_eq!(matched.radius, 2);
}

/// An account whose contact list the relays never returned must stay
/// *unknown*, not be recorded as following nobody. Recording the guess
/// turns a relay hiccup into a permanent dead end, because cached follow
/// edges do not expire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        .directory()
        .search_users(params(&account.account_id_hex, "needle", (2, 2)))
        .await
        .unwrap();
    drain(subscription).await;

    assert_eq!(
        cache.search_graph_follows_for_test(&friend).unwrap(),
        None,
        "an unanswered contact list must stay re-fetchable"
    );
}

/// Someone you share a group with is socially close even if neither of you
/// has followed the other, so a caller can seed them into radius 1. The
/// seeded account here is in no follow list at all -- only the seed puts
/// them within reach.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_seeded_account_is_searchable_at_radius_one_without_being_followed() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let co_member = format!("{:064x}", 81);
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.invalid");
    let cache = app.directory_cache_for_account(&account).unwrap();
    let now = unix_now();

    cache
        .put_search_graph_record_for_test(
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
        .directory()
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        .directory()
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
    let stranger_runtime = stranger_app.runtime();
    let stranger = stranger_runtime
        .create_identity(crate::AccountSetupRequest {
            default_relays: vec![author_endpoint.clone()],
            bootstrap_relays: vec![author_endpoint.clone(), searcher_endpoint.clone()],
            publish_missing_relay_lists: true,
            ..crate::AccountSetupRequest::default()
        })
        .await
        .expect("create the stranger's identity")
        .account;
    wait_for_network_ready(&stranger_runtime, &stranger.account_id_hex).await;
    stranger_app
        .publish_account_relay_lists(
            &stranger.account_id_hex,
            crate::AccountRelayListBootstrap::new(
                vec![author_endpoint.clone()],
                vec![author_endpoint.clone(), searcher_endpoint],
            ),
        )
        .await
        .expect("make the stranger's write relay discoverable");
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
        .directory()
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_graph_falls_back_to_the_configured_seed_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let seed = format!("{:064x}", 91);
    let stranger = format!("{:064x}", 92);
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.invalid",
        crate::MarmotAppConfig::white_noise()
            .with_directory_search_fallback_seeds(vec![seed.clone()])
            .with_open_ranking_provider(None, Vec::new()),
    );
    let cache = app.directory_cache_for_account(&account).unwrap();
    let now = unix_now();

    // Alice follows nobody. The seed follows someone worth finding.
    cache
        .remember_search_graph_follows_for_test(
            &seed,
            &npub_for_account_id_lossy(&seed),
            std::slice::from_ref(&stranger),
        )
        .unwrap();
    cache
        .put_search_graph_record_for_test(
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
        .directory()
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

/// Cached profiles remain searchable, but the fallback graph is traversed
/// only when the searcher's own graph is empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        crate::MarmotAppConfig::white_noise()
            .with_directory_search_fallback_seeds(vec![seed.clone()])
            .with_open_ranking_provider(None, Vec::new()),
    );
    let cache = app.directory_cache_for_account(&account).unwrap();
    let now = unix_now();

    cache
        .put(&UserDirectoryRecord {
            follows: vec![friend.clone()],
            ..record_named(&account.account_id_hex, "alice")
        })
        .unwrap();
    cache
        .remember_search_graph_follows_for_test(
            &seed,
            &npub_for_account_id_lossy(&seed),
            std::slice::from_ref(&seeded_stranger),
        )
        .unwrap();
    cache
        .put_search_graph_record_for_test(
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
        .directory()
        .search_users(params(&account.account_id_hex, "needle", (0, 2)))
        .await
        .unwrap();
    let updates = drain(subscription).await;

    let cached = updates
        .iter()
        .find(|update| update.trigger == SearchUpdateTrigger::CachedResultsFound)
        .unwrap();
    let result = cached
        .new_results
        .iter()
        .find(|result| result.account_id_hex == seeded_stranger)
        .unwrap();
    assert_eq!(
        result.radius, OFF_GRAPH_SEARCH_RADIUS,
        "public cache is searchable without adopting the seed's graph"
    );
    assert!(!result.is_followed_by_searcher);
    assert!(
        updates.iter().all(|update| !matches!(
            update.trigger,
            SearchUpdateTrigger::RadiusStarted {
                radius: OFF_GRAPH_SEARCH_RADIUS
            }
        )),
        "a searcher with follows must not traverse the fallback seed"
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_promoted_row_without_a_profile_does_not_mask_the_cached_one() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let stranger = format!("{:064x}", 101);
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.invalid");
    let cache = app.directory_cache_for_account(&account).unwrap();
    let now = unix_now();

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
        .put_search_graph_record_for_test(
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
        .directory()
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_npub_match_resolved_by_the_outbox_tier_is_reported_once() {
    let relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let author_relay = nostr_relay_builder::MockRelay::run().await.unwrap();
    let author_relay_url = author_relay.url().await.to_string();

    let author_endpoint = cgka_traits::TransportEndpoint(author_relay_url.clone());
    let searcher_endpoint = cgka_traits::TransportEndpoint(relay_url.clone());
    let stranger_dir = tempfile::tempdir().unwrap();
    let stranger_app = MarmotApp::with_relay(stranger_dir.path(), author_relay_url.clone());
    let stranger_runtime = stranger_app.runtime();
    let stranger = stranger_runtime
        .create_identity(crate::AccountSetupRequest {
            default_relays: vec![author_endpoint.clone()],
            bootstrap_relays: vec![author_endpoint.clone(), searcher_endpoint.clone()],
            publish_missing_relay_lists: true,
            ..crate::AccountSetupRequest::default()
        })
        .await
        .expect("create the stranger's identity")
        .account;
    wait_for_network_ready(&stranger_runtime, &stranger.account_id_hex).await;
    stranger_app
        .publish_account_relay_lists(
            &stranger.account_id_hex,
            crate::AccountRelayListBootstrap::new(
                vec![author_endpoint.clone()],
                vec![author_endpoint.clone(), searcher_endpoint],
            ),
        )
        .await
        .expect("make the stranger's write relay discoverable");
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
        .directory()
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_seed_is_rejected_rather_than_failing_the_traversal() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.invalid");

    let error = app
        .directory()
        .search_users(UserSearchParams {
            radius_one_seeds: vec!["not-a-pubkey".to_owned()],
            ..params(&account.account_id_hex, "needle", (0, 1))
        })
        .await
        .expect_err("a malformed seed is a bad request, not a silent skip");

    assert!(
        matches!(error, DirectoryError::InvalidPublicKey),
        "{error:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        .directory()
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
