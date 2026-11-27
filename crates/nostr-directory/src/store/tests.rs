use super::*;
use crate::{DirectoryAccount, DirectoryConfig, DirectoryState};
use std::sync::{Arc, Barrier, Mutex, mpsc};
use std::time::Duration;
use transport_nostr::MarmotRelayPlane;

type ChangeCallback = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

#[derive(Clone)]
struct Resources {
    account: DirectoryAccount,
    cache: DirectoryCache,
    shared: SqliteSharedStorage,
    changed: Option<ChangeCallback>,
}

impl DirectoryResources for Resources {
    fn local_accounts(&self) -> Result<Vec<DirectoryAccount>, DirectoryError> {
        std::thread::yield_now();
        Ok(vec![self.account.clone()])
    }

    fn account_id_for_label(&self, _: &str) -> Result<String, DirectoryError> {
        Ok(self.account.account_id_hex.clone())
    }

    fn current_caches(&self) -> Result<Vec<DirectoryCache>, DirectoryError> {
        // Perturb scheduling at a real host boundary, without supplying a
        // snapshot, a result, or an ordering between the two writers.
        std::thread::yield_now();
        Ok(vec![self.cache.clone()])
    }

    fn cache_for_account(&self, _: &DirectoryAccount) -> Result<DirectoryCache, DirectoryError> {
        Ok(self.cache.clone())
    }

    fn shared_storage(&self) -> Result<SqliteSharedStorage, DirectoryError> {
        std::thread::yield_now();
        Ok(self.shared.clone())
    }

    fn directory_entry_changed(&self, _: &str) {
        let callback = self
            .changed
            .as_ref()
            .and_then(|changed| changed.lock().unwrap().take());
        // The one-shot slot is unlocked before host code reenters Directory.
        if let Some(callback) = callback {
            callback();
        }
    }

    fn account_key_package_published(&self, _: &str) {}
}

fn relay_lists(created_at: u64) -> AccountRelayListStatus {
    let mut status = AccountRelayListStatus::empty();
    status.nip65.created_at = created_at;
    status.nip65.relays = vec!["wss://relay.example".into()];
    status.nip65.read_relays = status.nip65.relays.clone();
    status.nip65.write_relays = status.nip65.relays.clone();
    status.inbox.created_at = created_at;
    status.inbox.relays = status.nip65.relays.clone();
    status.refresh();
    status
}

fn check_snapshot(
    failures: &mut Vec<String>,
    tier: &str,
    round: u64,
    entry: Option<UserDirectoryRecord>,
    profile: &UserProfileMetadata,
    lists: &AccountRelayListStatus,
) {
    let Some(entry) = entry else {
        failures.push(format!("round {round}: {tier} has no directory entry"));
        return;
    };
    if entry.profile.as_ref() != Some(profile) || &entry.relay_lists != lists {
        failures.push(format!(
            "round {round}: {tier} lost an independently committed component \
             (profile stamp {:?}, NIP-65 stamp {}, inbox stamp {}, complete {})",
            entry.profile.as_ref().map(|value| value.created_at),
            entry.relay_lists.nip65.created_at,
            entry.relay_lists.inbox.created_at,
            entry.relay_lists.complete,
        ));
    }
}

/// Independent kind-0 and relay-list writes must survive in both stored
/// tiers. A whole-row read/modify/write without a shared mutation owner loses
/// one component when writers from separate Directory values overlap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_profile_and_relay_writes_preserve_both_components() {
    const ROUNDS: u64 = 64;
    let temp = tempfile::tempdir().unwrap();
    let cache_path = temp.path().join("directory.sqlite3");
    let key = storage_sqlite::SqlCipherKey::raw([0x31; 32]);
    let cache = DirectoryCache::open(cache_path.clone(), &key).unwrap();
    let shared = SqliteSharedStorage::in_memory().unwrap();
    let account_id = nostr::prelude::Keys::generate().public_key().to_hex();
    let resources = Resources {
        account: DirectoryAccount {
            account_id_hex: account_id.clone(),
            label: "fixture".into(),
            local_signing: true,
            active_signing: true,
        },
        cache: cache.clone(),
        shared: shared.clone(),
        changed: None,
    };
    let config = DirectoryConfig {
        directory_relays: vec![],
        default_relays: vec![],
        max_future_skew: Duration::from_secs(60),
        open_ranking: None,
        fallback_seeds: vec![],
        http_builder: Ok,
        test_clock: None,
    };
    let plane = MarmotRelayPlane::full_history();
    let state = DirectoryState::default();
    let mut failures = Vec::new();

    for round in 1..=ROUNDS {
        let profile = UserProfileMetadata {
            name: Some(format!("profile-{round}")),
            created_at: 1_000 + round,
            ..Default::default()
        };
        let lists = relay_lists(2_000 + round);
        let start = Arc::new(Barrier::new(2));

        // The host builds a fresh service value for each call while sharing
        // its DirectoryState and real storage handles, as MarmotApp does.
        let profile_directory = Directory::new(
            resources.clone(),
            config.clone(),
            plane.clone(),
            state.clone(),
        );
        let profile_account = account_id.clone();
        let profile_value = profile.clone();
        let profile_start = start.clone();
        let profile_writer = std::thread::spawn(move || {
            profile_start.wait();
            profile_directory.remember_directory_profile(&profile_account, &profile_value)
        });
        let relay_directory = Directory::new(
            resources.clone(),
            config.clone(),
            plane.clone(),
            state.clone(),
        );
        let relay_account = account_id.clone();
        let relay_value = lists.clone();
        let relay_writer = std::thread::spawn(move || {
            start.wait();
            relay_directory.remember_directory_relay_lists(&relay_account, &relay_value)
        });

        // Join both before checking anything, including a writer's error, so
        // an assertion cannot leave its peer blocked at the start barrier.
        let profile_result = profile_writer.join();
        let relay_result = relay_writer.join();
        profile_result.unwrap().unwrap();
        relay_result.unwrap().unwrap();
        check_snapshot(
            &mut failures,
            "encrypted cache",
            round,
            cache.entry(&account_id).unwrap(),
            &profile,
            &lists,
        );
        check_snapshot(
            &mut failures,
            "shared store",
            round,
            shared
                .public_directory_user(&account_id)
                .unwrap()
                .map(user_directory_record_from_public)
                .transpose()
                .unwrap(),
            &profile,
            &lists,
        );
    }

    cache.close().unwrap();
    let reopened = DirectoryCache::open(cache_path, &key).unwrap();
    check_snapshot(
        &mut failures,
        "reopened encrypted cache",
        ROUNDS,
        reopened.entry(&account_id).unwrap(),
        &UserProfileMetadata {
            name: Some(format!("profile-{ROUNDS}")),
            created_at: 1_000 + ROUNDS,
            ..Default::default()
        },
        &relay_lists(2_000 + ROUNDS),
    );
    reopened.close().unwrap();
    shared.close().unwrap();
    plane.shutdown().await;

    assert!(
        failures.is_empty(),
        "{} stored snapshots lost committed components; first failures:\n{}",
        failures.len(),
        failures.into_iter().take(8).collect::<Vec<_>>().join("\n"),
    );
}

/// Host notification must observe both tiers committed and may synchronously
/// call Directory again. Notifying before cache writes loses the nested
/// component; notifying while the mutation lane is held deadlocks that call.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_callback_observes_full_write_and_preserves_a_reentrant_update() {
    let temp = tempfile::tempdir().unwrap();
    let key = storage_sqlite::SqlCipherKey::raw([0x32; 32]);
    let cache = DirectoryCache::open(temp.path().join("directory.sqlite3"), &key).unwrap();
    let shared = SqliteSharedStorage::in_memory().unwrap();
    let account_id = nostr::prelude::Keys::generate().public_key().to_hex();
    let changed = Arc::new(Mutex::new(None));
    let resources = Resources {
        account: DirectoryAccount {
            account_id_hex: account_id.clone(),
            label: "fixture".into(),
            local_signing: true,
            active_signing: true,
        },
        cache: cache.clone(),
        shared: shared.clone(),
        changed: Some(changed.clone()),
    };
    let config = DirectoryConfig {
        directory_relays: vec![],
        default_relays: vec![],
        max_future_skew: Duration::from_secs(60),
        open_ranking: None,
        fallback_seeds: vec![],
        http_builder: Ok,
        test_clock: None,
    };
    let plane = MarmotRelayPlane::full_history();
    let state = DirectoryState::default();
    let directory = Directory::new(
        resources.clone(),
        config.clone(),
        plane.clone(),
        state.clone(),
    );
    directory
        .remember_directory_profile(
            &account_id,
            &UserProfileMetadata {
                name: Some("before notification".into()),
                created_at: 90,
                ..Default::default()
            },
        )
        .unwrap();

    let profile = UserProfileMetadata {
        name: Some("notified profile".into()),
        created_at: 100,
        ..Default::default()
    };
    let observed_committed_profile = Arc::new(Mutex::new(None));
    let observation = observed_committed_profile.clone();
    let callback_cache = cache.clone();
    let callback_shared = shared.clone();
    let callback_account = account_id.clone();
    let callback_directory = Directory::new(resources, config, plane.clone(), state);
    let lists = relay_lists(200);
    let callback_lists = lists.clone();
    let callback_profile = profile.clone();
    *changed.lock().unwrap() = Some(Box::new(move || {
        let cached = callback_cache
            .entry(&callback_account)
            .unwrap()
            .map(|entry| public_directory_user_record(&entry))
            .transpose()
            .unwrap();
        let published = callback_shared
            .public_directory_user(&callback_account)
            .unwrap();
        let published_profile = published
            .as_ref()
            .and_then(|record| record.profile_json.as_ref())
            .map(|json| serde_json::from_str::<UserProfileMetadata>(json))
            .transpose()
            .unwrap();
        *observation.lock().unwrap() =
            Some(published_profile.as_ref() == Some(&callback_profile) && cached == published);
        callback_directory
            .remember_directory_relay_lists(&callback_account, &callback_lists)
            .unwrap();
    }));

    let profile_value = profile.clone();
    let profile_account = account_id.clone();
    let (done, completion) = mpsc::channel();
    let writer = std::thread::spawn(move || {
        let result = directory.remember_directory_profile(&profile_account, &profile_value);
        let _ = done.send(result);
    });
    // A positive completion guard reports a notification-under-lock deadlock
    // without joining a writer which can never finish.
    let result = completion
        .recv_timeout(Duration::from_secs(5))
        .expect("a host callback must complete its reentrant directory write");
    writer.join().unwrap();
    result.unwrap();

    let mut failures = Vec::new();
    if *observed_committed_profile.lock().unwrap() != Some(true) {
        failures
            .push("the host callback ran before both tiers contained the notified profile".into());
    }
    check_snapshot(
        &mut failures,
        "encrypted cache after reentrant update",
        1,
        cache.entry(&account_id).unwrap(),
        &profile,
        &lists,
    );
    check_snapshot(
        &mut failures,
        "shared store after reentrant update",
        1,
        shared
            .public_directory_user(&account_id)
            .unwrap()
            .map(user_directory_record_from_public)
            .transpose()
            .unwrap(),
        &profile,
        &lists,
    );
    cache.close().unwrap();
    shared.close().unwrap();
    plane.shutdown().await;
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_ingress_authenticates_before_writing_either_store() {
    use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};
    use transport_nostr_peeler::NostrTransportEvent;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory.sqlite3");
    let key = storage_sqlite::SqlCipherKey::raw([0x25; 32]);
    let cache = DirectoryCache::open(path.clone(), &key).unwrap();
    let shared = SqliteSharedStorage::in_memory().unwrap();
    let keys = Keys::generate();
    let author = keys.public_key().to_hex();
    let resources = Resources {
        account: DirectoryAccount {
            account_id_hex: author.clone(),
            label: "fixture".into(),
            local_signing: true,
            active_signing: true,
        },
        cache: cache.clone(),
        shared: shared.clone(),
        changed: None,
    };
    let plane = MarmotRelayPlane::full_history();
    let directory = Directory::new(
        resources,
        DirectoryConfig {
            directory_relays: vec![],
            default_relays: vec![],
            max_future_skew: Duration::from_secs(60),
            open_ranking: None,
            fallback_seeds: vec![],
            http_builder: Ok,
            test_clock: None,
        },
        plane.clone(),
        DirectoryState::default(),
    );
    let record = |event| RelayEventRecord {
        endpoints: vec![cgka_traits::TransportEndpoint(
            "wss://source.example".into(),
        )],
        event,
    };
    for (kind, tag_name) in [(0, "p"), (3, "p"), (10002, "r"), (10050, "relay")] {
        let signed = |created_at, value: &str| {
            let event = EventBuilder::new(Kind::from(kind), format!(r#"{{"name":"{value}"}}"#))
                .tags([Tag::parse([tag_name, value]).unwrap()])
                .custom_created_at(Timestamp::from_secs(created_at))
                .finalize(&keys)
                .unwrap();
            NostrTransportEvent::from_nostr_event(&event).unwrap()
        };
        let first_follow = Keys::generate().public_key().to_hex();
        let second_follow = Keys::generate().public_key().to_hex();
        let initial = signed(
            100,
            if kind == 3 {
                &first_follow
            } else {
                "wss://initial.example"
            },
        );
        let newer = signed(
            200,
            if kind == 3 {
                &second_follow
            } else {
                "wss://newer.example"
            },
        );
        let before = shared.public_directory_user(&author).unwrap();
        let mut unsigned = newer.clone();
        unsigned.sig = None;
        directory
            .ingest_directory_relay_event(record(unsigned))
            .unwrap();
        assert_eq!(
            shared.public_directory_user(&author).unwrap(),
            before,
            "an unsigned event must not create or change a directory row"
        );
        directory
            .ingest_directory_relay_event(record(initial.clone()))
            .unwrap();
        let stored = cache.entry(&author).unwrap();
        let published = shared.public_directory_user(&author).unwrap();
        assert!(
            stored.is_some(),
            "the signed control must actually be stored"
        );
        let mut tampered = newer.clone();
        tampered.id = initial.id.clone();
        tampered.sig = initial.sig.clone();
        let parsed =
            nostr::event::Event::from_json(serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(!parsed.verify_id());
        assert!(parsed.verify_signature());
        let mut invalid_signature = newer.clone();
        invalid_signature.sig = Some("00".repeat(64));
        for invalid in [tampered, invalid_signature] {
            directory
                .ingest_directory_relay_event(record(invalid))
                .unwrap();
            assert_eq!(
                cache.entry(&author).unwrap(),
                stored,
                "kind {kind}: cache changed"
            );
            assert_eq!(
                shared.public_directory_user(&author).unwrap(),
                published,
                "kind {kind}: shared row changed"
            );
        }
        directory
            .ingest_directory_relay_event(record(newer.clone()))
            .unwrap();
        assert_ne!(
            cache.entry(&author).unwrap(),
            stored,
            "a valid newer event must win"
        );
        let latest = cache.entry(&author).unwrap();
        for duplicate_or_stale in [newer, initial] {
            directory
                .ingest_directory_relay_event(record(duplicate_or_stale))
                .unwrap();
            assert_eq!(
                cache.entry(&author).unwrap(),
                latest,
                "kind {kind}: duplicate and stale authenticated events preserve freshness"
            );
        }
    }
    let expected = cache.entry(&author).unwrap();
    cache.close().unwrap();
    let reopened = DirectoryCache::open(path, &key).unwrap();
    assert_eq!(reopened.entry(&author).unwrap(), expected);
    reopened.close().unwrap();
    shared.close().unwrap();
    plane.shutdown().await;
}

/// Live kind-3 contact-list replays must not overwrite newer follow edges in
/// either the promoted directory row or the un-promoted search graph, even
/// across cache reopen, while an explicit same-second publish still wins over
/// a stale same-second relay echo.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_kind_3_recency_guards_search_graph_and_survives_reopen() {
    use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};
    use transport_nostr_peeler::NostrTransportEvent;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory.sqlite3");
    let key = storage_sqlite::SqlCipherKey::raw([0x35; 32]);
    let cache = DirectoryCache::open(path.clone(), &key).unwrap();
    let shared = SqliteSharedStorage::in_memory().unwrap();
    let local_keys = Keys::generate();
    let local_author = local_keys.public_key().to_hex();
    let unknown_keys = Keys::generate();
    let unknown_author = unknown_keys.public_key().to_hex();
    let bob = Keys::generate().public_key().to_hex();
    let carol = Keys::generate().public_key().to_hex();
    let dave = Keys::generate().public_key().to_hex();

    let resources = Resources {
        account: DirectoryAccount {
            account_id_hex: local_author.clone(),
            label: "fixture".into(),
            local_signing: true,
            active_signing: true,
        },
        cache: cache.clone(),
        shared: shared.clone(),
        changed: None,
    };
    let plane = MarmotRelayPlane::full_history();
    let directory = Directory::new(
        resources.clone(),
        DirectoryConfig {
            directory_relays: vec![],
            default_relays: vec![],
            max_future_skew: Duration::from_secs(60),
            open_ranking: None,
            fallback_seeds: vec![],
            http_builder: Ok,
            test_clock: None,
        },
        plane.clone(),
        DirectoryState::default(),
    );
    let kind3 = |keys: &Keys, created_at: u64, follow: &str| {
        let event = EventBuilder::new(Kind::ContactList, "")
            .tags([Tag::parse(["p", follow]).unwrap()])
            .custom_created_at(Timestamp::from_secs(created_at))
            .finalize(keys)
            .unwrap();
        RelayEventRecord {
            endpoints: vec![cgka_traits::TransportEndpoint("wss://relay.example".into())],
            event: NostrTransportEvent::from_nostr_event(&event).unwrap(),
        }
    };

    // Un-promoted author: newer kind-3 populates search graph without promoting,
    // and an older kind-3 replay cannot overwrite it.
    directory
        .ingest_directory_relay_event(kind3(&unknown_keys, 200, &bob))
        .unwrap();
    assert!(cache.entry(&unknown_author).unwrap().is_none());
    assert_eq!(
        cache.search_graph_follows(&unknown_author).unwrap(),
        Some(vec![bob.clone()])
    );
    directory
        .ingest_directory_relay_event(kind3(&unknown_keys, 100, &carol))
        .unwrap();
    assert_eq!(
        cache.search_graph_follows(&unknown_author).unwrap(),
        Some(vec![bob.clone()])
    );

    // Promoted local account: explicit same-second publish wins, while an
    // equal-second or older live relay echo cannot overwrite it.
    directory.remember_directory_user(&local_author).unwrap();
    directory
        .ingest_directory_relay_event(kind3(&local_keys, 200, &bob))
        .unwrap();
    assert_eq!(
        cache.entry(&local_author).unwrap().unwrap().follows,
        vec![bob.clone()]
    );
    directory
        .remember_directory_follow_edges_for_search(
            &local_author,
            &FetchedFollowList {
                follows: vec![dave.clone()],
                source_relays: vec!["wss://relay.example".into()],
                created_at: 200,
            },
        )
        .unwrap();
    assert_eq!(
        cache.entry(&local_author).unwrap().unwrap().follows,
        vec![dave.clone()]
    );
    directory
        .ingest_directory_relay_event(kind3(&local_keys, 200, &bob))
        .unwrap();
    directory
        .ingest_directory_relay_event(kind3(&local_keys, 150, &carol))
        .unwrap();
    assert_eq!(
        cache.entry(&local_author).unwrap().unwrap().follows,
        vec![dave.clone()]
    );
    assert_eq!(
        cache.search_graph_follows(&local_author).unwrap(),
        Some(vec![dave.clone()])
    );

    // Promote the graph-only author: promotion seeds both `directory_users` and
    // `shared_storage` from the already-accepted search-graph contact list (200),
    // so neither stale replays (100) nor a conflicting first equal-timestamp live
    // event (200, carol) can overwrite the accepted follows ([bob]).
    directory
        .remember_directory_message_sender(&unknown_author)
        .unwrap();
    assert_eq!(
        cache.entry(&unknown_author).unwrap().unwrap().follows,
        vec![bob.clone()]
    );
    assert_eq!(
        cache
            .entry(&unknown_author)
            .unwrap()
            .unwrap()
            .follows_created_at,
        200
    );
    assert_eq!(
        shared
            .public_directory_user(&unknown_author)
            .unwrap()
            .unwrap()
            .follows,
        vec![bob.clone()]
    );
    // First equal-timestamp live event after promotion carries conflicting follows
    // ([carol] at 200) and must be rejected without touching either tier.
    directory
        .ingest_directory_relay_event(kind3(&unknown_keys, 200, &carol))
        .unwrap();
    directory
        .ingest_directory_relay_event(kind3(&unknown_keys, 100, &carol))
        .unwrap();
    directory
        .remember_directory_follow_list(
            &unknown_author,
            &FetchedFollowList {
                follows: vec![carol.clone()],
                source_relays: vec!["wss://relay.example".into()],
                created_at: 100,
            },
        )
        .unwrap();
    assert_eq!(
        cache.entry(&unknown_author).unwrap().unwrap().follows,
        vec![bob.clone()]
    );
    assert_eq!(
        shared
            .public_directory_user(&unknown_author)
            .unwrap()
            .unwrap()
            .follows,
        vec![bob.clone()]
    );
    assert_eq!(
        cache.search_graph_follows(&unknown_author).unwrap(),
        Some(vec![bob.clone()])
    );

    // Pre-existing lagging promoted row (e.g. upgraded DB where `directory_users`
    // has follows_created_at = 0 while search graph already holds [bob] at 200):
    // a conflicting equal-timestamp live event ([carol] at 200) must repair the
    // promoted row from the graph's stored [bob], never from [carol].
    let legacy_keys = Keys::generate();
    let legacy_author = legacy_keys.public_key().to_hex();
    directory.remember_directory_user(&legacy_author).unwrap();
    cache
        .remember_search_graph_follows(
            &legacy_author,
            &crate::ids::npub_for_account_id(&legacy_author).unwrap(),
            std::slice::from_ref(&bob),
            200,
            false,
        )
        .unwrap();
    directory
        .ingest_directory_relay_event(kind3(&legacy_keys, 200, &carol))
        .unwrap();
    assert_eq!(
        cache.entry(&legacy_author).unwrap().unwrap().follows,
        vec![bob.clone()]
    );
    assert_eq!(
        cache
            .entry(&legacy_author)
            .unwrap()
            .unwrap()
            .follows_created_at,
        200
    );
    assert_eq!(
        shared
            .public_directory_user(&legacy_author)
            .unwrap()
            .unwrap()
            .follows,
        vec![bob.clone()]
    );
    assert_eq!(
        cache.search_graph_follows(&legacy_author).unwrap(),
        Some(vec![bob.clone()])
    );

    // Partial write failure after `shared_storage` commits (cache write fails):
    // `shared_storage` advances to [dave] at 300 while the account cache still holds
    // [bob] at 200. Retrying the live event at 300 (even with conflicting payload
    // [carol]) must reconcile the lagging cache from `shared_storage`'s accepted [dave].
    let failing_cache = DirectoryCache::open(
        temp.path().join("failing-cache.sqlite3"),
        &storage_sqlite::SqlCipherKey::raw([0x39; 32]),
    )
    .unwrap();
    failing_cache
        .put(&cache.entry(&unknown_author).unwrap().unwrap())
        .unwrap();
    {
        let conn = failing_cache.lock().unwrap();
        conn.execute_batch(
            "CREATE TRIGGER fail_cache_write BEFORE UPDATE ON directory_users
             BEGIN SELECT RAISE(ABORT, 'simulated cache write failure'); END;",
        )
        .unwrap();
    }
    let partial_failure_directory = Directory::new(
        Resources {
            cache: failing_cache.clone(),
            ..resources.clone()
        },
        DirectoryConfig {
            directory_relays: vec![],
            default_relays: vec![],
            max_future_skew: Duration::from_secs(60),
            open_ranking: None,
            fallback_seeds: vec![],
            http_builder: Ok,
            test_clock: None,
        },
        plane.clone(),
        DirectoryState::default(),
    );
    assert!(
        partial_failure_directory
            .ingest_directory_relay_event(kind3(&unknown_keys, 300, &dave))
            .is_err()
    );
    assert_eq!(
        shared
            .public_directory_user(&unknown_author)
            .unwrap()
            .unwrap()
            .follows,
        vec![dave.clone()]
    );
    assert_eq!(
        cache.search_graph_follows(&unknown_author).unwrap(),
        Some(vec![bob.clone()])
    );
    failing_cache.close().unwrap();
    directory
        .ingest_directory_relay_event(kind3(&unknown_keys, 300, &carol))
        .unwrap();
    assert_eq!(
        cache.entry(&unknown_author).unwrap().unwrap().follows,
        vec![dave.clone()]
    );
    assert_eq!(
        cache
            .entry(&unknown_author)
            .unwrap()
            .unwrap()
            .follows_created_at,
        300
    );
    assert_eq!(
        cache.search_graph_follows(&unknown_author).unwrap(),
        Some(vec![dave.clone()])
    );

    // Reopen cache: durable follows_created_at still blocks older replays for both
    // known and promoted graph-only authors.
    cache.close().unwrap();
    let reopened = DirectoryCache::open(path, &key).unwrap();
    let reopened_directory = Directory::new(
        Resources {
            cache: reopened.clone(),
            ..resources
        },
        DirectoryConfig {
            directory_relays: vec![],
            default_relays: vec![],
            max_future_skew: Duration::from_secs(60),
            open_ranking: None,
            fallback_seeds: vec![],
            http_builder: Ok,
            test_clock: None,
        },
        plane.clone(),
        DirectoryState::default(),
    );
    reopened_directory
        .ingest_directory_relay_event(kind3(&local_keys, 180, &carol))
        .unwrap();
    reopened_directory
        .ingest_directory_relay_event(kind3(&unknown_keys, 250, &carol))
        .unwrap();
    reopened_directory
        .remember_directory_follow_list(
            &unknown_author,
            &FetchedFollowList {
                follows: vec![carol.clone()],
                source_relays: vec!["wss://relay.example".into()],
                created_at: 250,
            },
        )
        .unwrap();
    assert_eq!(
        reopened.entry(&local_author).unwrap().unwrap().follows,
        vec![dave.clone()]
    );
    assert_eq!(
        reopened
            .entry(&local_author)
            .unwrap()
            .unwrap()
            .follows_created_at,
        200
    );
    assert_eq!(
        reopened.entry(&unknown_author).unwrap().unwrap().follows,
        vec![dave.clone()]
    );
    assert_eq!(
        reopened.search_graph_follows(&unknown_author).unwrap(),
        Some(vec![dave])
    );

    reopened.close().unwrap();
    shared.close().unwrap();
    plane.shutdown().await;
}

/// Cached KeyPackages must respect recency and shared replacement/deletion
/// barriers: older KeyPackages cannot overwrite newer ones, live kind-5
/// deletions and newer malformed replacements clear cached `entry.key_package`
/// across both tiers, and replayed deleted KeyPackages stay rejected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_package_recency_barriers_and_live_kind_5_deletion_invalidation() {
    use cgka_traits::engine::KeyPackage;
    use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};
    use transport_nostr_peeler::NostrTransportEvent;

    let temp = tempfile::tempdir().unwrap();
    let cache_a = DirectoryCache::open(
        temp.path().join("cache-a.sqlite3"),
        &storage_sqlite::SqlCipherKey::raw([0x36; 32]),
    )
    .unwrap();
    let cache_b_path = temp.path().join("cache-b.sqlite3");
    let cache_b_key = storage_sqlite::SqlCipherKey::raw([0x37; 32]);
    let cache_b = DirectoryCache::open(cache_b_path.clone(), &cache_b_key).unwrap();
    let shared = SqliteSharedStorage::in_memory().unwrap();
    let keys = Keys::generate();
    let author = keys.public_key().to_hex();
    let unknown_keys = Keys::generate();
    let unknown_author = unknown_keys.public_key().to_hex();

    let resources = Resources {
        account: DirectoryAccount {
            account_id_hex: author.clone(),
            label: "fixture".into(),
            local_signing: true,
            active_signing: true,
        },
        cache: cache_a.clone(),
        shared: shared.clone(),
        changed: None,
    };
    let plane = MarmotRelayPlane::full_history();
    let config = DirectoryConfig {
        directory_relays: vec![],
        default_relays: vec![],
        max_future_skew: Duration::from_secs(60),
        open_ranking: None,
        fallback_seeds: vec![],
        http_builder: Ok,
        test_clock: None,
    };
    let directory = Directory::new(
        resources.clone(),
        config.clone(),
        plane.clone(),
        DirectoryState::default(),
    );

    let make_fetched = |slot: &str, event_id: &str, created_at: u64, byte: u8| FetchedKeyPackage {
        account_id_hex: author.clone(),
        key_package: KeyPackage::new(vec![byte; 32]),
        key_package_id: slot.to_owned(),
        key_package_ref_hex: format!("{byte:02x}").repeat(32),
        key_package_event_id: event_id.to_owned(),
        created_at,
        source_relays: vec!["wss://relay.example".into()],
        relay_lists: AccountRelayListStatus::empty(),
    };

    let now = crate::unix_now_seconds();
    let kp_newer = make_fetched("slot-1", &"bb".repeat(32), now - 300, 0x22);
    let kp_older_same_slot = make_fetched("slot-1", &"aa".repeat(32), now - 400, 0x11);
    let kp_tie_higher_id = make_fetched("slot-1", &"cc".repeat(32), now - 300, 0x12);
    let kp_other_slot = make_fetched("slot-2", &"dd".repeat(32), now - 400, 0x13);
    directory.remember_directory_key_package(&kp_newer).unwrap();
    // Seed a stale second cache before the deletion arrives.
    cache_b
        .put(&cache_a.entry(&author).unwrap().unwrap())
        .unwrap();
    cache_b.close().unwrap();

    // Older same-slot replay and same-second higher-id tie must not overwrite the cached slot.
    directory
        .remember_directory_key_package(&kp_older_same_slot)
        .unwrap();
    directory
        .remember_directory_key_package(&kp_tie_higher_id)
        .unwrap();
    assert_eq!(
        cache_a
            .entry(&author)
            .unwrap()
            .unwrap()
            .key_package
            .as_ref()
            .unwrap()
            .key_package_event_id,
        kp_newer.key_package_event_id
    );

    // Live relay ingest of a real signed older-slot kind-30443 event through
    // `ingest_directory_relay_event` must NOT regress a newer cached slot.
    {
        use cgka_engine::account_identity_proof::{
            AccountIdentityProofRequest, AccountIdentityProofSigner,
        };
        use cgka_traits::engine::CgkaEngine as _;

        struct TestProofSigner(Keys);
        impl AccountIdentityProofSigner for TestProofSigner {
            fn sign_account_identity_proof(
                &self,
                request: &AccountIdentityProofRequest,
            ) -> Result<[u8; 64], String> {
                let event = request
                    .proof_event()
                    .and_then(|event| event.finalize(&self.0).map_err(|err| err.to_string()))?;
                request.signature_from_signed_event(event)
            }
        }

        let live_keys = Keys::generate();
        let live_author = live_keys.public_key().to_hex();
        let mut engine = cgka_engine::EngineBuilder::new(
            storage_sqlite::SqliteAccountStorage::in_memory().unwrap(),
        )
        .identity(hex::decode(&live_author).unwrap())
        .account_identity_proof_signer(Arc::new(TestProofSigner(live_keys.clone())))
        .peeler(Box::new(transport_nostr_peeler::NostrMlsPeeler::default()))
        .build()
        .unwrap();
        let newer_kp = engine.fresh_key_package().await.unwrap();
        let older_kp = engine.fresh_key_package().await.unwrap();
        let make_signed_kp = |key_package: KeyPackage, slot: &str, created_at: u64| {
            let metadata = cgka_engine::key_package_metadata(&key_package).unwrap();
            let unsigned = transport_nostr_adapter::NostrKeyPackagePublication {
                client_name: None,
                account_id: cgka_traits::MemberId::new(hex::decode(&live_author).unwrap()),
                key_package,
                key_package_slot_id: slot.to_owned(),
                key_package_ref: metadata.key_package_ref_hex,
                mls_ciphersuite: format!("0x{:04x}", metadata.ciphersuite),
                mls_extensions: metadata
                    .mls_extensions
                    .iter()
                    .map(|id| format!("0x{id:04x}"))
                    .collect(),
                mls_proposals: metadata
                    .mls_proposals
                    .iter()
                    .map(|id| format!("0x{id:04x}"))
                    .collect(),
                app_components: metadata
                    .app_components
                    .iter()
                    .filter(|id| {
                        **id >= cgka_traits::app_components::PRIVATE_USE_APP_COMPONENT_ID_START
                    })
                    .map(|id| format!("0x{id:04x}"))
                    .collect(),
                publish_endpoints: vec![cgka_traits::TransportEndpoint(
                    "wss://relay.example".into(),
                )],
            }
            .to_event_at(created_at)
            .unwrap();
            let tags = unsigned
                .tags
                .iter()
                .map(|tag| Tag::parse(tag.iter().map(String::as_str)).unwrap())
                .collect::<Vec<_>>();
            let signed =
                EventBuilder::new(Kind::from(KIND_MARMOT_KEY_PACKAGE as u16), unsigned.content)
                    .tags(tags)
                    .custom_created_at(Timestamp::from_secs(created_at))
                    .finalize(&live_keys)
                    .unwrap();
            let event_id = signed.id.to_hex();
            (
                event_id,
                RelayEventRecord {
                    endpoints: vec![cgka_traits::TransportEndpoint("wss://relay.example".into())],
                    event: NostrTransportEvent::from_nostr_event(&signed).unwrap(),
                },
            )
        };
        let (newer_id, newer_record) = make_signed_kp(newer_kp, "live-slot-2", now - 250);
        let (_older_id, older_record) = make_signed_kp(older_kp, "live-slot-1", now - 350);
        directory
            .ingest_directory_relay_event(newer_record)
            .unwrap();
        directory
            .ingest_directory_relay_event(older_record)
            .unwrap();
        assert_eq!(
            cache_a
                .entry(&live_author)
                .unwrap()
                .unwrap()
                .key_package
                .as_ref()
                .unwrap()
                .key_package_event_id,
            newer_id
        );
    }

    // Explicitly remembering a different valid slot (e.g. selector choosing a non-last-resort
    // slot created earlier than a last-resort slot) must not be blocked by cross-slot created_at.
    directory
        .remember_directory_key_package(&kp_other_slot)
        .unwrap();
    assert_eq!(
        cache_a
            .entry(&author)
            .unwrap()
            .unwrap()
            .key_package
            .as_ref()
            .unwrap()
            .key_package_event_id,
        kp_other_slot.key_package_event_id
    );
    // Restore `slot-1` as the cached KeyPackage before exercising live kind-5 deletion.
    directory.remember_directory_key_package(&kp_newer).unwrap();
    assert_eq!(
        cache_a
            .entry(&author)
            .unwrap()
            .unwrap()
            .key_package
            .as_ref()
            .unwrap()
            .key_package_event_id,
        kp_newer.key_package_event_id
    );

    // Live kind-5 targeting the cached slot clears `entry.key_package` in both tiers.
    let delete_slot = EventBuilder::new(Kind::EventDeletion, "")
        .tags([
            Tag::parse(["k", &KIND_MARMOT_KEY_PACKAGE.to_string()]).unwrap(),
            Tag::parse(["a", &format!("{KIND_MARMOT_KEY_PACKAGE}:{author}:slot-1")]).unwrap(),
        ])
        .custom_created_at(Timestamp::from_secs(now - 200))
        .finalize(&keys)
        .unwrap();
    directory
        .ingest_directory_relay_event(RelayEventRecord {
            endpoints: vec![cgka_traits::TransportEndpoint("wss://relay.example".into())],
            event: NostrTransportEvent::from_nostr_event(&delete_slot).unwrap(),
        })
        .unwrap();
    assert!(
        cache_a
            .entry(&author)
            .unwrap()
            .unwrap()
            .key_package
            .is_none()
    );
    assert!(
        shared
            .public_directory_user(&author)
            .unwrap()
            .unwrap()
            .key_package_json
            .is_none()
    );

    // Reopening a previously closed cache that still had the deleted KeyPackage
    // on disk must not surface it past the shared deletion barrier.
    let reopened_b = DirectoryCache::open(cache_b_path, &cache_b_key).unwrap();
    let merged = directory
        .directory_entry_for_account_id_with_handles(
            &author,
            std::slice::from_ref(&reopened_b),
            &shared,
            &HashMap::new(),
        )
        .unwrap()
        .unwrap();
    assert!(merged.key_package.is_none());
    reopened_b.close().unwrap();

    // A replayed copy of the deleted KeyPackage must stay rejected.
    directory.remember_directory_key_package(&kp_newer).unwrap();
    assert!(
        cache_a
            .entry(&author)
            .unwrap()
            .unwrap()
            .key_package
            .is_none()
    );

    // Live kind-5 for an unknown author records the barrier without promoting them.
    let delete_unknown = EventBuilder::new(Kind::EventDeletion, "")
        .tags([
            Tag::parse(["k", &KIND_MARMOT_KEY_PACKAGE.to_string()]).unwrap(),
            Tag::parse([
                "a",
                &format!("{KIND_MARMOT_KEY_PACKAGE}:{unknown_author}:slot-x"),
            ])
            .unwrap(),
        ])
        .custom_created_at(Timestamp::from_secs(now - 200))
        .finalize(&unknown_keys)
        .unwrap();
    directory
        .ingest_directory_relay_event(RelayEventRecord {
            endpoints: vec![cgka_traits::TransportEndpoint("wss://relay.example".into())],
            event: NostrTransportEvent::from_nostr_event(&delete_unknown).unwrap(),
        })
        .unwrap();
    assert!(cache_a.entry(&unknown_author).unwrap().is_none());
    assert!(
        shared
            .public_directory_user(&unknown_author)
            .unwrap()
            .is_none()
    );

    // A newer valid KeyPackage after deletion is accepted; then a newer malformed
    // live kind-30443 for that same slot supersedes and clears it.
    let kp_fresh = make_fetched("slot-1", &"cc".repeat(32), now - 100, 0x33);
    directory.remember_directory_key_package(&kp_fresh).unwrap();
    assert_eq!(
        cache_a
            .entry(&author)
            .unwrap()
            .unwrap()
            .key_package
            .as_ref()
            .unwrap()
            .key_package_event_id,
        kp_fresh.key_package_event_id
    );
    let malformed_replacement = EventBuilder::new(
        Kind::from(KIND_MARMOT_KEY_PACKAGE as u16),
        "not-valid-base64!!!",
    )
    .tags([Tag::parse(["d", "slot-1"]).unwrap()])
    .custom_created_at(Timestamp::from_secs(now - 50))
    .finalize(&keys)
    .unwrap();
    assert!(
        directory
            .ingest_directory_relay_event(RelayEventRecord {
                endpoints: vec![cgka_traits::TransportEndpoint("wss://relay.example".into())],
                event: NostrTransportEvent::from_nostr_event(&malformed_replacement).unwrap(),
            })
            .is_err()
    );
    assert!(
        cache_a
            .entry(&author)
            .unwrap()
            .unwrap()
            .key_package
            .is_none()
    );

    cache_a.close().unwrap();
    shared.close().unwrap();
    plane.shutdown().await;
}
