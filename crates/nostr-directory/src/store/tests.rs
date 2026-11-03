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
        // Follow edges do not retain a timestamp; only profiles and relay
        // lists have stale-event ordering at this ingress.
        let replays = if kind == 3 {
            vec![newer]
        } else {
            vec![newer, initial]
        };
        for duplicate_or_stale in replays {
            directory
                .ingest_directory_relay_event(record(duplicate_or_stale))
                .unwrap();
            assert_eq!(
                cache.entry(&author).unwrap(),
                latest,
                "duplicate and stale authenticated events preserve freshness"
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
