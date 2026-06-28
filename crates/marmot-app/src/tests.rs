use super::*;
use cgka_traits::Timestamp;
use cgka_traits::app_event::{
    AGENT_ACTIVITY_STATUS_TAG, AGENT_OPERATION_NAME_TAG, AGENT_OPERATION_STATUS_TAG,
    AGENT_OPERATION_TYPE_TAG, EVENT_REF_TAG, GROUP_SYSTEM_TYPE_TAG,
    MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY, MARMOT_APP_EVENT_KIND_AGENT_OPERATION,
    MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, MARMOT_APP_EVENT_KIND_CHAT,
    MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
    MARMOT_APP_EVENT_KIND_REACTION, MarmotAppEvent as MarmotInnerEvent, QUOTE_REF_TAG,
    STREAM_CHUNKS_TAG, STREAM_FINAL_KIND_TAG, STREAM_HASH_TAG, STREAM_START_TAG, STREAM_TAG,
    STREAM_TYPE_TAG,
};
use marmot_account::AccountHomeError;
use storage_sqlite::StoredRelayTelemetrySettings;
use transport_quic_broker::BrokerServerTrust;

use crate::audit_log::AUDIT_ID_BYTES;
use crate::conversions::{app_group_from_stored_group, stored_group_from_app_group};
use crate::directory::records::public_directory_user_record;
use crate::ids::npub_for_account_id_lossy;
use crate::key_package_records::{
    relay_list_queries, require_key_package_tag, require_multi_value_key_package_tag,
    require_multi_value_key_package_tag_contains,
};
use crate::messages::STREAM_ROUTE_QUIC;
use crate::messages::{AppMessageIntent, build_inner_event};

#[test]
fn legacy_projection_update_json_defaults_new_streaming_fields() {
    let update: AppProjectionUpdate = serde_json::from_str(
        r#"{"group_id_hex":"group","timeline_messages":[],"chat_list_row":null}"#,
    )
    .unwrap();

    assert!(update.timeline_changes.is_empty());
    assert_eq!(
        update.chat_list_trigger,
        ChatListUpdateTrigger::SnapshotRefresh
    );
}

fn relay_delivery(event_id: String, pubkey: String) -> cgka_traits::TransportDelivery {
    let event = NostrTransportEvent {
        id: event_id,
        pubkey,
        created_at: 1,
        kind: transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE,
        tags: vec![vec!["h".to_owned(), "aa".to_owned()]],
        content: "ciphertext".to_owned(),
        sig: None,
    };
    cgka_traits::TransportDelivery {
        account_id: MemberId::new(vec![0; 32]),
        group_id_hint: None,
        message: event.to_transport_message().unwrap(),
        received_at: cgka_traits::transport::Timestamp(1),
        source: cgka_traits::TransportDeliverySource {
            transport: cgka_traits::transport::TransportSource("nostr".to_owned()),
            plane: cgka_traits::TransportDeliveryPlane::Group,
            endpoint: None,
            subscription_id: None,
            wire: None,
        },
    }
}

#[test]
fn key_package_id_list_tag_must_be_exactly_one() {
    let make = |tags: Vec<Vec<String>>| NostrTransportEvent {
        id: "00".repeat(32),
        pubkey: "11".repeat(32),
        created_at: 1,
        kind: 30443,
        tags,
        content: String::new(),
        sig: None,
    };
    // A single id-list tag is accepted.
    let one = make(vec![vec!["mls_extensions".into(), "0x0006".into()]]);
    assert!(require_multi_value_key_package_tag(&one, "mls_extensions").is_ok());
    // Two tags with the same id-list name MUST be rejected, not first-match read.
    let two = make(vec![
        vec!["mls_extensions".into(), "0x0006".into()],
        vec!["mls_extensions".into(), "0xf2f1".into()],
    ]);
    assert!(require_multi_value_key_package_tag(&two, "mls_extensions").is_err());
    assert!(
        require_multi_value_key_package_tag_contains(&two, "mls_extensions", "0x0006").is_err()
    );
    // The single-value consumer (mls_ciphersuite) also rejects a duplicate.
    let two_cs = make(vec![
        vec!["mls_ciphersuite".into(), "0x0001".into()],
        vec!["mls_ciphersuite".into(), "0x0002".into()],
    ]);
    assert!(require_key_package_tag(&two_cs, "mls_ciphersuite", |_| true).is_err());
}

#[test]
fn relay_list_discovery_builds_one_limited_query_per_required_kind() {
    let account_id_hex =
        "0000000000000000000000000000000000000000000000000000000000000001".to_owned();

    let queries = relay_list_queries(account_id_hex.clone());

    assert_eq!(queries.len(), 2);
    let kinds = queries
        .iter()
        .map(|query| {
            assert_eq!(query.authors, vec![account_id_hex.clone()]);
            assert_eq!(query.limit, 12);
            query.kind
        })
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        vec![KIND_NIP65_RELAY_LIST, KIND_MARMOT_INBOX_RELAY_LIST]
    );
}

#[test]
fn directory_search_bounds_frontier_from_cached_follow_lists() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let cache = app.directory_cache_for_account(&account).unwrap();
    let follows = (0..USER_DIRECTORY_SEARCH_MAX_FRONTIER + 8)
        .map(|idx| format!("{:064x}", idx + 1))
        .collect::<Vec<_>>();

    cache
        .put(&UserDirectoryRecord {
            account_id_hex: account.account_id_hex.clone(),
            npub: npub_for_account_id_lossy(&account.account_id_hex),
            local_account: None,
            profile: None,
            follows: follows.clone(),
            follow_source_relays: Vec::new(),
            relay_lists: AccountRelayListStatus::empty(),
            key_package: None,
        })
        .unwrap();

    for follow in follows {
        cache
            .put(&UserDirectoryRecord {
                account_id_hex: follow.clone(),
                npub: npub_for_account_id_lossy(&follow),
                local_account: None,
                profile: Some(UserProfileMetadata {
                    name: Some("needle".into()),
                    display_name: None,
                    about: None,
                    picture: None,
                    nip05: None,
                    lud16: None,
                    created_at: 0,
                    source_relays: Vec::new(),
                }),
                follows: Vec::new(),
                follow_source_relays: Vec::new(),
                relay_lists: AccountRelayListStatus::empty(),
                key_package: None,
            })
            .unwrap();
    }

    let results = app
        .search_user_directory(UserDirectorySearch {
            searcher_account_id_hex: account.account_id_hex,
            query: "needle".into(),
            radius_start: 1,
            radius_end: 1,
            limit: None,
        })
        .unwrap();

    assert_eq!(results.len(), USER_DIRECTORY_SEARCH_MAX_FRONTIER);
}

#[test]
fn directory_search_uses_graph_cache_without_promoting_known_user() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let cache = app.directory_cache_for_account(&account).unwrap();
    let graph_user = format!("{:064x}", 42);

    cache
        .put(&UserDirectoryRecord {
            account_id_hex: account.account_id_hex.clone(),
            npub: npub_for_account_id_lossy(&account.account_id_hex),
            local_account: None,
            profile: None,
            follows: vec![graph_user.clone()],
            follow_source_relays: Vec::new(),
            relay_lists: AccountRelayListStatus::empty(),
            key_package: None,
        })
        .unwrap();
    cache
        .put_search_graph_record(
            &directory::DirectorySearchGraphRecord {
                account_id_hex: graph_user.clone(),
                npub: npub_for_account_id_lossy(&graph_user),
                profile: Some(UserProfileMetadata {
                    name: Some("graph-needle".into()),
                    display_name: None,
                    about: None,
                    picture: None,
                    nip05: None,
                    lud16: None,
                    created_at: 1_700_000_001,
                    source_relays: Vec::new(),
                }),
                follows: Some(Vec::new()),
                metadata_updated_at: Some(1_700_000_001),
                metadata_expires_at: None,
            },
            1_700_000_002,
        )
        .unwrap();

    let results = app
        .search_user_directory(UserDirectorySearch {
            searcher_account_id_hex: account.account_id_hex.clone(),
            query: "graph-needle".into(),
            radius_start: 1,
            radius_end: 1,
            limit: None,
        })
        .unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].account_id_hex, graph_user);
    assert!(
        app.directory_entry_for_account_id(&graph_user)
            .unwrap()
            .is_none()
    );
}

fn test_directory_record(account_id_hex: &str, name: &str, created_at: u64) -> UserDirectoryRecord {
    UserDirectoryRecord {
        account_id_hex: account_id_hex.to_owned(),
        npub: npub_for_account_id_lossy(account_id_hex),
        local_account: None,
        profile: Some(UserProfileMetadata {
            name: Some(name.to_owned()),
            display_name: None,
            about: None,
            picture: None,
            nip05: None,
            lud16: None,
            created_at,
            source_relays: Vec::new(),
        }),
        follows: Vec::new(),
        follow_source_relays: Vec::new(),
        relay_lists: AccountRelayListStatus::empty(),
        key_package: None,
    }
}

#[test]
fn duplicate_directory_entry_save_skips_cache_writes() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let cache = app.directory_cache_for_account(&account).unwrap();
    let account_id = format!("{:064x}", 42);
    let mut entry = test_directory_record(&account_id, "cached-peer", 1_700_000_042);
    entry.profile.as_mut().unwrap().source_relays = vec!["wss://profiles.example".into()];

    cache.reset_put_count_for_test();
    app.save_directory_entry_with_reason(&entry, "message")
        .unwrap();
    assert_eq!(cache.put_count_for_test(), 1);

    cache.reset_put_count_for_test();
    app.save_directory_entry_with_reason(&entry, "message")
        .unwrap();
    assert_eq!(cache.put_count_for_test(), 0);

    entry.profile.as_mut().unwrap().display_name = Some("cached peer".into());
    app.save_directory_entry_with_reason(&entry, "message")
        .unwrap();
    assert_eq!(cache.put_count_for_test(), 1);
}

#[test]
fn remember_directory_profile_if_newer_keeps_local_edit_on_equal_timestamp() {
    // Regression for darkmatter#206: Nostr `created_at` is second-resolution,
    // so a rapid profile republish can carry the same timestamp as the
    // previous pre-edit kind-0. A lagging relay can then serve that stale
    // same-second copy back during a directory refresh. The cache must be
    // retained on an equal timestamp so the just-published local edit is not
    // reverted; only a strictly newer fetch replaces it.
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let account_id = format!("{:064x}", 206);

    // Local edit cached at t=1_700_000_000 (own-account entry).
    app.save_directory_entry(&test_directory_record(
        &account_id,
        "edited-local",
        1_700_000_000,
    ))
    .unwrap();

    // Stale relay copy arrives with the SAME second-resolution timestamp.
    let stale_same_second = UserProfileMetadata {
        name: Some("stale-relay".to_owned()),
        created_at: 1_700_000_000,
        ..UserProfileMetadata::default()
    };
    app.remember_directory_profile_if_newer(&account_id, &stale_same_second)
        .unwrap();

    // The local edit must survive the equal-timestamp refresh.
    let entry = app
        .directory_entry_for_account_id(&account_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        entry.profile.and_then(|profile| profile.name),
        Some("edited-local".to_owned())
    );

    // A strictly newer fetch still wins (genuine remote update).
    let newer = UserProfileMetadata {
        name: Some("newer-remote".to_owned()),
        created_at: 1_700_000_001,
        ..UserProfileMetadata::default()
    };
    app.remember_directory_profile_if_newer(&account_id, &newer)
        .unwrap();
    let entry = app
        .directory_entry_for_account_id(&account_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        entry.profile.and_then(|profile| profile.name),
        Some("newer-remote".to_owned())
    );
}

#[test]
fn directory_entry_prefers_newer_shared_record_over_stale_cache() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let cache = app.directory_cache_for_account(&account).unwrap();
    let contact = format!("{:064x}", 42);

    cache
        .put(&test_directory_record(&contact, "old-cache", 1))
        .unwrap();
    app.shared_storage()
        .unwrap()
        .put_public_directory_user(
            &public_directory_user_record(&test_directory_record(&contact, "new-shared", 2))
                .unwrap(),
        )
        .unwrap();

    let entry = app
        .directory_entry_for_account_id(&contact)
        .unwrap()
        .unwrap();

    assert_eq!(
        entry.profile.and_then(|profile| profile.name),
        Some("new-shared".to_owned())
    );
    assert_eq!(
        app.display_name_for_account_id(&contact).unwrap(),
        Some("new-shared".to_owned())
    );
}

#[test]
fn repeated_display_name_lookup_reuses_directory_cache_handle() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let contact = format!("{:064x}", 44);

    app.save_directory_entry(&test_directory_record(&contact, "Cached Contact", 1))
        .unwrap();
    drop(app);
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    for _ in 0..5 {
        assert_eq!(
            app.display_name_for_account_id(&contact).unwrap(),
            Some("Cached Contact".to_owned())
        );
    }

    assert_eq!(app.directory_cache_open_count_for_test(), 1);
    assert!(app.directory_cache_path(&account.label).exists());
}

#[test]
fn batch_display_name_lookup_opens_one_directory_cache_per_local_account() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let contact = format!("{:064x}", 45);

    app.save_directory_entry(&test_directory_record(&contact, "Batch Contact", 1))
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    for _ in 0..5 {
        let names = app
            .display_names_for_account_ids(&[contact.clone(), bob.account_id_hex.clone()])
            .unwrap();
        assert_eq!(names.get(&contact), Some(&"Batch Contact".to_owned()));
        assert_eq!(names.get(&bob.account_id_hex), Some(&"bob".to_owned()));
    }

    assert_eq!(app.directory_cache_open_count_for_test(), 2);
}

#[test]
fn warm_directory_storage_opens_shared_and_local_directory_handles() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let public_key = nostr::Keys::generate().public_key().to_hex();
    let public_account = home.add_public_account(&public_key).unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    app.warm_directory_storage().unwrap();
    let open_count_after_warm = app.directory_cache_open_count_for_test();

    assert_eq!(open_count_after_warm, 2);
    assert!(app.shared_storage_path().exists());
    assert!(app.directory_cache_path(&alice.label).exists());
    assert!(app.directory_cache_path(&bob.label).exists());
    assert!(!app.directory_cache_path(&public_account.label).exists());

    assert_eq!(
        app.display_name_for_account_id(&alice.account_id_hex)
            .unwrap(),
        Some("alice".to_owned())
    );
    assert_eq!(
        app.display_names_for_account_ids(&[bob.account_id_hex.clone(), public_key])
            .unwrap()
            .get(&bob.account_id_hex),
        Some(&"bob".to_owned())
    );
    assert_eq!(
        app.directory_cache_open_count_for_test(),
        open_count_after_warm
    );
}

#[test]
fn drop_account_caches_evicts_storage_and_directory_handles_and_warm_flags() {
    // Regression for darkmatter#220: removing an account (or rolling back a
    // failed setup) must evict the cached account-storage connection and
    // directory-cache handle before the account directory is deleted.
    // Otherwise the stale handle keeps pointing at the unlinked inode and a
    // later re-import silently splits writes across a deleted DB.
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    // Warm the account-storage connection, directory cache, and the
    // account-state / chat-list warm flags.
    app.ensure_account_state(&alice.label).unwrap();
    let account_summary = app.account_home().account(&alice.label).unwrap();
    app.ensure_chat_list_projection(&account_summary).unwrap();
    app.display_name_for_account_id(&alice.account_id_hex)
        .unwrap();

    assert!(app.account_storage_cached_for_test(&alice.label));
    assert!(app.directory_cache_cached_for_test(&alice.label));
    assert!(
        app.account_state_ready
            .lock()
            .unwrap()
            .contains(&alice.label)
    );
    assert!(
        app.chat_list_projection_warmed
            .lock()
            .unwrap()
            .contains(&alice.label)
    );

    app.drop_account_caches(&alice.label);

    assert!(!app.account_storage_cached_for_test(&alice.label));
    assert!(!app.directory_cache_cached_for_test(&alice.label));
    assert!(
        !app.account_state_ready
            .lock()
            .unwrap()
            .contains(&alice.label)
    );
    assert!(
        !app.chat_list_projection_warmed
            .lock()
            .unwrap()
            .contains(&alice.label)
    );
    assert!(
        !app.chat_list_projection_stale
            .lock()
            .unwrap()
            .contains(&alice.label)
    );
}

#[test]
fn legacy_plaintext_directory_cache_migrates_once_into_resident_cache() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let legacy_path = dir.path().join(APP_CACHE_DB_FILE);
    let cleanup_marker = dir.path().join(DIRECTORY_FUTURE_CREATED_AT_CLEANUP_MARKER);
    fs::write(cleanup_marker, b"done\n").unwrap();
    drop(Connection::open(&legacy_path).unwrap());
    let legacy_cache = DirectoryCache::open_legacy_plaintext(legacy_path.clone())
        .unwrap()
        .unwrap();
    let contact = format!("{:064x}", 46);
    legacy_cache
        .put(&test_directory_record(&contact, "Legacy Contact", 1))
        .unwrap();
    drop(legacy_cache);

    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let entry = app
        .directory_entry_for_account_id(&contact)
        .unwrap()
        .unwrap();

    assert_eq!(
        entry.profile.and_then(|profile| profile.name),
        Some("Legacy Contact".to_owned())
    );
    let shared_entry = app
        .shared_storage()
        .unwrap()
        .public_directory_user(&contact)
        .unwrap()
        .unwrap();
    assert_eq!(shared_entry.account_id_hex, contact);
    assert!(!legacy_path.exists());
    let open_count_after_migration = app.directory_cache_open_count_for_test();
    assert!(open_count_after_migration >= 1);

    let entry = app
        .directory_entry_for_account_id(&contact)
        .unwrap()
        .unwrap();
    assert_eq!(
        entry.profile.and_then(|profile| profile.name),
        Some("Legacy Contact".to_owned())
    );
    assert_eq!(
        app.directory_cache_open_count_for_test(),
        open_count_after_migration
    );
}

#[test]
fn legacy_plaintext_directory_cache_migrates_to_shared_storage_without_account_caches() {
    let dir = tempfile::tempdir().unwrap();
    let legacy_path = dir.path().join(APP_CACHE_DB_FILE);
    drop(Connection::open(&legacy_path).unwrap());
    let legacy_cache = DirectoryCache::open_legacy_plaintext(legacy_path.clone())
        .unwrap()
        .unwrap();
    let contact = format!("{:064x}", 47);
    legacy_cache
        .put(&test_directory_record(&contact, "Shared Legacy Contact", 1))
        .unwrap();
    drop(legacy_cache);

    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.migrate_legacy_directory_cache_once(&[]).unwrap();

    let shared_entry = app
        .shared_storage()
        .unwrap()
        .public_directory_user(&contact)
        .unwrap()
        .unwrap();
    let hydrated = app.hydrate_public_directory_record(shared_entry).unwrap();
    assert_eq!(
        hydrated.profile.and_then(|profile| profile.name),
        Some("Shared Legacy Contact".to_owned())
    );
    assert!(!legacy_path.exists());
}

#[test]
fn legacy_plaintext_directory_cache_keeps_file_when_migration_fails() {
    let dir = tempfile::tempdir().unwrap();
    let legacy_path = dir.path().join(APP_CACHE_DB_FILE);
    drop(Connection::open(&legacy_path).unwrap());
    let legacy_cache = DirectoryCache::open_legacy_plaintext(legacy_path.clone())
        .unwrap()
        .unwrap();
    legacy_cache
        .put(&UserDirectoryRecord {
            account_id_hex: "not-a-public-key".to_owned(),
            npub: "npub-invalid".to_owned(),
            local_account: None,
            profile: None,
            follows: Vec::new(),
            follow_source_relays: Vec::new(),
            relay_lists: AccountRelayListStatus::empty(),
            key_package: None,
        })
        .unwrap();
    drop(legacy_cache);

    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    assert!(app.migrate_legacy_directory_cache_once(&[]).is_err());
    assert!(legacy_path.exists());
    assert!(
        !*app
            .legacy_directory_cache_checked
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    );
}

#[test]
fn directory_entries_and_save_keep_newer_shared_record() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let cache = app.directory_cache_for_account(&account).unwrap();
    let contact = format!("{:064x}", 43);
    let stale = test_directory_record(&contact, "old-cache", 1);
    let fresh = test_directory_record(&contact, "new-shared", 2);

    cache.put(&stale).unwrap();
    app.shared_storage()
        .unwrap()
        .put_public_directory_user(&public_directory_user_record(&fresh).unwrap())
        .unwrap();

    let listed = app.directory_entries().unwrap();
    let listed_entry = listed
        .iter()
        .find(|entry| entry.account_id_hex == contact)
        .unwrap();
    assert_eq!(
        listed_entry
            .profile
            .as_ref()
            .and_then(|profile| profile.name.as_deref()),
        Some("new-shared")
    );

    app.save_directory_entry_with_reason(&stale, "stale-cache")
        .unwrap();
    let entry = app
        .directory_entry_for_account_id(&contact)
        .unwrap()
        .unwrap();
    assert_eq!(
        entry.profile.and_then(|profile| profile.name),
        Some("new-shared".to_owned())
    );
}

#[test]
fn received_message_sender_is_admitted_to_directory_cache() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let sender = format!("{:064x}", 42);

    assert!(
        app.directory_entry_for_account_id(&sender)
            .unwrap()
            .is_none()
    );
    app.remember_directory_message_sender(&ReceivedMessage {
        message_id_hex: "message-id".to_owned(),
        source_message_id_hex: "source-message-id".to_owned(),
        sender: sender.clone(),
        sender_display_name: None,
        group_id: GroupId::new(vec![0x01]),
        source_epoch: 0,
        plaintext: "hello".to_owned(),
        kind: MARMOT_APP_EVENT_KIND_CHAT,
        tags: Vec::new(),
        recorded_at: 0,
    })
    .unwrap();

    let entry = app
        .directory_entry_for_account_id(&sender)
        .unwrap()
        .unwrap();
    assert_eq!(entry.account_id_hex, sender);
    assert!(entry.profile.is_none());
    assert!(entry.follows.is_empty());
}

#[test]
fn directory_sync_plan_watches_local_accounts_and_known_users() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let contact = format!("{:064x}", 42);

    app.remember_directory_user_with_reason(&contact, "message")
        .unwrap();

    let plan = app.directory_sync_plan().unwrap();
    let watched = plan
        .batches
        .iter()
        .flat_map(|batch| batch.authors.clone())
        .collect::<Vec<_>>();

    assert_eq!(
        plan.endpoints,
        vec![TransportEndpoint("wss://relay.example".to_owned())]
    );
    assert_eq!(plan.watched_user_count, 2);
    assert!(watched.contains(&account.account_id_hex));
    assert!(watched.contains(&contact));
}

#[test]
fn avatar_url_round_trips_through_account_projection() {
    let mut group = AppGroupRecord::new(
        "aa".to_owned(),
        AppGroupNostrRoutingComponent::new(
            NostrRoutingV1::new([0xAA; 32], vec!["wss://relay.example".to_owned()]).unwrap(),
        )
        .unwrap(),
        "group".to_owned(),
        String::new(),
        AppGroupImageInput::default(),
        AppGroupAdminPolicyComponent::new(Vec::new()),
        AppGroupMessageRetentionComponent::disabled(),
    );
    group.avatar_url = AppGroupAvatarUrlComponent::new(
        "https://cdn.example.com/a.png".to_owned(),
        Some("512x512".to_owned()),
        None,
    )
    .unwrap();

    let stored = stored_group_from_app_group(&group);
    let restored = app_group_from_stored_group(stored).unwrap();
    assert_eq!(restored.avatar_url, group.avatar_url);
    assert!(restored.avatar_url.present);
    assert_eq!(restored.avatar_url.url, "https://cdn.example.com/a.png");

    // An absent avatar restores as absent.
    let mut plain = group.clone();
    plain.avatar_url = AppGroupAvatarUrlComponent::absent();
    let restored_plain = app_group_from_stored_group(stored_group_from_app_group(&plain)).unwrap();
    assert!(!restored_plain.avatar_url.present);
}

#[test]
fn notification_settings_default_local_notifications_on_for_new_account() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    let settings = app.notification_settings("alice").unwrap();

    assert_eq!(settings.account_ref, "alice");
    assert_eq!(settings.account_id_hex, account.account_id_hex);
    assert!(settings.local_notifications_enabled);
    assert!(!settings.native_push_enabled);
}

#[test]
fn legacy_account_projection_imports_once_into_account_storage() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let keys = app.account_home().load_signing_keys("alice").unwrap();
    let legacy_path = app.legacy_account_projection_path("alice");
    let legacy_key = app
        .sqlcipher_key(
            "alice",
            &keys,
            &legacy_path,
            SqlcipherDatabaseKind::AccountProjection,
        )
        .unwrap();
    let mut legacy = LegacyAccountProjectionDb::open(legacy_path.clone(), &legacy_key).unwrap();
    let group = AppGroupRecord::new(
        "aa".to_owned(),
        AppGroupNostrRoutingComponent::new(
            NostrRoutingV1::new([0xAA; 32], vec!["wss://relay.example".to_owned()]).unwrap(),
        )
        .unwrap(),
        "legacy".to_owned(),
        String::new(),
        AppGroupImageInput::default(),
        AppGroupAdminPolicyComponent::new(Vec::new()),
        AppGroupMessageRetentionComponent::disabled(),
    );
    legacy
        .save_state(&AccountState {
            label: "alice".to_owned(),
            seen_events: vec!["seen".to_owned()],
            last_transport_timestamp: Some(1_700_000_100),
            groups: vec![group],
        })
        .unwrap();
    legacy
        .record_message(&AppMessageProjection {
            message_id_hex: "legacy-message".to_owned(),
            source_message_id_hex: None,
            direction: "received".to_owned(),
            group_id_hex: "aa".to_owned(),
            sender: account.account_id_hex.clone(),
            plaintext: "from legacy".to_owned(),
            kind: 9,
            tags: Vec::new(),
            source_epoch: None,
            recorded_at: Some(1_700_000_101),
            origin_commit_id: None,
        })
        .unwrap();
    legacy
        .set_native_push_enabled("alice", &account.account_id_hex, true)
        .unwrap();
    legacy
        .set_local_notifications_enabled("alice", &account.account_id_hex, false)
        .unwrap();
    legacy
        .upsert_push_registration(
            PushRegistration {
                account_ref: "alice".to_owned(),
                account_id_hex: account.account_id_hex.clone(),
                platform: PushPlatform::Apns,
                token_fingerprint: "fingerprint".to_owned(),
                server_pubkey_hex: "bb".repeat(32),
                relay_hint: Some("wss://relay.example".to_owned()),
                created_at_ms: 10,
                updated_at_ms: 11,
                last_shared_at_ms: None,
            },
            vec![1, 2, 3],
        )
        .unwrap();
    legacy
        .upsert_group_push_token(&GroupPushTokenRecord {
            group_id_hex: "aa".to_owned(),
            member_id_hex: account.account_id_hex.clone(),
            leaf_index: 7,
            platform: PushPlatform::Apns,
            token_fingerprint: "fingerprint".to_owned(),
            server_pubkey_hex: "bb".repeat(32),
            relay_hint: None,
            encrypted_token: vec![9, 8, 7],
            updated_at_ms: 12,
        })
        .unwrap();

    let groups = app.groups("alice").unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].profile.name, "legacy");
    let messages = app.messages("alice").unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].plaintext, "from legacy");
    let settings = app.notification_settings("alice").unwrap();
    assert!(!settings.local_notifications_enabled);
    assert!(settings.native_push_enabled);
    assert!(app.push_registration("alice").unwrap().is_some());
    assert_eq!(app.group_push_tokens("alice", "aa").unwrap().len(), 1);

    legacy
        .record_message(&AppMessageProjection {
            message_id_hex: "post-marker".to_owned(),
            source_message_id_hex: None,
            direction: "received".to_owned(),
            group_id_hex: "aa".to_owned(),
            sender: account.account_id_hex,
            plaintext: "should stay legacy-only".to_owned(),
            kind: 9,
            tags: Vec::new(),
            source_epoch: None,
            recorded_at: Some(1_700_000_102),
            origin_commit_id: None,
        })
        .unwrap();
    assert_eq!(app.messages("alice").unwrap().len(), 1);
}

#[test]
fn own_relay_echo_requires_known_event_id_not_just_pubkey() {
    let local_pubkey = "11".repeat(32);
    let known_event_id = "22".repeat(32);
    let new_cross_device_event_id = "33".repeat(32);
    let known_event_ids = HashSet::from([known_event_id.clone()]);

    let known_local_delivery = relay_delivery(known_event_id.clone(), local_pubkey.clone());
    assert!(client::is_own_relay_echo(
        &known_local_delivery,
        &local_pubkey,
        &known_event_ids
    ));

    let same_pubkey_new_event = relay_delivery(new_cross_device_event_id, local_pubkey.clone());
    assert!(!client::is_own_relay_echo(
        &same_pubkey_new_event,
        &local_pubkey,
        &known_event_ids
    ));

    let known_other_pubkey_delivery = relay_delivery(known_event_id, "44".repeat(32));
    assert!(!client::is_own_relay_echo(
        &known_other_pubkey_delivery,
        &local_pubkey,
        &known_event_ids
    ));
}

#[test]
fn account_worker_is_spawned_as_abortable_async_task() {
    let source = include_str!("runtime/account_worker.rs");

    assert!(source.contains("tokio::spawn(run_app_runtime_account_worker"));
    assert!(source.contains("managed account worker shutdown timed out; aborting"));
}

#[test]
fn account_worker_reconnect_backoff_doubles_caps_and_resets() {
    let mut backoff =
        runtime::AccountWorkerReconnectBackoff::new(Duration::from_secs(2), Duration::from_secs(8));

    assert_eq!(
        backoff.next_delay_with_jitter(Duration::ZERO),
        Duration::from_secs(2)
    );
    assert_eq!(
        backoff.next_delay_with_jitter(Duration::ZERO),
        Duration::from_secs(4)
    );
    assert_eq!(
        backoff.next_delay_with_jitter(Duration::ZERO),
        Duration::from_secs(8)
    );
    assert_eq!(
        backoff.next_delay_with_jitter(Duration::from_secs(100)),
        Duration::from_secs(8)
    );
    backoff.reset();
    assert_eq!(
        backoff.next_delay_with_jitter(Duration::ZERO),
        Duration::from_secs(2)
    );
}

#[test]
fn app_transport_routing_recovers_from_poisoned_lock() {
    let routing = AppTransportRouting::new(AppRoutingState {
        local_inbox_endpoints: Vec::new(),
        key_package_endpoints: Vec::new(),
        inbox_routes: HashMap::new(),
        group_routes: Vec::new(),
        required_acks: 1,
    });
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = routing.inner.write().unwrap();
        panic!("poison app routing lock");
    }));

    routing.replace(AppRoutingState {
        local_inbox_endpoints: Vec::new(),
        key_package_endpoints: Vec::new(),
        inbox_routes: HashMap::new(),
        group_routes: Vec::new(),
        required_acks: 2,
    });

    assert_eq!(routing.snapshot().required_acks, 2);
}

#[test]
fn relay_plane_rebuild_uses_persisted_cursor_with_bounded_overlap() {
    let relay_plane = MarmotRelayPlane::with_subscription_rebuild_lookback(Duration::from_secs(30));

    assert_eq!(
        relay_plane.subscription_rebuild_since(Some(1_700_000_000)),
        Some(Timestamp(1_699_999_970))
    );
    assert_eq!(
        relay_plane.subscription_rebuild_since(Some(20)),
        Some(Timestamp(0))
    );
    assert_eq!(relay_plane.subscription_rebuild_since(None), None);
    assert_eq!(
        MarmotRelayPlane::full_history().subscription_rebuild_since(Some(1_700_000_000)),
        None
    );
}

#[test]
fn agent_stream_candidate_parser_skips_malformed_quic_candidates() {
    let candidates = vec![
        "quic://".to_owned(),
        "https://127.0.0.1:4450".to_owned(),
        "quic://127.0.0.1:4450".to_owned(),
    ];

    let parsed = runtime::parse_quic_candidates(&candidates).expect("valid fallback candidate");

    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].authority, "127.0.0.1:4450");
    assert_eq!(parsed[0].server_name, "127.0.0.1");
}

#[test]
fn agent_stream_insecure_local_only_applies_to_loopback_brokers() {
    let loopback = "127.0.0.1:4450".parse().unwrap();
    let remote = "203.0.113.10:4450".parse().unwrap();

    assert!(matches!(
        runtime::broker_trust_for_addr(loopback, None, true),
        BrokerServerTrust::InsecureLocal
    ));
    assert!(matches!(
        runtime::broker_trust_for_addr(remote, None, true),
        BrokerServerTrust::Platform
    ));
    assert!(matches!(
        runtime::broker_trust_for_addr(remote, Some(vec![1, 2, 3]), true),
        BrokerServerTrust::CertificateDer(der) if der == vec![1, 2, 3]
    ));
}

#[test]
fn remembered_seen_events_are_bounded_in_memory() {
    let mut state = AccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: None,
        groups: Vec::new(),
    };
    let mut seen = HashSet::new();

    for index in 0..(MAX_SEEN_EVENT_IDS + 2) {
        let event_id = format!("event-{index:05}");
        remember_seen_event(&mut seen, &mut state, event_id);
    }

    assert_eq!(state.seen_events.len(), MAX_SEEN_EVENT_IDS);
    // Pruning the oldest ids out of the ordered Vec must also drop them from
    // the lookup set, so the two stay the same bounded size without rebuilding.
    assert_eq!(seen.len(), MAX_SEEN_EVENT_IDS);
    assert!(!seen.contains("event-00000"));
    assert!(!seen.contains("event-00001"));
    assert!(seen.contains("event-00002"));
    assert_eq!(
        state.seen_events.first().map(String::as_str),
        Some("event-00002")
    );
    let expected_last = format!("event-{:05}", MAX_SEEN_EVENT_IDS + 1);
    assert!(seen.contains(expected_last.as_str()));
    assert_eq!(
        state.seen_events.last().map(String::as_str),
        Some(expected_last.as_str())
    );
}

#[test]
fn remember_seen_event_deduplicates_via_lookup_set() {
    let mut state = AccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: None,
        groups: Vec::new(),
    };
    let mut seen = HashSet::new();

    remember_seen_event(&mut seen, &mut state, "dup".to_owned());
    remember_seen_event(&mut seen, &mut state, "dup".to_owned());
    remember_seen_event(&mut seen, &mut state, "other".to_owned());

    assert_eq!(
        state.seen_events,
        vec!["dup".to_owned(), "other".to_owned()]
    );
    assert_eq!(seen.len(), 2);
    assert!(seen.contains("dup"));
    assert!(seen.contains("other"));
}

const SENDER_HEX: &str = "aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55";

fn build(intent: AppMessageIntent) -> MarmotInnerEvent {
    build_inner_event(&intent, SENDER_HEX, 1_700_000_000).unwrap()
}

#[test]
fn chat_intent_builds_kind_nine_with_no_tags() {
    let event = build(AppMessageIntent::Chat {
        content: "hello".to_owned(),
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_CHAT);
    assert_eq!(event.content, "hello");
    assert!(event.tags.is_empty());
    assert_eq!(event.pubkey, SENDER_HEX);
}

#[test]
fn reaction_intent_builds_kind_seven_with_e_tag() {
    let event = build(AppMessageIntent::Reaction {
        target_message_id: "abc123".to_owned(),
        emoji: "🔥".to_owned(),
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_REACTION);
    assert_eq!(event.content, "🔥");
    assert_eq!(tag_value(&event.tags, EVENT_REF_TAG), Some("abc123"));
}

#[test]
fn reaction_intent_rejects_empty_emoji() {
    let result = build_inner_event(
        &AppMessageIntent::Reaction {
            target_message_id: "abc123".to_owned(),
            emoji: "  ".to_owned(),
        },
        SENDER_HEX,
        1,
    );
    assert!(matches!(result, Err(AppError::InvalidAppMessagePayload(_))));
}

#[test]
fn delete_intent_builds_empty_kind_five_with_e_tag() {
    let event = build(AppMessageIntent::Delete {
        target_message_id: "abc123".to_owned(),
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_DELETE);
    assert_eq!(event.content, "");
    assert_eq!(tag_value(&event.tags, EVENT_REF_TAG), Some("abc123"));
}

#[test]
fn reply_intent_builds_kind_nine_with_e_and_q_tags() {
    let event = build(AppMessageIntent::Reply {
        target_message_id: "parent".to_owned(),
        text: "sure".to_owned(),
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_CHAT);
    assert_eq!(event.content, "sure");
    assert_eq!(tag_value(&event.tags, EVENT_REF_TAG), Some("parent"));
    assert_eq!(tag_value(&event.tags, QUOTE_REF_TAG), Some("parent"));
}

#[test]
fn media_intent_builds_kind_nine_with_ordered_imeta_tags() {
    let event = build(AppMessageIntent::Media {
        attachments: vec![
            MediaAttachmentReference {
                locators: vec![MediaLocator {
                    kind: "blossom-v1".to_owned(),
                    value: format!("https://media.example/{}.bin", hex::encode([0x33_u8; 32])),
                }],
                ciphertext_sha256: hex::encode([0x33_u8; 32]),
                plaintext_sha256: hex::encode([0x11_u8; 32]),
                nonce_hex: hex::encode([0x22_u8; 12]),
                file_name: "a.png".to_owned(),
                media_type: "image/png".to_owned(),
                version: ENCRYPTED_MEDIA_VERSION.to_owned(),
                source_epoch: 7,
                dim: Some("10x20".to_owned()),
                thumbhash: Some("thumb".to_owned()),
            },
            MediaAttachmentReference {
                locators: vec![MediaLocator {
                    kind: "blossom-v1".to_owned(),
                    value: format!("https://media.example/{}.bin", hex::encode([0x44_u8; 32])),
                }],
                ciphertext_sha256: hex::encode([0x44_u8; 32]),
                plaintext_sha256: hex::encode([0x55_u8; 32]),
                nonce_hex: hex::encode([0x66_u8; 12]),
                file_name: "b.mp4".to_owned(),
                media_type: "video/mp4".to_owned(),
                version: ENCRYPTED_MEDIA_VERSION.to_owned(),
                source_epoch: 7,
                dim: None,
                thumbhash: None,
            },
        ],
        caption: Some("cap".to_owned()),
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_CHAT);
    assert_eq!(event.content, "cap");
    let imeta = event
        .tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
        .collect::<Vec<_>>();
    assert_eq!(imeta.len(), 2);
    assert!(imeta[0].iter().any(|field| field
        == &format!(
            "locator blossom-v1 https://media.example/{}.bin",
            hex::encode([0x33_u8; 32])
        )));
    assert!(imeta[0].iter().any(|field| field == "m image/png"));
    assert!(imeta[0].iter().any(|field| field == "filename a.png"));
    assert!(
        imeta[0]
            .iter()
            .any(|field| field == "nonce 222222222222222222222222")
    );
    assert!(imeta[0].iter().any(|field| field == "v encrypted-media-v1"));
    assert!(imeta[0].iter().any(|field| field == "thumbhash thumb"));
    assert!(imeta[1].iter().any(|field| field
        == &format!(
            "locator blossom-v1 https://media.example/{}.bin",
            hex::encode([0x44_u8; 32])
        )));
}

#[test]
fn stream_start_intent_builds_kind_1200_with_broker_tags() {
    let event = build(AppMessageIntent::StreamStart {
        stream_id: vec![0xab; 32],
        quic_candidates: vec![
            "quic://broker.example:4450".to_owned(),
            "quic://[::1]:4450".to_owned(),
        ],
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_AGENT_STREAM_START);
    assert_eq!(event.content, "");
    let start = StreamStartView::from_event(event.kind, &event.tags).unwrap();
    assert_eq!(start.stream_id_hex, hex::encode([0xab; 32]));
    assert_eq!(start.route, STREAM_ROUTE_QUIC);
    assert_eq!(
        start.quic_candidates,
        vec![
            "quic://broker.example:4450".to_owned(),
            "quic://[::1]:4450".to_owned(),
        ]
    );
    assert_eq!(tag_value(&event.tags, STREAM_TYPE_TAG), Some("text"));
    assert_eq!(tag_value(&event.tags, STREAM_FINAL_KIND_TAG), Some("9"));
}

#[test]
fn stream_start_intent_requires_a_broker() {
    let result = build_inner_event(
        &AppMessageIntent::StreamStart {
            stream_id: vec![0xab; 32],
            quic_candidates: vec!["   ".to_owned()],
        },
        SENDER_HEX,
        1,
    );
    assert!(matches!(result, Err(AppError::AgentStreamMissingCandidate)));
}

#[test]
fn stream_final_intent_builds_kind_nine_stream_final() {
    let start_event_id = "aa".repeat(32);
    let event = build(AppMessageIntent::StreamFinal {
        request: AgentTextStreamFinishRequest {
            stream_id: vec![0xcd; 32],
            start_event_id: start_event_id.clone(),
            final_text_or_reference: "done".to_owned(),
            transcript_hash: [0xee; 32],
            chunk_count: 3,
            finished_at: 9,
        },
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_CHAT);
    assert_eq!(event.content, "done");
    assert!(is_stream_final_event(event.kind, &event.tags));
    assert_eq!(
        tag_value(&event.tags, STREAM_TAG),
        Some(hex::encode([0xcd; 32]).as_str())
    );
    assert_eq!(
        tag_value(&event.tags, STREAM_START_TAG),
        Some(start_event_id.as_str())
    );
    assert_eq!(
        tag_value(&event.tags, STREAM_HASH_TAG),
        Some(hex::encode([0xee; 32]).as_str())
    );
    assert_eq!(tag_value(&event.tags, STREAM_CHUNKS_TAG), Some("3"));
}

#[test]
fn agent_activity_intent_builds_kind_1201_json_payload() {
    let event = build(AppMessageIntent::AgentActivity {
        status: "thinking".to_owned(),
        text: "Thinking".to_owned(),
        reply_to_message_id: Some("parent".to_owned()),
        extra: None,
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY);
    assert_eq!(
        tag_value(&event.tags, AGENT_ACTIVITY_STATUS_TAG),
        Some("thinking")
    );
    assert_eq!(tag_value(&event.tags, EVENT_REF_TAG), Some("parent"));
    let content: serde_json::Value = serde_json::from_str(&event.content).unwrap();
    assert_eq!(content["v"], 1);
    assert_eq!(content["status"], "thinking");
    assert_eq!(content["text"], "Thinking");
}

#[test]
fn agent_operation_intent_builds_kind_1202_json_payload() {
    let event = build(AppMessageIntent::AgentOperation {
        event_type: "tool_call".to_owned(),
        status: "started".to_owned(),
        operation_id: Some("call-123".to_owned()),
        run_id: Some("run-1".to_owned()),
        turn_id: Some("turn-1".to_owned()),
        name: Some("search".to_owned()),
        text: "Searching".to_owned(),
        preview: Some("glp-1".to_owned()),
        details: Some(serde_json::json!({"args": {"query": "glp-1"}})),
        sequence: Some(2),
        ok: None,
        duration_ms: None,
        reply_to_message_id: Some("parent".to_owned()),
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_AGENT_OPERATION);
    assert_eq!(
        tag_value(&event.tags, AGENT_OPERATION_STATUS_TAG),
        Some("started")
    );
    assert_eq!(
        tag_value(&event.tags, AGENT_OPERATION_TYPE_TAG),
        Some("tool_call")
    );
    assert_eq!(
        tag_value(&event.tags, AGENT_OPERATION_NAME_TAG),
        Some("search")
    );
    assert_eq!(tag_value(&event.tags, EVENT_REF_TAG), Some("parent"));
    let content: serde_json::Value = serde_json::from_str(&event.content).unwrap();
    assert_eq!(content["event_type"], "tool_call");
    assert_eq!(content["status"], "started");
    assert_eq!(content["operation_id"], "call-123");
    assert_eq!(content["run_id"], "run-1");
    assert_eq!(content["turn_id"], "turn-1");
    assert_eq!(content["name"], "search");
    assert_eq!(content["preview"], "glp-1");
    assert_eq!(content["details"]["args"]["query"], "glp-1");
    assert_eq!(content["sequence"], 2);
}

#[test]
fn group_system_intent_builds_kind_1210_json_payload() {
    let event = build(AppMessageIntent::GroupSystem {
        system_type: "member_added".to_owned(),
        text: "Member added".to_owned(),
        data: Some(serde_json::json!({"member": "alice"})),
    });
    assert_eq!(event.kind, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM);
    assert_eq!(
        tag_value(&event.tags, GROUP_SYSTEM_TYPE_TAG),
        Some("member_added")
    );
    let content: serde_json::Value = serde_json::from_str(&event.content).unwrap();
    assert_eq!(content["system_type"], "member_added");
    assert_eq!(content["text"], "Member added");
    assert_eq!(content["data"]["member"], "alice");
    assert!(content.get("status").is_none());
}

#[test]
fn received_event_decodes_when_id_and_sender_match() {
    let event = build(AppMessageIntent::Chat {
        content: "hi".to_owned(),
    });
    let bytes = event.encode().unwrap();
    let group_id = GroupId::new(vec![0x01]);
    let message = groups::decode_received_event(
        &bytes,
        SENDER_HEX,
        None,
        &group_id,
        0,
        "msg1",
        1_700_000_000,
        false,
    )
    .expect("valid event is accepted");
    assert_eq!(message.plaintext, "hi");
    assert_eq!(message.kind, MARMOT_APP_EVENT_KIND_CHAT);
    assert_eq!(message.sender, SENDER_HEX);
    assert_eq!(message.recorded_at, 1_700_000_000);
}

#[test]
fn received_media_message_with_out_of_policy_locator_is_still_delivered() {
    // PR #328 review Finding 2 (core regression): a delayed media message
    // whose locator kind is no longer in the group's current policy MUST
    // still be delivered. Ingest is purely structural, so `decode_received_event`
    // keeps a structurally well-formed media reference regardless of locator
    // policy; fetchability is decided later at download time.
    let event = build(AppMessageIntent::Media {
        attachments: vec![MediaAttachmentReference {
            // A locator kind that is not the default `blossom-v1` and would be
            // out of a blossom-only policy.
            locators: vec![MediaLocator {
                kind: "ipfs-v1".to_owned(),
                value: "ipfs://bafybeigdyrexample".to_owned(),
            }],
            ciphertext_sha256: hex::encode([0x33_u8; 32]),
            plaintext_sha256: hex::encode([0x11_u8; 32]),
            nonce_hex: hex::encode([0x22_u8; 12]),
            file_name: "a.png".to_owned(),
            media_type: "image/png".to_owned(),
            version: ENCRYPTED_MEDIA_VERSION.to_owned(),
            source_epoch: 7,
            dim: None,
            thumbhash: None,
        }],
        caption: Some("delayed media".to_owned()),
    });
    let bytes = event.encode().unwrap();
    let group_id = GroupId::new(vec![0x01]);
    let message =
        groups::decode_received_event(&bytes, SENDER_HEX, None, &group_id, 7, "msg1", 0, false)
            .expect("an out-of-policy media locator must not drop the message");
    assert_eq!(message.plaintext, "delayed media");
    assert!(
        message
            .tags
            .iter()
            .any(|tag| tag.first().map(String::as_str) == Some("imeta")),
        "the imeta tag is preserved on the delivered message",
    );
}

#[test]
fn received_media_message_with_malformed_reference_is_rejected() {
    // PR #328 review Finding 2: structural malformation (here a bad
    // ciphertext hash) still drops the message, unlike out-of-policy locators.
    let mut event = build(AppMessageIntent::Media {
        attachments: vec![MediaAttachmentReference {
            locators: vec![MediaLocator {
                kind: "blossom-v1".to_owned(),
                value: "https://media.example/a.png".to_owned(),
            }],
            ciphertext_sha256: hex::encode([0x33_u8; 32]),
            plaintext_sha256: hex::encode([0x11_u8; 32]),
            nonce_hex: hex::encode([0x22_u8; 12]),
            file_name: "a.png".to_owned(),
            media_type: "image/png".to_owned(),
            version: ENCRYPTED_MEDIA_VERSION.to_owned(),
            source_epoch: 7,
            dim: None,
            thumbhash: None,
        }],
        caption: None,
    });
    // Corrupt the ciphertext hash in the serialized imeta tag, then recompute
    // the canonical id so the message passes id/sender checks and the only
    // remaining failure is the structural media-reference check.
    for tag in &mut event.tags {
        for field in tag.iter_mut() {
            if let Some(rest) = field.strip_prefix("ciphertext_sha256 ") {
                let _ = rest;
                *field = "ciphertext_sha256 not-a-valid-hash".to_owned();
            }
        }
    }
    event.id = cgka_traits::canonical_event_id(
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    );
    let bytes = event.encode().unwrap();
    let group_id = GroupId::new(vec![0x01]);
    assert!(
        groups::decode_received_event(&bytes, SENDER_HEX, None, &group_id, 7, "msg1", 0, false)
            .is_none(),
        "a structurally malformed media reference must drop the message",
    );
}

#[test]
fn received_event_with_tampered_id_is_rejected() {
    let mut event = build(AppMessageIntent::Chat {
        content: "hi".to_owned(),
    });
    // Mutate the content without recomputing the id: the canonical id no
    // longer matches, so the strict decoder must reject it.
    event.content = "tampered".to_owned();
    let bytes = serde_json::to_vec(&event).unwrap();
    let group_id = GroupId::new(vec![0x01]);
    assert!(
        groups::decode_received_event(&bytes, SENDER_HEX, None, &group_id, 0, "msg1", 0, false)
            .is_none()
    );
}

#[test]
fn received_event_with_wrong_sender_is_rejected() {
    let event = build(AppMessageIntent::Chat {
        content: "hi".to_owned(),
    });
    let bytes = event.encode().unwrap();
    let group_id = GroupId::new(vec![0x01]);
    let other_sender = "bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66bb66";
    // The inner pubkey is SENDER_HEX, but MLS authenticated `other_sender`.
    assert!(
        groups::decode_received_event(&bytes, other_sender, None, &group_id, 0, "msg1", 0, false)
            .is_none()
    );
}

#[test]
fn inner_event_id_matches_nostr_sdk_event_id() {
    use nostr::{EventId, Keys, Kind, Tag, Tags, Timestamp};

    let keys = Keys::generate();
    let pubkey = keys.public_key();
    let created_at = 1_700_000_123_u64;
    let kind = MARMOT_APP_EVENT_KIND_CHAT;
    let tags = vec![
        vec![EVENT_REF_TAG.to_owned(), "parent-id".to_owned()],
        vec![QUOTE_REF_TAG.to_owned(), "parent-id".to_owned()],
    ];
    let content = "hello from marmot 🦫";

    // Our canonical id over the unsigned-event preimage.
    let ours = cgka_traits::canonical_event_id(&pubkey.to_hex(), created_at, kind, &tags, content);

    // The nostr SDK's NIP-01 id for the same {pubkey, created_at, kind,
    // tags, content}. If these diverge, external Nostr clients would reject
    // our inner event id.
    let sdk_tags = Tags::from_list(
        tags.iter()
            .map(|tag| Tag::parse(tag.clone()).unwrap())
            .collect(),
    );
    let theirs = EventId::new(
        &pubkey,
        &Timestamp::from(created_at),
        &Kind::from(kind as u16),
        &sdk_tags,
        content,
    );

    assert_eq!(ours, theirs.to_hex());
}

#[test]
fn app_error_display_does_not_expose_group_or_account_ids() {
    let group_id = "aa".repeat(32);
    let account_id = "bb".repeat(32);
    let errors = [
        AppError::UnknownGroup(group_id.clone()).to_string(),
        AppError::MissingKeyPackage(account_id.clone()).to_string(),
        AppError::MissingDirectoryEntry(account_id.clone()).to_string(),
        AppError::AccountHome(AccountHomeError::SecretNotFound(account_id.clone())).to_string(),
    ];

    for error in errors {
        assert!(!error.contains(&group_id), "{error}");
        assert!(!error.contains(&account_id), "{error}");
    }
}

#[test]
fn telemetry_install_id_is_stable_uuid_per_app_root() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    let first = app.telemetry_install_id().unwrap();
    let second = app.telemetry_install_id().unwrap();
    let reopened = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .telemetry_install_id()
        .unwrap();

    assert_eq!(first, second);
    assert_eq!(first, reopened);
    assert_eq!(first.len(), 36);
    assert_eq!(first.as_bytes()[14], b'4');
    assert_eq!(first.chars().filter(|ch| *ch == '-').count(), 4);
    assert_ne!(first.len(), AUDIT_ID_BYTES * 2);
}

#[test]
fn relay_telemetry_settings_persist_in_shared_storage() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    assert_eq!(
        app.relay_telemetry_settings().unwrap(),
        RelayTelemetrySettings::default()
    );

    let updated = RelayTelemetrySettings {
        export_enabled: true,
        export_interval_seconds: 30,
    };
    let stored = app.set_relay_telemetry_settings(updated).unwrap();

    assert_eq!(
        stored,
        RelayTelemetrySettings {
            export_enabled: true,
            export_interval_seconds: 30,
        }
    );
    assert_eq!(
        app.relay_telemetry_export_config().unwrap(),
        RelayTelemetryExportConfig {
            enabled: true,
            endpoint: None,
            interval: Duration::from_secs(30),
            authorization_bearer_token: None,
            resource: None,
        }
    );

    let reopened = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    assert_eq!(reopened.relay_telemetry_settings().unwrap(), stored);
}

#[test]
fn relay_telemetry_settings_reject_zero_interval() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");

    let err = app
        .set_relay_telemetry_settings(RelayTelemetrySettings {
            export_interval_seconds: 0,
            ..Default::default()
        })
        .expect_err("zero interval should be rejected");

    assert!(matches!(err, AppError::InvalidRelayTelemetrySettings(_)));
}

#[test]
fn relay_telemetry_settings_reject_invalid_persisted_interval() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.shared_storage()
        .unwrap()
        .set_relay_telemetry_settings(&StoredRelayTelemetrySettings {
            export_enabled: true,
            export_interval_seconds: 0,
        })
        .unwrap();

    let err = app
        .relay_telemetry_settings()
        .expect_err("invalid persisted interval should be rejected");

    assert!(matches!(err, AppError::InvalidRelayTelemetrySettings(_)));
}

#[test]
fn secure_prune_account_app_events_before_returns_media_hashes_above_storage_layer() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    app.save_state(&AccountState {
        label: "alice".to_owned(),
        seen_events: Vec::new(),
        last_transport_timestamp: None,
        groups: vec![AppGroupRecord::new(
            "aa".to_owned(),
            AppGroupNostrRoutingComponent::new(
                NostrRoutingV1::new([0xAA; 32], vec!["wss://relay.example".to_owned()]).unwrap(),
            )
            .unwrap(),
            "alpha".to_owned(),
            String::new(),
            AppGroupImageInput::default(),
            AppGroupAdminPolicyComponent::new(Vec::new()),
            AppGroupMessageRetentionComponent::disabled(),
        )],
    })
    .unwrap();
    let media_hash = "ef".repeat(32);
    app.record_account_app_event(
        "alice",
        &AppMessageProjection {
            message_id_hex: "old-aa".to_owned(),
            source_message_id_hex: None,
            direction: "received".to_owned(),
            group_id_hex: "aa".to_owned(),
            sender: account.account_id_hex,
            plaintext: "expired plaintext".to_owned(),
            kind: MARMOT_APP_EVENT_KIND_CHAT,
            tags: vec![vec![
                "imeta".to_owned(),
                "v encrypted-media-v1".to_owned(),
                format!("ciphertext_sha256 {media_hash}"),
            ]],
            source_epoch: None,
            recorded_at: Some(10),
            origin_commit_id: None,
        },
    )
    .unwrap();
    assert!(
        app.chat_list_row("alice", "aa")
            .unwrap()
            .unwrap()
            .last_message
            .is_some()
    );

    let outcome = app
        .secure_prune_account_app_events_before("alice", "aa", 15)
        .unwrap();

    assert_eq!(outcome.pruned_messages, 1);
    assert_eq!(outcome.media_ciphertext_sha256, vec![media_hash]);
    assert!(
        app.chat_list_row("alice", "aa")
            .unwrap()
            .unwrap()
            .last_message
            .is_none()
    );
}
