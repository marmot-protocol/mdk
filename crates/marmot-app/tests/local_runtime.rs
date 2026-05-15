use cgka_traits::TransportEndpoint;
use marmot_account::AccountHome;
use marmot_app::{AccountRelayListBootstrap, MarmotApp, UserDirectorySearch, UserProfileMetadata};

#[tokio::test]
async fn local_app_runtime_exchanges_messages_without_lab() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();

    let app = MarmotApp::local(dir.path());
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("general", &["bob"]).await.unwrap();

    let joined = bob.sync().await.unwrap();
    assert_eq!(joined.joined_groups, vec![group_id.clone()]);

    alice
        .send(&group_id, b"hello from app runtime")
        .await
        .unwrap();

    let received = bob.sync().await.unwrap();
    assert_eq!(received.messages.len(), 1);
    assert_eq!(received.messages[0].sender, "alice");
    assert_eq!(received.messages[0].group_id, group_id);
    assert_eq!(received.messages[0].plaintext, "hello from app runtime");
}

#[tokio::test]
async fn local_app_runtime_reopens_account_state() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();

    let app = MarmotApp::local(dir.path());
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("restart", &["bob"]).await.unwrap();
    assert!(bob.sync().await.unwrap().joined_groups.contains(&group_id));
    drop(alice);
    drop(bob);

    let reopened = MarmotApp::local(dir.path());
    let status = reopened.status("bob").unwrap();
    assert_eq!(status.account, "bob");
    assert_eq!(
        status.groups[0].group_id_hex,
        hex::encode(group_id.as_slice())
    );
    let projection_path = dir.path().join("accounts/bob/app.sqlite3");
    assert!(projection_path.exists());
    let plain_open_result = rusqlite::Connection::open(&projection_path).and_then(|conn| {
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
    });
    assert!(plain_open_result.is_err());
    assert!(!dir.path().join("accounts/bob/app-state.json").exists());
}

#[tokio::test]
async fn local_app_publishes_account_relay_lists_for_setup() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let app = MarmotApp::local(dir.path());

    let status = app
        .publish_account_relay_lists(
            "alice",
            AccountRelayListBootstrap::new(
                vec![
                    TransportEndpoint("wss://relay1.example".into()),
                    TransportEndpoint("wss://relay2.example".into()),
                ],
                vec![TransportEndpoint("marmot-local://seed".into())],
            ),
        )
        .await
        .unwrap();

    assert!(status.complete);
    assert_eq!(
        status.default_relays,
        vec![
            "wss://relay1.example".to_owned(),
            "wss://relay2.example".to_owned()
        ]
    );
    assert_eq!(status.bootstrap_relays, vec!["marmot-local://seed"]);
    assert_eq!(status.nip65.kind, 10002);
    assert_eq!(status.inbox.kind, 10050);
    assert_eq!(status.key_package.kind, 10051);

    let account_id = home.account("alice").unwrap().account_id_hex;
    let fetched = app
        .fetch_account_relay_list_status_for_account_id(
            &account_id,
            vec![TransportEndpoint("marmot-local://seed".into())],
        )
        .await
        .unwrap();
    assert_eq!(fetched, status);
}

#[tokio::test]
async fn local_relay_list_fetch_only_uses_requested_bootstrap_relays() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let app = MarmotApp::local(dir.path());

    app.publish_account_relay_lists(
        "alice",
        AccountRelayListBootstrap::new(
            vec![TransportEndpoint("marmot-local://key-packages".into())],
            vec![TransportEndpoint("marmot-local://seed-a".into())],
        ),
    )
    .await
    .unwrap();

    let account_id = home.account("alice").unwrap().account_id_hex;
    let missing_from_seed_b = app
        .fetch_account_relay_list_status_for_account_id(
            &account_id,
            vec![TransportEndpoint("marmot-local://seed-b".into())],
        )
        .await
        .unwrap();

    assert!(!missing_from_seed_b.complete);
    assert_eq!(
        missing_from_seed_b.missing,
        vec!["nip65", "inbox", "key_package"]
    );
    assert_eq!(
        missing_from_seed_b.bootstrap_relays,
        vec!["marmot-local://seed-b"]
    );
}

#[tokio::test]
async fn directory_cache_is_durable_app_state_not_json_user_files() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let app = MarmotApp::local(dir.path());
    let account_id = home.account("alice").unwrap().account_id_hex;

    app.publish_account_relay_lists(
        "alice",
        AccountRelayListBootstrap::new(
            vec![TransportEndpoint("marmot-local://key-packages".into())],
            vec![TransportEndpoint("marmot-local://seed".into())],
        ),
    )
    .await
    .unwrap();

    let reopened = MarmotApp::local(dir.path());
    let cached = reopened
        .directory_entry_for_account_id(&account_id)
        .unwrap()
        .expect("directory entry");

    assert_eq!(cached.account_id_hex, account_id);
    assert!(cached.relay_lists.complete);
    assert!(dir.path().join("app-cache.sqlite3").exists());
    assert!(!dir.path().join("directory/users").exists());
}

#[tokio::test]
async fn user_directory_refresh_precaches_follows_profiles_and_searches_by_radius() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    home.create_account("carol").unwrap();
    let alice_id = home.account("alice").unwrap().account_id_hex;
    let bob_id = home.account("bob").unwrap().account_id_hex;
    let carol_id = home.account("carol").unwrap().account_id_hex;
    let app = MarmotApp::local(dir.path());
    let bootstrap = AccountRelayListBootstrap::new(
        vec![TransportEndpoint("marmot-local://social".into())],
        vec![TransportEndpoint("marmot-local://seed".into())],
    );

    app.publish_user_profile(
        "bob",
        UserProfileMetadata {
            name: Some("bob".into()),
            display_name: Some("Bob Builder".into()),
            about: Some("Can we fix it".into()),
            picture: None,
            nip05: Some("bob@example.test".into()),
            created_at: 0,
            source_relays: Vec::new(),
        },
        bootstrap.clone(),
    )
    .await
    .unwrap();
    app.publish_user_profile(
        "carol",
        UserProfileMetadata {
            name: Some("carol".into()),
            display_name: Some("Carol Singer".into()),
            about: None,
            picture: None,
            nip05: None,
            created_at: 0,
            source_relays: Vec::new(),
        },
        bootstrap.clone(),
    )
    .await
    .unwrap();
    app.publish_account_follow_list("alice", &[&bob_id], bootstrap.clone())
        .await
        .unwrap();
    app.publish_account_follow_list("bob", &[&carol_id], bootstrap.clone())
        .await
        .unwrap();

    let alice_refresh = app
        .refresh_user_directory_for_account_id(
            &alice_id,
            vec![TransportEndpoint("marmot-local://seed".into())],
        )
        .await
        .unwrap();
    assert_eq!(alice_refresh.follow_count, 1);
    assert_eq!(alice_refresh.profile_count, 1);

    let bob_refresh = app
        .refresh_user_directory_for_account_id(
            &bob_id,
            vec![TransportEndpoint("marmot-local://seed".into())],
        )
        .await
        .unwrap();
    assert_eq!(bob_refresh.follow_count, 1);
    assert_eq!(bob_refresh.profile_count, 1);

    let alice_record = app
        .directory_entry_for_account_id(&alice_id)
        .unwrap()
        .expect("alice directory record");
    assert_eq!(alice_record.account_id_hex, alice_id);
    assert!(alice_record.npub.starts_with("npub1"));
    assert_eq!(alice_record.local_account.as_ref().unwrap().label, "alice");
    assert_eq!(alice_record.follows, vec![bob_id.clone()]);

    let bob_record = app
        .directory_entry_for_account_id(&bob_id)
        .unwrap()
        .expect("bob directory record");
    assert_eq!(
        bob_record.profile.as_ref().unwrap().display_name.as_deref(),
        Some("Bob Builder")
    );

    let bob_results = app
        .search_user_directory(UserDirectorySearch {
            searcher_account_id_hex: alice_id.clone(),
            query: "builder".into(),
            radius_start: 0,
            radius_end: 1,
            limit: None,
        })
        .unwrap();
    assert_eq!(bob_results[0].account_id_hex, bob_id);
    assert_eq!(bob_results[0].radius, 1);

    let carol_too_close = app
        .search_user_directory(UserDirectorySearch {
            searcher_account_id_hex: alice_id.clone(),
            query: "carol".into(),
            radius_start: 0,
            radius_end: 1,
            limit: None,
        })
        .unwrap();
    assert!(carol_too_close.is_empty());

    let carol_results = app
        .search_user_directory(UserDirectorySearch {
            searcher_account_id_hex: alice_id,
            query: "carol".into(),
            radius_start: 0,
            radius_end: 2,
            limit: None,
        })
        .unwrap();
    assert_eq!(carol_results[0].account_id_hex, carol_id);
    assert_eq!(carol_results[0].radius, 2);
}

#[tokio::test]
async fn account_projection_db_records_received_messages() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();

    let app = MarmotApp::local(dir.path());
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("messages", &["bob"]).await.unwrap();
    let alice_groups = app.groups("alice").unwrap();
    assert_eq!(alice_groups[0].profile.component_id, 0x8001);
    assert_eq!(alice_groups[0].profile.component, "marmot.group.profile.v1");
    assert_eq!(alice_groups[0].profile.name, "messages");
    assert_eq!(alice_groups[0].image.component_id, 0x8002);
    assert_eq!(
        alice_groups[0].image.component,
        "marmot.group.blossom.image.v1"
    );
    assert!(!alice_groups[0].image.present);
    bob.sync().await.unwrap();
    let bob_groups = app.groups("bob").unwrap();
    assert_eq!(bob_groups[0].profile.name, "messages");

    alice
        .send(&group_id, b"persist this projection")
        .await
        .unwrap();
    let alice_messages = MarmotApp::local(dir.path()).messages("alice").unwrap();
    assert_eq!(alice_messages.len(), 1);
    assert_eq!(alice_messages[0].direction, "sent");
    assert_eq!(alice_messages[0].sender, "alice");
    assert_eq!(alice_messages[0].plaintext, "persist this projection");

    alice.sync().await.unwrap();
    let alice_messages = MarmotApp::local(dir.path()).messages("alice").unwrap();
    assert_eq!(alice_messages.len(), 1);

    bob.sync().await.unwrap();

    let messages = MarmotApp::local(dir.path()).messages("bob").unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].direction, "received");
    assert_eq!(messages[0].sender, "alice");
    assert_eq!(messages[0].group_id_hex, hex::encode(group_id.as_slice()));
    assert_eq!(messages[0].plaintext, "persist this projection");
}
