use cgka_traits::TransportEndpoint;
use marmot_account::AccountHome;
use marmot_app::{
    AGENT_TEXT_STREAM_COMPONENT_ID, AccountRelayListBootstrap, MarmotApp, UserDirectorySearch,
    UserProfileMetadata,
};
use nostr_relay_builder::MockRelay;

async fn mock_relay() -> (MockRelay, String) {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    (relay, url)
}

async fn mock_app(dir: &tempfile::TempDir) -> (MockRelay, MarmotApp, String) {
    let (relay, url) = mock_relay().await;
    let app = MarmotApp::with_relay(dir.path(), url.clone());
    (relay, app, url)
}

fn endpoint(url: &str) -> TransportEndpoint {
    TransportEndpoint(url.to_owned())
}

#[tokio::test]
async fn relay_app_runtime_exchanges_messages_without_lab() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();

    let (_relay, app, _url) = mock_app(&dir).await;
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
async fn relay_app_runtime_creates_default_agent_text_stream_group() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();

    let (_relay, app, _url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("agent", &["bob"]).await.unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());

    let alice_group = app.group("alice", &group_id_hex).unwrap().unwrap();
    assert!(alice_group.agent_text_stream.required);
    assert_eq!(alice_group.agent_text_stream.component_id, 0x8006);
    assert_eq!(
        alice_group.agent_text_stream.component,
        "marmot.group.agent-text-stream.quic.v1"
    );
    assert_eq!(
        alice_group.agent_text_stream.required_member_roles,
        vec!["receive".to_owned()]
    );
    assert_eq!(
        alice_group.agent_text_stream.allowed_member_roles,
        vec!["receive".to_owned(), "send".to_owned()]
    );
    assert_eq!(
        alice_group.agent_text_stream.required_route_modes,
        vec!["brokered_quic".to_owned()]
    );
    assert_eq!(
        alice_group.agent_text_stream.allowed_route_modes,
        vec!["brokered_quic".to_owned()]
    );
    assert_eq!(
        alice_group.agent_text_stream.data_hex,
        "0103020200001000000000000000"
    );

    bob.sync().await.unwrap();
    let bob_group = app.group("bob", &group_id_hex).unwrap().unwrap();
    assert!(bob_group.agent_text_stream.required);

    alice.send(&group_id, b"write a summary").await.unwrap();
    let prompt = bob.sync().await.unwrap();
    assert_eq!(prompt.messages.len(), 1);
    assert_eq!(prompt.messages[0].sender, "alice");
    assert_eq!(prompt.messages[0].plaintext, "write a summary");

    let alice_secret = alice
        .safe_export_secret(&group_id, AGENT_TEXT_STREAM_COMPONENT_ID)
        .unwrap();
    let bob_secret = bob
        .safe_export_secret(&group_id, AGENT_TEXT_STREAM_COMPONENT_ID)
        .unwrap();
    let repeated_alice_secret = alice
        .safe_export_secret(&group_id, AGENT_TEXT_STREAM_COMPONENT_ID)
        .unwrap_err();

    assert_eq!(alice_secret, bob_secret);
    assert!(
        repeated_alice_secret.to_string().contains("PuncturedInput"),
        "{repeated_alice_secret}"
    );
}

#[tokio::test]
async fn relay_app_runtime_reopens_account_state() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();

    let (_relay, app, url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("restart", &["bob"]).await.unwrap();
    assert!(bob.sync().await.unwrap().joined_groups.contains(&group_id));
    drop(alice);
    drop(bob);

    let reopened = MarmotApp::with_relay(dir.path(), url);
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
async fn relay_app_publishes_account_relay_lists_for_setup() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let (_seed, app, seed_url) = mock_app(&dir).await;

    let status = app
        .publish_account_relay_lists(
            "alice",
            AccountRelayListBootstrap::new(
                vec![
                    TransportEndpoint("wss://relay1.example".into()),
                    TransportEndpoint("wss://relay2.example".into()),
                ],
                vec![endpoint(&seed_url)],
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
    assert_eq!(status.bootstrap_relays, vec![seed_url.clone()]);
    assert_eq!(status.nip65.kind, 10002);
    assert_eq!(status.inbox.kind, 10050);
    assert_eq!(status.key_package.kind, 10051);

    let account_id = home.account("alice").unwrap().account_id_hex;
    let fetched = app
        .fetch_account_relay_list_status_for_account_id(&account_id, vec![endpoint(&seed_url)])
        .await
        .unwrap();
    assert_eq!(fetched, status);
}

#[tokio::test]
async fn relay_list_fetch_only_uses_requested_bootstrap_relays() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let (seed_a, seed_a_url) = mock_relay().await;
    let (seed_b, seed_b_url) = mock_relay().await;
    let _relays = (seed_a, seed_b);
    let app = MarmotApp::with_relay(dir.path(), seed_a_url.clone());

    app.publish_account_relay_lists(
        "alice",
        AccountRelayListBootstrap::new(vec![endpoint(&seed_a_url)], vec![endpoint(&seed_a_url)]),
    )
    .await
    .unwrap();

    let account_id = home.account("alice").unwrap().account_id_hex;
    let missing_from_seed_b = app
        .fetch_account_relay_list_status_for_account_id(&account_id, vec![endpoint(&seed_b_url)])
        .await
        .unwrap();

    assert!(!missing_from_seed_b.complete);
    assert_eq!(
        missing_from_seed_b.missing,
        vec!["nip65", "inbox", "key_package"]
    );
    assert_eq!(missing_from_seed_b.bootstrap_relays, vec![seed_b_url]);
}

#[tokio::test]
async fn directory_cache_is_durable_app_state_not_json_user_files() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let (_seed, app, seed_url) = mock_app(&dir).await;
    let account_id = home.account("alice").unwrap().account_id_hex;

    app.publish_account_relay_lists(
        "alice",
        AccountRelayListBootstrap::new(vec![endpoint(&seed_url)], vec![endpoint(&seed_url)]),
    )
    .await
    .unwrap();

    let reopened = MarmotApp::with_relay(dir.path(), seed_url);
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
    let (_seed, app, seed_url) = mock_app(&dir).await;
    let bootstrap =
        AccountRelayListBootstrap::new(vec![endpoint(&seed_url)], vec![endpoint(&seed_url)]);

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
        .refresh_user_directory_for_account_id(&alice_id, vec![endpoint(&seed_url)])
        .await
        .unwrap();
    assert_eq!(alice_refresh.follow_count, 1);
    assert_eq!(alice_refresh.profile_count, 1);

    let bob_refresh = app
        .refresh_user_directory_for_account_id(&bob_id, vec![endpoint(&seed_url)])
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

    let (_relay, app, url) = mock_app(&dir).await;
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
    assert_eq!(alice_groups[0].admin_policy.component_id, 0x8003);
    assert_eq!(
        alice_groups[0].admin_policy.component,
        "marmot.group.admin-policy.v1"
    );
    assert_eq!(alice_groups[0].admin_policy.admins.len(), 1);
    bob.sync().await.unwrap();
    let bob_groups = app.groups("bob").unwrap();
    assert_eq!(bob_groups[0].profile.name, "messages");
    assert_eq!(bob_groups[0].admin_policy, alice_groups[0].admin_policy);

    alice
        .send(&group_id, b"persist this projection")
        .await
        .unwrap();
    let alice_messages = MarmotApp::with_relay(dir.path(), url.clone())
        .messages("alice")
        .unwrap();
    assert_eq!(alice_messages.len(), 1);
    assert_eq!(alice_messages[0].direction, "sent");
    assert_eq!(alice_messages[0].sender, "alice");
    assert_eq!(alice_messages[0].plaintext, "persist this projection");

    alice.sync().await.unwrap();
    let alice_messages = MarmotApp::with_relay(dir.path(), url.clone())
        .messages("alice")
        .unwrap();
    assert_eq!(alice_messages.len(), 1);

    bob.sync().await.unwrap();

    let messages = MarmotApp::with_relay(dir.path(), url)
        .messages("bob")
        .unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].direction, "received");
    assert_eq!(messages[0].sender, "alice");
    assert_eq!(messages[0].group_id_hex, hex::encode(group_id.as_slice()));
    assert_eq!(messages[0].plaintext, "persist this projection");
}
