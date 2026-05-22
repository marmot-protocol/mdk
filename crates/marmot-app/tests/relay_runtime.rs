use cgka_traits::TransportEndpoint;
use cgka_traits::{MarmotAppMessagePayloadV1, MarmotMediaReferenceV1, MarmotReactionActionV1};
use marmot_account::AccountHome;
use marmot_app::{
    AGENT_TEXT_STREAM_COMPONENT_ID, AccountRelayListBootstrap, AccountSetupRequest,
    AppMessageQuery, MarmotApp, MarmotAppEvent, MarmotAppRuntime, RuntimeMessageUpdate,
    UserDirectorySearch, UserProfileMetadata,
};
use nostr_relay_builder::MockRelay;
use tokio::time::{Duration, timeout};

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

fn assert_two_word_pseudonym(value: &str) {
    let words = value.split(' ').collect::<Vec<_>>();
    assert_eq!(words.len(), 2, "expected two words: {value}");
    for word in words {
        let mut chars = word.chars();
        assert!(
            chars.next().is_some_and(|ch| ch.is_ascii_uppercase()),
            "word should start uppercase: {word}"
        );
        assert!(
            chars.all(|ch| ch.is_ascii_lowercase()),
            "word should be title-cased ASCII: {word}"
        );
    }
}

#[tokio::test]
async fn app_runtime_create_identity_bootstraps_managed_account_and_key_package() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());

    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&url)],
            bootstrap_relays: vec![endpoint(&url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();

    assert!(created.account.local_signing);
    assert!(created.relay_lists.complete);
    assert!(created.key_package_bytes.is_some_and(|bytes| bytes > 0));
    let directory_entry = app
        .directory_entry_for_account_id(&created.account.account_id_hex)
        .unwrap()
        .expect("directory entry");
    let profile = directory_entry.profile.expect("created identity profile");
    let profile_name = profile.name.as_deref().expect("profile name");
    assert_eq!(profile.display_name.as_deref(), Some(profile_name));
    assert_two_word_pseudonym(profile_name);
    assert_eq!(
        runtime
            .accounts()
            .managed_accounts()
            .unwrap()
            .into_iter()
            .filter(|account| account.account_id_hex == created.account.account_id_hex)
            .count(),
        1
    );
    let relay_health = runtime.shared_services().relay_plane().relay_health().await;
    assert!(
        relay_health.directory_completed_fetches > 0,
        "identity setup should use the runtime shared relay plane for directory discovery"
    );

    let fetched = app
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();
    assert_eq!(
        fetched.key_package.0.len(),
        created.key_package_bytes.unwrap()
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_reuses_initial_key_package_when_republishing() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());

    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&url)],
            bootstrap_relays: vec![endpoint(&url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    let first = app
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();

    let republished_bytes = runtime
        .publish_key_package(&created.account.account_id_hex)
        .await
        .unwrap();
    let second = app
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();

    assert_eq!(republished_bytes, first.key_package.0.len());
    assert_eq!(second.key_package_id, first.key_package_id);
    assert_eq!(second.key_package, first.key_package);

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_can_rotate_key_package_on_request() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());

    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&url)],
            bootstrap_relays: vec![endpoint(&url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    let first = app
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();

    let rotated_bytes = runtime
        .rotate_key_package(&created.account.account_id_hex)
        .await
        .unwrap();
    let rotated = app
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();
    runtime
        .publish_key_package(&created.account.account_id_hex)
        .await
        .unwrap();
    let republished = app
        .fetch_latest_key_package_for_account_id(
            &created.account.account_id_hex,
            vec![endpoint(&url)],
        )
        .await
        .unwrap();

    assert_eq!(rotated_bytes, rotated.key_package.0.len());
    assert_ne!(rotated.key_package_id, first.key_package_id);
    assert_eq!(republished.key_package_id, rotated.key_package_id);
    assert_eq!(republished.key_package, rotated.key_package);

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_rotate_repairs_missing_key_package_relay_list() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("bob").unwrap();
    let (_relay, app, url) = mock_app(&dir).await;

    app.publish_account_relay_list_kind("bob", "nip65", vec![endpoint(&url)], vec![endpoint(&url)])
        .await
        .unwrap();
    let incomplete = app
        .publish_account_relay_list_kind("bob", "inbox", vec![endpoint(&url)], vec![endpoint(&url)])
        .await
        .unwrap();
    assert_eq!(incomplete.missing, vec!["key_package"]);

    let runtime = MarmotAppRuntime::new(app.clone());
    let bob = home.account("bob").unwrap().account_id_hex;
    let rotated_bytes = runtime.rotate_key_package("bob").await.unwrap();
    let repaired = app
        .fetch_account_relay_list_status_for_account_id(&bob, vec![endpoint(&url)])
        .await
        .unwrap();
    let fetched = app
        .fetch_latest_key_package_for_account_id(&bob, vec![endpoint(&url)])
        .await
        .unwrap();

    assert!(repaired.complete);
    assert_eq!(repaired.key_package.relays, vec![url]);
    assert_eq!(fetched.key_package.0.len(), rotated_bytes);

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_replaces_invalid_cached_key_package_when_republishing() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());

    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&url)],
            bootstrap_relays: vec![endpoint(&url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    let cache_path = dir
        .path()
        .join("key-packages")
        .join(format!("{}.json", created.account.label));
    std::fs::write(
        &cache_path,
        serde_json::json!({
            "account_label": created.account.label,
            "account_id_hex": created.account.account_id_hex,
            "key_package_id": "legacy-invalid",
            "key_package_hex": "010203",
        })
        .to_string(),
    )
    .unwrap();

    let republished_bytes = runtime
        .publish_key_package(&created.account.account_id_hex)
        .await
        .unwrap();
    let cache: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();

    assert!(republished_bytes > 3);
    assert_ne!(cache["key_package_id"], "legacy-invalid");
    assert_ne!(cache["key_package_hex"], "010203");

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_executes_group_and_message_intents_on_managed_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup.clone()).await.unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let bob_id = bob.account.account_id_hex.clone();
    let mut events = runtime.subscribe();

    let group_id = runtime
        .create_group(
            &alice.account.account_id_hex,
            "runtime intents",
            std::slice::from_ref(&bob.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined_group, .. }
                if account_id_hex == &bob_id && joined_group == &group_id
        )
    })
    .await;

    runtime
        .send_message(
            &alice.account.account_id_hex,
            &group_id,
            b"hello through runtime intents".to_vec(),
        )
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::MessageReceived(message)
                if message.account_id_hex == bob_id
                    && message.message.group_id == group_id
                    && message.message.plaintext == "hello through runtime intents"
        )
    })
    .await;

    let stream_id = [0x44; 32];
    runtime
        .start_agent_text_stream(
            &alice.account.account_id_hex,
            &group_id,
            &stream_id,
            123,
            vec!["quic://127.0.0.1:4450".to_owned()],
        )
        .await
        .unwrap();
    let stream_event = wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::AgentStreamStarted(stream)
                if stream.account_id_hex == bob_id
                    && stream.message.group_id == group_id
                    && stream.payload.kind() == "start"
                    && stream.payload.stream_id() == hex::encode(stream_id)
        )
    })
    .await;
    assert!(matches!(
        stream_event,
        MarmotAppEvent::AgentStreamStarted(_)
    ));

    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_emits_live_messages_for_local_accounts_without_manual_sync() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    let bob_id = home.account("bob").unwrap().account_id_hex;

    let (_relay, app, _url) = mock_app(&dir).await;
    let mut bob_setup = app.client("bob").await.unwrap();
    bob_setup.publish_key_package().await.unwrap();
    drop(bob_setup);

    let runtime = MarmotAppRuntime::new(app.clone());
    let mut events = runtime.subscribe();
    runtime.start().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("live", &["bob"]).await.unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined_group, .. }
                if account_id_hex == &bob_id && joined_group == &group_id
        )
    })
    .await;

    alice
        .send(&group_id, b"hello through the app runtime")
        .await
        .unwrap();
    let received = wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::MessageReceived(message)
                if message.account_id_hex == bob_id
                    && message.message.group_id == group_id
                    && message.message.plaintext == "hello through the app runtime"
        )
    })
    .await;

    assert!(matches!(received, MarmotAppEvent::MessageReceived(_)));
    runtime.shutdown().await;
}

#[tokio::test]
async fn app_runtime_message_subscription_returns_snapshot_then_live_updates() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup.clone()).await.unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();
    let bob_id = bob.account.account_id_hex.clone();
    let mut events = runtime.subscribe();

    let group_id = runtime
        .create_group(
            &alice.account.account_id_hex,
            "message subscriptions",
            std::slice::from_ref(&bob.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    wait_for_event(&mut events, |event| {
        matches!(
            event,
            MarmotAppEvent::GroupJoined { account_id_hex, group_id: joined_group, .. }
                if account_id_hex == &bob_id && joined_group == &group_id
        )
    })
    .await;

    runtime
        .send_message(
            &alice.account.account_id_hex,
            &group_id,
            b"already projected".to_vec(),
        )
        .await
        .unwrap();

    let group_id_hex = hex::encode(group_id.as_slice());
    let mut subscription = runtime
        .subscribe_messages(
            &bob.account.account_id_hex,
            AppMessageQuery {
                group_id_hex: Some(group_id_hex),
                limit: Some(10),
            },
        )
        .unwrap();
    assert_eq!(subscription.snapshot.len(), 1);
    assert_eq!(subscription.snapshot[0].plaintext, "already projected");

    runtime
        .send_message(
            &alice.account.account_id_hex,
            &group_id,
            b"live through runtime subscription".to_vec(),
        )
        .await
        .unwrap();
    let update = wait_for_message_update(&mut subscription, |update| {
        matches!(
            update,
            RuntimeMessageUpdate::Message(message)
                if message.account_id_hex == bob_id
                    && message.message.group_id == group_id
                    && message.message.plaintext == "live through runtime subscription"
        )
    })
    .await;
    assert!(matches!(update, RuntimeMessageUpdate::Message(_)));

    runtime.shutdown().await;
}

async fn wait_for_event<F>(
    events: &mut tokio::sync::broadcast::Receiver<MarmotAppEvent>,
    mut matches_event: F,
) -> MarmotAppEvent
where
    F: FnMut(&MarmotAppEvent) -> bool,
{
    timeout(Duration::from_secs(5), async {
        loop {
            let event = events.recv().await.unwrap();
            if matches_event(&event) {
                return event;
            }
        }
    })
    .await
    .expect("runtime event")
}

async fn wait_for_message_update<F>(
    subscription: &mut marmot_app::RuntimeMessagesSubscription,
    mut matches_update: F,
) -> RuntimeMessageUpdate
where
    F: FnMut(&RuntimeMessageUpdate) -> bool,
{
    timeout(Duration::from_secs(5), async {
        loop {
            let update = subscription.recv().await.expect("message update");
            if matches_update(&update) {
                return update;
            }
        }
    })
    .await
    .expect("runtime message update")
}

#[tokio::test]
async fn app_runtime_chat_and_group_state_subscriptions_stream_projection_updates() {
    let dir = tempfile::tempdir().unwrap();
    let (_relay, app, url) = mock_app(&dir).await;
    let runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![endpoint(&url)],
        bootstrap_relays: vec![endpoint(&url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let alice = runtime.create_identity(setup.clone()).await.unwrap();
    let bob = runtime.create_identity(setup).await.unwrap();

    let mut bob_chats = runtime
        .subscribe_chats(&bob.account.account_id_hex, false)
        .unwrap();
    assert!(bob_chats.snapshot.is_empty());

    let group_id = runtime
        .create_group(
            &alice.account.account_id_hex,
            "runtime chats",
            std::slice::from_ref(&bob.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    let chat = wait_for_chat_update(&mut bob_chats, |chat| chat.group_id_hex == group_id_hex).await;
    assert_eq!(chat.profile.name, "runtime chats");

    let mut group_state = runtime
        .subscribe_group_state(&bob.account.account_id_hex, &group_id_hex)
        .unwrap();
    assert_eq!(group_state.snapshot.group_id_hex, group_id_hex);

    runtime
        .update_group_profile(
            &alice.account.account_id_hex,
            &group_id,
            Some("renamed runtime chat".to_owned()),
            None,
        )
        .await
        .unwrap();
    let updated = wait_for_group_state_update(&mut group_state, |group| {
        group.profile.name == "renamed runtime chat"
    })
    .await;
    assert_eq!(updated.group_id_hex, group_id_hex);

    runtime.shutdown().await;
}

async fn wait_for_chat_update<F>(
    subscription: &mut marmot_app::RuntimeChatsSubscription,
    mut matches_update: F,
) -> marmot_app::AppGroupRecord
where
    F: FnMut(&marmot_app::AppGroupRecord) -> bool,
{
    timeout(Duration::from_secs(5), async {
        loop {
            let update = subscription.recv().await.expect("chat update");
            if matches_update(&update) {
                return update;
            }
        }
    })
    .await
    .expect("runtime chat update")
}

async fn wait_for_group_state_update<F>(
    subscription: &mut marmot_app::RuntimeGroupStateSubscription,
    mut matches_update: F,
) -> marmot_app::AppGroupRecord
where
    F: FnMut(&marmot_app::AppGroupRecord) -> bool,
{
    timeout(Duration::from_secs(5), async {
        loop {
            let update = subscription.recv().await.expect("group state update");
            if matches_update(&update) {
                return update;
            }
        }
    })
    .await
    .expect("runtime group state update")
}

#[tokio::test]
async fn relay_app_runtime_exchanges_messages_without_lab() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    let alice_id = home.account("alice").unwrap().account_id_hex;

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
    assert_eq!(received.messages[0].sender, alice_id);
    assert_eq!(
        received.messages[0].sender_display_name.as_deref(),
        Some("alice")
    );
    assert_eq!(received.messages[0].group_id, group_id);
    assert_eq!(received.messages[0].plaintext, "hello from app runtime");
}

#[tokio::test]
async fn relay_app_runtime_publishes_member_leave() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();

    let (_relay, app, _url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("departures", &["bob"]).await.unwrap();
    bob.sync().await.unwrap();

    let leave = bob.leave_group(&group_id).await.unwrap();
    assert_eq!(leave.published, 1);

    let alice_sync = alice.sync().await.unwrap();
    assert!(alice_sync.events.iter().any(|event| matches!(
        event,
        cgka_traits::GroupEvent::MemberRemoved { group_id: removed_group, .. }
            if removed_group == &group_id
    )));
}

#[tokio::test]
async fn relay_app_runtime_projects_typed_reactions_and_deletes() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();

    let (_relay, app, _url) = mock_app(&dir).await;
    let mut bob = app.client("bob").await.unwrap();
    bob.publish_key_package().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group_id = alice.create_group("updates", &["bob"]).await.unwrap();
    bob.sync().await.unwrap();

    let sent = alice
        .send(&group_id, b"message with lifecycle")
        .await
        .unwrap();
    let target_message_id = sent.message_ids[0].clone();
    bob.sync().await.unwrap();

    bob.react_to_message(&group_id, &target_message_id, "+")
        .await
        .unwrap();
    let reaction = alice.sync().await.unwrap();
    assert_eq!(reaction.messages.len(), 1);
    assert_eq!(
        reaction.messages[0].plaintext,
        format!("reacted + to {target_message_id}")
    );
    assert_eq!(
        reaction.messages[0].app_message,
        Some(MarmotAppMessagePayloadV1::Reaction {
            target_message_id: target_message_id.clone(),
            emoji: "+".to_owned(),
            action: MarmotReactionActionV1::Add,
        })
    );

    let empty_reaction = bob
        .react_to_message(&group_id, &target_message_id, "")
        .await
        .unwrap_err();
    assert!(empty_reaction.to_string().contains("non-empty emoji"));

    bob.delete_message(&group_id, &target_message_id)
        .await
        .unwrap();
    let deletion = alice.sync().await.unwrap();
    assert_eq!(
        deletion.messages[0].plaintext,
        format!("deleted {target_message_id}")
    );
    assert_eq!(
        deletion.messages[0].app_message,
        Some(MarmotAppMessagePayloadV1::Delete { target_message_id })
    );

    bob.send_media_reference(
        &group_id,
        MarmotMediaReferenceV1 {
            file_hash_hex: hex::encode([0x42_u8; 32]),
            file_name: "diagram.png".to_owned(),
            media_type: "image/png".to_owned(),
            size_bytes: 1234,
        },
        Some("launch diagram".to_owned()),
    )
    .await
    .unwrap();
    let media = alice.sync().await.unwrap();
    assert_eq!(
        media.messages[0].plaintext,
        "media diagram.png: launch diagram"
    );
    assert!(matches!(
        media.messages[0].app_message,
        Some(MarmotAppMessagePayloadV1::Media { .. })
    ));

    let bad_media = bob
        .send_media_reference(
            &group_id,
            MarmotMediaReferenceV1 {
                file_hash_hex: "not-hex".to_owned(),
                file_name: "diagram.png".to_owned(),
                media_type: "image/png".to_owned(),
                size_bytes: 1234,
            },
            None,
        )
        .await
        .unwrap_err();
    assert!(bad_media.to_string().contains("media hash"));
}

#[tokio::test]
async fn relay_app_runtime_creates_default_agent_text_stream_group() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    let alice_id = home.account("alice").unwrap().account_id_hex;

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
    assert_eq!(prompt.messages[0].sender, alice_id);
    assert_eq!(
        prompt.messages[0].sender_display_name.as_deref(),
        Some("alice")
    );
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
            lud16: None,
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
            lud16: None,
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
    let alice_id = home.account("alice").unwrap().account_id_hex;

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
    assert_eq!(alice_messages[0].sender, alice_id);
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
    assert_eq!(messages[0].sender, alice_id);
    assert_eq!(messages[0].group_id_hex, hex::encode(group_id.as_slice()));
    assert_eq!(messages[0].plaintext, "persist this projection");
}

#[tokio::test]
async fn account_publishes_route_to_own_nip65_not_bootstrap() {
    let dir = tempfile::tempdir().unwrap();
    let (_home, home_url) = mock_relay().await;
    let (_other, other_url) = mock_relay().await;
    let app = MarmotApp::with_relay(dir.path(), home_url.clone());
    let runtime = MarmotAppRuntime::new(app.clone());

    // The account's NIP-65 write relay is the home relay.
    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(&home_url)],
            bootstrap_relays: vec![endpoint(&home_url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    let id = created.account.account_id_hex.clone();
    let label = created.account.label.clone();

    let status = app.account_relay_list_status_for_account_id(&id).unwrap();
    assert!(
        status.nip65.relays.iter().any(|r| r == &home_url),
        "nip65 should include the home relay, got {:?}",
        status.nip65.relays
    );

    // Publish a distinct profile, passing the OTHER relay as bootstrap.
    // Outbox routing must send it to the account's NIP-65 (home), not other.
    app.publish_user_profile(
        &label,
        UserProfileMetadata {
            name: Some("OutboxTest".to_owned()),
            ..UserProfileMetadata::default()
        },
        AccountRelayListBootstrap::new(vec![endpoint(&other_url)], vec![endpoint(&other_url)]),
    )
    .await
    .unwrap();

    // The bootstrap relay must NOT have the profile (outbox ignored it).
    app.refresh_profile_for_account_id(&id, vec![endpoint(&other_url)])
        .await
        .unwrap();
    let from_other = app
        .directory_entry_for_account_id(&id)
        .unwrap()
        .and_then(|entry| entry.profile)
        .and_then(|profile| profile.name);
    assert_ne!(
        from_other.as_deref(),
        Some("OutboxTest"),
        "profile must not be on the bootstrap relay; outbox should target nip65"
    );

    // The account's NIP-65 (home) relay SHOULD have it.
    app.refresh_profile_for_account_id(&id, vec![endpoint(&home_url)])
        .await
        .unwrap();
    let from_home = app
        .directory_entry_for_account_id(&id)
        .unwrap()
        .and_then(|entry| entry.profile)
        .and_then(|profile| profile.name);
    assert_eq!(
        from_home.as_deref(),
        Some("OutboxTest"),
        "profile should be retrievable from the account's nip65 (home) relay"
    );
}
