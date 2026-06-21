//! White-box tests for the connector exercising private/`pub(crate)` internals across modules.

use agent_control::{
    AGENT_CONTROL_STREAM_STATUS_STARTED, AgentControlEnvelope, AgentControlEvent,
    AgentControlRequest, AgentControlResponse, read_envelope, write_frame,
};
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_RECORD_STATUS, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
    AgentTextStreamTranscriptV1,
};
use cgka_traits::app_event::{
    MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY, MARMOT_APP_EVENT_KIND_AGENT_OPERATION,
    MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, MARMOT_APP_EVENT_KIND_CHAT,
    MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_EDIT, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
    MARMOT_APP_EVENT_KIND_REACTION, STREAM_TAG,
};
use cgka_traits::engine::{GroupEvent, GroupStateChange};
use cgka_traits::{EpochId, GroupId, MessageId};
use marmot_account::AccountHome;
use marmot_app::{
    AccountSetupRequest, MarmotApp, MarmotAppEvent, MarmotAppRuntime, ReceivedMessage,
    RuntimeAgentStreamMessage, RuntimeMessageReceived,
};
use nostr_relay_builder::MockRelay;
use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::Ordering;
use tokio::io::BufReader;
use tokio::net::UnixStream;
use tokio::time::{Duration, sleep, timeout};

use crate::allowlist::{AllowlistRecord, AllowlistStore};
use crate::event_projection::{
    DeliveredInboundCursor, InboundCatchUpDriver, control_event_from_debug_event,
    control_event_from_runtime_event, inbound_message_event_from_record, resync_required_event,
    runtime_replay_dedup_key,
};
use crate::{
    AgentConnector, AgentConnectorConfig, bind_connector_socket, bind_connector_socket_with_mode,
    serve_socket,
};
use marmot_app::AppMessageRecord;

const CONTROL_RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);

fn test_config(
    home: &Path,
    socket: impl Into<std::path::PathBuf>,
    relays: Vec<String>,
    allow_any: bool,
    debug_controls: bool,
) -> AgentConnectorConfig {
    let mut config = AgentConnectorConfig::new(home);
    config.socket = socket.into();
    config.relays = relays;
    config.allow_any = allow_any;
    config.debug_controls = debug_controls;
    config
}

fn received_message(
    kind: u64,
    plaintext: impl Into<String>,
    tags: Vec<Vec<String>>,
) -> ReceivedMessage {
    ReceivedMessage {
        message_id_hex: "33".repeat(32),
        source_message_id_hex: "44".repeat(32),
        sender: "bb".repeat(32),
        sender_display_name: None,
        group_id: cgka_traits::GroupId::new(vec![0x22; 32]),
        source_epoch: 7,
        plaintext: plaintext.into(),
        kind,
        tags,
        recorded_at: 42,
    }
}

#[test]
fn control_event_forwards_only_chat_inner_events_as_inbound_messages() {
    let agent_account_id_hex = "aa".repeat(32);
    let non_conversational = [
        (MARMOT_APP_EVENT_KIND_DELETE, ""),
        (MARMOT_APP_EVENT_KIND_REACTION, "+"),
        (MARMOT_APP_EVENT_KIND_EDIT, "edited text"),
        (MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY, "thinking"),
        (MARMOT_APP_EVENT_KIND_AGENT_OPERATION, "tool running"),
        (MARMOT_APP_EVENT_KIND_GROUP_SYSTEM, "member added"),
    ];

    for (kind, plaintext) in non_conversational {
        let event = MarmotAppEvent::MessageReceived(RuntimeMessageReceived {
            account_id_hex: agent_account_id_hex.clone(),
            account_label: "agent".to_owned(),
            message: received_message(kind, plaintext, Vec::new()),
        });

        assert_eq!(
            control_event_from_runtime_event(event, None, None),
            None,
            "kind {kind} must not be forwarded to Hermes as a prompt"
        );
    }

    let event = MarmotAppEvent::MessageReceived(RuntimeMessageReceived {
        account_id_hex: agent_account_id_hex,
        account_label: "agent".to_owned(),
        message: received_message(
            MARMOT_APP_EVENT_KIND_CHAT,
            "hello agent",
            vec![vec![
                "imeta".to_owned(),
                "url https://example.invalid/a.png".to_owned(),
            ]],
        ),
    });

    let Some(AgentControlEvent::InboundMessage { text, .. }) =
        control_event_from_runtime_event(event, None, None)
    else {
        panic!("expected kind-9 chat event to become an inbound message");
    };
    assert_eq!(text, "hello agent");
}

#[test]
fn control_event_projects_kind5_deletion_as_message_deleted() {
    let agent_account_id_hex = "aa".repeat(32);
    let target = "99".repeat(32);
    let event = MarmotAppEvent::MessageReceived(RuntimeMessageReceived {
        account_id_hex: agent_account_id_hex.clone(),
        account_label: "agent".to_owned(),
        message: received_message(
            MARMOT_APP_EVENT_KIND_DELETE,
            "",
            vec![vec!["e".to_owned(), target.clone()]],
        ),
    });

    let Some(AgentControlEvent::MessageDeleted {
        account_id_hex,
        target_message_id_hex,
        sender_account_id_hex,
        ..
    }) = control_event_from_runtime_event(event, None, None)
    else {
        panic!("expected kind-5 deletion to become MessageDeleted");
    };
    assert_eq!(account_id_hex, agent_account_id_hex);
    assert_eq!(target_message_id_hex, target);
    assert_eq!(sender_account_id_hex, "bb".repeat(32));
}

#[test]
fn control_event_projects_group_rename_as_group_state_changed() {
    // A GroupRenamed change projects to a coarse `group_renamed` control event
    // carrying the new group display name in `detail`. Privacy: member/admin
    // changes carry NO detail (the subject member's pubkey is never surfaced).
    let agent_account_id_hex = "aa".repeat(32);
    let event = MarmotAppEvent::GroupEvent(marmot_app::RuntimeGroupEvent {
        account_id_hex: agent_account_id_hex.clone(),
        account_label: "agent".to_owned(),
        event: GroupEvent::GroupStateChanged {
            group_id: GroupId::new(vec![0x22; 32]),
            epoch: EpochId(3),
            actor: None,
            change: GroupStateChange::GroupRenamed {
                name: "Team".to_owned(),
            },
            origin_commit_id: None,
        },
    });

    let Some(AgentControlEvent::GroupStateChanged {
        account_id_hex,
        group_id_hex,
        change,
        detail,
    }) = control_event_from_runtime_event(event, None, None)
    else {
        panic!("expected a group state change to project to GroupStateChanged");
    };
    assert_eq!(account_id_hex, agent_account_id_hex);
    assert_eq!(group_id_hex, "22".repeat(32));
    assert_eq!(change, "group_renamed");
    assert_eq!(detail, Some("Team".to_owned()));
}

#[test]
fn control_event_group_state_change_member_add_carries_no_member_detail() {
    // A member add must NOT surface the subject member's pubkey: the projection
    // collapses to a coarse change kind with `detail == None`.
    let agent_account_id_hex = "aa".repeat(32);
    let member = cgka_traits::MemberId::new(vec![0x99; 32]);
    let event = MarmotAppEvent::GroupEvent(marmot_app::RuntimeGroupEvent {
        account_id_hex: agent_account_id_hex,
        account_label: "agent".to_owned(),
        event: GroupEvent::GroupStateChanged {
            group_id: GroupId::new(vec![0x22; 32]),
            epoch: EpochId(4),
            actor: None,
            change: GroupStateChange::MemberAdded { member },
            origin_commit_id: None,
        },
    });

    let Some(AgentControlEvent::GroupStateChanged { change, detail, .. }) =
        control_event_from_runtime_event(event, None, None)
    else {
        panic!("expected a member add to project to GroupStateChanged");
    };
    assert_eq!(change, "member_added");
    assert_eq!(detail, None, "member pubkey must never be surfaced");
}

#[test]
fn control_event_projects_imeta_tag_into_inbound_media_ref() {
    // A kind-9 chat carrying a structurally valid `imeta` tag must project a
    // single media reference onto the InboundMessage (the non-secret mirror: no
    // content key, just fetch + authentication metadata for download_media).
    let agent_account_id_hex = "aa".repeat(32);
    // A blossom-v1 locator URL MUST carry the ciphertext hash so the fetched blob
    // matches the reference; the parser enforces this binding.
    let ciphertext_sha256 = "cd".repeat(32);
    let plaintext_sha256 = "ab".repeat(32);
    let nonce_hex = "0".repeat(24); // 12 bytes
    let locator_url = format!("https://blossom.example.com/{ciphertext_sha256}.bin");
    let imeta = vec![
        "imeta".to_owned(),
        "v encrypted-media-v1".to_owned(),
        format!("locator blossom-v1 {locator_url}"),
        format!("ciphertext_sha256 {ciphertext_sha256}"),
        format!("plaintext_sha256 {plaintext_sha256}"),
        format!("nonce {nonce_hex}"),
        "m image/png".to_owned(),
        "filename a.png".to_owned(),
    ];
    let event = MarmotAppEvent::MessageReceived(RuntimeMessageReceived {
        account_id_hex: agent_account_id_hex,
        account_label: "agent".to_owned(),
        message: received_message(MARMOT_APP_EVENT_KIND_CHAT, "see this", vec![imeta]),
    });

    let Some(AgentControlEvent::InboundMessage { media, .. }) =
        control_event_from_runtime_event(event, None, None)
    else {
        panic!("expected kind-9 chat event to become an inbound message");
    };
    assert_eq!(media.len(), 1, "one imeta tag should project one media ref");
    let attachment = &media[0];
    assert_eq!(attachment.media_type, "image/png");
    assert_eq!(attachment.file_name, "a.png");
    assert_eq!(attachment.ciphertext_sha256, ciphertext_sha256);
    assert_eq!(attachment.source_epoch, 7); // received_message uses source_epoch 7
    assert_eq!(attachment.locators.len(), 1);
    assert_eq!(attachment.locators[0].kind, "blossom-v1");
    assert_eq!(attachment.locators[0].value, locator_url);
}

#[test]
fn control_event_emits_stream_update_for_agent_stream_started() {
    let agent_account_id_hex = "aa".repeat(32);
    let stream_id_hex = "55".repeat(32);
    let event = MarmotAppEvent::AgentStreamStarted(RuntimeAgentStreamMessage {
        account_id_hex: agent_account_id_hex.clone(),
        account_label: "agent".to_owned(),
        message: received_message(
            MARMOT_APP_EVENT_KIND_AGENT_STREAM_START,
            "",
            vec![vec![STREAM_TAG.to_owned(), stream_id_hex.clone()]],
        ),
    });

    let Some(AgentControlEvent::StreamUpdate {
        account_id_hex,
        group_id_hex,
        stream_id_hex: event_stream_id_hex,
        status,
    }) = control_event_from_runtime_event(event, None, None)
    else {
        panic!("expected agent stream start to become a stream update");
    };

    assert_eq!(account_id_hex, agent_account_id_hex);
    assert_eq!(group_id_hex, "22".repeat(32));
    assert_eq!(event_stream_id_hex, stream_id_hex);
    assert_eq!(status, AGENT_CONTROL_STREAM_STATUS_STARTED);
}

#[tokio::test]
async fn inbound_catch_up_driver_tracks_active_subscriptions() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relays(dir.path(), Vec::new()));
    let driver = InboundCatchUpDriver::new(runtime.clone());

    let (_first_events, first_subscription) = driver.subscribe();
    assert_eq!(driver.active.load(Ordering::Acquire), 1);
    assert!(driver.started.load(Ordering::Acquire));

    let (_second_events, second_subscription) = driver.subscribe();
    assert_eq!(driver.active.load(Ordering::Acquire), 2);

    drop(first_subscription);
    assert_eq!(driver.active.load(Ordering::Acquire), 1);

    drop(second_subscription);
    assert_eq!(driver.active.load(Ordering::Acquire), 0);

    runtime.shutdown().await;
}

#[tokio::test]
async fn inbound_catch_up_driver_failure_does_not_close_subscribers() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relays(dir.path(), Vec::new()));
    runtime.shutdown().await;
    let driver = InboundCatchUpDriver::new(runtime);
    let (mut events, _subscription) = driver.subscribe();

    assert!(driver.request().await.is_err());
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(driver.active.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn stream_session_sweeper_aborts_idle_session_and_keeps_active_one() {
    use crate::stream_session::{ActiveStreamSession, StreamSessionStore};
    use agent_stream_compose::StreamComposeCommand;
    use cgka_traits::GroupId;
    use std::time::{Duration, Instant};

    let store = StreamSessionStore::default();

    // An idle session: last activity well beyond the timeout. Its compose
    // task stands in for run_stream_compose_session: it exits when it
    // observes the dedicated cancel signal (modeling the graceful Abort
    // path), and otherwise blocks on the command channel.
    let (idle_tx, mut idle_rx) = tokio::sync::mpsc::channel::<StreamComposeCommand>(4);
    let (idle_cancel_tx, mut idle_cancel_rx) = tokio::sync::mpsc::channel::<()>(1);
    let idle_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = idle_cancel_rx.recv() => break,
                cmd = idle_rx.recv() => {
                    if cmd.is_none() {
                        break;
                    }
                }
            }
        }
    });
    store.insert(
        "aa".to_owned(),
        ActiveStreamSession {
            account_label: "agent".to_owned(),
            group_id: GroupId::new(vec![1]),
            stream_id: vec![0xaa],
            start_message_id_hex: "00".to_owned(),
            tx: idle_tx,
            cancel_tx: idle_cancel_tx,
            abort: idle_handle.abort_handle(),
            last_activity: Instant::now() - Duration::from_secs(3600),
        },
    );

    // A fresh session that must survive the sweep.
    let (active_tx, mut active_rx) = tokio::sync::mpsc::channel::<StreamComposeCommand>(4);
    let (active_cancel_tx, _active_cancel_rx) = tokio::sync::mpsc::channel::<()>(1);
    let active_handle = tokio::spawn(async move { while active_rx.recv().await.is_some() {} });
    store.insert(
        "bb".to_owned(),
        ActiveStreamSession {
            account_label: "agent".to_owned(),
            group_id: GroupId::new(vec![2]),
            stream_id: vec![0xbb],
            start_message_id_hex: "00".to_owned(),
            tx: active_tx,
            cancel_tx: active_cancel_tx,
            abort: active_handle.abort_handle(),
            last_activity: Instant::now(),
        },
    );

    let swept = store.sweep_idle(Duration::from_secs(300));
    assert_eq!(swept, 1, "exactly the idle session should be swept");

    // Idle session is gone and its compose task observed the graceful
    // cancel, then finished — dropping the mpsc Sender / transcript / quinn
    // endpoint it was holding open.
    assert!(
        store.remove("aa").is_err(),
        "idle session should be removed"
    );
    let _ = tokio::time::timeout(Duration::from_secs(5), idle_handle)
        .await
        .expect("swept compose task should finish promptly");

    // Active session is untouched and still usable.
    assert!(store.get("bb").is_ok(), "active session should remain");
    active_handle.abort();
}

#[tokio::test]
async fn connector_socket_bind_removes_stale_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dev").join("dm-agent.sock");
    let listener = bind_connector_socket(&socket).unwrap();
    drop(listener);

    let listener = bind_connector_socket(&socket).unwrap();

    assert!(
        listener.local_addr().is_ok(),
        "expected connector socket to rebind after stale socket cleanup"
    );
}

#[tokio::test]
async fn connector_socket_bind_preserves_existing_non_socket_path() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dev").join("dm-agent.sock");
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    std::fs::write(&socket, b"not a socket").unwrap();

    let error = bind_connector_socket(&socket).unwrap_err();

    assert_eq!(error.code(), "io_error");
    assert_eq!(std::fs::read(&socket).unwrap(), b"not a socket");
}

#[tokio::test]
async fn connector_socket_bind_applies_configured_group_modes() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dev").join("dm-agent.sock");

    let listener = bind_connector_socket_with_mode(&socket, 0o770, 0o660).unwrap();

    assert!(
        listener.local_addr().is_ok(),
        "expected connector socket to bind with configured permissions"
    );
    assert_eq!(
        socket
            .parent()
            .unwrap()
            .metadata()
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o770
    );
    assert_eq!(
        socket.metadata().unwrap().permissions().mode() & 0o777,
        0o660
    );
}

#[tokio::test]
async fn connector_control_plane_requires_token_for_group_shared_modes() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dev").join("dm-agent.sock");
    let mut config = test_config(dir.path(), socket, Vec::new(), false, false);
    config.socket_dir_mode = 0o770;
    config.socket_mode = 0o660;

    let error = serve_socket(config).await.unwrap_err();

    assert_eq!(error.code(), "unsafe_control_plane_config");
}

#[tokio::test]
async fn connector_control_plane_rejects_world_accessible_modes() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dev").join("dm-agent.sock");
    let mut config = test_config(dir.path(), socket, Vec::new(), false, false);
    config.auth_token = Some("shared-secret".to_owned());
    config.socket_mode = 0o666;

    let error = serve_socket(config).await.unwrap_err();

    assert_eq!(error.code(), "unsafe_control_plane_config");
}

#[tokio::test]
async fn connector_socket_serves_account_list() {
    let dir = tempfile::tempdir().unwrap();
    let account_home = AccountHome::open(dir.path());
    let account = account_home.create_account("agent").unwrap();
    let socket = dir.path().join("dev").join("dm-agent.sock");
    let connector = AgentConnector::open(test_config(
        dir.path(),
        socket.clone(),
        Vec::new(),
        false,
        false,
    ))
    .unwrap();
    let listener = bind_connector_socket(&socket).unwrap();
    assert_eq!(
        socket
            .parent()
            .unwrap()
            .metadata()
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        socket.metadata().unwrap().permissions().mode() & 0o777,
        0o600
    );
    let server = tokio::spawn(async move { connector.serve_once(&listener).await });

    let client = UnixStream::connect(&socket).await.unwrap();
    let (client_read, mut client_write) = tokio::io::split(client);
    let mut client_read = BufReader::new(client_read);
    let request = AgentControlEnvelope::request(
        Some("req-accounts".to_owned()),
        AgentControlRequest::AccountList,
    );
    write_frame(&mut client_write, &request).await.unwrap();

    let response: AgentControlEnvelope<AgentControlResponse> =
        read_envelope(&mut client_read).await.unwrap().unwrap();
    assert_eq!(response.id.as_deref(), Some("req-accounts"));
    let AgentControlResponse::AccountList { accounts } = response.payload else {
        panic!("expected account list response");
    };
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].account_id_hex, account.account_id_hex);
    assert_eq!(accounts[0].label, "agent");
    assert!(accounts[0].local_signing);

    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn connector_socket_requires_configured_auth_token() {
    let dir = tempfile::tempdir().unwrap();
    let account_home = AccountHome::open(dir.path());
    let account = account_home.create_account("agent").unwrap();
    let socket = dir.path().join("dev").join("dm-agent.sock");
    let mut config = test_config(dir.path(), socket.clone(), Vec::new(), false, false);
    config.auth_token = Some("test-token".to_owned());
    let connector = AgentConnector::open(config).unwrap();
    let listener = bind_connector_socket(&socket).unwrap();

    let denied = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-no-token",
        AgentControlRequest::AccountList,
    )
    .await;

    let AgentControlResponse::Error { code, .. } = denied.payload else {
        panic!("expected unauthorized response without token");
    };
    assert_eq!(denied.id.as_deref(), Some("req-no-token"));
    assert_eq!(code, "unauthorized");

    let wrong = serve_control_request_once_with_auth(
        &connector,
        &listener,
        &socket,
        "req-wrong-token",
        AgentControlRequest::AccountList,
        Some("wrong-token"),
    )
    .await;

    let AgentControlResponse::Error { code, .. } = wrong.payload else {
        panic!("expected unauthorized response with wrong token");
    };
    assert_eq!(wrong.id.as_deref(), Some("req-wrong-token"));
    assert_eq!(code, "unauthorized");

    let allowed = serve_control_request_once_with_auth(
        &connector,
        &listener,
        &socket,
        "req-token",
        AgentControlRequest::AccountList,
        Some("test-token"),
    )
    .await;

    assert_eq!(allowed.id.as_deref(), Some("req-token"));
    let AgentControlResponse::AccountList { accounts } = allowed.payload else {
        panic!("expected account list response with correct token");
    };
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].account_id_hex, account.account_id_hex);
}

#[tokio::test]
async fn connector_socket_subscribes_to_inbound_messages() {
    let dir = tempfile::tempdir().unwrap();
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let app = MarmotApp::with_relay(dir.path(), relay_url.clone());
    let setup_runtime = MarmotAppRuntime::new(app);
    let setup = AccountSetupRequest {
        default_relays: vec![crate::validation::endpoint(&relay_url)],
        bootstrap_relays: vec![crate::validation::endpoint(&relay_url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let agent = setup_runtime.create_identity(setup.clone()).await.unwrap();
    let human = setup_runtime.create_identity(setup).await.unwrap();
    let group_id = setup_runtime
        .create_group(
            &agent.account.account_id_hex,
            "agent inbound",
            std::slice::from_ref(&human.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    setup_runtime
        .accept_group_invite(&human.account.account_id_hex, &group_id)
        .await
        .unwrap();
    setup_runtime.shutdown().await;

    let group_id_hex = hex::encode(group_id.as_slice());
    let socket = dir.path().join("dev").join("dm-agent.sock");
    let server = tokio::spawn(serve_socket(test_config(
        dir.path(),
        socket.clone(),
        vec![relay_url],
        false,
        false,
    )));

    let subscriber = connect_with_retry(&socket).await;
    let (subscriber_read, mut subscriber_write) = tokio::io::split(subscriber);
    let mut subscriber_read = BufReader::new(subscriber_read);
    let subscribe = AgentControlEnvelope::request(
        Some("req-subscribe".to_owned()),
        AgentControlRequest::SubscribeInbound {
            account_id_hex: Some(agent.account.account_id_hex.clone()),
            group_id_hex: Some(group_id_hex.clone()),
        },
    );
    write_frame(&mut subscriber_write, &subscribe)
        .await
        .unwrap();
    let ack: AgentControlEnvelope<AgentControlResponse> = timeout(
        CONTROL_RESPONSE_TIMEOUT,
        read_envelope(&mut subscriber_read),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(ack.id.as_deref(), Some("req-subscribe"));
    assert_eq!(ack.payload, AgentControlResponse::Ack);

    let sender = connect_with_retry(&socket).await;
    let (sender_read, mut sender_write) = tokio::io::split(sender);
    let mut sender_read = BufReader::new(sender_read);
    let send = AgentControlEnvelope::request(
        Some("req-human-final".to_owned()),
        AgentControlRequest::SendFinal {
            account_id_hex: human.account.account_id_hex.clone(),
            group_id_hex: group_id_hex.clone(),
            text: "hello agent".to_owned(),
            reply_to_message_id_hex: None,
            idempotency_key: None,
        },
    );
    write_frame(&mut sender_write, &send).await.unwrap();
    let sent: AgentControlEnvelope<AgentControlResponse> =
        timeout(CONTROL_RESPONSE_TIMEOUT, read_envelope(&mut sender_read))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    assert!(matches!(
        sent.payload,
        AgentControlResponse::FinalSent { .. }
    ));

    let inbound = read_matching_inbound_message(&mut subscriber_read, "hello agent").await;
    assert_eq!(inbound.id.as_deref(), Some("req-subscribe"));
    let AgentControlEvent::InboundMessage {
        account_id_hex,
        group_id_hex: event_group_id_hex,
        sender_account_id_hex,
        text,
        ..
    } = inbound.payload
    else {
        panic!("expected inbound message event");
    };
    assert_eq!(account_id_hex, agent.account.account_id_hex);
    assert_eq!(event_group_id_hex, group_id_hex);
    assert_eq!(sender_account_id_hex, human.account.account_id_hex);
    assert_eq!(text, "hello agent");

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn connector_socket_subscribe_terminates_when_client_disconnects() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dev").join("dm-agent.sock");
    let connector = AgentConnector::open(test_config(
        dir.path(),
        socket.clone(),
        Vec::new(),
        false,
        false,
    ))
    .unwrap();
    let listener = bind_connector_socket(&socket).unwrap();
    let server = tokio::spawn(async move { connector.serve_once(&listener).await });

    let subscriber = UnixStream::connect(&socket).await.unwrap();
    let (subscriber_read, mut subscriber_write) = tokio::io::split(subscriber);
    let mut subscriber_read = BufReader::new(subscriber_read);
    let subscribe = AgentControlEnvelope::request(
        Some("req-disconnect-subscribe".to_owned()),
        AgentControlRequest::SubscribeInbound {
            account_id_hex: None,
            group_id_hex: None,
        },
    );
    write_frame(&mut subscriber_write, &subscribe)
        .await
        .unwrap();
    let ack: AgentControlEnvelope<AgentControlResponse> = timeout(
        CONTROL_RESPONSE_TIMEOUT,
        read_envelope(&mut subscriber_read),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(ack.payload, AgentControlResponse::Ack);

    drop(subscriber_write);
    drop(subscriber_read);

    timeout(Duration::from_secs(1), server)
        .await
        .expect("subscribe connection should terminate promptly after client disconnect")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn connector_debug_controls_inject_inbound_and_record_final_sends() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dev").join("dm-agent.sock");
    let account_id_hex = "11".repeat(32);
    let group_id_hex = "22".repeat(32);
    let message_id_hex = "33".repeat(32);
    let sender_account_id_hex = "44".repeat(32);
    let server = tokio::spawn(serve_socket(test_config(
        dir.path(),
        socket.clone(),
        Vec::new(),
        false,
        true,
    )));

    let subscriber = connect_with_retry(&socket).await;
    let (subscriber_read, mut subscriber_write) = tokio::io::split(subscriber);
    let mut subscriber_read = BufReader::new(subscriber_read);
    let subscribe = AgentControlEnvelope::request(
        Some("req-debug-subscribe".to_owned()),
        AgentControlRequest::SubscribeInbound {
            account_id_hex: Some(account_id_hex.clone()),
            group_id_hex: Some(group_id_hex.clone()),
        },
    );
    write_frame(&mut subscriber_write, &subscribe)
        .await
        .unwrap();
    let ack: AgentControlEnvelope<AgentControlResponse> = timeout(
        CONTROL_RESPONSE_TIMEOUT,
        read_envelope(&mut subscriber_read),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(ack.payload, AgentControlResponse::Ack);

    let injected = send_control_request(
        &socket,
        "req-debug-inject",
        AgentControlRequest::DebugInjectInbound {
            account_id_hex: account_id_hex.clone(),
            group_id_hex: group_id_hex.clone(),
            message_id_hex: message_id_hex.clone(),
            sender_account_id_hex: sender_account_id_hex.clone(),
            text: "ping from connector".to_owned(),
        },
    )
    .await;
    assert_eq!(injected.payload, AgentControlResponse::Ack);

    let inbound = read_matching_inbound_message(&mut subscriber_read, "ping from connector").await;
    let AgentControlEvent::InboundMessage {
        account_id_hex: event_account_id_hex,
        group_id_hex: event_group_id_hex,
        message_id_hex: event_message_id_hex,
        sender_account_id_hex: event_sender_account_id_hex,
        text,
        ..
    } = inbound.payload
    else {
        panic!("expected debug inbound message event");
    };
    assert_eq!(event_account_id_hex, account_id_hex);
    assert_eq!(event_group_id_hex, group_id_hex);
    assert_eq!(event_message_id_hex, message_id_hex);
    assert_eq!(event_sender_account_id_hex, sender_account_id_hex);
    assert_eq!(text, "ping from connector");

    let sent = send_control_request(
        &socket,
        "req-debug-final",
        AgentControlRequest::SendFinal {
            account_id_hex: account_id_hex.clone(),
            group_id_hex: group_id_hex.clone(),
            text: "marmot-e2e-ok: ping from connector".to_owned(),
            reply_to_message_id_hex: Some(message_id_hex.clone()),
            idempotency_key: None,
        },
    )
    .await;
    let AgentControlResponse::FinalSent { message_ids_hex } = sent.payload else {
        panic!("expected debug final sent response");
    };
    assert_eq!(message_ids_hex, vec![format!("{:064x}", 1)]);

    let recorded = send_control_request(
        &socket,
        "req-debug-finals",
        AgentControlRequest::DebugRecordedFinals,
    )
    .await;
    let AgentControlResponse::DebugRecordedFinals { sends } = recorded.payload else {
        panic!("expected recorded debug finals");
    };
    assert_eq!(sends.len(), 1);
    assert_eq!(sends[0].account_id_hex, account_id_hex);
    assert_eq!(sends[0].group_id_hex, group_id_hex);
    assert_eq!(
        sends[0].text,
        "marmot-e2e-ok: ping from connector".to_owned()
    );
    assert_eq!(
        sends[0].reply_to_message_id_hex.as_deref(),
        Some(message_id_hex.as_str())
    );
    assert_eq!(sends[0].message_ids_hex, vec![format!("{:064x}", 1)]);

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn connector_debug_controls_are_disabled_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dev").join("dm-agent.sock");
    let connector = AgentConnector::open(test_config(
        dir.path(),
        socket.clone(),
        Vec::new(),
        false,
        false,
    ))
    .unwrap();
    let listener = bind_connector_socket(&socket).unwrap();

    let response = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-debug-disabled",
        AgentControlRequest::DebugRecordedFinals,
    )
    .await;
    let AgentControlResponse::Error { code, .. } = response.payload else {
        panic!("expected debug controls disabled error");
    };
    assert_eq!(code, "debug_controls_disabled");
}

#[tokio::test]
async fn connector_socket_updates_allowlist() {
    let dir = tempfile::tempdir().unwrap();
    let account_home = AccountHome::open(dir.path());
    let agent = account_home.create_account("agent").unwrap();
    let welcomer = account_home.create_account("welcomer").unwrap();
    let socket = dir.path().join("dev").join("dm-agent.sock");
    let connector = AgentConnector::open(test_config(
        dir.path(),
        socket.clone(),
        Vec::new(),
        false,
        false,
    ))
    .unwrap();
    let listener = bind_connector_socket(&socket).unwrap();

    let added = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-allow-add",
        AgentControlRequest::AllowlistAdd {
            account_id_hex: agent.account_id_hex.clone(),
            welcomer_account_id_hex: welcomer.account_id_hex.clone(),
        },
    )
    .await;
    assert_allowlist(
        added,
        "req-allow-add",
        &agent.account_id_hex,
        &[welcomer.account_id_hex.as_str()],
    );

    let listed = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-allow-list",
        AgentControlRequest::AllowlistList {
            account_id_hex: agent.account_id_hex.clone(),
        },
    )
    .await;
    assert_allowlist(
        listed,
        "req-allow-list",
        &agent.account_id_hex,
        &[welcomer.account_id_hex.as_str()],
    );

    let removed = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-allow-remove",
        AgentControlRequest::AllowlistRemove {
            account_id_hex: agent.account_id_hex.clone(),
            welcomer_account_id_hex: welcomer.account_id_hex.clone(),
        },
    )
    .await;
    assert_allowlist(removed, "req-allow-remove", &agent.account_id_hex, &[]);
}

#[test]
fn allowlist_store_treats_corrupt_record_as_empty_and_recovers_on_write() {
    let dir = tempfile::tempdir().unwrap();
    let store = AllowlistStore::new(dir.path());
    let account_id_hex = format!("{:064x}", 1);
    let welcomer_account_id_hex = format!("{:064x}", 2);
    std::fs::create_dir_all(&store.dir).unwrap();
    std::fs::write(store.record_path(&account_id_hex), b"{not valid json").unwrap();

    assert_eq!(store.list(&account_id_hex).unwrap(), Vec::<String>::new());
    assert!(
        !store
            .contains(&account_id_hex, &welcomer_account_id_hex)
            .unwrap()
    );

    assert_eq!(
        store
            .add(&account_id_hex, &welcomer_account_id_hex)
            .unwrap(),
        vec![welcomer_account_id_hex.clone()]
    );
    assert_eq!(
        store
            .read_record(&account_id_hex)
            .unwrap()
            .welcomer_account_ids_hex,
        vec![welcomer_account_id_hex]
    );
}

#[test]
fn allowlist_store_atomic_write_replaces_stale_temp_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = AllowlistStore::new(dir.path());
    let account_id_hex = format!("{:064x}", 1);
    let welcomer_account_id_hex = format!("{:064x}", 2);
    let temp_path = store.temp_record_path(&account_id_hex);
    std::fs::create_dir_all(&store.dir).unwrap();
    std::fs::write(&temp_path, b"partial write from crashed writer").unwrap();

    store
        .write_record(&AllowlistRecord {
            account_id_hex: account_id_hex.clone(),
            welcomer_account_ids_hex: vec![welcomer_account_id_hex.clone()],
        })
        .unwrap();

    assert!(!temp_path.exists());
    assert_eq!(
        store
            .read_record(&account_id_hex)
            .unwrap()
            .welcomer_account_ids_hex,
        vec![welcomer_account_id_hex]
    );
    assert_eq!(
        store
            .record_path(&account_id_hex)
            .metadata()
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn allowlist_store_ignores_record_whose_account_id_does_not_match_path() {
    let dir = tempfile::tempdir().unwrap();
    let store = AllowlistStore::new(dir.path());
    let requested_account_id_hex = format!("{:064x}", 1);
    let other_account_id_hex = format!("{:064x}", 99);
    let welcomer_account_id_hex = format!("{:064x}", 2);
    std::fs::create_dir_all(&store.dir).unwrap();

    // A well-formed record placed at account #1's path, but whose embedded
    // `account_id_hex` claims to belong to account #99 (tampered/relocated file).
    let forged = serde_json::to_vec(&AllowlistRecord {
        account_id_hex: other_account_id_hex.clone(),
        welcomer_account_ids_hex: vec![welcomer_account_id_hex.clone()],
    })
    .unwrap();
    std::fs::write(store.record_path(&requested_account_id_hex), &forged).unwrap();

    // The mismatched record must not be served as account #1's allowlist: its
    // forged welcomer must not appear and the record reads back as empty.
    let record = store.read_record(&requested_account_id_hex).unwrap();
    assert_eq!(record.account_id_hex, requested_account_id_hex);
    assert_eq!(record.welcomer_account_ids_hex, Vec::<String>::new());
    assert_eq!(
        store.list(&requested_account_id_hex).unwrap(),
        Vec::<String>::new()
    );
    assert!(
        !store
            .contains(&requested_account_id_hex, &welcomer_account_id_hex)
            .unwrap()
    );

    // A subsequent write for account #1 must land at account #1's own path and
    // leave account #99's file untouched (no redirected write).
    store
        .add(&requested_account_id_hex, &welcomer_account_id_hex)
        .unwrap();
    assert_eq!(
        store
            .read_record(&requested_account_id_hex)
            .unwrap()
            .welcomer_account_ids_hex,
        vec![welcomer_account_id_hex]
    );
    assert!(!store.record_path(&other_account_id_hex).exists());
}

#[tokio::test]
async fn stream_session_store_resolves_non_canonical_stream_id() {
    use crate::stream_session::{ActiveStreamSession, StreamSessionStore};
    use agent_stream_compose::StreamComposeCommand;
    use cgka_traits::GroupId;
    use std::time::Instant;

    let store = StreamSessionStore::default();
    // Sessions are always inserted under a lowercase-canonical hex key
    // (`hex::encode`), as `stream_begin_response` does.
    let canonical_stream_id_hex = "aabb".to_owned();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<StreamComposeCommand>(4);
    let (cancel_tx, _cancel_rx) = tokio::sync::mpsc::channel::<()>(1);
    let handle = tokio::spawn(async move { while rx.recv().await.is_some() {} });
    store.insert(
        canonical_stream_id_hex.clone(),
        ActiveStreamSession {
            account_label: "agent".to_owned(),
            group_id: GroupId::new(vec![1]),
            stream_id: vec![0xaa, 0xbb],
            start_message_id_hex: "00".to_owned(),
            tx,
            cancel_tx,
            abort: handle.abort_handle(),
            last_activity: Instant::now(),
        },
    );

    // A non-canonical (uppercase) but valid hex id must resolve the same session
    // through both the lookup and the removal paths, because the store
    // normalizes the query key before matching.
    assert!(
        store.get("AABB").is_ok(),
        "uppercase stream id should resolve the canonically stored session"
    );
    assert!(
        store.remove("AABB").is_ok(),
        "uppercase stream id should remove the canonically stored session"
    );
    assert!(
        store.get("aabb").is_err(),
        "session should be gone after removal via the non-canonical id"
    );
    handle.abort();
}

#[tokio::test]
async fn stream_session_sweep_does_not_force_abort_when_cancel_already_queued() {
    use crate::stream_session::{ActiveStreamSession, StreamSessionStore};
    use agent_stream_compose::StreamComposeCommand;
    use cgka_traits::GroupId;
    use std::time::{Duration, Instant};

    let store = StreamSessionStore::default();
    // Depth-1 cancel channel that we pre-fill so the sweeper's `try_send`
    // observes `TrySendError::Full` rather than a closed channel. The receiver
    // is kept alive (held in `_cancel_rx`) but never drained, modeling a session
    // that already has a cancel pending.
    let (cancel_tx, _cancel_rx) = tokio::sync::mpsc::channel::<()>(1);
    cancel_tx.try_send(()).expect("prime the cancel channel");

    let (tx, _rx) = tokio::sync::mpsc::channel::<StreamComposeCommand>(4);
    // A live task whose abort would set the AbortHandle's finished flag; if the
    // sweeper force-aborts on `Full`, this task would be cancelled.
    let handle = tokio::spawn(async move {
        std::future::pending::<()>().await;
    });
    let abort = handle.abort_handle();
    store.insert(
        "aa".to_owned(),
        ActiveStreamSession {
            account_label: "agent".to_owned(),
            group_id: GroupId::new(vec![1]),
            stream_id: vec![0xaa],
            start_message_id_hex: "00".to_owned(),
            tx,
            cancel_tx,
            abort,
            last_activity: Instant::now() - Duration::from_secs(3600),
        },
    );

    let swept = store.sweep_idle(Duration::from_secs(300));
    assert_eq!(swept, 1, "the idle session is still swept from the store");

    // A `Full` cancel channel means a cancel is already pending, so the sweeper
    // must NOT force-abort the task — it is left to drain its cancel and emit a
    // live `Abort`. Give the runtime a moment, then confirm the task was not
    // cancelled out from under us.
    sleep(Duration::from_millis(50)).await;
    assert!(
        !handle.is_finished(),
        "a Full cancel channel must not trigger a forced abort"
    );
    handle.abort();
}

#[tokio::test]
async fn connector_policy_accepts_allowed_welcomer() {
    let agent_dir = tempfile::tempdir().unwrap();
    let human_dir = tempfile::tempdir().unwrap();
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let agent_app = MarmotApp::with_relay(agent_dir.path(), relay_url.clone());
    let human_app = MarmotApp::with_relay(human_dir.path(), relay_url.clone());
    let agent_setup_runtime = MarmotAppRuntime::new(agent_app.clone());
    let human_runtime = MarmotAppRuntime::new(human_app);
    let setup = AccountSetupRequest {
        default_relays: vec![crate::validation::endpoint(&relay_url)],
        bootstrap_relays: vec![crate::validation::endpoint(&relay_url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let agent = agent_setup_runtime
        .create_identity(setup.clone())
        .await
        .unwrap();
    let human = human_runtime.create_identity(setup).await.unwrap();
    agent_setup_runtime.shutdown().await;

    let socket = agent_dir.path().join("dev").join("dm-agent.sock");
    let server = tokio::spawn(serve_socket(test_config(
        agent_dir.path(),
        socket.clone(),
        vec![relay_url],
        false,
        false,
    )));
    let added = send_control_request(
        &socket,
        "req-allow-human",
        AgentControlRequest::AllowlistAdd {
            account_id_hex: agent.account.account_id_hex.clone(),
            welcomer_account_id_hex: human.account.account_id_hex.clone(),
        },
    )
    .await;
    assert_allowlist(
        added,
        "req-allow-human",
        &agent.account.account_id_hex,
        &[human.account.account_id_hex.as_str()],
    );

    let group_id = human_runtime
        .create_group(
            &human.account.account_id_hex,
            "allowed invite",
            std::slice::from_ref(&agent.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    wait_for_group_state(&agent_app, &agent.account.label, &group_id_hex, |group| {
        !group.pending_confirmation && !group.archived
    })
    .await;

    human_runtime.shutdown().await;
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn connector_policy_declines_unlisted_welcomer() {
    let agent_dir = tempfile::tempdir().unwrap();
    let human_dir = tempfile::tempdir().unwrap();
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let agent_app = MarmotApp::with_relay(agent_dir.path(), relay_url.clone());
    let human_app = MarmotApp::with_relay(human_dir.path(), relay_url.clone());
    let agent_setup_runtime = MarmotAppRuntime::new(agent_app.clone());
    let human_runtime = MarmotAppRuntime::new(human_app);
    let setup = AccountSetupRequest {
        default_relays: vec![crate::validation::endpoint(&relay_url)],
        bootstrap_relays: vec![crate::validation::endpoint(&relay_url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let agent = agent_setup_runtime
        .create_identity(setup.clone())
        .await
        .unwrap();
    let human = human_runtime.create_identity(setup).await.unwrap();
    agent_setup_runtime.shutdown().await;

    let socket = agent_dir.path().join("dev").join("dm-agent.sock");
    let server = tokio::spawn(serve_socket(test_config(
        agent_dir.path(),
        socket.clone(),
        vec![relay_url],
        false,
        false,
    )));
    assert!(matches!(
        send_control_request(&socket, "req-ready", AgentControlRequest::AccountList)
            .await
            .payload,
        AgentControlResponse::AccountList { .. }
    ));

    let group_id = human_runtime
        .create_group(
            &human.account.account_id_hex,
            "unlisted invite",
            std::slice::from_ref(&agent.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    wait_for_group_state(&agent_app, &agent.account.label, &group_id_hex, |group| {
        !group.pending_confirmation && group.archived
    })
    .await;

    human_runtime.shutdown().await;
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn connector_policy_allow_any_accepts_unlisted_welcomer() {
    let agent_dir = tempfile::tempdir().unwrap();
    let human_dir = tempfile::tempdir().unwrap();
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let agent_app = MarmotApp::with_relay(agent_dir.path(), relay_url.clone());
    let human_app = MarmotApp::with_relay(human_dir.path(), relay_url.clone());
    let agent_setup_runtime = MarmotAppRuntime::new(agent_app.clone());
    let human_runtime = MarmotAppRuntime::new(human_app);
    let setup = AccountSetupRequest {
        default_relays: vec![crate::validation::endpoint(&relay_url)],
        bootstrap_relays: vec![crate::validation::endpoint(&relay_url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let agent = agent_setup_runtime
        .create_identity(setup.clone())
        .await
        .unwrap();
    let human = human_runtime.create_identity(setup).await.unwrap();
    agent_setup_runtime.shutdown().await;

    let socket = agent_dir.path().join("dev").join("dm-agent.sock");
    let server = tokio::spawn(serve_socket(test_config(
        agent_dir.path(),
        socket.clone(),
        vec![relay_url],
        true,
        false,
    )));
    assert!(matches!(
        send_control_request(&socket, "req-ready", AgentControlRequest::AccountList)
            .await
            .payload,
        AgentControlResponse::AccountList { .. }
    ));

    let group_id = human_runtime
        .create_group(
            &human.account.account_id_hex,
            "allow any invite",
            std::slice::from_ref(&agent.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    wait_for_group_state(&agent_app, &agent.account.label, &group_id_hex, |group| {
        !group.pending_confirmation && !group.archived
    })
    .await;

    human_runtime.shutdown().await;
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn connector_start_reconciles_existing_allowed_pending_invite() {
    let setup = setup_existing_pending_invite("existing pending invite").await;
    let connector = AgentConnector::open(test_config(
        setup.dir.path(),
        setup.dir.path().join("dev").join("dm-agent.sock"),
        vec![setup.relay_url.clone()],
        false,
        false,
    ))
    .unwrap();
    connector
        .allowlist_add_response(&setup.agent_account_id_hex, &setup.human_account_id_hex)
        .unwrap();

    connector.start().await.unwrap();

    wait_for_group_state(
        &setup.app,
        &setup.agent_label,
        &setup.group_id_hex,
        |group| !group.pending_confirmation && !group.archived,
    )
    .await;

    connector.runtime.shutdown().await;
}

#[tokio::test]
async fn connector_start_reconciles_existing_unlisted_pending_invite_by_declining() {
    let setup = setup_existing_pending_invite("existing unlisted pending invite").await;
    let connector = AgentConnector::open(test_config(
        setup.dir.path(),
        setup.dir.path().join("dev").join("dm-agent.sock"),
        vec![setup.relay_url.clone()],
        false,
        false,
    ))
    .unwrap();

    connector.start().await.unwrap();

    wait_for_group_state(
        &setup.app,
        &setup.agent_label,
        &setup.group_id_hex,
        |group| !group.pending_confirmation && group.archived,
    )
    .await;

    connector.runtime.shutdown().await;
}

#[test]
fn invite_policy_retry_state_uses_capped_backoff_and_prunes_non_pending() {
    let mut retry_state = crate::validation::InvitePolicyRetryState::default();
    let key = crate::validation::InvitePolicyKey::new("aa", "bb");
    let other_key = crate::validation::InvitePolicyKey::new("cc", "dd");
    let now = tokio::time::Instant::now();

    assert!(retry_state.is_due(&key, now));
    let (attempts, delay) = retry_state.record_failure(key.clone(), now);
    assert_eq!(attempts, 1);
    assert_eq!(delay, crate::INVITE_POLICY_RETRY_BASE);
    assert!(!retry_state.is_due(&key, now + delay - Duration::from_millis(1)));
    assert!(retry_state.is_due(&key, now + delay));

    let (attempts, delay) = retry_state.record_failure(key.clone(), now + delay);
    assert_eq!(attempts, 2);
    assert_eq!(delay, crate::INVITE_POLICY_RETRY_BASE * 2);

    let mut current = now;
    let mut capped_delay = delay;
    for expected_attempt in 3..=20 {
        current += capped_delay;
        let (attempts, delay) = retry_state.record_failure(key.clone(), current);
        assert_eq!(attempts, expected_attempt);
        assert!(delay <= crate::INVITE_POLICY_RETRY_MAX);
        capped_delay = delay;
    }
    assert_eq!(capped_delay, crate::INVITE_POLICY_RETRY_MAX);

    retry_state.record_failure(other_key.clone(), now);
    retry_state.retain_pending(&HashSet::from([key.clone()]));
    assert!(retry_state.failures.contains_key(&key));
    assert!(!retry_state.failures.contains_key(&other_key));

    retry_state.clear(&key);
    assert!(retry_state.is_due(&key, now));
}

#[tokio::test]
async fn connector_socket_creates_local_account() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dev").join("dm-agent.sock");
    let connector = AgentConnector::open(test_config(
        dir.path(),
        socket.clone(),
        Vec::new(),
        false,
        false,
    ))
    .unwrap();
    let listener = bind_connector_socket(&socket).unwrap();
    let server = tokio::spawn(async move { connector.serve_once(&listener).await });

    let client = UnixStream::connect(&socket).await.unwrap();
    let (client_read, mut client_write) = tokio::io::split(client);
    let mut client_read = BufReader::new(client_read);
    let request = AgentControlEnvelope::request(
        Some("req-create".to_owned()),
        AgentControlRequest::AccountCreate {
            label: Some("agent".to_owned()),
            publish_key_package: false,
        },
    );
    write_frame(&mut client_write, &request).await.unwrap();

    let response: AgentControlEnvelope<AgentControlResponse> =
        read_envelope(&mut client_read).await.unwrap().unwrap();
    assert_eq!(response.id.as_deref(), Some("req-create"));
    let AgentControlResponse::AccountCreated { account } = response.payload else {
        panic!("expected account created response");
    };
    assert_eq!(account.label, "agent");
    assert!(account.local_signing);

    let stored = AccountHome::open(dir.path()).account("agent").unwrap();
    assert_eq!(stored.account_id_hex, account.account_id_hex);

    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn connector_socket_publishes_key_package() {
    let dir = tempfile::tempdir().unwrap();
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let account_home = AccountHome::open(dir.path());
    let account = account_home.create_account("agent").unwrap();
    let app = MarmotApp::with_relay(dir.path(), relay_url.clone());
    let socket = dir.path().join("dev").join("dm-agent.sock");
    let connector = AgentConnector::open(test_config(
        dir.path(),
        socket.clone(),
        vec![relay_url.clone()],
        false,
        false,
    ))
    .unwrap();
    let listener = bind_connector_socket(&socket).unwrap();
    let server = tokio::spawn(async move { connector.serve_once(&listener).await });

    let client = UnixStream::connect(&socket).await.unwrap();
    let (client_read, mut client_write) = tokio::io::split(client);
    let mut client_read = BufReader::new(client_read);
    let request = AgentControlEnvelope::request(
        Some("req-publish".to_owned()),
        AgentControlRequest::AccountPublishKeyPackage {
            account_id_hex: account.account_id_hex.clone(),
        },
    );
    write_frame(&mut client_write, &request).await.unwrap();

    let response: AgentControlEnvelope<AgentControlResponse> =
        read_envelope(&mut client_read).await.unwrap().unwrap();
    assert_eq!(response.id.as_deref(), Some("req-publish"));
    let AgentControlResponse::KeyPackagePublished {
        account_id_hex,
        key_package_bytes,
    } = response.payload.clone()
    else {
        panic!(
            "expected key package published response, got {:?}",
            response.payload
        );
    };
    assert_eq!(account_id_hex, account.account_id_hex);
    assert!(key_package_bytes > 0);
    let fetched = app
        .fetch_latest_key_package_for_account_id(
            &account.account_id_hex,
            vec![crate::validation::endpoint(&relay_url)],
        )
        .await
        .unwrap();
    assert_eq!(key_package_bytes, fetched.key_package.bytes().len());

    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn connector_socket_publishes_profile_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let account_home = AccountHome::open(dir.path());
    let account = account_home.create_account("agent").unwrap();
    let app = MarmotApp::with_relay(dir.path(), relay_url.clone());
    let socket = dir.path().join("dev").join("dm-agent.sock");
    let connector = AgentConnector::open(test_config(
        dir.path(),
        socket.clone(),
        vec![relay_url.clone()],
        false,
        false,
    ))
    .unwrap();
    let listener = bind_connector_socket(&socket).unwrap();
    let server = tokio::spawn(async move { connector.serve_once(&listener).await });

    let client = UnixStream::connect(&socket).await.unwrap();
    let (client_read, mut client_write) = tokio::io::split(client);
    let mut client_read = BufReader::new(client_read);
    let request = AgentControlEnvelope::request(
        Some("req-profile".to_owned()),
        AgentControlRequest::AccountPublishProfile {
            account_id_hex: account.account_id_hex.clone(),
            name: "  Hermes Agent  ".to_owned(),
            display_name: None,
        },
    );
    write_frame(&mut client_write, &request).await.unwrap();

    let response: AgentControlEnvelope<AgentControlResponse> =
        read_envelope(&mut client_read).await.unwrap().unwrap();
    assert_eq!(response.id.as_deref(), Some("req-profile"));
    let AgentControlResponse::ProfilePublished {
        account_id_hex,
        name,
        display_name,
    } = response.payload.clone()
    else {
        panic!(
            "expected profile published response, got {:?}",
            response.payload
        );
    };
    assert_eq!(account_id_hex, account.account_id_hex);
    assert_eq!(name, "Hermes Agent");
    assert_eq!(display_name.as_deref(), Some("Hermes Agent"));

    app.refresh_profile_for_account_id(
        &account.account_id_hex,
        vec![crate::validation::endpoint(&relay_url)],
    )
    .await
    .unwrap();
    let profile = app
        .directory_entry_for_account_id(&account.account_id_hex)
        .unwrap()
        .and_then(|entry| entry.profile)
        .expect("published profile");
    assert_eq!(profile.name.as_deref(), Some("Hermes Agent"));
    assert_eq!(profile.display_name.as_deref(), Some("Hermes Agent"));

    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn connector_start_publishes_key_package_for_existing_local_account() {
    let dir = tempfile::tempdir().unwrap();
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let account_home = AccountHome::open(dir.path());
    let account = account_home.create_account("agent").unwrap();
    let app = MarmotApp::with_relay(dir.path(), relay_url.clone());
    let connector = AgentConnector::open(test_config(
        dir.path(),
        dir.path().join("dev").join("dm-agent.sock"),
        vec![relay_url.clone()],
        false,
        false,
    ))
    .unwrap();

    connector.start().await.unwrap();

    let fetched = app
        .fetch_latest_key_package_for_account_id(
            &account.account_id_hex,
            vec![crate::validation::endpoint(&relay_url)],
        )
        .await
        .unwrap();
    assert!(!fetched.key_package.bytes().is_empty());

    connector.runtime.shutdown().await;
}

#[tokio::test]
async fn connector_socket_sends_final_message() {
    let dir = tempfile::tempdir().unwrap();
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let app = MarmotApp::with_relay(dir.path(), relay_url.clone());
    let setup_runtime = MarmotAppRuntime::new(app);
    let setup = AccountSetupRequest {
        default_relays: vec![crate::validation::endpoint(&relay_url)],
        bootstrap_relays: vec![crate::validation::endpoint(&relay_url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let agent = setup_runtime.create_identity(setup.clone()).await.unwrap();
    let human = setup_runtime.create_identity(setup).await.unwrap();
    let group_id = setup_runtime
        .create_group(
            &agent.account.account_id_hex,
            "agent final",
            std::slice::from_ref(&human.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    setup_runtime.shutdown().await;

    let group_id_hex = hex::encode(group_id.as_slice());
    let socket = dir.path().join("dev").join("dm-agent.sock");
    let connector = AgentConnector::open(test_config(
        dir.path(),
        socket.clone(),
        vec![relay_url],
        false,
        false,
    ))
    .unwrap();
    let listener = bind_connector_socket(&socket).unwrap();
    let server = tokio::spawn(async move { connector.serve_once(&listener).await });

    let client = UnixStream::connect(&socket).await.unwrap();
    let (client_read, mut client_write) = tokio::io::split(client);
    let mut client_read = BufReader::new(client_read);
    let request = AgentControlEnvelope::request(
        Some("req-final".to_owned()),
        AgentControlRequest::SendFinal {
            account_id_hex: agent.account.account_id_hex,
            group_id_hex,
            text: "final answer".to_owned(),
            reply_to_message_id_hex: None,
            idempotency_key: None,
        },
    );
    write_frame(&mut client_write, &request).await.unwrap();

    let response: AgentControlEnvelope<AgentControlResponse> =
        read_envelope(&mut client_read).await.unwrap().unwrap();
    assert_eq!(response.id.as_deref(), Some("req-final"));
    let AgentControlResponse::FinalSent { message_ids_hex } = response.payload else {
        panic!("expected final sent response");
    };
    assert_eq!(message_ids_hex.len(), 1);
    assert!(!message_ids_hex[0].is_empty());

    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn connector_socket_composes_and_finalizes_stream() {
    let dir = tempfile::tempdir().unwrap();
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let app = MarmotApp::with_relay(dir.path(), relay_url.clone());
    let setup_runtime = MarmotAppRuntime::new(app);
    let setup = AccountSetupRequest {
        default_relays: vec![crate::validation::endpoint(&relay_url)],
        bootstrap_relays: vec![crate::validation::endpoint(&relay_url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let agent = setup_runtime.create_identity(setup.clone()).await.unwrap();
    let human = setup_runtime.create_identity(setup).await.unwrap();
    let group_id = setup_runtime
        .create_group(
            &agent.account.account_id_hex,
            "agent stream",
            std::slice::from_ref(&human.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    setup_runtime.shutdown().await;

    let group_id_hex = hex::encode(group_id.as_slice());
    let stream_id_hex = hex::encode([0x77; 32]);
    let socket = dir.path().join("dev").join("dm-agent.sock");
    let connector = AgentConnector::open(test_config(
        dir.path(),
        socket.clone(),
        vec![relay_url],
        false,
        false,
    ))
    .unwrap();
    let listener = bind_connector_socket(&socket).unwrap();

    let begun = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-stream-begin",
        AgentControlRequest::StreamBegin {
            account_id_hex: agent.account.account_id_hex.clone(),
            group_id_hex: group_id_hex.clone(),
            stream_id_hex: Some(stream_id_hex.clone()),
            quic_candidates: vec!["quic://127.0.0.1:9".to_owned()],
        },
    )
    .await;
    let AgentControlResponse::StreamBegun {
        stream_id_hex: begun_stream_id_hex,
        start_message_id_hex,
        quic_candidates,
        ..
    } = begun.payload
    else {
        panic!("expected stream begun response");
    };
    assert_eq!(begun_stream_id_hex, stream_id_hex);
    assert_eq!(quic_candidates, vec!["quic://127.0.0.1:9"]);

    let appended = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-stream-append",
        AgentControlRequest::StreamAppend {
            stream_id_hex: stream_id_hex.clone(),
            append_text: "hello stream".to_owned(),
        },
    )
    .await;
    assert_eq!(appended.payload, AgentControlResponse::Ack);

    let status = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-stream-status",
        AgentControlRequest::StreamStatus {
            stream_id_hex: stream_id_hex.clone(),
            status: "thinking".to_owned(),
        },
    )
    .await;
    assert_eq!(status.payload, AgentControlResponse::Ack);

    let transcript_hash_hex = expected_stream_transcript_hash(
        &stream_id_hex,
        &start_message_id_hex,
        &[
            (AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, "hello stream"),
            (AGENT_TEXT_STREAM_RECORD_STATUS, "thinking"),
        ],
    );
    let finalized = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-stream-finalize",
        AgentControlRequest::StreamFinalize {
            stream_id_hex: stream_id_hex.clone(),
            final_text: "hello stream".to_owned(),
            transcript_hash_hex,
            chunk_count: 2,
        },
    )
    .await;
    let AgentControlResponse::StreamFinalized {
        stream_id_hex: finalized_stream_id_hex,
        message_ids_hex,
    } = finalized.payload
    else {
        panic!("expected stream finalized response");
    };
    assert_eq!(finalized_stream_id_hex, stream_id_hex);
    assert_eq!(message_ids_hex.len(), 1);
    assert!(!message_ids_hex[0].is_empty());
}

#[tokio::test]
async fn connector_socket_cancels_stream_session() {
    let dir = tempfile::tempdir().unwrap();
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let app = MarmotApp::with_relay(dir.path(), relay_url.clone());
    let setup_runtime = MarmotAppRuntime::new(app);
    let setup = AccountSetupRequest {
        default_relays: vec![crate::validation::endpoint(&relay_url)],
        bootstrap_relays: vec![crate::validation::endpoint(&relay_url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let agent = setup_runtime.create_identity(setup.clone()).await.unwrap();
    let human = setup_runtime.create_identity(setup).await.unwrap();
    let group_id = setup_runtime
        .create_group(
            &agent.account.account_id_hex,
            "agent cancelled stream",
            std::slice::from_ref(&human.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    setup_runtime.shutdown().await;

    let group_id_hex = hex::encode(group_id.as_slice());
    let stream_id_hex = hex::encode([0x88; 32]);
    let socket = dir.path().join("dev").join("dm-agent.sock");
    let connector = AgentConnector::open(test_config(
        dir.path(),
        socket.clone(),
        vec![relay_url],
        false,
        false,
    ))
    .unwrap();
    let listener = bind_connector_socket(&socket).unwrap();

    let begun = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-stream-begin-cancel",
        AgentControlRequest::StreamBegin {
            account_id_hex: agent.account.account_id_hex,
            group_id_hex,
            stream_id_hex: Some(stream_id_hex.clone()),
            quic_candidates: vec!["quic://127.0.0.1:9".to_owned()],
        },
    )
    .await;
    assert!(matches!(
        begun.payload,
        AgentControlResponse::StreamBegun { .. }
    ));

    let status = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-stream-status",
        AgentControlRequest::StreamStatus {
            stream_id_hex: stream_id_hex.clone(),
            status: "thinking".to_owned(),
        },
    )
    .await;
    assert_eq!(status.payload, AgentControlResponse::Ack);

    let cancelled = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-stream-cancel",
        AgentControlRequest::StreamCancel {
            stream_id_hex: stream_id_hex.clone(),
            reason: Some("gateway_replaced_text".to_owned()),
        },
    )
    .await;
    assert_eq!(cancelled.payload, AgentControlResponse::Ack);

    let append_after_cancel = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-stream-append-after-cancel",
        AgentControlRequest::StreamAppend {
            stream_id_hex,
            append_text: "late".to_owned(),
        },
    )
    .await;
    let AgentControlResponse::Error { code, .. } = append_after_cancel.payload else {
        panic!("expected append-after-cancel error");
    };
    assert_eq!(code, "stream_error");
}

async fn connect_with_retry(socket: &Path) -> UnixStream {
    for _ in 0..100 {
        match UnixStream::connect(socket).await {
            Ok(stream) => return stream,
            Err(_) => sleep(Duration::from_millis(20)).await,
        }
    }
    UnixStream::connect(socket).await.unwrap()
}

async fn send_control_request(
    socket: &Path,
    id: &str,
    request: AgentControlRequest,
) -> AgentControlEnvelope<AgentControlResponse> {
    send_control_request_with_auth(socket, id, request, None).await
}

async fn send_control_request_with_auth(
    socket: &Path,
    id: &str,
    request: AgentControlRequest,
    auth_token: Option<&str>,
) -> AgentControlEnvelope<AgentControlResponse> {
    let client = connect_with_retry(socket).await;
    let (client_read, mut client_write) = tokio::io::split(client);
    let mut client_read = BufReader::new(client_read);
    let mut request = AgentControlEnvelope::request(Some(id.to_owned()), request);
    if let Some(auth_token) = auth_token {
        request = request.with_auth_token(auth_token);
    }
    write_frame(&mut client_write, &request).await.unwrap();
    timeout(CONTROL_RESPONSE_TIMEOUT, read_envelope(&mut client_read))
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}

async fn serve_control_request_once(
    connector: &AgentConnector,
    listener: &tokio::net::UnixListener,
    socket: &Path,
    id: &str,
    request: AgentControlRequest,
) -> AgentControlEnvelope<AgentControlResponse> {
    let (server, response) = tokio::join!(
        connector.serve_once(listener),
        send_control_request(socket, id, request)
    );
    server.unwrap();
    response
}

async fn serve_control_request_once_with_auth(
    connector: &AgentConnector,
    listener: &tokio::net::UnixListener,
    socket: &Path,
    id: &str,
    request: AgentControlRequest,
    auth_token: Option<&str>,
) -> AgentControlEnvelope<AgentControlResponse> {
    let (server, response) = tokio::join!(
        connector.serve_once(listener),
        send_control_request_with_auth(socket, id, request, auth_token)
    );
    server.unwrap();
    response
}

fn assert_allowlist(
    response: AgentControlEnvelope<AgentControlResponse>,
    expected_id: &str,
    expected_account_id_hex: &str,
    expected_welcomer_account_ids_hex: &[&str],
) {
    assert_eq!(response.id.as_deref(), Some(expected_id));
    let AgentControlResponse::Allowlist {
        account_id_hex,
        welcomer_account_ids_hex,
    } = response.payload
    else {
        panic!("expected allowlist response");
    };
    assert_eq!(account_id_hex, expected_account_id_hex);
    assert_eq!(
        welcomer_account_ids_hex,
        expected_welcomer_account_ids_hex
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
    );
}

fn expected_stream_transcript_hash(
    stream_id_hex: &str,
    start_message_id_hex: &str,
    records: &[(u8, &str)],
) -> String {
    let stream_id = hex::decode(stream_id_hex).unwrap();
    let start_event_id = MessageId::new(hex::decode(start_message_id_hex).unwrap());
    let mut transcript = AgentTextStreamTranscriptV1::new(stream_id, start_event_id);
    for (seq, (record_type, text)) in (1_u64..).zip(records.iter()) {
        transcript.append(seq, *record_type, text.as_bytes());
    }
    hex::encode(transcript.hash())
}

struct ExistingPendingInviteSetup {
    dir: tempfile::TempDir,
    _relay: MockRelay,
    relay_url: String,
    app: MarmotApp,
    agent_label: String,
    agent_account_id_hex: String,
    human_account_id_hex: String,
    group_id_hex: String,
}

async fn setup_existing_pending_invite(group_name: &str) -> ExistingPendingInviteSetup {
    let dir = tempfile::tempdir().unwrap();
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let app = MarmotApp::with_relay(dir.path(), relay_url.clone());
    let setup_runtime = MarmotAppRuntime::new(app.clone());
    let setup = AccountSetupRequest {
        default_relays: vec![crate::validation::endpoint(&relay_url)],
        bootstrap_relays: vec![crate::validation::endpoint(&relay_url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let agent = setup_runtime.create_identity(setup.clone()).await.unwrap();
    let human = setup_runtime.create_identity(setup).await.unwrap();

    let group_id = setup_runtime
        .create_group(
            &human.account.account_id_hex,
            group_name,
            std::slice::from_ref(&agent.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    let group_id_hex = hex::encode(group_id.as_slice());
    wait_for_group_state(&app, &agent.account.label, &group_id_hex, |group| {
        group.pending_confirmation && !group.archived
    })
    .await;
    setup_runtime.shutdown().await;

    ExistingPendingInviteSetup {
        dir,
        _relay: relay,
        relay_url,
        app,
        agent_label: agent.account.label,
        agent_account_id_hex: agent.account.account_id_hex,
        human_account_id_hex: human.account.account_id_hex,
        group_id_hex,
    }
}

async fn wait_for_group_state<F>(
    app: &MarmotApp,
    account_label: &str,
    group_id_hex: &str,
    mut predicate: F,
) where
    F: FnMut(&marmot_app::AppGroupRecord) -> bool,
{
    timeout(Duration::from_secs(30), async {
        loop {
            if let Some(group) = app.group(account_label, group_id_hex).unwrap()
                && predicate(&group)
            {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
}

async fn read_matching_inbound_message<R>(
    reader: &mut R,
    expected_text: &str,
) -> AgentControlEnvelope<AgentControlEvent>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    for _ in 0..10 {
        let event: AgentControlEnvelope<AgentControlEvent> =
            timeout(CONTROL_RESPONSE_TIMEOUT, read_envelope(reader))
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        if matches!(
            &event.payload,
            AgentControlEvent::InboundMessage { text, .. } if text == expected_text
        ) {
            return event;
        }
    }
    panic!("expected inbound message event with text {expected_text:?}");
}

#[test]
fn resync_required_event_carries_dropped_count_and_subscription_scope() {
    // Regression for darkmatter#210: a lagged inbound broadcast must surface a
    // ResyncRequired event (scoped to the subscription) instead of silently dropping
    // user messages to the agent.
    let event = resync_required_event(Some("aa"), Some("bb"), 42);
    assert_eq!(
        event,
        AgentControlEvent::ResyncRequired {
            account_id_hex: Some("aa".to_owned()),
            group_id_hex: Some("bb".to_owned()),
            dropped_events: 42,
        }
    );

    // An unscoped subscription leaves the fields None but still reports the drop count.
    let unscoped = resync_required_event(None, None, 7);
    assert_eq!(
        unscoped,
        AgentControlEvent::ResyncRequired {
            account_id_hex: None,
            group_id_hex: None,
            dropped_events: 7,
        }
    );
}

#[test]
fn control_event_from_debug_event_passes_resync_required_through_filters() {
    let resync = AgentControlEvent::ResyncRequired {
        account_id_hex: Some("aa".to_owned()),
        group_id_hex: Some("bb".to_owned()),
        dropped_events: 3,
    };

    // Matching filters keep the event.
    assert_eq!(
        control_event_from_debug_event(resync.clone(), Some("aa"), Some("bb")),
        Some(resync.clone())
    );
    // A non-matching account filter drops it.
    assert_eq!(
        control_event_from_debug_event(resync.clone(), Some("zz"), None),
        None
    );
    // No filters always keep it.
    assert_eq!(
        control_event_from_debug_event(resync.clone(), None, None),
        Some(resync)
    );
}

fn received_chat_record(
    message_id_hex: &str,
    group_id_hex: &str,
    sender: &str,
    text: &str,
) -> AppMessageRecord {
    AppMessageRecord {
        message_id_hex: message_id_hex.to_owned(),
        direction: "received".to_owned(),
        group_id_hex: group_id_hex.to_owned(),
        sender: sender.to_owned(),
        plaintext: text.to_owned(),
        kind: MARMOT_APP_EVENT_KIND_CHAT,
        tags: Vec::new(),
        source_epoch: Some(1),
        recorded_at: 100,
        received_at: 100,
    }
}

#[test]
fn inbound_message_event_from_record_projects_received_chat() {
    // Regression for darkmatter#210: a missed inbound chat recovered from storage must
    // project into exactly the same InboundMessage event the live path emits, so the
    // consumer's existing handler delivers it to the agent.
    let record = received_chat_record("aa", "bb", "cc", "hello agent");
    let event =
        inbound_message_event_from_record("acct", record, Some("acct"), Some("bb")).unwrap();
    assert_eq!(
        event,
        AgentControlEvent::InboundMessage {
            account_id_hex: "acct".to_owned(),
            group_id_hex: "bb".to_owned(),
            message_id_hex: "aa".to_owned(),
            sender_account_id_hex: "cc".to_owned(),
            text: "hello agent".to_owned(),
            mentions_self: false,
            reply_to_message_id_hex: None,
            sender_display_name: None,
            media: Vec::new(),
        }
    );
}

#[test]
fn inbound_message_event_from_record_projects_received_delete() {
    // Regression for darkmatter#505: storage replay must surface a missed inbound kind-5
    // deletion the same way the live MessageReceived path does.
    let target = "99".repeat(32);
    let mut record = received_chat_record("dd", "bb", "cc", "");
    record.kind = MARMOT_APP_EVENT_KIND_DELETE;
    record.tags = vec![vec!["e".to_owned(), target.clone()]];

    let event =
        inbound_message_event_from_record("acct", record, Some("acct"), Some("bb")).unwrap();
    assert_eq!(
        event,
        AgentControlEvent::MessageDeleted {
            account_id_hex: "acct".to_owned(),
            group_id_hex: "bb".to_owned(),
            target_message_id_hex: target,
            sender_account_id_hex: "cc".to_owned(),
        }
    );
}

#[test]
fn inbound_message_event_from_record_projects_group_system_row() {
    // Regression for darkmatter#505: durable kind-1210 group-system rows synthesized from
    // GroupStateChanged events must replay as group_state_changed control events after lag.
    let content = cgka_traits::app_event::GroupSystemEvent::new(
        cgka_traits::app_event::GROUP_SYSTEM_TYPE_GROUP_RENAMED,
        "Group renamed",
        Some(serde_json::json!({
            cgka_traits::app_event::GROUP_SYSTEM_DATA_NAME: "Team",
            // Subject/actor-like data must not be surfaced in the control event.
            cgka_traits::app_event::GROUP_SYSTEM_DATA_SUBJECT: "99".repeat(32),
        })),
    )
    .to_content()
    .unwrap();
    let mut record = received_chat_record("ee", "bb", "", &content);
    record.direction = "system".to_owned();
    record.kind = MARMOT_APP_EVENT_KIND_GROUP_SYSTEM;

    let event =
        inbound_message_event_from_record("acct", record, Some("acct"), Some("bb")).unwrap();
    assert_eq!(
        event,
        AgentControlEvent::GroupStateChanged {
            account_id_hex: "acct".to_owned(),
            group_id_hex: "bb".to_owned(),
            change: "group_renamed".to_owned(),
            detail: Some("Team".to_owned()),
        }
    );
}

#[test]
fn runtime_replay_dedup_key_matches_group_system_storage_row_id() {
    // The live GroupStateChanged event and the synthesized storage row must share the same
    // replay cursor id, otherwise replay after later lag would duplicate already-delivered state.
    let group_id = GroupId::new(vec![0x22; 32]);
    let actor = cgka_traits::MemberId::new(vec![0xbb; 32]);
    let event = MarmotAppEvent::GroupEvent(marmot_app::RuntimeGroupEvent {
        account_id_hex: "acct".to_owned(),
        account_label: "agent".to_owned(),
        event: GroupEvent::GroupStateChanged {
            group_id: group_id.clone(),
            epoch: EpochId(3),
            actor: Some(actor.clone()),
            change: GroupStateChange::GroupRenamed {
                name: "Team".to_owned(),
            },
            origin_commit_id: None,
        },
    });

    let content = cgka_traits::app_event::GroupSystemEvent::new(
        cgka_traits::app_event::GROUP_SYSTEM_TYPE_GROUP_RENAMED,
        "Group renamed",
        Some(serde_json::json!({
            cgka_traits::app_event::GROUP_SYSTEM_DATA_ACTOR: hex::encode(actor.as_slice()),
            cgka_traits::app_event::GROUP_SYSTEM_DATA_NAME: "Team",
        })),
    )
    .to_content()
    .unwrap();
    let tags = vec![vec![
        cgka_traits::app_event::GROUP_SYSTEM_TYPE_TAG.to_owned(),
        cgka_traits::app_event::GROUP_SYSTEM_TYPE_GROUP_RENAMED.to_owned(),
    ]];
    let group_id_hex = hex::encode(group_id.as_slice());
    let expected = cgka_traits::app_event::canonical_event_id(
        &hex::encode(actor.as_slice()),
        3,
        MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
        &tags,
        &format!("{group_id_hex}\u{1f}{content}"),
    );

    assert_eq!(
        runtime_replay_dedup_key(&event).as_deref(),
        Some(expected.as_str())
    );
}

#[test]
fn inbound_message_event_from_record_extracts_mention_and_reply() {
    // A `p`-tag for the receiving account marks a mention; the first `e`-tag is
    // the reply target. Both let a channel gate/thread without re-parsing tags.
    let parent_msg_id = "bb".repeat(32);
    let mut record = received_chat_record("aa", "bb", "cc", "hey there");
    record.tags = vec![
        vec!["p".to_owned(), "acct".to_owned()],
        vec!["e".to_owned(), parent_msg_id.clone()],
    ];
    let event =
        inbound_message_event_from_record("acct", record, Some("acct"), Some("bb")).unwrap();
    let AgentControlEvent::InboundMessage {
        mentions_self,
        reply_to_message_id_hex,
        ..
    } = event
    else {
        panic!("expected inbound message event");
    };
    assert!(mentions_self, "p-tag for the account should mark a mention");
    assert_eq!(
        reply_to_message_id_hex.as_deref(),
        Some(parent_msg_id.as_str())
    );
}

#[test]
fn inbound_message_event_detects_inline_nostr_mention() {
    // Marmot clients address a member with an inline `nostr:<pubkey-hex>` token
    // (no p-tag), and the account id IS the pubkey hex.
    let record = received_chat_record("aa", "bb", "cc", "hey nostr:acct can you help?");
    let event =
        inbound_message_event_from_record("acct", record, Some("acct"), Some("bb")).unwrap();
    let AgentControlEvent::InboundMessage { mentions_self, .. } = event else {
        panic!("expected inbound message event");
    };
    assert!(mentions_self, "inline nostr:<pubkey> should mark a mention");
}

#[test]
fn inbound_message_event_detects_npub_bech32_mention() {
    // A p-tag-less mention whose inline text is the bech32 `nostr:npub1…` form
    // (what marmot-markdown renders) must still be detected.
    let account = "aa".repeat(32);
    let npub = marmot_app::npub_for_account_id(&account).unwrap();
    let text = format!("hey nostr:{npub} can you help?");
    let record = received_chat_record("11", "bb", "cc", &text);
    let event = inbound_message_event_from_record(&account, record, None, Some("bb")).unwrap();
    let AgentControlEvent::InboundMessage { mentions_self, .. } = event else {
        panic!("expected inbound message event");
    };
    assert!(
        mentions_self,
        "inline nostr:<npub> bech32 mention should be detected"
    );
}

#[test]
fn inbound_message_event_detects_p_tag_mention_without_inline_text() {
    // The p-tag is authoritative: a mention with only the structured tag (no
    // inline nostr: reference in the body) is still detected.
    let account = "aa".repeat(32);
    let mut record = received_chat_record("11", "bb", "cc", "please take a look");
    record.tags = vec![vec!["p".to_owned(), account.clone()]];
    let event = inbound_message_event_from_record(&account, record, None, Some("bb")).unwrap();
    let AgentControlEvent::InboundMessage { mentions_self, .. } = event else {
        panic!("expected inbound message event");
    };
    assert!(
        mentions_self,
        "p-tag mention should be detected without inline text"
    );
}

#[test]
fn safe_media_filename_strips_path_traversal() {
    use crate::messaging::safe_media_filename;
    assert_eq!(safe_media_filename("a.png"), "a.png");
    assert_eq!(safe_media_filename("../../etc/passwd"), "passwd");
    assert_eq!(safe_media_filename("dir/b.jpg"), "b.jpg");
    assert_eq!(safe_media_filename(".."), "media");
    assert_eq!(safe_media_filename(""), "media");
}

#[test]
fn inbound_message_event_from_record_skips_non_inbound_and_own_and_filtered() {
    // Outbound (own) messages are never re-delivered as inbound.
    let mut own = received_chat_record("aa", "bb", "acct", "mine");
    own.direction = "sent".to_owned();
    assert!(inbound_message_event_from_record("acct", own, None, None).is_none());

    // A received message authored by the subscribed account itself is skipped (mirrors live).
    let self_authored = received_chat_record("aa", "bb", "acct", "loopback");
    assert!(inbound_message_event_from_record("acct", self_authored, None, None).is_none());

    // Unsupported non-chat kinds (reactions, agent stream starts) are not replayed.
    let mut reaction = received_chat_record("aa", "bb", "cc", "+1");
    reaction.kind = MARMOT_APP_EVENT_KIND_AGENT_STREAM_START;
    assert!(inbound_message_event_from_record("acct", reaction, None, None).is_none());

    // A group-system row that was received as an app message, rather than synthesized locally,
    // is not treated as a durable GroupStateChanged replay event.
    let mut received_system = received_chat_record("aa", "bb", "cc", "{}");
    received_system.kind = MARMOT_APP_EVENT_KIND_GROUP_SYSTEM;
    assert!(inbound_message_event_from_record("acct", received_system, None, None).is_none());

    // A mismatched group filter excludes the message.
    let other_group = received_chat_record("aa", "bb", "cc", "elsewhere");
    assert!(
        inbound_message_event_from_record("acct", other_group, Some("acct"), Some("zz")).is_none()
    );
}

#[test]
fn delivered_inbound_cursor_dedups_and_evicts_oldest() {
    let mut cursor = DeliveredInboundCursor::new(3);
    assert!(!cursor.contains("a"));
    cursor.record("a".to_owned());
    cursor.record("b".to_owned());
    cursor.record("c".to_owned());
    assert!(cursor.contains("a"));
    assert!(cursor.contains("c"));

    // Re-recording an existing id is a no-op and does not evict anything.
    cursor.record("a".to_owned());
    assert!(cursor.contains("b"));

    // Exceeding capacity evicts the oldest id ("a"), keeping the most recent three.
    cursor.record("d".to_owned());
    assert!(
        !cursor.contains("a"),
        "oldest id should be evicted at capacity"
    );
    assert!(cursor.contains("b"));
    assert!(cursor.contains("c"));
    assert!(cursor.contains("d"));
}

#[tokio::test]
async fn replay_missed_inbound_recovers_dropped_messages_and_dedups() {
    // End-to-end regression for darkmatter#210: when the inbound broadcast lags, the
    // connector re-queries storage and re-delivers the genuinely-missed inbound messages on
    // the existing InboundMessage path the consumer already handles. A real send populates
    // storage; replay must surface it, and a second replay (with the id already delivered)
    // must not re-deliver it.
    let dir = tempfile::tempdir().unwrap();
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let app = MarmotApp::with_relay(dir.path(), relay_url.clone());
    let setup_runtime = MarmotAppRuntime::new(app);
    let setup = AccountSetupRequest {
        default_relays: vec![crate::validation::endpoint(&relay_url)],
        bootstrap_relays: vec![crate::validation::endpoint(&relay_url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let agent = setup_runtime.create_identity(setup.clone()).await.unwrap();
    let human = setup_runtime.create_identity(setup).await.unwrap();
    let group_id = setup_runtime
        .create_group(
            &agent.account.account_id_hex,
            "agent inbound replay",
            std::slice::from_ref(&human.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    setup_runtime.shutdown().await;
    let group_id_hex = hex::encode(group_id.as_slice());

    let connector = AgentConnector::open(test_config(
        dir.path(),
        dir.path().join("dev").join("dm-agent.sock"),
        vec![relay_url],
        false,
        false,
    ))
    .unwrap();

    // Deliver a real inbound message into storage via a normal send + catch-up.
    connector.runtime.catch_up_accounts().await.unwrap();
    let _ = connector
        .send_final_response(
            &human.account.account_id_hex,
            &group_id_hex,
            "missed while lagging".to_owned(),
            None,
            None,
        )
        .await
        .unwrap();
    // Let the agent account observe the message so it lands in its storage projection.
    for _ in 0..40 {
        connector.runtime.catch_up_accounts().await.unwrap();
        let stored = connector
            .runtime
            .messages_with_query(
                &agent.account.account_id_hex,
                crate::AppMessageQuery {
                    group_id_hex: Some(group_id_hex.clone()),
                    limit: None,
                },
            )
            .unwrap();
        if stored.iter().any(|m| m.plaintext == "missed while lagging") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // First replay surfaces the missed inbound message as an InboundMessage event.
    let mut delivered = DeliveredInboundCursor::new(crate::DELIVERED_INBOUND_CURSOR_CAPACITY);
    let replayed = connector
        .replay_missed_inbound(
            Some(&agent.account.account_id_hex),
            Some(&group_id_hex),
            &mut delivered,
        )
        .unwrap();
    let recovered: Vec<_> = replayed
        .iter()
        .filter_map(|event| match event {
            AgentControlEvent::InboundMessage {
                text,
                sender_account_id_hex,
                ..
            } => Some((text.clone(), sender_account_id_hex.clone())),
            _ => None,
        })
        .collect();
    assert!(
        recovered
            .iter()
            .any(|(text, sender)| text == "missed while lagging"
                && sender == &human.account.account_id_hex),
        "replay should recover the missed inbound message, got {recovered:?}"
    );

    // Second replay must not re-deliver the same message (cursor dedup).
    let replayed_again = connector
        .replay_missed_inbound(
            Some(&agent.account.account_id_hex),
            Some(&group_id_hex),
            &mut delivered,
        )
        .unwrap();
    assert!(
        !replayed_again.iter().any(|event| matches!(
            event,
            AgentControlEvent::InboundMessage { text, .. } if text == "missed while lagging"
        )),
        "second replay must not duplicate an already-delivered message"
    );
}

#[tokio::test]
async fn send_final_with_repeated_idempotency_key_dedups_without_second_send() {
    // GAP-06: a retry that reuses the same idempotency key must return the
    // ORIGINAL durable message ids without re-sending, so a post-write-timeout
    // retry can never double-post an unrecallable encrypted message. Observable
    // proof of "no second send": only one copy of the text lands in storage.
    let dir = tempfile::tempdir().unwrap();
    let relay = MockRelay::run().await.unwrap();
    let relay_url = relay.url().await.to_string();
    let app = MarmotApp::with_relay(dir.path(), relay_url.clone());
    let setup_runtime = MarmotAppRuntime::new(app);
    let setup = AccountSetupRequest {
        default_relays: vec![crate::validation::endpoint(&relay_url)],
        bootstrap_relays: vec![crate::validation::endpoint(&relay_url)],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    };
    let agent = setup_runtime.create_identity(setup.clone()).await.unwrap();
    let human = setup_runtime.create_identity(setup).await.unwrap();
    let group_id = setup_runtime
        .create_group(
            &agent.account.account_id_hex,
            "agent idempotent send",
            std::slice::from_ref(&human.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    setup_runtime.shutdown().await;
    let group_id_hex = hex::encode(group_id.as_slice());

    let connector = AgentConnector::open(test_config(
        dir.path(),
        dir.path().join("dev").join("dm-agent.sock"),
        vec![relay_url],
        false,
        false,
    ))
    .unwrap();
    connector.runtime.catch_up_accounts().await.unwrap();

    let key = "retry-key-1".to_owned();
    let AgentControlResponse::FinalSent {
        message_ids_hex: first_ids,
    } = connector
        .send_final_response(
            &agent.account.account_id_hex,
            &group_id_hex,
            "idempotent reply".to_owned(),
            None,
            Some(key.clone()),
        )
        .await
        .unwrap()
    else {
        panic!("expected first send to return FinalSent");
    };
    assert!(!first_ids.is_empty(), "a real send returns message ids");

    // Second call with the SAME key returns the cached ids verbatim.
    let AgentControlResponse::FinalSent {
        message_ids_hex: second_ids,
    } = connector
        .send_final_response(
            &agent.account.account_id_hex,
            &group_id_hex,
            "idempotent reply".to_owned(),
            None,
            Some(key),
        )
        .await
        .unwrap()
    else {
        panic!("expected second send to return cached FinalSent");
    };
    assert_eq!(
        second_ids, first_ids,
        "a repeated idempotency key must return the original message ids"
    );

    // Observable proof there was no second underlying send: exactly one copy of
    // the text exists in the agent's own group storage projection.
    let stored = connector
        .runtime
        .messages_with_query(
            &agent.account.account_id_hex,
            crate::AppMessageQuery {
                group_id_hex: Some(group_id_hex.clone()),
                limit: None,
            },
        )
        .unwrap();
    let copies = stored
        .iter()
        .filter(|m| m.plaintext == "idempotent reply")
        .count();
    assert_eq!(copies, 1, "a deduped retry must not re-post the message");
}

#[test]
fn send_idempotency_store_returns_recorded_ids_for_a_key() {
    use crate::stream_session::SendIdempotencyStore;

    let store = SendIdempotencyStore::default();
    assert_eq!(store.get("k1", 7), None, "an unseen key has no cached ids");

    let ids = vec!["aa".repeat(32), "bb".repeat(32)];
    store.record("k1".to_owned(), 7, ids.clone());
    assert_eq!(
        store.get("k1", 7),
        Some(ids),
        "a recorded key returns its message ids for a matching fingerprint"
    );
    assert_eq!(
        store.get("k1", 8),
        None,
        "a recorded key with a non-matching fingerprint is a cache miss"
    );
    assert_eq!(store.get("k2", 7), None, "an unrelated key stays absent");
}

#[test]
fn send_idempotency_store_keeps_first_recorded_ids_for_a_key() {
    use crate::stream_session::SendIdempotencyStore;

    let store = SendIdempotencyStore::default();
    let first = vec!["11".repeat(32)];
    let second = vec!["22".repeat(32)];
    store.record("dup".to_owned(), 1, first.clone());
    // A repeat record (e.g. a racing duplicate) must not overwrite the original
    // committed entry: the first successful send for a key always wins, even if
    // the later record carries a different fingerprint.
    store.record("dup".to_owned(), 2, second);
    assert_eq!(store.get("dup", 1), Some(first));
}

#[test]
fn send_idempotency_store_evicts_oldest_keys_past_capacity() {
    use crate::stream_session::SendIdempotencyStore;

    // Cap is 1024; fill past it and assert the oldest key is evicted FIFO while
    // the newest remain. This bounds memory for a long-lived connector.
    let store = SendIdempotencyStore::default();
    for n in 0..1100u32 {
        store.record(format!("key-{n}"), u64::from(n), vec![format!("{n:064x}")]);
    }
    assert_eq!(store.get("key-0", 0), None, "oldest key must be evicted");
    assert_eq!(store.get("key-75", 75), None, "early keys must be evicted");
    assert_eq!(
        store.get("key-1099", 1099),
        Some(vec![format!("{:064x}", 1099)]),
        "the newest key must still be cached"
    );
    assert_eq!(
        store.get("key-200", 200),
        Some(vec![format!("{:064x}", 200)]),
        "a key within the retained window must still be cached"
    );
}
