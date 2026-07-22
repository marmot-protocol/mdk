//! White-box tests for the connector exercising private/`pub(crate)` internals across modules.

use agent_control::{
    AGENT_CONTROL_STREAM_STATUS_STARTED, AgentControlEnvelope, AgentControlEvent,
    AgentControlRequest, AgentControlResponse, read_envelope, write_frame,
};
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN, AGENT_TEXT_STREAM_RECORD_STATUS,
    AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, AgentTextStreamTranscriptV1,
};
use cgka_traits::app_event::{
    MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY, MARMOT_APP_EVENT_KIND_AGENT_OPERATION,
    MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, MARMOT_APP_EVENT_KIND_CHAT,
    MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_EDIT, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
    MARMOT_APP_EVENT_KIND_REACTION, STREAM_PARENT_TAG, STREAM_TAG,
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

#[tokio::test]
async fn control_operation_timeout_bounds_a_stalled_whole_operation() {
    let started = tokio::time::Instant::now();
    let error = crate::with_control_operation_timeout_after(
        "test_stalled_operation",
        Duration::from_millis(10),
        std::future::pending::<()>(),
    )
    .await
    .expect_err("a stalled operation must time out");

    assert!(matches!(
        error,
        crate::ConnectorError::OperationTimedOut("test_stalled_operation")
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn control_frame_write_timeout_includes_flush() {
    struct FlushStallingWriter;

    impl tokio::io::AsyncWrite for FlushStallingWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    let response = AgentControlEnvelope::new(None, AgentControlResponse::Ack);
    let error = crate::connection::write_control_frame_with_timeout(
        &mut FlushStallingWriter,
        &response,
        Duration::from_millis(10),
    )
    .await
    .expect_err("a stalled flush must time out");

    assert!(matches!(
        error,
        crate::ConnectorError::OperationTimedOut("control_frame_write")
    ));
}

#[test]
fn inbound_subscription_quota_preserves_one_shot_capacity() {
    let limiter = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let subscription = AgentControlRequest::SubscribeInbound {
        account_id_hex: None,
        group_id_hex: None,
    };

    let first = crate::connection::try_acquire_inbound_subscription(&subscription, &limiter)
        .expect("first subscription should be admitted")
        .expect("subscription should hold a permit");
    assert!(
        crate::connection::try_acquire_inbound_subscription(&subscription, &limiter).is_err(),
        "a second subscription must hit the dedicated cap"
    );
    assert!(
        crate::connection::try_acquire_inbound_subscription(
            &AgentControlRequest::AccountList,
            &limiter,
        )
        .expect("one-shot requests bypass the subscription cap")
        .is_none()
    );

    drop(first);
    assert!(
        crate::connection::try_acquire_inbound_subscription(&subscription, &limiter)
            .expect("released subscription capacity should be reusable")
            .is_some()
    );
}

#[test]
fn poisoned_connector_store_mutex_recovers_inner_state() {
    let mutex = std::sync::Arc::new(std::sync::Mutex::new(vec![1]));
    let panic_mutex = std::sync::Arc::clone(&mutex);

    let panic_result = std::thread::spawn(move || {
        let mut values = panic_mutex.lock().expect("initial lock should succeed");
        values.push(2);
        panic!("poison test mutex");
    })
    .join();
    assert!(panic_result.is_err());

    crate::lock_recover(&mutex).push(3);
    assert_eq!(*crate::lock_recover(&mutex), vec![1, 2, 3]);
}

#[test]
fn profile_name_validation_rejects_non_whitespace_control_characters() {
    use crate::validation::validate_profile_name;

    assert_eq!(
        validate_profile_name("  Alice\nAgent  ".to_owned()).unwrap(),
        "Alice Agent"
    );
    for name in ["Alice\u{1b}[2J", "Alice\0Agent", "Alice\u{7}Agent"] {
        assert!(matches!(
            validate_profile_name(name.to_owned()),
            Err(crate::ConnectorError::InvalidProfileName(
                "control_characters"
            ))
        ));
    }
}

fn test_config(
    home: &Path,
    socket: impl Into<std::path::PathBuf>,
    relays: Vec<String>,
    dev_allow_any_invites: bool,
    debug_controls: bool,
) -> AgentConnectorConfig {
    let mut config = AgentConnectorConfig::new(home);
    config.socket = socket.into();
    config.relays = relays;
    config.dev_allow_any_invites = dev_allow_any_invites;
    config.debug_controls = debug_controls;
    config.media_allowed_roots = Vec::new();
    // The white-box suite drives streams at loopback brokers and connects to an
    // in-process `MockRelay` at loopback; production defaults keep both off (see
    // `allow_insecure_local_broker` / `allow_loopback_relays`).
    config.allow_insecure_local_broker = true;
    config.allow_loopback_relays = true;
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
        received_at: 84,
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
                previous_name: None,
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
            stream_capability: [0x77; 32],
            start_message_id_hex: "00".to_owned(),
            tx: idle_tx,
            cancel_tx: idle_cancel_tx,
            abort: idle_handle.abort_handle(),
            last_activity: Instant::now() - Duration::from_secs(3600),
            finalized: None,
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
            stream_capability: [0x77; 32],
            start_message_id_hex: "00".to_owned(),
            tx: active_tx,
            cancel_tx: active_cancel_tx,
            abort: active_handle.abort_handle(),
            last_activity: Instant::now(),
            finalized: None,
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

/// A finalized-but-unpublished session must survive the idle sweep even when
/// its last activity is well past the timeout: its compose task has exited and
/// the frozen transcript is the only handle for retrying a failed durable
/// finish. Sweeping it would recreate the #366 failure mode.
#[tokio::test]
async fn stream_session_sweep_spares_finalized_session_despite_idle() {
    use crate::stream_session::{ActiveStreamSession, FinalizedStream, StreamSessionStore};
    use agent_stream_compose::StreamComposeCommand;
    use cgka_traits::GroupId;
    use std::time::{Duration, Instant};

    let store = StreamSessionStore::default();

    // The compose task has already exited after a validated Finish; model that
    // with an immediately-finished task so its Sender is closed like the real
    // post-finalize session.
    let (tx, rx) = tokio::sync::mpsc::channel::<StreamComposeCommand>(4);
    drop(rx);
    let (cancel_tx, _cancel_rx) = tokio::sync::mpsc::channel::<()>(1);
    let handle = tokio::spawn(async {});
    store.insert(
        "aa".to_owned(),
        ActiveStreamSession {
            account_label: "agent".to_owned(),
            group_id: GroupId::new(vec![1]),
            stream_id: vec![0xaa],
            stream_capability: [0x77; 32],
            start_message_id_hex: "00".to_owned(),
            tx,
            cancel_tx,
            abort: handle.abort_handle(),
            // Idle far beyond the timeout, but finalized: must be spared.
            last_activity: Instant::now() - Duration::from_secs(3600),
            finalized: Some(FinalizedStream {
                final_text: "frozen".to_owned(),
                transcript_hash: [0x22; 32],
                chunk_count: 1,
            }),
        },
    );

    let swept = store.sweep_idle(Duration::from_secs(300));
    assert_eq!(swept, 0, "a finalized session must never be swept");
    assert!(
        store.get("aa").is_ok(),
        "the finalized session (and its retry handle) must survive the sweep"
    );
}

#[tokio::test]
async fn connector_socket_bind_removes_stale_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dev").join("wn-agent.sock");
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
    let socket = dir.path().join("dev").join("wn-agent.sock");
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    std::fs::write(&socket, b"not a socket").unwrap();

    let error = bind_connector_socket(&socket).unwrap_err();

    assert_eq!(error.code(), "io_error");
    assert_eq!(std::fs::read(&socket).unwrap(), b"not a socket");
}

#[tokio::test]
async fn connector_socket_bind_applies_configured_group_modes() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dev").join("wn-agent.sock");

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
    assert!(
        !fs_private::socket_staging_dir(&socket).exists(),
        "staging dir should be removed after bind"
    );
}

#[tokio::test]
async fn connector_socket_bind_preserves_preexisting_custom_parent_mode() {
    let dir = tempfile::tempdir().unwrap();
    let shared_parent = dir.path().join("s");
    std::fs::create_dir(&shared_parent).unwrap();
    std::fs::set_permissions(&shared_parent, std::fs::Permissions::from_mode(0o750)).unwrap();
    let socket = shared_parent.join("a");

    let listener = bind_connector_socket_with_mode(&socket, 0o700, 0o600).unwrap();

    assert!(listener.local_addr().is_ok());
    assert_eq!(
        shared_parent.metadata().unwrap().permissions().mode() & 0o777,
        0o750
    );
}

#[tokio::test]
async fn connector_socket_bind_rejects_symlinked_parent_without_chmodding_target() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    let link = dir.path().join("dev");
    std::fs::create_dir(&target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    symlink(&target, &link).unwrap();

    let error = bind_connector_socket_with_mode(&link.join("wn-agent.sock"), 0o700, 0o600)
        .expect_err("symlinked socket parent must be rejected");

    assert_eq!(error.code(), "io_error");
    assert_eq!(
        target.metadata().unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert!(!target.join("wn-agent.sock").exists());
}

#[tokio::test]
async fn connector_socket_bind_rejects_unconfigured_group_writable_parent() {
    let dir = tempfile::tempdir().unwrap();
    let shared_parent = dir.path().join("shared");
    std::fs::create_dir(&shared_parent).unwrap();
    std::fs::set_permissions(&shared_parent, std::fs::Permissions::from_mode(0o770)).unwrap();

    let error = bind_connector_socket_with_mode(&shared_parent.join("wn-agent.sock"), 0o700, 0o600)
        .expect_err("unexpected group write access must be rejected");

    assert_eq!(error.code(), "io_error");
    assert!(!shared_parent.join("wn-agent.sock").exists());
}

#[tokio::test]
async fn connector_control_plane_requires_token_for_group_shared_modes() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dev").join("wn-agent.sock");
    let mut config = test_config(dir.path(), socket, Vec::new(), false, false);
    config.socket_dir_mode = 0o770;
    config.socket_mode = 0o660;

    let error = serve_socket(config).await.unwrap_err();

    assert_eq!(error.code(), "unsafe_control_plane_config");
}

#[tokio::test]
async fn connector_control_plane_rejects_world_accessible_modes() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dev").join("wn-agent.sock");
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
    let socket = dir.path().join("dev").join("wn-agent.sock");
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
async fn connector_socket_caps_concurrent_connections() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dev").join("wn-agent.sock");
    let mut config = test_config(dir.path(), socket.clone(), Vec::new(), false, false);
    config.max_connections = 1;
    let server = tokio::spawn(serve_socket(config));

    // A long-lived subscription holds the only permit for its whole session;
    // the ack proves it is accepted and served before the second connection.
    let held = connect_with_retry(&socket).await;
    let (held_read, mut held_write) = tokio::io::split(held);
    let mut held_read = BufReader::new(held_read);
    let request = AgentControlEnvelope::request(
        Some("req-held".to_owned()),
        AgentControlRequest::SubscribeInbound {
            account_id_hex: None,
            group_id_hex: None,
        },
    );
    write_frame(&mut held_write, &request).await.unwrap();
    let response: AgentControlEnvelope<AgentControlResponse> =
        timeout(CONTROL_RESPONSE_TIMEOUT, read_envelope(&mut held_read))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    assert_eq!(response.id.as_deref(), Some("req-held"));
    assert_eq!(response.payload, AgentControlResponse::Ack);

    // A second concurrent connection is over the global cap and receives a
    // typed busy response rather than an ambiguous empty close.
    let refused = UnixStream::connect(&socket).await.unwrap();
    let (refused_read, mut refused_write) = tokio::io::split(refused);
    let mut refused_read = BufReader::new(refused_read);
    let request = AgentControlEnvelope::request(
        Some("req-refused".to_owned()),
        AgentControlRequest::AccountList,
    );
    let _ = write_frame(&mut refused_write, &request).await;
    let refused_response: AgentControlEnvelope<AgentControlResponse> =
        timeout(CONTROL_RESPONSE_TIMEOUT, read_envelope(&mut refused_read))
            .await
            .expect("busy response should not time out")
            .expect("busy response should be a valid frame")
            .expect("busy response should not be empty");
    assert!(matches!(
        refused_response.payload,
        AgentControlResponse::Error { ref code, .. } if code == "server_busy"
    ));

    // Dropping the held connection frees the permit for a new connection.
    drop(held_read);
    drop(held_write);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let client = connect_with_retry(&socket).await;
        let (client_read, mut client_write) = tokio::io::split(client);
        let mut client_read = BufReader::new(client_read);
        let request = AgentControlEnvelope::request(
            Some("req-after-release".to_owned()),
            AgentControlRequest::AccountList,
        );
        if write_frame(&mut client_write, &request).await.is_ok()
            && let Ok(Ok(Some(response))) = timeout(
                Duration::from_secs(2),
                read_envelope::<_, AgentControlResponse>(&mut client_read),
            )
            .await
        {
            assert_eq!(response.id.as_deref(), Some("req-after-release"));
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "released permit must allow a new connection to be served"
        );
        sleep(Duration::from_millis(50)).await;
    }

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn connector_control_plane_rejects_zero_connection_cap() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dev").join("wn-agent.sock");
    let mut config = test_config(dir.path(), socket, Vec::new(), false, false);
    config.max_connections = 0;

    let error = serve_socket(config).await.unwrap_err();

    assert_eq!(error.code(), "unsafe_control_plane_config");
}

#[tokio::test]
async fn connector_socket_requires_configured_auth_token() {
    let dir = tempfile::tempdir().unwrap();
    let account_home = AccountHome::open(dir.path());
    let account = account_home.create_account("agent").unwrap();
    let socket = dir.path().join("dev").join("wn-agent.sock");
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
    let socket = dir.path().join("dev").join("wn-agent.sock");
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
    let socket = dir.path().join("dev").join("wn-agent.sock");
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
    let socket = dir.path().join("dev").join("wn-agent.sock");
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
    let socket = dir.path().join("dev").join("wn-agent.sock");
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
    let socket = dir.path().join("dev").join("wn-agent.sock");
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
            stream_capability: [0x77; 32],
            start_message_id_hex: "00".to_owned(),
            tx,
            cancel_tx,
            abort: handle.abort_handle(),
            last_activity: Instant::now(),
            finalized: None,
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
            stream_capability: [0x77; 32],
            start_message_id_hex: "00".to_owned(),
            tx,
            cancel_tx,
            abort,
            last_activity: Instant::now() - Duration::from_secs(3600),
            finalized: None,
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

    let socket = agent_dir.path().join("dev").join("wn-agent.sock");
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

    let socket = agent_dir.path().join("dev").join("wn-agent.sock");
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
async fn connector_policy_dev_allow_any_accepts_unlisted_authenticated_welcomer() {
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

    let socket = agent_dir.path().join("dev").join("wn-agent.sock");
    let server = tokio::spawn(serve_socket(test_config(
        agent_dir.path(),
        socket.clone(),
        vec![relay_url],
        true,
        true,
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

#[test]
fn dev_allow_any_invites_still_requires_an_authenticated_welcomer() {
    assert!(crate::invite_policy::invite_policy_allows(
        true, true, false
    ));
    assert!(!crate::invite_policy::invite_policy_allows(
        true, false, false
    ));
}

#[test]
fn dev_allow_any_invites_requires_debug_controls() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(
        dir.path(),
        dir.path().join("dev").join("wn-agent.sock"),
        Vec::new(),
        true,
        false,
    );
    config.debug_controls = false;

    let error = crate::validation::validate_control_plane_config(&config)
        .expect_err("dev allow-any must require debug controls");
    assert_eq!(error.code(), "unsafe_control_plane_config");
}

#[tokio::test]
async fn connector_start_reconciles_existing_allowed_pending_invite() {
    let setup = setup_existing_pending_invite("existing pending invite").await;
    let connector = AgentConnector::open(test_config(
        setup.dir.path(),
        setup.dir.path().join("dev").join("wn-agent.sock"),
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
        setup.dir.path().join("dev").join("wn-agent.sock"),
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
    let socket = dir.path().join("dev").join("wn-agent.sock");
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
    let socket = dir.path().join("dev").join("wn-agent.sock");
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
    let socket = dir.path().join("dev").join("wn-agent.sock");
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
        dir.path().join("dev").join("wn-agent.sock"),
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
    let socket = dir.path().join("dev").join("wn-agent.sock");
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
    let parent_message_id_hex = hex::encode([0x88; 32]);
    let socket = dir.path().join("dev").join("wn-agent.sock");
    let connector = AgentConnector::open(test_config(
        dir.path(),
        socket.clone(),
        vec![relay_url],
        false,
        false,
    ))
    .unwrap();
    let listener = bind_connector_socket(&socket).unwrap();

    let missing_begin_id = connector
        .stream_begin_response(
            None,
            &agent.account.account_id_hex,
            &group_id_hex,
            Some(stream_id_hex.clone()),
            Some(parent_message_id_hex.clone()),
            vec!["quic://127.0.0.1:9".to_owned()],
        )
        .await;
    assert!(matches!(
        missing_begin_id,
        Err(crate::ConnectorError::InvalidStreamBeginRequestId)
    ));

    let begin_request = AgentControlRequest::StreamBegin {
        account_id_hex: agent.account.account_id_hex.clone(),
        group_id_hex: group_id_hex.clone(),
        stream_id_hex: Some(stream_id_hex.clone()),
        parent_message_id_hex: Some(parent_message_id_hex.clone()),
        quic_candidates: vec!["quic://127.0.0.1:9".to_owned()],
    };
    let begun = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-stream-begin",
        begin_request.clone(),
    )
    .await;
    let first_begun_payload = begun.payload.clone();

    let retried_begin = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-stream-begin",
        begin_request.clone(),
    )
    .await;
    assert_eq!(
        retried_begin.payload, first_begun_payload,
        "an identical begin retry must return the original capability and receipt"
    );

    let conflicting_retry = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-stream-begin",
        AgentControlRequest::StreamBegin {
            account_id_hex: agent.account.account_id_hex.clone(),
            group_id_hex: group_id_hex.clone(),
            stream_id_hex: Some(stream_id_hex.clone()),
            parent_message_id_hex: None,
            quic_candidates: vec!["quic://127.0.0.1:9".to_owned()],
        },
    )
    .await;
    let AgentControlResponse::Error { code, .. } = conflicting_retry.payload else {
        panic!("expected conflicting stream-begin retry error");
    };
    assert_eq!(code, "stream_begin_request_conflict");

    let colliding_begin = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-stream-begin-collision",
        begin_request,
    )
    .await;
    let AgentControlResponse::Error { code, .. } = colliding_begin.payload else {
        panic!("expected stream-id collision error");
    };
    assert_eq!(code, "stream_id_in_use");

    let AgentControlResponse::StreamBegun {
        stream_id_hex: begun_stream_id_hex,
        stream_capability,
        start_message_id_hex,
        quic_candidates,
        ..
    } = begun.payload
    else {
        panic!("expected stream begun response");
    };
    assert_eq!(begun_stream_id_hex, stream_id_hex);
    assert_eq!(stream_capability.len(), 64);
    assert_eq!(hex::decode(&stream_capability).unwrap().len(), 32);
    assert_eq!(stream_capability, stream_capability.to_ascii_lowercase());
    assert_eq!(quic_candidates, vec!["quic://127.0.0.1:9"]);
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
    let start = stored
        .iter()
        .find(|message| message.message_id_hex == start_message_id_hex)
        .expect("stream start must be in the local app projection");
    assert_eq!(
        stored
            .iter()
            .filter(|message| message.kind == MARMOT_APP_EVENT_KIND_AGENT_STREAM_START)
            .count(),
        1,
        "begin retries and collisions must not publish another start event"
    );
    assert_eq!(start.kind, MARMOT_APP_EVENT_KIND_AGENT_STREAM_START);
    assert_eq!(
        start
            .tags
            .iter()
            .find(|tag| tag.first().map(String::as_str) == Some(STREAM_PARENT_TAG))
            .and_then(|tag| tag.get(1))
            .map(String::as_str),
        Some(parent_message_id_hex.as_str())
    );

    let appended = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-stream-append",
        AgentControlRequest::StreamAppend {
            stream_id_hex: stream_id_hex.clone(),
            stream_capability: stream_capability.clone(),
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
            stream_capability: stream_capability.clone(),
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
            stream_capability,
            final_text: "hello stream".to_owned(),
            transcript_hash_hex,
            chunk_count: 2,
            idempotency_key: None,
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

/// Regression for #366: a finalize whose expectation does not match the
/// composed transcript must not tear down the stream session. The compose
/// task keeps running, further appends succeed, and a corrected finalize
/// completes the stream.
#[tokio::test]
async fn connector_socket_finalize_mismatch_keeps_stream_session_retryable() {
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
            "agent retryable finalize",
            std::slice::from_ref(&human.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    setup_runtime.shutdown().await;

    let group_id_hex = hex::encode(group_id.as_slice());
    let stream_id_hex = hex::encode([0x99; 32]);
    let socket = dir.path().join("dev").join("wn-agent.sock");
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
        "req-retry-begin",
        AgentControlRequest::StreamBegin {
            account_id_hex: agent.account.account_id_hex.clone(),
            group_id_hex: group_id_hex.clone(),
            stream_id_hex: Some(stream_id_hex.clone()),
            parent_message_id_hex: None,
            quic_candidates: vec!["quic://127.0.0.1:9".to_owned()],
        },
    )
    .await;
    let AgentControlResponse::StreamBegun {
        stream_capability,
        start_message_id_hex,
        ..
    } = begun.payload
    else {
        panic!("expected stream begun response");
    };

    let appended = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-retry-append",
        AgentControlRequest::StreamAppend {
            stream_id_hex: stream_id_hex.clone(),
            stream_capability: stream_capability.clone(),
            append_text: "hello stream".to_owned(),
        },
    )
    .await;
    assert_eq!(appended.payload, AgentControlResponse::Ack);

    // Correct text and hash, wrong chunk count: the finalize must fail
    // without tearing down the compose session.
    let first_hash = expected_stream_transcript_hash(
        &stream_id_hex,
        &start_message_id_hex,
        &[(AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, "hello stream")],
    );
    let mismatched = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-retry-finalize-mismatch",
        AgentControlRequest::StreamFinalize {
            stream_id_hex: stream_id_hex.clone(),
            stream_capability: stream_capability.clone(),
            final_text: "hello stream".to_owned(),
            transcript_hash_hex: first_hash,
            chunk_count: 7,
            idempotency_key: None,
        },
    )
    .await;
    let AgentControlResponse::Error { code, .. } = mismatched.payload else {
        panic!("expected finalize mismatch error");
    };
    assert_eq!(code, "stream_error");

    // The compose session must have survived the mismatch: a further append
    // still succeeds.
    let appended_again = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-retry-append-again",
        AgentControlRequest::StreamAppend {
            stream_id_hex: stream_id_hex.clone(),
            stream_capability: stream_capability.clone(),
            append_text: " again".to_owned(),
        },
    )
    .await;
    assert_eq!(appended_again.payload, AgentControlResponse::Ack);

    // A corrected finalize over the full transcript succeeds.
    let corrected_hash = expected_stream_transcript_hash(
        &stream_id_hex,
        &start_message_id_hex,
        &[
            (AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, "hello stream"),
            (AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, " again"),
        ],
    );
    let finalized = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-retry-finalize",
        AgentControlRequest::StreamFinalize {
            stream_id_hex: stream_id_hex.clone(),
            stream_capability,
            final_text: "hello stream again".to_owned(),
            transcript_hash_hex: corrected_hash,
            chunk_count: 2,
            idempotency_key: None,
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

/// Regression for #366 (review follow-up): once the compose task has validated
/// and exited, the durable `finish_agent_text_stream` publish can still fail.
/// The frozen transcript on the still-registered session must let a re-issued
/// finalize complete that publish WITHOUT the (now-dead) compose task, and a
/// retry that disagrees with the frozen transcript must be rejected.
#[tokio::test]
async fn connector_finalize_retries_durable_finish_without_compose_task() {
    use crate::error::ConnectorError;
    use crate::stream_session::FinalizedStream;
    use crate::validation::normalize_hex;

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
            "agent durable finalize retry",
            std::slice::from_ref(&human.account.account_id_hex),
            None,
        )
        .await
        .unwrap();
    setup_runtime.shutdown().await;

    let group_id_hex = hex::encode(group_id.as_slice());
    let stream_id_hex = hex::encode([0x5a; 32]);
    let socket = dir.path().join("dev").join("wn-agent.sock");
    let connector = AgentConnector::open(test_config(
        dir.path(),
        socket.clone(),
        vec![relay_url],
        false,
        false,
    ))
    .unwrap();
    let listener = bind_connector_socket(&socket).unwrap();

    // Begin (and start the runtime) so the durable finish below has a real
    // account, group, and stream-start event to reference.
    let begun = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-durable-begin",
        AgentControlRequest::StreamBegin {
            account_id_hex: agent.account.account_id_hex.clone(),
            group_id_hex,
            stream_id_hex: Some(stream_id_hex.clone()),
            parent_message_id_hex: None,
            quic_candidates: vec!["quic://127.0.0.1:9".to_owned()],
        },
    )
    .await;
    let AgentControlResponse::StreamBegun {
        stream_capability, ..
    } = begun.payload
    else {
        panic!("expected stream begun response");
    };

    // Reconstruct the exact state left after a validated finalize whose durable
    // publish then failed: the compose task has exited (abort it here to prove
    // the retry never talks to it) and the transcript is frozen on the still
    // registered session.
    let stream_id_norm = normalize_hex(&stream_id_hex).unwrap();
    let session = connector.streams.get(&stream_id_norm).unwrap();
    session.abort.abort();
    let transcript_hash = [0x11u8; 32];
    assert!(
        connector.streams.mark_finalized(
            &stream_id_norm,
            &session,
            FinalizedStream {
                final_text: "frozen final".to_owned(),
                transcript_hash,
                chunk_count: 1,
            },
        ),
        "freeze must land on the still-current session"
    );

    // A retry that disagrees with the frozen transcript is rejected and leaves
    // the session registered.
    let mismatch = connector
        .stream_finalize_response(
            &stream_id_hex,
            &stream_capability,
            "different final".to_owned(),
            &hex::encode(transcript_hash),
            1,
            Some("frozen-finalize".to_owned()),
        )
        .await;
    assert!(
        matches!(mismatch, Err(ConnectorError::Stream(_))),
        "a retry disagreeing with the frozen transcript must be rejected"
    );
    assert!(
        connector.streams.get(&stream_id_norm).is_ok(),
        "a rejected retry must not drop the session"
    );

    // A matching retry completes the durable publish from the frozen transcript
    // — the compose task was aborted above, so this proves it is not consulted —
    // and only then removes the session.
    let finalized = connector
        .stream_finalize_response(
            &stream_id_hex,
            &stream_capability,
            "frozen final".to_owned(),
            &hex::encode(transcript_hash),
            1,
            Some("frozen-finalize".to_owned()),
        )
        .await
        .expect("frozen-transcript retry finalizes without the compose task");
    let AgentControlResponse::StreamFinalized {
        message_ids_hex, ..
    } = finalized
    else {
        panic!("expected stream finalized response");
    };
    assert_eq!(message_ids_hex.len(), 1);
    assert!(!message_ids_hex[0].is_empty());
    assert!(
        connector.streams.get(&stream_id_norm).is_err(),
        "a successful durable finish must remove the session"
    );

    // A client retry after receiving a timeout from the successful durable
    // publish path must return the original ids even though the stream session
    // is gone. This is the post-success half of stream_finalize idempotency.
    let retried_after_success = connector
        .stream_finalize_response(
            &stream_id_hex,
            &stream_capability,
            "frozen final".to_owned(),
            &hex::encode(transcript_hash),
            1,
            Some("frozen-finalize".to_owned()),
        )
        .await
        .expect("idempotent stream_finalize retry returns cached ids");
    let AgentControlResponse::StreamFinalized {
        message_ids_hex: retried_ids,
        ..
    } = retried_after_success
    else {
        panic!("expected stream finalized response");
    };
    assert_eq!(retried_ids, message_ids_hex);

    let wrong_capability = hex::encode([0x99; 32]);
    let wrong_capability_retry = connector
        .stream_finalize_response(
            &stream_id_hex,
            &wrong_capability,
            "frozen final".to_owned(),
            &hex::encode(transcript_hash),
            1,
            Some("frozen-finalize".to_owned()),
        )
        .await;
    assert!(
        wrong_capability_retry.is_err(),
        "a finalized idempotency receipt must remain bound to its capability"
    );
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
    let socket = dir.path().join("dev").join("wn-agent.sock");
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
            parent_message_id_hex: None,
            quic_candidates: vec!["quic://127.0.0.1:9".to_owned()],
        },
    )
    .await;
    let AgentControlResponse::StreamBegun {
        stream_capability, ..
    } = begun.payload
    else {
        panic!("expected stream begun response");
    };

    let wrong_capability = hex::encode([0x99; 32]);
    let denied_cancel = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-stream-cancel-denied",
        AgentControlRequest::StreamCancel {
            stream_id_hex: stream_id_hex.clone(),
            stream_capability: wrong_capability,
            reason: Some("unauthorized".to_owned()),
        },
    )
    .await;
    let AgentControlResponse::Error { code, .. } = denied_cancel.payload else {
        panic!("expected denied cancel error");
    };
    assert_eq!(code, "stream_capability_denied");

    let status = serve_control_request_once(
        &connector,
        &listener,
        &socket,
        "req-stream-status",
        AgentControlRequest::StreamStatus {
            stream_id_hex: stream_id_hex.clone(),
            stream_capability: stream_capability.clone(),
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
            stream_capability: stream_capability.clone(),
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
            stream_capability,
            append_text: "late".to_owned(),
        },
    )
    .await;
    let AgentControlResponse::Error { code, .. } = append_after_cancel.payload else {
        panic!("expected append-after-cancel error");
    };
    assert_eq!(code, "stream_capability_denied");
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
    // Regression for mdk#210: a lagged inbound broadcast must surface a
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
        insert_order: 0,
    }
}

#[test]
fn inbound_message_event_from_record_projects_received_chat() {
    // Regression for mdk#210: a missed inbound chat recovered from storage must
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
    // Regression for mdk#505: storage replay must surface a missed inbound kind-5
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
    // Regression for mdk#505: durable kind-1210 group-system rows synthesized from
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
    assert_runtime_replay_dedup_key_matches_group_rename(None);
}

#[test]
fn runtime_replay_dedup_key_matches_group_system_storage_row_id_with_old_name() {
    // `previous_name` is rendered as `data.old_name`, which participates in the
    // canonical row id. Live delivery and replay must therefore agree when it is
    // populated, not only when it is absent.
    assert_runtime_replay_dedup_key_matches_group_rename(Some("Old Team"));
}

fn assert_runtime_replay_dedup_key_matches_group_rename(previous_name: Option<&str>) {
    let group_id = GroupId::new(vec![0x22; 32]);
    let actor = cgka_traits::MemberId::new(vec![0xbb; 32]);
    let change = GroupStateChange::GroupRenamed {
        name: "Team".to_owned(),
        previous_name: previous_name.map(str::to_owned),
    };
    let event = MarmotAppEvent::GroupEvent(marmot_app::RuntimeGroupEvent {
        account_id_hex: "acct".to_owned(),
        account_label: "agent".to_owned(),
        event: GroupEvent::GroupStateChanged {
            group_id: group_id.clone(),
            epoch: EpochId(3),
            actor: Some(actor.clone()),
            change: change.clone(),
            origin_commit_id: None,
        },
    });

    let expected =
        cgka_traits::app_event::group_system_canonical_id(&group_id, 3, Some(&actor), &change)
            .unwrap();

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
fn inbound_message_event_does_not_scan_for_hex_mentions_past_the_cap() {
    let account = "aa".repeat(32);
    let mut text = "x".repeat(AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize);
    text.push_str(&format!(" nostr:{account}"));

    assert!(
        !inbound_message_mentions_self_for_text(&account, &text),
        "nostr:<hex> mentions past the bounded scan window must be ignored"
    );
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

fn inbound_message_mentions_self_for_text(account: &str, text: &str) -> bool {
    let record = received_chat_record("11", "bb", "cc", text);
    let event = inbound_message_event_from_record(account, record, None, Some("bb")).unwrap();
    let AgentControlEvent::InboundMessage { mentions_self, .. } = event else {
        panic!("expected inbound message event");
    };
    mentions_self
}

#[test]
fn inbound_message_event_detects_bare_at_npub_mention() {
    // Clients can emit the visible bare `@npub1…` handle without a p-tag or
    // `nostr:` scheme; agent-control mention classification must still fire.
    let account = "aa".repeat(32);
    let npub = marmot_app::npub_for_account_id(&account).unwrap();

    assert!(
        inbound_message_mentions_self_for_text(&account, &format!("hey @{npub} can you help?")),
        "bare @npub bech32 mention should be detected"
    );
}

#[test]
fn inbound_message_event_uses_markdown_boundaries_for_bare_at_npub_mention() {
    let account = "aa".repeat(32);
    let npub = marmot_app::npub_for_account_id(&account).unwrap();

    for text in [
        format!("not-a-mention@{npub}"),
        format!("a_@{npub}"),
        format!("/@{npub}"),
        format!("@{npub}_tail"),
        format!("@{npub}/tail"),
    ] {
        assert!(
            !inbound_message_mentions_self_for_text(&account, &text),
            "non-visible markdown mention must not be detected: {text}"
        );
    }
}

#[test]
fn inbound_message_event_ignores_uppercase_bare_at_npub_mention() {
    let account = "aa".repeat(32);
    let npub = marmot_app::npub_for_account_id(&account).unwrap();
    let text = format!("@{}", npub.to_ascii_uppercase());

    assert!(
        !inbound_message_mentions_self_for_text(&account, &text),
        "uppercase @NPUB is not a visible marmot-markdown mention"
    );
}

#[test]
fn inbound_message_event_ignores_different_account_bare_at_npub_mention() {
    let account = "aa".repeat(32);
    let other_account = "bb".repeat(32);
    let other_npub = marmot_app::npub_for_account_id(&other_account).unwrap();
    let text = format!("hey @{other_npub}");

    assert!(
        !inbound_message_mentions_self_for_text(&account, &text),
        "visible mention for a different account must not mention this account"
    );
}

#[test]
fn inbound_message_event_ignores_bare_at_npub_in_image_alt_text() {
    let account = "aa".repeat(32);
    let npub = marmot_app::npub_for_account_id(&account).unwrap();
    let text = format!("![hey @{npub}](https://example.invalid/a.png)");

    assert!(
        !inbound_message_mentions_self_for_text(&account, &text),
        "image alt text should not count as a visible addressed mention"
    );
}

#[test]
fn inbound_message_mention_check_is_fast_on_hostile_markdown_without_npub() {
    // Regression for mdk#663: mention classification ran the unbounded
    // Markdown parser on attacker-controlled inbound plaintext. A bracket/image
    // emphasis bomb with no p-tag and no npub reference forced a super-linear
    // full parse on every kind-9 chat message (live projection and replay).
    // With no visible npub token present, classification must short-circuit
    // before parsing and stay fast.
    let account = "aa".repeat(32);
    // `![a](` repeated has known super-linear parse cost; 80 KB of it parses in
    // well over a second unbounded. It contains no npub and no p-tag, so the
    // correct answer is "not a mention" and the cheap path must reach it.
    let hostile = "![a](".repeat(16_000);

    let start = std::time::Instant::now();
    let mentions = inbound_message_mentions_self_for_text(&account, &hostile);
    let elapsed = start.elapsed();

    assert!(
        !mentions,
        "hostile markdown without an npub is not a mention"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "mention classification must not run the unbounded parser on hostile \
         markdown (took {elapsed:?})"
    );
}

#[test]
fn inbound_message_mention_check_is_fast_on_hostile_markdown_with_visible_npub() {
    // A visible candidate npub must not send the remaining hostile plaintext
    // through the Markdown parser. The parser path previously spent hundreds of
    // milliseconds on this capped prefix; the bounded token scanner should be
    // effectively linear and still detect the visible mention.
    let account = "aa".repeat(32);
    let npub = marmot_app::npub_for_account_id(&account).unwrap();
    let hostile = format!("hey @{npub} {}", "![a](".repeat(16_000));

    let start = std::time::Instant::now();
    let mentions = inbound_message_mentions_self_for_text(&account, &hostile);
    let elapsed = start.elapsed();

    assert!(mentions, "visible @npub mention should be detected");
    assert!(
        elapsed < Duration::from_millis(500),
        "visible-npub classification must not parse hostile markdown \
         (took {elapsed:?})"
    );
}

#[test]
fn inbound_message_mention_check_ignores_image_alt_npub_fast_on_hostile_markdown() {
    // Review regression for PR #677: putting the target npub in image alt text
    // made the old pre-filter call the Markdown parser on the hostile capped
    // prefix even though image alt text is not an addressed visible mention.
    let account = "aa".repeat(32);
    let npub = marmot_app::npub_for_account_id(&account).unwrap();
    let hostile = format!("![hey @{npub}]({}", "![a](".repeat(16_000));

    let start = std::time::Instant::now();
    let mentions = inbound_message_mentions_self_for_text(&account, &hostile);
    let elapsed = start.elapsed();

    assert!(
        !mentions,
        "npub in image alt text should not count as a visible addressed mention"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "image-alt npub classification must not parse hostile markdown \
         (took {elapsed:?})"
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
fn media_download_subdir_is_stable_and_content_derived() {
    use crate::messaging::media_download_subdir;

    let a = media_download_subdir(b"plaintext-a");
    let b = media_download_subdir(b"plaintext-b");
    assert_eq!(a, media_download_subdir(b"plaintext-a"), "stable per blob");
    assert_ne!(a, b, "distinct content must not share a subdir");
    // Lowercase hex: always a single safe path component.
    assert_eq!(a.len(), 64);
    assert!(
        a.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
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
    // End-to-end regression for mdk#210: when the inbound broadcast lags, the
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
        dir.path().join("dev").join("wn-agent.sock"),
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
        dir.path().join("dev").join("wn-agent.sock"),
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
            &group_id_hex.to_uppercase(),
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
        "a repeated idempotency key must return the original ids across equivalent hex casing"
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

    let dir = tempfile::tempdir().unwrap();
    let store = SendIdempotencyStore::new(dir.path());
    let fingerprint = "fp-k1".to_owned();
    assert_eq!(
        store.get("k1", &fingerprint),
        None,
        "an unseen key has no cached ids"
    );

    let ids = vec!["aa".repeat(32), "bb".repeat(32)];
    store.record("k1".to_owned(), fingerprint.clone(), ids.clone());
    assert_eq!(
        store.get("k1", &fingerprint),
        Some(ids),
        "a recorded key returns its message ids for a matching fingerprint"
    );
    assert_eq!(
        store.get("k1", "fp-other"),
        None,
        "a recorded key with a non-matching fingerprint is a cache miss"
    );
    assert_eq!(
        store.get("k2", &fingerprint),
        None,
        "an unrelated key stays absent"
    );
}

#[test]
fn send_idempotency_persist_preserves_existing_socket_directory_mode() {
    use crate::stream_session::SendIdempotencyStore;
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let dev = dir.path().join("dev");
    std::fs::create_dir(&dev).unwrap();
    std::fs::set_permissions(&dev, std::fs::Permissions::from_mode(0o750)).unwrap();

    let store = SendIdempotencyStore::new(dir.path());
    store.record(
        "key".to_owned(),
        "fingerprint".to_owned(),
        vec!["aa".repeat(32)],
    );

    assert_eq!(
        std::fs::metadata(dev).unwrap().permissions().mode() & 0o777,
        0o750
    );
}

#[test]
fn send_idempotency_store_keeps_first_recorded_ids_for_a_key() {
    use crate::stream_session::SendIdempotencyStore;

    let dir = tempfile::tempdir().unwrap();
    let store = SendIdempotencyStore::new(dir.path());
    let first = vec!["11".repeat(32)];
    let second = vec!["22".repeat(32)];
    store.record("dup".to_owned(), "fp-first".to_owned(), first.clone());
    // A repeat record (e.g. a racing duplicate) must not overwrite the original
    // committed entry: the first successful send for a key always wins, even if
    // the later record carries a different fingerprint.
    store.record("dup".to_owned(), "fp-second".to_owned(), second);
    assert_eq!(store.get("dup", "fp-first"), Some(first));
}

#[test]
fn send_idempotency_store_evicts_oldest_keys_past_capacity() {
    use crate::stream_session::SendIdempotencyStore;

    // Cap is 1024; fill past it and assert the oldest key is evicted FIFO while
    // the newest remain. This bounds memory for a long-lived connector.
    let dir = tempfile::tempdir().unwrap();
    let store = SendIdempotencyStore::new(dir.path());
    for n in 0..1100u32 {
        store.record(
            format!("key-{n}"),
            format!("fp-{n}"),
            vec![format!("{n:064x}")],
        );
    }
    assert_eq!(
        store.get("key-0", "fp-0"),
        None,
        "oldest key must be evicted"
    );
    assert_eq!(
        store.get("key-75", "fp-75"),
        None,
        "early keys must be evicted"
    );
    assert_eq!(
        store.get("key-1099", "fp-1099"),
        Some(vec![format!("{:064x}", 1099)]),
        "the newest key must still be cached"
    );
    assert_eq!(
        store.get("key-200", "fp-200"),
        Some(vec![format!("{:064x}", 200)]),
        "a key within the retained window must still be cached"
    );
}

#[test]
fn send_idempotency_store_survives_connector_restart() {
    use crate::messaging::send_final_fingerprint;
    use crate::stream_session::SendIdempotencyStore;

    let dir = tempfile::tempdir().unwrap();
    let fingerprint = send_final_fingerprint("aa", "bb", "hello", Some("cc"));
    let ids = vec!["aa".repeat(32)];
    {
        let store = SendIdempotencyStore::new(dir.path());
        store.record("retry-key".to_owned(), fingerprint.clone(), ids.clone());
    }
    let reloaded = SendIdempotencyStore::new(dir.path());
    assert_eq!(
        reloaded.get("retry-key", &fingerprint),
        Some(ids),
        "a persisted idempotency record must survive restart"
    );
    assert_eq!(
        reloaded.get(
            "retry-key",
            &send_final_fingerprint("aa", "bb", "hello", None)
        ),
        None,
        "a mismatched fingerprint must remain a cache miss after restart"
    );
}

#[test]
fn send_idempotency_store_persists_fifo_eviction() {
    use crate::stream_session::SendIdempotencyStore;

    let dir = tempfile::tempdir().unwrap();
    {
        let store = SendIdempotencyStore::new(dir.path());
        for n in 0..1100u32 {
            store.record(
                format!("key-{n}"),
                format!("fp-{n}"),
                vec![format!("{n:064x}")],
            );
        }
    }
    let reloaded = SendIdempotencyStore::new(dir.path());
    assert_eq!(
        reloaded.get("key-0", "fp-0"),
        None,
        "oldest key must stay evicted"
    );
    assert_eq!(
        reloaded.get("key-1099", "fp-1099"),
        Some(vec![format!("{:064x}", 1099)]),
        "newest retained key must reload from disk"
    );
}

#[test]
fn send_idempotency_store_ignores_corrupt_on_disk_file() {
    use crate::stream_session::SendIdempotencyStore;

    let dir = tempfile::tempdir().unwrap();
    let store = SendIdempotencyStore::new(dir.path());
    std::fs::create_dir_all(store.file_path().parent().unwrap()).unwrap();
    std::fs::write(store.file_path(), b"{not valid json").unwrap();

    let reloaded = SendIdempotencyStore::new(dir.path());
    assert_eq!(reloaded.get("missing", "fp-missing"), None);
    reloaded.record(
        "fresh".to_owned(),
        "fp-fresh".to_owned(),
        vec!["cc".repeat(32)],
    );
    assert_eq!(
        reloaded.get("fresh", "fp-fresh"),
        Some(vec!["cc".repeat(32)])
    );
}

#[test]
fn send_idempotency_store_atomic_write_replaces_stale_temp_file() {
    use crate::stream_session::SendIdempotencyStore;

    let dir = tempfile::tempdir().unwrap();
    let store = SendIdempotencyStore::new(dir.path());
    let temp_path = store.temp_path();
    std::fs::create_dir_all(store.file_path().parent().unwrap()).unwrap();
    std::fs::write(&temp_path, b"partial write from crashed writer").unwrap();

    store.record("k1".to_owned(), "fp-k1".to_owned(), vec!["aa".repeat(32)]);

    assert!(!temp_path.exists());
    assert!(store.file_path().exists());
    assert_eq!(
        store.file_path().metadata().unwrap().permissions().mode() & 0o777,
        0o600
    );
    let reloaded = SendIdempotencyStore::new(dir.path());
    assert_eq!(reloaded.get("k1", "fp-k1"), Some(vec!["aa".repeat(32)]));
}

#[test]
fn send_final_fingerprint_pins_stable_digests() {
    use crate::messaging::send_final_fingerprint;

    assert_eq!(
        send_final_fingerprint("aa", "bb", "hello", None),
        "e252cba2c8a1728d36a0cc74a06b00502113fb22cdf10076dd73f5aa88d60f27"
    );
    assert_eq!(
        send_final_fingerprint("aa", "bb", "hello", Some("cc")),
        "f44ab9cc17e0db7571b1e6b1d76b12f09346ea94a576a2a8711272e2caaa6588"
    );
}

#[test]
fn send_final_fingerprint_includes_reply_to_target() {
    use crate::messaging::send_final_fingerprint;

    let without_reply = send_final_fingerprint("aa", "bb", "hello", None);
    let with_reply = send_final_fingerprint("aa", "bb", "hello", Some("cc"));
    assert_ne!(
        without_reply, with_reply,
        "reply target must participate in the request fingerprint"
    );
    assert_eq!(
        send_final_fingerprint("aa", "bb", "hello", Some("cc")),
        with_reply,
        "the same reply target must hash consistently"
    );
    assert_ne!(
        send_final_fingerprint("aa", "bb", "hello", None),
        send_final_fingerprint("aa", "bb", "hello", Some("")),
        "missing reply target must not collide with an empty reply target"
    );
}

#[tokio::test]
async fn media_temp_sweeper_removes_directories_older_than_cutoff() {
    use std::time::{Duration, SystemTime};

    use crate::media_temp::sweep_media_dirs_modified_before;

    let tmp = tempfile::tempdir().unwrap();
    let stale = tmp.path().join("stale-blob");
    tokio::fs::create_dir_all(&stale).await.unwrap();
    let cutoff = SystemTime::now() + Duration::from_secs(3600);
    let swept = sweep_media_dirs_modified_before(tmp.path(), cutoff)
        .await
        .unwrap();
    assert_eq!(
        swept, 1,
        "directories older than the cutoff must be removed"
    );
    assert!(!stale.exists(), "stale media dir must be deleted");
}

#[tokio::test]
async fn media_temp_sweeper_spares_dirs_with_recently_rewritten_files() {
    use std::time::{Duration, SystemTime};

    use crate::media_temp::sweep_media_dirs_modified_before;

    let tmp = tempfile::tempdir().unwrap();
    let blob_dir = tmp.path().join("blob");
    tokio::fs::create_dir_all(&blob_dir).await.unwrap();
    let file_path = blob_dir.join("media.bin");
    tokio::fs::write(&file_path, b"first download")
        .await
        .unwrap();

    // Pick a cutoff after the dir was created, then mimic a re-download of
    // the same blob: an in-place truncating overwrite updates the file mtime
    // but not the parent dir mtime.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let cutoff = SystemTime::now();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&file_path)
        .await
        .unwrap();
    use tokio::io::AsyncWriteExt as _;
    file.write_all(b"second download").await.unwrap();
    drop(file);

    let swept = sweep_media_dirs_modified_before(tmp.path(), cutoff)
        .await
        .unwrap();
    assert_eq!(
        swept, 0,
        "a dir whose file was re-downloaded after the cutoff must not be swept"
    );
    assert!(
        file_path.exists(),
        "recently re-downloaded media must survive the sweep"
    );

    // Once nothing inside the dir is newer than the cutoff, it is reclaimed.
    let late_cutoff = SystemTime::now() + Duration::from_secs(3600);
    let swept = sweep_media_dirs_modified_before(tmp.path(), late_cutoff)
        .await
        .unwrap();
    assert_eq!(swept, 1, "fully stale dirs are still reclaimed");
    assert!(!blob_dir.exists());
}

#[tokio::test]
async fn create_media_download_dir_hardens_root_and_blob_dir_to_0700() {
    use std::os::unix::fs::PermissionsExt as _;

    use crate::media_temp::create_media_download_dir_in;

    // Drive an isolated root directly so we never touch the process-global
    // `$TMPDIR` (which would race the rest of the suite under parallel load).
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("marmot-media");

    let subdir = "deadbeefcafef00d";
    let dir = create_media_download_dir_in(&root, subdir).await.unwrap();

    assert!(dir.is_dir(), "per-blob dir must be created");
    assert_eq!(
        dir,
        root.join(subdir),
        "per-blob dir must live under the marmot-media root"
    );

    let root_mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
    let blob_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        root_mode, 0o700,
        "marmot-media root must be owner-only (0700), not world-traversable"
    );
    assert_eq!(
        blob_mode, 0o700,
        "per-blob dir must be owner-only (0700), not world-traversable"
    );

    // Idempotent: a repeat download for the same blob re-hardens cleanly even
    // when the root and subdir already exist.
    let dir_again = create_media_download_dir_in(&root, subdir).await.unwrap();
    assert_eq!(dir, dir_again);
    let blob_mode_again = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(blob_mode_again, 0o700);
}

#[tokio::test]
async fn create_media_download_dir_creates_root_atomically_at_0700() {
    use std::os::unix::fs::PermissionsExt as _;

    use crate::media_temp::create_media_download_dir_in;

    // A fresh (absent) root must be created already-private, never transiently
    // at the umask-masked default mode while empty.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("marmot-media");
    assert!(!root.exists(), "precondition: root must not exist yet");

    let dir = create_media_download_dir_in(&root, "cafebabe00ff")
        .await
        .unwrap();

    let root_mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        root_mode, 0o700,
        "freshly created marmot-media root must be owner-only (0700)"
    );
    assert!(dir.is_dir());
}

#[tokio::test]
async fn create_media_download_dir_rejects_symlink_root_without_creating_child() {
    use crate::media_temp::create_media_download_dir_in;

    // A local attacker pre-creates `marmot-media` as a symlink to a directory
    // they control. We must refuse to use it and must NOT create the
    // secret-named `<ciphertext_sha256>` child (which would leak the hash into
    // the attacker's tree).
    let tmp = tempfile::tempdir().unwrap();
    let attacker_dir = tmp.path().join("attacker-owned");
    std::fs::create_dir(&attacker_dir).unwrap();
    let root = tmp.path().join("marmot-media");
    std::os::unix::fs::symlink(&attacker_dir, &root).unwrap();

    let subdir = "deadbeefcafef00d";
    let err = create_media_download_dir_in(&root, subdir)
        .await
        .expect_err("symlink root must be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);

    // The ciphertext-hash child must not have been materialized anywhere.
    assert!(
        !attacker_dir.join(subdir).exists(),
        "secret-named child must NOT be created inside the attacker-controlled symlink target"
    );
    assert!(
        std::fs::symlink_metadata(&root)
            .unwrap()
            .file_type()
            .is_symlink(),
        "we must not have replaced or followed the attacker's symlink"
    );
}

#[tokio::test]
async fn create_media_download_dir_rejects_non_directory_root_without_creating_child() {
    use crate::media_temp::create_media_download_dir_in;

    // If `marmot-media` already exists as a plain file (pre-created by another
    // user), refuse to use it and never derive the secret-named child.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("marmot-media");
    std::fs::write(&root, b"not a directory").unwrap();

    let subdir = "deadbeefcafef00d";
    let err = create_media_download_dir_in(&root, subdir)
        .await
        .expect_err("non-directory root must be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);

    assert!(
        root.is_file(),
        "the pre-existing file root must be left untouched"
    );
    assert!(
        !root.join(subdir).exists(),
        "no secret-named child may be created under a non-directory root"
    );
}

#[tokio::test]
async fn create_media_download_dir_rejects_symlink_per_blob_child() {
    use std::os::unix::fs::PermissionsExt as _;

    use crate::media_temp::create_media_download_dir_in;

    // The root itself is a valid owner-only directory, but a `<ciphertext_sha256>`
    // child was pre-planted as a symlink to an attacker-controlled directory
    // (the window a legacy/loose root leaves open). We must refuse to follow it,
    // so neither the 0700 chmod nor the later 0600 plaintext write lands in the
    // attacker's tree.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("marmot-media");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

    let attacker_dir = tmp.path().join("attacker-owned");
    std::fs::create_dir(&attacker_dir).unwrap();
    let subdir = "deadbeefcafef00d";
    std::os::unix::fs::symlink(&attacker_dir, root.join(subdir)).unwrap();

    let err = create_media_download_dir_in(&root, subdir)
        .await
        .expect_err("symlink per-blob child must be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);

    // The symlink must be left as-is (not followed) and the attacker's target
    // must not have been chmodded to 0700 by `harden_media_dir`.
    assert!(
        std::fs::symlink_metadata(root.join(subdir))
            .unwrap()
            .file_type()
            .is_symlink(),
        "we must not have replaced or followed the attacker's child symlink"
    );
    let attacker_mode = std::fs::metadata(&attacker_dir)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_ne!(
        attacker_mode, 0o700,
        "the attacker-controlled target must not be hardened through the symlink"
    );
}

#[tokio::test]
async fn create_media_download_dir_rejects_non_directory_per_blob_child() {
    use std::os::unix::fs::PermissionsExt as _;

    use crate::media_temp::create_media_download_dir_in;

    // A `<ciphertext_sha256>` child pre-planted as a plain file under an
    // otherwise valid root must be rejected rather than written through.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("marmot-media");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

    let subdir = "deadbeefcafef00d";
    std::fs::write(root.join(subdir), b"not a directory").unwrap();

    let err = create_media_download_dir_in(&root, subdir)
        .await
        .expect_err("non-directory per-blob child must be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);

    assert!(
        root.join(subdir).is_file(),
        "the pre-existing file child must be left untouched"
    );
}

#[test]
fn quic_candidate_parser_ignores_path_query_and_fragment() {
    use crate::quic::parse_quic_candidate;

    // Per transports/quic.md the authority ends at the first of '/', '?', '#';
    // the connector must accept the same candidates the app/CLI parsers do
    // (regression: it previously only split on '/').
    for (candidate, expected_authority, expected_server_name) in [
        (
            "quic://broker.example:4450",
            "broker.example:4450",
            "broker.example",
        ),
        (
            "quic://broker.example:4450?x=1",
            "broker.example:4450",
            "broker.example",
        ),
        (
            "quic://broker.example:4450/path?x=1#frag",
            "broker.example:4450",
            "broker.example",
        ),
        (
            "quic://broker.example:4450#frag",
            "broker.example:4450",
            "broker.example",
        ),
    ] {
        let parsed = parse_quic_candidate(candidate).expect("candidate parses");
        assert_eq!(parsed.authority, expected_authority, "{candidate}");
        assert_eq!(parsed.server_name, expected_server_name, "{candidate}");
    }
}

#[test]
fn broker_trust_requires_explicit_opt_in_and_a_literal_loopback_host() {
    use transport_quic_broker::BrokerServerTrust;

    use crate::quic::broker_trust_for_candidate;

    // Off by default: even a literal loopback candidate verifies certificates.
    assert!(matches!(
        broker_trust_for_candidate("127.0.0.1", false),
        BrokerServerTrust::Platform
    ));
    assert!(matches!(
        broker_trust_for_candidate("localhost", false),
        BrokerServerTrust::Platform
    ));

    // With the dev opt-in only LITERAL loopback hosts skip verification.
    assert!(matches!(
        broker_trust_for_candidate("127.0.0.1", true),
        BrokerServerTrust::InsecureLocal
    ));
    assert!(matches!(
        broker_trust_for_candidate("localhost", true),
        BrokerServerTrust::InsecureLocal
    ));
    assert!(matches!(
        broker_trust_for_candidate("::1", true),
        BrokerServerTrust::InsecureLocal
    ));

    // A DOMAIN that could resolve to loopback never selects insecure trust
    // (resolution-dependent downgrade, issue #356).
    assert!(matches!(
        broker_trust_for_candidate("evil.example", true),
        BrokerServerTrust::Platform
    ));
}

// Agent-supplied `quic://` candidates must clear the shared dial-safety gate
// at resolve time: literal-IP authorities resolve without DNS, so these cover
// the canonical non-public classes end to end (issue #385).
#[tokio::test]
async fn quic_candidate_resolve_rejects_non_public_addresses_without_opt_in() {
    use crate::quic::{parse_quic_candidate, resolve_quic_candidate_addr};

    for authority in [
        "quic://10.0.0.5:4433",
        "quic://169.254.169.254:80",
        "quic://100.64.0.1:4433",
        "quic://127.0.0.1:4433",
        "quic://[::1]:4433",
        "quic://[fc00::1]:4433",
    ] {
        let candidate = parse_quic_candidate(authority).expect("candidate parses");
        let result = resolve_quic_candidate_addr(&candidate, false).await;
        assert!(
            result.is_err(),
            "{authority} must be rejected without the dev opt-in"
        );
    }
}

#[tokio::test]
async fn quic_candidate_resolve_opt_in_admits_loopback_only() {
    use crate::quic::{parse_quic_candidate, resolve_quic_candidate_addr};

    let candidate = parse_quic_candidate("quic://127.0.0.1:4433").expect("candidate parses");
    let addr = resolve_quic_candidate_addr(&candidate, true)
        .await
        .expect("loopback resolves under the dev opt-in");
    assert!(addr.ip().is_loopback());

    // The opt-in opens loopback only; private/link-local candidates stay
    // rejected even in dev mode.
    for authority in ["quic://10.0.0.5:4433", "quic://169.254.169.254:80"] {
        let candidate = parse_quic_candidate(authority).expect("candidate parses");
        let result = resolve_quic_candidate_addr(&candidate, true).await;
        assert!(
            result.is_err(),
            "{authority} must be rejected even with the dev opt-in"
        );
    }
}
