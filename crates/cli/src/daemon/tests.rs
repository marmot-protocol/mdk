use super::*;
use cgka_traits::GroupId;
use cgka_traits::MessageId;
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, AgentTextStreamTranscriptV1,
};
use nostr_relay_builder::MockRelay;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
#[cfg(unix)]
fn daemon_pid_and_log_writers_create_private_files() {
    let home = tempfile::tempdir().expect("tempdir");
    let pid_path = home.path().join("dev").join("dmd.pid");
    let log_path = home.path().join("logs").join("dmd.log");

    write_pid_file(&pid_path).expect("write pid file");
    drop(open_daemon_log(&log_path).expect("open daemon log"));

    assert_eq!(
        pid_path
            .parent()
            .expect("pid parent")
            .metadata()
            .expect("pid parent metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        pid_path
            .metadata()
            .expect("pid metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        log_path
            .parent()
            .expect("log parent")
            .metadata()
            .expect("log parent metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        log_path
            .metadata()
            .expect("log metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn apply_defaults_overwrites_forwarded_cli_relay_with_daemon_relay() {
    let defaults = DaemonDefaults {
        home: PathBuf::from("/tmp/dm-daemon-home"),
        socket: PathBuf::from("/tmp/dm-daemon.sock"),
        pid_path: PathBuf::from("/tmp/dm-daemon.pid"),
        log_path: PathBuf::from("/tmp/dm-daemon.log"),
        relay: Some("wss://daemon.example".to_owned()),
        discovery_relays: vec!["wss://discovery.example".to_owned()],
        default_account_relays: vec!["wss://account.example".to_owned()],
        secret_store: Some(crate::SecretStoreKind::File),
        keychain_service: Some("daemon-keychain".to_owned()),
    };
    let mut cli = Cli {
        home: None,
        socket: Some(PathBuf::from("/tmp/forwarded.sock")),
        relay: Some("wss://client.example".to_owned()),
        daemon_discovery_relays: Vec::new(),
        daemon_default_account_relays: Vec::new(),
        secret_store: None,
        keychain_service: None,
        account: None,
        json: true,
        command: crate::Command::Sync,
    };

    apply_defaults(&mut cli, &defaults);

    assert_eq!(cli.relay.as_deref(), Some("wss://daemon.example"));
    assert_eq!(cli.socket, None);
}

#[test]
fn apply_defaults_overwrites_client_storage_scope_with_daemon_defaults() {
    let defaults = DaemonDefaults {
        home: PathBuf::from("/tmp/dm-daemon-home"),
        socket: PathBuf::from("/tmp/dm-daemon.sock"),
        pid_path: PathBuf::from("/tmp/dm-daemon.pid"),
        log_path: PathBuf::from("/tmp/dm-daemon.log"),
        relay: Some("wss://daemon.example".to_owned()),
        discovery_relays: Vec::new(),
        default_account_relays: Vec::new(),
        secret_store: Some(crate::SecretStoreKind::File),
        keychain_service: Some("daemon-keychain".to_owned()),
    };
    let mut cli = Cli {
        home: Some(PathBuf::from("/tmp/client-selected-home")),
        socket: Some(PathBuf::from("/tmp/forwarded.sock")),
        relay: None,
        daemon_discovery_relays: Vec::new(),
        daemon_default_account_relays: Vec::new(),
        secret_store: Some(crate::SecretStoreKind::Keychain),
        keychain_service: Some("client-keychain".to_owned()),
        account: None,
        json: true,
        command: crate::Command::Sync,
    };

    apply_defaults(&mut cli, &defaults);

    assert_eq!(cli.home.as_deref(), Some(defaults.home.as_path()));
    assert_eq!(cli.secret_store, Some(crate::SecretStoreKind::File));
    assert_eq!(cli.keychain_service.as_deref(), Some("daemon-keychain"));
}

#[test]
fn apply_defaults_adds_daemon_account_relays_to_account_create() {
    let defaults = DaemonDefaults {
        home: PathBuf::from("/tmp/dm-daemon-home"),
        socket: PathBuf::from("/tmp/dm-daemon.sock"),
        pid_path: PathBuf::from("/tmp/dm-daemon.pid"),
        log_path: PathBuf::from("/tmp/dm-daemon.log"),
        relay: Some("wss://daemon.example".to_owned()),
        discovery_relays: vec!["wss://discovery.example".to_owned()],
        default_account_relays: vec!["wss://account.example".to_owned()],
        secret_store: Some(crate::SecretStoreKind::File),
        keychain_service: Some("daemon-keychain".to_owned()),
    };
    let mut cli = Cli {
        home: None,
        socket: Some(PathBuf::from("/tmp/forwarded.sock")),
        relay: None,
        daemon_discovery_relays: Vec::new(),
        daemon_default_account_relays: Vec::new(),
        secret_store: None,
        keychain_service: None,
        account: None,
        json: true,
        command: crate::Command::Account {
            command: crate::AccountCommand::Create {
                identity: None,
                nsec_stdin: false,
                default_relays: Vec::new(),
                bootstrap_relays: Vec::new(),
                publish_missing_relay_lists: false,
            },
        },
    };

    apply_defaults(&mut cli, &defaults);

    let crate::Command::Account {
        command:
            crate::AccountCommand::Create {
                default_relays,
                bootstrap_relays,
                ..
            },
    } = cli.command
    else {
        panic!("expected account create command");
    };
    assert_eq!(default_relays, vec!["wss://account.example"]);
    assert_eq!(bootstrap_relays, vec!["wss://discovery.example"]);
}

fn test_stream_compose_open(
    stream_id: Vec<u8>,
    start_event_id: MessageId,
) -> OpenBrokerTextPublisher {
    OpenBrokerTextPublisher {
        broker_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
        server_name: "localhost".to_owned(),
        trust: transport_quic_broker::BrokerServerTrust::InsecureLocal,
        stream_id,
        start_event_id,
        crypto: None,
        max_plaintext_frame_len: None,
    }
}

fn test_stream_compose_report(stream_id: &[u8]) -> DaemonOutgoingStreamReport {
    DaemonOutgoingStreamReport {
        account: Some("account".to_owned()),
        group_id: hex::encode([0x11; 32]),
        stream_id: hex::encode(stream_id),
        start_message_id: hex::encode([0x22; 32]),
        candidate: "quic://127.0.0.1:9".to_owned(),
        status: "streaming".to_owned(),
        text: String::new(),
        transcript_hash: None,
        chunk_count: 0,
        error: None,
    }
}

fn expected_stream_transcript_hash(
    stream_id: &[u8],
    start_event_id: &MessageId,
    text: &str,
    chunk_bytes: usize,
) -> String {
    expected_stream_transcript_hash_for_appends(stream_id, start_event_id, &[text], chunk_bytes)
}

fn expected_stream_transcript_hash_for_appends(
    stream_id: &[u8],
    start_event_id: &MessageId,
    appends: &[&str],
    chunk_bytes: usize,
) -> String {
    let mut transcript =
        AgentTextStreamTranscriptV1::new(stream_id.to_vec(), start_event_id.clone());
    let mut seq = 1_u64;
    for text in appends {
        for chunk in transport_quic_stream::split_text_deltas(text, chunk_bytes) {
            transcript.append(seq, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, &chunk);
            seq += 1;
        }
    }
    hex::encode(transcript.hash())
}

#[tokio::test]
async fn stream_compose_returns_local_transcript_when_broker_connect_is_pending() {
    let stream_id = vec![0xaa; 32];
    let start_event_id = MessageId::new(vec![0xbb; 32]);
    let open = test_stream_compose_open(stream_id.clone(), start_event_id.clone());
    let report = test_stream_compose_report(&stream_id);
    let (tx, rx) = mpsc::channel(4);
    let (_cancel_tx, cancel_rx) = mpsc::channel(1);
    let session = tokio::spawn(run_stream_compose_session(open, 8, rx, cancel_rx, report));

    let (append_tx, append_rx) = oneshot::channel();
    tx.send(StreamComposeCommand::Append {
        text: "hello ".to_owned(),
        respond: append_tx,
    })
    .await
    .unwrap();
    let appended = tokio::time::timeout(Duration::from_millis(250), append_rx)
        .await
        .expect("append should not wait for broker connect")
        .unwrap()
        .unwrap();
    assert_eq!(appended.text, "hello ");
    assert_eq!(appended.chunk_count, 1);

    let (finish_tx, finish_rx) = oneshot::channel();
    tx.send(StreamComposeCommand::Finish { respond: finish_tx })
        .await
        .unwrap();
    let finished = tokio::time::timeout(Duration::from_millis(250), finish_rx)
        .await
        .expect("finish should use local transcript fallback")
        .unwrap()
        .unwrap();

    assert_eq!(finished.status, "finished");
    assert_eq!(finished.text, "hello ");
    assert_eq!(finished.chunk_count, 1);
    assert_eq!(
        finished.transcript_hash.as_deref(),
        Some(expected_stream_transcript_hash(&stream_id, &start_event_id, "hello ", 8).as_str())
    );

    session.await.unwrap();
}

#[tokio::test]
async fn stream_compose_final_report_contains_full_transcript_text() {
    let stream_id = vec![0xcc; 32];
    let start_event_id = MessageId::new(vec![0xdd; 32]);
    let open = test_stream_compose_open(stream_id.clone(), start_event_id.clone());
    let report = test_stream_compose_report(&stream_id);
    let (tx, rx) = mpsc::channel(4);
    let (_cancel_tx, cancel_rx) = mpsc::channel(1);
    let session = tokio::spawn(run_stream_compose_session(open, 5, rx, cancel_rx, report));

    for text in ["hello ", "world"] {
        let (respond, response) = oneshot::channel();
        tx.send(StreamComposeCommand::Append {
            text: text.to_owned(),
            respond,
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_millis(250), response)
            .await
            .expect("append should complete")
            .unwrap()
            .unwrap();
    }

    let (respond, response) = oneshot::channel();
    tx.send(StreamComposeCommand::Finish { respond })
        .await
        .unwrap();
    let finished = tokio::time::timeout(Duration::from_millis(250), response)
        .await
        .expect("finish should complete")
        .unwrap()
        .unwrap();

    assert_eq!(finished.text, "hello world");
    assert_eq!(finished.chunk_count, 3);
    assert_eq!(
        finished.transcript_hash.as_deref(),
        Some(
            expected_stream_transcript_hash_for_appends(
                &stream_id,
                &start_event_id,
                &["hello ", "world"],
                5,
            )
            .as_str()
        )
    );

    session.await.unwrap();
}

#[test]
fn destructive_execute_commands_are_refused_over_daemon() {
    let reset =
        blocked_daemon_execute_output(&daemon_test_cli(crate::Command::Reset { confirm: true }))
            .expect("reset should be blocked");
    let reset_json: serde_json::Value =
        serde_json::from_str(reset.stdout.trim()).expect("reset error JSON");
    assert_eq!(reset.code, 1);
    assert_eq!(reset_json["error"]["code"], "daemon_forbidden");
    assert_eq!(reset_json["error"]["command"], "reset");

    let logout = blocked_daemon_execute_output(&daemon_test_cli(crate::Command::Logout {
        pubkey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
    }))
    .expect("logout should be blocked");
    let logout_json: serde_json::Value =
        serde_json::from_str(logout.stdout.trim()).expect("logout error JSON");
    assert_eq!(logout.code, 1);
    assert_eq!(logout_json["error"]["code"], "daemon_forbidden");
    assert_eq!(logout_json["error"]["command"], "logout");
}

#[test]
fn long_running_stream_execute_commands_are_refused_over_daemon() {
    let receive = blocked_daemon_execute_output(&daemon_test_cli(crate::Command::Stream {
        command: crate::StreamCommand::Receive {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4450),
            start_event_id: None,
        },
    }))
    .expect("stream receive should be blocked");
    let receive_json: serde_json::Value =
        serde_json::from_str(receive.stdout.trim()).expect("receive error JSON");
    assert_eq!(receive.code, 1);
    assert_eq!(receive_json["error"]["code"], "daemon_forbidden");
    assert_eq!(receive_json["error"]["command"], "stream receive");

    let unanchored_send = blocked_daemon_execute_output(&daemon_test_cli(crate::Command::Stream {
        command: crate::StreamCommand::Send {
            broker: false,
            connect: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4450),
            server_name: "localhost".to_owned(),
            server_cert_der_hex: None,
            insecure_local: true,
            stream_id: None,
            start_event_id: None,
            chunk_bytes: 1024,
            chunk_delay_ms: 0,
            text: vec!["hello".to_owned()],
        },
    }))
    .expect("unanchored stream send should be blocked");
    let unanchored_send_json: serde_json::Value =
        serde_json::from_str(unanchored_send.stdout.trim()).expect("send error JSON");
    assert_eq!(unanchored_send.code, 1);
    assert_eq!(unanchored_send_json["error"]["code"], "daemon_forbidden");
    assert_eq!(unanchored_send_json["error"]["command"], "stream send");

    let foreground_watch =
        blocked_daemon_execute_output(&daemon_test_cli(crate::Command::Stream {
            command: crate::StreamCommand::Watch {
                group: "aa".repeat(32),
                stream_id: None,
                server_cert_der_hex: None,
                insecure_local: true,
                background: false,
            },
        }))
        .expect("foreground stream watch should be blocked");
    let foreground_watch_json: serde_json::Value =
        serde_json::from_str(foreground_watch.stdout.trim()).expect("watch error JSON");
    assert_eq!(foreground_watch.code, 1);
    assert_eq!(foreground_watch_json["error"]["code"], "daemon_forbidden");
    assert_eq!(foreground_watch_json["error"]["command"], "stream watch");
}

#[tokio::test]
async fn daemon_peer_authorization_accepts_current_uid() {
    let (stream, _peer) = UnixStream::pair().expect("unix stream pair");

    authorize_daemon_peer(&stream).expect("same-uid peer should be authorized");
}

#[test]
fn daemon_peer_authorization_rejects_mismatched_uid_value() {
    let current_uid = current_effective_uid();
    // Lazily compute the fallback: `unwrap_or` would eagerly evaluate
    // `current_uid - 1`, which underflows when running as uid 0 (root).
    let other_uid = current_uid
        .checked_add(1)
        .unwrap_or_else(|| current_uid - 1);

    assert!(!daemon_peer_uid_authorized(other_uid, current_uid));
}

#[tokio::test]
async fn daemon_request_reader_rejects_oversized_requests() {
    let (mut server, mut client) = UnixStream::pair().expect("unix stream pair");
    let writer = tokio::spawn(async move {
        let oversized = vec![b'{'; MAX_DAEMON_REQUEST_BYTES + 1];
        client
            .write_all(&oversized)
            .await
            .expect("write oversized request");
        client.shutdown().await.expect("shutdown client");
    });

    let err = read_daemon_request(&mut server)
        .await
        .expect_err("oversized request should fail");

    assert!(
        err.to_string().contains("daemon request exceeds"),
        "unexpected error: {err}"
    );
    writer.await.expect("writer task");
}

#[tokio::test]
async fn daemon_request_reader_size_cap_excludes_the_framing_newline() {
    // A frame whose payload is exactly MAX_DAEMON_REQUEST_BYTES, followed by the
    // framing newline (MAX + 1 bytes on the wire), is within the cap: the size
    // check counts payload bytes only. It must get past the size gate and fail
    // at JSON parsing instead of being rejected as oversized. This guards the
    // BufReader + take().read_until() rewrite, which now strips the trailing
    // newline before the cap check.
    let (mut server, mut client) = UnixStream::pair().expect("unix stream pair");
    let writer = tokio::spawn(async move {
        let mut frame = vec![b'a'; MAX_DAEMON_REQUEST_BYTES];
        frame.push(b'\n');
        client
            .write_all(&frame)
            .await
            .expect("write max-size frame");
        client.shutdown().await.expect("shutdown client");
    });

    let err = read_daemon_request(&mut server)
        .await
        .expect_err("a non-JSON payload at the cap should fail to parse");

    assert!(
        !err.to_string().contains("daemon request exceeds"),
        "max-size payload must clear the size cap, got: {err}"
    );
    assert!(
        err.downcast_ref::<serde_json::Error>().is_some(),
        "expected a JSON parse error, got: {err}"
    );
    writer.await.expect("writer task");
}

#[tokio::test]
async fn daemon_request_reader_times_out_on_stalled_client() {
    // A same-UID client that connects but never sends a newline-terminated
    // frame must not wedge the accept loop. The bounded read returns a
    // TimedOut error so the loop reports and continues instead of blocking
    // every other client indefinitely (regression for #190).
    let (mut server, _client) = UnixStream::pair().expect("unix stream pair");

    let err = read_daemon_request_within(&mut server, Duration::from_millis(50))
        .await
        .expect_err("stalled client should time out");

    let io_err = err
        .downcast_ref::<std::io::Error>()
        .expect("timeout should surface as an io::Error");
    assert_eq!(
        io_err.kind(),
        ErrorKind::TimedOut,
        "unexpected error kind: {io_err:?}"
    );
    // `_client` is held open for the duration: the timeout fires precisely
    // because the peer is connected but silent.
}

#[tokio::test]
async fn daemon_ping_is_not_blocked_by_stalled_request_reader() {
    // Regression for #191: accepting one same-UID client that writes a partial
    // frame and then stalls must not keep the accept loop from serving another
    // client's Ping/Status/Shutdown request.
    let home = tempfile::tempdir().expect("tempdir");
    let socket = home.path().join("dev").join("dmd.sock");
    let relay = MockRelay::run().await.expect("start mock relay");
    let relay_url = relay.url().await.to_string();
    let args = DaemonArgs {
        home: Some(home.path().to_path_buf()),
        data_dir: None,
        logs_dir: None,
        socket: Some(socket.clone()),
        relay: Some(relay_url),
        discovery_relays: Vec::new(),
        default_account_relays: Vec::new(),
        secret_store: Some(crate::SecretStoreKind::File),
        keychain_service: Some("dm-test-keychain".to_owned()),
    };
    let server = tokio::spawn(run_server(args));
    for _ in 0..50 {
        if socket.try_exists().expect("socket existence check") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(socket.try_exists().expect("socket existence check"));

    let mut stalled = UnixStream::connect(&socket)
        .await
        .expect("connect stalled client");
    stalled
        .write_all(b"{\"Ping\"")
        .await
        .expect("write partial request");

    let ping = tokio::time::timeout(
        Duration::from_millis(250),
        send_request(&socket, &DaemonRequest::Ping),
    )
    .await;
    drop(stalled);

    let shutdown_output = tokio::time::timeout(
        Duration::from_secs(5),
        send_request(&socket, &DaemonRequest::Shutdown),
    )
    .await
    .expect("shutdown request should not time out")
    .expect("shutdown request should succeed");
    assert_eq!(shutdown_output.code, 0);

    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server task should not time out")
        .expect("server task should not panic")
        .expect("server should shut down cleanly");

    let output = ping
        .expect("ping should not wait behind stalled request reader")
        .expect("ping request should succeed");
    assert_eq!(output.code, 0);
}

#[tokio::test]
async fn daemon_status_response_does_not_wait_for_busy_workers() {
    // Execute requests run outside the accept loop but may still own the shared
    // worker mutex while a long command is in flight. Status must use a
    // best-effort worker snapshot instead of waiting on that mutex; otherwise a
    // long Execute still starves daemon status/stop at the next request.
    let defaults = DaemonDefaults {
        home: PathBuf::from("/tmp/dm-daemon-home"),
        socket: PathBuf::from("/tmp/dm-daemon.sock"),
        pid_path: PathBuf::from("/tmp/dm-daemon.pid"),
        log_path: PathBuf::from("/tmp/dm-daemon.log"),
        relay: None,
        discovery_relays: Vec::new(),
        default_account_relays: Vec::new(),
        secret_store: Some(crate::SecretStoreKind::File),
        keychain_service: Some("daemon-keychain".to_owned()),
    };
    let state = Arc::new(Mutex::new(DaemonState {
        pid: 42,
        started_at: 7,
        last_runtime_activity: None,
    }));
    let workers = SharedDaemonWorkers::default();
    let _busy = workers.lock().await;

    let output = tokio::time::timeout(
        Duration::from_millis(50),
        daemon_status_output(&defaults, state, workers.clone()),
    )
    .await
    .expect("status should not wait behind a busy Execute worker");

    assert_eq!(output.code, 0);
    let status: DaemonStatus = serde_json::from_str(output.stdout.trim()).expect("status JSON");
    assert!(status.running);
    assert_eq!(status.pid, Some(42));
}

#[tokio::test]
async fn daemon_execute_local_command_runs_without_holding_worker_lock() {
    // A relay-less local command takes the `run_cli_local` path, which opens its own
    // account/session and touches no shared daemon state. It must run WITHOUT acquiring the
    // workers lock, so a concurrent lock holder (e.g. another command mid-reconcile against a
    // slow relay) cannot head-of-line block it (#633). We hold the workers lock for the entire
    // call: if the handler tried to lock it, this would deadlock and hit the timeout.
    let defaults = DaemonDefaults {
        home: PathBuf::from("/tmp/dm-daemon-home-hol"),
        socket: PathBuf::from("/tmp/dm-daemon-hol.sock"),
        pid_path: PathBuf::from("/tmp/dm-daemon-hol.pid"),
        log_path: PathBuf::from("/tmp/dm-daemon-hol.log"),
        relay: None,
        discovery_relays: Vec::new(),
        default_account_relays: Vec::new(),
        secret_store: Some(crate::SecretStoreKind::File),
        keychain_service: Some("daemon-keychain".to_owned()),
    };
    let state = Arc::new(Mutex::new(DaemonState {
        pid: 1,
        started_at: 0,
        last_runtime_activity: None,
    }));
    let events = DaemonEventHub::new();
    let workers = SharedDaemonWorkers::default();

    // Hold the workers lock for the whole Execute.
    let busy = workers.lock().await;

    let (mut server, client) = UnixStream::pair().expect("unix stream pair");
    let cli = Box::new(daemon_test_cli(crate::Command::Whoami));

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        handle_execute_connection(cli, &mut server, &defaults, state, events, &workers),
    )
    .await
    .expect("a relay-less Execute must not block on the held workers lock");
    result.expect("handle_execute_connection should succeed off the lock");

    drop(busy);
    drop(client);
}

#[tokio::test]
async fn daemon_request_reader_within_returns_request_before_timeout() {
    let (mut server, mut client) = UnixStream::pair().expect("unix stream pair");
    let writer = tokio::spawn(async move {
        let request = DaemonRequest::Ping;
        let bytes = encode_daemon_request(&request).expect("encode ping");
        client.write_all(&bytes).await.expect("write ping request");
        client.shutdown().await.expect("shutdown client");
    });

    let request = read_daemon_request_within(&mut server, Duration::from_secs(5))
        .await
        .expect("a prompt request should be read before the timeout");
    assert!(
        matches!(request, DaemonRequest::Ping),
        "unexpected request variant"
    );
    writer.await.expect("writer task");
}

#[test]
fn encode_daemon_request_rejects_oversized_payloads() {
    // Build an Execute request whose serialized form exceeds the limit by
    // stuffing a huge relay string into the Cli. This mirrors the real
    // benign trigger: `messages send` with a body over ~1 MiB.
    let huge = "a".repeat(MAX_DAEMON_REQUEST_BYTES + 1);
    let mut cli = daemon_test_cli(crate::Command::Whoami);
    cli.relay = Some(huge);
    let request = DaemonRequest::Execute { cli: Box::new(cli) };

    let err = encode_daemon_request(&request)
        .expect_err("oversized request should be rejected before sending");

    match err {
        DaemonClientError::RequestTooLarge { size, limit } => {
            assert_eq!(limit, MAX_DAEMON_REQUEST_BYTES);
            assert!(
                size > MAX_DAEMON_REQUEST_BYTES,
                "reported size {size} should exceed the limit"
            );
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn encode_daemon_request_accepts_normal_payloads() {
    let request = DaemonRequest::Status;
    let bytes = encode_daemon_request(&request).expect("status request should encode");
    assert!(
        bytes.ends_with(b"\n"),
        "encoded request must be newline-terminated"
    );
    assert!(bytes.len() <= MAX_DAEMON_REQUEST_BYTES + 1);
}

fn daemon_test_cli(command: crate::Command) -> Cli {
    Cli {
        home: None,
        socket: None,
        relay: None,
        daemon_discovery_relays: Vec::new(),
        daemon_default_account_relays: Vec::new(),
        secret_store: None,
        keychain_service: None,
        account: None,
        json: true,
        command,
    }
}

#[test]
fn runtime_message_json_marks_account_label_sender_as_me() {
    let message = marmot_app::ReceivedMessage {
        message_id_hex: "01".to_owned(),
        source_message_id_hex: "source-01".to_owned(),
        sender: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        sender_display_name: Some("Alice Example".to_owned()),
        group_id: GroupId::new(vec![0xab; 32]),
        source_epoch: 0,
        plaintext: "hello".to_owned(),
        kind: cgka_traits::MARMOT_APP_EVENT_KIND_CHAT,
        tags: Vec::new(),
        recorded_at: 0,
    };

    let value = runtime_message_json(
        &message,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "Alice Example",
    );

    assert_eq!(value["direction"], "sent");
    assert_eq!(
        value["from"],
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        value["account_id"],
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(value["from_display_name"], serde_json::Value::Null);
}

#[tokio::test]
async fn stream_watch_workers_reap_finished_handles_on_replace() {
    let workers = StreamWatchWorkers::default();
    workers.replace("finished".to_owned(), tokio::spawn(async {}));
    for _ in 0..10 {
        tokio::task::yield_now().await;
        if workers
            .handles
            .lock()
            .map(|handles| handles["finished"].is_finished())
            .unwrap_or(false)
        {
            break;
        }
    }

    workers.replace(
        "running".to_owned(),
        tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }),
    );

    let handles = workers.handles.lock().expect("worker lock");
    assert!(!handles.contains_key("finished"));
    assert!(handles.contains_key("running"));
    handles["running"].abort();
}

fn stub_compose_session(stream_id: &str) -> StreamComposeSession {
    let report = StreamComposeReport {
        account: None,
        group_id: "abcd".to_owned(),
        stream_id: stream_id.to_owned(),
        start_message_id: "ef01".to_owned(),
        candidate: "quic://127.0.0.1:9000".to_owned(),
        status: "streaming".to_owned(),
        text: "hello transcript".to_owned(),
        transcript_hash: Some("aa".to_owned()),
        chunk_count: 1,
        error: None,
    };
    let (tx, mut rx) = mpsc::channel::<StreamComposeCommand>(4);
    let (cancel_tx, _cancel_rx) = mpsc::channel::<()>(1);
    let handle = tokio::spawn(async move {
        // Minimal stand-in for the compose worker: answer a single Finish with a
        // completed report, then exit like the real session does.
        while let Some(command) = rx.recv().await {
            if let StreamComposeCommand::Finish { respond } = command {
                let _ = respond.send(Ok(report.clone()));
                return;
            }
        }
    });
    StreamComposeSession {
        tx,
        cancel_tx,
        handle,
    }
}

#[tokio::test]
async fn finish_stream_compose_keeps_session_when_marker_publish_fails() {
    // Canonical 32-byte (64 hex char) stream id so the test always reaches the
    // marker-publish-failure branch and never short-circuits on stream-id
    // normalization (which would otherwise let it pass for the wrong reason).
    let stream_id = "abababababababababababababababababababababababababababababababab";
    // `relay: None` disables the hosted runtime, so the finish-marker command
    // returns an error without any live runtime — the deterministic stand-in for
    // a marker publish failure.
    let defaults = DaemonDefaults {
        home: PathBuf::from("/tmp/dm-daemon-home"),
        socket: PathBuf::from("/tmp/dm-daemon.sock"),
        pid_path: PathBuf::from("/tmp/dm-daemon.pid"),
        log_path: PathBuf::from("/tmp/dm-daemon.log"),
        relay: None,
        discovery_relays: Vec::new(),
        default_account_relays: Vec::new(),
        secret_store: None,
        keychain_service: None,
    };
    let state = Arc::new(Mutex::new(DaemonState {
        pid: 0,
        started_at: 0,
        last_runtime_activity: None,
    }));
    let events = DaemonEventHub::new();
    let mut runtime_host = AppRuntimeHost::default();
    let mut workers = StreamComposeWorkers::default();
    let key = stream_compose_key(None, stream_id);
    workers.insert(key.clone(), stub_compose_session(stream_id));

    let cli = daemon_test_cli(crate::Command::Sync);
    let output = finish_stream_compose(
        &cli,
        &defaults,
        state,
        events,
        &mut runtime_host,
        &mut workers,
        stream_id,
    )
    .await;

    assert_ne!(
        output.code, 0,
        "marker publish failure should surface as an error"
    );
    assert!(
        workers.get(&key).is_some(),
        "the compose session must be retained so the transcript stays retryable"
    );
}

#[test]
fn runtime_message_json_carries_named_peer_display_name() {
    let message = marmot_app::ReceivedMessage {
        message_id_hex: "02".to_owned(),
        source_message_id_hex: "source-02".to_owned(),
        sender: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        sender_display_name: Some("Bob Example".to_owned()),
        group_id: GroupId::new(vec![0xcd; 32]),
        source_epoch: 0,
        plaintext: "hello back".to_owned(),
        kind: cgka_traits::MARMOT_APP_EVENT_KIND_CHAT,
        tags: Vec::new(),
        recorded_at: 0,
    };

    let value = runtime_message_json(
        &message,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "Alice Example",
    );

    assert_eq!(value["direction"], "received");
    assert_eq!(
        value["from"],
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
    assert_eq!(
        value["account_id"],
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(value["from_display_name"], "Bob Example");
}

#[test]
fn runtime_message_json_keeps_source_recorded_at_and_live_received_at() {
    // Live payloads must echo the message's own source timestamp under
    // `recorded_at` (so they match replay/snapshot payloads) while stamping
    // `received_at` with the live delivery time.
    let source_recorded_at = 1_700_000_000;
    let before = unix_now();
    let message = marmot_app::ReceivedMessage {
        message_id_hex: "03".to_owned(),
        source_message_id_hex: "source-03".to_owned(),
        sender: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        sender_display_name: Some("Bob Example".to_owned()),
        group_id: GroupId::new(vec![0xcd; 32]),
        source_epoch: 0,
        plaintext: "hello back".to_owned(),
        kind: cgka_traits::MARMOT_APP_EVENT_KIND_CHAT,
        tags: Vec::new(),
        recorded_at: source_recorded_at,
    };

    let value = runtime_message_json(
        &message,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "Alice Example",
    );
    let after = unix_now();

    assert_eq!(value["recorded_at"], source_recorded_at);
    let received_at = value["received_at"]
        .as_u64()
        .expect("received_at should be a unix timestamp");
    assert!(
        (before..=after).contains(&received_at),
        "received_at {received_at} should be a live timestamp in [{before}, {after}]"
    );
    assert_ne!(
        value["recorded_at"], value["received_at"],
        "recorded_at must track source time, not the live received_at"
    );
}

#[test]
fn account_error_activity_message_excludes_account_identity() {
    let account_id_hex =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned();
    let account_label = "Dana Example".to_owned();
    let error = marmot_app::RuntimeAccountError {
        account_id_hex: account_id_hex.clone(),
        account_label: account_label.clone(),
        message: "relay handshake timed out".to_owned(),
    };

    let recorded = account_error_activity_message(&error);

    assert!(
        recorded.contains("relay handshake timed out"),
        "the upstream error message should be preserved: {recorded}"
    );
    assert!(
        !recorded.contains(&account_id_hex),
        "the stored error string must not expose the account id: {recorded}"
    );
    assert!(
        !recorded.contains(&account_label),
        "the stored error string must not expose the account label: {recorded}"
    );

    // The recorded string is stored verbatim into the report exposed via
    // `dm daemon status --json` / the TUI, so the privacy guarantee carries
    // through to the surfaced `errors` field.
    let state = Arc::new(Mutex::new(DaemonState {
        pid: 0,
        started_at: 0,
        last_runtime_activity: None,
    }));
    record_runtime_activity_error(&state, recorded.clone());
    let exposed = state
        .lock()
        .expect("state lock")
        .last_runtime_activity
        .clone()
        .expect("activity recorded");
    assert_eq!(exposed.errors, vec![recorded]);
    assert!(!exposed.errors[0].contains(&account_id_hex));
    assert!(!exposed.errors[0].contains(&account_label));
}

#[test]
fn message_subscription_filters_group_events_by_account() {
    let response = DaemonStreamResponse::ok(serde_json::json!({
        "type": "message",
        "message": {
            "account_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "group_id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "message_id": "01",
            "plaintext": "wrong account copy"
        }
    }));

    assert!(!stream_response_matches_subscription(
        &response,
        Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ));
    assert!(stream_response_matches_subscription(
        &response,
        Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ));
    assert!(stream_response_matches_subscription(
        &response,
        None,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ));
}

#[test]
fn message_subscription_seen_message_ids_are_bounded_to_recent_ids() {
    let mut seen_messages = BoundedMessageSubscriptionIds::with_limit(3);
    let mut seen_stream_previews = BoundedMessageSubscriptionIds::with_limit(3);

    for index in 0..5 {
        let response = DaemonStreamResponse::ok(serde_json::json!({
            "type": "message",
            "message": { "message_id": format!("message-{index}") }
        }));
        assert!(mark_stream_response_seen(
            &response,
            &mut seen_messages,
            &mut seen_stream_previews
        ));
    }

    assert_eq!(seen_messages.len(), 3);
    assert!(!seen_messages.contains("message-0"));
    assert!(!seen_messages.contains("message-1"));
    assert!(seen_messages.contains("message-2"));
    assert!(seen_messages.contains("message-4"));

    let duplicate = DaemonStreamResponse::ok(serde_json::json!({
        "type": "message",
        "message": { "message_id": "message-2" }
    }));
    assert!(!mark_stream_response_seen(
        &duplicate,
        &mut seen_messages,
        &mut seen_stream_previews
    ));
}

#[test]
fn message_subscription_seen_stream_previews_are_bounded_to_recent_ids() {
    let mut seen_messages = BoundedMessageSubscriptionIds::with_limit(3);
    let mut seen_stream_previews = BoundedMessageSubscriptionIds::with_limit(3);

    for index in 0..5 {
        let response = DaemonStreamResponse::ok(serde_json::json!({
            "type": "stream_preview",
            "stream_preview": {
                "watch_id": format!("watch-{index}"),
                "status": "running",
                "text": format!("chunk-{index}")
            }
        }));
        assert!(mark_stream_response_seen(
            &response,
            &mut seen_messages,
            &mut seen_stream_previews
        ));
    }

    assert_eq!(seen_stream_previews.len(), 3);
    assert!(!seen_stream_previews.contains("watch-0:running:chunk-0::"));
    assert!(!seen_stream_previews.contains("watch-1:running:chunk-1::"));
    assert!(seen_stream_previews.contains("watch-2:running:chunk-2::"));
    assert!(seen_stream_previews.contains("watch-4:running:chunk-4::"));
}

#[test]
fn messages_subscribe_args_allow_all_groups() {
    let cli = Cli {
        home: None,
        socket: None,
        relay: None,
        daemon_discovery_relays: Vec::new(),
        daemon_default_account_relays: Vec::new(),
        secret_store: None,
        keychain_service: None,
        account: None,
        json: true,
        command: crate::Command::Messages {
            command: crate::MessageCommand::Subscribe {
                group: None,
                limit: Some(250),
            },
        },
    };

    assert_eq!(messages_subscribe_args(&cli), Ok((None, Some(200))));
}

#[test]
fn timeline_messages_subscribe_is_routed_by_command_shape() {
    let cli = Cli {
        home: None,
        socket: None,
        relay: None,
        daemon_discovery_relays: Vec::new(),
        daemon_default_account_relays: Vec::new(),
        secret_store: None,
        keychain_service: None,
        account: None,
        json: true,
        command: crate::Command::Messages {
            command: crate::MessageCommand::Timeline {
                command: crate::MessageTimelineCommand::Subscribe {
                    group: Some("not-hex".to_owned()),
                    limit: Some(25),
                },
            },
        },
    };

    assert!(is_timeline_messages_subscribe(&cli));
    assert!(timeline_messages_subscribe_args(&cli).is_err());
}

#[test]
fn timeline_stream_plain_output_is_human_readable() {
    let ready = serde_json::json!({
        "type": "timeline_subscription_ready",
        "group_id": "aa"
    });
    assert_eq!(
        stream_result_plain(&ready),
        "timeline subscription ready group=aa"
    );

    let page = serde_json::json!({
        "type": "initial_timeline_page",
        "has_more_before": true,
        "has_more_after": false,
        "messages": [
            {
                "group_id": "aa",
                "from": "alice",
                "plaintext": "hello",
                "deleted": false
            }
        ]
    });

    assert_eq!(
        stream_result_plain(&page),
        "initial timeline page has_more_before=true has_more_after=false\ngroup=aa from=alice: hello"
    );

    let projection = serde_json::json!({
        "type": "timeline_projection_updated",
        "group_id": "aa",
        "chat_list_trigger": "NewLastMessage",
        "changes": [
            {
                "type": "upsert",
                "trigger": "NewMessage",
                "message": {
                    "message_id": "01",
                    "group_id": "aa",
                    "from": "alice",
                    "plaintext": "hello"
                }
            }
        ]
    });
    assert_eq!(
        stream_result_plain(&projection),
        "timeline projection updated group=aa changes=1 chat_list_trigger=NewLastMessage"
    );
}

#[test]
fn message_subscription_filters_stream_updates_by_account_when_present() {
    let scoped_delta = DaemonStreamResponse::ok(serde_json::json!({
        "type": "agent_stream_delta",
        "agent_stream_delta": {
            "account": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "group_id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "stream_id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "text": "hello"
        }
    }));
    let accountless_preview = DaemonStreamResponse::ok(serde_json::json!({
        "type": "stream_preview",
        "stream_preview": {
            "group_id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "stream_id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "status": "running",
            "text": "hello"
        }
    }));

    assert!(!stream_response_matches_subscription(
        &scoped_delta,
        Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ));
    assert!(stream_response_matches_subscription(
        &scoped_delta,
        Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ));
    assert!(stream_response_matches_subscription(
        &accountless_preview,
        Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ));
}
