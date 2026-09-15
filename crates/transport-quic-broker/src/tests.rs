//! White-box unit tests: exercise the broker engine, framing, TLS helpers, and
//! client/server internals that are only reachable inside the crate.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_RECORD_ABORT, AGENT_TEXT_STREAM_RECORD_CHECKPOINT,
    AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA, AGENT_TEXT_STREAM_RECORD_STATUS,
    AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, AgentTextStreamKeyContextV1, AgentTextStreamRecordV1,
    AgentTextStreamTranscriptV1,
};
use cgka_traits::{EpochId, GroupId, MemberId, MessageId, SecretBytes};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, TransportConfig, VarInt};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use transport_quic_stream::{
    AgentTextStreamCrypto, AgentTextStreamReceiveLimitError, AgentTextStreamReceiveLimits,
    EphemeralPublisherSequenceStore, QuicPreviewTransportProfile, stream_record_text,
};

use crate::client::{
    BrokerServerTrust, BrokerTextPublisher, OpenBrokerTextPublisher, PublishTextToBroker,
    SubscribeTextFromBroker, publish_text_to_broker, subscribe_text_from_broker,
    subscribe_text_from_broker_with_limits,
};
use crate::config::{QuicBrokerConfig, QuicBrokerTlsConfig};
use crate::control::BrokerStreamKey;
use crate::control::QuicBrokerControlEnvelopeV1;
use crate::error::QuicBrokerError;
use crate::frame::{
    broker_read_deadline, broker_write_deadline, read_record_frame, validate_frame_len,
    write_control_frame, write_record_frame, write_record_frame_with_deadline,
};
use crate::handlers::{BrokerStreamPolicy, PublishForwardLimits, handle_connection};
use crate::protocol::{
    DEFAULT_BROKER_BACKLOG_DEPTH, DEFAULT_BROKER_MAX_BACKLOG_BYTES, DEFAULT_BROKER_MAX_ROOMS,
    DEFAULT_BROKER_REPLAY_TTL, DEFAULT_SUBSCRIBER_QUEUE_DEPTH, FINISHED_ROOM_TTL,
    LOCAL_SERVER_BIND, MAX_BROKER_REPLAY_TTL, MAX_FRAME_SIZE, QUIC_BROKER_ALPN_V1,
    RECORD_QUIET_GAP_DEADLINE, SEND_STOP_WAIT, SUBSCRIBER_WRITE_DEADLINE, UNFINISHED_ROOM_TTL,
};
use crate::server::{QuicBrokerServer, certificate_sha256_fingerprint_hex};
use crate::state::BrokerState;
use crate::tls::{
    SkipServerVerification, broker_rustls_client_config, client_bind_addr_for_broker,
    client_endpoint, configure_server,
};

/// State helper with replay retention enabled (the profile cap) so the
/// pre-existing backlog tests keep exercising retention; replay-TTL
/// behavior itself is covered by the dedicated tests below.
fn test_state(max_backlog: usize) -> BrokerState {
    BrokerState::new(
        DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        max_backlog,
        DEFAULT_BROKER_MAX_ROOMS,
        DEFAULT_BROKER_MAX_BACKLOG_BYTES,
        MAX_BROKER_REPLAY_TTL,
    )
}

#[tokio::test]
async fn broker_forwards_live_records_to_subscriber_with_same_transcript() {
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let stream_id = vec![0xaa; 32];
    let start_event_id = MessageId::new(vec![0x11; 32]);
    let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
    }));
    sleep(Duration::from_millis(100)).await;

    let sent = publish_text_to_broker(PublishTextToBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert),
        stream_id: stream_id.clone(),
        start_event_id,
        text: "hello broker stream".to_owned(),
        max_chunk_bytes: 6,
        chunk_delay: Duration::ZERO,
        crypto: None,
        max_plaintext_frame_len: None,
    })
    .await
    .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert_eq!(received.stream_id, stream_id);
    assert_eq!(received.text, "hello broker stream");
    assert_eq!(received.chunk_count, 4);
    assert_eq!(sent.chunk_count, received.chunk_count);
    assert_eq!(sent.transcript_hash, received.transcript_hash);

    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn broker_applies_quiet_gap_not_handshake_deadline_to_authenticated_publisher() {
    // Regression for the live-preview latch: an agent that goes quiet between
    // records (e.g. a long tool call with no progress events) must not have
    // its publish stream errored by the short handshake `read_timeout`. That
    // deadline only bounds the pre-auth control frame; post-handshake record
    // reads fall under the far more generous shared 120s quiet-gap deadline
    // (`RECORD_QUIET_GAP_DEADLINE`), matching the direct path and the
    // subscriber loop. Here we use a tiny read_timeout and idle well past it
    // between two records, and assert both records still arrive.
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        read_timeout: Duration::from_millis(100),
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let stream_id = vec![0xa9; 32];
    let start_event_id = MessageId::new(vec![0x19; 32]);
    let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
    }));
    sleep(Duration::from_millis(100)).await;

    let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert),
        stream_id: stream_id.clone(),
        start_event_id,
        crypto: None,
        max_plaintext_frame_len: None,
    })
    .await
    .unwrap();
    publisher
        .append_text("before", 32, Duration::ZERO)
        .await
        .unwrap();
    // Idle far longer than the per-record read_timeout (100ms).
    sleep(Duration::from_millis(500)).await;
    // This write would have failed before the fix, because the broker would
    // have already errored the publish stream on the idle gap.
    publisher
        .append_text("after", 32, Duration::ZERO)
        .await
        .unwrap();
    let sent = publisher.finish().await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert_eq!(received.stream_id, stream_id);
    assert_eq!(received.text, "beforeafter");
    assert_eq!(sent.chunk_count, received.chunk_count);
    assert_eq!(sent.transcript_hash, received.transcript_hash);

    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn broker_closes_subscribers_when_publish_stream_errors_after_backlog() {
    let stream_id = vec![0xac; 32];
    let start_event_id = MessageId::new(vec![0x21; 32]);
    let small_record = AgentTextStreamRecordV1::text_delta(stream_id.clone(), 1, b"ok".to_vec());
    let large_record = AgentTextStreamRecordV1::text_delta(
        stream_id.clone(),
        2,
        b"this record is too large".to_vec(),
    );
    let max_backlog_bytes = small_record.encode().unwrap().len();
    assert!(large_record.encode().unwrap().len() > max_backlog_bytes);

    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        max_backlog_bytes,
        // Backlog byte budgets only apply when replay retention is on.
        replay_ttl: MAX_BROKER_REPLAY_TTL,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
    }));
    sleep(Duration::from_millis(100)).await;

    let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert),
        stream_id: stream_id.clone(),
        start_event_id,
        crypto: None,
        max_plaintext_frame_len: None,
    })
    .await
    .unwrap();
    publisher
        .append_text("ok", 32, Duration::ZERO)
        .await
        .unwrap();
    publisher
        .append_text("this record is too large", 32, Duration::ZERO)
        .await
        .unwrap();
    let _ = publisher.finish().await;

    let received = tokio::time::timeout(Duration::from_secs(2), subscriber)
        .await
        .expect("subscriber should not park forever after publish loop error")
        .unwrap()
        .unwrap();

    assert_eq!(received.stream_id, stream_id);
    assert_eq!(received.text, "ok");
    assert_eq!(received.chunk_count, 1);

    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn broker_forwards_status_records_without_adding_to_text() {
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let stream_id = vec![0xcc; 32];
    let start_event_id = MessageId::new(vec![0x33; 32]);
    let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
    }));
    sleep(Duration::from_millis(100)).await;

    let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert),
        stream_id: stream_id.clone(),
        start_event_id,
        crypto: None,
        max_plaintext_frame_len: None,
    })
    .await
    .unwrap();
    publisher
        .append_text("hello", 32, Duration::ZERO)
        .await
        .unwrap();
    publisher
        .append_record_text(
            AGENT_TEXT_STREAM_RECORD_STATUS,
            "thinking",
            32,
            Duration::ZERO,
        )
        .await
        .unwrap();
    let sent = publisher.finish().await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert_eq!(received.stream_id, stream_id);
    assert_eq!(received.text, "hello");
    assert_eq!(received.chunk_count, 2);
    assert_eq!(received.chunks.len(), 2);
    assert_eq!(
        received.chunks[0].record_type,
        AGENT_TEXT_STREAM_RECORD_TEXT_DELTA
    );
    assert_eq!(received.chunks[0].text, "hello");
    assert_eq!(
        received.chunks[1].record_type,
        AGENT_TEXT_STREAM_RECORD_STATUS
    );
    assert_eq!(received.chunks[1].text, "thinking");
    assert_eq!(sent.chunk_count, received.chunk_count);
    assert_eq!(sent.transcript_hash, received.transcript_hash);

    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn broker_forwards_abort_record_to_subscriber() {
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let stream_id = vec![0x5a; 32];
    let start_event_id = MessageId::new(vec![0x5b; 32]);
    let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
    }));
    sleep(Duration::from_millis(100)).await;

    let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert),
        stream_id: stream_id.clone(),
        start_event_id,
        crypto: None,
        max_plaintext_frame_len: None,
    })
    .await
    .unwrap();
    publisher
        .append_text("partial answer", 32, Duration::ZERO)
        .await
        .unwrap();
    publisher.append_abort().await.unwrap();
    let sent = publisher.finish().await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    // The provisional text is the TextDelta only; the Abort carries no text
    // but is delivered as a terminal record the receiver acts on.
    assert_eq!(received.text, "partial answer");
    assert_eq!(received.chunk_count, 2);
    assert_eq!(received.chunks.len(), 2);
    assert_eq!(
        received.chunks[0].record_type,
        AGENT_TEXT_STREAM_RECORD_TEXT_DELTA
    );
    assert_eq!(
        received.chunks[1].record_type,
        AGENT_TEXT_STREAM_RECORD_ABORT
    );
    assert_eq!(received.chunks[1].text, "");
    assert_eq!(sent.chunk_count, received.chunk_count);
    assert_eq!(sent.transcript_hash, received.transcript_hash);

    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn broker_forwards_checkpoint_snapshot_without_merging_into_final_text() {
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let stream_id = vec![0xc4; 32];
    let start_event_id = MessageId::new(vec![0x44; 32]);
    let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
    }));
    sleep(Duration::from_millis(100)).await;

    let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert),
        stream_id: stream_id.clone(),
        start_event_id,
        crypto: None,
        max_plaintext_frame_len: None,
    })
    .await
    .unwrap();
    // A delta builds the provisional answer; the checkpoint is a full preview
    // snapshot the receiver forwards for the consumer to swap in.
    publisher
        .append_text("hello", 32, Duration::ZERO)
        .await
        .unwrap();
    publisher
        .append_record_text(
            AGENT_TEXT_STREAM_RECORD_CHECKPOINT,
            "hello world",
            32,
            Duration::ZERO,
        )
        .await
        .unwrap();
    let sent = publisher.finish().await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    // Checkpoint plaintext reaches the subscriber as the record's text...
    assert_eq!(received.chunks.len(), 2);
    assert_eq!(
        received.chunks[1].record_type,
        AGENT_TEXT_STREAM_RECORD_CHECKPOINT
    );
    assert_eq!(received.chunks[1].text, "hello world");
    // ...but it is not merged into the provisional final text, which stays the
    // concatenation of TextDelta frames only.
    assert_eq!(received.text, "hello");
    assert_eq!(received.chunk_count, 2);
    assert_eq!(sent.chunk_count, received.chunk_count);
    assert_eq!(sent.transcript_hash, received.transcript_hash);

    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn broker_progress_and_status_only_stream_yields_empty_final_text() {
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let stream_id = vec![0x9c; 32];
    let start_event_id = MessageId::new(vec![0x55; 32]);
    let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
    }));
    sleep(Duration::from_millis(100)).await;

    let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert),
        stream_id: stream_id.clone(),
        start_event_id,
        crypto: None,
        max_plaintext_frame_len: None,
    })
    .await
    .unwrap();
    publisher
        .append_record_text(
            AGENT_TEXT_STREAM_RECORD_STATUS,
            "thinking",
            32,
            Duration::ZERO,
        )
        .await
        .unwrap();
    publisher
        .append_record_text(
            AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA,
            "searching",
            32,
            Duration::ZERO,
        )
        .await
        .unwrap();
    let sent = publisher.finish().await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    // A stream that never sends a TextDelta has no chat answer: the final text
    // is legitimately empty, so consumers can tell "no answer" apart from a
    // real preview instead of rendering a blank chat bubble.
    assert_eq!(received.text, "");
    // The status/progress content is still delivered per-record for live
    // non-chat chrome.
    assert_eq!(received.chunks.len(), 2);
    assert_eq!(
        received.chunks[0].record_type,
        AGENT_TEXT_STREAM_RECORD_STATUS
    );
    assert_eq!(received.chunks[0].text, "thinking");
    assert_eq!(
        received.chunks[1].record_type,
        AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA
    );
    assert_eq!(received.chunks[1].text, "searching");
    assert_eq!(received.chunk_count, 2);
    assert_eq!(sent.transcript_hash, received.transcript_hash);

    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn broker_subscriber_rejects_streams_past_receive_limits() {
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let stream_id = vec![0xdd; 32];
    let start_event_id = MessageId::new(vec![0x44; 32]);
    let subscriber = tokio::spawn(subscribe_text_from_broker_with_limits(
        SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        },
        AgentTextStreamReceiveLimits {
            max_records: 1,
            max_plaintext_bytes: 1024,
            ..AgentTextStreamReceiveLimits::default()
        },
        |_| {},
    ));
    sleep(Duration::from_millis(100)).await;

    let _ = publish_text_to_broker(PublishTextToBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert),
        stream_id,
        start_event_id,
        text: "two records".to_owned(),
        max_chunk_bytes: 3,
        chunk_delay: Duration::ZERO,
        crypto: None,
        max_plaintext_frame_len: None,
    })
    .await;

    let err = timeout(Duration::from_secs(5), subscriber)
        .await
        .expect("subscriber should hit receive limit")
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        err,
        QuicBrokerError::ReceiveLimit(AgentTextStreamReceiveLimitError::RecordLimitExceeded {
            attempted: 2,
            limit: 1
        })
    ));

    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn broker_replays_full_backlog_to_late_subscriber() {
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        per_subscriber_queue: 2,
        max_backlog: 16,
        // Late-subscriber backlog replay requires an explicit replay
        // window; the default TTL of zero retains nothing.
        replay_ttl: MAX_BROKER_REPLAY_TTL,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let stream_id = vec![0xbb; 32];
    let start_event_id = MessageId::new(vec![0x22; 32]);
    let early_subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
    }));
    sleep(Duration::from_millis(100)).await;

    let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
        max_plaintext_frame_len: None,
    })
    .await
    .unwrap();

    publisher
        .append_text("abcdefghij", 1, Duration::ZERO)
        .await
        .unwrap();
    let late_subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert),
        stream_id: stream_id.clone(),
        start_event_id,
        crypto: None,
    }));
    sleep(Duration::from_millis(100)).await;

    let sent = publisher.finish().await.unwrap();
    let _ = early_subscriber.await;
    let late_received = late_subscriber.await.unwrap().unwrap();

    assert_eq!(late_received.text, "abcdefghij");
    assert_eq!(late_received.chunk_count, 10);
    assert_eq!(sent.transcript_hash, late_received.transcript_hash);

    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn broker_replays_finished_backlog_to_late_subscriber() {
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        max_backlog: DEFAULT_BROKER_BACKLOG_DEPTH,
        // Late-subscriber backlog replay requires an explicit replay
        // window; the default TTL of zero retains nothing.
        replay_ttl: MAX_BROKER_REPLAY_TTL,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let stream_id = vec![0xcc; 32];
    let start_event_id = MessageId::new(vec![0x33; 32]);
    let early_subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
    }));
    sleep(Duration::from_millis(100)).await;

    let sent = publish_text_to_broker(PublishTextToBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        text: "finished transcript".to_owned(),
        max_chunk_bytes: 4,
        crypto: None,
        chunk_delay: Duration::ZERO,
        max_plaintext_frame_len: None,
    })
    .await
    .unwrap();
    let early_received = early_subscriber.await.unwrap().unwrap();
    assert_eq!(early_received.transcript_hash, sent.transcript_hash);

    let late_received = timeout(
        Duration::from_secs(5),
        subscribe_text_from_broker(SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert),
            stream_id,
            start_event_id,
            crypto: None,
        }),
    )
    .await
    .expect("late subscriber should receive retained finished backlog")
    .unwrap();

    assert_eq!(late_received.text, "finished transcript");
    assert_eq!(late_received.transcript_hash, sent.transcript_hash);

    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn broker_retains_finished_rooms_and_closes_live_subscribers() {
    let state = Arc::new(test_state(DEFAULT_BROKER_BACKLOG_DEPTH));
    let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
    let record = AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"hello".to_vec());
    let (_subscriber_id, _backlog, mut rx) = state.subscribe(key.clone()).await.unwrap();
    assert_eq!(state.room_count().await, 1);

    state.publish(&key, record.clone()).await.unwrap();
    state.finish_room(&key).await;

    assert_eq!(state.room_count().await, 1);
    assert_eq!(rx.recv().await.expect("queued live record").seq, record.seq);
    assert!(rx.recv().await.is_none());

    let (_late_id, backlog, mut finished_rx) = state.subscribe(key).await.unwrap();
    assert_eq!(backlog.len(), 1);
    assert_eq!(backlog[0].seq, record.seq);
    assert!(finished_rx.recv().await.is_none());
}

#[tokio::test]
async fn broker_frees_backlog_accounting_when_publisher_reuses_finished_room() {
    let state = Arc::new(test_state(DEFAULT_BROKER_BACKLOG_DEPTH));
    let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
    let record = AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"hello".to_vec());

    state.publish(&key, record).await.unwrap();
    state.finish_room(&key).await;
    assert!(state.backlog_bytes_for_test().await > 0);

    // A new publisher reusing the finished key resets the room in place,
    // discarding its retained backlog; the discarded bytes must leave the
    // global accounting with it instead of lingering as phantom budget until
    // the next state-touching op happens to recompute the total.
    let waiter = {
        let state = Arc::clone(&state);
        let key = key.clone();
        tokio::spawn(async move { state.wait_for_subscriber(&key).await })
    };
    // The waiter's first lock iteration performs the reset; poll (bounded, and
    // well under the publish grace period) rather than assume a fixed delay is
    // enough under CI contention. The counter must drop to zero from the reset
    // itself — `backlog_bytes_for_test` only reads, and no other
    // state-touching op runs that could recompute the total.
    let mut reset_freed_accounting = false;
    for _ in 0..200 {
        if state.backlog_bytes_for_test().await == 0 {
            reset_freed_accounting = true;
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    assert!(
        reset_freed_accounting,
        "finished-room reset must free the discarded backlog accounting"
    );

    let (_subscriber_id, _backlog, _rx) = state.subscribe(key).await.unwrap();
    waiter.await.unwrap().unwrap();
    assert_eq!(state.backlog_bytes_for_test().await, 0);
}

#[tokio::test]
async fn broker_drops_finished_rooms_after_ttl() {
    let state = Arc::new(test_state(DEFAULT_BROKER_BACKLOG_DEPTH));
    let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
    let record = AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"hello".to_vec());

    state.publish(&key, record).await.unwrap();
    state.finish_room(&key).await;

    assert_eq!(state.room_count().await, 1);
    state
        .age_finished_room_for_test(&key, FINISHED_ROOM_TTL + Duration::from_secs(1))
        .await;
    state.drop_expired_finished_room(&key).await;
    assert_eq!(state.room_count().await, 0);
}

#[tokio::test]
async fn broker_purges_stale_unfinished_rooms_without_live_subscribers() {
    let state = test_state(DEFAULT_BROKER_BACKLOG_DEPTH);
    let stale_key = BrokerStreamKey::new(vec![0xab; 32], MessageId::new(vec![0x12; 32]));
    let live_key = BrokerStreamKey::new(vec![0xcd; 32], MessageId::new(vec![0x34; 32]));

    state
        .publish(
            &stale_key,
            AgentTextStreamRecordV1::text_delta(vec![0xab; 32], 1, b"stale".to_vec()),
        )
        .await
        .unwrap();
    state
        .publish(
            &live_key,
            AgentTextStreamRecordV1::text_delta(vec![0xcd; 32], 1, b"live".to_vec()),
        )
        .await
        .unwrap();
    let (_subscriber_id, _backlog, _rx) = state.subscribe(live_key.clone()).await.unwrap();
    state
        .age_unfinished_room_for_test(&stale_key, UNFINISHED_ROOM_TTL + Duration::from_secs(1))
        .await;
    state
        .age_unfinished_room_for_test(&live_key, UNFINISHED_ROOM_TTL + Duration::from_secs(1))
        .await;

    state
        .publish(
            &BrokerStreamKey::new(vec![0xef; 32], MessageId::new(vec![0x56; 32])),
            AgentTextStreamRecordV1::text_delta(vec![0xef; 32], 1, b"trigger".to_vec()),
        )
        .await
        .unwrap();

    assert_eq!(state.room_count().await, 2);
    let (_late_id, stale_backlog, _stale_rx) = state.subscribe(stale_key).await.unwrap();
    assert!(stale_backlog.is_empty());
    let (_live_id, live_backlog, _live_rx) = state.subscribe(live_key).await.unwrap();
    assert_eq!(live_backlog.len(), 1);
}

#[tokio::test]
async fn broker_buffers_records_until_subscriber_arrives() {
    let state = test_state(DEFAULT_BROKER_BACKLOG_DEPTH);
    let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
    let record = AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"hello".to_vec());

    assert_eq!(state.publish(&key, record.clone()).await.unwrap(), 0);
    let (_subscriber_id, backlog, _rx) = state.subscribe(key).await.unwrap();
    let received = backlog.first().expect("subscriber should receive backlog");

    assert_eq!(received.seq, record.seq);
    assert_eq!(received.plaintext_frame, record.plaintext_frame);
}

#[tokio::test]
async fn broker_backlog_drops_oldest_records_when_bound_reached() {
    let state = test_state(2);
    let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
    for seq in 1..=3 {
        let record = AgentTextStreamRecordV1::text_delta(
            vec![0xaa; 32],
            seq,
            format!("chunk-{seq}").into_bytes(),
        );
        assert_eq!(state.publish(&key, record).await.unwrap(), 0);
    }

    let (_subscriber_id, backlog, mut rx) = state.subscribe(key).await.unwrap();
    let first = backlog.first().expect("subscriber should receive backlog");
    let second = backlog.get(1).expect("subscriber should receive backlog");
    assert_eq!(first.seq, 2);
    assert_eq!(second.seq, 3);
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn broker_state_rejects_new_rooms_past_limit() {
    let state = BrokerState::new(
        DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        DEFAULT_BROKER_BACKLOG_DEPTH,
        1,
        usize::MAX,
        MAX_BROKER_REPLAY_TTL,
    );
    let first_key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
    let second_key = BrokerStreamKey::new(vec![0xbb; 32], MessageId::new(vec![0x22; 32]));

    state
        .publish(
            &first_key,
            AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"first".to_vec()),
        )
        .await
        .unwrap();
    let err = state
        .publish(
            &second_key,
            AgentTextStreamRecordV1::text_delta(vec![0xbb; 32], 1, b"second".to_vec()),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        QuicBrokerError::RoomLimitExceeded { limit: 1 }
    ));
    assert_eq!(state.room_count().await, 1);
}

#[tokio::test]
async fn broker_state_enforces_global_backlog_byte_budget() {
    let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
    let sample = AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"hello".to_vec());
    let state = BrokerState::new(
        DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        DEFAULT_BROKER_BACKLOG_DEPTH,
        4,
        sample.encode().unwrap().len() * 2,
        MAX_BROKER_REPLAY_TTL,
    );

    for seq in 1..=3 {
        state
            .publish(
                &key,
                AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], seq, b"hello".to_vec()),
            )
            .await
            .unwrap();
    }

    let (_subscriber_id, backlog, _rx) = state.subscribe(key).await.unwrap();
    assert_eq!(
        backlog.iter().map(|record| record.seq).collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert!(state.backlog_bytes_for_test().await <= sample.encode().unwrap().len() * 2);
}

#[tokio::test]
async fn broker_read_deadline_times_out_stalled_reads() {
    let err = broker_read_deadline(Duration::from_millis(5), async {
        sleep(Duration::from_millis(50)).await;
        Ok::<_, std::io::Error>(())
    })
    .await
    .unwrap_err();

    assert!(matches!(err, QuicBrokerError::ReadTimeout));
}

#[test]
fn broker_config_rejects_zero_resource_limits() {
    assert!(matches!(
        QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            max_rooms: 0,
            ..QuicBrokerConfig::default()
        }),
        Err(QuicBrokerError::EmptyRoomLimit)
    ));
    assert!(matches!(
        QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            max_connections: 0,
            ..QuicBrokerConfig::default()
        }),
        Err(QuicBrokerError::EmptyConnectionLimit)
    ));
    assert!(matches!(
        QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            max_streams_per_connection: 0,
            ..QuicBrokerConfig::default()
        }),
        Err(QuicBrokerError::EmptyStreamLimit)
    ));
    assert!(matches!(
        QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            read_timeout: Duration::ZERO,
            ..QuicBrokerConfig::default()
        }),
        Err(QuicBrokerError::EmptyReadTimeout)
    ));
    assert!(matches!(
        QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            publish_max_records: 0,
            ..QuicBrokerConfig::default()
        }),
        Err(QuicBrokerError::EmptyPublishRecordLimit)
    ));
    assert!(matches!(
        QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            publish_max_frame_bytes: 0,
            ..QuicBrokerConfig::default()
        }),
        Err(QuicBrokerError::EmptyPublishFrameByteLimit)
    ));
}

#[test]
fn oversized_frames_are_rejected_before_allocation() {
    assert!(matches!(
        validate_frame_len(MAX_FRAME_SIZE + 1, MAX_FRAME_SIZE),
        Err(QuicBrokerError::FrameTooLarge(_))
    ));
}

#[test]
fn stream_record_text_decodes_renderable_frames_and_leaves_advisory_records_empty() {
    use cgka_traits::agent_text_stream::{
        AGENT_TEXT_STREAM_RECORD_ABORT, AGENT_TEXT_STREAM_RECORD_FINAL_NOTICE,
    };

    let stream_id = vec![0x11; 32];
    let record = |record_type, plaintext: &str| {
        AgentTextStreamRecordV1::new(stream_id.clone(), 1, record_type, plaintext.as_bytes())
    };

    // Renderable frames decode to their UTF-8 plaintext. Checkpoint is a full
    // preview snapshot the consumer swaps in, so it must not stay blank.
    for (record_type, plaintext) in [
        (AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, "hello"),
        (AGENT_TEXT_STREAM_RECORD_STATUS, "thinking"),
        (AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA, "search: glp-1"),
        (AGENT_TEXT_STREAM_RECORD_CHECKPOINT, "hello world"),
    ] {
        assert_eq!(
            stream_record_text(&record(record_type, plaintext)),
            plaintext
        );
    }

    // Abort and FinalNotice are advisory: the consumer reacts to the record
    // type, so they decode to "" even when the sender attached bytes.
    for record_type in [
        AGENT_TEXT_STREAM_RECORD_ABORT,
        AGENT_TEXT_STREAM_RECORD_FINAL_NOTICE,
        0xff,
    ] {
        assert_eq!(stream_record_text(&record(record_type, "ignored")), "");
    }
}

#[test]
fn client_bind_addr_matches_broker_address_family() {
    assert_eq!(
        client_bind_addr_for_broker(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4450)),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    );
    assert_eq!(
        client_bind_addr_for_broker(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4450)),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    );
}

#[tokio::test]
async fn broker_can_bind_with_pem_certificate_files() {
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    std::fs::write(&cert_path, certified_key.cert.pem()).unwrap();
    std::fs::write(&key_path, certified_key.signing_key.serialize_pem()).unwrap();

    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        max_backlog: DEFAULT_BROKER_BACKLOG_DEPTH,
        tls: QuicBrokerTlsConfig::PemFiles {
            cert_path,
            key_path,
        },
        ..QuicBrokerConfig::default()
    })
    .unwrap();

    assert_eq!(server.server_cert_der(), certified_key.cert.der().as_ref());
}

#[test]
fn certificate_fingerprint_is_sha256_hex() {
    assert_eq!(
        certificate_sha256_fingerprint_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn broker_rejects_replay_ttl_above_profile_cap() {
    assert!(matches!(
        QuicBrokerServer::bind(QuicBrokerConfig {
            bind_addr: LOCAL_SERVER_BIND,
            replay_ttl: MAX_BROKER_REPLAY_TTL + Duration::from_secs(1),
            ..QuicBrokerConfig::default()
        }),
        Err(QuicBrokerError::ReplayTtlTooLarge {
            requested_secs: 301,
            cap_secs: 300
        })
    ));
}

#[tokio::test]
async fn broker_purges_expired_backlog_before_serving_late_subscriber() {
    let state = BrokerState::new(
        DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        DEFAULT_BROKER_BACKLOG_DEPTH,
        DEFAULT_BROKER_MAX_ROOMS,
        DEFAULT_BROKER_MAX_BACKLOG_BYTES,
        Duration::from_secs(30),
    );
    let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
    for seq in 1..=2 {
        state
            .publish(
                &key,
                AgentTextStreamRecordV1::text_delta(
                    vec![0xaa; 32],
                    seq,
                    format!("chunk-{seq}").into_bytes(),
                ),
            )
            .await
            .unwrap();
    }
    // Age the oldest entry past the replay window; the newer one stays.
    state
        .age_oldest_backlog_for_test(&key, 1, Duration::from_secs(31))
        .await;

    let (_subscriber_id, backlog, _rx) = state.subscribe(key).await.unwrap();
    assert_eq!(
        backlog.iter().map(|record| record.seq).collect::<Vec<_>>(),
        vec![2]
    );
}

#[tokio::test]
async fn broker_state_retains_no_backlog_with_default_zero_replay_ttl() {
    let state = BrokerState::new(
        DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        DEFAULT_BROKER_BACKLOG_DEPTH,
        DEFAULT_BROKER_MAX_ROOMS,
        DEFAULT_BROKER_MAX_BACKLOG_BYTES,
        DEFAULT_BROKER_REPLAY_TTL,
    );
    let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
    // Keep the room alive with a live subscriber, then publish.
    let (_subscriber_id, _backlog, mut rx) = state.subscribe(key.clone()).await.unwrap();
    state
        .publish(
            &key,
            AgentTextStreamRecordV1::text_delta(vec![0xaa; 32], 1, b"live".to_vec()),
        )
        .await
        .unwrap();
    assert_eq!(rx.recv().await.expect("live record").seq, 1);
    assert_eq!(state.backlog_bytes_for_test().await, 0);

    let (_late_id, backlog, _late_rx) = state.subscribe(key).await.unwrap();
    assert!(backlog.is_empty(), "zero replay ttl must serve no backlog");
}

#[tokio::test]
async fn broker_state_skips_record_encoding_when_replay_retention_is_disabled() {
    let key = BrokerStreamKey::new(vec![0xaa; 32], MessageId::new(vec![0x11; 32]));
    // `BrokerState` receives records that the frame decoder already validated.
    // This invalid record is a white-box canary: `encode()` rejects it, so a
    // no-replay publish must not touch the encode path at all.
    let invalid_record = AgentTextStreamRecordV1::text_delta(Vec::<u8>::new(), 1, b"live");
    assert!(invalid_record.encode().is_err());

    let no_replay_state = BrokerState::new(
        DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        DEFAULT_BROKER_BACKLOG_DEPTH,
        DEFAULT_BROKER_MAX_ROOMS,
        DEFAULT_BROKER_MAX_BACKLOG_BYTES,
        DEFAULT_BROKER_REPLAY_TTL,
    );
    assert_eq!(
        no_replay_state
            .publish(&key, invalid_record.clone())
            .await
            .unwrap(),
        0
    );
    assert_eq!(no_replay_state.backlog_bytes_for_test().await, 0);

    let retaining_state = BrokerState::new(
        DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        DEFAULT_BROKER_BACKLOG_DEPTH,
        DEFAULT_BROKER_MAX_ROOMS,
        DEFAULT_BROKER_MAX_BACKLOG_BYTES,
        Duration::from_secs(30),
    );
    assert!(matches!(
        retaining_state
            .publish(&key, invalid_record)
            .await
            .unwrap_err(),
        QuicBrokerError::Record(_)
    ));
}

#[tokio::test]
async fn broker_serves_no_backlog_to_late_subscriber_by_default() {
    // Default config: replay_ttl is zero, so a late subscriber sees only
    // live records. Its first record is ahead of seq 1, which it must
    // report as a gap instead of silently producing a wrong transcript.
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let stream_id = vec![0xe1; 32];
    let start_event_id = MessageId::new(vec![0x71; 32]);
    let early_subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
    }));
    sleep(Duration::from_millis(100)).await;

    let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
        max_plaintext_frame_len: None,
    })
    .await
    .unwrap();
    publisher
        .append_text("ab", 1, Duration::ZERO)
        .await
        .unwrap();
    sleep(Duration::from_millis(100)).await;

    let late_subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert),
        stream_id: stream_id.clone(),
        start_event_id,
        crypto: None,
    }));
    sleep(Duration::from_millis(100)).await;

    publisher.append_text("c", 1, Duration::ZERO).await.unwrap();
    let _ = publisher.finish().await.unwrap();

    let early_received = timeout(Duration::from_secs(5), early_subscriber)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(early_received.text, "abc");

    let late_err = timeout(Duration::from_secs(5), late_subscriber)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        late_err,
        QuicBrokerError::UnexpectedSequence {
            expected: 1,
            actual: 3
        }
    ));

    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn subscriber_discards_duplicate_records_replayed_through_broker() {
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let stream_id = vec![0xe2; 32];
    let start_event_id = MessageId::new(vec![0x72; 32]);
    let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
    }));
    sleep(Duration::from_millis(100)).await;

    // Raw publisher that re-sends an already-delivered record, like a
    // broker replaying retained backlog on reconnect. The duplicate must
    // be discarded silently by the subscriber, never stream-fatal.
    let endpoint =
        client_endpoint(BrokerServerTrust::CertificateDer(server_cert), broker_addr).unwrap();
    let connection = endpoint
        .connect(broker_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let mut send = connection.open_uni().await.unwrap();
    write_control_frame(
        &mut send,
        &QuicBrokerControlEnvelopeV1::publish(stream_id.clone(), &start_event_id),
    )
    .await
    .unwrap();
    let first = AgentTextStreamRecordV1::text_delta(stream_id.clone(), 1, b"he".to_vec());
    let second = AgentTextStreamRecordV1::text_delta(stream_id.clone(), 2, b"ll".to_vec());
    let third = AgentTextStreamRecordV1::text_delta(stream_id.clone(), 3, b"o".to_vec());
    for record in [&first, &second, &first, &second, &third] {
        write_record_frame(&mut send, record).await.unwrap();
    }
    send.finish().unwrap();
    let _ = timeout(SEND_STOP_WAIT, send.stopped()).await;
    connection.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;

    let received = timeout(Duration::from_secs(5), subscriber)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(received.text, "hello");
    assert_eq!(received.chunk_count, 3);
    assert_eq!(
        received
            .chunks
            .iter()
            .map(|chunk| chunk.seq)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );

    let mut transcript = AgentTextStreamTranscriptV1::new(stream_id, start_event_id);
    transcript.append(1, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"he");
    transcript.append(2, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"ll");
    transcript.append(3, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"o");
    assert_eq!(received.transcript_hash, transcript.hash());

    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn broker_subscriber_counts_replayed_duplicates_against_record_limit() {
    // Regression: a malicious/compromised broker can replay `seq <= high_water`
    // frames forever. The subscriber's dedup `continue` discards them before
    // limit accounting, so before the fix those frames never counted against
    // `max_records` and the loop read/allocated unboundedly. Here a custom
    // publisher sends one accepted record then a duplicate `seq=1`; with
    // `max_records: 1` the subscriber must trip the record limit on the
    // duplicate frame instead of silently discarding it and succeeding.
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let stream_id = vec![0xe5; 32];
    let start_event_id = MessageId::new(vec![0x75; 32]);
    let subscriber = tokio::spawn(subscribe_text_from_broker_with_limits(
        SubscribeTextFromBroker {
            broker_addr,
            server_name: "localhost".to_owned(),
            trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
            stream_id: stream_id.clone(),
            start_event_id: start_event_id.clone(),
            crypto: None,
        },
        AgentTextStreamReceiveLimits {
            max_records: 1,
            max_plaintext_bytes: 1024,
            ..AgentTextStreamReceiveLimits::default()
        },
        |_| {},
    ));
    sleep(Duration::from_millis(100)).await;

    // Raw publisher that sends one accepted record then re-sends `seq=1`, like
    // a broker replaying retained backlog. The duplicate must count against the
    // limit, not be discarded before accounting.
    let endpoint =
        client_endpoint(BrokerServerTrust::CertificateDer(server_cert), broker_addr).unwrap();
    let connection = endpoint
        .connect(broker_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let mut send = connection.open_uni().await.unwrap();
    write_control_frame(
        &mut send,
        &QuicBrokerControlEnvelopeV1::publish(stream_id.clone(), &start_event_id),
    )
    .await
    .unwrap();
    let accepted = AgentTextStreamRecordV1::text_delta(stream_id.clone(), 1, b"hi".to_vec());
    for record in [&accepted, &accepted] {
        write_record_frame(&mut send, record).await.unwrap();
    }
    send.finish().unwrap();
    let _ = timeout(SEND_STOP_WAIT, send.stopped()).await;

    let err = timeout(Duration::from_secs(5), subscriber)
        .await
        .expect("subscriber should trip the record limit on the replayed duplicate")
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        err,
        QuicBrokerError::ReceiveLimit(AgentTextStreamReceiveLimitError::RecordLimitExceeded {
            attempted: 2,
            limit: 1
        })
    ));

    connection.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;
    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn broker_negotiates_v1_alpn_and_rejects_clients_without_it() {
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    // The broker-path client endpoint negotiates marmot.quic_broker.v1.
    let endpoint = client_endpoint(
        BrokerServerTrust::CertificateDer(server_cert.clone()),
        broker_addr,
    )
    .unwrap();
    let connection = endpoint
        .connect(broker_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let handshake = connection
        .handshake_data()
        .expect("handshake data available")
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .expect("rustls handshake data");
    assert_eq!(handshake.protocol.as_deref(), Some(QUIC_BROKER_ALPN_V1));
    connection.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;

    // A client that offers no ALPN fails the TLS handshake.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let crypto = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new(provider))
        .with_no_client_auth();
    let client_config = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto).expect("quic client config"),
    ));
    let mut no_alpn_endpoint = Endpoint::client(LOCAL_SERVER_BIND).unwrap();
    no_alpn_endpoint.set_default_client_config(client_config);
    let result = no_alpn_endpoint
        .connect(broker_addr, "localhost")
        .unwrap()
        .await;
    assert!(
        result.is_err(),
        "broker must reject clients without the broker ALPN"
    );
    no_alpn_endpoint.wait_idle().await;

    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn broker_rejects_publish_envelope_on_bidirectional_stream() {
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let endpoint =
        client_endpoint(BrokerServerTrust::CertificateDer(server_cert), broker_addr).unwrap();
    let connection = endpoint
        .connect(broker_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    write_control_frame(
        &mut send,
        &QuicBrokerControlEnvelopeV1::publish(vec![0xe3; 32], &MessageId::new(vec![0x73; 32])),
    )
    .await
    .unwrap();
    send.finish().unwrap();

    // The broker rejects the stream without serving any records: the
    // return direction errors instead of delivering a record frame.
    let read = timeout(
        Duration::from_secs(5),
        read_record_frame(&mut recv, None, MAX_FRAME_SIZE),
    )
    .await
    .expect("broker should answer the rejected stream promptly");
    assert!(
        read.is_err(),
        "publish envelope on a bidirectional stream must be rejected"
    );

    connection.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;
    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn broker_rejects_subscribe_envelope_on_unidirectional_stream() {
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    // The broker task is intentionally not joined: the test returns while
    // the legit subscriber is still parked waiting for a publisher.
    let _broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let stream_id = vec![0xe4; 32];
    let start_event_id = MessageId::new(vec![0x74; 32]);
    let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
    }));
    sleep(Duration::from_millis(100)).await;

    // A rogue client that sends a subscribe envelope on a unidirectional
    // stream and then writes record frames must not be treated as the
    // room's publisher.
    let endpoint =
        client_endpoint(BrokerServerTrust::CertificateDer(server_cert), broker_addr).unwrap();
    let connection = endpoint
        .connect(broker_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let mut send = connection.open_uni().await.unwrap();
    write_control_frame(
        &mut send,
        &QuicBrokerControlEnvelopeV1::subscribe(stream_id.clone(), &start_event_id),
    )
    .await
    .unwrap();
    let _ = write_record_frame(
        &mut send,
        &AgentTextStreamRecordV1::text_delta(stream_id, 1, b"rogue".to_vec()),
    )
    .await;
    let _ = send.finish();

    // The legit subscriber must not receive the rogue record; it stays
    // blocked waiting for a real publisher.
    let subscriber = match timeout(Duration::from_millis(500), subscriber).await {
        Err(_) => {
            connection.close(0_u32.into(), b"done");
            endpoint.wait_idle().await;
            let _ = shutdown_tx.send(());
            return;
        }
        Ok(joined) => joined,
    };
    panic!("subscriber should still be waiting, got {subscriber:?}");
}

#[test]
fn broker_and_direct_transports_share_hardening_profile() {
    use transport_quic_stream::{
        QUIC_PREVIEW_KEEP_ALIVE_INTERVAL, QUIC_PREVIEW_MAX_FRAME_LEN, QUIC_PREVIEW_MAX_IDLE_TIMEOUT,
    };

    use crate::protocol::{DEFAULT_BROKER_KEEP_ALIVE_INTERVAL, DEFAULT_BROKER_MAX_IDLE_TIMEOUT};
    use crate::tls::broker_transport_config;

    // One hardening profile drives both transports: the broker's public
    // defaults are aliases of the shared constants, and its frame cap is the
    // shared cap. Paired with the direct-path liveness test in
    // `transport-quic-stream`, this pins both servers to equivalent bounds.
    assert_eq!(
        DEFAULT_BROKER_MAX_IDLE_TIMEOUT,
        QUIC_PREVIEW_MAX_IDLE_TIMEOUT
    );
    assert_eq!(
        DEFAULT_BROKER_KEEP_ALIVE_INTERVAL,
        QUIC_PREVIEW_KEEP_ALIVE_INTERVAL
    );
    assert_eq!(MAX_FRAME_SIZE, QUIC_PREVIEW_MAX_FRAME_LEN);

    // Same Debug-based check as the direct path, since quinn exposes no
    // transport-config getters.
    let transport = format!(
        "{:?}",
        broker_transport_config(&QuicBrokerConfig::default()).unwrap()
    );
    assert!(
        transport.contains("max_idle_timeout: Some(30000)"),
        "{transport}"
    );
    assert!(
        transport.contains("keep_alive_interval: Some(10s)"),
        "{transport}"
    );
    assert!(
        transport.contains("max_concurrent_uni_streams: 64,"),
        "{transport}"
    );
    assert!(
        transport.contains("max_concurrent_bidi_streams: 64,"),
        "{transport}"
    );
}

#[test]
fn broker_server_and_client_configs_disable_early_data() {
    use crate::tls::{broker_rustls_client_config, broker_rustls_server_config};

    // Pin the shared early-data policy: TLS 0-RTT stays off on the broker
    // because it has no app-layer anti-replay, so replayable early data would
    // let a passive attacker replay publish control frames to create/feed
    // rooms without a fresh handshake.
    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(certified_key.cert);
    let key_der =
        rustls::pki_types::PrivatePkcs8KeyDer::from(certified_key.signing_key.serialize_der());
    let server = broker_rustls_server_config(vec![cert_der], key_der.into()).unwrap();
    assert_eq!(server.max_early_data_size, 0);

    let client = broker_rustls_client_config(
        BrokerServerTrust::InsecureLocal,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4450),
    )
    .unwrap();
    assert!(!client.enable_early_data);
}

#[tokio::test]
async fn broker_applies_one_deadline_across_dribbled_length_prefix() {
    // One deadline must span the whole control-frame read: with the old
    // per-`recv.read()` deadline, every delivered byte restarted the window,
    // so a peer dribbling one length-prefix byte per window stretched the
    // pre-auth read to FRAME_LEN_BYTES x read_timeout. Dribble bytes slower
    // than the whole-frame deadline and assert the broker stops the stream.
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        read_timeout: Duration::from_millis(300),
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let endpoint =
        client_endpoint(BrokerServerTrust::CertificateDer(server_cert), broker_addr).unwrap();
    let connection = endpoint
        .connect(broker_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let mut send = connection.open_uni().await.unwrap();

    // Declare a valid (sub-cap) control frame length so only the deadline,
    // never the length check, can end the read. One byte per 200ms lands
    // every write inside a fresh 300ms per-read window, but the whole prefix
    // takes ~600ms: only a whole-frame deadline stops the stream before the
    // 4-byte length prefix completes.
    let mut accepted_bytes = 0;
    for byte in 100_u32.to_be_bytes() {
        if send.write_all(&[byte]).await.is_err() {
            break;
        }
        accepted_bytes += 1;
        sleep(Duration::from_millis(200)).await;
    }
    timeout(Duration::from_secs(5), send.stopped())
        .await
        .expect("broker stops the dribbled stream")
        .unwrap();
    assert!(
        accepted_bytes < 4,
        "whole-frame deadline must fire before the dribbled length prefix \
         completes; {accepted_bytes} bytes were accepted"
    );

    connection.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;
    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[test]
fn max_control_frame_len_covers_maximal_valid_envelope() {
    use crate::protocol::MAX_CONTROL_FRAME_LEN;

    // A maximal valid envelope (64-byte stream id, 64-byte start event id)
    // encodes to 155 bytes: 1+21 protocol string, 1 type, and 2+64 for each
    // id (a QUIC varint needs 2 bytes for lengths above 63). The pre-auth cap
    // keeps headroom above it while forbidding the previous ~66 KB pre-auth
    // allocation.
    let envelope =
        QuicBrokerControlEnvelopeV1::publish(vec![0x42; 64], &MessageId::new(vec![0x24; 64]));
    let encoded = envelope.encode().unwrap();
    assert_eq!(encoded.len(), 155);
    assert!(encoded.len() <= MAX_CONTROL_FRAME_LEN);

    assert!(validate_frame_len(155, MAX_CONTROL_FRAME_LEN).is_ok());
    assert!(matches!(
        validate_frame_len(MAX_CONTROL_FRAME_LEN + 1, MAX_CONTROL_FRAME_LEN),
        Err(QuicBrokerError::FrameTooLarge(_))
    ));
}

#[tokio::test]
async fn broker_rejects_control_frames_above_control_cap() {
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let endpoint =
        client_endpoint(BrokerServerTrust::CertificateDer(server_cert), broker_addr).unwrap();
    let connection = endpoint
        .connect(broker_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let mut send = connection.open_uni().await.unwrap();
    // Declare a 1 KiB control frame: valid as a record-sized frame, but far
    // above the 256-byte control cap, so the broker rejects it at the length
    // check without reading or allocating the payload.
    send.write_all(&1024_u32.to_be_bytes()).await.unwrap();
    send.write_all(&[0_u8; 64]).await.unwrap();

    timeout(Duration::from_secs(5), send.stopped())
        .await
        .expect("broker stops oversized control frames")
        .unwrap();

    connection.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;
    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn broker_forwards_long_publish_past_receive_defaults_without_closing_room() {
    // Forward-role limits come from broker config, not the subscriber-sized
    // receive defaults (4096 records / 1 MiB): a legitimate long preview must
    // pass through the broker without the room closing mid-stream.
    let record_count = 4097_usize;
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        // Big enough that the subscriber's live queue never backpressure-drops
        // it while the publisher streams the whole preview.
        per_subscriber_queue: 2 * record_count,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let stream_id = vec![0xc4; 32];
    let start_event_id = MessageId::new(vec![0x91; 32]);
    let subscriber_limits = AgentTextStreamReceiveLimits {
        max_records: 2 * record_count as u64,
        max_plaintext_bytes: 16 * 1024 * 1024,
        ..AgentTextStreamReceiveLimits::default()
    };
    let subscriber_config = SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
    };
    let subscriber = tokio::spawn(subscribe_text_from_broker_with_limits(
        subscriber_config,
        subscriber_limits,
        |_| {},
    ));
    sleep(Duration::from_millis(100)).await;

    // One byte per record pushes the record count past the receiver default.
    let sent = publish_text_to_broker(PublishTextToBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert),
        stream_id: stream_id.clone(),
        start_event_id,
        text: "a".repeat(record_count),
        max_chunk_bytes: 1,
        chunk_delay: Duration::ZERO,
        crypto: None,
        max_plaintext_frame_len: None,
    })
    .await
    .unwrap();
    assert_eq!(sent.chunk_count, record_count as u64);

    let received = timeout(Duration::from_secs(30), subscriber)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(received.chunk_count, record_count as u64);
    assert_eq!(received.text.len(), record_count);
    assert_eq!(sent.transcript_hash, received.transcript_hash);

    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn broker_publish_forward_limits_come_from_config() {
    // An operator-tuned publish cap ends the room after exactly that many
    // forwarded records: the subscriber sees a clean end of stream with the
    // records forwarded before the limit tripped.
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        publish_max_records: 8,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let stream_id = vec![0xd7; 32];
    let start_event_id = MessageId::new(vec![0x3c; 32]);
    let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
    }));
    sleep(Duration::from_millis(100)).await;

    let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert),
        stream_id: stream_id.clone(),
        start_event_id,
        crypto: None,
        max_plaintext_frame_len: None,
    })
    .await
    .unwrap();
    publisher
        .append_text("abcdefghi", 1, Duration::ZERO)
        .await
        .unwrap();
    // The broker kills the publish stream on record 9; the publisher's close
    // handshake may surface that asynchronously, so its result is not the
    // assertion here.
    let _ = publisher.finish().await;

    let received = timeout(Duration::from_secs(5), subscriber)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(received.chunk_count, 8);
    assert_eq!(received.text, "abcdefgh");

    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn subscriber_replaces_invalid_utf8_frame_instead_of_aborting_stream() {
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let stream_id = vec![0xe8; 32];
    let start_event_id = MessageId::new(vec![0x55; 32]);
    let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
    }));
    sleep(Duration::from_millis(100)).await;

    // Raw publisher so the middle frame can carry authentic-but-non-UTF-8
    // bytes; the broker forwards records without decoding their text.
    let endpoint =
        client_endpoint(BrokerServerTrust::CertificateDer(server_cert), broker_addr).unwrap();
    let connection = endpoint
        .connect(broker_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let mut send = connection.open_uni().await.unwrap();
    write_control_frame(
        &mut send,
        &QuicBrokerControlEnvelopeV1::publish(stream_id.clone(), &start_event_id),
    )
    .await
    .unwrap();
    let records = vec![
        AgentTextStreamRecordV1::text_delta(stream_id.clone(), 1, b"ok".to_vec()),
        AgentTextStreamRecordV1::text_delta(stream_id.clone(), 2, vec![0xff, 0xfe]),
        AgentTextStreamRecordV1::text_delta(stream_id.clone(), 3, b"done".to_vec()),
    ];
    for record in &records {
        write_record_frame(&mut send, record).await.unwrap();
    }
    send.finish().unwrap();
    let _ = timeout(SEND_STOP_WAIT, send.stopped()).await;
    connection.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;

    let received = timeout(Duration::from_secs(5), subscriber)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // The non-UTF-8 frame renders as replacement characters instead of
    // tearing down the preview; transcript hashing covers the raw bytes, so
    // the transcripts still match a sender-side transcript over them.
    assert_eq!(received.chunk_count, 3);
    assert_eq!(received.chunks[1].text, "\u{FFFD}\u{FFFD}");
    assert_eq!(received.text, "ok\u{FFFD}\u{FFFD}done");
    let mut expected_transcript = AgentTextStreamTranscriptV1::new(stream_id, start_event_id);
    for record in &records {
        expected_transcript.append(record.seq, record.record_type, &record.plaintext_frame);
    }
    assert_eq!(received.transcript_hash, expected_transcript.hash());

    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn broker_subscribe_snapshots_backlog_by_reference() {
    // The backlog snapshot handed to a subscriber must be Arc clones of the
    // retained records, not deep copies: serving even a full backlog under
    // the single global broker mutex then costs pointer-sized clones only.
    let state = test_state(DEFAULT_BROKER_BACKLOG_DEPTH);
    let key = BrokerStreamKey {
        stream_id: vec![0xaa; 32],
        start_event_id: MessageId::new(vec![0x77; 32]),
    };
    let record =
        AgentTextStreamRecordV1::text_delta(key.stream_id.clone(), 1, b"retained".to_vec());
    state.publish(&key, record).await.unwrap();

    let (first_id, first_backlog, _first_rx) = state.subscribe(key.clone()).await.unwrap();
    let (_second_id, second_backlog, _second_rx) = state.subscribe(key.clone()).await.unwrap();
    assert_eq!(first_backlog.len(), 1);
    assert_eq!(second_backlog.len(), 1);
    assert!(Arc::ptr_eq(&first_backlog[0], &second_backlog[0]));
    state.unsubscribe(&key, first_id).await;
}

#[tokio::test]
async fn broker_publish_frame_byte_limit_counts_wire_bytes_for_encrypted_records() {
    // The broker forwards records without decrypting, so the publish byte
    // budget counts the frame payload as carried on the wire: for encrypted
    // previews that is ciphertext, i.e. plaintext plus a 16-byte AEAD tag per
    // record. Five 10-byte plaintext chunks (50 plaintext bytes) encrypt to
    // 26-byte wire frames; against a 100-byte budget the fourth record trips
    // it (4 x 26 = 104), while a plaintext-counting budget would have passed
    // all five. This pins the wire semantics the knob's name advertises.
    let stream_id = vec![0xb1; 32];
    let start_event_id = MessageId::new(vec![0x66; 32]);
    let crypto = AgentTextStreamCrypto::new(
        SecretBytes::new(vec![0x07; 32]),
        AgentTextStreamKeyContextV1::new(
            GroupId::new(vec![0x01; 32]),
            stream_id.clone(),
            EpochId(3),
            MemberId::new(vec![0x02; 32]),
            start_event_id.clone(),
        ),
    )
    .with_publisher_sequence_store(Arc::new(EphemeralPublisherSequenceStore::default()));

    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: LOCAL_SERVER_BIND,
        publish_max_frame_bytes: 100,
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: Some(crypto.clone()),
    }));
    sleep(Duration::from_millis(100)).await;

    let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert),
        stream_id: stream_id.clone(),
        start_event_id,
        crypto: Some(crypto),
        max_plaintext_frame_len: None,
    })
    .await
    .unwrap();
    publisher
        .append_text(&"a".repeat(50), 10, Duration::ZERO)
        .await
        .unwrap();
    // The broker kills the publish stream on the fourth record; the
    // publisher's close handshake may surface that asynchronously.
    let _ = publisher.finish().await;

    let received = timeout(Duration::from_secs(5), subscriber)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(received.chunk_count, 3);
    assert_eq!(received.text, "a".repeat(30));

    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

const TEST_WRITE_TIMEOUT: Duration = Duration::from_millis(250);
const TEST_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const TEST_KEEP_ALIVE: Duration = Duration::from_millis(400);
const STALL_SEND_WINDOW: u64 = 2048;
const STALL_STREAM_RECEIVE_WINDOW: u32 = 1024;
const HANDSHAKE_RECEIVE_WINDOW: u32 = 1_250_000;
const STALL_PAYLOAD_LEN: usize = 32_768;

fn stall_record(stream_id: &[u8], seq: u64) -> AgentTextStreamRecordV1 {
    AgentTextStreamRecordV1::text_delta(stream_id.to_vec(), seq, vec![b'x'; STALL_PAYLOAD_LEN])
}

fn small_record(stream_id: &[u8], seq: u64, payload: &[u8]) -> AgentTextStreamRecordV1 {
    AgentTextStreamRecordV1::text_delta(stream_id.to_vec(), seq, payload.to_vec())
}

fn injected_write_policy(max_streams: usize) -> BrokerStreamPolicy {
    BrokerStreamPolicy {
        max_streams_per_connection: max_streams,
        read_timeout: Duration::from_secs(5),
        write_timeout: TEST_WRITE_TIMEOUT,
        publish_limits: PublishForwardLimits {
            max_records: 4096,
            max_frame_bytes: 64 * 1024 * 1024,
        },
    }
}

fn client_writer_stall_transport() -> TransportConfig {
    let mut transport = QuicPreviewTransportProfile::client()
        .transport_config()
        .expect("client transport");
    transport
        .max_idle_timeout(Some(TEST_IDLE_TIMEOUT.try_into().expect("idle timeout")))
        .keep_alive_interval(Some(TEST_KEEP_ALIVE))
        .send_window(STALL_SEND_WINDOW)
        .receive_window(VarInt::from_u32(HANDSHAKE_RECEIVE_WINDOW));
    transport
}

fn client_unread_receiver_transport() -> TransportConfig {
    let mut transport = QuicPreviewTransportProfile::client()
        .transport_config()
        .expect("client transport");
    transport
        .max_idle_timeout(Some(TEST_IDLE_TIMEOUT.try_into().expect("idle timeout")))
        .keep_alive_interval(Some(TEST_KEEP_ALIVE))
        .stream_receive_window(VarInt::from_u32(STALL_STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(HANDSHAKE_RECEIVE_WINDOW));
    transport
}

fn server_writer_stall_transport() -> TransportConfig {
    let mut transport =
        QuicPreviewTransportProfile::broker_server(8, TEST_IDLE_TIMEOUT, TEST_KEEP_ALIVE)
            .transport_config()
            .expect("broker transport");
    transport.send_window(STALL_SEND_WINDOW);
    transport
}

fn server_unread_receiver_transport() -> TransportConfig {
    let mut transport =
        QuicPreviewTransportProfile::broker_server(8, TEST_IDLE_TIMEOUT, TEST_KEEP_ALIVE)
            .transport_config()
            .expect("broker transport");
    transport.stream_receive_window(VarInt::from_u32(STALL_STREAM_RECEIVE_WINDOW));
    transport
}

fn flow_controlled_client_endpoint(server_cert: Vec<u8>, broker_addr: SocketAddr) -> Endpoint {
    let crypto =
        broker_rustls_client_config(BrokerServerTrust::CertificateDer(server_cert), broker_addr)
            .unwrap();
    let mut client_config = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto).expect("quic client config"),
    ));
    client_config.transport_config(Arc::new(client_unread_receiver_transport()));
    let mut endpoint = Endpoint::client(client_bind_addr_for_broker(broker_addr)).unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
}

struct FlowControlledBroker {
    state: Arc<BrokerState>,
    server_endpoint: Endpoint,
    client_endpoint: Endpoint,
    reading_client_endpoint: Endpoint,
    broker_addr: SocketAddr,
    accept_task: JoinHandle<()>,
}

async fn spawn_flow_controlled_broker(
    state: Arc<BrokerState>,
    policy: BrokerStreamPolicy,
) -> FlowControlledBroker {
    let (mut server_config, server_cert) =
        configure_server(&QuicBrokerTlsConfig::GenerateSelfSigned {
            subject_alt_names: vec!["localhost".to_owned()],
        })
        .unwrap();
    server_config.transport_config(Arc::new(server_writer_stall_transport()));
    let server_endpoint = Endpoint::server(server_config, LOCAL_SERVER_BIND).unwrap();
    let broker_addr = server_endpoint.local_addr().unwrap();
    let stalled_client = flow_controlled_client_endpoint(server_cert.clone(), broker_addr);
    let reading_client =
        client_endpoint(BrokerServerTrust::CertificateDer(server_cert), broker_addr).unwrap();
    let accept_endpoint = server_endpoint.clone();
    let accept_state = Arc::clone(&state);
    let accept_task = tokio::spawn(async move {
        while let Some(incoming) = accept_endpoint.accept().await {
            let Ok(connecting) = incoming.await else {
                continue;
            };
            let state = Arc::clone(&accept_state);
            tokio::spawn(async move {
                let _ = handle_connection(state, connecting, policy).await;
            });
        }
    });
    FlowControlledBroker {
        state,
        server_endpoint,
        client_endpoint: stalled_client,
        reading_client_endpoint: reading_client,
        broker_addr,
        accept_task,
    }
}

impl FlowControlledBroker {
    async fn connect_stalled(&self) -> quinn::Connection {
        self.client_endpoint
            .connect(self.broker_addr, "localhost")
            .unwrap()
            .await
            .unwrap()
    }

    async fn connect_reading(&self) -> quinn::Connection {
        self.reading_client_endpoint
            .connect(self.broker_addr, "localhost")
            .unwrap()
            .await
            .unwrap()
    }

    async fn shutdown(self) {
        self.client_endpoint.close(0_u32.into(), b"done");
        self.reading_client_endpoint.close(0_u32.into(), b"done");
        self.server_endpoint.close(0_u32.into(), b"done");
        let _ = timeout(Duration::from_secs(2), self.client_endpoint.wait_idle()).await;
        let _ = timeout(
            Duration::from_secs(2),
            self.reading_client_endpoint.wait_idle(),
        )
        .await;
        let _ = timeout(Duration::from_secs(2), self.server_endpoint.wait_idle()).await;
        self.accept_task.abort();
        let _ = self.accept_task.await;
    }
}

async fn subscribe_unread(
    connection: &quinn::Connection,
    stream_id: &[u8],
    start_event_id: &MessageId,
) -> (quinn::SendStream, quinn::RecvStream) {
    let (mut send, recv) = connection.open_bi().await.unwrap();
    write_control_frame(
        &mut send,
        &QuicBrokerControlEnvelopeV1::subscribe(stream_id.to_vec(), start_event_id),
    )
    .await
    .unwrap();
    send.finish().unwrap();
    (send, recv)
}

async fn wait_live_subscribers(state: &BrokerState, key: &BrokerStreamKey, expected: usize) {
    timeout(Duration::from_secs(2), async {
        loop {
            if state.live_subscriber_count_for_test(key).await == expected {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("timed out waiting for {expected} live subscriber(s)");
    });
}

struct FlowControlledWritePair {
    server_endpoint: Endpoint,
    client_endpoint: Endpoint,
    server_connection: quinn::Connection,
    client_connection: quinn::Connection,
    send: quinn::SendStream,
    accept:
        Option<JoinHandle<Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>>>,
}

async fn connected_flow_controlled_pair() -> FlowControlledWritePair {
    let (mut server_config, server_cert) =
        configure_server(&QuicBrokerTlsConfig::GenerateSelfSigned {
            subject_alt_names: vec!["localhost".to_owned()],
        })
        .unwrap();
    server_config.transport_config(Arc::new(server_unread_receiver_transport()));
    let server_endpoint = Endpoint::server(server_config, LOCAL_SERVER_BIND).unwrap();
    let broker_addr = server_endpoint.local_addr().unwrap();
    let writer_crypto =
        broker_rustls_client_config(BrokerServerTrust::CertificateDer(server_cert), broker_addr)
            .unwrap();
    let mut writer_config = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(writer_crypto).expect("quic client config"),
    ));
    writer_config.transport_config(Arc::new(client_writer_stall_transport()));
    let mut client_endpoint = Endpoint::client(client_bind_addr_for_broker(broker_addr)).unwrap();
    client_endpoint.set_default_client_config(writer_config);
    let incoming = server_endpoint.accept();
    let connecting = client_endpoint.connect(broker_addr, "localhost").unwrap();
    let (server_connection, client_connection) = timeout(Duration::from_secs(2), async {
        tokio::join!(
            async { incoming.await.expect("incoming").await.unwrap() },
            async { connecting.await.unwrap() }
        )
    })
    .await
    .expect("flow-controlled handshake");
    let accept_connection = server_connection.clone();
    let accept = tokio::spawn(async move { accept_connection.accept_bi().await });
    let (send, _client_recv) = timeout(Duration::from_secs(2), client_connection.open_bi())
        .await
        .expect("open bi")
        .unwrap();
    FlowControlledWritePair {
        server_endpoint,
        client_endpoint,
        server_connection,
        client_connection,
        send,
        accept: Some(accept),
    }
}

impl FlowControlledWritePair {
    async fn shutdown(mut self) {
        self.client_connection.close(0_u32.into(), b"done");
        self.server_connection.close(0_u32.into(), b"done");
        if let Some(accept) = self.accept.take() {
            accept.abort();
        }
        let _ = timeout(Duration::from_secs(2), self.client_endpoint.wait_idle()).await;
        let _ = timeout(Duration::from_secs(2), self.server_endpoint.wait_idle()).await;
    }
}

#[test]
fn subscriber_write_deadline_reuses_record_quiet_gap() {
    assert_eq!(SUBSCRIBER_WRITE_DEADLINE, RECORD_QUIET_GAP_DEADLINE);
    assert_eq!(SUBSCRIBER_WRITE_DEADLINE, Duration::from_secs(120));
}

#[tokio::test]
async fn broker_write_deadline_times_out_stalled_writes() {
    let err = broker_write_deadline(Duration::from_millis(5), async {
        sleep(Duration::from_millis(50)).await;
        Ok::<_, std::io::Error>(())
    })
    .await
    .unwrap_err();

    assert!(matches!(err, QuicBrokerError::WriteTimeout));
    assert!(!matches!(err, QuicBrokerError::ReadTimeout));
}

#[tokio::test]
async fn broker_write_deadline_uses_one_budget_across_incremental_progress() {
    // Two 60ms phases finish inside a restarted 100ms per-phase window, but
    // one budget covering prefix plus body must fire at 100ms.
    let err = broker_write_deadline(Duration::from_millis(100), async {
        sleep(Duration::from_millis(60)).await;
        sleep(Duration::from_millis(60)).await;
        Ok::<_, std::io::Error>(())
    })
    .await
    .unwrap_err();

    assert!(matches!(err, QuicBrokerError::WriteTimeout));
}

#[tokio::test]
async fn write_record_frame_with_deadline_round_trips_record() {
    let mut pair = connected_flow_controlled_pair().await;
    let record = small_record(&[0x51; 32], 1, b"round-trip");
    let write = write_record_frame_with_deadline(&mut pair.send, &record, TEST_WRITE_TIMEOUT);
    let accept = pair.accept.take().expect("accept task");
    let (write_result, accept_result) = tokio::join!(write, accept);
    write_result.unwrap();
    let (_, mut recv) = accept_result.unwrap().unwrap();
    pair.send.finish().unwrap();
    let received = read_record_frame(&mut recv, Some(Duration::from_secs(2)), MAX_FRAME_SIZE)
        .await
        .unwrap()
        .expect("record");
    assert_eq!(received.encode().unwrap(), record.encode().unwrap());
    pair.shutdown().await;
}

#[tokio::test]
async fn unbounded_record_write_stays_pending_when_peer_does_not_read() {
    // Baseline: the pre-fix helper has no application deadline, so a
    // flow-controlled write stays pending past a bounded watchdog.
    let mut pair = connected_flow_controlled_pair().await;
    let record = stall_record(&[0x52; 32], 1);
    let write = timeout(
        TEST_WRITE_TIMEOUT,
        write_record_frame(&mut pair.send, &record),
    );
    let accept = timeout(
        Duration::from_secs(2),
        pair.accept.take().expect("accept task"),
    );
    let (pending, _accepted) = tokio::join!(write, accept);
    assert!(
        pending.is_err(),
        "unbounded write_record_frame must still be pending while the peer does not read"
    );
    pair.shutdown().await;
}

#[tokio::test]
async fn write_record_frame_with_deadline_returns_write_timeout_when_peer_does_not_read() {
    let mut pair = connected_flow_controlled_pair().await;
    let record = stall_record(&[0x53; 32], 1);
    let write = write_record_frame_with_deadline(&mut pair.send, &record, TEST_WRITE_TIMEOUT);
    let accept = timeout(
        Duration::from_secs(2),
        pair.accept.take().expect("accept task"),
    );
    let (result, _accepted) = tokio::join!(write, accept);
    let err = timeout(Duration::from_secs(2), async { result })
        .await
        .expect("write deadline must return")
        .unwrap_err();
    assert!(matches!(err, QuicBrokerError::WriteTimeout));
    pair.shutdown().await;
}

#[tokio::test]
async fn write_record_frame_with_deadline_preserves_non_timeout_write_errors() {
    let mut pair = connected_flow_controlled_pair().await;
    pair.server_connection.close(0_u32.into(), b"closed");
    let _ = timeout(Duration::from_secs(2), pair.server_endpoint.wait_idle()).await;
    let err = write_record_frame_with_deadline(
        &mut pair.send,
        &small_record(&[0x54; 32], 1, b"closed"),
        Duration::from_secs(2),
    )
    .await
    .unwrap_err();
    assert!(
        !matches!(
            err,
            QuicBrokerError::WriteTimeout | QuicBrokerError::ReadTimeout
        ),
        "closed-stream write must stay a transport error, got {err:?}"
    );
    pair.shutdown().await;
}

#[tokio::test]
async fn broker_resets_stalled_live_subscriber_and_releases_stream_permit() {
    let key = BrokerStreamKey::new(vec![0x61; 32], MessageId::new(vec![0x71; 32]));
    let broker = spawn_flow_controlled_broker(
        Arc::new(BrokerState::new(
            DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            DEFAULT_BROKER_BACKLOG_DEPTH,
            DEFAULT_BROKER_MAX_ROOMS,
            DEFAULT_BROKER_MAX_BACKLOG_BYTES,
            Duration::ZERO,
        )),
        injected_write_policy(1),
    )
    .await;
    let connection = broker.connect_stalled().await;
    let (_send, mut recv) =
        subscribe_unread(&connection, &key.stream_id, &key.start_event_id).await;
    wait_live_subscribers(&broker.state, &key, 1).await;
    broker
        .state
        .publish(&key, stall_record(&key.stream_id, 1))
        .await
        .unwrap();
    wait_live_subscribers(&broker.state, &key, 0).await;
    timeout(Duration::from_secs(2), async {
        loop {
            if read_record_frame(&mut recv, Some(Duration::from_millis(50)), MAX_FRAME_SIZE)
                .await
                .is_err()
            {
                return;
            }
        }
    })
    .await
    .expect("stalled subscriber stream must be reset");

    let (_send2, mut recv2) =
        subscribe_unread(&connection, &key.stream_id, &key.start_event_id).await;
    wait_live_subscribers(&broker.state, &key, 1).await;
    broker
        .state
        .publish(&key, small_record(&key.stream_id, 2, b"next"))
        .await
        .unwrap();
    let received = timeout(
        Duration::from_secs(2),
        read_record_frame(&mut recv2, Some(Duration::from_secs(2)), MAX_FRAME_SIZE),
    )
    .await
    .expect("eviction must release the stream permit")
    .unwrap()
    .expect("second subscriber record");
    assert_eq!(received.plaintext_frame, b"next");
    connection.close(0_u32.into(), b"done");
    broker.shutdown().await;
}

#[tokio::test]
async fn broker_resets_stalled_backlog_replay_and_unsubscribes() {
    let key = BrokerStreamKey::new(vec![0x62; 32], MessageId::new(vec![0x72; 32]));
    let state = Arc::new(BrokerState::new(
        DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        DEFAULT_BROKER_BACKLOG_DEPTH,
        DEFAULT_BROKER_MAX_ROOMS,
        DEFAULT_BROKER_MAX_BACKLOG_BYTES,
        MAX_BROKER_REPLAY_TTL,
    ));
    state
        .publish(&key, stall_record(&key.stream_id, 1))
        .await
        .unwrap();
    let broker = spawn_flow_controlled_broker(Arc::clone(&state), injected_write_policy(1)).await;
    let connection = broker.connect_stalled().await;
    let (_send, mut recv) =
        subscribe_unread(&connection, &key.stream_id, &key.start_event_id).await;
    wait_live_subscribers(&state, &key, 1).await;
    wait_live_subscribers(&state, &key, 0).await;
    timeout(Duration::from_secs(2), async {
        loop {
            if read_record_frame(&mut recv, Some(Duration::from_millis(50)), MAX_FRAME_SIZE)
                .await
                .is_err()
            {
                return;
            }
        }
    })
    .await
    .expect("stalled backlog write must reset the subscriber");
    connection.close(0_u32.into(), b"done");
    broker.shutdown().await;
}

#[tokio::test]
async fn broker_resets_stalled_finished_room_backlog_replay() {
    let key = BrokerStreamKey::new(vec![0x63; 32], MessageId::new(vec![0x73; 32]));
    let state = Arc::new(BrokerState::new(
        DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        DEFAULT_BROKER_BACKLOG_DEPTH,
        DEFAULT_BROKER_MAX_ROOMS,
        DEFAULT_BROKER_MAX_BACKLOG_BYTES,
        MAX_BROKER_REPLAY_TTL,
    ));
    state
        .publish(&key, stall_record(&key.stream_id, 1))
        .await
        .unwrap();
    // Mark finished without the 60s expiry task so the test runtime can exit.
    assert!(state.mark_room_finished_for_test(&key).await);
    let broker = spawn_flow_controlled_broker(Arc::clone(&state), injected_write_policy(1)).await;
    let connection = timeout(Duration::from_secs(2), broker.connect_stalled())
        .await
        .expect("finished-room connect");
    let (_send, mut recv) = timeout(
        Duration::from_secs(2),
        subscribe_unread(&connection, &key.stream_id, &key.start_event_id),
    )
    .await
    .expect("finished-room subscribe");
    // Do not read: consuming bytes would slide flow control and let the
    // backlog write finish instead of proving the deadline.
    sleep(TEST_WRITE_TIMEOUT * 3).await;
    timeout(Duration::from_secs(2), async {
        loop {
            if read_record_frame(&mut recv, Some(Duration::from_millis(50)), MAX_FRAME_SIZE)
                .await
                .is_err()
            {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("finished-room backlog stall must reset the subscriber");
    assert_eq!(state.live_subscriber_count_for_test(&key).await, 0);
    connection.close(0_u32.into(), b"done");
    broker.shutdown().await;
}

#[tokio::test]
async fn broker_unsubscribes_when_queue_eviction_races_a_pending_write() {
    let key = BrokerStreamKey::new(vec![0x64; 32], MessageId::new(vec![0x74; 32]));
    let state = Arc::new(BrokerState::new(
        1,
        DEFAULT_BROKER_BACKLOG_DEPTH,
        DEFAULT_BROKER_MAX_ROOMS,
        DEFAULT_BROKER_MAX_BACKLOG_BYTES,
        Duration::ZERO,
    ));
    let broker = spawn_flow_controlled_broker(Arc::clone(&state), injected_write_policy(1)).await;
    let connection = broker.connect_stalled().await;
    let (_send, mut recv) =
        subscribe_unread(&connection, &key.stream_id, &key.start_event_id).await;
    wait_live_subscribers(&state, &key, 1).await;
    state
        .publish(&key, stall_record(&key.stream_id, 1))
        .await
        .unwrap();
    timeout(Duration::from_millis(100), async {
        loop {
            if state.live_subscriber_count_for_test(&key).await == 1 {
                return;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .ok();
    state
        .publish(&key, small_record(&key.stream_id, 2, b"queued"))
        .await
        .unwrap();
    state
        .publish(&key, small_record(&key.stream_id, 3, b"evict"))
        .await
        .unwrap();
    assert_eq!(state.live_subscriber_count_for_test(&key).await, 0);
    sleep(TEST_WRITE_TIMEOUT * 3).await;
    timeout(Duration::from_secs(2), async {
        loop {
            if read_record_frame(&mut recv, Some(Duration::from_millis(50)), MAX_FRAME_SIZE)
                .await
                .is_err()
            {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("pending write must still time out after queue eviction");
    connection.close(0_u32.into(), b"done");
    broker.shutdown().await;
}

#[tokio::test]
async fn broker_keeps_healthy_subscriber_when_peer_times_out() {
    let key = BrokerStreamKey::new(vec![0x65; 32], MessageId::new(vec![0x75; 32]));
    let state = Arc::new(BrokerState::new(
        DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        DEFAULT_BROKER_BACKLOG_DEPTH,
        DEFAULT_BROKER_MAX_ROOMS,
        DEFAULT_BROKER_MAX_BACKLOG_BYTES,
        Duration::ZERO,
    ));
    let broker = spawn_flow_controlled_broker(Arc::clone(&state), injected_write_policy(2)).await;
    let stalled = broker.connect_stalled().await;
    let healthy = broker.connect_reading().await;
    let (_stalled_send, mut stalled_recv) =
        subscribe_unread(&stalled, &key.stream_id, &key.start_event_id).await;
    let (_healthy_send, mut healthy_recv) =
        subscribe_unread(&healthy, &key.stream_id, &key.start_event_id).await;
    wait_live_subscribers(&state, &key, 2).await;

    state
        .publish(&key, stall_record(&key.stream_id, 1))
        .await
        .unwrap();
    let first = timeout(
        Duration::from_secs(2),
        read_record_frame(
            &mut healthy_recv,
            Some(Duration::from_secs(2)),
            MAX_FRAME_SIZE,
        ),
    )
    .await
    .expect("healthy subscriber must receive the first record")
    .unwrap()
    .expect("first record");
    assert_eq!(first.seq, 1);

    wait_live_subscribers(&state, &key, 1).await;
    timeout(Duration::from_secs(2), async {
        loop {
            if read_record_frame(
                &mut stalled_recv,
                Some(Duration::from_millis(50)),
                MAX_FRAME_SIZE,
            )
            .await
            .is_err()
            {
                return;
            }
        }
    })
    .await
    .expect("stalled sibling must be reset");

    state
        .publish(&key, small_record(&key.stream_id, 2, b"still-here"))
        .await
        .unwrap();
    let second = timeout(
        Duration::from_secs(2),
        read_record_frame(
            &mut healthy_recv,
            Some(Duration::from_secs(2)),
            MAX_FRAME_SIZE,
        ),
    )
    .await
    .expect("healthy subscriber must survive sibling eviction")
    .unwrap()
    .expect("second record");
    assert_eq!(second.plaintext_frame, b"still-here");
    assert_eq!(state.live_subscriber_count_for_test(&key).await, 1);
    stalled.close(0_u32.into(), b"done");
    healthy.close(0_u32.into(), b"done");
    broker.shutdown().await;
}

#[tokio::test]
async fn broker_write_deadline_does_not_evict_quiet_subscriber() {
    let key = BrokerStreamKey::new(vec![0x66; 32], MessageId::new(vec![0x76; 32]));
    let state = Arc::new(BrokerState::new(
        DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        DEFAULT_BROKER_BACKLOG_DEPTH,
        DEFAULT_BROKER_MAX_ROOMS,
        DEFAULT_BROKER_MAX_BACKLOG_BYTES,
        Duration::ZERO,
    ));
    let broker = spawn_flow_controlled_broker(Arc::clone(&state), injected_write_policy(1)).await;
    let connection = broker.connect_reading().await;
    let (_send, mut recv) =
        subscribe_unread(&connection, &key.stream_id, &key.start_event_id).await;
    wait_live_subscribers(&state, &key, 1).await;
    state
        .publish(&key, small_record(&key.stream_id, 1, b"before"))
        .await
        .unwrap();
    let first = timeout(
        Duration::from_secs(2),
        read_record_frame(&mut recv, Some(Duration::from_secs(2)), MAX_FRAME_SIZE),
    )
    .await
    .unwrap()
    .unwrap()
    .expect("first record");
    assert_eq!(first.plaintext_frame, b"before");
    sleep(TEST_WRITE_TIMEOUT * 2).await;
    assert_eq!(state.live_subscriber_count_for_test(&key).await, 1);
    state
        .publish(&key, small_record(&key.stream_id, 2, b"after"))
        .await
        .unwrap();
    let second = timeout(
        Duration::from_secs(2),
        read_record_frame(&mut recv, Some(Duration::from_secs(2)), MAX_FRAME_SIZE),
    )
    .await
    .unwrap()
    .unwrap()
    .expect("quiet subscriber must still receive later records");
    assert_eq!(second.plaintext_frame, b"after");
    connection.close(0_u32.into(), b"done");
    broker.shutdown().await;
}

#[tokio::test]
async fn broker_allows_timely_writes_whose_total_exceeds_one_window() {
    let key = BrokerStreamKey::new(vec![0x67; 32], MessageId::new(vec![0x77; 32]));
    let state = Arc::new(BrokerState::new(
        DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
        DEFAULT_BROKER_BACKLOG_DEPTH,
        DEFAULT_BROKER_MAX_ROOMS,
        DEFAULT_BROKER_MAX_BACKLOG_BYTES,
        Duration::ZERO,
    ));
    let broker = spawn_flow_controlled_broker(Arc::clone(&state), injected_write_policy(1)).await;
    let connection = broker.connect_reading().await;
    let (_send, mut recv) =
        subscribe_unread(&connection, &key.stream_id, &key.start_event_id).await;
    wait_live_subscribers(&state, &key, 1).await;

    let mut received = Vec::new();
    for seq in 1..=4_u64 {
        state
            .publish(
                &key,
                small_record(&key.stream_id, seq, format!("c{seq}").as_bytes()),
            )
            .await
            .unwrap();
        let record = timeout(
            Duration::from_secs(2),
            read_record_frame(&mut recv, Some(Duration::from_secs(2)), MAX_FRAME_SIZE),
        )
        .await
        .unwrap()
        .unwrap()
        .expect("timely record");
        received.push(record.plaintext_frame.clone());
        sleep(TEST_WRITE_TIMEOUT / 2).await;
    }
    assert_eq!(
        received,
        vec![
            b"c1".to_vec(),
            b"c2".to_vec(),
            b"c3".to_vec(),
            b"c4".to_vec()
        ]
    );
    assert_eq!(state.live_subscriber_count_for_test(&key).await, 1);
    connection.close(0_u32.into(), b"done");
    broker.shutdown().await;
}
