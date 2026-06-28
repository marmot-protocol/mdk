//! White-box unit tests: exercise the broker engine, framing, TLS helpers, and
//! client/server internals that are only reachable inside the crate.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use cgka_traits::MessageId;
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_RECORD_ABORT, AGENT_TEXT_STREAM_RECORD_CHECKPOINT,
    AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA, AGENT_TEXT_STREAM_RECORD_STATUS,
    AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, AgentTextStreamRecordV1, AgentTextStreamTranscriptV1,
};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint};
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};
use transport_quic_stream::{AgentTextStreamReceiveLimitError, AgentTextStreamReceiveLimits};

use crate::client::{
    BrokerServerTrust, BrokerTextPublisher, OpenBrokerTextPublisher, PublishTextToBroker,
    SubscribeTextFromBroker, publish_text_to_broker, stream_record_text,
    subscribe_text_from_broker, subscribe_text_from_broker_with_limits,
};
use crate::config::{QuicBrokerConfig, QuicBrokerTlsConfig};
use crate::control::BrokerStreamKey;
use crate::control::QuicBrokerControlEnvelopeV1;
use crate::error::QuicBrokerError;
use crate::frame::{
    broker_read_deadline, read_record_frame, validate_frame_len, write_control_frame,
    write_record_frame,
};
use crate::protocol::{
    DEFAULT_BROKER_BACKLOG_DEPTH, DEFAULT_BROKER_MAX_BACKLOG_BYTES, DEFAULT_BROKER_MAX_ROOMS,
    DEFAULT_BROKER_REPLAY_TTL, DEFAULT_SUBSCRIBER_QUEUE_DEPTH, FINISHED_ROOM_TTL,
    LOCAL_SERVER_BIND, MAX_BROKER_REPLAY_TTL, MAX_FRAME_SIZE, QUIC_BROKER_ALPN_V1, SEND_STOP_WAIT,
    UNFINISHED_ROOM_TTL,
};
use crate::server::{QuicBrokerServer, certificate_sha256_fingerprint_hex};
use crate::state::BrokerState;
use crate::tls::{SkipServerVerification, client_bind_addr_for_broker, client_endpoint};

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
async fn broker_does_not_apply_per_record_deadline_to_authenticated_publisher() {
    // Regression for the live-preview latch: an agent that goes quiet between
    // records (e.g. a long tool call with no progress events) must not have
    // its publish stream errored by a per-record read deadline. Before the
    // fix, `read_timeout` was enforced on every record-frame read after the
    // handshake, so an idle gap longer than the deadline killed the stream;
    // the composer then latched `live_error` and the preview was dead for the
    // rest of the response. Here we use a tiny read_timeout and idle well past
    // it between two records, and assert both records still arrive. The QUIC
    // idle timeout (kept long here) is what reaps a genuinely dead publisher.
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
            stream_record_text(&record(record_type, plaintext)).unwrap(),
            plaintext
        );
    }

    // Abort and FinalNotice are advisory: the consumer reacts to the record
    // type, so they decode to "" even when the sender attached bytes.
    for record_type in [
        AGENT_TEXT_STREAM_RECORD_ABORT,
        AGENT_TEXT_STREAM_RECORD_FINAL_NOTICE,
    ] {
        assert_eq!(
            stream_record_text(&record(record_type, "ignored")).unwrap(),
            ""
        );
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
