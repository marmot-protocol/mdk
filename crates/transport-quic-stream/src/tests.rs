//! Cross-cutting unit and end-to-end tests exercising the protocol caps,
//! splitter, framing, crypto round-trip, limits, and the send/receive loop.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str;
use std::time::Duration;

use cgka_traits::MessageId;
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_RECORD_CHECKPOINT, AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA,
    AGENT_TEXT_STREAM_RECORD_STATUS, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
    AgentTextStreamKeyContextV1, AgentTextStreamRecordV1, AgentTextStreamTranscriptV1,
};
use cgka_traits::{EpochId, GroupId, MemberId, SecretBytes};

use crate::crypto::{AgentTextStreamCrypto, decrypt_record, encrypt_record};
use crate::error::QuicTextStreamError;
use crate::frame::{validate_frame_len, write_record};
use crate::limits::{
    AgentTextStreamReceiveAccumulator, AgentTextStreamReceiveLimitError,
    AgentTextStreamReceiveLimits,
};
use crate::protocol::{
    AGENT_TEXT_STREAM_FRAME_ALLOWANCE, DEFAULT_QUIC_STREAM_KEEP_ALIVE_INTERVAL,
    DEFAULT_QUIC_STREAM_MAX_IDLE_TIMEOUT, LOCAL_BIND, MAX_FRAME_SIZE, QUIC_STREAM_ALPN_V1,
    QUIC_STREAM_PROTOCOL_V1, SEND_CLOSE_WAIT, frame_len_cap,
};
use crate::receive::{QuicTextStreamReceiver, ServerTrust, stream_record_text};
use crate::send::{SendTextStream, send_text_stream, split_text_deltas};
use crate::tls::{client_endpoint, configure_server};
use tokio::time::{sleep, timeout};

#[test]
fn direct_path_alpn_is_the_pinned_wire_value() {
    // Wire-visible interop id; both peers must offer exactly this (quic.md).
    assert_eq!(QUIC_STREAM_PROTOCOL_V1, "marmot.quic_stream.v1");
    assert_eq!(QUIC_STREAM_ALPN_V1, b"marmot.quic_stream.v1");
}

#[test]
fn direct_server_config_sets_quic_liveness_backstop() {
    let (server_config, _cert_der) = configure_server().unwrap();

    assert_eq!(
        DEFAULT_QUIC_STREAM_MAX_IDLE_TIMEOUT,
        Duration::from_secs(30)
    );
    assert_eq!(
        DEFAULT_QUIC_STREAM_KEEP_ALIVE_INTERVAL,
        Duration::from_secs(10)
    );
    assert!(DEFAULT_QUIC_STREAM_KEEP_ALIVE_INTERVAL < DEFAULT_QUIC_STREAM_MAX_IDLE_TIMEOUT);

    let default_transport = format!("{:?}", quinn::TransportConfig::default());
    assert!(
        default_transport.contains("max_idle_timeout: Some(30000)"),
        "{default_transport}"
    );
    assert!(
        default_transport.contains("keep_alive_interval: None"),
        "{default_transport}"
    );

    // Quinn exposes setters for these transport knobs but no public getters, so
    // this config-level regression test uses its Debug output as the least
    // invasive check that configure_server attached the intended direct-path
    // transport config. If Quinn reformats Debug, re-check the wiring rather
    // than treating the string shape as protocol behavior.
    let transport = format!("{:?}", server_config.transport);
    assert!(
        transport.contains("max_idle_timeout: Some(30000)"),
        "{transport}"
    );
    assert!(
        transport.contains("keep_alive_interval: Some(10s)"),
        "{transport}"
    );
}

#[test]
fn text_delta_splitter_preserves_utf8_boundaries() {
    let chunks = split_text_deltas("héllo", 2);
    assert_eq!(
        chunks
            .iter()
            .map(|chunk| str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>(),
        vec!["h", "é", "ll", "o"]
    );
}

#[test]
fn text_delta_splitter_keeps_oversized_multibyte_characters_whole() {
    let chunks = split_text_deltas("éa", 1);
    assert_eq!(
        chunks
            .iter()
            .map(|chunk| str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>(),
        vec!["é", "a"]
    );
}

#[test]
fn oversized_frames_are_rejected_before_allocation() {
    assert!(matches!(
        validate_frame_len(MAX_FRAME_SIZE + 1, MAX_FRAME_SIZE),
        Err(QuicTextStreamError::FrameTooLarge(_))
    ));
}

#[test]
fn policy_frame_cap_is_policy_plus_fixed_allowance_with_app_ceiling() {
    assert_eq!(AGENT_TEXT_STREAM_FRAME_ALLOWANCE, 1024);
    assert_eq!(frame_len_cap(None), MAX_FRAME_SIZE);
    assert_eq!(
        frame_len_cap(Some(4096)),
        4096 + AGENT_TEXT_STREAM_FRAME_ALLOWANCE
    );
    // A policy above the app-profile ceiling is clamped to the ceiling, and
    // a zero policy falls back to the ceiling.
    assert_eq!(frame_len_cap(Some(u32::MAX)), MAX_FRAME_SIZE);
    assert_eq!(frame_len_cap(Some(0)), MAX_FRAME_SIZE);
    assert!(matches!(
        validate_frame_len(
            4096 + AGENT_TEXT_STREAM_FRAME_ALLOWANCE + 1,
            frame_len_cap(Some(4096))
        ),
        Err(QuicTextStreamError::FrameTooLarge(_))
    ));
    assert!(
        validate_frame_len(
            4096 + AGENT_TEXT_STREAM_FRAME_ALLOWANCE,
            frame_len_cap(Some(4096))
        )
        .is_ok()
    );
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
fn receive_limits_bound_record_count_and_plaintext_bytes() {
    let record = AgentTextStreamRecordV1::text_delta(vec![0x11; 32], 1, b"hello".to_vec());
    let mut record_limited = AgentTextStreamReceiveAccumulator::new(AgentTextStreamReceiveLimits {
        max_records: 1,
        max_plaintext_bytes: 1024,
        ..AgentTextStreamReceiveLimits::default()
    });
    record_limited.observe(&record).unwrap();
    assert_eq!(record_limited.wire_records(), 0);
    record_limited.observe_wire_record().unwrap();
    assert_eq!(record_limited.wire_records(), 1);
    assert!(matches!(
        record_limited.observe_wire_record(),
        Err(AgentTextStreamReceiveLimitError::RecordLimitExceeded {
            attempted: 2,
            limit: 1
        })
    ));
    assert!(matches!(
        record_limited.observe(&record),
        Err(AgentTextStreamReceiveLimitError::RecordLimitExceeded {
            attempted: 2,
            limit: 1
        })
    ));

    let mut byte_limited = AgentTextStreamReceiveAccumulator::new(AgentTextStreamReceiveLimits {
        max_records: 10,
        max_plaintext_bytes: 4,
        ..AgentTextStreamReceiveLimits::default()
    });
    assert!(matches!(
        byte_limited.observe(&record),
        Err(
            AgentTextStreamReceiveLimitError::PlaintextByteLimitExceeded {
                attempted: 5,
                limit: 4
            }
        )
    ));
}

#[test]
fn crypto_seals_record_body_and_round_trips() {
    let stream_id = vec![0x42; 32];
    let crypto = AgentTextStreamCrypto::new(
        SecretBytes::new(vec![0x07; 32]),
        AgentTextStreamKeyContextV1::new(
            GroupId::new(vec![0x01; 32]),
            stream_id.clone(),
            EpochId(3),
            MemberId::new(vec![0x02; 32]),
            MessageId::new(vec![0x24; 32]),
        ),
    );
    let record = AgentTextStreamRecordV1::text_delta(stream_id, 1, b"hello".to_vec());
    let sealed = encrypt_record(&crypto, &record).unwrap();
    assert_ne!(sealed.plaintext_frame, b"hello");
    assert!(
        !sealed
            .encode()
            .unwrap()
            .windows(b"hello".len())
            .any(|window| window == b"hello")
    );

    let opened = decrypt_record(&crypto, &sealed).unwrap();
    assert_eq!(opened, record);
}

#[test]
fn crypto_debug_redacts_stream_secret() {
    let crypto = AgentTextStreamCrypto::new(
        SecretBytes::new(b"debug-visible stream secret!!!!!".to_vec()),
        AgentTextStreamKeyContextV1::new(
            GroupId::new(vec![0x01; 32]),
            vec![0x42; 32],
            EpochId(3),
            MemberId::new(vec![0x02; 32]),
            MessageId::new(vec![0x24; 32]),
        ),
    );

    let rendered = format!("{crypto:?}");

    assert!(!rendered.contains("debug-visible"));
    assert!(rendered.contains("redacted"));
}

#[test]
fn crypto_rejects_wrong_stream_secret_length() {
    let crypto = AgentTextStreamCrypto::new(
        SecretBytes::new(vec![0x07; 31]),
        AgentTextStreamKeyContextV1::new(
            GroupId::new(vec![0x01; 32]),
            vec![0x42; 32],
            EpochId(3),
            MemberId::new(vec![0x02; 32]),
            MessageId::new(vec![0x24; 32]),
        ),
    );
    let record = AgentTextStreamRecordV1::text_delta(vec![0x42; 32], 1, b"hello".to_vec());

    assert!(matches!(
        encrypt_record(&crypto, &record),
        Err(QuicTextStreamError::Crypto(_))
    ));
}

#[tokio::test]
async fn insecure_local_rejects_remote_server_addr() {
    let err = send_text_stream(SendTextStream {
        server_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 4450),
        server_name: "example.com".to_owned(),
        trust: ServerTrust::InsecureLocal,
        stream_id: vec![0x42; 32],
        start_event_id: MessageId::new(vec![0x24; 32]),
        text: "hello".to_owned(),
        max_chunk_bytes: 5,
        chunk_delay: Duration::ZERO,
        crypto: None,
        max_plaintext_frame_len: None,
    })
    .await
    .unwrap_err();

    assert!(matches!(
        err,
        QuicTextStreamError::InsecureLocalRequiresLoopback(_)
    ));
}

#[tokio::test]
async fn quic_receiver_renders_text_deltas_in_order() {
    let receiver = QuicTextStreamReceiver::bind(LOCAL_BIND).unwrap();
    let server_addr = receiver.local_addr().unwrap();
    let server_cert = receiver.server_cert_der().to_vec();
    let stream_id = vec![0x42; 32];
    let start_event_id = MessageId::new(vec![0x24; 32]);
    let receive = tokio::spawn(receiver.receive_once(start_event_id.clone(), None));

    let sent = send_text_stream(SendTextStream {
        server_addr,
        server_name: "localhost".to_owned(),
        trust: ServerTrust::CertificateDer(server_cert),
        stream_id: stream_id.clone(),
        start_event_id,
        text: "hello over quic".to_owned(),
        max_chunk_bytes: 5,
        chunk_delay: Duration::ZERO,
        crypto: None,
        max_plaintext_frame_len: None,
    })
    .await
    .unwrap();

    let received = receive.await.unwrap().unwrap();
    assert_eq!(received.stream_id, stream_id);
    assert_eq!(received.text, "hello over quic");
    assert_eq!(
        received
            .chunks
            .iter()
            .map(|chunk| chunk.text.as_str())
            .collect::<Vec<_>>(),
        vec!["hello", " over", " quic"]
    );
    assert_eq!(received.chunk_count, 3);
    assert_eq!(sent.stream_id, stream_id);
    assert_eq!(sent.chunk_count, 3);
    assert_eq!(sent.transcript_hash, received.transcript_hash);
}

#[tokio::test]
async fn send_clamps_chunk_size_to_group_policy_cap() {
    let receiver = QuicTextStreamReceiver::bind(LOCAL_BIND).unwrap();
    let server_addr = receiver.local_addr().unwrap();
    let server_cert = receiver.server_cert_der().to_vec();
    let stream_id = vec![0x42; 32];
    let start_event_id = MessageId::new(vec![0x24; 32]);
    let receive = tokio::spawn(receiver.receive_once(start_event_id.clone(), None));

    let sent = send_text_stream(SendTextStream {
        server_addr,
        server_name: "localhost".to_owned(),
        trust: ServerTrust::CertificateDer(server_cert),
        stream_id: stream_id.clone(),
        start_event_id,
        text: "hello over quic".to_owned(),
        max_chunk_bytes: 1024,
        chunk_delay: Duration::ZERO,
        crypto: None,
        max_plaintext_frame_len: Some(5),
    })
    .await
    .unwrap();

    let received = receive.await.unwrap().unwrap();
    assert_eq!(received.text, "hello over quic");
    assert_eq!(
        received
            .chunks
            .iter()
            .map(|chunk| chunk.text.as_str())
            .collect::<Vec<_>>(),
        vec!["hello", " over", " quic"]
    );
    assert_eq!(sent.chunk_count, 3);
}

async fn raw_record_sender(
    server_addr: SocketAddr,
    server_cert: Vec<u8>,
    records: Vec<AgentTextStreamRecordV1>,
) {
    raw_record_sender_with_inter_record_delay(server_addr, server_cert, records, Duration::ZERO)
        .await;
}

async fn raw_record_sender_with_inter_record_delay(
    server_addr: SocketAddr,
    server_cert: Vec<u8>,
    records: Vec<AgentTextStreamRecordV1>,
    inter_record_delay: Duration,
) {
    let endpoint = client_endpoint(ServerTrust::CertificateDer(server_cert), server_addr).unwrap();
    let connection = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let mut send = connection.open_uni().await.unwrap();
    for (index, record) in records.iter().enumerate() {
        write_record(&mut send, record).await.unwrap();
        if index + 1 < records.len() && !inter_record_delay.is_zero() {
            sleep(inter_record_delay).await;
        }
    }
    send.finish().unwrap();
    if timeout(SEND_CLOSE_WAIT, connection.closed()).await.is_err() {
        connection.close(0_u32.into(), b"done");
    }
    endpoint.wait_idle().await;
}

async fn stalled_uni_sender(server_addr: SocketAddr, server_cert: Vec<u8>, hold: Duration) {
    let endpoint = client_endpoint(ServerTrust::CertificateDer(server_cert), server_addr).unwrap();
    let connection = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let _send = connection.open_uni().await.unwrap();
    sleep(hold).await;
    connection.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;
}

#[tokio::test]
async fn receiver_silently_discards_replayed_records_at_or_below_high_water() {
    let receiver = QuicTextStreamReceiver::bind(LOCAL_BIND).unwrap();
    let server_addr = receiver.local_addr().unwrap();
    let server_cert = receiver.server_cert_der().to_vec();
    let stream_id = vec![0x42; 32];
    let start_event_id = MessageId::new(vec![0x24; 32]);
    let receive = tokio::spawn(receiver.receive_once(start_event_id.clone(), None));

    let first = AgentTextStreamRecordV1::text_delta(stream_id.clone(), 1, b"hel".to_vec());
    let second = AgentTextStreamRecordV1::text_delta(stream_id.clone(), 2, b"lo".to_vec());
    let third = AgentTextStreamRecordV1::text_delta(stream_id.clone(), 3, b" world".to_vec());
    // A broker replaying its retained backlog re-sends records the receiver
    // already accepted; those must be discarded silently, never
    // stream-fatal, and the next accepted record is high-water + 1.
    raw_record_sender(
        server_addr,
        server_cert,
        vec![
            first.clone(),
            second.clone(),
            first.clone(),
            second.clone(),
            third.clone(),
        ],
    )
    .await;

    let received = receive.await.unwrap().unwrap();
    assert_eq!(received.text, "hello world");
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
    transcript.append(1, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"hel");
    transcript.append(2, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"lo");
    transcript.append(3, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b" world");
    assert_eq!(received.transcript_hash, transcript.hash());
}

#[tokio::test]
async fn receiver_counts_replayed_records_toward_receive_record_limit() {
    let receiver = QuicTextStreamReceiver::bind(LOCAL_BIND).unwrap();
    let server_addr = receiver.local_addr().unwrap();
    let server_cert = receiver.server_cert_der().to_vec();
    let stream_id = vec![0x42; 32];
    let start_event_id = MessageId::new(vec![0x24; 32]);
    let limits = AgentTextStreamReceiveLimits {
        max_records: 2,
        max_plaintext_bytes: 1024,
        ..AgentTextStreamReceiveLimits::default()
    };
    let receive = tokio::spawn(receiver.receive_once_with_limits(start_event_id, None, limits));

    let duplicate = AgentTextStreamRecordV1::text_delta(stream_id, 0, b"dupe".to_vec());
    raw_record_sender(
        server_addr,
        server_cert,
        vec![duplicate.clone(), duplicate.clone(), duplicate],
    )
    .await;

    let err = receive.await.unwrap().unwrap_err();
    assert!(matches!(
        err,
        QuicTextStreamError::ReceiveLimit(AgentTextStreamReceiveLimitError::RecordLimitExceeded {
            attempted: 3,
            limit: 2
        })
    ));
}

#[tokio::test]
async fn receiver_times_out_when_peer_stalls_before_first_frame() {
    let receiver = QuicTextStreamReceiver::bind(LOCAL_BIND).unwrap();
    let server_addr = receiver.local_addr().unwrap();
    let server_cert = receiver.server_cert_der().to_vec();
    let start_event_id = MessageId::new(vec![0x24; 32]);
    let limits = AgentTextStreamReceiveLimits {
        read_timeout: Duration::from_millis(50),
        ..AgentTextStreamReceiveLimits::default()
    };
    let receive = tokio::spawn(receiver.receive_once_with_limits(start_event_id, None, limits));

    stalled_uni_sender(server_addr, server_cert, Duration::from_millis(200)).await;

    let err = receive.await.unwrap().unwrap_err();
    assert!(matches!(err, QuicTextStreamError::ReadTimeout));
}

#[tokio::test]
async fn receiver_allows_quiet_gap_after_first_record_longer_than_setup_deadline() {
    let receiver = QuicTextStreamReceiver::bind(LOCAL_BIND).unwrap();
    let server_addr = receiver.local_addr().unwrap();
    let server_cert = receiver.server_cert_der().to_vec();
    let stream_id = vec![0x42; 32];
    let start_event_id = MessageId::new(vec![0x24; 32]);
    let limits = AgentTextStreamReceiveLimits {
        read_timeout: Duration::from_millis(50),
        ..AgentTextStreamReceiveLimits::default()
    };
    let receive = tokio::spawn(receiver.receive_once_with_limits(start_event_id, None, limits));

    raw_record_sender_with_inter_record_delay(
        server_addr,
        server_cert,
        vec![
            AgentTextStreamRecordV1::text_delta(stream_id.clone(), 1, b"hel".to_vec()),
            AgentTextStreamRecordV1::text_delta(stream_id, 2, b"lo".to_vec()),
        ],
        Duration::from_millis(150),
    )
    .await;

    let received = receive.await.unwrap().unwrap();
    assert_eq!(received.text, "hello");
    assert_eq!(received.chunk_count, 2);
}

#[tokio::test]
async fn receiver_keeps_setup_deadline_after_discarded_initial_replay_record() {
    let receiver = QuicTextStreamReceiver::bind(LOCAL_BIND).unwrap();
    let server_addr = receiver.local_addr().unwrap();
    let server_cert = receiver.server_cert_der().to_vec();
    let stream_id = vec![0x42; 32];
    let start_event_id = MessageId::new(vec![0x24; 32]);
    let limits = AgentTextStreamReceiveLimits {
        read_timeout: Duration::from_millis(50),
        ..AgentTextStreamReceiveLimits::default()
    };
    let receive = tokio::spawn(receiver.receive_once_with_limits(start_event_id, None, limits));

    let endpoint = client_endpoint(ServerTrust::CertificateDer(server_cert), server_addr).unwrap();
    let connection = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let mut send = connection.open_uni().await.unwrap();
    let discarded = AgentTextStreamRecordV1::text_delta(stream_id.clone(), 0, b"dupe".to_vec());
    write_record(&mut send, &discarded).await.unwrap();
    sleep(Duration::from_millis(150)).await;
    let accepted = AgentTextStreamRecordV1::text_delta(stream_id, 1, b"hel".to_vec());
    let _ = write_record(&mut send, &accepted).await;
    let _ = send.finish();
    connection.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;

    let err = receive.await.unwrap().unwrap_err();
    assert!(matches!(err, QuicTextStreamError::ReadTimeout));
}

#[tokio::test]
async fn receiver_reports_gap_when_record_is_ahead_of_high_water() {
    let receiver = QuicTextStreamReceiver::bind(LOCAL_BIND).unwrap();
    let server_addr = receiver.local_addr().unwrap();
    let server_cert = receiver.server_cert_der().to_vec();
    let stream_id = vec![0x42; 32];
    let start_event_id = MessageId::new(vec![0x24; 32]);
    let receive = tokio::spawn(receiver.receive_once(start_event_id, None));

    raw_record_sender(
        server_addr,
        server_cert,
        vec![
            AgentTextStreamRecordV1::text_delta(stream_id.clone(), 1, b"hel".to_vec()),
            AgentTextStreamRecordV1::text_delta(stream_id, 3, b"lo".to_vec()),
        ],
    )
    .await;

    let err = receive.await.unwrap().unwrap_err();
    assert!(matches!(
        err,
        QuicTextStreamError::UnexpectedSequence {
            expected: 2,
            actual: 3
        }
    ));
}
