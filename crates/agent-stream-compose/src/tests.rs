use std::future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use cgka_traits::MessageId;
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_RECORD_ABORT, AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA,
    AGENT_TEXT_STREAM_RECORD_STATUS, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
    AgentTextStreamTranscriptV1,
};
use tokio::sync::{mpsc, oneshot};
use transport_quic_broker::{
    BrokerServerTrust, OpenBrokerTextPublisher, QuicBrokerConfig, QuicBrokerServer,
    SubscribeTextFromBroker, subscribe_text_from_broker,
};

use super::*;

fn test_stream_compose_open(
    stream_id: Vec<u8>,
    start_event_id: MessageId,
) -> OpenBrokerTextPublisher {
    OpenBrokerTextPublisher {
        broker_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::InsecureLocal,
        stream_id,
        start_event_id,
        crypto: None,
        max_plaintext_frame_len: None,
    }
}

fn test_stream_compose_report(stream_id: &[u8]) -> StreamComposeReport {
    StreamComposeReport {
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

fn expected_stream_transcript_hash_for_records(
    stream_id: &[u8],
    start_event_id: &MessageId,
    records: &[(u8, &str)],
    chunk_bytes: usize,
) -> String {
    let mut transcript =
        AgentTextStreamTranscriptV1::new(stream_id.to_vec(), start_event_id.clone());
    let mut seq = 1_u64;
    for (record_type, text) in records {
        for chunk in transport_quic_stream::split_text_deltas(text, chunk_bytes) {
            transcript.append(seq, *record_type, &chunk);
            seq += 1;
        }
    }
    hex::encode(transcript.hash())
}

#[tokio::test]
async fn compose_session_finalizes_local_transcript_when_broker_connect_is_pending() {
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
        Some(
            expected_stream_transcript_hash_for_appends(
                &stream_id,
                &start_event_id,
                &["hello "],
                8,
            )
            .as_str()
        )
    );

    session.await.unwrap();
}

#[tokio::test]
async fn compose_session_clamps_local_transcript_to_group_policy_cap() {
    let stream_id = vec![0xab; 32];
    let start_event_id = MessageId::new(vec![0xbc; 32]);
    let mut open = test_stream_compose_open(stream_id.clone(), start_event_id.clone());
    open.max_plaintext_frame_len = Some(5);
    let report = test_stream_compose_report(&stream_id);
    let (tx, rx) = mpsc::channel(4);
    let (_cancel_tx, cancel_rx) = mpsc::channel(1);
    let session = tokio::spawn(run_stream_compose_session(
        open, 1024, rx, cancel_rx, report,
    ));

    let (append_tx, append_rx) = oneshot::channel();
    tx.send(StreamComposeCommand::Append {
        text: "hello over quic".to_owned(),
        respond: append_tx,
    })
    .await
    .unwrap();
    let appended = tokio::time::timeout(Duration::from_millis(250), append_rx)
        .await
        .expect("append should not wait for broker connect")
        .unwrap()
        .unwrap();
    assert_eq!(appended.chunk_count, 3);
    assert_eq!(
        appended.transcript_hash.as_deref(),
        Some(
            expected_stream_transcript_hash_for_appends(
                &stream_id,
                &start_event_id,
                &["hello over quic"],
                5,
            )
            .as_str()
        )
    );

    let (finish_tx, finish_rx) = oneshot::channel();
    tx.send(StreamComposeCommand::Finish { respond: finish_tx })
        .await
        .unwrap();
    let finished = tokio::time::timeout(Duration::from_millis(250), finish_rx)
        .await
        .expect("finish should use policy-clamped local transcript")
        .unwrap()
        .unwrap();
    assert_eq!(finished.chunk_count, 3);

    session.await.unwrap();
}

#[tokio::test]
async fn compose_session_final_report_contains_full_transcript_text() {
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

#[tokio::test]
async fn compose_session_status_updates_transcript_without_changing_text() {
    let stream_id = vec![0xee; 32];
    let start_event_id = MessageId::new(vec![0xff; 32]);
    let open = test_stream_compose_open(stream_id.clone(), start_event_id.clone());
    let report = test_stream_compose_report(&stream_id);
    let (tx, rx) = mpsc::channel(4);
    let (_cancel_tx, cancel_rx) = mpsc::channel(1);
    let session = tokio::spawn(run_stream_compose_session(open, 16, rx, cancel_rx, report));

    let (append_respond, append_response) = oneshot::channel();
    tx.send(StreamComposeCommand::Append {
        text: "hello".to_owned(),
        respond: append_respond,
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_millis(250), append_response)
        .await
        .expect("append should complete")
        .unwrap()
        .unwrap();

    let (status_respond, status_response) = oneshot::channel();
    tx.send(StreamComposeCommand::Status {
        status: "thinking".to_owned(),
        respond: status_respond,
    })
    .await
    .unwrap();
    let status_report = tokio::time::timeout(Duration::from_millis(250), status_response)
        .await
        .expect("status should complete")
        .unwrap()
        .unwrap();

    let expected_hash = expected_stream_transcript_hash_for_records(
        &stream_id,
        &start_event_id,
        &[
            (AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, "hello"),
            (AGENT_TEXT_STREAM_RECORD_STATUS, "thinking"),
        ],
        16,
    );
    assert_eq!(status_report.status, "thinking");
    assert_eq!(status_report.text, "hello");
    assert_eq!(status_report.chunk_count, 2);
    assert_eq!(
        status_report.transcript_hash.as_deref(),
        Some(expected_hash.as_str())
    );

    let (finish_respond, finish_response) = oneshot::channel();
    tx.send(StreamComposeCommand::Finish {
        respond: finish_respond,
    })
    .await
    .unwrap();
    let finished = tokio::time::timeout(Duration::from_millis(250), finish_response)
        .await
        .expect("finish should complete")
        .unwrap()
        .unwrap();

    assert_eq!(finished.status, "finished");
    assert_eq!(finished.text, "hello");
    assert_eq!(finished.chunk_count, 2);
    assert_eq!(
        finished.transcript_hash.as_deref(),
        Some(expected_hash.as_str())
    );

    session.await.unwrap();
}

#[tokio::test]
async fn compose_session_progress_updates_transcript_without_changing_text() {
    let stream_id = vec![0x9a; 32];
    let start_event_id = MessageId::new(vec![0x9b; 32]);
    let open = test_stream_compose_open(stream_id.clone(), start_event_id.clone());
    let report = test_stream_compose_report(&stream_id);
    let (tx, rx) = mpsc::channel(4);
    let (_cancel_tx, cancel_rx) = mpsc::channel(1);
    let session = tokio::spawn(run_stream_compose_session(open, 16, rx, cancel_rx, report));

    let (append_respond, append_response) = oneshot::channel();
    tx.send(StreamComposeCommand::Append {
        text: "answer".to_owned(),
        respond: append_respond,
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_millis(250), append_response)
        .await
        .expect("append should complete")
        .unwrap()
        .unwrap();

    let (progress_respond, progress_response) = oneshot::channel();
    tx.send(StreamComposeCommand::Progress {
        text: "search: glp-1".to_owned(),
        respond: progress_respond,
    })
    .await
    .unwrap();
    let progress_report = tokio::time::timeout(Duration::from_millis(250), progress_response)
        .await
        .expect("progress should complete")
        .unwrap()
        .unwrap();

    let expected_hash = expected_stream_transcript_hash_for_records(
        &stream_id,
        &start_event_id,
        &[
            (AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, "answer"),
            (AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA, "search: glp-1"),
        ],
        16,
    );
    assert_eq!(progress_report.text, "answer");
    assert_eq!(progress_report.chunk_count, 2);
    assert_eq!(
        progress_report.transcript_hash.as_deref(),
        Some(expected_hash.as_str())
    );

    let (finish_respond, finish_response) = oneshot::channel();
    tx.send(StreamComposeCommand::Finish {
        respond: finish_respond,
    })
    .await
    .unwrap();
    let finished = tokio::time::timeout(Duration::from_millis(250), finish_response)
        .await
        .expect("finish should complete")
        .unwrap()
        .unwrap();

    assert_eq!(finished.status, "finished");
    assert_eq!(finished.text, "answer");
    assert_eq!(finished.chunk_count, 2);
    assert_eq!(
        finished.transcript_hash.as_deref(),
        Some(expected_hash.as_str())
    );

    session.await.unwrap();
}

struct StalledPublisher {
    append_started: Option<oneshot::Sender<()>>,
}

impl super::LiveBrokerPublisher for StalledPublisher {
    async fn append_record_text(
        &mut self,
        _record_type: u8,
        _text: &str,
        _chunk_bytes: usize,
    ) -> Result<(), String> {
        if let Some(append_started) = self.append_started.take() {
            let _ = append_started.send(());
        }
        future::pending().await
    }

    async fn append_abort(&mut self) -> Result<(), String> {
        Ok(())
    }

    async fn finish(self) -> Result<(), String> {
        Ok(())
    }
}

struct DropNotifyingPublisher {
    dropped: Option<oneshot::Sender<()>>,
}

impl Drop for DropNotifyingPublisher {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}

impl super::LiveBrokerPublisher for DropNotifyingPublisher {
    async fn append_record_text(
        &mut self,
        _record_type: u8,
        _text: &str,
        _chunk_bytes: usize,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn append_abort(&mut self) -> Result<(), String> {
        Ok(())
    }

    async fn finish(self) -> Result<(), String> {
        Ok(())
    }
}

#[tokio::test]
async fn append_live_record_times_out_stalled_publisher_and_drops_it() {
    let mut publisher = Some(StalledPublisher {
        append_started: None,
    });
    let mut pending_live_records = super::PendingLiveRecords::default();
    let mut live_error = None;

    super::append_live_record(
        &mut super::ComposeLiveSink {
            publisher: &mut publisher,
            pending_live_records: &mut pending_live_records,
            live_error: &mut live_error,
            live_write_timeout: Duration::from_millis(10),
        },
        AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
        "hello".to_owned(),
        8,
    )
    .await;

    assert!(publisher.is_none(), "stalled publisher should be dropped");
    assert!(pending_live_records.records.is_empty());
    assert!(
        live_error
            .as_deref()
            .is_some_and(|err| err.contains("timed out")),
        "append should record live timeout: {live_error:?}"
    );
}

#[tokio::test]
async fn append_live_record_disables_live_preview_when_pending_record_cap_is_exceeded() {
    let mut publisher: Option<StalledPublisher> = None;
    let mut pending_live_records = super::PendingLiveRecords::default();
    let mut live_error = None;

    for idx in 0..super::MAX_PENDING_LIVE_RECORDS {
        super::append_live_record(
            &mut super::ComposeLiveSink {
                publisher: &mut publisher,
                pending_live_records: &mut pending_live_records,
                live_error: &mut live_error,
                live_write_timeout: Duration::from_millis(10),
            },
            AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
            format!("record-{idx}"),
            8,
        )
        .await;
        assert!(live_error.is_none());
    }
    assert_eq!(
        pending_live_records.records.len(),
        super::MAX_PENDING_LIVE_RECORDS
    );

    super::append_live_record(
        &mut super::ComposeLiveSink {
            publisher: &mut publisher,
            pending_live_records: &mut pending_live_records,
            live_error: &mut live_error,
            live_write_timeout: Duration::from_millis(10),
        },
        AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
        "overflow".to_owned(),
        8,
    )
    .await;

    assert!(pending_live_records.records.is_empty());
    assert!(
        live_error
            .as_deref()
            .is_some_and(|err| err.contains(&format!(
                "pending live stream buffer exceeded {} records",
                super::MAX_PENDING_LIVE_RECORDS
            ))),
        "pending record overflow should disable live preview: {live_error:?}"
    );
}

#[tokio::test]
async fn append_live_record_disables_live_preview_when_pending_byte_cap_is_exceeded() {
    let mut publisher: Option<StalledPublisher> = None;
    let mut pending_live_records = super::PendingLiveRecords::default();
    let mut live_error = None;

    super::append_live_record(
        &mut super::ComposeLiveSink {
            publisher: &mut publisher,
            pending_live_records: &mut pending_live_records,
            live_error: &mut live_error,
            live_write_timeout: Duration::from_millis(10),
        },
        AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
        "x".repeat(super::MAX_PENDING_LIVE_RECORD_BYTES + 1),
        8,
    )
    .await;

    assert!(pending_live_records.records.is_empty());
    assert!(
        live_error
            .as_deref()
            .is_some_and(|err| err.contains(&format!(
                "pending live stream buffer exceeded {} bytes",
                super::MAX_PENDING_LIVE_RECORD_BYTES
            ))),
        "pending byte overflow should disable live preview: {live_error:?}"
    );
}

#[tokio::test]
async fn compose_session_drops_late_connect_after_pending_overflow_disables_live_preview() {
    let stream_id = vec![0x3a; 32];
    let start_event_id = MessageId::new(vec![0x3b; 32]);
    let open = test_stream_compose_open(stream_id.clone(), start_event_id.clone());
    let report = test_stream_compose_report(&stream_id);
    let (tx, rx) = mpsc::channel(4);
    let (_cancel_tx, cancel_rx) = mpsc::channel(1);
    let (connect_tx, connect_rx) = oneshot::channel();
    let session = tokio::spawn(super::run_stream_compose_session_with_connector(
        open,
        async move { connect_rx.await.map_err(|err| err.to_string()) },
        8,
        rx,
        cancel_rx,
        report,
        super::LiveBrokerTimeouts {
            write: Duration::from_millis(50),
            connect: Duration::ZERO,
        },
    ));

    let mut transcript_inputs = Vec::new();
    for idx in 0..super::MAX_PENDING_LIVE_RECORDS {
        let text = format!("record-{idx}");
        let (respond, response) = oneshot::channel();
        tx.send(StreamComposeCommand::Append {
            text: text.clone(),
            respond,
        })
        .await
        .unwrap();
        let appended = tokio::time::timeout(Duration::from_millis(250), response)
            .await
            .expect("append should complete while broker connect is pending")
            .unwrap()
            .unwrap();
        assert_eq!(appended.error, None);
        transcript_inputs.push(text);
    }

    let (overflow_respond, overflow_response) = oneshot::channel();
    tx.send(StreamComposeCommand::Append {
        text: "overflow".to_owned(),
        respond: overflow_respond,
    })
    .await
    .unwrap();
    let overflowed = tokio::time::timeout(Duration::from_millis(250), overflow_response)
        .await
        .expect("overflow append should complete")
        .unwrap()
        .unwrap();
    assert!(
        overflowed
            .error
            .as_deref()
            .is_some_and(|err| err.contains(&format!(
                "pending live stream buffer exceeded {} records",
                super::MAX_PENDING_LIVE_RECORDS
            ))),
        "overflow should latch live preview error: {:?}",
        overflowed.error
    );
    transcript_inputs.push("overflow".to_owned());

    let (dropped_tx, dropped_rx) = oneshot::channel();
    assert!(
        connect_tx
            .send(DropNotifyingPublisher {
                dropped: Some(dropped_tx),
            })
            .is_ok(),
        "session should still be waiting for broker connect"
    );
    tokio::time::timeout(Duration::from_millis(250), dropped_rx)
        .await
        .expect("late broker connect should be dropped after live preview is disabled")
        .unwrap();

    let (finish_respond, finish_response) = oneshot::channel();
    tx.send(StreamComposeCommand::Finish {
        respond: finish_respond,
    })
    .await
    .unwrap();
    let finished = tokio::time::timeout(Duration::from_millis(250), finish_response)
        .await
        .expect("finish should complete after live preview overflow")
        .unwrap()
        .unwrap();
    assert_eq!(finished.status, "finished");
    assert!(
        finished
            .error
            .as_deref()
            .is_some_and(|err| err.contains(&format!(
                "pending live stream buffer exceeded {} records",
                super::MAX_PENDING_LIVE_RECORDS
            ))),
        "finish should preserve live preview overflow: {:?}",
        finished.error
    );
    let expected_inputs = transcript_inputs
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        finished.transcript_hash.as_deref(),
        Some(
            expected_stream_transcript_hash_for_appends(
                &stream_id,
                &start_event_id,
                &expected_inputs,
                8,
            )
            .as_str()
        )
    );

    session.await.unwrap();
}

struct StalledFinishPublisher;

impl super::LiveBrokerPublisher for StalledFinishPublisher {
    async fn append_record_text(
        &mut self,
        _record_type: u8,
        _text: &str,
        _chunk_bytes: usize,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn append_abort(&mut self) -> Result<(), String> {
        Ok(())
    }

    async fn finish(self) -> Result<(), String> {
        future::pending().await
    }
}

#[tokio::test]
async fn finish_report_times_out_stalled_live_finish_and_uses_local_transcript() {
    let stream_id = vec![0x5a; 32];
    let start_event_id = MessageId::new(vec![0x5b; 32]);
    let open = test_stream_compose_open(stream_id.clone(), start_event_id.clone());
    let mut report = test_stream_compose_report(&stream_id);
    let transcript = super::LocalComposeTranscript::new(&open);
    let mut publisher = Some(StalledFinishPublisher);
    let mut pending_live_records = super::PendingLiveRecords::default();
    let mut live_error = None;

    let finished = super::finish_stream_compose_report(
        &mut report,
        &transcript,
        super::ComposeLiveSink {
            publisher: &mut publisher,
            pending_live_records: &mut pending_live_records,
            live_error: &mut live_error,
            live_write_timeout: Duration::from_millis(10),
        },
        8,
    )
    .await
    .unwrap();

    assert!(
        publisher.is_none(),
        "publisher should be consumed on finish"
    );
    assert_eq!(finished.status, "finished");
    assert_eq!(finished.chunk_count, 0);
    assert!(
        finished
            .error
            .as_deref()
            .is_some_and(|err| err.contains("timed out")),
        "finish should report live timeout: {:?}",
        finished.error
    );
}

#[tokio::test]
async fn compose_session_times_out_stalled_live_flush_and_still_finishes() {
    let stream_id = vec![0x4a; 32];
    let start_event_id = MessageId::new(vec![0x4b; 32]);
    let open = test_stream_compose_open(stream_id.clone(), start_event_id.clone());
    let report = test_stream_compose_report(&stream_id);
    let (tx, rx) = mpsc::channel(4);
    let (_cancel_tx, cancel_rx) = mpsc::channel(1);
    let (connect_tx, connect_rx) = oneshot::channel();
    let (append_started_tx, append_started_rx) = oneshot::channel();
    let session = tokio::spawn(super::run_stream_compose_session_with_connector(
        open,
        async move {
            connect_rx.await.map_err(|err| err.to_string())?;
            Ok::<_, String>(StalledPublisher {
                append_started: Some(append_started_tx),
            })
        },
        8,
        rx,
        cancel_rx,
        report,
        super::LiveBrokerTimeouts {
            write: Duration::from_millis(10),
            connect: Duration::from_secs(5),
        },
    ));

    let (append_tx, append_rx) = oneshot::channel();
    tx.send(StreamComposeCommand::Append {
        text: "hello".to_owned(),
        respond: append_tx,
    })
    .await
    .unwrap();
    let appended = tokio::time::timeout(Duration::from_millis(250), append_rx)
        .await
        .expect("append should use local transcript while broker connect is pending")
        .unwrap()
        .unwrap();
    assert_eq!(appended.text, "hello");
    assert_eq!(appended.chunk_count, 1);
    assert_eq!(appended.error, None);

    connect_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_millis(250), append_started_rx)
        .await
        .expect("pending live flush should start")
        .unwrap();

    let (finish_tx, finish_rx) = oneshot::channel();
    tx.send(StreamComposeCommand::Finish { respond: finish_tx })
        .await
        .unwrap();
    let finished = tokio::time::timeout(Duration::from_millis(250), finish_rx)
        .await
        .expect("finish should not wait indefinitely behind the stalled live flush")
        .unwrap()
        .unwrap();

    assert_eq!(finished.status, "finished");
    assert_eq!(finished.text, "hello");
    assert_eq!(finished.chunk_count, 1);
    assert!(
        finished
            .error
            .as_deref()
            .is_some_and(|err| err.contains("timed out")),
        "finish should report live timeout: {:?}",
        finished.error
    );
    assert_eq!(
        finished.transcript_hash.as_deref(),
        Some(
            expected_stream_transcript_hash_for_appends(
                &stream_id,
                &start_event_id,
                &["hello"],
                8,
            )
            .as_str()
        )
    );

    session.await.unwrap();
}

#[tokio::test]
async fn compose_session_times_out_pending_broker_connect_and_disables_live_preview() {
    let stream_id = vec![0x6a; 32];
    let start_event_id = MessageId::new(vec![0x6b; 32]);
    let open = test_stream_compose_open(stream_id.clone(), start_event_id.clone());
    let report = test_stream_compose_report(&stream_id);
    let (tx, rx) = mpsc::channel(4);
    let (_cancel_tx, cancel_rx) = mpsc::channel(1);
    let session = tokio::spawn(super::run_stream_compose_session_with_connector(
        open,
        future::pending::<Result<StalledPublisher, String>>(),
        8,
        rx,
        cancel_rx,
        report,
        super::LiveBrokerTimeouts {
            write: Duration::from_millis(50),
            connect: Duration::from_millis(10),
        },
    ));

    let (first_tx, first_rx) = oneshot::channel();
    tx.send(StreamComposeCommand::Append {
        text: "buffered".to_owned(),
        respond: first_tx,
    })
    .await
    .unwrap();
    let first = tokio::time::timeout(Duration::from_millis(250), first_rx)
        .await
        .expect("append should use local transcript while broker connect is pending")
        .unwrap()
        .unwrap();
    assert_eq!(first.text, "buffered");
    assert_eq!(first.error, None);

    tokio::time::sleep(Duration::from_millis(50)).await;

    let (second_tx, second_rx) = oneshot::channel();
    tx.send(StreamComposeCommand::Append {
        text: " after timeout".to_owned(),
        respond: second_tx,
    })
    .await
    .unwrap();
    let second = tokio::time::timeout(Duration::from_millis(250), second_rx)
        .await
        .expect("append should complete after broker connect timeout")
        .unwrap()
        .unwrap();
    assert_eq!(second.text, "buffered after timeout");
    assert!(
        second
            .error
            .as_deref()
            .is_some_and(|err| err.contains("live broker connect timed out")),
        "append should report broker connect timeout: {:?}",
        second.error
    );

    let (finish_tx, finish_rx) = oneshot::channel();
    tx.send(StreamComposeCommand::Finish { respond: finish_tx })
        .await
        .unwrap();
    let finished = tokio::time::timeout(Duration::from_millis(250), finish_rx)
        .await
        .expect("finish should complete after broker connect timeout")
        .unwrap()
        .unwrap();
    assert_eq!(finished.status, "finished");
    assert_eq!(finished.text, "buffered after timeout");
    assert!(
        finished
            .error
            .as_deref()
            .is_some_and(|err| err.contains("live broker connect timed out")),
        "finish should preserve broker connect timeout: {:?}",
        finished.error
    );
    assert_eq!(
        finished.transcript_hash.as_deref(),
        Some(
            expected_stream_transcript_hash_for_appends(
                &stream_id,
                &start_event_id,
                &["buffered", " after timeout"],
                8,
            )
            .as_str()
        )
    );

    session.await.unwrap();
}

#[tokio::test]
async fn compose_session_cancel_emits_abort_record_to_subscriber() {
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        ..QuicBrokerConfig::default()
    })
    .unwrap();
    let broker_addr = server.local_addr().unwrap();
    let server_cert = server.server_cert_der().to_vec();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let broker_task = tokio::spawn(server.run_until(async {
        let _ = shutdown_rx.await;
    }));

    let stream_id = vec![0xc1; 32];
    let start_event_id = MessageId::new(vec![0xc2; 32]);

    // A subscriber attaches to the live preview before any records arrive.
    let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
    }));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let open = OpenBrokerTextPublisher {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert),
        stream_id: stream_id.clone(),
        start_event_id,
        crypto: None,
        max_plaintext_frame_len: None,
    };
    let report = test_stream_compose_report(&stream_id);
    let (tx, rx) = mpsc::channel(4);
    let (cancel_tx, cancel_rx) = mpsc::channel(1);
    let session = tokio::spawn(run_stream_compose_session(open, 16, rx, cancel_rx, report));

    // Let the broker connect land so the text delta is flushed live (rather
    // than buffered as a pending record) before we append.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let (append_respond, append_response) = oneshot::channel();
    tx.send(StreamComposeCommand::Append {
        text: "partial answer".to_owned(),
        respond: append_respond,
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_millis(500), append_response)
        .await
        .expect("append should complete")
        .unwrap()
        .unwrap();

    // Cancel the preview. The session must publish a live Abort record and
    // close the publisher cleanly so the subscriber observes the terminal
    // cancellation instead of an open-ended preview.
    cancel_tx.send(()).await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
        .await
        .expect("subscriber should finish once the stream is aborted and closed")
        .unwrap()
        .unwrap();

    assert_eq!(received.text, "partial answer");
    assert!(
        received
            .chunks
            .iter()
            .any(|chunk| chunk.record_type == AGENT_TEXT_STREAM_RECORD_ABORT),
        "subscriber must observe a live Abort record on cancel; got {:?}",
        received
            .chunks
            .iter()
            .map(|chunk| chunk.record_type)
            .collect::<Vec<_>>()
    );
    let abort = received
        .chunks
        .iter()
        .find(|chunk| chunk.record_type == AGENT_TEXT_STREAM_RECORD_ABORT)
        .unwrap();
    assert_eq!(abort.text, "");

    session.await.unwrap();
    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn compose_session_cancel_completes_when_broker_unreachable() {
    // Broker addr that never accepts a connection: cancel must still tear
    // the session down promptly (bounded connect grace) rather than hang.
    let stream_id = vec![0xd1; 32];
    let start_event_id = MessageId::new(vec![0xd2; 32]);
    let open = test_stream_compose_open(stream_id.clone(), start_event_id);
    let report = test_stream_compose_report(&stream_id);
    let (tx, rx) = mpsc::channel(4);
    let (cancel_tx, cancel_rx) = mpsc::channel(1);
    let session = tokio::spawn(run_stream_compose_session(open, 16, rx, cancel_rx, report));

    // Append before any broker connection is established; this is buffered
    // locally as a pending live record.
    let (append_respond, append_response) = oneshot::channel();
    tx.send(StreamComposeCommand::Append {
        text: "buffered".to_owned(),
        respond: append_respond,
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_millis(500), append_response)
        .await
        .expect("append should not wait on broker connect")
        .unwrap()
        .unwrap();

    cancel_tx.send(()).await.unwrap();

    // The session must terminate within the bounded cancel grace + slack,
    // not stall on an unreachable broker connect.
    tokio::time::timeout(Duration::from_secs(8), session)
        .await
        .expect("cancel must not hang when the broker is unreachable")
        .unwrap();
}

/// Regression for the cancel-starvation bug: a full command queue must not
/// prevent cancellation from reaching the session. The dedicated cancel
/// signal is polled with `biased` priority on its own bounded channel, so
/// even when every `StreamComposeCommand` slot is occupied the session still
/// observes the cancel, emits a live `Abort`, and the subscriber sees it
/// instead of an open-ended preview.
#[tokio::test]
async fn compose_session_cancel_wins_even_with_full_command_queue() {
    let server = QuicBrokerServer::bind(QuicBrokerConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
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
    let start_event_id = MessageId::new(vec![0xe2; 32]);

    let subscriber = tokio::spawn(subscribe_text_from_broker(SubscribeTextFromBroker {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert.clone()),
        stream_id: stream_id.clone(),
        start_event_id: start_event_id.clone(),
        crypto: None,
    }));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let open = OpenBrokerTextPublisher {
        broker_addr,
        server_name: "localhost".to_owned(),
        trust: BrokerServerTrust::CertificateDer(server_cert),
        stream_id: stream_id.clone(),
        start_event_id,
        crypto: None,
        max_plaintext_frame_len: None,
    };
    let report = test_stream_compose_report(&stream_id);
    // Capacity-1 command channel keeps the queue trivially saturable.
    let (tx, rx) = mpsc::channel(1);
    let (cancel_tx, cancel_rx) = mpsc::channel(1);
    let session = tokio::spawn(run_stream_compose_session(open, 16, rx, cancel_rx, report));

    // Land at least one live record so the publisher is connected and the
    // subscriber has an open preview to be aborted.
    let (append_respond, append_response) = oneshot::channel();
    tx.send(StreamComposeCommand::Append {
        text: "partial answer".to_owned(),
        respond: append_respond,
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_millis(500), append_response)
        .await
        .expect("first append should complete")
        .unwrap()
        .unwrap();

    // Saturate the command queue: one in-flight (being processed) plus a
    // full buffer. We never await these responses, so the command channel
    // stays full and a Cancel command could never be `try_send`-ed onto it.
    for _ in 0..8 {
        let (respond, _ignored) = oneshot::channel();
        if tx
            .try_send(StreamComposeCommand::Append {
                text: "queued".to_owned(),
                respond,
            })
            .is_err()
        {
            // Channel is full — exactly the starvation condition we want.
            break;
        }
    }
    assert!(
        tx.try_reserve().is_err(),
        "command queue should be saturated for this regression"
    );

    // The dedicated cancel signal must still get through.
    cancel_tx
        .send(())
        .await
        .expect("cancel signal must not be starved by a full command queue");

    let received = tokio::time::timeout(Duration::from_secs(5), subscriber)
        .await
        .expect("subscriber should finish once the stream is aborted and closed")
        .unwrap()
        .unwrap();

    assert!(
        received
            .chunks
            .iter()
            .any(|chunk| chunk.record_type == AGENT_TEXT_STREAM_RECORD_ABORT),
        "subscriber must observe a live Abort even when the command queue is full; got {:?}",
        received
            .chunks
            .iter()
            .map(|chunk| chunk.record_type)
            .collect::<Vec<_>>()
    );

    tokio::time::timeout(Duration::from_secs(5), session)
        .await
        .expect("session must terminate after cancel")
        .unwrap();
    let _ = shutdown_tx.send(());
    broker_task.await.unwrap().unwrap();
}
