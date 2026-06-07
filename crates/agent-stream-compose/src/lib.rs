//! Reusable live-preview stream composition for Marmot agent integrations.

use std::collections::VecDeque;
use std::time::Duration;

use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN, AGENT_TEXT_STREAM_RECORD_STATUS,
    AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, AgentTextStreamTranscriptV1,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use transport_quic_broker::{BrokerTextPublisher, OpenBrokerTextPublisher};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamComposeReport {
    pub account: Option<String>,
    pub group_id: String,
    pub stream_id: String,
    pub start_message_id: String,
    pub candidate: String,
    pub status: String,
    pub text: String,
    pub transcript_hash: Option<String>,
    pub chunk_count: u64,
    pub error: Option<String>,
}

pub enum StreamComposeCommand {
    Append {
        text: String,
        respond: oneshot::Sender<Result<StreamComposeReport, String>>,
    },
    Status {
        status: String,
        respond: oneshot::Sender<Result<StreamComposeReport, String>>,
    },
    Finish {
        respond: oneshot::Sender<Result<StreamComposeReport, String>>,
    },
    Cancel,
}

pub async fn run_stream_compose_session(
    open: OpenBrokerTextPublisher,
    chunk_bytes: usize,
    mut rx: mpsc::Receiver<StreamComposeCommand>,
    mut report: StreamComposeReport,
) {
    let mut transcript = LocalComposeTranscript::new(&open);
    let mut pending_live_records = VecDeque::new();
    let mut publisher = None;
    let mut connect_task = Some(tokio::spawn(BrokerTextPublisher::connect(open)));
    let mut live_error = None;

    loop {
        let command = if let Some(task) = connect_task.as_mut() {
            tokio::select! {
                connect_result = task => {
                    connect_task = None;
                    match connect_result {
                        Ok(Ok(mut connected)) => {
                            if let Err(err) = flush_pending_live_records(
                                &mut connected,
                                &mut pending_live_records,
                                chunk_bytes,
                            )
                            .await
                            {
                                live_error = Some(err);
                            } else {
                                publisher = Some(connected);
                            }
                        }
                        Ok(Err(err)) => {
                            live_error = Some(err.to_string());
                            pending_live_records.clear();
                        }
                        Err(err) => {
                            live_error = Some(err.to_string());
                            pending_live_records.clear();
                        }
                    }
                    continue;
                }
                command = rx.recv() => command,
            }
        } else {
            rx.recv().await
        };
        let Some(command) = command else {
            if let Some(task) = connect_task {
                task.abort();
            }
            return;
        };

        match command {
            StreamComposeCommand::Append { text, respond } => {
                let result = append_stream_compose_text(
                    &mut report,
                    &mut transcript,
                    &mut publisher,
                    &mut pending_live_records,
                    &mut live_error,
                    text,
                    chunk_bytes,
                )
                .await;
                let _ = respond.send(result);
            }
            StreamComposeCommand::Status { status, respond } => {
                let result = append_stream_compose_status(
                    &mut report,
                    &mut transcript,
                    &mut publisher,
                    &mut pending_live_records,
                    &mut live_error,
                    status,
                    chunk_bytes,
                )
                .await;
                let _ = respond.send(result);
            }
            StreamComposeCommand::Finish { respond } => {
                if let Some(task) = connect_task.take() {
                    task.abort();
                }
                let result = finish_stream_compose_report(
                    &mut report,
                    &transcript,
                    &mut publisher,
                    &mut pending_live_records,
                    &mut live_error,
                    chunk_bytes,
                )
                .await;
                let _ = respond.send(result);
                return;
            }
            StreamComposeCommand::Cancel => {
                if let Some(task) = connect_task {
                    task.abort();
                }
                return;
            }
        }
    }
}

struct LocalComposeTranscript {
    transcript: AgentTextStreamTranscriptV1,
    next_seq: u64,
}

struct PendingComposeRecord {
    record_type: u8,
    text: String,
}

impl LocalComposeTranscript {
    fn new(open: &OpenBrokerTextPublisher) -> Self {
        Self {
            transcript: AgentTextStreamTranscriptV1::new(
                open.stream_id.clone(),
                open.start_event_id.clone(),
            ),
            next_seq: 1,
        }
    }

    fn append_text(&mut self, text: &str, chunk_bytes: usize) -> Result<u64, String> {
        self.append_record_text(AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, text, chunk_bytes)
    }

    fn append_record_text(
        &mut self,
        record_type: u8,
        text: &str,
        chunk_bytes: usize,
    ) -> Result<u64, String> {
        validate_stream_chunk_bytes(chunk_bytes)?;
        let mut appended = 0_u64;
        for chunk in transport_quic_stream::split_text_deltas(text, chunk_bytes) {
            self.transcript.append(self.next_seq, record_type, &chunk);
            self.next_seq += 1;
            appended += 1;
        }
        Ok(appended)
    }

    fn transcript_hash(&self) -> String {
        hex::encode(self.transcript.hash())
    }

    fn chunk_count(&self) -> u64 {
        self.transcript.chunk_count()
    }
}

fn validate_stream_chunk_bytes(chunk_bytes: usize) -> Result<(), String> {
    if chunk_bytes == 0 {
        return Err("agent text stream chunk size cannot be zero".to_owned());
    }
    if chunk_bytes > AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize {
        return Err(format!(
            "agent text stream chunk size exceeds app profile max: {chunk_bytes}"
        ));
    }
    Ok(())
}

async fn append_stream_compose_text(
    report: &mut StreamComposeReport,
    transcript: &mut LocalComposeTranscript,
    publisher: &mut Option<BrokerTextPublisher>,
    pending_live_records: &mut VecDeque<PendingComposeRecord>,
    live_error: &mut Option<String>,
    text: String,
    chunk_bytes: usize,
) -> Result<StreamComposeReport, String> {
    transcript.append_text(&text, chunk_bytes)?;
    report.text.push_str(&text);
    report.chunk_count = transcript.chunk_count();
    report.transcript_hash = Some(transcript.transcript_hash());

    append_live_record(
        publisher,
        pending_live_records,
        live_error,
        AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
        text,
        chunk_bytes,
    )
    .await;
    if let Some(err) = live_error {
        report.error = Some(format!("live stream failed: {err}"));
    }

    Ok(report.clone())
}

async fn append_stream_compose_status(
    report: &mut StreamComposeReport,
    transcript: &mut LocalComposeTranscript,
    publisher: &mut Option<BrokerTextPublisher>,
    pending_live_records: &mut VecDeque<PendingComposeRecord>,
    live_error: &mut Option<String>,
    status: String,
    chunk_bytes: usize,
) -> Result<StreamComposeReport, String> {
    transcript.append_record_text(AGENT_TEXT_STREAM_RECORD_STATUS, &status, chunk_bytes)?;
    report.status.clone_from(&status);
    report.chunk_count = transcript.chunk_count();
    report.transcript_hash = Some(transcript.transcript_hash());

    append_live_record(
        publisher,
        pending_live_records,
        live_error,
        AGENT_TEXT_STREAM_RECORD_STATUS,
        status,
        chunk_bytes,
    )
    .await;
    if let Some(err) = live_error {
        report.error = Some(format!("live stream failed: {err}"));
    }

    Ok(report.clone())
}

async fn append_live_record(
    publisher: &mut Option<BrokerTextPublisher>,
    pending_live_records: &mut VecDeque<PendingComposeRecord>,
    live_error: &mut Option<String>,
    record_type: u8,
    text: String,
    chunk_bytes: usize,
) {
    if live_error.is_none() {
        if let Some(publisher) = publisher.as_mut() {
            if let Err(err) = publisher
                .append_record_text(record_type, &text, chunk_bytes, Duration::ZERO)
                .await
                .map_err(|err| err.to_string())
            {
                *live_error = Some(err);
            }
        } else {
            pending_live_records.push_back(PendingComposeRecord { record_type, text });
        }
    }
}

async fn finish_stream_compose_report(
    report: &mut StreamComposeReport,
    transcript: &LocalComposeTranscript,
    publisher: &mut Option<BrokerTextPublisher>,
    pending_live_records: &mut VecDeque<PendingComposeRecord>,
    live_error: &mut Option<String>,
    chunk_bytes: usize,
) -> Result<StreamComposeReport, String> {
    if live_error.is_none()
        && let Some(publisher) = publisher.as_mut()
        && let Err(err) =
            flush_pending_live_records(publisher, pending_live_records, chunk_bytes).await
    {
        *live_error = Some(err);
    }

    if live_error.is_none()
        && let Some(publisher) = publisher.take()
        && let Err(err) = publisher.finish().await.map_err(|err| err.to_string())
    {
        *live_error = Some(err);
    }

    report.status = "finished".to_owned();
    report.transcript_hash = Some(transcript.transcript_hash());
    report.chunk_count = transcript.chunk_count();
    if let Some(err) = live_error {
        report.error = Some(format!("live stream failed: {err}"));
    }
    Ok(report.clone())
}

async fn flush_pending_live_records(
    publisher: &mut BrokerTextPublisher,
    pending_live_records: &mut VecDeque<PendingComposeRecord>,
    chunk_bytes: usize,
) -> Result<(), String> {
    while let Some(record) = pending_live_records.pop_front() {
        if let Err(err) = publisher
            .append_record_text(
                record.record_type,
                &record.text,
                chunk_bytes,
                Duration::ZERO,
            )
            .await
            .map_err(|err| err.to_string())
        {
            pending_live_records.clear();
            return Err(err);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use cgka_traits::MessageId;
    use cgka_traits::agent_text_stream::{
        AGENT_TEXT_STREAM_RECORD_STATUS, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
        AgentTextStreamTranscriptV1,
    };
    use tokio::sync::{mpsc, oneshot};
    use transport_quic_broker::{BrokerServerTrust, OpenBrokerTextPublisher};

    use crate::{StreamComposeCommand, StreamComposeReport, run_stream_compose_session};

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
        let session = tokio::spawn(run_stream_compose_session(open, 8, rx, report));

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
    async fn compose_session_final_report_contains_full_transcript_text() {
        let stream_id = vec![0xcc; 32];
        let start_event_id = MessageId::new(vec![0xdd; 32]);
        let open = test_stream_compose_open(stream_id.clone(), start_event_id.clone());
        let report = test_stream_compose_report(&stream_id);
        let (tx, rx) = mpsc::channel(4);
        let session = tokio::spawn(run_stream_compose_session(open, 5, rx, report));

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
        let session = tokio::spawn(run_stream_compose_session(open, 16, rx, report));

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
}
