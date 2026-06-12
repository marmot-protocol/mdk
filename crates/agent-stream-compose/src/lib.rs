//! Reusable live-preview stream composition for Marmot agent integrations.

use std::collections::VecDeque;
use std::future::Future;
use std::time::Duration;

use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN, AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA,
    AGENT_TEXT_STREAM_RECORD_STATUS, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
    AgentTextStreamTranscriptV1,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use transport_quic_broker::{BrokerTextPublisher, OpenBrokerTextPublisher};

/// Bounded grace period to let an in-flight broker connect land during cancel
/// so a live `Abort` record can be published before the session shuts down.
const CANCEL_CONNECT_GRACE: Duration = Duration::from_secs(2);

const DEFAULT_LIVE_BROKER_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

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
    Progress {
        text: String,
        respond: oneshot::Sender<Result<StreamComposeReport, String>>,
    },
    Finish {
        respond: oneshot::Sender<Result<StreamComposeReport, String>>,
    },
}

trait LiveBrokerPublisher: Sized + Send + 'static {
    async fn append_record_text(
        &mut self,
        record_type: u8,
        text: &str,
        chunk_bytes: usize,
    ) -> Result<(), String>;

    /// Emit a single live `Abort` (`0x05`) record so online subscribers observe
    /// the terminal cancellation of the preview.
    async fn append_abort(&mut self) -> Result<(), String>;

    async fn finish(self) -> Result<(), String>;
}

impl LiveBrokerPublisher for BrokerTextPublisher {
    async fn append_record_text(
        &mut self,
        record_type: u8,
        text: &str,
        chunk_bytes: usize,
    ) -> Result<(), String> {
        BrokerTextPublisher::append_record_text(
            self,
            record_type,
            text,
            chunk_bytes,
            Duration::ZERO,
        )
        .await
        .map(|_| ())
        .map_err(|err| err.to_string())
    }

    async fn append_abort(&mut self) -> Result<(), String> {
        BrokerTextPublisher::append_abort(self)
            .await
            .map_err(|err| err.to_string())
    }

    async fn finish(self) -> Result<(), String> {
        BrokerTextPublisher::finish(self)
            .await
            .map(|_| ())
            .map_err(|err| err.to_string())
    }
}

pub async fn run_stream_compose_session(
    open: OpenBrokerTextPublisher,
    chunk_bytes: usize,
    rx: mpsc::Receiver<StreamComposeCommand>,
    cancel_rx: mpsc::Receiver<()>,
    report: StreamComposeReport,
) {
    let connect = BrokerTextPublisher::connect(open.clone());
    run_stream_compose_session_with_connector(
        open,
        connect,
        chunk_bytes,
        rx,
        cancel_rx,
        report,
        DEFAULT_LIVE_BROKER_WRITE_TIMEOUT,
    )
    .await;
}

async fn run_stream_compose_session_with_connector<P, C, E>(
    open: OpenBrokerTextPublisher,
    connect: C,
    chunk_bytes: usize,
    mut rx: mpsc::Receiver<StreamComposeCommand>,
    mut cancel_rx: mpsc::Receiver<()>,
    mut report: StreamComposeReport,
    live_write_timeout: Duration,
) where
    P: LiveBrokerPublisher,
    C: Future<Output = Result<P, E>> + Send + 'static,
    E: ToString + Send + 'static,
{
    let mut transcript = LocalComposeTranscript::new(&open);
    let mut pending_live_records = VecDeque::new();
    let mut publisher = None;
    let mut connect_task = Some(tokio::spawn(async move {
        connect.await.map_err(|err| err.to_string())
    }));
    let mut live_error = None;

    loop {
        // The dedicated cancel signal is a separate, bounded channel that
        // callers cannot starve behind queued append/status/progress commands.
        // Poll it first (`biased`) so an explicit cancel always wins the race
        // against pending work and the session emits a live `Abort` before it
        // shuts down.
        let command = if let Some(task) = connect_task.as_mut() {
            tokio::select! {
                biased;
                _ = cancel_rx.recv() => {
                    cancel_stream_compose_session(
                        connect_task.take(),
                        &mut publisher,
                        &mut live_error,
                        live_write_timeout,
                    )
                    .await;
                    return;
                }
                connect_result = task => {
                    connect_task = None;
                    match connect_result {
                        Ok(Ok(mut connected)) => {
                            if let Err(err) = live_broker_deadline(
                                live_write_timeout,
                                flush_pending_live_records(
                                    &mut connected,
                                    &mut pending_live_records,
                                    chunk_bytes,
                                ),
                            )
                            .await
                            {
                                live_error = Some(err);
                                pending_live_records.clear();
                            } else {
                                publisher = Some(connected);
                            }
                        }
                        Ok(Err(err)) => {
                            live_error = Some(err);
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
            tokio::select! {
                biased;
                _ = cancel_rx.recv() => {
                    cancel_stream_compose_session(
                        None,
                        &mut publisher,
                        &mut live_error,
                        live_write_timeout,
                    )
                    .await;
                    return;
                }
                command = rx.recv() => command,
            }
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
                    ComposeLiveSink {
                        publisher: &mut publisher,
                        pending_live_records: &mut pending_live_records,
                        live_error: &mut live_error,
                        live_write_timeout,
                    },
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
                    ComposeLiveSink {
                        publisher: &mut publisher,
                        pending_live_records: &mut pending_live_records,
                        live_error: &mut live_error,
                        live_write_timeout,
                    },
                    status,
                    chunk_bytes,
                )
                .await;
                let _ = respond.send(result);
            }
            StreamComposeCommand::Progress { text, respond } => {
                let result = append_stream_compose_progress(
                    &mut report,
                    &mut transcript,
                    ComposeLiveSink {
                        publisher: &mut publisher,
                        pending_live_records: &mut pending_live_records,
                        live_error: &mut live_error,
                        live_write_timeout,
                    },
                    text,
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
                    ComposeLiveSink {
                        publisher: &mut publisher,
                        pending_live_records: &mut pending_live_records,
                        live_error: &mut live_error,
                        live_write_timeout,
                    },
                    chunk_bytes,
                )
                .await;
                let _ = respond.send(result);
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

async fn append_stream_compose_text<P: LiveBrokerPublisher>(
    report: &mut StreamComposeReport,
    transcript: &mut LocalComposeTranscript,
    mut live: ComposeLiveSink<'_, P>,
    text: String,
    chunk_bytes: usize,
) -> Result<StreamComposeReport, String> {
    transcript.append_text(&text, chunk_bytes)?;
    report.text.push_str(&text);
    report.chunk_count = transcript.chunk_count();
    report.transcript_hash = Some(transcript.transcript_hash());

    append_live_record(
        &mut live,
        AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
        text,
        chunk_bytes,
    )
    .await;
    if let Some(err) = live.live_error.as_deref() {
        report.error = Some(format!("live stream failed: {err}"));
    }

    Ok(report.clone())
}

async fn append_stream_compose_status<P: LiveBrokerPublisher>(
    report: &mut StreamComposeReport,
    transcript: &mut LocalComposeTranscript,
    live: ComposeLiveSink<'_, P>,
    status: String,
    chunk_bytes: usize,
) -> Result<StreamComposeReport, String> {
    report.status.clone_from(&status);
    append_stream_compose_non_text_record(
        report,
        transcript,
        live,
        AGENT_TEXT_STREAM_RECORD_STATUS,
        status,
        chunk_bytes,
    )
    .await
}

async fn append_stream_compose_progress<P: LiveBrokerPublisher>(
    report: &mut StreamComposeReport,
    transcript: &mut LocalComposeTranscript,
    live: ComposeLiveSink<'_, P>,
    text: String,
    chunk_bytes: usize,
) -> Result<StreamComposeReport, String> {
    append_stream_compose_non_text_record(
        report,
        transcript,
        live,
        AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA,
        text,
        chunk_bytes,
    )
    .await
}

struct ComposeLiveSink<'a, P> {
    publisher: &'a mut Option<P>,
    pending_live_records: &'a mut VecDeque<PendingComposeRecord>,
    live_error: &'a mut Option<String>,
    live_write_timeout: Duration,
}

async fn append_stream_compose_non_text_record<P: LiveBrokerPublisher>(
    report: &mut StreamComposeReport,
    transcript: &mut LocalComposeTranscript,
    mut live: ComposeLiveSink<'_, P>,
    record_type: u8,
    text: String,
    chunk_bytes: usize,
) -> Result<StreamComposeReport, String> {
    transcript.append_record_text(record_type, &text, chunk_bytes)?;
    report.chunk_count = transcript.chunk_count();
    report.transcript_hash = Some(transcript.transcript_hash());

    append_live_record(&mut live, record_type, text, chunk_bytes).await;
    if let Some(err) = live.live_error.as_deref() {
        report.error = Some(format!("live stream failed: {err}"));
    }

    Ok(report.clone())
}

async fn append_live_record<P: LiveBrokerPublisher>(
    live: &mut ComposeLiveSink<'_, P>,
    record_type: u8,
    text: String,
    chunk_bytes: usize,
) {
    if live.live_error.is_none() {
        if let Some(connected) = live.publisher.as_mut() {
            if let Err(err) = live_broker_deadline(
                live.live_write_timeout,
                connected.append_record_text(record_type, &text, chunk_bytes),
            )
            .await
            {
                *live.live_error = Some(err);
                *live.publisher = None;
                live.pending_live_records.clear();
            }
        } else {
            live.pending_live_records
                .push_back(PendingComposeRecord { record_type, text });
        }
    }
}

async fn finish_stream_compose_report<P: LiveBrokerPublisher>(
    report: &mut StreamComposeReport,
    transcript: &LocalComposeTranscript,
    live: ComposeLiveSink<'_, P>,
    chunk_bytes: usize,
) -> Result<StreamComposeReport, String> {
    let flush_result = if live.live_error.is_none() {
        if let Some(connected) = live.publisher.as_mut() {
            Some(
                live_broker_deadline(
                    live.live_write_timeout,
                    flush_pending_live_records(connected, live.pending_live_records, chunk_bytes),
                )
                .await,
            )
        } else {
            None
        }
    } else {
        None
    };
    if let Some(Err(err)) = flush_result {
        *live.live_error = Some(err);
        *live.publisher = None;
        live.pending_live_records.clear();
    }

    if live.live_error.is_none()
        && let Some(connected) = live.publisher.take()
        && let Err(err) = live_broker_deadline(live.live_write_timeout, connected.finish()).await
    {
        *live.live_error = Some(err);
    }

    report.status = "finished".to_owned();
    report.transcript_hash = Some(transcript.transcript_hash());
    report.chunk_count = transcript.chunk_count();
    if let Some(err) = live.live_error.as_deref() {
        report.error = Some(format!("live stream failed: {err}"));
    }
    Ok(report.clone())
}

async fn flush_pending_live_records<P: LiveBrokerPublisher>(
    publisher: &mut P,
    pending_live_records: &mut VecDeque<PendingComposeRecord>,
    chunk_bytes: usize,
) -> Result<(), String> {
    while let Some(record) = pending_live_records.pop_front() {
        if let Err(err) = publisher
            .append_record_text(record.record_type, &record.text, chunk_bytes)
            .await
        {
            pending_live_records.clear();
            return Err(err);
        }
    }
    Ok(())
}

async fn live_broker_deadline<T>(
    live_write_timeout: Duration,
    operation: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    if live_write_timeout.is_zero() {
        return operation.await;
    }
    // Dropping the timed-out operation cancels the in-flight QUIC write; callers
    // then drop the publisher so future live records fall back to the local transcript.
    tokio::time::timeout(live_write_timeout, operation)
        .await
        .map_err(|_| format!("live broker write timed out after {live_write_timeout:?}"))?
}

/// Cancel an in-flight compose session, emitting a live `Abort` record so any
/// online subscribers observe the terminal cancellation of the preview.
///
/// If the broker publisher is connected (or the connect task is still pending,
/// in which case we briefly await it), we send a single `Abort` record and
/// close the publisher cleanly with `finish`. If the broker was never reachable
/// (connect failed, or a prior live error already poisoned the stream), local
/// cleanup still proceeds: the pending connect task is aborted and we return
/// without emitting anything. Abort/finish writes are bounded by
/// `live_write_timeout` so a stalled broker cannot stall cleanup.
async fn cancel_stream_compose_session<P>(
    connect_task: Option<tokio::task::JoinHandle<Result<P, String>>>,
    publisher: &mut Option<P>,
    live_error: &mut Option<String>,
    live_write_timeout: Duration,
) where
    P: LiveBrokerPublisher,
{
    // If we never finished connecting, give the in-flight connect a brief,
    // bounded chance to land so the abort can be published; otherwise drop it.
    // Bounding matters for abandoned/idle sweeps where the broker is gone and an
    // unbounded await would stall cleanup for the full connect timeout.
    if publisher.is_none()
        && live_error.is_none()
        && let Some(task) = connect_task
    {
        match tokio::time::timeout(CANCEL_CONNECT_GRACE, task).await {
            Ok(Ok(Ok(connected))) => *publisher = Some(connected),
            Ok(Ok(Err(err))) => *live_error = Some(err),
            Ok(Err(err)) => *live_error = Some(err.to_string()),
            Err(_) => *live_error = Some("broker connect timed out during cancel".to_owned()),
        }
    } else if let Some(task) = connect_task {
        task.abort();
    }

    if live_error.is_none()
        && let Some(mut connected) = publisher.take()
        && live_broker_deadline(live_write_timeout, connected.append_abort())
            .await
            .is_ok()
    {
        let _ = live_broker_deadline(live_write_timeout, connected.finish()).await;
    }
}

#[cfg(test)]
mod tests {
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

    #[tokio::test]
    async fn append_live_record_times_out_stalled_publisher_and_drops_it() {
        let mut publisher = Some(StalledPublisher {
            append_started: None,
        });
        let mut pending_live_records = std::collections::VecDeque::new();
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
        assert!(pending_live_records.is_empty());
        assert!(
            live_error
                .as_deref()
                .is_some_and(|err| err.contains("timed out")),
            "append should record live timeout: {live_error:?}"
        );
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
        let mut pending_live_records = std::collections::VecDeque::new();
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
            Duration::from_millis(10),
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
}
