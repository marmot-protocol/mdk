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
use transport_quic_stream::effective_plaintext_cap;

/// Bounded grace period to let an in-flight broker connect land during cancel
/// so a live `Abort` record can be published before the session shuts down.
const CANCEL_CONNECT_GRACE: Duration = Duration::from_secs(2);

const DEFAULT_LIVE_BROKER_TIMEOUTS: LiveBrokerTimeouts = LiveBrokerTimeouts {
    connect: Duration::from_secs(5),
    write: Duration::from_secs(5),
};
const MAX_PENDING_LIVE_RECORDS: usize = 256;
const MAX_PENDING_LIVE_RECORD_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy)]
struct LiveBrokerTimeouts {
    connect: Duration,
    write: Duration,
}

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
        DEFAULT_LIVE_BROKER_TIMEOUTS,
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
    live_timeouts: LiveBrokerTimeouts,
) where
    P: LiveBrokerPublisher,
    C: Future<Output = Result<P, E>> + Send + 'static,
    E: ToString + Send + 'static,
{
    let chunk_bytes =
        effective_stream_compose_chunk_bytes(chunk_bytes, open.max_plaintext_frame_len);
    let mut transcript = LocalComposeTranscript::new(&open);
    let mut pending_live_records = PendingLiveRecords::default();
    let mut publisher = None;
    let live_connect_timeout = live_timeouts.connect;
    let live_write_timeout = live_timeouts.write;
    let mut connect_task = Some(tokio::spawn(async move {
        live_broker_connect_deadline(live_connect_timeout, connect).await
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
                            if live_error.is_some() {
                                // Live preview was already disabled (for example by
                                // pending-buffer overflow); drop the late publisher
                                // instead of retaining an unused connection.
                                pending_live_records.clear();
                            } else if let Err(err) = live_broker_deadline(
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

#[derive(Default)]
struct PendingLiveRecords {
    records: VecDeque<PendingComposeRecord>,
    bytes: usize,
}

impl PendingLiveRecords {
    fn clear(&mut self) {
        self.records.clear();
        self.bytes = 0;
    }

    fn push_bounded(&mut self, record_type: u8, text: String) -> Result<(), String> {
        let record_bytes = text.len();
        // Pending records are only a provisional live preview while the broker
        // connects. Once either cap is exceeded, discard them and disable live
        // preview for the rest of the session; the local transcript still
        // preserves the full final report.
        if self.records.len() >= MAX_PENDING_LIVE_RECORDS {
            self.clear();
            return Err(format!(
                "pending live stream buffer exceeded {MAX_PENDING_LIVE_RECORDS} records before broker connect completed"
            ));
        }
        if self.bytes.saturating_add(record_bytes) > MAX_PENDING_LIVE_RECORD_BYTES {
            self.clear();
            return Err(format!(
                "pending live stream buffer exceeded {MAX_PENDING_LIVE_RECORD_BYTES} bytes before broker connect completed"
            ));
        }

        self.bytes += record_bytes;
        self.records
            .push_back(PendingComposeRecord { record_type, text });
        Ok(())
    }

    fn pop_front(&mut self) -> Option<PendingComposeRecord> {
        let record = self.records.pop_front()?;
        self.bytes = self.bytes.saturating_sub(record.text.len());
        Some(record)
    }
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

fn effective_stream_compose_chunk_bytes(
    requested_chunk_bytes: usize,
    policy_max_plaintext_frame_len: Option<u32>,
) -> usize {
    if requested_chunk_bytes == 0
        || requested_chunk_bytes > AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize
    {
        requested_chunk_bytes
    } else {
        requested_chunk_bytes.min(effective_plaintext_cap(policy_max_plaintext_frame_len))
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
    pending_live_records: &'a mut PendingLiveRecords,
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
        } else if let Err(err) = live.pending_live_records.push_bounded(record_type, text) {
            *live.live_error = Some(err);
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
    pending_live_records: &mut PendingLiveRecords,
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

async fn live_broker_connect_deadline<P, E>(
    live_connect_timeout: Duration,
    connect: impl Future<Output = Result<P, E>>,
) -> Result<P, String>
where
    E: ToString,
{
    if live_connect_timeout.is_zero() {
        return connect.await.map_err(|err| err.to_string());
    }
    tokio::time::timeout(live_connect_timeout, connect)
        .await
        .map_err(|_| format!("live broker connect timed out after {live_connect_timeout:?}"))?
        .map_err(|err| err.to_string())
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
mod tests;
