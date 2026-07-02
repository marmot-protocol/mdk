//! Broker client surface: publisher/subscriber request types, the streaming
//! [`BrokerTextPublisher`], and the one-shot publish/subscribe helpers.

use std::net::SocketAddr;
use std::str;
use std::time::Duration;

use cgka_traits::MessageId;
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN, AGENT_TEXT_STREAM_RECORD_ABORT,
    AGENT_TEXT_STREAM_RECORD_CHECKPOINT, AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA,
    AGENT_TEXT_STREAM_RECORD_STATUS, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, AgentTextStreamRecordV1,
    AgentTextStreamTranscriptV1,
};
use quinn::Endpoint;
use tokio::time::{sleep, timeout};
use transport_quic_stream::{
    AgentTextStreamCrypto, AgentTextStreamReceiveAccumulator, AgentTextStreamReceiveLimitError,
    AgentTextStreamReceiveLimits, ReceivedTextChunk, ReceivedTextStream, SentTextStream,
    decrypt_record, effective_plaintext_cap, encrypt_record, frame_len_cap,
};

use crate::control::QuicBrokerControlEnvelopeV1;
use crate::error::QuicBrokerError;
use crate::frame::{read_record_frame, write_control_frame, write_record_frame};
use crate::protocol::{SEND_STOP_WAIT, SUBSCRIBER_RECORD_READ_DEADLINE};
use crate::tls::client_endpoint;

#[derive(Clone, Debug)]
pub enum BrokerServerTrust {
    Platform,
    CertificateDer(Vec<u8>),
    InsecureLocal,
}

#[derive(Clone, Debug)]
pub struct PublishTextToBroker {
    pub broker_addr: SocketAddr,
    pub server_name: String,
    pub trust: BrokerServerTrust,
    pub stream_id: Vec<u8>,
    pub start_event_id: MessageId,
    pub text: String,
    pub max_chunk_bytes: usize,
    pub chunk_delay: Duration,
    pub crypto: Option<AgentTextStreamCrypto>,
    /// Group policy `max_plaintext_frame_len` when the caller has the decoded
    /// `AgentTextStreamQuicPolicyV1` available. Chunk size is clamped to it;
    /// the app-profile constant is the ceiling and the fallback when `None`.
    pub max_plaintext_frame_len: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct OpenBrokerTextPublisher {
    pub broker_addr: SocketAddr,
    pub server_name: String,
    pub trust: BrokerServerTrust,
    pub stream_id: Vec<u8>,
    pub start_event_id: MessageId,
    pub crypto: Option<AgentTextStreamCrypto>,
    /// Group policy `max_plaintext_frame_len` when the caller has the decoded
    /// `AgentTextStreamQuicPolicyV1` available. Chunk size is clamped to it;
    /// the app-profile constant is the ceiling and the fallback when `None`.
    pub max_plaintext_frame_len: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct SubscribeTextFromBroker {
    pub broker_addr: SocketAddr,
    pub server_name: String,
    pub trust: BrokerServerTrust,
    pub stream_id: Vec<u8>,
    pub start_event_id: MessageId,
    pub crypto: Option<AgentTextStreamCrypto>,
}

pub struct BrokerTextPublisher {
    endpoint: Endpoint,
    connection: quinn::Connection,
    send: quinn::SendStream,
    transcript: AgentTextStreamTranscriptV1,
    next_seq: u64,
    crypto: Option<AgentTextStreamCrypto>,
    max_plaintext_frame_len: Option<u32>,
}

impl BrokerTextPublisher {
    pub async fn connect(config: OpenBrokerTextPublisher) -> Result<Self, QuicBrokerError> {
        let endpoint = client_endpoint(config.trust, config.broker_addr)?;
        let connection = endpoint
            .connect(config.broker_addr, &config.server_name)?
            .await?;
        let mut send = connection.open_uni().await?;
        write_control_frame(
            &mut send,
            &QuicBrokerControlEnvelopeV1::publish(config.stream_id.clone(), &config.start_event_id),
        )
        .await?;

        Ok(Self {
            endpoint,
            connection,
            send,
            transcript: AgentTextStreamTranscriptV1::new(config.stream_id, config.start_event_id),
            next_seq: 1,
            crypto: config.crypto,
            max_plaintext_frame_len: config.max_plaintext_frame_len,
        })
    }

    pub async fn append_text(
        &mut self,
        text: &str,
        max_chunk_bytes: usize,
        chunk_delay: Duration,
    ) -> Result<u64, QuicBrokerError> {
        self.append_record_text(
            AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
            text,
            max_chunk_bytes,
            chunk_delay,
        )
        .await
    }

    pub async fn append_record_text(
        &mut self,
        record_type: u8,
        text: &str,
        max_chunk_bytes: usize,
        chunk_delay: Duration,
    ) -> Result<u64, QuicBrokerError> {
        if max_chunk_bytes == 0 {
            return Err(QuicBrokerError::EmptyChunkSize);
        }
        if max_chunk_bytes > AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize {
            return Err(QuicBrokerError::ChunkSizeTooLarge(max_chunk_bytes));
        }
        // Clamp the chunk size to the group policy cap when the publisher was
        // opened with one; the app-profile constant remains the ceiling.
        let max_chunk_bytes =
            max_chunk_bytes.min(effective_plaintext_cap(self.max_plaintext_frame_len));

        let mut appended = 0_u64;
        for chunk in transport_quic_stream::split_text_deltas(text, max_chunk_bytes) {
            let record = AgentTextStreamRecordV1::new(
                self.transcript.stream_id().to_vec(),
                self.next_seq,
                record_type,
                chunk,
            );
            record.validate()?;
            self.next_seq += 1;
            let wire_record = if let Some(crypto) = &self.crypto {
                encrypt_record(crypto, &record)?
            } else {
                record.clone()
            };
            write_record_frame(&mut self.send, &wire_record).await?;
            self.transcript
                .append(record.seq, record.record_type, &record.plaintext_frame);
            appended += 1;
            if !chunk_delay.is_zero() {
                sleep(chunk_delay).await;
            }
        }
        Ok(appended)
    }

    /// Emit a single zero-length `Abort` (`0x05`) record so live subscribers
    /// observe the terminal cancellation of a preview and remove or mark it as
    /// cancelled. `Abort` carries no durable text; it consumes one `seq` and
    /// contributes to the transcript like any other record.
    pub async fn append_abort(&mut self) -> Result<(), QuicBrokerError> {
        let record = AgentTextStreamRecordV1::new(
            self.transcript.stream_id().to_vec(),
            self.next_seq,
            AGENT_TEXT_STREAM_RECORD_ABORT,
            Vec::new(),
        );
        record.validate()?;
        self.next_seq += 1;
        let wire_record = if let Some(crypto) = &self.crypto {
            encrypt_record(crypto, &record)?
        } else {
            record.clone()
        };
        write_record_frame(&mut self.send, &wire_record).await?;
        self.transcript
            .append(record.seq, record.record_type, &record.plaintext_frame);
        Ok(())
    }

    pub async fn finish(mut self) -> Result<SentTextStream, QuicBrokerError> {
        self.send.finish()?;
        let stopped = timeout(SEND_STOP_WAIT, self.send.stopped()).await;
        self.connection.close(0_u32.into(), b"done");
        self.endpoint.wait_idle().await;
        match stopped {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => {}
        }
        Ok(SentTextStream {
            stream_id: self.transcript.stream_id().to_vec(),
            transcript_hash: self.transcript.hash(),
            chunk_count: self.transcript.chunk_count(),
        })
    }
}

pub async fn publish_text_to_broker(
    config: PublishTextToBroker,
) -> Result<SentTextStream, QuicBrokerError> {
    let mut publisher = BrokerTextPublisher::connect(OpenBrokerTextPublisher {
        broker_addr: config.broker_addr,
        server_name: config.server_name,
        trust: config.trust,
        stream_id: config.stream_id,
        start_event_id: config.start_event_id,
        crypto: config.crypto,
        max_plaintext_frame_len: config.max_plaintext_frame_len,
    })
    .await?;
    publisher
        .append_text(&config.text, config.max_chunk_bytes, config.chunk_delay)
        .await?;
    publisher.finish().await
}

pub async fn subscribe_text_from_broker(
    config: SubscribeTextFromBroker,
) -> Result<ReceivedTextStream, QuicBrokerError> {
    subscribe_text_from_broker_with_updates(config, |_| {}).await
}

pub async fn subscribe_text_from_broker_with_updates<F>(
    config: SubscribeTextFromBroker,
    mut on_chunk: F,
) -> Result<ReceivedTextStream, QuicBrokerError>
where
    F: FnMut(&ReceivedTextChunk),
{
    subscribe_text_from_broker_with_limits(
        config,
        AgentTextStreamReceiveLimits::default(),
        &mut on_chunk,
    )
    .await
}

pub async fn subscribe_text_from_broker_with_limits<F>(
    config: SubscribeTextFromBroker,
    limits: AgentTextStreamReceiveLimits,
    mut on_chunk: F,
) -> Result<ReceivedTextStream, QuicBrokerError>
where
    F: FnMut(&ReceivedTextChunk),
{
    let endpoint = client_endpoint(config.trust, config.broker_addr)?;
    let connection = endpoint
        .connect(config.broker_addr, &config.server_name)?
        .await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    write_control_frame(
        &mut send,
        &QuicBrokerControlEnvelopeV1::subscribe(config.stream_id.clone(), &config.start_event_id),
    )
    .await?;
    send.finish()?;

    // Last-accepted seq high-water mark per the QUIC transport binding:
    // records at or below it (duplicates, broker backlog replayed on
    // reconnect) are discarded silently and are never stream-fatal; the next
    // accepted record is high_water + 1; a record further ahead is a gap.
    let mut high_water = 0_u64;
    let mut chunks = Vec::new();
    let mut text = String::new();
    let mut transcript =
        AgentTextStreamTranscriptV1::new(config.stream_id.clone(), config.start_event_id);
    let mut limit_state = AgentTextStreamReceiveAccumulator::new(limits);
    let max_frame_len = frame_len_cap(Some(limits.max_plaintext_frame_len));
    // The broker is untrusted and can replay `seq <= high_water` frames
    // forever. Those discards never reach `limit_state.observe`, so count every
    // frame read off the wire here and trip `max_records` before the dedup
    // `continue` can silently bypass it. A read deadline (instead of `None`)
    // breaks a starved read so a malicious broker cannot wedge the loop.
    let mut frames_read = 0_u64;

    while let Some(record) = read_record_frame(
        &mut recv,
        Some(SUBSCRIBER_RECORD_READ_DEADLINE),
        max_frame_len,
    )
    .await?
    {
        frames_read = frames_read.saturating_add(1);
        if frames_read > limits.max_records {
            return Err(QuicBrokerError::ReceiveLimit(
                AgentTextStreamReceiveLimitError::RecordLimitExceeded {
                    attempted: frames_read,
                    limit: limits.max_records,
                },
            ));
        }
        if record.seq <= high_water {
            continue;
        }
        if record.seq != high_water + 1 {
            return Err(QuicBrokerError::UnexpectedSequence {
                expected: high_water + 1,
                actual: record.seq,
            });
        }
        let record = if let Some(crypto) = &config.crypto {
            decrypt_record(crypto, &record)?
        } else {
            record
        };
        limit_state.observe(&record)?;
        if record.stream_id != config.stream_id {
            return Err(QuicBrokerError::MixedStreamIds);
        }
        high_water = record.seq;

        let frame_text = stream_record_text(&record)?;
        if record.record_type == AGENT_TEXT_STREAM_RECORD_TEXT_DELTA {
            text.push_str(&frame_text);
        }
        transcript.append(record.seq, record.record_type, &record.plaintext_frame);
        let chunk = ReceivedTextChunk {
            seq: record.seq,
            record_type: record.record_type,
            flags: record.flags,
            text: frame_text,
        };
        on_chunk(&chunk);
        chunks.push(chunk);
    }

    connection.close(0_u32.into(), b"done");
    if chunks.is_empty() {
        return Err(QuicBrokerError::EmptyStream);
    }
    Ok(ReceivedTextStream {
        stream_id: transcript.stream_id().to_vec(),
        chunks,
        text,
        transcript_hash: transcript.hash(),
        chunk_count: transcript.chunk_count(),
    })
}

/// Decode the per-record text a subscriber can surface for a single stream record.
///
/// `TextDelta`, `Status`, `ProgressDelta`, and `Checkpoint` carry UTF-8 the
/// consumer renders: deltas build the provisional preview, status/progress feed
/// non-chat agent chrome, and a `Checkpoint` is a full preview snapshot the
/// consumer swaps in for its live preview. `Abort` and `FinalNotice` are
/// advisory (the consumer acts on the record type, not its bytes), as is any
/// unknown future type, so they decode to an empty string. Note this only
/// decodes one record's frame; accumulation into the provisional answer text is
/// the caller's job and stays `TextDelta`-only.
pub(crate) fn stream_record_text(
    record: &AgentTextStreamRecordV1,
) -> Result<String, QuicBrokerError> {
    match record.record_type {
        AGENT_TEXT_STREAM_RECORD_TEXT_DELTA
        | AGENT_TEXT_STREAM_RECORD_STATUS
        | AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA
        | AGENT_TEXT_STREAM_RECORD_CHECKPOINT => {
            Ok(str::from_utf8(&record.plaintext_frame)?.to_owned())
        }
        _ => Ok(String::new()),
    }
}
