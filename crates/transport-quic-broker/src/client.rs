//! Broker client surface: publisher/subscriber request types, the streaming
//! [`BrokerTextPublisher`], and the one-shot publish/subscribe helpers.

use std::net::SocketAddr;
use std::time::Duration;

use cgka_traits::MessageId;
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN, AGENT_TEXT_STREAM_RECORD_ABORT,
    AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, AgentTextStreamRecordV1, AgentTextStreamTranscriptV1,
};
use quinn::Endpoint;
use tokio::time::{sleep, timeout};
use transport_quic_stream::{
    AgentTextStreamCrypto, AgentTextStreamReceiveAccumulator, AgentTextStreamReceiveLimitError,
    AgentTextStreamReceiveLimits, QUIC_PREVIEW_CONNECT_TIMEOUT, ReceivedTextChunk,
    ReceivedTextStream, SentTextStream, connect_with_timeout, decrypt_record,
    effective_plaintext_cap, encrypt_record, frame_len_cap, stream_record_text,
};

use crate::control::QuicBrokerControlEnvelopeV1;
use crate::error::QuicBrokerError;
use crate::frame::{read_record_frame, write_control_frame, write_record_frame};
use crate::protocol::{RECORD_QUIET_GAP_DEADLINE, SEND_STOP_WAIT};
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

/// Receiver lifecycle state retained across reconnects and ordered candidate
/// failover. Sequence, transcript, and limits continue from the same durable
/// kind-1200 start context.
pub struct BrokerTextReceiverState {
    high_water: u64,
    frames_read: u64,
    limits: AgentTextStreamReceiveLimits,
    chunks: Vec<ReceivedTextChunk>,
    text: String,
    transcript: AgentTextStreamTranscriptV1,
    limit_state: AgentTextStreamReceiveAccumulator,
}

impl BrokerTextReceiverState {
    pub fn new(
        stream_id: Vec<u8>,
        start_event_id: MessageId,
        limits: AgentTextStreamReceiveLimits,
    ) -> Self {
        Self {
            high_water: 0,
            frames_read: 0,
            limits,
            chunks: Vec::new(),
            text: String::new(),
            transcript: AgentTextStreamTranscriptV1::new(stream_id, start_event_id),
            limit_state: AgentTextStreamReceiveAccumulator::new(limits),
        }
    }

    pub fn high_water(&self) -> u64 {
        self.high_water
    }

    fn begin_record(&mut self, seq: u64) -> Result<bool, QuicBrokerError> {
        self.frames_read = self.frames_read.saturating_add(1);
        if self.frames_read > self.limits.max_records {
            return Err(QuicBrokerError::ReceiveLimit(
                AgentTextStreamReceiveLimitError::RecordLimitExceeded {
                    attempted: self.frames_read,
                    limit: self.limits.max_records,
                },
            ));
        }
        if seq <= self.high_water {
            return Ok(false);
        }
        if seq != self.high_water + 1 {
            return Err(QuicBrokerError::UnexpectedSequence {
                expected: self.high_water + 1,
                actual: seq,
            });
        }
        Ok(true)
    }

    fn accept_record(
        &mut self,
        record: AgentTextStreamRecordV1,
        expected_stream_id: &[u8],
    ) -> Result<ReceivedTextChunk, QuicBrokerError> {
        self.limit_state.observe(&record)?;
        if record.stream_id != expected_stream_id {
            return Err(QuicBrokerError::MixedStreamIds);
        }
        self.high_water = record.seq;
        let frame_text = stream_record_text(&record);
        if record.record_type == AGENT_TEXT_STREAM_RECORD_TEXT_DELTA {
            self.text.push_str(&frame_text);
        }
        self.transcript
            .append(record.seq, record.record_type, &record.plaintext_frame);
        let chunk = ReceivedTextChunk {
            seq: record.seq,
            record_type: record.record_type,
            flags: record.flags,
            text: frame_text,
        };
        self.chunks.push(chunk.clone());
        Ok(chunk)
    }
}

impl BrokerTextPublisher {
    pub async fn connect(config: OpenBrokerTextPublisher) -> Result<Self, QuicBrokerError> {
        let endpoint = client_endpoint(config.trust, config.broker_addr)?;
        let connection = connect_with_timeout(
            &endpoint,
            config.broker_addr,
            &config.server_name,
            QUIC_PREVIEW_CONNECT_TIMEOUT,
        )
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

        let frames = transport_quic_stream::split_text_deltas(text, max_chunk_bytes)
            .into_iter()
            .map(|chunk| (record_type, chunk))
            .collect::<Vec<_>>();
        let reservation = self
            .crypto
            .as_ref()
            .filter(|_| !frames.is_empty())
            .map(|crypto| {
                transport_quic_stream::reserve_publisher_records_for_transport(
                    crypto,
                    self.transcript.stream_id(),
                    self.transcript.start_event_id(),
                    &frames,
                )
            })
            .transpose()?;
        let records = if let Some(reservation) = &reservation {
            reservation.records.clone()
        } else {
            frames
                .into_iter()
                .map(|(record_type, chunk)| {
                    let record = AgentTextStreamRecordV1::new(
                        self.transcript.stream_id().to_vec(),
                        self.next_seq,
                        record_type,
                        chunk,
                    );
                    self.next_seq += 1;
                    record
                })
                .collect()
        };

        let mut appended = 0_u64;
        for record in records {
            record.validate()?;
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
        if let Some(reservation) = reservation {
            let hash = reservation.transcript_hash;
            let count = reservation.chunk_count;
            reservation.confirm()?;
            self.transcript = AgentTextStreamTranscriptV1::from_state(
                self.transcript.stream_id().to_vec(),
                self.transcript.start_event_id().clone(),
                hash,
                count,
            );
            self.next_seq = count.saturating_add(1);
        }
        Ok(appended)
    }

    /// Emit a single zero-length `Abort` (`0x05`) record so live subscribers
    /// observe the terminal cancellation of a preview and remove or mark it as
    /// cancelled. `Abort` carries no durable text; it consumes one `seq` and
    /// contributes to the transcript like any other record.
    pub async fn append_abort(&mut self) -> Result<(), QuicBrokerError> {
        let frames = vec![(AGENT_TEXT_STREAM_RECORD_ABORT, Vec::new())];
        let reservation = self
            .crypto
            .as_ref()
            .map(|crypto| {
                transport_quic_stream::reserve_publisher_records_for_transport(
                    crypto,
                    self.transcript.stream_id(),
                    self.transcript.start_event_id(),
                    &frames,
                )
            })
            .transpose()?;
        let record = match &reservation {
            Some(reservation) => reservation.records.first().cloned().ok_or_else(|| {
                transport_quic_stream::QuicTextStreamError::PublisherSequence(
                    "publisher reservation returned no records".to_owned(),
                )
            })?,
            None => AgentTextStreamRecordV1::new(
                self.transcript.stream_id().to_vec(),
                self.next_seq,
                AGENT_TEXT_STREAM_RECORD_ABORT,
                Vec::new(),
            ),
        };
        record.validate()?;
        if reservation.is_none() {
            self.next_seq += 1;
        }
        let wire_record = if let Some(crypto) = &self.crypto {
            encrypt_record(crypto, &record)?
        } else {
            record.clone()
        };
        write_record_frame(&mut self.send, &wire_record).await?;
        self.transcript
            .append(record.seq, record.record_type, &record.plaintext_frame);
        if let Some(reservation) = reservation {
            let hash = reservation.transcript_hash;
            let count = reservation.chunk_count;
            reservation.confirm()?;
            self.transcript = AgentTextStreamTranscriptV1::from_state(
                self.transcript.stream_id().to_vec(),
                self.transcript.start_event_id().clone(),
                hash,
                count,
            );
            self.next_seq = count.saturating_add(1);
        }
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
    on_chunk: F,
) -> Result<ReceivedTextStream, QuicBrokerError>
where
    F: FnMut(&ReceivedTextChunk),
{
    let mut state = BrokerTextReceiverState::new(
        config.stream_id.clone(),
        config.start_event_id.clone(),
        limits,
    );
    subscribe_text_from_broker_with_resume(config, &mut state, on_chunk).await
}

pub async fn subscribe_text_from_broker_with_resume<F>(
    config: SubscribeTextFromBroker,
    state: &mut BrokerTextReceiverState,
    mut on_chunk: F,
) -> Result<ReceivedTextStream, QuicBrokerError>
where
    F: FnMut(&ReceivedTextChunk),
{
    let endpoint = client_endpoint(config.trust, config.broker_addr)?;
    let connection = connect_with_timeout(
        &endpoint,
        config.broker_addr,
        &config.server_name,
        QUIC_PREVIEW_CONNECT_TIMEOUT,
    )
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
    let max_frame_len = frame_len_cap(Some(state.limits.max_plaintext_frame_len));
    // The broker is untrusted and can replay `seq <= high_water` frames
    // forever. Those discards never reach `limit_state.observe`, so count every
    // frame read off the wire here and trip `max_records` before the dedup
    // `continue` can silently bypass it. A read deadline (instead of `None`)
    // breaks a starved read so a malicious broker cannot wedge the loop.
    while let Some(record) =
        read_record_frame(&mut recv, Some(RECORD_QUIET_GAP_DEADLINE), max_frame_len).await?
    {
        if !state.begin_record(record.seq)? {
            continue;
        }
        let record = if let Some(crypto) = &config.crypto {
            decrypt_record(crypto, &record)?
        } else {
            record
        };
        let chunk = state.accept_record(record, &config.stream_id)?;
        on_chunk(&chunk);
    }

    connection.close(0_u32.into(), b"done");
    if state.chunks.is_empty() {
        return Err(QuicBrokerError::EmptyStream);
    }
    Ok(ReceivedTextStream {
        stream_id: state.transcript.stream_id().to_vec(),
        chunks: state.chunks.clone(),
        text: state.text.clone(),
        transcript_hash: state.transcript.hash(),
        chunk_count: state.transcript.chunk_count(),
    })
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use cgka_traits::agent_text_stream::AgentTextStreamRecordV1;

    #[test]
    fn receiver_state_continues_high_water_and_transcript_across_reconnects() {
        let stream_id = vec![0x31; 32];
        let start = MessageId::new(vec![0x41; 32]);
        let limits = AgentTextStreamReceiveLimits::default();
        let mut state = BrokerTextReceiverState::new(stream_id.clone(), start.clone(), limits);

        let first = AgentTextStreamRecordV1::text_delta(stream_id.clone(), 1, b"one".to_vec());
        assert!(state.begin_record(first.seq).unwrap());
        state.accept_record(first, &stream_id).unwrap();

        let replay = AgentTextStreamRecordV1::text_delta(stream_id.clone(), 1, b"one".to_vec());
        assert!(
            !state.begin_record(replay.seq).unwrap(),
            "a reconnect replay at the high-water mark is harmless"
        );
        let second = AgentTextStreamRecordV1::text_delta(stream_id.clone(), 2, b"two".to_vec());
        assert!(state.begin_record(second.seq).unwrap());
        state.accept_record(second, &stream_id).unwrap();

        let mut expected = AgentTextStreamTranscriptV1::new(stream_id, start);
        expected.append(1, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"one");
        expected.append(2, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, b"two");
        assert_eq!(state.high_water(), 2);
        assert_eq!(state.text, "onetwo");
        assert_eq!(state.transcript.hash(), expected.hash());
        assert_eq!(state.transcript.chunk_count(), 2);
    }
}
