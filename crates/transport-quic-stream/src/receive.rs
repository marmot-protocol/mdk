//! The single-stream QUIC receiver: accept one uni stream, enforce sequencing
//! and limits, decode/decrypt records, and assemble the received transcript.

use std::net::SocketAddr;
use std::str;

use cgka_traits::MessageId;
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_RECORD_CHECKPOINT, AGENT_TEXT_STREAM_RECORD_PROGRESS_DELTA,
    AGENT_TEXT_STREAM_RECORD_STATUS, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, AgentTextStreamRecordV1,
    AgentTextStreamTranscriptV1,
};
use quinn::Endpoint;

use crate::crypto::{AgentTextStreamCrypto, decrypt_record};
use crate::error::QuicTextStreamError;
use crate::frame::{read_deadline, read_record};
use crate::limits::{AgentTextStreamReceiveAccumulator, AgentTextStreamReceiveLimits};
use crate::protocol::frame_len_cap;
use crate::tls::configure_server;

pub struct QuicTextStreamReceiver {
    endpoint: Endpoint,
    server_cert_der: Vec<u8>,
}

impl QuicTextStreamReceiver {
    pub fn bind(bind_addr: SocketAddr) -> Result<Self, QuicTextStreamError> {
        let (server_config, server_cert_der) = configure_server()?;
        let endpoint = Endpoint::server(server_config, bind_addr)?;
        Ok(Self {
            endpoint,
            server_cert_der,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, QuicTextStreamError> {
        Ok(self.endpoint.local_addr()?)
    }

    pub fn server_cert_der(&self) -> &[u8] {
        &self.server_cert_der
    }

    pub async fn receive_once(
        self,
        start_event_id: MessageId,
        crypto: Option<AgentTextStreamCrypto>,
    ) -> Result<ReceivedTextStream, QuicTextStreamError> {
        self.receive_once_with_limits(
            start_event_id,
            crypto,
            AgentTextStreamReceiveLimits::default(),
        )
        .await
    }

    pub async fn receive_once_with_limits(
        self,
        start_event_id: MessageId,
        crypto: Option<AgentTextStreamCrypto>,
        limits: AgentTextStreamReceiveLimits,
    ) -> Result<ReceivedTextStream, QuicTextStreamError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(QuicTextStreamError::EndpointClosed)?;
        let connection = incoming.await?;
        let mut recv = read_deadline(limits.read_timeout, connection.accept_uni()).await?;
        let mut stream_id = None;
        // Last-accepted seq high-water mark per the QUIC transport binding:
        // records at or below it (duplicates, transport-level replay) are
        // discarded silently and are never stream-fatal; the next accepted
        // record is high_water + 1; a record further ahead is a gap.
        let mut high_water = 0_u64;
        let mut chunks = Vec::new();
        let mut text = String::new();
        let mut transcript = None;
        let mut limit_state = AgentTextStreamReceiveAccumulator::new(limits);
        let max_frame_len = frame_len_cap(Some(limits.max_plaintext_frame_len));

        while let Some(record) = read_record(&mut recv, max_frame_len, limits.read_timeout).await? {
            limit_state.observe_wire_record()?;
            if record.seq <= high_water {
                continue;
            }
            if record.seq != high_water + 1 {
                return Err(QuicTextStreamError::UnexpectedSequence {
                    expected: high_water + 1,
                    actual: record.seq,
                });
            }
            let record = if let Some(crypto) = &crypto {
                decrypt_record(crypto, &record)?
            } else {
                record
            };
            limit_state.observe(&record)?;
            high_water = record.seq;

            if let Some(existing) = &stream_id {
                if existing != &record.stream_id {
                    return Err(QuicTextStreamError::MixedStreamIds);
                }
            } else {
                transcript = Some(AgentTextStreamTranscriptV1::new(
                    record.stream_id.clone(),
                    start_event_id.clone(),
                ));
                stream_id = Some(record.stream_id.clone());
            }

            let frame_text = stream_record_text(&record)?;
            if record.record_type == AGENT_TEXT_STREAM_RECORD_TEXT_DELTA {
                text.push_str(&frame_text);
            }

            let transcript = transcript
                .as_mut()
                .expect("transcript is initialized with first record");
            transcript.append(record.seq, record.record_type, &record.plaintext_frame);
            chunks.push(ReceivedTextChunk {
                seq: record.seq,
                record_type: record.record_type,
                flags: record.flags,
                text: frame_text,
            });
        }

        connection.close(0_u32.into(), b"done");

        let Some(transcript) = transcript else {
            return Err(QuicTextStreamError::EmptyStream);
        };

        Ok(ReceivedTextStream {
            stream_id: stream_id.expect("stream id is initialized with first record"),
            chunks,
            text,
            transcript_hash: transcript.hash(),
            chunk_count: transcript.chunk_count(),
        })
    }
}

/// Decode the per-record text a consumer can surface for a single stream record.
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
) -> Result<String, QuicTextStreamError> {
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

#[derive(Clone, Debug)]
pub enum ServerTrust {
    Platform,
    CertificateDer(Vec<u8>),
    InsecureLocal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedTextStream {
    pub stream_id: Vec<u8>,
    pub chunks: Vec<ReceivedTextChunk>,
    pub text: String,
    pub transcript_hash: [u8; 32],
    pub chunk_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedTextChunk {
    pub seq: u64,
    pub record_type: u8,
    pub flags: u8,
    pub text: String,
}
