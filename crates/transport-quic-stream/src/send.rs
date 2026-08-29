//! The single-stream QUIC sender: chunk text into TextDelta records, seal and
//! frame them, plus the stream-id and UTF-8-safe chunk-splitting helpers.

use std::net::SocketAddr;
use std::time::Duration;

use cgka_traits::MessageId;
use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN, AgentTextStreamRecordV1, AgentTextStreamTranscriptV1,
};
use rand::{RngCore, rngs::OsRng};
use tokio::time::{sleep, timeout};

use crate::crypto::{AgentTextStreamCrypto, encrypt_record};
use crate::error::QuicTextStreamError;
use crate::frame::write_record;
use crate::hardening::{QUIC_PREVIEW_CONNECT_TIMEOUT, connect_with_timeout};
use crate::protocol::{SEND_CLOSE_WAIT, effective_plaintext_cap};
use crate::publisher_sequence::reserve_publisher_records;
use crate::receive::ServerTrust;
use crate::tls::client_endpoint;

#[derive(Clone, Debug)]
pub struct SendTextStream {
    pub server_addr: SocketAddr,
    pub server_name: String,
    pub trust: ServerTrust,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentTextStream {
    pub stream_id: Vec<u8>,
    pub transcript_hash: [u8; 32],
    pub chunk_count: u64,
}

pub async fn send_text_stream(
    config: SendTextStream,
) -> Result<SentTextStream, QuicTextStreamError> {
    let frames = text_delta_frames(
        &config.text,
        config.max_chunk_bytes,
        config.max_plaintext_frame_len,
    )?;

    let endpoint = client_endpoint(config.trust, config.server_addr)?;
    let connection = connect_with_timeout(
        &endpoint,
        config.server_addr,
        &config.server_name,
        QUIC_PREVIEW_CONNECT_TIMEOUT,
    )
    .await?;
    let mut send = connection.open_uni().await?;
    let mut transcript =
        AgentTextStreamTranscriptV1::new(config.stream_id.clone(), config.start_event_id.clone());
    let reservation = config
        .crypto
        .as_ref()
        .filter(|_| !frames.is_empty())
        .map(|crypto| {
            reserve_publisher_records(crypto, &config.stream_id, &config.start_event_id, &frames)
        })
        .transpose()?;
    let records = if let Some(reservation) = &reservation {
        reservation.records.clone()
    } else {
        frames
            .into_iter()
            .enumerate()
            .map(|(index, (record_type, plaintext))| {
                AgentTextStreamRecordV1::new(
                    config.stream_id.clone(),
                    index as u64 + 1,
                    record_type,
                    plaintext,
                )
            })
            .collect()
    };

    for record in records {
        let wire_record = if let Some(crypto) = &config.crypto {
            encrypt_record(crypto, &record)?
        } else {
            record.clone()
        };
        write_record(&mut send, &wire_record).await?;
        transcript.append(record.seq, record.record_type, &record.plaintext_frame);
        if !config.chunk_delay.is_zero() {
            sleep(config.chunk_delay).await;
        }
    }
    let (transcript_hash, chunk_count) = if let Some(reservation) = reservation {
        let transcript_hash = reservation.transcript_hash;
        let chunk_count = reservation.chunk_count;
        reservation.confirm()?;
        (transcript_hash, chunk_count)
    } else {
        (transcript.hash(), transcript.chunk_count())
    };

    send.finish()?;
    if timeout(SEND_CLOSE_WAIT, connection.closed()).await.is_err() {
        connection.close(0_u32.into(), b"done");
    }
    endpoint.wait_idle().await;
    Ok(SentTextStream {
        stream_id: transcript.stream_id().to_vec(),
        transcript_hash,
        chunk_count,
    })
}

/// Persist and confirm exactly one bounded text-record range, then replace the
/// crypto's SQL-backed sequence store with a one-shot in-memory capability for
/// that same range. This is for hosts that must terminally close storage before
/// network I/O to transfer exclusive root ownership.
///
/// A later network failure burns the confirmed range rather than risking nonce
/// reuse. The returned capability rejects any different frame set and cannot be
/// reused for another send.
pub fn prepare_text_stream_crypto_for_network_handoff(
    crypto: AgentTextStreamCrypto,
    stream_id: &[u8],
    start_event_id: &MessageId,
    text: &str,
    max_chunk_bytes: usize,
    max_plaintext_frame_len: Option<u32>,
) -> Result<AgentTextStreamCrypto, QuicTextStreamError> {
    let frames = text_delta_frames(text, max_chunk_bytes, max_plaintext_frame_len)?;
    if frames.is_empty() {
        return Ok(crypto);
    }
    let detached_store = reserve_publisher_records(&crypto, stream_id, start_event_id, &frames)?
        .confirm_and_detach_store()?;
    Ok(crypto.with_publisher_sequence_store(detached_store))
}

fn text_delta_frames(
    text: &str,
    max_chunk_bytes: usize,
    max_plaintext_frame_len: Option<u32>,
) -> Result<Vec<(u8, Vec<u8>)>, QuicTextStreamError> {
    if max_chunk_bytes == 0 {
        return Err(QuicTextStreamError::EmptyChunkSize);
    }
    if max_chunk_bytes > AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize {
        return Err(QuicTextStreamError::ChunkSizeTooLarge(max_chunk_bytes));
    }
    // Clamp the chunk size to the group policy cap when the caller supplied
    // one. A plaintext within the cap always encrypts to a ciphertext within
    // the record's `ciphertext<0..2^16-1>` field bound (cap + 16 <= 65535).
    let max_chunk_bytes = max_chunk_bytes.min(effective_plaintext_cap(max_plaintext_frame_len));
    Ok(split_text_deltas(text, max_chunk_bytes)
        .into_iter()
        .map(|chunk| {
            (
                cgka_traits::agent_text_stream::AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
                chunk,
            )
        })
        .collect())
}

pub fn random_stream_id() -> Vec<u8> {
    let mut stream_id = [0_u8; 32];
    OsRng.fill_bytes(&mut stream_id);
    stream_id.to_vec()
}

pub fn split_text_deltas(text: &str, max_chunk_bytes: usize) -> Vec<Vec<u8>> {
    if text.is_empty() {
        return Vec::new();
    }

    let mut chunks = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        let ch_len = ch.len_utf8();
        if !current.is_empty() && current.len() + ch_len > max_chunk_bytes {
            chunks.push(std::mem::take(&mut current).into_bytes());
        }
        if current.is_empty() && ch_len > max_chunk_bytes {
            chunks.push(ch.to_string().into_bytes());
            continue;
        }
        current.push(ch);
    }
    if !current.is_empty() {
        chunks.push(current.into_bytes());
    }
    chunks
}
