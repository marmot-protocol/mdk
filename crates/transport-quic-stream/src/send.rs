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
use crate::protocol::{SEND_CLOSE_WAIT, effective_plaintext_cap};
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
    if config.max_chunk_bytes == 0 {
        return Err(QuicTextStreamError::EmptyChunkSize);
    }
    if config.max_chunk_bytes > AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize {
        return Err(QuicTextStreamError::ChunkSizeTooLarge(
            config.max_chunk_bytes,
        ));
    }
    // Clamp the chunk size to the group policy cap when the caller supplied
    // one. A plaintext within the cap always encrypts to a ciphertext within
    // the record's `ciphertext<0..2^16-1>` field bound (cap + 16 <= 65535).
    let max_chunk_bytes = config
        .max_chunk_bytes
        .min(effective_plaintext_cap(config.max_plaintext_frame_len));

    let endpoint = client_endpoint(config.trust, config.server_addr)?;
    let connection = endpoint
        .connect(config.server_addr, &config.server_name)?
        .await?;
    let mut send = connection.open_uni().await?;
    let mut transcript =
        AgentTextStreamTranscriptV1::new(config.stream_id.clone(), config.start_event_id);

    for (index, chunk) in split_text_deltas(&config.text, max_chunk_bytes)
        .into_iter()
        .enumerate()
    {
        let record =
            AgentTextStreamRecordV1::text_delta(config.stream_id.clone(), index as u64 + 1, chunk);
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

    send.finish()?;
    if timeout(SEND_CLOSE_WAIT, connection.closed()).await.is_err() {
        connection.close(0_u32.into(), b"done");
    }
    endpoint.wait_idle().await;
    Ok(SentTextStream {
        stream_id: transcript.stream_id().to_vec(),
        transcript_hash: transcript.hash(),
        chunk_count: transcript.chunk_count(),
    })
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
