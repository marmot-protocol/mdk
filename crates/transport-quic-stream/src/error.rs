//! The crate's single error type spanning QUIC, TLS, record, and crypto faults.

use std::net::SocketAddr;
use std::str;

use cgka_traits::agent_text_stream::AgentTextStreamRecordError;

use crate::limits::AgentTextStreamReceiveLimitError;

#[derive(Debug, thiserror::Error)]
pub enum QuicTextStreamError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
    #[error(transparent)]
    QuinnConfig(#[from] quinn::ConfigError),
    #[error(transparent)]
    Connect(#[from] quinn::ConnectError),
    #[error(transparent)]
    Connection(#[from] quinn::ConnectionError),
    #[error(transparent)]
    Write(#[from] quinn::WriteError),
    #[error(transparent)]
    Read(#[from] quinn::ReadError),
    #[error(transparent)]
    ReadExact(#[from] quinn::ReadExactError),
    #[error(transparent)]
    ClosedStream(#[from] quinn::ClosedStream),
    #[error(transparent)]
    Stopped(#[from] quinn::StoppedError),
    #[error(transparent)]
    Record(#[from] AgentTextStreamRecordError),
    #[error(transparent)]
    ReceiveLimit(#[from] AgentTextStreamReceiveLimitError),
    #[error(transparent)]
    Utf8(#[from] str::Utf8Error),
    #[error("certificate setup failed: {0}")]
    Certificate(String),
    #[error("QUIC client config failed: {0}")]
    ClientConfig(String),
    #[error("--insecure-local is only allowed for loopback QUIC endpoints, got {0}")]
    InsecureLocalRequiresLoopback(SocketAddr),
    #[error("QUIC endpoint closed before accepting a stream")]
    EndpointClosed,
    #[error("agent text stream did not contain any records")]
    EmptyStream,
    #[error("agent text stream frame length was truncated")]
    TruncatedFrameLength,
    #[error("agent text stream frame cannot be empty")]
    EmptyFrame,
    #[error("agent text stream frame is too large: {0}")]
    FrameTooLarge(usize),
    #[error("agent text stream frame read timed out")]
    ReadTimeout,
    #[error("agent text stream chunk size cannot be zero")]
    EmptyChunkSize,
    #[error("agent text stream chunk size exceeds app profile max: {0}")]
    ChunkSizeTooLarge(usize),
    #[error("agent text stream encrypted frame would exceed app profile max: plaintext {0}")]
    EncryptedFrameTooLarge(usize),
    #[error("agent text stream mixed stream ids in one QUIC stream")]
    MixedStreamIds,
    /// A record arrived ahead of the high-water mark (`actual > expected`),
    /// signalling a gap the receiver cannot fill without a replay source.
    /// Records at or below the high-water mark are discarded silently and
    /// never raise this error.
    #[error("agent text stream sequence gap: expected {expected}, got {actual}")]
    UnexpectedSequence { expected: u64, actual: u64 },
    #[error("agent text stream crypto failed: {0}")]
    Crypto(String),
}
