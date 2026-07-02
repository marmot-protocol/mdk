//! Broker error type shared across the client, server, and broker-state paths.

use std::net::SocketAddr;
use std::str;

use cgka_traits::agent_text_stream::AgentTextStreamRecordError;
use transport_quic_stream::AgentTextStreamReceiveLimitError;

#[derive(Debug, thiserror::Error)]
pub enum QuicBrokerError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
    #[error(transparent)]
    QuinnConfig(#[from] quinn::ConfigError),
    #[error("broker QUIC transport value exceeds varint bounds")]
    TransportValueTooLarge(#[from] quinn::VarIntBoundsExceeded),
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
    Utf8(#[from] str::Utf8Error),
    #[error(transparent)]
    StreamCrypto(#[from] transport_quic_stream::QuicTextStreamError),
    #[error(transparent)]
    ReceiveLimit(#[from] AgentTextStreamReceiveLimitError),
    #[error("certificate setup failed: {0}")]
    Certificate(String),
    #[error("certificate PEM file did not contain any certificates")]
    EmptyCertificateChain,
    #[error("private key PEM file did not contain a usable private key")]
    MissingPrivateKey,
    #[error("QUIC client config failed: {0}")]
    ClientConfig(String),
    #[error("--insecure-local is only allowed for loopback QUIC broker endpoints, got {0}")]
    InsecureLocalRequiresLoopback(SocketAddr),
    #[error("broker subscriber queue depth cannot be zero")]
    EmptySubscriberQueue,
    #[error("broker backlog depth cannot be zero")]
    EmptyBacklog,
    #[error("broker room limit cannot be zero")]
    EmptyRoomLimit,
    #[error("broker backlog byte limit cannot be zero")]
    EmptyBacklogByteLimit,
    #[error("broker connection limit cannot be zero")]
    EmptyConnectionLimit,
    #[error("broker per-connection stream limit cannot be zero")]
    EmptyStreamLimit,
    #[error("broker read timeout cannot be zero")]
    EmptyReadTimeout,
    #[error("broker idle timeout cannot be zero")]
    EmptyIdleTimeout,
    #[error("broker keep-alive interval cannot be zero")]
    EmptyKeepAliveInterval,
    #[error(
        "broker replay ttl exceeds the application profile cap: {requested_secs}s > {cap_secs}s"
    )]
    ReplayTtlTooLarge { requested_secs: u64, cap_secs: u64 },
    #[error("broker room limit exceeded: {limit}")]
    RoomLimitExceeded { limit: usize },
    #[error("broker backlog record is larger than the byte budget: {record_bytes} > {limit}")]
    BacklogRecordTooLarge { record_bytes: usize, limit: usize },
    #[error("broker frame read timed out")]
    ReadTimeout,
    #[error("broker control frame is missing")]
    MissingControlFrame,
    #[error("wrong broker control protocol: {0}")]
    WrongControlProtocol(String),
    #[error("unknown broker control type: {0}")]
    UnknownControlType(u8),
    #[error("broker control envelope is truncated while reading {0}")]
    ControlTruncated(&'static str),
    #[error("broker control envelope carries trailing bytes: {0}")]
    ControlTrailingBytes(usize),
    #[error("publish streams must be unidirectional")]
    PublishRequiresUnidirectionalStream,
    #[error("subscribe streams must be bidirectional")]
    SubscribeRequiresBidirectionalStream,
    #[error("agent text stream id cannot be empty")]
    EmptyStreamId,
    #[error("agent text stream id is too long: {0}")]
    StreamIdTooLong(usize),
    #[error("agent text stream start event id cannot be empty")]
    EmptyStartEventId,
    #[error("agent text stream start event id is too long: {0}")]
    StartEventIdTooLong(usize),
    #[error("agent text stream did not contain any records")]
    EmptyStream,
    #[error("agent text stream frame length was truncated")]
    TruncatedFrameLength,
    #[error("agent text stream frame cannot be empty")]
    EmptyFrame,
    #[error("agent text stream frame is too large: {0}")]
    FrameTooLarge(usize),
    #[error("agent text stream chunk size cannot be zero")]
    EmptyChunkSize,
    #[error("agent text stream chunk size exceeds app profile max: {0}")]
    ChunkSizeTooLarge(usize),
    #[error("agent text stream mixed stream ids")]
    MixedStreamIds,
    /// A record arrived ahead of the high-water mark (`actual > expected`),
    /// signalling a gap the receiver cannot fill without a replay source.
    /// Records at or below the high-water mark are discarded silently and
    /// never raise this error.
    #[error("agent text stream sequence gap: expected {expected}, got {actual}")]
    UnexpectedSequence { expected: u64, actual: u64 },
}
