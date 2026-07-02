//! Raw QUIC transport binding for transient Marmot agent text stream previews.
//!
//! This crate owns the direct-path QUIC endpoint setup and the reliable,
//! length-prefixed stream framing used to carry agent text stream preview
//! records. Shared record semantics, transcript hashing, and protocol
//! constants live in `cgka-traits`; live chunks are provisional preview data
//! and the final MLS app payload remains authoritative.

mod crypto;
mod error;
mod frame;
mod limits;
mod protocol;
mod receive;
mod send;
mod tls;

#[cfg(test)]
mod tests;

pub use crypto::{
    AgentTextStreamCrypto, decrypt_record, derive_record_key, derive_record_nonce, encrypt_record,
    record_aad,
};
pub use error::QuicTextStreamError;
pub use limits::{
    AgentTextStreamReceiveAccumulator, AgentTextStreamReceiveLimitError,
    AgentTextStreamReceiveLimits,
};
pub use protocol::{
    AGENT_TEXT_STREAM_FRAME_ALLOWANCE, QUIC_STREAM_ALPN_V1, QUIC_STREAM_PROTOCOL_V1,
    effective_plaintext_cap, frame_len_cap,
};
pub use receive::{QuicTextStreamReceiver, ReceivedTextChunk, ReceivedTextStream, ServerTrust};
pub use send::{
    SendTextStream, SentTextStream, random_stream_id, send_text_stream, split_text_deltas,
};
