//! Direct-path QUIC protocol/ALPN identifiers, frame-size constants, and the
//! plaintext/frame-length cap helpers shared across the transport.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_AEAD_TAG_LEN, AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN,
};

pub(crate) const FRAME_LEN_BYTES: usize = 4;
pub(crate) const LOCAL_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

/// Direct-path QUIC ALPN, pinned by spec/transports/quic.md. Both peers MUST
/// negotiate exactly this protocol; it is the direct-path counterpart to the
/// broker path's `marmot.quic_broker.v1` and the direct path's versioning hook.
pub const QUIC_STREAM_PROTOCOL_V1: &str = "marmot.quic_stream.v1";
/// `QUIC_STREAM_PROTOCOL_V1` as ALPN bytes.
pub const QUIC_STREAM_ALPN_V1: &[u8] = QUIC_STREAM_PROTOCOL_V1.as_bytes();
/// Spec-pinned reader allowance on top of the plaintext frame policy cap: a
/// reader rejects a frame whose `frame_len` exceeds the group's
/// `max_plaintext_frame_len` policy value plus exactly 1024 bytes of header
/// and AEAD-tag allowance.
pub const AGENT_TEXT_STREAM_FRAME_ALLOWANCE: usize = 1024;
pub(crate) const MAX_FRAME_SIZE: usize =
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize + AGENT_TEXT_STREAM_FRAME_ALLOWANCE;
/// Direct QUIC idle backstop. This intentionally pins Quinn's current 30s
/// default so future dependency default drift does not change the direct path's
/// liveness semantics. The post-setup record quiet-gap deadline is 120s, but
/// QUIC liveness should still reap a fully silent dead peer explicitly.
pub(crate) const DEFAULT_QUIC_STREAM_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Keep-alive cadence for otherwise idle direct QUIC preview connections. This
/// opt-in knob is the behavior delta over Quinn's disabled-by-default keepalive
/// and must stay below the idle timeout to preserve live idle connections.
pub(crate) const DEFAULT_QUIC_STREAM_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
pub(crate) const SEND_CLOSE_WAIT: Duration = Duration::from_secs(5);
pub(crate) const AEAD_TAG_LEN: usize = AGENT_TEXT_STREAM_AEAD_TAG_LEN;
pub(crate) const AGENT_TEXT_STREAM_SECRET_LEN: usize = 32;

/// Effective plaintext cap for a stream given an optional group policy value:
/// the policy bound when present, with the app-profile constant as the
/// ceiling and fallback.
pub fn effective_plaintext_cap(policy_max_plaintext_frame_len: Option<u32>) -> usize {
    policy_max_plaintext_frame_len
        .filter(|len| *len > 0)
        .map_or(AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN, |len| {
            len.min(AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN)
        }) as usize
}

/// Maximum accepted wire `frame_len` for a stream: the effective plaintext cap
/// plus the spec-pinned 1024-byte header/AEAD-tag allowance.
pub fn frame_len_cap(policy_max_plaintext_frame_len: Option<u32>) -> usize {
    effective_plaintext_cap(policy_max_plaintext_frame_len) + AGENT_TEXT_STREAM_FRAME_ALLOWANCE
}
