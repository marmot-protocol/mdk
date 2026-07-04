//! The shared QUIC preview hardening profile: transport config, dial deadline,
//! and the absolute frame cap consumed by both the direct path (this crate)
//! and the broker path (`transport-quic-broker`).
//!
//! Every preview endpoint role — direct server/client, broker server/client —
//! derives its `TransportConfig` from [`QuicPreviewTransportProfile`] and dials
//! through [`connect_with_timeout`], so liveness and bounds changes happen here
//! once instead of drifting per crate.
//!
//! Early-data policy: TLS 0-RTT stays disabled on every preview endpoint.
//! Neither path has an application-layer anti-replay mechanism, so replayable
//! 0-RTT flights would let a passive network attacker replay pre-auth control
//! and record frames (room creation / budget burn on the broker). rustls'
//! defaults (`max_early_data_size = 0`, `enable_early_data = false`) are the
//! policy; tests in both crates pin it.

use std::net::SocketAddr;
use std::time::Duration;

use quinn::{Connection, Endpoint, TransportConfig, VarInt};
use tokio::time::timeout;

use cgka_traits::agent_text_stream::AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN;

use crate::protocol::AGENT_TEXT_STREAM_FRAME_ALLOWANCE;

/// QUIC idle backstop shared by every preview endpoint. Intentionally pins
/// Quinn's current 30s default so dependency default drift cannot change
/// preview liveness semantics.
pub const QUIC_PREVIEW_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Keep-alive cadence for otherwise idle preview connections. This opt-in knob
/// is the behavior delta over Quinn's disabled-by-default keepalive and must
/// stay below the idle timeout so healthy but app-silent peers survive the
/// backstop.
pub const QUIC_PREVIEW_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// Application-level bound on a preview QUIC dial (connect plus TLS
/// handshake), so a blackholed or stalling peer cannot pin a sender task on an
/// unbounded handshake. Zero disables the deadline.
pub const QUIC_PREVIEW_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Absolute wire frame cap for preview records on both paths: the app-profile
/// plaintext ceiling plus the spec-pinned header/AEAD-tag allowance.
pub const QUIC_PREVIEW_MAX_FRAME_LEN: usize =
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize + AGENT_TEXT_STREAM_FRAME_ALLOWANCE;

/// One transport profile per preview endpoint role. Stream-concurrency caps
/// bound what the *peer* may open toward this endpoint; liveness knobs apply
/// to the connection as a whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuicPreviewTransportProfile {
    pub max_idle_timeout: Duration,
    pub keep_alive_interval: Duration,
    pub max_concurrent_uni_streams: u64,
    pub max_concurrent_bidi_streams: u64,
}

impl QuicPreviewTransportProfile {
    /// The direct-path receiver: the sender opens exactly one unidirectional
    /// record stream and nothing else.
    pub fn direct_server() -> Self {
        Self {
            max_idle_timeout: QUIC_PREVIEW_MAX_IDLE_TIMEOUT,
            keep_alive_interval: QUIC_PREVIEW_KEEP_ALIVE_INTERVAL,
            max_concurrent_uni_streams: 1,
            max_concurrent_bidi_streams: 0,
        }
    }

    /// Any preview client (direct sender, broker publisher, broker
    /// subscriber): no server on either path ever opens a stream toward a
    /// client, so peer-initiated stream budgets are zero.
    pub fn client() -> Self {
        Self {
            max_idle_timeout: QUIC_PREVIEW_MAX_IDLE_TIMEOUT,
            keep_alive_interval: QUIC_PREVIEW_KEEP_ALIVE_INTERVAL,
            max_concurrent_uni_streams: 0,
            max_concurrent_bidi_streams: 0,
        }
    }

    /// The broker server: operator-tunable liveness plus symmetric caps on
    /// client-opened publish (uni) and subscribe (bidi) streams.
    pub fn broker_server(
        max_streams_per_connection: u64,
        max_idle_timeout: Duration,
        keep_alive_interval: Duration,
    ) -> Self {
        Self {
            max_idle_timeout,
            keep_alive_interval,
            max_concurrent_uni_streams: max_streams_per_connection,
            max_concurrent_bidi_streams: max_streams_per_connection,
        }
    }

    pub fn transport_config(&self) -> Result<TransportConfig, quinn::VarIntBoundsExceeded> {
        let mut transport = TransportConfig::default();
        transport
            .max_concurrent_uni_streams(VarInt::try_from(self.max_concurrent_uni_streams)?)
            .max_concurrent_bidi_streams(VarInt::try_from(self.max_concurrent_bidi_streams)?)
            .max_idle_timeout(Some(self.max_idle_timeout.try_into()?))
            .keep_alive_interval(Some(self.keep_alive_interval));
        Ok(transport)
    }
}

/// A dial failure from [`connect_with_timeout`], mapped into each crate's
/// error enum at the call site.
#[derive(Debug, thiserror::Error)]
pub enum QuicConnectFault {
    #[error(transparent)]
    Connect(#[from] quinn::ConnectError),
    #[error(transparent)]
    Connection(#[from] quinn::ConnectionError),
    #[error("QUIC preview connect timed out")]
    Timeout,
}

/// Dial a preview endpoint with one deadline across the whole connect plus TLS
/// handshake. Zero disables the deadline.
pub async fn connect_with_timeout(
    endpoint: &Endpoint,
    server_addr: SocketAddr,
    server_name: &str,
    connect_timeout: Duration,
) -> Result<Connection, QuicConnectFault> {
    let connecting = endpoint.connect(server_addr, server_name)?;
    if connect_timeout.is_zero() {
        return Ok(connecting.await?);
    }
    match timeout(connect_timeout, connecting).await {
        Ok(connection) => Ok(connection?),
        Err(_) => Err(QuicConnectFault::Timeout),
    }
}
