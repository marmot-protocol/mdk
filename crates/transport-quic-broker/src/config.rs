//! Broker server configuration and its TLS-source selection enum.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use crate::protocol::{
    DEFAULT_BROKER_BACKLOG_DEPTH, DEFAULT_BROKER_KEEP_ALIVE_INTERVAL,
    DEFAULT_BROKER_MAX_BACKLOG_BYTES, DEFAULT_BROKER_MAX_CONNECTIONS,
    DEFAULT_BROKER_MAX_IDLE_TIMEOUT, DEFAULT_BROKER_MAX_ROOMS,
    DEFAULT_BROKER_MAX_STREAMS_PER_CONNECTION, DEFAULT_BROKER_READ_TIMEOUT,
    DEFAULT_BROKER_REPLAY_TTL, DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
};

#[derive(Clone, Debug)]
pub struct QuicBrokerConfig {
    pub bind_addr: SocketAddr,
    pub per_subscriber_queue: usize,
    pub max_backlog: usize,
    pub max_rooms: usize,
    pub max_backlog_bytes: usize,
    pub max_connections: usize,
    pub max_streams_per_connection: usize,
    pub read_timeout: Duration,
    pub max_idle_timeout: Duration,
    pub keep_alive_interval: Duration,
    /// Replay window for serving retained backlog to late subscribers. The
    /// broker timestamps backlog records on append and purges entries older
    /// than this window before serving them. `0` (the default) retains no
    /// replay backlog; the hard cap is [`MAX_BROKER_REPLAY_TTL`] (300s). The
    /// group policy `replay_ttl_secs` is the interop-visible bound; this
    /// broker is policy-blind, so the operator-configured value applies to
    /// every room.
    ///
    /// [`MAX_BROKER_REPLAY_TTL`]: crate::MAX_BROKER_REPLAY_TTL
    pub replay_ttl: Duration,
    pub tls: QuicBrokerTlsConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuicBrokerTlsConfig {
    GenerateSelfSigned {
        subject_alt_names: Vec<String>,
    },
    PemFiles {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
}

impl Default for QuicBrokerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4450),
            per_subscriber_queue: DEFAULT_SUBSCRIBER_QUEUE_DEPTH,
            max_backlog: DEFAULT_BROKER_BACKLOG_DEPTH,
            max_rooms: DEFAULT_BROKER_MAX_ROOMS,
            max_backlog_bytes: DEFAULT_BROKER_MAX_BACKLOG_BYTES,
            max_connections: DEFAULT_BROKER_MAX_CONNECTIONS,
            max_streams_per_connection: DEFAULT_BROKER_MAX_STREAMS_PER_CONNECTION,
            read_timeout: DEFAULT_BROKER_READ_TIMEOUT,
            max_idle_timeout: DEFAULT_BROKER_MAX_IDLE_TIMEOUT,
            keep_alive_interval: DEFAULT_BROKER_KEEP_ALIVE_INTERVAL,
            replay_ttl: DEFAULT_BROKER_REPLAY_TTL,
            tls: QuicBrokerTlsConfig::GenerateSelfSigned {
                subject_alt_names: vec!["localhost".to_owned()],
            },
        }
    }
}
