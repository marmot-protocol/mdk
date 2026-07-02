//! Memory-only QUIC broker for Marmot agent text stream previews.
//!
//! This crate is organized as a facade: each submodule owns one concern and the
//! public surface is re-exported here so every item keeps its
//! `transport_quic_broker::ItemName` path.

mod client;
mod config;
mod control;
mod error;
mod frame;
mod handlers;
mod protocol;
mod server;
mod state;
mod tls;

#[cfg(test)]
mod tests;

pub use client::{
    BrokerServerTrust, BrokerTextPublisher, OpenBrokerTextPublisher, PublishTextToBroker,
    SubscribeTextFromBroker, publish_text_to_broker, subscribe_text_from_broker,
    subscribe_text_from_broker_with_limits, subscribe_text_from_broker_with_updates,
};
pub use config::{QuicBrokerConfig, QuicBrokerTlsConfig};
pub use control::{BrokerStreamKey, QuicBrokerControlEnvelopeV1, QuicBrokerControlTypeV1};
pub use error::QuicBrokerError;
pub use protocol::{
    DEFAULT_BROKER_BACKLOG_DEPTH, DEFAULT_BROKER_KEEP_ALIVE_INTERVAL,
    DEFAULT_BROKER_MAX_BACKLOG_BYTES, DEFAULT_BROKER_MAX_CONNECTIONS,
    DEFAULT_BROKER_MAX_IDLE_TIMEOUT, DEFAULT_BROKER_MAX_ROOMS,
    DEFAULT_BROKER_MAX_STREAMS_PER_CONNECTION, DEFAULT_BROKER_READ_TIMEOUT,
    DEFAULT_BROKER_REPLAY_TTL, DEFAULT_SUBSCRIBER_QUEUE_DEPTH, MAX_BROKER_REPLAY_TTL,
    QUIC_BROKER_ALPN_V1, QUIC_BROKER_CONTROL_PUBLISH, QUIC_BROKER_CONTROL_SUBSCRIBE,
    QUIC_BROKER_PROTOCOL_V1,
};
pub use server::QuicBrokerServer;
