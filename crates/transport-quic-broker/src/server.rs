//! Broker server: binds the QUIC endpoint, enforces connection limits, and
//! accepts connections into the per-connection stream handlers.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::Endpoint;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::config::QuicBrokerConfig;
use crate::error::QuicBrokerError;
use crate::handlers::handle_connection;
use crate::protocol::MAX_BROKER_REPLAY_TTL;
use crate::state::BrokerState;
use crate::tls::{broker_transport_config, configure_server};

pub struct QuicBrokerServer {
    endpoint: Endpoint,
    server_cert_der: Vec<u8>,
    state: Arc<BrokerState>,
    connection_limiter: Arc<Semaphore>,
    max_streams_per_connection: usize,
    read_timeout: Duration,
}

impl QuicBrokerServer {
    pub fn bind(config: QuicBrokerConfig) -> Result<Self, QuicBrokerError> {
        if config.per_subscriber_queue == 0 {
            return Err(QuicBrokerError::EmptySubscriberQueue);
        }
        if config.max_backlog == 0 {
            return Err(QuicBrokerError::EmptyBacklog);
        }
        if config.max_rooms == 0 {
            return Err(QuicBrokerError::EmptyRoomLimit);
        }
        if config.max_backlog_bytes == 0 {
            return Err(QuicBrokerError::EmptyBacklogByteLimit);
        }
        if config.max_connections == 0 {
            return Err(QuicBrokerError::EmptyConnectionLimit);
        }
        if config.max_streams_per_connection == 0 {
            return Err(QuicBrokerError::EmptyStreamLimit);
        }
        if config.read_timeout.is_zero() {
            return Err(QuicBrokerError::EmptyReadTimeout);
        }
        if config.max_idle_timeout.is_zero() {
            return Err(QuicBrokerError::EmptyIdleTimeout);
        }
        if config.keep_alive_interval.is_zero() {
            return Err(QuicBrokerError::EmptyKeepAliveInterval);
        }
        if config.replay_ttl > MAX_BROKER_REPLAY_TTL {
            return Err(QuicBrokerError::ReplayTtlTooLarge {
                requested_secs: config.replay_ttl.as_secs(),
                cap_secs: MAX_BROKER_REPLAY_TTL.as_secs(),
            });
        }
        let (mut server_config, server_cert_der) = configure_server(&config.tls)?;
        server_config.transport_config(Arc::new(broker_transport_config(&config)?));
        let endpoint = Endpoint::server(server_config, config.bind_addr)?;
        Ok(Self {
            endpoint,
            server_cert_der,
            state: Arc::new(BrokerState::new(
                config.per_subscriber_queue,
                config.max_backlog,
                config.max_rooms,
                config.max_backlog_bytes,
                config.replay_ttl,
            )),
            connection_limiter: Arc::new(Semaphore::new(config.max_connections)),
            max_streams_per_connection: config.max_streams_per_connection,
            read_timeout: config.read_timeout,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, QuicBrokerError> {
        Ok(self.endpoint.local_addr()?)
    }

    pub fn server_cert_der(&self) -> &[u8] {
        &self.server_cert_der
    }

    pub fn server_cert_sha256_fingerprint(&self) -> String {
        certificate_sha256_fingerprint_hex(&self.server_cert_der)
    }

    pub async fn run_until(
        self,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), QuicBrokerError> {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    self.endpoint.close(0_u32.into(), b"shutdown");
                    self.endpoint.wait_idle().await;
                    return Ok(());
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        return Ok(());
                    };
                    let Ok(permit) = Arc::clone(&self.connection_limiter).try_acquire_owned() else {
                        incoming.refuse();
                        continue;
                    };
                    let state = Arc::clone(&self.state);
                    let max_streams_per_connection = self.max_streams_per_connection;
                    let read_timeout = self.read_timeout;
                    tokio::spawn(async move {
                        let _permit = permit;
                        let Ok(connection) = incoming.await else {
                            return;
                        };
                        let _ = handle_connection(
                            state,
                            connection,
                            max_streams_per_connection,
                            read_timeout,
                        ).await;
                    });
                }
            }
        }
    }
}

pub(crate) fn certificate_sha256_fingerprint_hex(certificate_der: &[u8]) -> String {
    hex::encode(Sha256::digest(certificate_der))
}
