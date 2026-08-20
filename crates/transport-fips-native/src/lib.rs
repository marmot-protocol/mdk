//! Native FIPS transport for Nostr relay commands.
//!
//! The public boundary remains [`transport_nostr_adapter::FipsRelayApi`]. This
//! crate owns the platform-specific connection to the local FIPS daemon and
//! Wok's WFP1 logical-message protocol. It never performs a WebSocket or HTTP
//! handshake.

use std::path::{Path, PathBuf};

/// Wok's FIPS application port for the experimental relay transport.
pub const DEFAULT_FIPS_RELAY_PORT: u16 = 7777;
pub const NATIVE_FIPS_SUPPORTED: bool = cfg!(any(target_os = "linux", target_os = "freebsd"));

/// Configuration for the local native FIPS API connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeFipsRelayConfig {
    socket_path: PathBuf,
    service_port: u16,
}

impl NativeFipsRelayConfig {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            service_port: DEFAULT_FIPS_RELAY_PORT,
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn service_port(&self) -> u16 {
        self.service_port
    }

    /// Override the service port for controlled interoperability tests.
    ///
    /// The `fips://<npub>` application-component endpoint intentionally does
    /// not carry a port. A configured backend therefore applies one port to
    /// every FIPS relay endpoint it serves.
    pub fn with_service_port(mut self, service_port: u16) -> Option<Self> {
        if service_port <= 1023 {
            return None;
        }
        self.service_port = service_port;
        Some(self)
    }
}

impl Default for NativeFipsRelayConfig {
    fn default() -> Self {
        Self::new("/run/fips/api.sock")
    }
}

#[cfg_attr(not(any(target_os = "linux", target_os = "freebsd")), allow(dead_code))]
mod wire;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod native;
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
mod unsupported;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub use native::NativeFipsRelayApi;
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
pub use unsupported::NativeFipsRelayApi;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_configuration_keeps_port_out_of_endpoint_identity() {
        let config = NativeFipsRelayConfig::default();
        assert_eq!(config.socket_path(), Path::new("/run/fips/api.sock"));
        assert_eq!(config.service_port(), DEFAULT_FIPS_RELAY_PORT);
        assert!(config.clone().with_service_port(1023).is_none());
        assert_eq!(config.with_service_port(4242).unwrap().service_port(), 4242);
    }
}
