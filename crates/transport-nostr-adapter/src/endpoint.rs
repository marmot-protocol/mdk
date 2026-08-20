//! Scheme-aware relay endpoint parsing for the Nostr transport adapter.
//!
//! `fips://` names a FIPS node, not a DNS host and not a WebSocket URL. The
//! The injected FIPS backend owns how that node is reached through the local
//! FIPS service.

use std::fmt;

use nostr::nips::nip19::FromBech32;
use nostr::{PublicKey, RelayUrl, ToBech32};

use cgka_traits::TransportEndpoint;

/// A provisional direct-FIPS relay endpoint.
///
/// The spike deliberately accepts only `fips://<npub>`. Ports, paths, query
/// parameters, fragments, and credentials are not part of this format.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FipsRelayEndpoint {
    raw: String,
    node_pubkey: PublicKey,
}

impl FipsRelayEndpoint {
    pub fn parse(raw: &str) -> Result<Self, NostrRelayEndpointError> {
        if raw != raw.trim() {
            return Err(NostrRelayEndpointError::InvalidFipsEndpoint);
        }
        let Some(npub) = raw.strip_prefix("fips://") else {
            return Err(NostrRelayEndpointError::UnsupportedScheme);
        };
        if npub.is_empty()
            || !npub.starts_with("npub1")
            || npub.bytes().any(|byte| byte.is_ascii_uppercase())
            || npub
                .bytes()
                .any(|byte| matches!(byte, b'/' | b':' | b'?' | b'#' | b'@'))
        {
            return Err(NostrRelayEndpointError::InvalidFipsEndpoint);
        }
        let node_pubkey = PublicKey::from_bech32(npub)
            .map_err(|_| NostrRelayEndpointError::InvalidFipsEndpoint)?;
        let canonical_npub = node_pubkey
            .to_bech32()
            .map_err(|_| NostrRelayEndpointError::InvalidFipsEndpoint)?;
        if canonical_npub != npub {
            return Err(NostrRelayEndpointError::InvalidFipsEndpoint);
        }
        Ok(Self {
            raw: raw.to_owned(),
            node_pubkey,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn node_pubkey(&self) -> PublicKey {
        self.node_pubkey
    }

    pub fn transport_endpoint(&self) -> TransportEndpoint {
        TransportEndpoint(self.raw.clone())
    }
}

/// The connection backend selected by a relay endpoint's scheme.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NostrRelayEndpoint {
    WebSocket(RelayUrl),
    Fips(FipsRelayEndpoint),
}

impl NostrRelayEndpoint {
    pub fn parse(raw: &str) -> Result<Self, NostrRelayEndpointError> {
        if raw.starts_with("fips://") {
            return FipsRelayEndpoint::parse(raw).map(Self::Fips);
        }
        let websocket_scheme =
            raw.split_once("://")
                .map(|(scheme, _)| scheme)
                .is_some_and(|scheme| {
                    scheme.eq_ignore_ascii_case("ws") || scheme.eq_ignore_ascii_case("wss")
                });
        if !websocket_scheme {
            return Err(NostrRelayEndpointError::UnsupportedScheme);
        }
        let relay = RelayUrl::parse(raw).map_err(|_| NostrRelayEndpointError::InvalidWebSocket)?;
        Ok(Self::WebSocket(relay))
    }

    pub fn transport_endpoint(&self) -> TransportEndpoint {
        match self {
            Self::WebSocket(endpoint) => TransportEndpoint(endpoint.to_string()),
            Self::Fips(endpoint) => endpoint.transport_endpoint(),
        }
    }
}

/// Privacy-safe endpoint parse error. It intentionally never includes input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NostrRelayEndpointError {
    UnsupportedScheme,
    InvalidWebSocket,
    InvalidFipsEndpoint,
}

impl fmt::Display for NostrRelayEndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedScheme => "unsupported relay endpoint scheme",
            Self::InvalidWebSocket => "invalid WebSocket relay endpoint",
            Self::InvalidFipsEndpoint => "invalid FIPS relay endpoint",
        };
        f.write_str(message)
    }
}

impl std::error::Error for NostrRelayEndpointError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_npub() -> String {
        PublicKey::from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap()
            .to_bech32()
            .unwrap()
    }

    #[test]
    fn accepts_exact_fips_node_endpoint() {
        let node_npub = node_npub();
        let endpoint =
            FipsRelayEndpoint::parse(&format!("fips://{node_npub}")).expect("valid FIPS endpoint");

        assert_eq!(endpoint.as_str(), format!("fips://{node_npub}"));
        assert_eq!(endpoint.node_pubkey().to_bech32().expect("npub"), node_npub);
    }

    #[test]
    fn rejects_fips_endpoint_extensions_and_non_npub_hosts() {
        let node_npub = node_npub();
        for endpoint in [
            format!("fips://{node_npub}/"),
            format!("fips://{node_npub}:443"),
            format!("fips://{node_npub}?service=relay"),
            format!("fips://{node_npub}#relay"),
            format!("fips://user@{node_npub}"),
            "fips://relay.example".to_owned(),
            "fips://".to_owned(),
        ] {
            assert!(
                FipsRelayEndpoint::parse(&endpoint).is_err(),
                "unexpectedly accepted {endpoint}"
            );
        }
    }

    #[test]
    fn dispatcher_distinguishes_websocket_and_fips_endpoints() {
        let node_npub = node_npub();
        assert!(matches!(
            NostrRelayEndpoint::parse("wss://relay.example").expect("wss"),
            NostrRelayEndpoint::WebSocket(_)
        ));
        assert!(matches!(
            NostrRelayEndpoint::parse(&format!("fips://{node_npub}")).expect("fips"),
            NostrRelayEndpoint::Fips(_)
        ));
        assert_eq!(
            NostrRelayEndpoint::parse("https://relay.example"),
            Err(NostrRelayEndpointError::UnsupportedScheme)
        );
    }
}
