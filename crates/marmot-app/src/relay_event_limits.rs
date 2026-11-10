//! The relay event limits the publish path enforces (mdk#2334): the exact
//! limits the deployment configures, and the WebSocket message limit a relay
//! advertises in its NIP-11 document, less the `["EVENT",…]` framing. The
//! smaller known value wins; a relay with neither has no known limit, and an
//! event is sent to it as before.
//!
//! The advertised limit is read only for events over 64 KiB, the smallest
//! event limit relays use, so ordinary traffic never waits on a document.

use std::collections::HashMap;

use async_trait::async_trait;
use cgka_traits::TransportEndpoint;
use nostr::prelude::RelayUrl;
use transport_nostr::RelayEventLimits;

use crate::RelayEventLimit;
use crate::relay_caps::RelayCapsCache;

/// `["EVENT",` and `]` around the event in a client's publish message.
const EVENT_MESSAGE_FRAMING_BYTES: usize = 10;
/// strfry's default `events.maxEventSize`. No relay MDK knows of refuses a
/// smaller event, so events up to this size skip the document lookup.
const ADVERTISED_LIMIT_CHECK_ABOVE_BYTES: usize = 64 * 1024;

pub(crate) struct AppRelayEventLimits {
    configured: HashMap<RelayUrl, usize>,
    caps: RelayCapsCache,
    allow_loopback: bool,
}

impl AppRelayEventLimits {
    pub(crate) fn new(
        limits: &[RelayEventLimit],
        caps: RelayCapsCache,
        allow_loopback: bool,
    ) -> Self {
        let mut configured = HashMap::new();
        for limit in limits {
            let Ok(relay) = RelayUrl::parse(limit.relay.trim()) else {
                continue;
            };
            let bytes = usize::try_from(limit.max_event_bytes).unwrap_or(usize::MAX);
            configured
                .entry(relay)
                .and_modify(|known: &mut usize| *known = (*known).min(bytes))
                .or_insert(bytes);
        }
        Self {
            configured,
            caps,
            allow_loopback,
        }
    }
}

#[async_trait]
impl RelayEventLimits for AppRelayEventLimits {
    async fn max_event_bytes(
        &self,
        endpoint: &TransportEndpoint,
        event_bytes: usize,
    ) -> Option<usize> {
        let configured = RelayUrl::parse(endpoint.as_str().trim())
            .ok()
            .and_then(|relay| self.configured.get(&relay).copied());
        if event_bytes <= ADVERTISED_LIMIT_CHECK_ABOVE_BYTES {
            return configured;
        }
        let advertised = self
            .caps
            .max_message_length(endpoint.as_str(), self.allow_loopback)
            .await;
        effective_limit(configured, advertised)
    }
}

/// The smaller of a configured event limit and the event room an advertised
/// message limit leaves.
fn effective_limit(configured: Option<usize>, max_message_length: Option<usize>) -> Option<usize> {
    let advertised =
        max_message_length.map(|length| length.saturating_sub(EVENT_MESSAGE_FRAMING_BYTES));
    match (configured, advertised) {
        (Some(configured), Some(advertised)) => Some(configured.min(advertised)),
        (configured, advertised) => configured.or(advertised),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(configured: &[(&str, u64)]) -> AppRelayEventLimits {
        AppRelayEventLimits::new(
            &configured
                .iter()
                .map(|(relay, max_event_bytes)| RelayEventLimit {
                    relay: (*relay).to_owned(),
                    max_event_bytes: *max_event_bytes,
                })
                .collect::<Vec<_>>(),
            RelayCapsCache::default(),
            false,
        )
    }

    fn endpoint(relay: &str) -> TransportEndpoint {
        TransportEndpoint(relay.to_owned())
    }

    #[tokio::test]
    async fn a_configured_limit_matches_any_spelling_of_its_relay() {
        let limits = limits(&[
            ("wss://relay.example", 2_000),
            ("wss://relay.example/", 1_500),
        ]);
        for spelling in [
            "wss://relay.example",
            "wss://RELAY.example/",
            " wss://relay.example ",
        ] {
            assert_eq!(
                limits.max_event_bytes(&endpoint(spelling), 100).await,
                Some(1_500),
                "{spelling}"
            );
        }
        assert_eq!(
            limits
                .max_event_bytes(&endpoint("wss://other.example"), 100)
                .await,
            None
        );
    }

    /// A large event reads the relay's document; a plaintext public relay's
    /// is refused before any I/O, so it reads as unknown and the configured
    /// limit stands.
    #[tokio::test]
    async fn an_unavailable_document_keeps_the_configured_limit() {
        let limits = limits(&[("ws://relay.example", 1_000_000)]);
        for event_bytes in [64 * 1024, 64 * 1024 + 1] {
            assert_eq!(
                limits
                    .max_event_bytes(&endpoint("ws://relay.example"), event_bytes)
                    .await,
                Some(1_000_000),
                "{event_bytes} bytes"
            );
        }
    }

    #[test]
    fn the_smaller_known_limit_wins() {
        assert_eq!(effective_limit(None, None), None);
        assert_eq!(effective_limit(Some(2_000_000), None), Some(2_000_000));
        // nos.lol advertises strfry's default 128 KiB message limit.
        assert_eq!(effective_limit(None, Some(131_072)), Some(131_062));
        assert_eq!(effective_limit(Some(65_536), Some(131_072)), Some(65_536));
        assert_eq!(
            effective_limit(Some(2_097_152), Some(1_000_000)),
            Some(999_990)
        );
        assert_eq!(effective_limit(None, Some(4)), Some(0));
    }
}
