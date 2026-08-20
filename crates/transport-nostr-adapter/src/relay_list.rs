use cgka_traits::{MemberId, TransportAdapterError, TransportEndpoint};
use transport_nostr_peeler::NostrTransportEvent;

use crate::{NostrRelayEndpoint, NostrRelayEndpointError};

pub const KIND_NIP65_RELAY_LIST: u64 = 10_002;
pub const KIND_MARMOT_INBOX_RELAY_LIST: u64 = 10_050;

const NIP65_RELAY_TAG: &str = "r";
const MARMOT_RELAY_TAG: &str = "relay";

/// Directional relay sets recovered from a NIP-65 kind-10002 event.
///
/// An unmarked `r` tag belongs to both sets. A `read`-marked tag belongs only
/// to `read_relays`, and a `write`-marked tag belongs only to `write_relays`.
/// Malformed tags and unknown markers are ignored. Repeated relay URLs are
/// deduplicated independently in each direction while preserving first-seen
/// order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NostrNip65RelaySet {
    pub read_relays: Vec<TransportEndpoint>,
    pub write_relays: Vec<TransportEndpoint>,
}

/// Parse the directional relay roles from a NIP-65 kind-10002 event.
///
/// This is intentionally a tolerant list parser: a hostile or future
/// extension tag must not turn a different valid `r` entry into a relay
/// target. Two-element tags are unmarked (read and write); longer tags accept
/// only the NIP-65 `read` and `write` markers in the third position and ignore
/// trailing extension values.
pub fn parse_nip65_relay_set(event: &NostrTransportEvent) -> NostrNip65RelaySet {
    if event.kind != KIND_NIP65_RELAY_LIST {
        return NostrNip65RelaySet::default();
    }

    let mut relays = NostrNip65RelaySet::default();
    for tag in &event.tags {
        let (relay, read, write) = match tag.as_slice() {
            [name, relay, marker_and_extensions @ ..]
                if name == NIP65_RELAY_TAG && !relay.trim().is_empty() =>
            {
                match marker_and_extensions.first().map(String::as_str) {
                    None => (relay.trim(), true, true),
                    Some(marker) if marker.eq_ignore_ascii_case("read") => {
                        (relay.trim(), true, false)
                    }
                    Some(marker) if marker.eq_ignore_ascii_case("write") => {
                        (relay.trim(), false, true)
                    }
                    Some(_) => continue,
                }
            }
            _ => continue,
        };

        if read {
            push_unique_endpoint(&mut relays.read_relays, relay);
        }
        if write {
            push_unique_endpoint(&mut relays.write_relays, relay);
        }
    }
    relays
}

fn push_unique_endpoint(endpoints: &mut Vec<TransportEndpoint>, relay: &str) {
    let relay = relay.trim();
    if !endpoints.iter().any(|endpoint| endpoint.0 == relay) {
        endpoints.push(TransportEndpoint(relay.to_owned()));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NostrAccountRelayListKind {
    Nip65,
    Inbox,
}

impl NostrAccountRelayListKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Nip65 => "nip65",
            Self::Inbox => "inbox",
        }
    }

    pub fn event_kind(self) -> u64 {
        match self {
            Self::Nip65 => KIND_NIP65_RELAY_LIST,
            Self::Inbox => KIND_MARMOT_INBOX_RELAY_LIST,
        }
    }

    fn relay_tag(self) -> &'static str {
        match self {
            Self::Nip65 => NIP65_RELAY_TAG,
            Self::Inbox => MARMOT_RELAY_TAG,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrAccountRelayListPublication {
    pub account_id: MemberId,
    pub list_kind: NostrAccountRelayListKind,
    pub relays: Vec<TransportEndpoint>,
    pub publish_endpoints: Vec<TransportEndpoint>,
}

impl NostrAccountRelayListPublication {
    pub fn to_event(&self) -> Result<NostrTransportEvent, TransportAdapterError> {
        if self.account_id.as_slice().len() != 32 {
            return Err(TransportAdapterError::Publish(
                "account relay-list author must be a 32-byte Nostr pubkey".into(),
            ));
        }
        let relays = self
            .relays
            .iter()
            .filter(|endpoint| {
                self.list_kind == NostrAccountRelayListKind::Inbox
                    || is_websocket_relay(endpoint).unwrap_or(false)
            })
            .collect::<Vec<_>>();
        if relays.is_empty() {
            return Err(TransportAdapterError::Publish(
                "account relay-list relays must not be empty".into(),
            ));
        }
        if self.publish_endpoints.is_empty() {
            return Err(TransportAdapterError::Publish(
                "account relay-list publish endpoints must not be empty".into(),
            ));
        }

        let relay_tag = self.list_kind.relay_tag();
        let tags = relays
            .iter()
            .map(|endpoint| vec![relay_tag.into(), endpoint.0.clone()])
            .collect::<Vec<_>>();
        Ok(NostrTransportEvent::new_unsigned(
            hex::encode(self.account_id.as_slice()),
            self.list_kind.event_kind(),
            tags,
            String::new(),
        ))
    }
}

/// A role-preserving NIP-65 kind-10002 publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrNip65RelayListPublication {
    pub account_id: MemberId,
    pub relays: NostrNip65RelaySet,
    pub publish_endpoints: Vec<TransportEndpoint>,
}

impl NostrNip65RelayListPublication {
    pub fn to_event(&self) -> Result<NostrTransportEvent, TransportAdapterError> {
        if self.account_id.as_slice().len() != 32 {
            return Err(TransportAdapterError::Publish(
                "account relay-list author must be a 32-byte Nostr pubkey".into(),
            ));
        }
        let read_relays = self
            .relays
            .read_relays
            .iter()
            .filter(|endpoint| is_websocket_relay(endpoint).unwrap_or(false))
            .collect::<Vec<_>>();
        let write_relays = self
            .relays
            .write_relays
            .iter()
            .filter(|endpoint| is_websocket_relay(endpoint).unwrap_or(false))
            .collect::<Vec<_>>();
        if read_relays.is_empty() && write_relays.is_empty() {
            return Err(TransportAdapterError::Publish(
                "account relay-list relays must not be empty".into(),
            ));
        }
        if self.publish_endpoints.is_empty() {
            return Err(TransportAdapterError::Publish(
                "account relay-list publish endpoints must not be empty".into(),
            ));
        }

        let mut tags = Vec::new();
        for endpoint in &read_relays {
            let write = write_relays.iter().any(|candidate| candidate == endpoint);
            let mut tag = vec![NIP65_RELAY_TAG.into(), endpoint.0.clone()];
            if !write {
                tag.push("read".into());
            }
            tags.push(tag);
        }
        for endpoint in &write_relays {
            if read_relays.iter().any(|candidate| candidate == endpoint) {
                continue;
            }
            tags.push(vec![
                NIP65_RELAY_TAG.into(),
                endpoint.0.clone(),
                "write".into(),
            ]);
        }
        Ok(NostrTransportEvent::new_unsigned(
            hex::encode(self.account_id.as_slice()),
            KIND_NIP65_RELAY_LIST,
            tags,
            String::new(),
        ))
    }
}

fn is_websocket_relay(endpoint: &TransportEndpoint) -> Result<bool, NostrRelayEndpointError> {
    NostrRelayEndpoint::parse(endpoint.as_str())
        .map(|endpoint| matches!(endpoint, NostrRelayEndpoint::WebSocket(_)))
}

#[cfg(test)]
mod tests {
    use nostr::{Keys, ToBech32};

    use super::*;

    fn fips_endpoint() -> TransportEndpoint {
        TransportEndpoint(format!(
            "fips://{}",
            Keys::generate().public_key().to_bech32().unwrap()
        ))
    }

    #[test]
    fn nip65_relay_list_uses_kind_10002_and_r_tags() {
        let publication = sample_publication(NostrAccountRelayListKind::Nip65);

        let event = publication.to_event().unwrap();

        assert_eq!(event.kind, KIND_NIP65_RELAY_LIST);
        assert_eq!(event.content, "");
        assert_eq!(
            event.tags,
            vec![
                vec!["r".to_string(), "wss://relay1.example".to_string()],
                vec!["r".to_string(), "wss://relay2.example".to_string()]
            ]
        );
    }

    #[test]
    fn marmot_inbox_relay_list_uses_kind_10050_and_relay_tags() {
        let publication = sample_publication(NostrAccountRelayListKind::Inbox);

        let event = publication.to_event().unwrap();

        assert_eq!(event.kind, KIND_MARMOT_INBOX_RELAY_LIST);
        assert_eq!(
            event.tags[0],
            vec!["relay".to_string(), "wss://relay1.example".to_string()]
        );
    }

    #[test]
    fn fips_endpoints_are_advertised_for_inbox_but_not_nip65_outbox() {
        let fips = fips_endpoint();
        let websocket = TransportEndpoint("wss://relay.example".into());
        let publication = |list_kind| NostrAccountRelayListPublication {
            account_id: MemberId::new(vec![0x11; 32]),
            list_kind,
            relays: vec![websocket.clone(), fips.clone()],
            publish_endpoints: vec![websocket.clone()],
        };

        let inbox = publication(NostrAccountRelayListKind::Inbox)
            .to_event()
            .unwrap();
        let nip65 = publication(NostrAccountRelayListKind::Nip65)
            .to_event()
            .unwrap();

        assert!(inbox.tags.iter().any(|tag| tag.get(1) == Some(&fips.0)));
        assert!(!nip65.tags.iter().any(|tag| tag.get(1) == Some(&fips.0)));
    }

    #[test]
    fn nip65_marker_matrix_is_directional_and_deduplicated() {
        let event = NostrTransportEvent::new_unsigned(
            "11".repeat(32),
            KIND_NIP65_RELAY_LIST,
            vec![
                vec!["r".into(), "wss://both.example".into()],
                vec!["r".into(), "wss://read.example".into(), "read".into()],
                vec!["r".into(), "wss://write.example".into(), "write".into()],
                vec!["r".into(), "wss://invalid.example".into(), "invalid".into()],
                vec!["r".into(), "wss://both.example".into()],
                vec!["r".into(), "wss://split.example".into(), "read".into()],
                vec!["r".into(), "wss://split.example".into(), "write".into()],
                vec![
                    "r".into(),
                    "wss://extra-field.example".into(),
                    "write".into(),
                    "extra".into(),
                ],
                vec!["r".into(), "wss://uppercase.example".into(), "READ".into()],
                vec!["r".into(), " wss://trimmed.example ".into()],
                vec!["r".into(), "wss://trimmed.example".into()],
                vec!["r".into(), "".into()],
                vec!["not-r".into(), "wss://wrong-tag.example".into()],
            ],
            String::new(),
        );

        let relays = parse_nip65_relay_set(&event);

        assert_eq!(
            relays.read_relays,
            vec![
                TransportEndpoint("wss://both.example".into()),
                TransportEndpoint("wss://read.example".into()),
                TransportEndpoint("wss://split.example".into()),
                TransportEndpoint("wss://uppercase.example".into()),
                TransportEndpoint("wss://trimmed.example".into()),
            ]
        );
        assert_eq!(
            relays.write_relays,
            vec![
                TransportEndpoint("wss://both.example".into()),
                TransportEndpoint("wss://write.example".into()),
                TransportEndpoint("wss://split.example".into()),
                TransportEndpoint("wss://extra-field.example".into()),
                TransportEndpoint("wss://trimmed.example".into()),
            ]
        );
    }

    #[test]
    fn nip65_parser_ignores_other_event_kinds() {
        let event = NostrTransportEvent::new_unsigned(
            "11".repeat(32),
            KIND_MARMOT_INBOX_RELAY_LIST,
            vec![vec!["r".into(), "wss://relay.example".into()]],
            String::new(),
        );

        assert_eq!(parse_nip65_relay_set(&event), NostrNip65RelaySet::default());
    }

    #[test]
    fn nip65_publication_preserves_directional_roles() {
        let publication = NostrNip65RelayListPublication {
            account_id: MemberId::new(vec![0xA1; 32]),
            relays: NostrNip65RelaySet {
                read_relays: vec![
                    TransportEndpoint("wss://both.example".into()),
                    TransportEndpoint("wss://read.example".into()),
                ],
                write_relays: vec![
                    TransportEndpoint("wss://both.example".into()),
                    TransportEndpoint("wss://write.example".into()),
                ],
            },
            publish_endpoints: vec![TransportEndpoint("wss://seed.example".into())],
        };

        let event = publication.to_event().unwrap();

        assert_eq!(
            event.tags,
            vec![
                vec!["r", "wss://both.example"],
                vec!["r", "wss://read.example", "read"],
                vec!["r", "wss://write.example", "write"],
            ]
        );
        assert_eq!(parse_nip65_relay_set(&event), publication.relays);
    }

    fn sample_publication(
        list_kind: NostrAccountRelayListKind,
    ) -> NostrAccountRelayListPublication {
        NostrAccountRelayListPublication {
            account_id: MemberId::new(vec![0xA1; 32]),
            list_kind,
            relays: vec![
                TransportEndpoint("wss://relay1.example".into()),
                TransportEndpoint("wss://relay2.example".into()),
            ],
            publish_endpoints: vec![TransportEndpoint("wss://seed.example".into())],
        }
    }
}
