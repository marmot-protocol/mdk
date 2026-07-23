use cgka_traits::{MemberId, TransportAdapterError, TransportEndpoint};
use transport_nostr_peeler::NostrTransportEvent;

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
/// target. Exact two-element tags are unmarked (read and write); exact
/// three-element tags accept only the NIP-65 `read` and `write` markers.
pub fn parse_nip65_relay_set(event: &NostrTransportEvent) -> NostrNip65RelaySet {
    if event.kind != KIND_NIP65_RELAY_LIST {
        return NostrNip65RelaySet::default();
    }

    let mut relays = NostrNip65RelaySet::default();
    for tag in &event.tags {
        let (relay, read, write) = match tag.as_slice() {
            [name, relay] if name == NIP65_RELAY_TAG && !relay.trim().is_empty() => {
                (relay, true, true)
            }
            [name, relay, marker]
                if name == NIP65_RELAY_TAG && !relay.trim().is_empty() && marker == "read" =>
            {
                (relay, true, false)
            }
            [name, relay, marker]
                if name == NIP65_RELAY_TAG && !relay.trim().is_empty() && marker == "write" =>
            {
                (relay, false, true)
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
        if self.relays.is_empty() {
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
        let tags = self
            .relays
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

#[cfg(test)]
mod tests {
    use super::*;

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
            ]
        );
        assert_eq!(
            relays.write_relays,
            vec![
                TransportEndpoint("wss://both.example".into()),
                TransportEndpoint("wss://write.example".into()),
                TransportEndpoint("wss://split.example".into()),
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
