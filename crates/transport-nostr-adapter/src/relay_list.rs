use cgka_traits::{MemberId, TransportAdapterError, TransportEndpoint};
use transport_nostr_peeler::NostrTransportEvent;

pub const KIND_NIP65_RELAY_LIST: u64 = 10_002;
pub const KIND_MARMOT_INBOX_RELAY_LIST: u64 = 10_050;

const NIP65_RELAY_TAG: &str = "r";
const MARMOT_RELAY_TAG: &str = "relay";

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
