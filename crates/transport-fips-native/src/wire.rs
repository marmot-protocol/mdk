use nostr::{
    Alphabet, ClientMessage, Filter, JsonUtil, Kind, PublicKey, RelayMessage, SingleLetterTag,
    SubscriptionId, Timestamp,
};
use transport_nostr_adapter::{FipsNostrFilter, FipsRelaySubscription};
use transport_nostr_peeler::NostrTransportEvent;

#[derive(Debug)]
pub(crate) enum InboundRelayMessage {
    Event {
        subscription_id: String,
        event: NostrTransportEvent,
    },
    EndOfStoredEvents {
        subscription_id: String,
    },
    Ok {
        event_id: String,
        accepted: bool,
    },
    Closed {
        subscription_id: String,
    },
    Unsupported,
}

pub(crate) struct OutboundEvent {
    pub event_id: String,
    pub message: String,
}

pub(crate) fn subscription_message(subscription: &FipsRelaySubscription) -> String {
    let mut filter = match &subscription.filter {
        FipsNostrFilter::AccountInbox { recipient, .. } => Filter::new()
            .kind(Kind::GiftWrap)
            .pubkey(PublicKey::from_byte_array(*recipient)),
        FipsNostrFilter::Group {
            transport_group_id, ..
        } => Filter::new().kind(Kind::MlsGroupMessage).custom_tags(
            SingleLetterTag::lowercase(Alphabet::H),
            [hex::encode(transport_group_id)],
        ),
    };
    let since = match &subscription.filter {
        FipsNostrFilter::AccountInbox { since, .. } | FipsNostrFilter::Group { since, .. } => {
            *since
        }
    };
    if let Some(since) = since {
        filter = filter.since(Timestamp::from_secs(since));
    }
    ClientMessage::req(
        SubscriptionId::new(subscription.subscription_id.clone()),
        filter,
    )
    .as_json()
}

pub(crate) fn unsubscribe_message(subscription_id: &str) -> String {
    ClientMessage::close(SubscriptionId::new(subscription_id)).as_json()
}

pub(crate) fn publish_message(event: &NostrTransportEvent) -> Option<OutboundEvent> {
    let event = event.to_verified_nostr_event().ok()?;
    let event_id = event.id.to_hex();
    Some(OutboundEvent {
        event_id,
        message: ClientMessage::event(event).as_json(),
    })
}

pub(crate) fn parse_relay_message(message: &[u8]) -> Option<InboundRelayMessage> {
    let message = RelayMessage::from_json(message).ok()?;
    match message {
        RelayMessage::Event {
            subscription_id,
            event,
        } => Some(InboundRelayMessage::Event {
            subscription_id: subscription_id.to_string(),
            event: NostrTransportEvent::from_nostr_event(event.as_ref()).ok()?,
        }),
        RelayMessage::EndOfStoredEvents(subscription_id) => {
            Some(InboundRelayMessage::EndOfStoredEvents {
                subscription_id: subscription_id.to_string(),
            })
        }
        RelayMessage::Ok {
            event_id, status, ..
        } => Some(InboundRelayMessage::Ok {
            event_id: event_id.to_hex(),
            accepted: status,
        }),
        RelayMessage::Closed {
            subscription_id, ..
        } => Some(InboundRelayMessage::Closed {
            subscription_id: subscription_id.to_string(),
        }),
        RelayMessage::Notice(_)
        | RelayMessage::Auth { .. }
        | RelayMessage::Count { .. }
        | RelayMessage::NegMsg { .. }
        | RelayMessage::NegErr { .. } => Some(InboundRelayMessage::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use nostr::{EventBuilder, Keys, Tag, TagKind};

    use super::*;

    #[test]
    fn account_and_group_filters_match_websocket_nostr_semantics() {
        let inbox = subscription_message(&FipsRelaySubscription {
            subscription_id: "inbox".into(),
            filter: FipsNostrFilter::AccountInbox {
                recipient: [3; 32],
                since: Some(42),
            },
        });
        let inbox: serde_json::Value = serde_json::from_str(&inbox).unwrap();
        assert_eq!(inbox[0], "REQ");
        assert_eq!(inbox[1], "inbox");
        assert_eq!(inbox[2]["kinds"], serde_json::json!([1059]));
        assert_eq!(inbox[2]["#p"], serde_json::json!([hex::encode([3; 32])]));
        assert_eq!(inbox[2]["since"], 42);

        let group = subscription_message(&FipsRelaySubscription {
            subscription_id: "group".into(),
            filter: FipsNostrFilter::Group {
                transport_group_id: vec![7; 32],
                since: None,
            },
        });
        let group: serde_json::Value = serde_json::from_str(&group).unwrap();
        assert_eq!(group[2]["kinds"], serde_json::json!([445]));
        assert_eq!(group[2]["#h"], serde_json::json!([hex::encode([7; 32])]));
    }

    #[test]
    fn publish_requires_a_verified_signed_event() {
        let unsigned = NostrTransportEvent::new_unsigned(
            "11".repeat(32),
            445,
            vec![vec!["h".into(), "22".repeat(32)]],
            "payload".into(),
        );
        assert!(publish_message(&unsigned).is_none());

        let keys = Keys::generate();
        let signed = EventBuilder::new(Kind::MlsGroupMessage, "payload")
            .tag(Tag::custom(TagKind::custom("h"), ["22".repeat(32)]))
            .sign_with_keys(&keys)
            .unwrap();
        let dto = NostrTransportEvent::from_nostr_event(&signed).unwrap();
        let outbound = publish_message(&dto).unwrap();
        let message: serde_json::Value = serde_json::from_str(&outbound.message).unwrap();
        assert_eq!(message[0], "EVENT");
        assert_eq!(message[1]["id"], signed.id.to_hex());
        assert_eq!(outbound.event_id, signed.id.to_hex());
    }

    #[test]
    fn relay_responses_are_strictly_classified() {
        assert!(matches!(
            parse_relay_message(br#"["EOSE","sub"]"#),
            Some(InboundRelayMessage::EndOfStoredEvents { subscription_id }) if subscription_id == "sub"
        ));
        assert!(matches!(
            parse_relay_message(
                br#"["OK","1111111111111111111111111111111111111111111111111111111111111111",true,"saved"]"#
            ),
            Some(InboundRelayMessage::Ok { accepted: true, .. })
        ));
        assert!(matches!(
            parse_relay_message(br#"["CLOSED","sub","auth-required: authenticate first"]"#),
            Some(InboundRelayMessage::Closed { subscription_id }) if subscription_id == "sub"
        ));
        assert!(parse_relay_message(br#"["EOSE"]"#).is_none());
    }
}
