use crate::{
    GROUP_TAG, KIND_MARMOT_GROUP_MESSAGE, KIND_NIP59_GIFT_WRAP, NOSTR_SOURCE, NostrPeelerError,
    RECIPIENT_TAG,
};
use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportMessage, TransportSource};
use cgka_traits::types::{MemberId, MessageId};
use nostr::{Event, JsonUtil};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Nostr event shape consumed and produced at the peeler boundary.
///
/// This is intentionally a small DTO instead of a relay client type. A Nostr
/// adapter can map real SDK events into this value after subscription, and map
/// locally wrapped events back into SDK builders before signing/publishing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NostrTransportEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

impl NostrTransportEvent {
    /// Convert a Nostr event into the raw transport message the engine ingests.
    pub fn to_transport_message(&self) -> Result<TransportMessage, NostrPeelerError> {
        let id = MessageId::new(decode_hex_exact("event id", &self.id, 32)?);
        let envelope = match self.kind {
            KIND_MARMOT_GROUP_MESSAGE => {
                let group_id = self.single_tag_value(GROUP_TAG)?;
                TransportEnvelope::GroupMessage {
                    transport_group_id: decode_hex("group h tag", group_id)?,
                }
            }
            KIND_NIP59_GIFT_WRAP => {
                let recipient = self
                    .tag_value(RECIPIENT_TAG)
                    .ok_or_else(|| NostrPeelerError::MissingTag(RECIPIENT_TAG.into()))?;
                TransportEnvelope::Welcome {
                    recipient: MemberId::new(decode_hex_exact("recipient p tag", recipient, 32)?),
                }
            }
            other => return Err(NostrPeelerError::UnsupportedKind(other)),
        };

        Ok(TransportMessage {
            id,
            payload: serde_json::to_vec(self)
                .map_err(|e| NostrPeelerError::Malformed(e.to_string()))?,
            timestamp: Timestamp(self.created_at),
            // Kind 445 MUST NOT carry any tag other than h/expiration
            // (transports/nostr.md). The peeler no longer extracts `e` causal
            // dependencies — the feature was unused — so this is always empty.
            causal_deps: Vec::new(),
            source: TransportSource(NOSTR_SOURCE.into()),
            envelope,
        })
    }

    /// Parse the Nostr DTO carried as a [`TransportMessage`] payload.
    pub fn from_transport_message(msg: &TransportMessage) -> Result<Self, NostrPeelerError> {
        serde_json::from_slice(&msg.payload).map_err(|e| NostrPeelerError::Malformed(e.to_string()))
    }

    /// Convert a signed Nostr SDK event into the boundary DTO.
    pub fn from_nostr_event(event: &Event) -> Result<Self, NostrPeelerError> {
        Ok(Self {
            id: event.id.to_hex(),
            pubkey: event.pubkey.to_hex(),
            created_at: event.created_at.as_secs(),
            kind: u64::from(event.kind.as_u16()),
            tags: event
                .tags
                .clone()
                .into_iter()
                .map(|tag| tag.to_vec())
                .collect(),
            content: event.content.clone(),
            sig: Some(event.sig.to_string()),
        })
    }

    /// Convert this DTO into a signed, verified Nostr SDK event.
    pub fn to_verified_nostr_event(&self) -> Result<Event, NostrPeelerError> {
        if self.sig.is_none() {
            return Err(NostrPeelerError::Malformed(
                "signed Nostr event is missing sig".into(),
            ));
        }
        let event = Event::from_json(
            serde_json::to_vec(self)
                .map_err(|e| NostrPeelerError::Malformed(format!("event JSON: {e}")))?,
        )
        .map_err(|e| NostrPeelerError::Malformed(format!("Nostr event parse: {e}")))?;
        event
            .verify()
            .map_err(|e| NostrPeelerError::Malformed(format!("Nostr event verification: {e}")))?;
        Ok(event)
    }

    /// Return the first value for a Nostr tag name.
    pub fn tag_value(&self, name: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
            .and_then(|tag| tag.get(1))
            .map(String::as_str)
    }

    /// Return every value for a Nostr tag name.
    pub fn tag_values(&self, name: &str) -> Vec<&str> {
        self.tags
            .iter()
            .filter(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
            .filter_map(|tag| tag.get(1))
            .map(String::as_str)
            .collect()
    }

    /// Return exactly one value for a Nostr tag name.
    pub fn single_tag_value(&self, name: &str) -> Result<&str, NostrPeelerError> {
        let values = self.tag_values(name);
        match values.as_slice() {
            [] => Err(NostrPeelerError::MissingTag(name.into())),
            [value] => Ok(value),
            _ => Err(NostrPeelerError::Malformed(format!(
                "Nostr event must contain exactly one {name} tag"
            ))),
        }
    }

    /// Build an unsigned local Nostr DTO and precompute the event id for the
    /// supplied unsigned event core.
    pub fn new_unsigned(
        pubkey: String,
        kind: u64,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Self {
        let created_at = now_unix_seconds();
        let id = pre_signing_id(&pubkey, created_at, kind, &tags, &content);
        Self {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig: None,
        }
    }
}

fn pre_signing_id(
    pubkey: &str,
    created_at: u64,
    kind: u64,
    tags: &[Vec<String>],
    content: &str,
) -> String {
    let preimage = Value::Array(vec![
        Value::from(0u8),
        Value::from(pubkey),
        Value::from(created_at),
        Value::from(kind),
        Value::Array(
            tags.iter()
                .map(|tag| Value::Array(tag.iter().map(|v| Value::from(v.as_str())).collect()))
                .collect(),
        ),
        Value::from(content),
    ]);
    let bytes = serde_json::to_vec(&preimage).expect("serializing Nostr event id should not fail");
    hex::encode(Sha256::digest(bytes))
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn decode_hex(label: &str, value: &str) -> Result<Vec<u8>, NostrPeelerError> {
    hex::decode(value).map_err(|e| NostrPeelerError::Malformed(format!("invalid hex {label}: {e}")))
}

pub(crate) fn decode_hex_exact(
    label: &str,
    value: &str,
    expected_len: usize,
) -> Result<Vec<u8>, NostrPeelerError> {
    let bytes = decode_hex(label, value)?;
    if bytes.len() != expected_len {
        return Err(NostrPeelerError::Malformed(format!(
            "{label} must be {expected_len} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_445_event_maps_to_group_transport_message() {
        let event = NostrTransportEvent {
            id: "11".repeat(32),
            pubkey: "22".repeat(32),
            created_at: 1_700_000_000,
            kind: KIND_MARMOT_GROUP_MESSAGE,
            tags: vec![vec!["h".into(), "aa55".into()]],
            content: "encrypted body".into(),
            sig: None,
        };

        let msg = event.to_transport_message().expect("event maps");

        assert_eq!(msg.id.as_slice(), vec![0x11; 32].as_slice());
        assert_eq!(msg.timestamp.0, 1_700_000_000);
        assert_eq!(msg.source.0, NOSTR_SOURCE);
        // The peeler does not extract `e` causal-dependency tags (kind 445 carries
        // none per transports/nostr.md).
        assert!(msg.causal_deps.is_empty());
        assert_eq!(
            msg.envelope,
            TransportEnvelope::GroupMessage {
                transport_group_id: vec![0xaa, 0x55],
            }
        );
        assert_eq!(
            NostrTransportEvent::from_transport_message(&msg).expect("payload parses"),
            event
        );
    }

    #[tokio::test]
    async fn signed_kind_1059_event_maps_to_welcome_transport_message() {
        let sender =
            nostr::Keys::parse("6b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();
        let receiver =
            nostr::Keys::parse("7b911fd37cdf5c81d4c0adb1ab7fa822ed253ab0ad9aa18d77257c88b29b718e")
                .unwrap();
        let rumor =
            nostr::EventBuilder::text_note("not a Marmot welcome").build(sender.public_key());
        let gift_wrap = nostr::EventBuilder::gift_wrap(&sender, &receiver.public_key(), rumor, [])
            .await
            .unwrap();
        let event = NostrTransportEvent::from_nostr_event(&gift_wrap).unwrap();

        let msg = event.to_transport_message().expect("event maps");

        assert_eq!(
            msg.envelope,
            TransportEnvelope::Welcome {
                recipient: MemberId::new(receiver.public_key().to_bytes().to_vec()),
            }
        );
        assert_eq!(
            NostrTransportEvent::from_transport_message(&msg).expect("payload parses"),
            event
        );
    }

    #[test]
    fn kind_1059_route_mapping_defers_signature_verification_to_peeling() {
        let event = NostrTransportEvent {
            id: "33".repeat(32),
            pubkey: "44".repeat(32),
            created_at: 1_700_000_001,
            kind: KIND_NIP59_GIFT_WRAP,
            tags: vec![vec!["p".into(), "55".repeat(32)]],
            content: "gift wrap body".into(),
            sig: None,
        };

        let msg = event
            .to_transport_message()
            .expect("route mapping should not verify gift-wrap signatures");

        assert_eq!(
            msg.envelope,
            TransportEnvelope::Welcome {
                recipient: MemberId::new(vec![0x55; 32]),
            }
        );
    }
}
