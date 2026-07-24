use crate::{
    EXPIRATION_TAG, GROUP_TAG, KIND_MARMOT_GROUP_MESSAGE, KIND_NIP59_GIFT_WRAP, NOSTR_SOURCE,
    NostrPeelerError, RECIPIENT_TAG,
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
        // #709/#351 — the resulting `TransportMessage.id` keys routing metrics,
        // telemetry, and the forensic `wire_id`, so bind it to the event hash
        // here rather than trusting the self-reported id. Kind-445 signature
        // verification happens before reading its routing tags and is repeated
        // by the peeler as defense in depth; gift-wrap verification stays at the
        // welcome peel boundary.
        if !self.id.eq_ignore_ascii_case(&self.computed_id()) {
            return Err(NostrPeelerError::Malformed(
                "event id does not match event hash".into(),
            ));
        }
        let id = MessageId::new(decode_hex_exact("event id", &self.id, 32)?);
        let envelope = match self.kind {
            KIND_MARMOT_GROUP_MESSAGE => {
                // Kind-445 routing is attacker-visible and drives account/group
                // delivery. Authenticate the complete outer event before reading
                // its tags so unauthenticated input never reaches engine state.
                self.to_verified_nostr_event()?;
                let group_id = validate_kind_445_tag_shape(self)?;
                TransportEnvelope::GroupMessage {
                    // The `h` tag is the hex of the 32-byte nostr_group_id
                    // (spec/transports/nostr.md); shorter/longer route ids are
                    // rejected, not passed through.
                    transport_group_id: decode_lowercase_hex_exact("group h tag", group_id, 32)?,
                }
            }
            KIND_NIP59_GIFT_WRAP => {
                let recipient = self.single_tag_value(RECIPIENT_TAG)?;
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

    /// Return the value of exactly one Nostr tag.
    ///
    /// Counts tag *occurrences* (any tag whose name matches), not extracted
    /// values, so a valueless duplicate like `["p"]` next to `["p", <value>]`
    /// is still rejected instead of collapsing to a single first-match value.
    pub fn single_tag_value(&self, name: &str) -> Result<&str, NostrPeelerError> {
        let mut matches = self
            .tags
            .iter()
            .filter(|tag| tag.first().is_some_and(|tag_name| tag_name == name));
        let first = matches
            .next()
            .ok_or_else(|| NostrPeelerError::MissingTag(name.into()))?;
        if matches.next().is_some() {
            return Err(NostrPeelerError::Malformed(format!(
                "Nostr event must contain exactly one {name} tag"
            )));
        }
        first.get(1).map(String::as_str).ok_or_else(|| {
            NostrPeelerError::Malformed(format!("Nostr event {name} tag has no value"))
        })
    }

    /// NIP-01 event id (lowercase hex sha256 of the canonical serialization)
    /// computed from this event's own fields, independent of the self-reported
    /// `id` field.
    pub fn computed_id(&self) -> String {
        pre_signing_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        )
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

pub(crate) fn decode_lowercase_hex_exact(
    label: &str,
    value: &str,
    expected_len: usize,
) -> Result<Vec<u8>, NostrPeelerError> {
    if !value
        .chars()
        .all(|ch| ch.is_ascii_digit() || matches!(ch, 'a'..='f'))
    {
        return Err(NostrPeelerError::Malformed(format!(
            "{label} must be lowercase hex"
        )));
    }
    decode_hex_exact(label, value, expected_len)
}

fn validate_expiration_tag_value(value: &str) -> Result<(), NostrPeelerError> {
    if value.is_empty() || !value.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(NostrPeelerError::Malformed(
            "kind-445 expiration tag must be a unix timestamp decimal string".into(),
        ));
    }
    value.parse::<u64>().map_err(|_| {
        NostrPeelerError::Malformed(
            "kind-445 expiration tag must be a unix timestamp decimal string".into(),
        )
    })?;
    Ok(())
}

/// Enforce the exact kind-445 outer tag shape from `spec/transports/nostr.md`.
///
/// Exactly one `h` tag and at most one `expiration` tag are permitted; tag order
/// is not specified. Returns the validated `h` tag value.
pub(crate) fn validate_kind_445_tag_shape(
    event: &NostrTransportEvent,
) -> Result<&str, NostrPeelerError> {
    let mut h_value: Option<&str> = None;
    let mut expiration_seen = false;

    for tag in &event.tags {
        let name = tag
            .first()
            .map(String::as_str)
            .ok_or_else(|| NostrPeelerError::Malformed("kind-445 tag has no name".into()))?;
        match name {
            GROUP_TAG => {
                if tag.len() != 2 {
                    return Err(NostrPeelerError::Malformed(
                        "kind-445 h tag must have exactly one value".into(),
                    ));
                }
                if h_value.is_some() {
                    return Err(NostrPeelerError::Malformed(
                        "Nostr event must contain exactly one h tag".into(),
                    ));
                }
                h_value = Some(tag[1].as_str());
            }
            EXPIRATION_TAG => {
                if tag.len() != 2 {
                    return Err(NostrPeelerError::Malformed(
                        "kind-445 expiration tag must have exactly one value".into(),
                    ));
                }
                if expiration_seen {
                    return Err(NostrPeelerError::Malformed(
                        "Nostr event must contain at most one expiration tag".into(),
                    ));
                }
                expiration_seen = true;
                validate_expiration_tag_value(tag[1].as_str())?;
            }
            _ => {
                return Err(NostrPeelerError::Malformed(
                    "kind-445 event has an unsupported tag".into(),
                ));
            }
        }
    }

    h_value.ok_or_else(|| NostrPeelerError::MissingTag(GROUP_TAG.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_kind_445_event(tags: Vec<Vec<String>>, content: &str) -> NostrTransportEvent {
        let tags = tags.into_iter().map(|tag| {
            let mut fields = tag.into_iter();
            let name = fields.next().expect("test tag has a name");
            nostr::Tag::custom(nostr::TagKind::custom(name), fields)
        });
        let signed = nostr::EventBuilder::new(
            nostr::Kind::Custom(KIND_MARMOT_GROUP_MESSAGE as u16),
            content,
        )
        .tags(tags)
        .sign_with_keys(&nostr::Keys::generate())
        .expect("sign kind-445 test event");
        NostrTransportEvent::from_nostr_event(&signed).expect("map signed test event")
    }

    #[test]
    fn kind_445_tag_shape_table() {
        let valid_h = "aa".repeat(32);
        let cases: Vec<(&str, Vec<Vec<String>>, bool)> = vec![
            ("missing h", vec![], false),
            (
                "duplicate h",
                vec![
                    vec!["h".into(), valid_h.clone()],
                    vec!["h".into(), valid_h.clone()],
                ],
                false,
            ),
            (
                "extra unknown tag",
                vec![
                    vec!["h".into(), valid_h.clone()],
                    vec!["encoding".into(), "base64".into()],
                ],
                false,
            ),
            (
                "h wrong arity (extra value)",
                vec![vec!["h".into(), valid_h.clone(), "extra".into()]],
                false,
            ),
            ("h valueless", vec![vec!["h".into()]], false),
            (
                "h uppercase hex",
                vec![vec!["h".into(), "AA".repeat(32)]],
                false,
            ),
            (
                "h wrong length (raw MLS group id sized)",
                vec![vec!["h".into(), "aa".repeat(16)]],
                false,
            ),
            (
                "expiration duplicate",
                vec![
                    vec!["h".into(), valid_h.clone()],
                    vec!["expiration".into(), "1700000060".into()],
                    vec!["expiration".into(), "1700000070".into()],
                ],
                false,
            ),
            (
                "expiration wrong arity",
                vec![vec!["h".into(), valid_h.clone()], vec!["expiration".into()]],
                false,
            ),
            (
                "expiration malformed timestamp",
                vec![
                    vec!["h".into(), valid_h.clone()],
                    vec!["expiration".into(), "not-a-timestamp".into()],
                ],
                false,
            ),
            (
                "valid h only",
                vec![vec!["h".into(), valid_h.clone()]],
                true,
            ),
            (
                "valid expiration then h",
                vec![
                    vec!["expiration".into(), "1700000060".into()],
                    vec!["h".into(), valid_h.clone()],
                ],
                true,
            ),
            (
                "valid h then expiration",
                vec![
                    vec!["h".into(), valid_h.clone()],
                    vec!["expiration".into(), "1700000060".into()],
                ],
                true,
            ),
        ];

        for (name, tags, should_accept) in cases {
            let event = signed_kind_445_event(tags, "encrypted body");
            let result = event.to_transport_message();
            assert_eq!(
                result.is_ok(),
                should_accept,
                "case {name}: expected accept={should_accept}, got {result:?}"
            );
            if should_accept {
                assert!(matches!(
                    result.unwrap().envelope,
                    TransportEnvelope::GroupMessage { .. }
                ));
            } else {
                assert!(matches!(
                    result,
                    Err(NostrPeelerError::Malformed(_) | NostrPeelerError::MissingTag(_))
                ));
            }
        }
    }

    #[test]
    fn kind_445_event_maps_to_group_transport_message() {
        let event =
            signed_kind_445_event(vec![vec!["h".into(), "aa".repeat(32)]], "encrypted body");

        let msg = event.to_transport_message().expect("event maps");

        assert_eq!(
            msg.id.as_slice(),
            hex::decode(&event.id).unwrap().as_slice()
        );
        assert_eq!(msg.timestamp.0, event.created_at);
        assert_eq!(msg.source.0, NOSTR_SOURCE);
        // The peeler does not extract `e` causal-dependency tags (kind 445 carries
        // none per transports/nostr.md).
        assert!(msg.causal_deps.is_empty());
        assert_eq!(
            msg.envelope,
            TransportEnvelope::GroupMessage {
                transport_group_id: vec![0xaa; 32],
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
        let mut event = NostrTransportEvent {
            id: String::new(),
            pubkey: "44".repeat(32),
            created_at: 1_700_000_001,
            kind: KIND_NIP59_GIFT_WRAP,
            tags: vec![vec!["p".into(), "55".repeat(32)]],
            content: "gift wrap body".into(),
            sig: None,
        };
        event.id = event.computed_id();

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

    #[test]
    fn route_mapping_rejects_forged_event_id() {
        // #351 — `TransportMessage.id` keys routing/telemetry/forensics, so a
        // self-reported id that does not match the event hash fails closed.
        let event = NostrTransportEvent {
            id: "33".repeat(32),
            pubkey: "22".repeat(32),
            created_at: 1_700_000_000,
            kind: KIND_MARMOT_GROUP_MESSAGE,
            tags: vec![vec!["h".into(), "aa".repeat(32)]],
            content: "encrypted body".into(),
            sig: None,
        };
        assert_ne!(event.id, event.computed_id());

        assert!(matches!(
            event.to_transport_message(),
            Err(NostrPeelerError::Malformed(_))
        ));
    }

    #[test]
    fn route_mapping_rejects_duplicate_recipient_tags() {
        // #336 — gift-wrap `p` extraction is strict single-tag, matching the
        // kind-445 `h` path; a multi-`p` wrap is rejected, not first-matched.
        let mut event = NostrTransportEvent {
            id: String::new(),
            pubkey: "44".repeat(32),
            created_at: 1_700_000_001,
            kind: KIND_NIP59_GIFT_WRAP,
            tags: vec![
                vec!["p".into(), "55".repeat(32)],
                vec!["p".into(), "66".repeat(32)],
            ],
            content: "gift wrap body".into(),
            sig: None,
        };
        event.id = event.computed_id();

        assert!(matches!(
            event.to_transport_message(),
            Err(NostrPeelerError::Malformed(_))
        ));
    }

    #[test]
    fn route_mapping_rejects_non_32_byte_group_route_id() {
        // The `h` tag is the hex of the 32-byte nostr_group_id
        // (spec/transports/nostr.md); a short route id must be rejected at the
        // boundary, not passed through into the transport envelope.
        let event = signed_kind_445_event(vec![vec!["h".into(), "aa55".into()]], "encrypted body");

        assert!(matches!(
            event.to_transport_message(),
            Err(NostrPeelerError::Malformed(_))
        ));
    }

    #[test]
    fn single_tag_enforcement_counts_valueless_duplicate_tags() {
        // A valueless `["p"]` next to `["p", <valid>]` must not collapse into
        // "exactly one value" — duplicate occurrences are rejected regardless
        // of whether each carries a value. Same contract for `h`.
        let mut gift_wrap = NostrTransportEvent {
            id: String::new(),
            pubkey: "44".repeat(32),
            created_at: 1_700_000_001,
            kind: KIND_NIP59_GIFT_WRAP,
            tags: vec![vec!["p".into()], vec!["p".into(), "55".repeat(32)]],
            content: "gift wrap body".into(),
            sig: None,
        };
        gift_wrap.id = gift_wrap.computed_id();
        assert!(matches!(
            gift_wrap.to_transport_message(),
            Err(NostrPeelerError::Malformed(_))
        ));

        let group = signed_kind_445_event(
            vec![vec!["h".into()], vec!["h".into(), "aa".repeat(32)]],
            "encrypted body",
        );
        assert!(matches!(
            group.to_transport_message(),
            Err(NostrPeelerError::Malformed(_))
        ));

        // A single matching tag with no value is malformed, not missing.
        let mut valueless = NostrTransportEvent {
            id: String::new(),
            pubkey: "44".repeat(32),
            created_at: 1_700_000_001,
            kind: KIND_NIP59_GIFT_WRAP,
            tags: vec![vec!["p".into()]],
            content: "gift wrap body".into(),
            sig: None,
        };
        valueless.id = valueless.computed_id();
        assert!(matches!(
            valueless.to_transport_message(),
            Err(NostrPeelerError::Malformed(_))
        ));
    }

    #[test]
    fn computed_id_matches_sdk_signed_event_id() {
        // `to_transport_message` verifies self-reported ids against
        // `computed_id`, so the local NIP-01 id computation must agree with the
        // Nostr SDK's — including for content that needs JSON escaping.
        let content = "line\nbreak \"quote\" back\\slash tab\t unicode ✨ control \u{1}";
        let signed = nostr::EventBuilder::new(
            nostr::Kind::Custom(KIND_MARMOT_GROUP_MESSAGE as u16),
            content,
        )
        .tags([nostr::Tag::custom(
            nostr::TagKind::custom("h"),
            [hex::encode([0x99; 32])],
        )])
        .sign_with_keys(&nostr::Keys::generate())
        .expect("sign kind-445");

        let dto = NostrTransportEvent::from_nostr_event(&signed).unwrap();

        assert_eq!(dto.id, dto.computed_id());
        assert!(dto.to_transport_message().is_ok());
    }
}
