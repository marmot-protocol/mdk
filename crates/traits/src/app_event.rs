//! Inner Marmot app event — the unsigned Nostr-shaped payload carried inside an
//! MLS application message.
//!
//! Per `spec/foundation/application-messages.md`, the plaintext of an MLS
//! application message decodes to a Nostr event minus `sig`:
//! `{ id, pubkey, created_at, kind, tags, content }`. `id` is the canonical
//! NIP-01 event id computed over `[0, pubkey, created_at, kind, tags, content]`.
//! MLS authenticates the sender; `pubkey` identifies the authoring Marmot
//! account (its Nostr/MLS-leaf identity). Decoders MUST reject a payload whose
//! `id` does not match, and callers MUST verify `pubkey` equals the
//! MLS-authenticated sender.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Nostr `kind` values used as Marmot inner app events.
pub const MARMOT_APP_EVENT_KIND_DELETE: u64 = 5;
pub const MARMOT_APP_EVENT_KIND_REACTION: u64 = 7;
pub const MARMOT_APP_EVENT_KIND_CHAT: u64 = 9;
pub const MARMOT_APP_EVENT_KIND_AGENT_STREAM_START: u64 = 1200;

/// Tag names. `e`/`q` are standard Nostr reference tags; the `stream-*` set is
/// owned by the agent-text-stream feature.
pub const EVENT_REF_TAG: &str = "e";
pub const QUOTE_REF_TAG: &str = "q";
pub const STREAM_TAG: &str = "stream";
pub const STREAM_TYPE_TAG: &str = "stream-type";
pub const STREAM_FINAL_KIND_TAG: &str = "final-kind";
pub const STREAM_ROUTE_TAG: &str = "route";
pub const STREAM_BROKER_TAG: &str = "broker";
pub const STREAM_PARENT_TAG: &str = "parent";
pub const STREAM_START_TAG: &str = "stream-start";
pub const STREAM_HASH_TAG: &str = "stream-hash";
pub const STREAM_CHUNKS_TAG: &str = "stream-chunks";

/// An unsigned Nostr event carried as the plaintext of an MLS application
/// message. Same fields as a Nostr event except `sig`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarmotAppEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MarmotAppEventError {
    #[error("marmot app event JSON: {0}")]
    Json(String),
    #[error("marmot app event id mismatch")]
    IdMismatch { expected: String, found: String },
    #[error("marmot app event pubkey mismatch")]
    PubkeyMismatch { expected: String, found: String },
}

impl MarmotAppEvent {
    /// Build an unsigned inner app event, computing the canonical NIP-01 id.
    pub fn new(
        pubkey: impl Into<String>,
        created_at: u64,
        kind: u64,
        tags: Vec<Vec<String>>,
        content: impl Into<String>,
    ) -> Self {
        let pubkey = pubkey.into();
        let content = content.into();
        let id = canonical_event_id(&pubkey, created_at, kind, &tags, &content);
        Self {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
        }
    }

    /// Serde struct-order JSON bytes for the MLS application-message plaintext.
    ///
    /// This is not NIP-01 canonical JSON: it serializes the struct fields in
    /// declaration order rather than the canonical `[0,pubkey,...]` array form.
    /// The `id` is the canonical NIP-01 id and is validated separately on
    /// decode via [`Self::validate_id`].
    pub fn encode(&self) -> Result<Vec<u8>, MarmotAppEventError> {
        serde_json::to_vec(self).map_err(|err| MarmotAppEventError::Json(err.to_string()))
    }

    /// Decode MLS plaintext bytes and strictly validate the canonical id.
    pub fn decode(bytes: &[u8]) -> Result<Self, MarmotAppEventError> {
        let event: Self = serde_json::from_slice(bytes)
            .map_err(|err| MarmotAppEventError::Json(err.to_string()))?;
        event.validate_id()?;
        Ok(event)
    }

    /// Recompute the canonical id and reject a mismatch.
    pub fn validate_id(&self) -> Result<(), MarmotAppEventError> {
        let expected = canonical_event_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        );
        if expected != self.id {
            return Err(MarmotAppEventError::IdMismatch {
                expected,
                found: self.id.clone(),
            });
        }
        Ok(())
    }

    /// Verify the inner author equals the MLS-authenticated sender pubkey.
    pub fn validate_sender(&self, mls_sender_pubkey_hex: &str) -> Result<(), MarmotAppEventError> {
        if self.pubkey != mls_sender_pubkey_hex {
            return Err(MarmotAppEventError::PubkeyMismatch {
                expected: mls_sender_pubkey_hex.to_owned(),
                found: self.pubkey.clone(),
            });
        }
        Ok(())
    }

    /// First value of the named tag (`tag[0] == name` → `tag[1]`).
    pub fn first_tag_value(&self, name: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
            .and_then(|tag| tag.get(1))
            .map(String::as_str)
    }
}

/// Canonical NIP-01 event id: lowercase hex `sha256` of the compact JSON array
/// `[0, pubkey, created_at, kind, tags, content]`.
pub fn canonical_event_id(
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
    let bytes = serde_json::to_vec(&preimage).expect("event id preimage serialization cannot fail");
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_event_round_trips_and_validates() {
        let event = MarmotAppEvent::new(
            "aa".repeat(32),
            1_700_000_000,
            MARMOT_APP_EVENT_KIND_CHAT,
            vec![],
            "hello",
        );
        let decoded = MarmotAppEvent::decode(&event.encode().unwrap()).unwrap();
        assert_eq!(decoded, event);
        decoded.validate_sender(&"aa".repeat(32)).unwrap();
    }

    #[test]
    fn tampered_content_fails_id_check() {
        let mut event =
            MarmotAppEvent::new("bb".repeat(32), 1, MARMOT_APP_EVENT_KIND_CHAT, vec![], "hi");
        event.content = "tampered".into();
        let bytes = serde_json::to_vec(&event).unwrap();
        assert!(matches!(
            MarmotAppEvent::decode(&bytes),
            Err(MarmotAppEventError::IdMismatch { .. })
        ));
    }

    #[test]
    fn wrong_sender_is_rejected() {
        let event =
            MarmotAppEvent::new("cc".repeat(32), 1, MARMOT_APP_EVENT_KIND_CHAT, vec![], "hi");
        assert!(matches!(
            event.validate_sender(&"dd".repeat(32)),
            Err(MarmotAppEventError::PubkeyMismatch { .. })
        ));
    }

    #[test]
    fn canonical_id_is_deterministic_hex32() {
        let id = canonical_event_id(&"00".repeat(32), 0, MARMOT_APP_EVENT_KIND_CHAT, &[], "");
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        // Stable across calls with identical inputs.
        assert_eq!(
            id,
            canonical_event_id(&"00".repeat(32), 0, MARMOT_APP_EVENT_KIND_CHAT, &[], "")
        );
    }

    #[test]
    fn stream_tags_round_trip() {
        let event = MarmotAppEvent::new(
            "ee".repeat(32),
            42,
            MARMOT_APP_EVENT_KIND_CHAT,
            vec![
                vec![STREAM_TAG.into(), "abc123".into()],
                vec![STREAM_START_TAG.into(), "deadbeef".into()],
            ],
            "final text",
        );
        let decoded = MarmotAppEvent::decode(&event.encode().unwrap()).unwrap();
        assert_eq!(decoded.first_tag_value(STREAM_TAG), Some("abc123"));
        assert_eq!(decoded.first_tag_value(STREAM_START_TAG), Some("deadbeef"));
    }
}
