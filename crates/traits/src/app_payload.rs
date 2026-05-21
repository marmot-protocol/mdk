//! Typed application-message payloads carried inside Marmot MLS messages.
//!
//! Plain text messages may still be sent as raw UTF-8 bytes. Structured chat
//! updates use this small JSON envelope so app surfaces can subscribe to one
//! message stream and branch on a stable `kind`.

use serde::{Deserialize, Serialize};

pub const MARMOT_APP_MESSAGE_PAYLOAD_V1: &str = "marmot.app_message.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarmotAppMessageEnvelopeV1 {
    pub marmot_payload: String,
    #[serde(flatten)]
    pub payload: MarmotAppMessagePayloadV1,
}

impl MarmotAppMessageEnvelopeV1 {
    pub fn new(payload: MarmotAppMessagePayloadV1) -> Self {
        Self {
            marmot_payload: MARMOT_APP_MESSAGE_PAYLOAD_V1.to_owned(),
            payload,
        }
    }

    pub fn reaction(
        target_message_id: impl Into<String>,
        emoji: impl Into<String>,
        action: MarmotReactionActionV1,
    ) -> Self {
        Self::new(MarmotAppMessagePayloadV1::Reaction {
            target_message_id: target_message_id.into(),
            emoji: emoji.into(),
            action,
        })
    }

    pub fn delete(target_message_id: impl Into<String>) -> Self {
        Self::new(MarmotAppMessagePayloadV1::Delete {
            target_message_id: target_message_id.into(),
        })
    }

    pub fn retry_group_convergence(target_message_id: impl Into<String>) -> Self {
        Self::new(MarmotAppMessagePayloadV1::Retry {
            target_message_id: target_message_id.into(),
            scope: MarmotRetryScopeV1::GroupConvergence,
        })
    }

    pub fn media(reference: MarmotMediaReferenceV1, caption: Option<String>) -> Self {
        Self::new(MarmotAppMessagePayloadV1::Media { reference, caption })
    }

    pub fn reply(target_message_id: impl Into<String>, text: impl Into<String>) -> Self {
        Self::new(MarmotAppMessagePayloadV1::Reply {
            target_message_id: target_message_id.into(),
            text: text.into(),
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.marmot_payload != MARMOT_APP_MESSAGE_PAYLOAD_V1 {
            return Err("unexpected Marmot app-message payload marker".into());
        }
        self.payload.validate()
    }

    pub fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Option<Self>, serde_json::Error> {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return Ok(None);
        };
        if value
            .get("marmot_payload")
            .and_then(serde_json::Value::as_str)
            != Some(MARMOT_APP_MESSAGE_PAYLOAD_V1)
        {
            return Ok(None);
        }
        serde_json::from_value(value).map(Some)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MarmotAppMessagePayloadV1 {
    Reaction {
        target_message_id: String,
        emoji: String,
        action: MarmotReactionActionV1,
    },
    Delete {
        target_message_id: String,
    },
    Retry {
        target_message_id: String,
        scope: MarmotRetryScopeV1,
    },
    Media {
        reference: MarmotMediaReferenceV1,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caption: Option<String>,
    },
    Reply {
        target_message_id: String,
        text: String,
    },
}

impl MarmotAppMessagePayloadV1 {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            MarmotAppMessagePayloadV1::Reaction {
                target_message_id,
                emoji,
                action,
            } => {
                validate_message_ref(target_message_id)?;
                if matches!(action, MarmotReactionActionV1::Add) && emoji.trim().is_empty() {
                    return Err("reaction add requires a non-empty emoji".into());
                }
            }
            MarmotAppMessagePayloadV1::Delete { target_message_id } => {
                validate_message_ref(target_message_id)?;
            }
            MarmotAppMessagePayloadV1::Retry {
                target_message_id, ..
            } => {
                validate_message_ref(target_message_id)?;
            }
            MarmotAppMessagePayloadV1::Media { reference, .. } => {
                reference.validate()?;
            }
            MarmotAppMessagePayloadV1::Reply {
                target_message_id,
                text,
            } => {
                validate_message_ref(target_message_id)?;
                if text.trim().is_empty() {
                    return Err("reply requires non-empty text".into());
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarmotReactionActionV1 {
    Add,
    Remove,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarmotRetryScopeV1 {
    GroupConvergence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarmotMediaReferenceV1 {
    pub file_hash_hex: String,
    pub file_name: String,
    pub media_type: String,
    pub size_bytes: u64,
}

impl MarmotMediaReferenceV1 {
    pub fn validate(&self) -> Result<(), String> {
        let hash = hex::decode(&self.file_hash_hex).map_err(|_| "media hash must be hex")?;
        if hash.len() != 32 {
            return Err("media hash must be 32 bytes".into());
        }
        if self.file_name.trim().is_empty() {
            return Err("media file name cannot be empty".into());
        }
        if self.media_type.trim().is_empty() {
            return Err("media type cannot be empty".into());
        }
        if self.size_bytes == 0 {
            return Err("media size must be greater than zero".into());
        }
        Ok(())
    }
}

pub fn display_text_for_app_message(payload: &MarmotAppMessagePayloadV1) -> String {
    match payload {
        MarmotAppMessagePayloadV1::Reaction {
            target_message_id,
            emoji,
            action,
        } => match action {
            MarmotReactionActionV1::Add => format!("reacted {emoji} to {target_message_id}"),
            MarmotReactionActionV1::Remove => format!("removed reaction from {target_message_id}"),
        },
        MarmotAppMessagePayloadV1::Delete { target_message_id } => {
            format!("deleted {target_message_id}")
        }
        MarmotAppMessagePayloadV1::Retry {
            target_message_id,
            scope,
        } => match scope {
            MarmotRetryScopeV1::GroupConvergence => {
                format!("requested retry for {target_message_id}")
            }
        },
        MarmotAppMessagePayloadV1::Media { reference, caption } => match caption {
            Some(caption) if !caption.is_empty() => {
                format!("media {}: {caption}", reference.file_name)
            }
            _ => format!("media {}", reference.file_name),
        },
        // A reply renders as a normal message; its display text is the body.
        MarmotAppMessagePayloadV1::Reply { text, .. } => text.clone(),
    }
}

fn validate_message_ref(target_message_id: &str) -> Result<(), String> {
    if target_message_id.trim().is_empty() {
        return Err("target message id cannot be empty".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reaction_envelope_round_trips() {
        let envelope =
            MarmotAppMessageEnvelopeV1::reaction("abc123", "+", MarmotReactionActionV1::Add);

        envelope.validate().unwrap();
        let encoded = envelope.encode().unwrap();
        let decoded = MarmotAppMessageEnvelopeV1::decode(&encoded).unwrap();

        assert_eq!(decoded, Some(envelope));
    }

    #[test]
    fn retry_envelope_round_trips() {
        let envelope = MarmotAppMessageEnvelopeV1::retry_group_convergence("abc123");

        envelope.validate().unwrap();
        let decoded = MarmotAppMessageEnvelopeV1::decode(&envelope.encode().unwrap()).unwrap();

        assert_eq!(decoded, Some(envelope));
    }

    #[test]
    fn media_reference_validation_rejects_bad_hash() {
        let envelope = MarmotAppMessageEnvelopeV1::media(
            MarmotMediaReferenceV1 {
                file_hash_hex: "not-hex".into(),
                file_name: "diagram.png".into(),
                media_type: "image/png".into(),
                size_bytes: 1234,
            },
            None,
        );

        assert!(envelope.validate().unwrap_err().contains("hex"));
    }

    #[test]
    fn non_marmot_json_is_ignored() {
        let decoded = MarmotAppMessageEnvelopeV1::decode(br#"{"kind":"reaction"}"#).unwrap();

        assert_eq!(decoded, None);
    }
}
