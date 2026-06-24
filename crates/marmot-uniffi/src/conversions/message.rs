//! Message-record and message-subscription-update FFI conversions.

use marmot_app::{
    AppMessageRecord, ReceivedMessage, RuntimeMessageReceived, RuntimeMessageUpdate,
    SecureDeleteExpiredResult,
};

use super::common::{MessageTagFfi, markdown_content_tokens, message_tags_ffi};
use crate::markdown::MarkdownDocumentFfi;

#[derive(Clone, Debug, uniffi::Record)]
pub struct AppMessageRecordFfi {
    pub message_id_hex: String,
    pub direction: String,
    pub group_id_hex: String,
    pub sender: String,
    pub plaintext: String,
    pub content_tokens: MarkdownDocumentFfi,
    /// Nostr `kind` of the inner Marmot app event (9 chat, 7 reaction, …).
    pub kind: u64,
    /// Nostr `tags` of the inner Marmot app event.
    pub tags: Vec<MessageTagFfi>,
    pub recorded_at: u64,
    pub received_at: u64,
}

impl From<AppMessageRecord> for AppMessageRecordFfi {
    fn from(value: AppMessageRecord) -> Self {
        let content_tokens = markdown_content_tokens(value.kind, &value.plaintext);
        Self {
            message_id_hex: value.message_id_hex,
            direction: value.direction,
            group_id_hex: value.group_id_hex,
            sender: value.sender,
            plaintext: value.plaintext,
            content_tokens,
            kind: value.kind,
            tags: message_tags_ffi(value.tags),
            recorded_at: value.recorded_at,
            received_at: value.received_at,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct SecureDeleteExpiredResultFfi {
    pub pruned_messages: u64,
    pub media_ciphertext_sha256: Vec<String>,
}

impl From<SecureDeleteExpiredResult> for SecureDeleteExpiredResultFfi {
    fn from(value: SecureDeleteExpiredResult) -> Self {
        Self {
            pruned_messages: value.pruned_messages,
            media_ciphertext_sha256: value.media_ciphertext_sha256,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ReceivedMessageFfi {
    pub message_id_hex: String,
    pub group_id_hex: String,
    pub sender: String,
    pub sender_display_name: Option<String>,
    pub plaintext: String,
    pub content_tokens: MarkdownDocumentFfi,
    /// Nostr `kind` of the inner Marmot app event.
    pub kind: u64,
    /// Nostr `tags` of the inner Marmot app event.
    pub tags: Vec<MessageTagFfi>,
    /// Source-event timestamp (seconds since epoch) for the MLS-delivered
    /// message. Clients should sort the timeline by this value so chronology
    /// reflects send time, not delivery time. Zero means the timestamp was
    /// unavailable at decode time.
    pub recorded_at: u64,
}

impl From<&ReceivedMessage> for ReceivedMessageFfi {
    fn from(value: &ReceivedMessage) -> Self {
        Self {
            message_id_hex: value.message_id_hex.clone(),
            group_id_hex: hex::encode(value.group_id.as_slice()),
            sender: value.sender.clone(),
            sender_display_name: value.sender_display_name.clone(),
            plaintext: value.plaintext.clone(),
            content_tokens: markdown_content_tokens(value.kind, &value.plaintext),
            kind: value.kind,
            tags: message_tags_ffi(value.tags.clone()),
            recorded_at: value.recorded_at,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct RuntimeMessageReceivedFfi {
    pub account_id_hex: String,
    pub account_label: String,
    pub message: ReceivedMessageFfi,
}

impl From<RuntimeMessageReceived> for RuntimeMessageReceivedFfi {
    fn from(value: RuntimeMessageReceived) -> Self {
        Self {
            account_id_hex: value.account_id_hex,
            account_label: value.account_label,
            message: ReceivedMessageFfi::from(&value.message),
        }
    }
}

/// A unified update from a messages subscription. Each variant carries enough
/// context for host apps to update an in-memory timeline without holding
/// onto the underlying marmot-app types.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum MessageUpdateFfi {
    /// A raw message update: chat, reply, media, reaction, delete, or the kind-9
    /// stream-final. Materialized timeline pages also include kind-1200 stream
    /// starts as `TimelineMessageRecordFfi` rows.
    Message { received: RuntimeMessageReceivedFfi },
    /// A kind-1200 agent text stream start — the signal to open the QUIC
    /// preview for raw message subscribers. Its stream id, route, and brokers
    /// live on `message.tags`.
    AgentStreamStarted { received: RuntimeMessageReceivedFfi },
}

impl From<RuntimeMessageUpdate> for MessageUpdateFfi {
    fn from(value: RuntimeMessageUpdate) -> Self {
        match value {
            RuntimeMessageUpdate::Message(m) => Self::Message { received: m.into() },
            RuntimeMessageUpdate::AgentStreamStarted(m) => Self::AgentStreamStarted {
                received: RuntimeMessageReceivedFfi {
                    account_id_hex: m.account_id_hex,
                    account_label: m.account_label,
                    message: ReceivedMessageFfi::from(&m.message),
                },
            },
        }
    }
}
