//! Composer draft FFI records and conversions.

use std::fmt;

use marmot_app::{
    MessageDraft, MessageDraftAttachment, MessageDraftAttachmentSummary, MessageDraftSummary,
};

/// One fully hydrated draft attachment crossing the host boundary.
#[derive(Clone, uniffi::Record)]
pub struct MessageDraftAttachmentFfi {
    pub id: String,
    pub file_name: String,
    pub media_type: String,
    pub plaintext: Vec<u8>,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
    pub duration_seconds: Option<f64>,
    pub waveform_samples: Vec<f64>,
}

impl fmt::Debug for MessageDraftAttachmentFfi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageDraftAttachmentFfi")
            .field("plaintext_len", &self.plaintext.len())
            .field("waveform_sample_count", &self.waveform_samples.len())
            .finish()
    }
}

impl From<MessageDraftAttachment> for MessageDraftAttachmentFfi {
    fn from(value: MessageDraftAttachment) -> Self {
        Self {
            id: value.id,
            file_name: value.file_name,
            media_type: value.media_type,
            plaintext: value.plaintext,
            dim: value.dim,
            thumbhash: value.thumbhash,
            duration_seconds: value.duration_seconds,
            waveform_samples: value.waveform_samples,
        }
    }
}

impl From<MessageDraftAttachmentFfi> for MessageDraftAttachment {
    fn from(value: MessageDraftAttachmentFfi) -> Self {
        Self {
            id: value.id,
            file_name: value.file_name,
            media_type: value.media_type,
            plaintext: value.plaintext,
            dim: value.dim,
            thumbhash: value.thumbhash,
            duration_seconds: value.duration_seconds,
            waveform_samples: value.waveform_samples,
        }
    }
}

/// One fully hydrated composer draft returned for a selected group.
#[derive(Clone, uniffi::Record)]
pub struct MessageDraftFfi {
    pub group_id_hex: String,
    pub content: String,
    pub reply_to_message_id_hex: Option<String>,
    pub media_attachments: Vec<MessageDraftAttachmentFfi>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl fmt::Debug for MessageDraftFfi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let attachment_bytes = self
            .media_attachments
            .iter()
            .map(|attachment| attachment.plaintext.len())
            .sum::<usize>();
        formatter
            .debug_struct("MessageDraftFfi")
            .field("content_len", &self.content.len())
            .field("attachment_count", &self.media_attachments.len())
            .field("attachment_bytes", &attachment_bytes)
            .field("created_at_ms", &self.created_at_ms)
            .field("updated_at_ms", &self.updated_at_ms)
            .finish()
    }
}

impl From<MessageDraft> for MessageDraftFfi {
    fn from(value: MessageDraft) -> Self {
        Self {
            group_id_hex: value.group_id_hex,
            content: value.content,
            reply_to_message_id_hex: value.reply_to_message_id_hex,
            media_attachments: value
                .media_attachments
                .into_iter()
                .map(Into::into)
                .collect(),
            created_at_ms: value.created_at_ms,
            updated_at_ms: value.updated_at_ms,
        }
    }
}

/// Attachment metadata for a draft-list preview. Plaintext bytes are omitted.
#[derive(Clone, uniffi::Record)]
pub struct MessageDraftAttachmentSummaryFfi {
    pub id: String,
    pub file_name: String,
    pub media_type: String,
    pub plaintext_size: u64,
}

impl fmt::Debug for MessageDraftAttachmentSummaryFfi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageDraftAttachmentSummaryFfi")
            .field("plaintext_size", &self.plaintext_size)
            .finish()
    }
}

impl From<MessageDraftAttachmentSummary> for MessageDraftAttachmentSummaryFfi {
    fn from(value: MessageDraftAttachmentSummary) -> Self {
        Self {
            id: value.id,
            file_name: value.file_name,
            media_type: value.media_type,
            plaintext_size: value.plaintext_size,
        }
    }
}

/// Metadata-only draft-list row. Use `messageDraft` to hydrate one selected
/// composer and its attachment plaintext.
#[derive(Clone, uniffi::Record)]
pub struct MessageDraftSummaryFfi {
    pub group_id_hex: String,
    pub content: String,
    pub reply_to_message_id_hex: Option<String>,
    pub media_attachments: Vec<MessageDraftAttachmentSummaryFfi>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl fmt::Debug for MessageDraftSummaryFfi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let attachment_bytes = self
            .media_attachments
            .iter()
            .map(|attachment| attachment.plaintext_size)
            .sum::<u64>();
        formatter
            .debug_struct("MessageDraftSummaryFfi")
            .field("content_len", &self.content.len())
            .field("attachment_count", &self.media_attachments.len())
            .field("attachment_bytes", &attachment_bytes)
            .field("created_at_ms", &self.created_at_ms)
            .field("updated_at_ms", &self.updated_at_ms)
            .finish()
    }
}

impl From<MessageDraftSummary> for MessageDraftSummaryFfi {
    fn from(value: MessageDraftSummary) -> Self {
        Self {
            group_id_hex: value.group_id_hex,
            content: value.content,
            reply_to_message_id_hex: value.reply_to_message_id_hex,
            media_attachments: value
                .media_attachments
                .into_iter()
                .map(Into::into)
                .collect(),
            created_at_ms: value.created_at_ms,
            updated_at_ms: value.updated_at_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft_ffi_debug_output_is_redacted() {
        let draft = MessageDraftFfi {
            group_id_hex: "private-group-id".to_owned(),
            content: "private draft content".to_owned(),
            reply_to_message_id_hex: Some("private-message-id".to_owned()),
            media_attachments: vec![MessageDraftAttachmentFfi {
                id: "private-attachment-id".to_owned(),
                file_name: "private-file-name.txt".to_owned(),
                media_type: "text/private".to_owned(),
                plaintext: b"private attachment bytes".to_vec(),
                dim: Some("private-dimensions".to_owned()),
                thumbhash: Some("private-thumbhash".to_owned()),
                duration_seconds: Some(1.5),
                waveform_samples: vec![0.25, 0.75],
            }],
            created_at_ms: 10,
            updated_at_ms: 20,
        };

        let debug = format!("{draft:?}");
        assert!(debug.contains("attachment_count: 1"));
        assert!(debug.contains("attachment_bytes: 24"));
        for sensitive in [
            "private-group-id",
            "private draft content",
            "private-message-id",
            "private-attachment-id",
            "private-file-name",
            "private attachment bytes",
        ] {
            assert!(!debug.contains(sensitive));
        }
    }
}
