//! Composer draft FFI records and conversions.

use std::fmt;

use marmot_app::{
    MessageDraft, MessageDraftAttachment, MessageDraftAttachmentFileRequest,
    MessageDraftAttachmentInput, MessageDraftAttachmentSummary, MessageDraftSummary,
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

/// One attachment of a revisioned draft save: a new inline body, an
/// attachment the draft already holds, kept by id with its body untouched,
/// or the id of one to remove. An attachment the save does not name stays
/// in the draft. `Removed` deletes one (and its staged file); `Inline` with
/// a held id replaces its body and releases a staged file it had.
#[derive(Clone, uniffi::Enum)]
pub enum MessageDraftAttachmentInputFfi {
    Inline {
        attachment: MessageDraftAttachmentFfi,
    },
    Retained {
        id: String,
    },
    Removed {
        id: String,
    },
}

impl fmt::Debug for MessageDraftAttachmentInputFfi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline { attachment } => formatter
                .debug_struct("Inline")
                .field("attachment", attachment)
                .finish(),
            Self::Retained { .. } => formatter.debug_struct("Retained").finish_non_exhaustive(),
            Self::Removed { .. } => formatter.debug_struct("Removed").finish_non_exhaustive(),
        }
    }
}

impl From<MessageDraftAttachmentInputFfi> for MessageDraftAttachmentInput {
    fn from(value: MessageDraftAttachmentInputFfi) -> Self {
        match value {
            MessageDraftAttachmentInputFfi::Inline { attachment } => {
                Self::Inline(attachment.into())
            }
            MessageDraftAttachmentInputFfi::Retained { id } => Self::Retained(id),
            MessageDraftAttachmentInputFfi::Removed { id } => Self::Removed(id),
        }
    }
}

/// A host file to copy into the draft as attachment `id`. `source_path`
/// names a regular file the process can open (not a symlink);
/// `expected_size`, when set, must equal its length. The metadata is the
/// same as an inline draft attachment's. Debug output omits every field.
#[derive(Clone, uniffi::Record)]
pub struct MessageDraftAttachmentFileRequestFfi {
    pub id: String,
    pub source_path: String,
    pub expected_size: Option<u64>,
    pub file_name: String,
    pub media_type: String,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
    pub duration_seconds: Option<f64>,
    pub waveform_samples: Vec<f64>,
}

impl fmt::Debug for MessageDraftAttachmentFileRequestFfi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageDraftAttachmentFileRequestFfi")
            .finish_non_exhaustive()
    }
}

impl From<MessageDraftAttachmentFileRequestFfi> for MessageDraftAttachmentFileRequest {
    fn from(value: MessageDraftAttachmentFileRequestFfi) -> Self {
        Self {
            id: value.id,
            source_path: value.source_path,
            expected_size: value.expected_size,
            file_name: value.file_name,
            media_type: value.media_type,
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
        let attachment_summary = MessageDraftAttachmentSummaryFfi {
            id: draft.media_attachments[0].id.clone(),
            file_name: draft.media_attachments[0].file_name.clone(),
            media_type: draft.media_attachments[0].media_type.clone(),
            plaintext_size: 24,
        };
        let summary = MessageDraftSummaryFfi {
            group_id_hex: draft.group_id_hex.clone(),
            content: draft.content.clone(),
            reply_to_message_id_hex: draft.reply_to_message_id_hex.clone(),
            media_attachments: vec![attachment_summary.clone()],
            created_at_ms: 10,
            updated_at_ms: 20,
        };
        let attachment_debug = format!("{:?}", draft.media_attachments[0]);
        assert!(attachment_debug.contains("plaintext_len: 24"));
        assert!(attachment_debug.contains("waveform_sample_count: 2"));
        let summary_debug = format!("{summary:?}");
        assert!(summary_debug.contains("attachment_count: 1"));
        assert!(summary_debug.contains("attachment_bytes: 24"));
        let inputs = [
            MessageDraftAttachmentInputFfi::Inline {
                attachment: draft.media_attachments[0].clone(),
            },
            MessageDraftAttachmentInputFfi::Retained {
                id: draft.media_attachments[0].id.clone(),
            },
            MessageDraftAttachmentInputFfi::Removed {
                id: draft.media_attachments[0].id.clone(),
            },
        ];
        let file_request = MessageDraftAttachmentFileRequestFfi {
            id: draft.media_attachments[0].id.clone(),
            source_path: "/private-file-name.txt".to_owned(),
            expected_size: Some(24),
            file_name: draft.media_attachments[0].file_name.clone(),
            media_type: draft.media_attachments[0].media_type.clone(),
            dim: Some("private-dimensions".to_owned()),
            thumbhash: Some("private-thumbhash".to_owned()),
            duration_seconds: Some(1.5),
            waveform_samples: vec![0.25, 0.75],
        };
        for debug in [
            debug,
            attachment_debug,
            format!("{attachment_summary:?}"),
            summary_debug,
            format!("{inputs:?}"),
            format!("{file_request:?}"),
        ] {
            for sensitive in [
                "private-group-id",
                "private draft content",
                "private-message-id",
                "private-attachment-id",
                "private-file-name",
                "private attachment bytes",
                "text/private",
                "private-dimensions",
                "private-thumbhash",
            ] {
                assert!(!debug.contains(sensitive), "draft debug leaked {sensitive}");
            }
            assert!(!debug.contains(&format!("{:?}", b"private attachment bytes")));
            assert!(!debug.contains("0.25") && !debug.contains("0.75"));
        }
    }
}
