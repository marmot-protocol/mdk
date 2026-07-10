//! Encrypted, per-account composer draft persistence.

use std::collections::HashSet;
use std::fmt;

use cgka_traits::storage::StorageError;
use storage_sqlite::{
    StoredMessageDraft, StoredMessageDraftAttachment, StoredMessageDraftAttachmentSummary,
    StoredMessageDraftSummary,
};

use crate::{AppError, MarmotApp};

/// One attachment retained with a composer draft. The plaintext bytes live only
/// in the account's encrypted SQLCipher database and are returned only by the
/// single-draft load API.
#[derive(Clone, PartialEq)]
pub struct MessageDraftAttachment {
    pub id: String,
    pub file_name: String,
    pub media_type: String,
    pub plaintext: Vec<u8>,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
    pub duration_seconds: Option<f64>,
    pub waveform_samples: Vec<f64>,
}

impl fmt::Debug for MessageDraftAttachment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageDraftAttachment")
            .field("plaintext_len", &self.plaintext.len())
            .field("waveform_sample_count", &self.waveform_samples.len())
            .finish()
    }
}

/// A fully hydrated composer draft for one group.
#[derive(Clone, PartialEq)]
pub struct MessageDraft {
    pub group_id_hex: String,
    pub content: String,
    pub reply_to_message_id_hex: Option<String>,
    pub media_attachments: Vec<MessageDraftAttachment>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl fmt::Debug for MessageDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let attachment_bytes = self
            .media_attachments
            .iter()
            .map(|attachment| attachment.plaintext.len())
            .sum::<usize>();
        formatter
            .debug_struct("MessageDraft")
            .field("content_len", &self.content.len())
            .field("attachment_count", &self.media_attachments.len())
            .field("attachment_bytes", &attachment_bytes)
            .field("created_at_ms", &self.created_at_ms)
            .field("updated_at_ms", &self.updated_at_ms)
            .finish()
    }
}

/// Attachment metadata used by draft-list previews without loading plaintext
/// attachment bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct MessageDraftAttachmentSummary {
    pub id: String,
    pub file_name: String,
    pub media_type: String,
    pub plaintext_size: u64,
}

impl fmt::Debug for MessageDraftAttachmentSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageDraftAttachmentSummary")
            .field("plaintext_size", &self.plaintext_size)
            .finish()
    }
}

/// A metadata-only draft-list row. Call [`MarmotApp::message_draft`] to hydrate
/// attachment plaintext for the composer that is being restored.
#[derive(Clone, PartialEq, Eq)]
pub struct MessageDraftSummary {
    pub group_id_hex: String,
    pub content: String,
    pub reply_to_message_id_hex: Option<String>,
    pub media_attachments: Vec<MessageDraftAttachmentSummary>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl fmt::Debug for MessageDraftSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let attachment_bytes = self
            .media_attachments
            .iter()
            .map(|attachment| attachment.plaintext_size)
            .sum::<u64>();
        formatter
            .debug_struct("MessageDraftSummary")
            .field("content_len", &self.content.len())
            .field("attachment_count", &self.media_attachments.len())
            .field("attachment_bytes", &attachment_bytes)
            .field("created_at_ms", &self.created_at_ms)
            .field("updated_at_ms", &self.updated_at_ms)
            .finish()
    }
}

impl From<StoredMessageDraftAttachment> for MessageDraftAttachment {
    fn from(value: StoredMessageDraftAttachment) -> Self {
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

impl From<MessageDraftAttachment> for StoredMessageDraftAttachment {
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

impl From<StoredMessageDraft> for MessageDraft {
    fn from(value: StoredMessageDraft) -> Self {
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

impl From<StoredMessageDraftAttachmentSummary> for MessageDraftAttachmentSummary {
    fn from(value: StoredMessageDraftAttachmentSummary) -> Self {
        Self {
            id: value.id,
            file_name: value.file_name,
            media_type: value.media_type,
            plaintext_size: value.plaintext_size,
        }
    }
}

impl From<StoredMessageDraftSummary> for MessageDraftSummary {
    fn from(value: StoredMessageDraftSummary) -> Self {
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

impl MarmotApp {
    /// List metadata-only composer drafts newest-first. Attachment plaintext is
    /// deliberately omitted; hydrate one selected composer with
    /// [`MarmotApp::message_draft`]. Hosts are responsible for deleting empty or
    /// sent drafts, while deleting a group cascades its remaining draft.
    pub fn message_drafts(&self, account_ref: &str) -> Result<Vec<MessageDraftSummary>, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        Ok(self
            .account_storage(&account.label)?
            .message_drafts()?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Load one fully hydrated composer draft, including attachment plaintext.
    pub fn message_draft(
        &self,
        account_ref: &str,
        group_id_hex: &str,
    ) -> Result<Option<MessageDraft>, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        Ok(self
            .account_storage(&account.label)?
            .message_draft(group_id_hex)?
            .map(Into::into))
    }

    /// Validate and upsert one composer draft in the account's encrypted store.
    /// Attachment identifiers must be unique, and all numeric media metadata
    /// must be finite so callers receive a typed validation error rather than a
    /// storage-backend failure.
    pub fn save_message_draft(
        &self,
        account_ref: &str,
        group_id_hex: &str,
        content: &str,
        reply_to_message_id_hex: Option<&str>,
        media_attachments: Vec<MessageDraftAttachment>,
    ) -> Result<MessageDraft, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        validate_message_draft_attachments(&media_attachments)?;
        let attachments = media_attachments
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        let result = self.account_storage(&account.label)?.save_message_draft(
            group_id_hex,
            content,
            reply_to_message_id_hex,
            &attachments,
        );
        match result {
            Ok(draft) => Ok(draft.into()),
            Err(StorageError::NotFound) => Err(AppError::UnknownGroup(group_id_hex.to_owned())),
            Err(error) => Err(error.into()),
        }
    }

    /// Delete one composer draft. Missing drafts are treated as already deleted.
    pub fn delete_message_draft(
        &self,
        account_ref: &str,
        group_id_hex: &str,
    ) -> Result<(), AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        self.account_storage(&account.label)?
            .delete_message_draft(group_id_hex)?;
        Ok(())
    }
}

fn validate_message_draft_attachments(
    attachments: &[MessageDraftAttachment],
) -> Result<(), AppError> {
    let mut ids = HashSet::with_capacity(attachments.len());
    for attachment in attachments {
        if attachment.id.trim().is_empty() {
            return Err(AppError::InvalidMessageDraft(
                "attachment id must not be empty".to_owned(),
            ));
        }
        if !ids.insert(attachment.id.as_str()) {
            return Err(AppError::InvalidMessageDraft(
                "attachment ids must be unique".to_owned(),
            ));
        }
        if attachment
            .duration_seconds
            .is_some_and(|duration| !duration.is_finite())
        {
            return Err(AppError::InvalidMessageDraft(
                "attachment duration must be finite".to_owned(),
            ));
        }
        if attachment
            .waveform_samples
            .iter()
            .any(|sample| !sample.is_finite())
        {
            return Err(AppError::InvalidMessageDraft(
                "attachment waveform samples must be finite".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attachment(id: &str) -> MessageDraftAttachment {
        MessageDraftAttachment {
            id: id.to_owned(),
            file_name: "private-file-name.txt".to_owned(),
            media_type: "text/private".to_owned(),
            plaintext: b"private attachment bytes".to_vec(),
            dim: Some("private-dimensions".to_owned()),
            thumbhash: Some("private-thumbhash".to_owned()),
            duration_seconds: Some(1.5),
            waveform_samples: vec![0.25, 0.75],
        }
    }

    #[test]
    fn draft_debug_output_is_redacted() {
        let draft = MessageDraft {
            group_id_hex: "private-group-id".to_owned(),
            content: "private draft content".to_owned(),
            reply_to_message_id_hex: Some("private-message-id".to_owned()),
            media_attachments: vec![attachment("private-attachment-id")],
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

    #[test]
    fn draft_attachment_validation_rejects_bad_host_input() {
        let duplicate = vec![attachment("same-id"), attachment("same-id")];
        assert!(matches!(
            validate_message_draft_attachments(&duplicate),
            Err(AppError::InvalidMessageDraft(details)) if details.contains("unique")
        ));

        let mut non_finite_duration = attachment("duration");
        non_finite_duration.duration_seconds = Some(f64::INFINITY);
        assert!(matches!(
            validate_message_draft_attachments(&[non_finite_duration]),
            Err(AppError::InvalidMessageDraft(details)) if details.contains("duration")
        ));

        let mut non_finite_waveform = attachment("waveform");
        non_finite_waveform.waveform_samples = vec![f64::NAN];
        assert!(matches!(
            validate_message_draft_attachments(&[non_finite_waveform]),
            Err(AppError::InvalidMessageDraft(details)) if details.contains("waveform")
        ));
    }
}
