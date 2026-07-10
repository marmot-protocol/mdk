//! Encrypted, per-account composer draft persistence.

use storage_sqlite::{StoredMessageDraft, StoredMessageDraftAttachment};

use crate::{AppError, MarmotApp};

#[derive(Clone, Debug, PartialEq)]
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

#[derive(Clone, Debug, PartialEq)]
pub struct MessageDraft {
    pub group_id_hex: String,
    pub content: String,
    pub reply_to_message_id_hex: Option<String>,
    pub media_attachments: Vec<MessageDraftAttachment>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
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

impl MarmotApp {
    pub fn message_drafts(&self, account_ref: &str) -> Result<Vec<MessageDraft>, AppError> {
        let account = self.account_home().account(account_ref)?;
        self.ensure_account_state(&account.label)?;
        Ok(self
            .account_storage(&account.label)?
            .message_drafts()?
            .into_iter()
            .map(Into::into)
            .collect())
    }

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
        self.group(&account.label, group_id_hex)?
            .ok_or_else(|| AppError::UnknownGroup(group_id_hex.to_owned()))?;
        let attachments = media_attachments
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        Ok(self
            .account_storage(&account.label)?
            .save_message_draft(group_id_hex, content, reply_to_message_id_hex, &attachments)?
            .into())
    }

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
