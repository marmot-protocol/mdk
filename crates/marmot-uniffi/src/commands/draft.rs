//! Encrypted, local composer draft commands.

use crate::conversions::{MessageDraftAttachmentFfi, MessageDraftFfi, group_id_from_hex};
use crate::errors::MarmotKitError;
use crate::{Marmot, optional_message_id_hex};

#[uniffi::export]
impl Marmot {
    /// All saved composer drafts for an account, newest-updated first.
    pub fn message_drafts(
        &self,
        account_ref: String,
    ) -> Result<Vec<MessageDraftFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .message_drafts(&account_ref)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// The saved composer draft for an account and MLS group, if one exists.
    pub fn message_draft(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<Option<MessageDraftFfi>, MarmotKitError> {
        let group_id_hex = canonical_group_id_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .message_draft(&account_ref, &group_id_hex)?
            .map(Into::into))
    }

    /// Upsert a composer draft into the account's encrypted SQLCipher store.
    pub fn save_message_draft(
        &self,
        account_ref: String,
        group_id_hex: String,
        content: String,
        reply_to_message_id_hex: Option<String>,
        media_attachments: Vec<MessageDraftAttachmentFfi>,
    ) -> Result<MessageDraftFfi, MarmotKitError> {
        let group_id_hex = canonical_group_id_hex(&group_id_hex)?;
        let reply_to_message_id_hex = optional_message_id_hex(reply_to_message_id_hex)?;
        Ok(self
            .runtime
            .save_message_draft(
                &account_ref,
                &group_id_hex,
                &content,
                reply_to_message_id_hex.as_deref(),
                media_attachments.into_iter().map(Into::into).collect(),
            )?
            .into())
    }

    /// Delete a saved composer draft. This is a no-op when no draft exists.
    pub fn delete_message_draft(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<(), MarmotKitError> {
        let group_id_hex = canonical_group_id_hex(&group_id_hex)?;
        self.runtime
            .delete_message_draft(&account_ref, &group_id_hex)?;
        Ok(())
    }
}

fn canonical_group_id_hex(value: &str) -> Result<String, MarmotKitError> {
    Ok(hex::encode(group_id_from_hex(value.trim())?.as_slice()))
}
