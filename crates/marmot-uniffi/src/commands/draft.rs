//! Encrypted, local composer draft commands.

use crate::conversions::{
    MessageDraftAttachmentFfi, MessageDraftFfi, MessageDraftSummaryFfi, group_id_from_hex,
};
use crate::errors::MarmotKitError;
use crate::{Marmot, optional_message_id_hex};

#[uniffi::export]
impl Marmot {
    /// Metadata-only saved composer drafts for an account, newest-updated
    /// first. Attachment plaintext is intentionally omitted from this list;
    /// call `messageDraft` when restoring one selected composer. Hosts must
    /// delete empty or sent drafts; deleting a group also removes its draft.
    pub fn message_drafts(
        &self,
        account_ref: String,
    ) -> Result<Vec<MessageDraftSummaryFfi>, MarmotKitError> {
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

#[cfg(test)]
mod tests {
    use cgka_traits::TransportEndpoint;
    use marmot_app::{AccountSetupRequest, MarmotApp};
    use nostr_relay_builder::MockRelay;

    use super::*;

    #[tokio::test]
    async fn draft_round_trip_crosses_runtime_and_ffi_boundaries() {
        let relay = MockRelay::run().await.expect("start mock relay");
        let relay_url = relay.url().await.to_string();
        let root = tempfile::tempdir().expect("tempdir");
        let app = MarmotApp::with_relays(root.path(), vec![relay_url.clone()]);
        let runtime = app.runtime();
        let kit = Marmot { app, runtime };
        let endpoint = TransportEndpoint(relay_url);
        let account = kit
            .runtime
            .create_identity(AccountSetupRequest {
                default_relays: vec![endpoint.clone()],
                bootstrap_relays: vec![endpoint],
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
                ..AccountSetupRequest::default()
            })
            .await
            .expect("create identity");
        let account_ref = account.account.account_id_hex;
        let group_id_hex = kit
            .create_group(
                account_ref.clone(),
                "Draft test".to_owned(),
                Vec::new(),
                None,
            )
            .await
            .expect("create group");
        let attachment = MessageDraftAttachmentFfi {
            id: "attachment-1".to_owned(),
            file_name: "note.txt".to_owned(),
            media_type: "text/plain".to_owned(),
            plaintext: b"private attachment".to_vec(),
            dim: None,
            thumbhash: None,
            duration_seconds: None,
            waveform_samples: Vec::new(),
        };

        let saved = kit
            .save_message_draft(
                account_ref.clone(),
                group_id_hex.clone(),
                "draft content".to_owned(),
                Some("aa".repeat(32)),
                vec![attachment],
            )
            .expect("save draft");
        assert_eq!(saved.content, "draft content");
        assert_eq!(saved.media_attachments.len(), 1);
        assert_eq!(saved.media_attachments[0].plaintext, b"private attachment");

        let summaries = kit
            .message_drafts(account_ref.clone())
            .expect("list draft summaries");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].group_id_hex, group_id_hex);
        assert_eq!(summaries[0].content, "draft content");
        assert_eq!(summaries[0].media_attachments.len(), 1);
        assert_eq!(summaries[0].media_attachments[0].plaintext_size, 18);

        let loaded = kit
            .message_draft(account_ref.clone(), group_id_hex.clone())
            .expect("load draft")
            .expect("saved draft exists");
        assert_eq!(loaded.media_attachments[0].plaintext, b"private attachment");

        let invalid = kit
            .save_message_draft(
                account_ref.clone(),
                group_id_hex.clone(),
                "invalid".to_owned(),
                None,
                vec![
                    MessageDraftAttachmentFfi {
                        id: "duplicate".to_owned(),
                        file_name: "first.txt".to_owned(),
                        media_type: "text/plain".to_owned(),
                        plaintext: vec![1],
                        dim: None,
                        thumbhash: None,
                        duration_seconds: None,
                        waveform_samples: Vec::new(),
                    },
                    MessageDraftAttachmentFfi {
                        id: "duplicate".to_owned(),
                        file_name: "second.txt".to_owned(),
                        media_type: "text/plain".to_owned(),
                        plaintext: vec![2],
                        dim: None,
                        thumbhash: None,
                        duration_seconds: None,
                        waveform_samples: Vec::new(),
                    },
                ],
            )
            .expect_err("duplicate attachment ids should be typed invalid input");
        assert!(matches!(
            invalid,
            MarmotKitError::InvalidMessageDraft { .. }
        ));

        let unknown_group = kit
            .save_message_draft(
                account_ref.clone(),
                "ff".repeat(16),
                "draft".to_owned(),
                None,
                Vec::new(),
            )
            .expect_err("unknown group should stay typed");
        assert!(matches!(unknown_group, MarmotKitError::UnknownGroup { .. }));

        kit.delete_message_draft(account_ref.clone(), group_id_hex.clone())
            .expect("delete draft");
        assert!(
            kit.message_draft(account_ref, group_id_hex)
                .expect("load deleted draft")
                .is_none()
        );
        kit.runtime.shutdown().await;
    }
}
