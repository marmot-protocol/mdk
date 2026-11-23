//! Encrypted, local composer draft commands.

use crate::conversions::{
    IdentifiedMessageDraftFfi, IdentifiedMessageDraftSummaryFfi, MessageDraftAttachmentFfi,
    MessageDraftFfi, MessageDraftIdFfi, MessageDraftRevisionFfi, MessageDraftSummaryFfi,
    SelectedMessageDraftFfi, group_id_from_hex,
};
use crate::errors::MarmotKitError;
use crate::{Marmot, optional_message_id_hex};
use std::sync::Arc;

#[uniffi::export]
impl Marmot {
    /// List the local active and saved drafts for one group, newest first.
    pub fn group_message_drafts(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<Vec<IdentifiedMessageDraftSummaryFfi>, MarmotKitError> {
        let group = canonical_group_id_hex(&group_id_hex)?;
        Ok(self
            .app
            .group_message_drafts(&account_ref, &group)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Read one draft's content and descriptors without changing the active composer.
    pub fn identified_message_draft(
        &self,
        account_ref: String,
        group_id_hex: String,
        id: MessageDraftIdFfi,
    ) -> Result<IdentifiedMessageDraftFfi, MarmotKitError> {
        let group = canonical_group_id_hex(&group_id_hex)?;
        Ok(self
            .app
            .identified_message_draft(&account_ref, &group, id.try_into()?)?
            .into())
    }

    /// Park the exact selected revision and leave the composer empty.
    pub fn archive_message_draft(
        &self,
        account_ref: String,
        revision: Arc<MessageDraftRevisionFfi>,
    ) -> Result<MessageDraftIdFfi, MarmotKitError> {
        Ok(self
            .app
            .archive_message_draft(&account_ref, &revision.inner)?
            .into())
    }

    /// Select one saved draft and park the current active draft in the same transaction.
    pub fn activate_message_draft(
        &self,
        account_ref: String,
        revision: Arc<MessageDraftRevisionFfi>,
        id: MessageDraftIdFfi,
    ) -> Result<SelectedMessageDraftFfi, MarmotKitError> {
        Ok(self
            .app
            .activate_message_draft(&account_ref, &revision.inner, id.try_into()?)?
            .into())
    }

    /// Remove one saved draft. An active draft cannot be removed through this operation.
    pub fn delete_saved_message_draft(
        &self,
        account_ref: String,
        group_id_hex: String,
        id: MessageDraftIdFfi,
    ) -> Result<(), MarmotKitError> {
        let group = canonical_group_id_hex(&group_id_hex)?;
        self.app
            .delete_saved_message_draft(&account_ref, &group, id.try_into()?)?;
        Ok(())
    }

    /// Active composer summaries for an account, newest first. For the
    /// active and saved drafts in one conversation, use `groupMessageDrafts`.
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

    /// The active composer draft for an account and MLS group, if one exists.
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

    /// Delete the active composer draft. This leaves saved entries in the group.
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

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Read up to 1 MiB from the content revision returned by the identified draft read.
    #[expect(
        clippy::too_many_arguments,
        reason = "identifies the draft, version and byte range"
    )]
    pub async fn read_identified_message_draft_attachment(
        &self,
        account_ref: String,
        group_id_hex: String,
        id: MessageDraftIdFfi,
        content_revision: i64,
        attachment_id: String,
        offset: u64,
        limit: u32,
    ) -> Result<Option<Vec<u8>>, MarmotKitError> {
        let group = canonical_group_id_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .read_identified_message_draft_attachment(
                &account_ref,
                group,
                id.try_into()?,
                content_revision,
                attachment_id,
                offset,
                limit as usize,
            )
            .await?
            .map(|mut bytes| std::mem::take(&mut *bytes)))
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

    #[test]
    fn draft_round_trip_crosses_runtime_and_ffi_boundaries() {
        // This test composes UniFFI, the app runtime, the account worker, MLS
        // group creation, and maintenance enrollment. Debug builds need more
        // than libtest's default 2 MiB stack while polling that chain.
        let test_thread = std::thread::Builder::new()
            .name("ffi-draft-runtime-round-trip".to_owned())
            .stack_size(4 * 1024 * 1024)
            .spawn(|| {
                let test_runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                test_runtime.block_on(draft_round_trip_body());
            })
            .unwrap();
        test_thread.join().unwrap();
    }

    async fn draft_round_trip_body() {
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
            .expect("create group")
            .group_id_hex
            .expect("selected members create a group");
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

        let revision = kit
            .selected_message_draft(account_ref.clone(), group_id_hex.clone())
            .unwrap()
            .revision;
        let id = kit
            .archive_message_draft(account_ref.clone(), revision.clone())
            .unwrap();
        assert_eq!(id.hex.len(), 32);
        let entries = kit
            .group_message_drafts(account_ref.clone(), group_id_hex.clone())
            .unwrap();
        assert_eq!(entries[0].id.hex, id.hex);
        assert!(matches!(
            entries[0].state,
            crate::conversions::MessageDraftStateFfi::Saved
        ));
        assert!(kit.message_drafts(account_ref.clone()).unwrap().is_empty());
        assert!(matches!(
            kit.activate_message_draft(account_ref.clone(), revision, id.clone()),
            Err(MarmotKitError::MessageDraftRevisionConflict)
        ));
        assert!(matches!(
            kit.identified_message_draft(
                account_ref.clone(),
                group_id_hex.clone(),
                MessageDraftIdFfi {
                    hex: "12".repeat(16)
                }
            ),
            Err(MarmotKitError::UnknownMessageDraft)
        ));
        let inspected = kit
            .identified_message_draft(account_ref.clone(), group_id_hex.clone(), id.clone())
            .unwrap();
        assert_eq!(
            kit.read_identified_message_draft_attachment(
                account_ref.clone(),
                group_id_hex.clone(),
                id.clone(),
                inspected.content_revision,
                "attachment-1".into(),
                8,
                10,
            )
            .await
            .unwrap()
            .unwrap(),
            b"attachment"
        );
        let current = kit
            .selected_message_draft(account_ref.clone(), group_id_hex.clone())
            .unwrap()
            .revision;
        let restored = kit
            .activate_message_draft(account_ref.clone(), current, id)
            .unwrap();
        assert_eq!(restored.draft.unwrap().content, "draft content");

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
