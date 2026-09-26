//! Additive, durable local send admission with caller correlation.
use crate::{Marmot, MarmotKitError, conversions::*};
use std::sync::Arc;

#[derive(Clone, uniffi::Record)]
pub struct LocalSendAcceptanceFfi {
    pub client_token: String,
    pub message_id_hex: String,
}
impl From<marmot_app::LocalSendAcceptance> for LocalSendAcceptanceFfi {
    fn from(value: marmot_app::LocalSendAcceptance) -> Self {
        Self {
            client_token: value.client_token,
            message_id_hex: value.message_id_hex,
        }
    }
}

#[derive(Clone, uniffi::Enum)]
pub enum LocalSendStatusFfi {
    Queued,
    EngineOwned,
    Completed { summary: SendSummaryFfi },
    Rejected,
}

#[derive(Clone, uniffi::Record)]
pub struct MediaUploadSubmissionFfi {
    pub upload: MediaUploadResultFfi,
    pub acceptance: Option<LocalSendAcceptanceFfi>,
}

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Return after durable local admission, independently of relay publication.
    /// Use one opaque token per logical submission; timeline rows echo it locally.
    pub async fn send_text_with_client_token(
        &self,
        account_ref: String,
        group_id_hex: String,
        text: String,
        client_token: String,
    ) -> Result<LocalSendAcceptanceFfi, MarmotKitError> {
        Ok(self
            .runtime
            .submit_text(
                &account_ref,
                &group_id_from_hex(&group_id_hex)?,
                text,
                client_token,
            )
            .await?
            .into())
    }

    /// Durably queue an edit for a text or reply submitted with a client token.
    /// The edit survives restart, targets the original's authoritative ID, and
    /// is rejected if that original never reaches the engine's durable queue.
    pub async fn edit_local_message_with_client_token(
        &self,
        account_ref: String,
        group_id_hex: String,
        original_client_token: String,
        content: String,
        edit_client_token: String,
    ) -> Result<LocalSendAcceptanceFfi, MarmotKitError> {
        Ok(self
            .runtime
            .submit_edit_for_local_send(
                &account_ref,
                &group_id_from_hex(&group_id_hex)?,
                original_client_token,
                content,
                edit_client_token,
            )
            .await?
            .into())
    }

    /// Durably admit a reply, retaining exact token correlation across restart.
    pub async fn reply_to_message_with_client_token(
        &self,
        account_ref: String,
        group_id_hex: String,
        target_message_id: String,
        text: String,
        client_token: String,
    ) -> Result<LocalSendAcceptanceFfi, MarmotKitError> {
        Ok(self
            .runtime
            .submit_reply(
                &account_ref,
                &group_id_from_hex(&group_id_hex)?,
                target_message_id,
                text,
                client_token,
            )
            .await?
            .into())
    }

    /// Atomically consume this draft revision and admit its token-bound message.
    pub async fn send_message_draft_with_client_token(
        &self,
        account_ref: String,
        revision: Arc<MessageDraftRevisionFfi>,
        attachments: Vec<MediaAttachmentReferenceFfi>,
        client_token: String,
    ) -> Result<LocalSendAcceptanceFfi, MarmotKitError> {
        Ok(self
            .runtime
            .submit_message_draft(
                &account_ref,
                &group_id_from_hex(revision.inner.group_id_hex())?,
                revision.inner.clone(),
                attachments.into_iter().map(Into::into).collect(),
                client_token,
            )
            .await?
            .into())
    }

    /// Upload encrypted attachments, then admit a correlated message if send=true.
    /// Upload completion precedes durable message acceptance.
    pub async fn upload_media_with_client_token(
        &self,
        account_ref: String,
        group_id_hex: String,
        request: MediaUploadRequestFfi,
        client_token: String,
    ) -> Result<MediaUploadSubmissionFfi, MarmotKitError> {
        let (upload, acceptance) = self
            .runtime
            .upload_media_with_client_token(
                &account_ref,
                &group_id_from_hex(&group_id_hex)?,
                request.into(),
                client_token,
            )
            .await?;
        Ok(MediaUploadSubmissionFfi {
            upload: upload.try_into()?,
            acceptance: acceptance.map(Into::into),
        })
    }

    /// Local-only status lookup, including after restart. Timeline subscriptions
    /// remain the source of subsequent transport delivery and failure updates.
    pub fn local_send_status(
        &self,
        account_ref: String,
        group_id_hex: String,
        client_token: String,
    ) -> Result<Option<LocalSendStatusFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .local_send_status(
                &account_ref,
                &group_id_from_hex(&group_id_hex)?,
                &client_token,
            )?
            .map(|status| match status {
                marmot_app::LocalSendStatus::Queued => LocalSendStatusFfi::Queued,
                marmot_app::LocalSendStatus::EngineOwned => LocalSendStatusFfi::EngineOwned,
                marmot_app::LocalSendStatus::Completed(summary) => LocalSendStatusFfi::Completed {
                    summary: summary.into(),
                },
                marmot_app::LocalSendStatus::Rejected => LocalSendStatusFfi::Rejected,
            }))
    }
}
