//! Encrypted-media upload/download/send/list commands.

use marmot_app::AppMessageQuery;

use crate::Marmot;
use crate::conversions::{
    MediaAttachmentReferenceFfi, MediaDownloadResultFfi, MediaRecordFfi, MediaUploadRequestFfi,
    MediaUploadResultFfi, SendSummaryFfi, group_id_from_hex, media_records_ffi,
};
use crate::errors::MarmotKitError;

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Send already-uploaded encrypted media attachments as a kind-9 chat
    /// carrying ordered NIP-92 `imeta` tags.
    pub async fn send_media_attachments(
        &self,
        account_ref: String,
        group_id_hex: String,
        attachments: Vec<MediaAttachmentReferenceFfi>,
        caption: Option<String>,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .send_media_attachments(
                &account_ref,
                &group_id,
                attachments.into_iter().map(Into::into).collect(),
                caption,
            )
            .await?;
        Ok(summary.into())
    }

    /// Backward-compatible single-attachment send helper. Prefer
    /// `send_media_attachments` for new callers so one chat can carry ordered
    /// mixed media attachments.
    pub async fn send_media_reference(
        &self,
        account_ref: String,
        group_id_hex: String,
        reference: MediaAttachmentReferenceFfi,
        caption: Option<String>,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        self.send_media_attachments(account_ref, group_id_hex, vec![reference], caption)
            .await
    }

    /// Encrypt plaintext attachments, upload the ciphertext blobs, and
    /// optionally send the resulting media references into the group.
    pub async fn upload_media(
        &self,
        account_ref: String,
        group_id_hex: String,
        request: MediaUploadRequestFfi,
    ) -> Result<MediaUploadResultFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let upload = self
            .runtime
            .upload_media(&account_ref, &group_id, request.into())
            .await?;
        Ok(upload.into())
    }

    /// Fetch an encrypted media blob and decrypt it using the group's
    /// encrypted media component secret.
    pub async fn download_media(
        &self,
        account_ref: String,
        group_id_hex: String,
        reference: MediaAttachmentReferenceFfi,
    ) -> Result<MediaDownloadResultFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let download = self
            .runtime
            .download_media(&account_ref, &group_id, reference.into())
            .await?;
        Ok(download.into())
    }

    /// Typed media references projected from group message history. Host apps
    /// can pass a returned `reference` back to `download_media`.
    pub fn list_media(
        &self,
        account_ref: String,
        group_id_hex: String,
        limit: Option<u32>,
    ) -> Result<Vec<MediaRecordFfi>, MarmotKitError> {
        let group_id_hex = hex::encode(group_id_from_hex(&group_id_hex)?.as_slice());
        let records = self.runtime.messages_with_query(
            &account_ref,
            AppMessageQuery {
                group_id_hex: Some(group_id_hex),
                limit: limit.map(|n| n as usize),
            },
        )?;
        Ok(media_records_ffi(records))
    }
}
