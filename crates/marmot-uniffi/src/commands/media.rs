//! Encrypted-media upload/download/send/list commands.

use marmot_app::AppMessageQuery;

use crate::Marmot;
use crate::conversions::{
    MediaAttachmentReferenceFfi, MediaDownloadResultFfi, MediaRecordFfi, MediaUploadRequestFfi,
    MediaUploadResultFfi, MessageTagFfi, SendSummaryFfi, group_id_from_hex, media_records_ffi,
};
use crate::errors::MarmotKitError;

/// Parse one authenticated encrypted-media `imeta` tag using MDK's frozen V1
/// or current V2 validation rules.
///
/// `source_epoch` is required because it is MLS metadata rather than an
/// `imeta` field and is needed to download the attachment later.
#[uniffi::export]
pub fn parse_media_imeta_tag(
    tag: MessageTagFfi,
    source_epoch: u64,
) -> Result<MediaAttachmentReferenceFfi, MarmotKitError> {
    marmot_app::media_attachment_from_imeta_tag(&tag.values, Some(source_epoch), false)
        .map(Into::into)
        .map_err(media_reference_error)
}

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Build one outbound encrypted-media `imeta` tag without publishing it.
    ///
    /// The account worker derives the target group's actual media profile and
    /// rejects a V1 reference for a V2 group (or a V2 reference for a legacy
    /// V1 group).
    pub async fn build_media_imeta_tag(
        &self,
        account_ref: String,
        group_id_hex: String,
        reference: MediaAttachmentReferenceFfi,
    ) -> Result<MessageTagFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let values = self
            .runtime
            .build_media_imeta_tag(&account_ref, &group_id, reference.into())
            .await
            .map_err(media_reference_error)?;
        Ok(MessageTagFfi { values })
    }

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

fn media_reference_error(error: marmot_app::AppError) -> MarmotKitError {
    match error {
        marmot_app::AppError::InvalidAppMessagePayload(details)
        | marmot_app::AppError::InvalidEncryptedMedia(details) => {
            MarmotKitError::InvalidMediaReference { details }
        }
        other => other.into(),
    }
}
