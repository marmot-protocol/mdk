//! File-backed composer draft attachments (mdk#3431). A host adds a large
//! attachment to a draft once, from a file, and refers to it by id after
//! that: saves retain it, reads take chunks or a handoff copy, and an upload
//! reads MDK's own copy. Its bytes never cross the FFI as one buffer. Every
//! store call here runs on the blocking pool.
use std::sync::Arc;

use media_store::{Category, StageOutcome};
use storage_sqlite::{
    MessageDraftAttachmentFileMeta, MessageDraftAttachmentRead, MessageDraftStageRefusal,
};
use zeroize::Zeroizing;

use super::MarmotAppRuntime;
use crate::drafts::{revision_error, validate_attachment_media_metadata};
use crate::media::file_transfer::{
    DraftUploadRequest, FileUploadSources, MAX_FILE_MEDIA_CIPHERTEXT_BYTES, MEDIA_AEAD_TAG_BYTES,
    MediaFileTransferControl,
};
use crate::media::handoff::{AttachmentHandoff, HandoffBody, HandoffSource};
use crate::media::outgoing::{HostSource, HostSourceWatch};
use crate::{
    AppError, EncryptedMediaVersion, MAX_ATTACHMENT_LOCAL_READ_BYTES,
    MAX_ENCRYPTED_MEDIA_BLOB_BYTES, MediaUploadResult, MessageDraftRevision, SelectedMessageDraft,
};

/// The most attachments a draft can hold once one is file-backed: an upload
/// takes at most this many.
pub const MAX_MESSAGE_DRAFT_ATTACHMENTS: u64 = 64;

/// The largest file a draft attachment can be: one encrypted media blob,
/// less its AEAD tag.
pub const MAX_MESSAGE_DRAFT_ATTACHMENT_FILE_BYTES: u64 =
    MAX_ENCRYPTED_MEDIA_BLOB_BYTES - MEDIA_AEAD_TAG_BYTES;

/// A host file to add to a draft. MDK copies it into its own encrypted
/// storage; the host may delete the file once the call returns.
#[derive(Clone)]
pub struct MessageDraftAttachmentFileRequest {
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

impl std::fmt::Debug for MessageDraftAttachmentFileRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageDraftAttachmentFileRequest")
            .field("expected_size", &self.expected_size)
            .finish_non_exhaustive()
    }
}

/// Whether a draft of `count` attachments holding `plaintext_bytes` can still
/// be uploaded as one batch.
fn draft_fits(count: u64, plaintext_bytes: u64) -> bool {
    count <= MAX_MESSAGE_DRAFT_ATTACHMENTS
        && count
            .checked_mul(MEDIA_AEAD_TAG_BYTES)
            .and_then(|tags| tags.checked_add(plaintext_bytes))
            .is_some_and(|wire| wire <= MAX_FILE_MEDIA_CIPHERTEXT_BYTES)
}

/// The draft's stage target, refusing the commit if the host file changed or
/// the operation was cancelled while it was copied: a cancellation seen
/// before the attachment joins the draft leaves no file behind.
struct CheckedStage<'a> {
    target: &'a storage_sqlite::MessageDraftAttachmentStage,
    source: &'a HostSourceWatch,
    control: &'a MediaFileTransferControl,
    refused: std::cell::Cell<Option<AppError>>,
}

impl media_store::StageTarget for CheckedStage<'_> {
    fn commit_staged(
        &self,
        id: media_store::FileId,
        digest: &[u8; 32],
    ) -> media_store::CatalogResult<media_store::StagedOutcome> {
        if let Err(error) = self.control.check() {
            self.refused.set(Some(error));
            return Ok(media_store::StagedOutcome::Superseded);
        }
        if !self.source.unchanged() {
            self.refused.set(Some(AppError::InvalidEncryptedMedia(
                "media source changed during reading".into(),
            )));
            return Ok(media_store::StagedOutcome::Superseded);
        }
        self.target.commit_staged(id, digest)
    }

    fn release_staged(&self, id: media_store::FileId) -> media_store::CatalogResult<bool> {
        self.target.release_staged(id)
    }
}

fn validate_read_range(offset: u64, limit: usize) -> Result<(), AppError> {
    if limit == 0 || limit > MAX_ATTACHMENT_LOCAL_READ_BYTES || offset >= i64::MAX as u64 {
        return Err(AppError::InvalidMessageDraft(
            "invalid attachment byte range".into(),
        ));
    }
    Ok(())
}

fn read_draft_bytes(
    app: &crate::MarmotApp,
    label: &str,
    storage: &storage_sqlite::SqliteAccountStorage,
    read: Option<MessageDraftAttachmentRead>,
    offset: u64,
    limit: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, AppError> {
    match read {
        None => Ok(None),
        Some(MessageDraftAttachmentRead::Bytes(bytes)) => Ok(Some(Zeroizing::new(bytes))),
        Some(MessageDraftAttachmentRead::MediaFile(id)) => {
            let media = app.account_media_store(label, storage)?;
            let Some(mut reader) = media
                .open_staged_reader(&id)
                .map_err(storage_sqlite::media_storage_error)?
            else {
                return Ok(None);
            };
            let mut bytes = Zeroizing::new(vec![0; limit]);
            let read = reader
                .read_at(offset, &mut bytes)
                .map_err(storage_sqlite::media_storage_error)?;
            bytes.truncate(read);
            Ok(Some(bytes))
        }
    }
}

fn refusal_error(refusal: Option<MessageDraftStageRefusal>, group: &str) -> AppError {
    match refusal {
        Some(MessageDraftStageRefusal::Conflict) => AppError::MessageDraftRevisionConflict,
        Some(MessageDraftStageRefusal::UnknownGroup) => AppError::UnknownGroup(group.to_owned()),
        Some(MessageDraftStageRefusal::DuplicateId) => {
            AppError::InvalidMessageDraft("attachment ids must be unique".into())
        }
        Some(MessageDraftStageRefusal::Full) => draft_full(),
        Some(MessageDraftStageRefusal::QuotaExceeded) => AppError::MessageDraftQuotaExceeded,
        // The pending copy's row was gone at commit (another process swept
        // it): the draft did not refuse it, so retrying can succeed.
        None => AppError::InvalidEncryptedMedia(
            "the staged copy was lost before it joined the draft".into(),
        ),
    }
}

fn draft_full() -> AppError {
    AppError::InvalidMessageDraft(
        "the draft cannot hold this attachment within the upload bounds".into(),
    )
}

impl MarmotAppRuntime {
    /// Copies a host file into the account's encrypted media store and
    /// appends it to the draft `revision` selects, returning the new
    /// selected draft. `revision` must be current when the call starts; text
    /// saves while the file copies do not lose it, but the host's next save
    /// with an older revision conflicts and must reload. A draft cleared,
    /// deleted or sent during the copy stays so: the copy is discarded with
    /// `MessageDraftRevisionConflict`. Refused before
    /// copying: an attachment over the blob limit, a draft it would take
    /// past 64 attachments or the upload batch bound, an id already in the
    /// draft, a media type with no canonical form, and a copy the disk cannot
    /// hold beyond its reserve (`StorageError::Capacity`). The media type is
    /// stored canonical, as the upload will describe it. `control` reports copied bytes and
    /// cancels: a cancellation before the attachment joins the draft leaves
    /// nothing behind. The host may delete its file once this returns.
    pub async fn stage_message_draft_attachment_file(
        &self,
        account_ref: &str,
        revision: MessageDraftRevision,
        request: MessageDraftAttachmentFileRequest,
        control: Arc<MediaFileTransferControl>,
    ) -> Result<SelectedMessageDraft, AppError> {
        if request.id.trim().is_empty() {
            return Err(AppError::InvalidMessageDraft(
                "attachment id must not be empty".into(),
            ));
        }
        validate_attachment_media_metadata(request.duration_seconds, &request.waveform_samples)?;
        // Refuse, before copying, a descriptor that an upload under either
        // encrypted-media version would refuse later. The type is stored in
        // its v2 form, which is canonical under both versions.
        for version in [EncryptedMediaVersion::V1, EncryptedMediaVersion::V2] {
            crate::media::outgoing::OutgoingDescriptor::new(
                request.file_name.clone(),
                &request.media_type,
                None,
                None,
                version,
            )?;
        }
        let media_type = crate::media::crypto::canonical_media_type_v2(&request.media_type)?;
        if request
            .expected_size
            .is_some_and(|size| size > MAX_MESSAGE_DRAFT_ATTACHMENT_FILE_BYTES)
        {
            return Err(blob_limit());
        }
        control.check()?;
        self.attachment_read_with(account_ref, move |app, label, storage, _| {
            let group = revision.group_id_hex().to_owned();
            let drafts = storage.app_storage();
            let (count, bytes) = drafts
                .message_draft_usage_if_revision(&revision, &request.id)
                .map_err(|error| revision_error(error, &group))?;
            let mut source = HostSource::open(
                std::path::Path::new(&request.source_path),
                request.expected_size,
                control.clone(),
            )?;
            let len = source.len();
            if len > MAX_MESSAGE_DRAFT_ATTACHMENT_FILE_BYTES {
                return Err(blob_limit());
            }
            let target = drafts
                .message_draft_attachment_stage(
                    &revision,
                    MessageDraftAttachmentFileMeta {
                        id: request.id,
                        file_name: request.file_name,
                        media_type,
                        dim: request.dim,
                        thumbhash: request.thumbhash,
                        duration_seconds: request.duration_seconds,
                        waveform_samples: request.waveform_samples,
                    },
                    len,
                    draft_fits,
                )
                .map_err(|error| revision_error(error, &group))?;
            if !draft_fits(count.saturating_add(1), bytes.saturating_add(len)) {
                return Err(draft_full());
            }
            let disk = crate::media::outgoing::send_disk_policy(app, &storage)?;
            crate::media::outgoing::admit_send_body(app, label, disk, len)?;
            let media = app.account_media_store(label, &storage)?;
            let watch = source.watch()?;
            let checked = CheckedStage {
                target: &target,
                source: &watch,
                control: &control,
                refused: std::cell::Cell::new(None),
            };
            let outcome = media
                .stage(
                    &checked,
                    Category::Retained,
                    &mut source,
                    len,
                    crate::unix_now_seconds(),
                    &|| control.is_cancelled(),
                )
                .map_err(crate::media::outgoing::staging_error)?;
            if outcome == StageOutcome::Superseded {
                return Err(checked
                    .refused
                    .take()
                    .unwrap_or_else(|| refusal_error(target.refusal(), &group)));
            }
            app.notify_draft_changed(label, &group);
            Ok(drafts.selected_message_draft(&group)?)
        })
        .await
    }

    /// Reads 1..=1 MiB of one draft attachment from `offset`, inline or
    /// file-backed, checked against `revision`. `None` means the draft has no
    /// such attachment (or its file is gone); `Some(empty)` is the end.
    /// Conflicts once the draft changes, so prefer
    /// [`Self::open_message_draft_attachment_handoff`] for long reads.
    pub async fn read_message_draft_attachment(
        &self,
        account_ref: &str,
        revision: MessageDraftRevision,
        attachment_id: String,
        offset: u64,
        limit: usize,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, AppError> {
        validate_read_range(offset, limit)?;
        self.attachment_read_with(account_ref, move |app, label, storage, _| {
            let read = storage
                .app_storage()
                .read_message_draft_attachment_if_revision(&revision, &attachment_id, offset, limit)
                .map_err(|error| revision_error(error, revision.group_id_hex()))?;
            read_draft_bytes(app, label, &storage, read, offset, limit)
        })
        .await
    }

    /// Read one bounded chunk from the content version returned by the identified draft read.
    #[expect(
        clippy::too_many_arguments,
        reason = "identifies the draft, version and byte range"
    )]
    pub async fn read_identified_message_draft_attachment(
        &self,
        account_ref: &str,
        group: String,
        draft: crate::MessageDraftId,
        content_revision: i64,
        attachment_id: String,
        offset: u64,
        limit: usize,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, AppError> {
        validate_read_range(offset, limit)?;
        self.attachment_read_with(account_ref, move |app, label, storage, _| {
            let read = storage
                .app_storage()
                .read_identified_message_draft_attachment(
                    &group,
                    draft,
                    content_revision,
                    &attachment_id,
                    offset,
                    limit,
                )
                .map_err(|error| revision_error(error, &group))?;
            read_draft_bytes(app, label, &storage, read, offset, limit)
        })
        .await
    }

    /// Writes a plaintext copy of one draft attachment for an OS surface that
    /// needs a real file (AVFoundation thumbnails and playback) and lends it
    /// under a lease, exactly as [`Self::open_attachment_handoff`] does. The
    /// revision is checked once, before the copy; later draft edits do not
    /// interrupt it. `None` means the draft has no such attachment.
    pub async fn open_message_draft_attachment_handoff(
        &self,
        account_ref: &str,
        revision: MessageDraftRevision,
        attachment_id: String,
        control: Arc<MediaFileTransferControl>,
    ) -> Result<Option<AttachmentHandoff>, AppError> {
        control.check()?;
        self.attachment_read_with(account_ref, move |app, label, storage, _| {
            let group = revision.group_id_hex();
            let selected = storage.app_storage().selected_message_draft(group)?;
            if selected.revision != revision {
                return Err(AppError::MessageDraftRevisionConflict);
            }
            let Some(attachment) = selected
                .draft
                .into_iter()
                .flat_map(|draft| draft.media_attachments)
                .find(|attachment| attachment.id == attachment_id)
            else {
                return Ok(None);
            };
            let body = match storage
                .app_storage()
                .read_message_draft_attachment_if_revision(
                    &revision,
                    &attachment_id,
                    0,
                    usize::try_from(attachment.plaintext_size).unwrap_or(usize::MAX),
                )
                .map_err(|error| revision_error(error, group))?
            {
                None => return Ok(None),
                Some(MessageDraftAttachmentRead::Bytes(bytes)) => {
                    HandoffBody::Bytes(Zeroizing::new(bytes))
                }
                Some(MessageDraftAttachmentRead::MediaFile(id)) => HandoffBody::Staged(id),
            };
            let source = HandoffSource {
                body,
                byte_count: attachment.plaintext_size,
                file_name: crate::media::handoff::handoff_name(
                    &attachment.file_name,
                    &attachment.media_type,
                ),
                media_type: attachment.media_type,
            };
            crate::media::handoff::open(app, label, &storage, source, &control)
        })
        .await
        .map(|pending| pending.map(crate::media::handoff::PendingHandoff::deliver))
    }

    /// Encrypts and uploads the draft attachments `attachment_ids` names, in
    /// that order, from the copies the draft holds, exactly as
    /// [`Self::upload_media_files`] uploads host files. Upload only: send the
    /// returned references with the draft. Each reference carries the
    /// attachment's `plaintext_sha256`. `revision` must be current when the
    /// bodies are read. `blossom_server` overrides the group's endpoints, as
    /// in a file upload request.
    pub async fn upload_message_draft_attachments(
        &self,
        account_ref: &str,
        revision: MessageDraftRevision,
        attachment_ids: Vec<String>,
        blossom_server: Option<String>,
        control: Arc<MediaFileTransferControl>,
    ) -> Result<MediaUploadResult, AppError> {
        let group = cgka_traits::GroupId::new(
            hex::decode(revision.group_id_hex())
                .map_err(|_| AppError::UnknownGroup(revision.group_id_hex().to_owned()))?,
        );
        self.accounts
            .upload_file_sources(
                account_ref,
                &group,
                FileUploadSources::Draft(DraftUploadRequest {
                    revision,
                    attachment_ids,
                    blossom_server,
                }),
                control,
            )
            .await
    }
}

fn blob_limit() -> AppError {
    AppError::InvalidEncryptedMedia("media source exceeds the media blob limit".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_draft_fits_one_upload_batch() {
        assert!(draft_fits(1, MAX_MESSAGE_DRAFT_ATTACHMENT_FILE_BYTES));
        assert!(draft_fits(64, 0));
        assert!(!draft_fits(65, 0));
        assert!(draft_fits(
            2,
            MAX_FILE_MEDIA_CIPHERTEXT_BYTES - 2 * MEDIA_AEAD_TAG_BYTES
        ));
        assert!(!draft_fits(
            2,
            MAX_FILE_MEDIA_CIPHERTEXT_BYTES - 2 * MEDIA_AEAD_TAG_BYTES + 1
        ));
        assert!(!draft_fits(u64::MAX, u64::MAX));
    }

    /// Only a draft that refused the attachment for its bounds says it is
    /// full: a stage whose pending copy was lost is retryable instead.
    #[test]
    fn a_lost_stage_is_not_reported_as_a_full_draft() {
        assert!(matches!(
            refusal_error(Some(MessageDraftStageRefusal::Full), "g"),
            AppError::InvalidMessageDraft(_)
        ));
        assert!(matches!(
            refusal_error(None, "g"),
            AppError::InvalidEncryptedMedia(_)
        ));
    }
}
