//! File-backed draft attachments (mdk#3431, migration 0209). A draft
//! attachment can own a staged media-store file instead of keeping its
//! bytes in the database. [`MessageDraftAttachmentStage`] is that file's
//! owner while the store writes it: its commit appends the attachment to the
//! draft. Deleting the attachment row releases the file through the
//! migration's triggers; the store (or its sweep) unlinks it afterwards. No
//! file I/O here.
use std::cell::Cell;

use media_store::{CatalogResult, FileId, StageTarget, StagedOutcome};

use super::revisioned::{check_revision_tx, composition_tx, revision_tx, selected_tx};
use super::*;
use crate::app::media_catalog::{STATE_STAGED, catalog_error};
use crate::{MessageDraftRevision, MessageDraftRevisionError, SelectedMessageDraftAttachment};

/// The descriptor of an attachment staged from a file. Its size and digest
/// come from the staged file itself.
#[derive(Clone, PartialEq)]
pub struct MessageDraftAttachmentFileMeta {
    pub id: String,
    pub file_name: String,
    pub media_type: String,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
    pub duration_seconds: Option<f64>,
    pub waveform_samples: Vec<f64>,
}

impl fmt::Debug for MessageDraftAttachmentFileMeta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageDraftAttachmentFileMeta")
            .field("waveform_sample_count", &self.waveform_samples.len())
            .finish_non_exhaustive()
    }
}

/// Why a staged file was not added to its draft. The store has already
/// abandoned the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageDraftStageRefusal {
    /// The store was reset or the active composition changed
    /// since the staging started.
    Conflict,
    /// The group is gone.
    UnknownGroup,
    /// The draft already has an attachment with this id.
    DuplicateId,
    /// The draft would exceed its attachment count or byte bound.
    Full,
    /// The account store's draft quota would be exceeded.
    QuotaExceeded,
}

/// The owner of one staged draft attachment while the store writes it. One
/// transaction per call, as [`StageTarget`] requires.
pub struct MessageDraftAttachmentStage {
    storage: SqliteAppStorage,
    expected: MessageDraftRevision,
    composition: i64,
    meta: MessageDraftAttachmentFileMeta,
    byte_len: u64,
    fits: fn(count: u64, plaintext_bytes: u64) -> bool,
    refusal: Cell<Option<MessageDraftStageRefusal>>,
}

impl MessageDraftAttachmentStage {
    /// Why the last commit refused the file, if it did.
    pub fn refusal(&self) -> Option<MessageDraftStageRefusal> {
        self.refusal.get()
    }

    fn refuse(&self, refusal: MessageDraftStageRefusal) -> StorageResult<StagedOutcome> {
        self.refusal.set(Some(refusal));
        Ok(StagedOutcome::Superseded)
    }

    fn commit(&self, id: FileId, digest: &[u8; 32]) -> StorageResult<StagedOutcome> {
        let conn = self.storage.lock()?;
        let group = self.expected.group_id_hex();
        // Text saves move the revision while a large file is copied, so the
        // commit needs only the store and the composition staging started
        // in; a cleared, deleted or sent draft has ended that composition.
        match revision_tx(&conn, group) {
            Ok(current) if current.same_store(&self.expected) => {}
            Ok(_) => return self.refuse(MessageDraftStageRefusal::Conflict),
            Err(StorageError::NotFound) => {
                return self.refuse(MessageDraftStageRefusal::UnknownGroup);
            }
            Err(error) => return Err(error),
        }
        if composition_tx(&conn, group)? != self.composition {
            return self.refuse(MessageDraftStageRefusal::Conflict);
        }
        let duplicate: bool = conn
            .query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM message_draft_attachments
                 WHERE draft_id = (SELECT draft_id FROM message_drafts WHERE group_id_hex = ?1 AND active = 1)
                   AND attachment_id = ?2)",
                params![group, self.meta.id],
                |row| row.get(0),
            )
            .storage()?;
        if duplicate {
            return self.refuse(MessageDraftStageRefusal::DuplicateId);
        }
        let (count, bytes) = draft_usage_tx(&conn, group)?;
        let add_bytes = i64::try_from(self.byte_len).unwrap_or(i64::MAX);
        match super::saved::check_attachment_limits(&conn, group, 1, add_bytes) {
            Ok(()) => {}
            Err(StorageError::MessageDraftQuotaExceeded) => {
                return self.refuse(MessageDraftStageRefusal::QuotaExceeded);
            }
            Err(error) => return Err(error),
        }
        if !(self.fits)(count.saturating_add(1), bytes.saturating_add(self.byte_len)) {
            return self.refuse(MessageDraftStageRefusal::Full);
        }
        let staged = conn
            .execute(
                "UPDATE media_files SET state=?3,plaintext_digest=?2 WHERE id=?1 AND state=0",
                params![id.as_bytes().as_slice(), digest.as_slice(), STATE_STAGED],
            )
            .storage()?;
        if staged != 1 {
            return Ok(StagedOutcome::Superseded);
        }
        let now_ms = unix_now_ms();
        let draft_id: [u8; 16] = conn.query_row_cached(
            "INSERT INTO message_drafts (
                group_id_hex, content, reply_to_message_id_hex, created_at_ms, updated_at_ms
             )
             VALUES (?1, '', NULL, ?2, ?2)
             ON CONFLICT(group_id_hex) WHERE active = 1 DO UPDATE SET updated_at_ms = excluded.updated_at_ms
             RETURNING draft_id",
            params![group, now_ms],
            |row| row.get(0),
        )
        .storage()?;
        let waveform_samples =
            serde_json::to_string(&self.meta.waveform_samples).map_err(|_| {
                StorageError::Serialization("invalid message draft waveform samples".to_owned())
            })?;
        conn.execute_cached(
            "INSERT INTO message_draft_attachments (
                draft_id, position, attachment_id, file_name, media_type,
                plaintext, dim, thumbhash, duration_seconds, waveform_samples_json, file_id
             )
             VALUES (?1, (SELECT coalesce(max(position) + 1, 0) FROM message_draft_attachments
                          WHERE draft_id = ?1),
                     ?2, ?3, ?4, x'', ?5, ?6, ?7, ?8, ?9)",
            params![
                draft_id,
                self.meta.id,
                self.meta.file_name,
                self.meta.media_type,
                self.meta.dim,
                self.meta.thumbhash,
                self.meta.duration_seconds,
                waveform_samples,
                id.as_bytes().as_slice(),
            ],
        )
        .storage()?;
        Ok(StagedOutcome::Staged)
    }
}

impl StageTarget for MessageDraftAttachmentStage {
    fn commit_staged(&self, id: FileId, digest: &[u8; 32]) -> CatalogResult<StagedOutcome> {
        self.refusal.set(None);
        self.storage
            .connection
            .with_transaction(|| self.commit(id, digest))
            .map_err(catalog_error)
    }

    fn release_staged(&self, id: FileId) -> CatalogResult<bool> {
        self.storage
            .connection
            .with_transaction(|| {
                let conn = self.storage.lock()?;
                let group = self.expected.group_id_hex();
                match revision_tx(&conn, group) {
                    Ok(revision) if revision.same_store(&self.expected) => {}
                    Ok(_) | Err(StorageError::NotFound) => return Ok(false),
                    Err(error) => return Err(error),
                }
                // An explicit release follows the staged file's owner even
                // after it parks. The row's trigger erases the file key.
                let deleted = conn.execute(
                        "DELETE FROM message_draft_attachments
                         WHERE draft_id IN (SELECT draft_id FROM message_drafts WHERE group_id_hex = ?1)
                           AND file_id = ?2
                         AND EXISTS(SELECT 1 FROM media_files WHERE id = ?2 AND state = ?3)",
                        params![
                            group,
                            id.as_bytes().as_slice(),
                            STATE_STAGED
                        ],
                    )
                    .storage()?;
                Ok(deleted == 1)
            })
            .map_err(catalog_error)
    }
}

/// A chunk of a draft attachment: inline bytes, or the staged file to read
/// it from.
#[derive(Clone, PartialEq, Eq)]
pub enum MessageDraftAttachmentRead {
    Bytes(Vec<u8>),
    MediaFile(FileId),
}

impl fmt::Debug for MessageDraftAttachmentRead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(bytes) => formatter
                .debug_struct("Bytes")
                .field("len", &bytes.len())
                .finish(),
            Self::MediaFile(_) => formatter.debug_struct("MediaFile").finish_non_exhaustive(),
        }
    }
}

/// What uploading one draft attachment reads.
#[derive(Clone, PartialEq, Eq)]
pub enum MessageDraftUploadBody {
    Inline(Vec<u8>),
    File { id: FileId, digest: [u8; 32] },
}

impl fmt::Debug for MessageDraftUploadBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline(bytes) => formatter
                .debug_struct("Inline")
                .field("len", &bytes.len())
                .finish(),
            Self::File { .. } => formatter.debug_struct("File").finish_non_exhaustive(),
        }
    }
}

/// One draft attachment to upload: its descriptor and its body.
#[derive(Clone, PartialEq)]
pub struct MessageDraftUploadSource {
    pub attachment: SelectedMessageDraftAttachment,
    pub body: MessageDraftUploadBody,
}

impl fmt::Debug for MessageDraftUploadSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageDraftUploadSource")
            .field("attachment", &self.attachment)
            .finish_non_exhaustive()
    }
}

/// The attachment count and plaintext bytes a draft holds.
fn draft_usage_tx(conn: &Connection, group: &str) -> StorageResult<(u64, u64)> {
    let (count, bytes): (i64, i64) = conn
        .query_row_cached(
            "SELECT count(*), coalesce(sum(CASE WHEN a.file_id IS NULL THEN length(a.plaintext)
                 ELSE m.byte_len END), 0)
             FROM message_draft_attachments a LEFT JOIN media_files m ON m.id = a.file_id
             WHERE a.draft_id = (SELECT draft_id FROM message_drafts WHERE group_id_hex = ?1 AND active = 1)",
            [group],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .storage()?;
    Ok((
        u64::try_from(count).unwrap_or_default(),
        u64::try_from(bytes).unwrap_or_default(),
    ))
}

impl SqliteAppStorage {
    /// The owner of a file being staged into the draft `expected` selects,
    /// which must be current now. The commit needs the same store and
    /// composition, not the same revision, so text saves during the copy do
    /// not lose it but a clear, send or selection change refuses it. `fits`
    /// checks the caller's upload limits at commit as well as the store quota.
    pub fn message_draft_attachment_stage(
        &self,
        expected: &MessageDraftRevision,
        meta: MessageDraftAttachmentFileMeta,
        byte_len: u64,
        fits: fn(count: u64, plaintext_bytes: u64) -> bool,
    ) -> Result<MessageDraftAttachmentStage, MessageDraftRevisionError> {
        let composition = self.connection.with_deferred_read(|conn| {
            check_revision_tx(conn, expected)?;
            let group = expected.group_id_hex();
            let added_bytes = i64::try_from(byte_len).unwrap_or(i64::MAX);
            super::saved::check_attachment_limits(conn, group, 1, added_bytes)?;
            Ok::<_, MessageDraftRevisionError>(composition_tx(conn, group)?)
        })?;
        Ok(MessageDraftAttachmentStage {
            storage: self.clone(),
            expected: expected.clone(),
            composition,
            meta,
            byte_len,
            fits,
            refusal: Cell::new(None),
        })
    }

    /// The attachment count and plaintext bytes of the draft `expected`
    /// selects, checked against that revision: what a stage must still fit.
    pub fn message_draft_usage_if_revision(
        &self,
        expected: &MessageDraftRevision,
        attachment_id: &str,
    ) -> Result<(u64, u64), MessageDraftRevisionError> {
        self.connection.with_deferred_read(|conn| {
            check_revision_tx(conn, expected)?;
            if draft_attachment_ids_tx(conn, expected.group_id_hex())?
                .iter()
                .any(|id| id == attachment_id)
            {
                return Err(MessageDraftRevisionError::Invalid(
                    "attachment ids must be unique",
                ));
            }
            Ok(draft_usage_tx(conn, expected.group_id_hex())?)
        })
    }

    /// Up to `limit` bytes of one draft attachment from `offset`, checked
    /// against the selected revision. A file-backed attachment returns its
    /// file, which the caller reads through the media store. `None` means the
    /// draft has no such attachment.
    pub fn read_message_draft_attachment_if_revision(
        &self,
        expected: &MessageDraftRevision,
        attachment_id: &str,
        offset: u64,
        limit: usize,
    ) -> Result<Option<MessageDraftAttachmentRead>, MessageDraftRevisionError> {
        self.connection.with_deferred_read(|conn| {
            check_revision_tx(conn, expected)?;
            let id = conn
                .query_row_cached(
                    "SELECT draft_id FROM message_drafts WHERE group_id_hex = ?1 AND active = 1",
                    [expected.group_id_hex()],
                    |row| row.get::<_, [u8; 16]>(0),
                )
                .optional()
                .storage()?;
            let Some(id) = id else { return Ok(None) };
            read_draft_attachment_tx(conn, &id, attachment_id, offset, limit)
        })
    }

    /// The attachments `ids` names, in that order, checked against the
    /// selected revision, for an upload from the draft. Inline bytes are
    /// copied out; a file-backed attachment returns its file and the digest
    /// recorded when it was staged.
    pub fn message_draft_upload_sources_if_revision(
        &self,
        expected: &MessageDraftRevision,
        ids: &[String],
    ) -> Result<Vec<MessageDraftUploadSource>, MessageDraftRevisionError> {
        self.connection.with_deferred_read(|conn| {
            check_revision_tx(conn, expected)?;
            let selected = selected_tx(conn, expected.group_id_hex())?
                .draft
                .map(|draft| draft.media_attachments)
                .unwrap_or_default();
            ids.iter()
                .map(|id| {
                    let attachment = selected
                        .iter()
                        .find(|attachment| attachment.id == *id)
                        .cloned()
                        .ok_or(MessageDraftRevisionError::Invalid(
                            "the draft has no such attachment",
                        ))?;
                    let (plaintext, file, digest): (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>) =
                        conn.query_row_cached(
                            "SELECT a.plaintext, a.file_id, m.plaintext_digest
                             FROM message_draft_attachments a
                             LEFT JOIN media_files m ON m.id = a.file_id
                             WHERE a.draft_id = (SELECT draft_id FROM message_drafts WHERE group_id_hex = ?1 AND active = 1) AND a.attachment_id = ?2",
                            params![expected.group_id_hex(), id],
                            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                        )
                        .storage()?;
                    let body = match (file, digest) {
                        (None, _) => MessageDraftUploadBody::Inline(plaintext),
                        (Some(file), Some(digest)) => MessageDraftUploadBody::File {
                            id: file_id(file)?,
                            digest: digest.try_into().map_err(|_| {
                                StorageError::Backend("invalid draft attachment digest".into())
                            })?,
                        },
                        (Some(_), None) => {
                            return Err(StorageError::Backend(
                                "draft attachment file row is missing".into(),
                            )
                            .into());
                        }
                    };
                    Ok(MessageDraftUploadSource { attachment, body })
                })
                .collect()
        })
    }

    /// The staged files a group's draft owns, so a caller can unlink the
    /// ones a later write released.
    pub fn message_draft_attachment_files(&self, group: &str) -> StorageResult<Vec<FileId>> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare_cached(
                "SELECT file_id FROM message_draft_attachments
                 WHERE draft_id IN (SELECT draft_id FROM message_drafts WHERE group_id_hex = ?1)
                   AND file_id IS NOT NULL",
            )
            .storage()?;
        let files = statement
            .query_map([group], |row| row.get::<_, Vec<u8>>(0))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        files.into_iter().map(file_id).collect()
    }
}

pub(super) fn read_draft_attachment_tx(
    conn: &Connection,
    draft_id: &[u8; 16],
    attachment_id: &str,
    offset: u64,
    limit: usize,
) -> Result<Option<MessageDraftAttachmentRead>, MessageDraftRevisionError> {
    let start = i64::try_from(offset)
        .ok()
        .and_then(|offset| offset.checked_add(1))
        .ok_or(MessageDraftRevisionError::Invalid(
            "invalid attachment range",
        ))?;
    let limit = i64::try_from(limit)
        .map_err(|_| MessageDraftRevisionError::Invalid("invalid attachment range"))?;
    conn.query_row_cached(
        "SELECT file_id, CASE WHEN file_id IS NULL THEN substr(plaintext, ?3, ?4) END
         FROM message_draft_attachments WHERE draft_id = ?1 AND attachment_id = ?2",
        params![draft_id, attachment_id, start, limit],
        |row| {
            Ok(match row.get::<_, Option<Vec<u8>>>(0)? {
                Some(file) => Err(file),
                None => Ok(row.get::<_, Option<Vec<u8>>>(1)?.unwrap_or_default()),
            })
        },
    )
    .optional()
    .storage()?
    .map(|read| match read {
        Ok(bytes) => Ok(MessageDraftAttachmentRead::Bytes(bytes)),
        Err(file) => Ok(MessageDraftAttachmentRead::MediaFile(file_id(file)?)),
    })
    .transpose()
}

fn file_id(bytes: Vec<u8>) -> StorageResult<FileId> {
    FileId::from_slice(&bytes)
        .ok_or_else(|| StorageError::Backend("invalid draft attachment file id".into()))
}

#[cfg(test)]
#[path = "files_tests.rs"]
mod tests;
