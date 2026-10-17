//! Outgoing attachments on the media store (mdk#2314 step 3). A file-backed
//! send reserves an `outgoing_attachment_uploads` row, stages its body as a
//! media file owned by that row ([`AttachmentUploadStage`]), uploads from the
//! staged file, and promotes it into the slots of the published message
//! ([`AttachmentUploadPromotion`]). The store drives the file and the order
//! of steps; these targets only touch rows, one transaction per call.
//!
//! Rows staged this way carry `file_id` and no bytes. Legacy rows (bytes in
//! SQLCipher, `file_id IS NULL`) keep their own promotion path until they
//! expire. No retained-byte budget applies here: free disk, checked by the
//! caller with `media_store::DiskPolicy::send_need`, is the only limit.
use media_store::{
    CatalogResult, FileId, FilePresence, Presence, PromoteTarget, PromotedOutcome, StageTarget,
    StagedOutcome,
};

use super::outgoing::{MAX_STAGED_UPLOADS, UPLOAD_TTL_SECONDS, staging_has_unfulfilled_owner};
use super::*;
use crate::app::media_catalog::{STATE_STAGED, attach_slot, catalog_error};

/// A file-backed upload and one sent message that carries its descriptor:
/// what the worker promotes
/// ([`SqliteAccountStorage::attachment_upload_promotion`]).
#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentUploadOwner {
    pub token: Vec<u8>,
    pub group_id_hex: String,
    pub message_id_hex: String,
    pub file: FileId,
}

impl std::fmt::Debug for AttachmentUploadOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentUploadOwner")
            .finish_non_exhaustive()
    }
}

/// The outgoing upload row that owns one staged body.
pub struct AttachmentUploadStage {
    storage: SqliteAccountStorage,
    token: Vec<u8>,
}

/// Promotion of one upload's file into the slots of a published message.
pub struct AttachmentUploadPromotion {
    storage: SqliteAccountStorage,
    group: String,
    message: String,
    token: Vec<u8>,
    clock: fn() -> u64,
}

impl SqliteAccountStorage {
    /// Reserves an upload row for a file-backed send before its body is
    /// staged. Its digest and file are recorded when the body is staged.
    /// `None` when the account already holds the maximum number of staged
    /// uploads. Expires like any staged upload unless a message owns it.
    pub fn reserve_attachment_upload(
        &self,
        group: &str,
        source_epoch: u64,
        now: u64,
    ) -> StorageResult<Option<Vec<u8>>> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let count: i64 = conn
                .query_row(
                    "SELECT count(*) FROM outgoing_attachment_uploads",
                    [],
                    |r| r.get(0),
                )
                .storage()?;
            if count >= MAX_STAGED_UPLOADS {
                return Ok(None);
            }
            let token: Vec<u8> = conn
                .query_row(
                    "INSERT INTO outgoing_attachment_uploads(
                         token,group_id_hex,source_epoch,plaintext_digest,bytes,expires_at)
                     VALUES(randomblob(16),?1,?2,zeroblob(32),x'',?3) RETURNING token",
                    params![
                        group,
                        u64_to_i64(source_epoch)?,
                        u64_to_i64(now.saturating_add(UPLOAD_TTL_SECONDS))?
                    ],
                    |row| row.get(0),
                )
                .storage()?;
            Ok(Some(token))
        })
    }

    /// The file an upload staged (or promoted), for streaming its upload.
    pub fn attachment_upload_file(&self, token: &[u8]) -> StorageResult<Option<FileId>> {
        let file: Option<Option<Vec<u8>>> = self
            .lock()?
            .query_row(
                "SELECT file_id FROM outgoing_attachment_uploads WHERE token=?1",
                [token],
                |row| row.get(0),
            )
            .optional()
            .storage()?;
        Ok(file.flatten().and_then(|id| FileId::from_slice(&id)))
    }

    /// Up to `limit` (upload, message) pairs to promote: a file-backed,
    /// bound upload and a visible slot of a sent message in a confirmed group
    /// that carries its exact descriptor, in `(token, group, message)` order
    /// after `after`. Found through the descriptor, not the owner rows, so an
    /// upload whose optional owner registration failed still promotes. The
    /// worker pages with its own cursor; the promotion target applies every
    /// other fence.
    pub fn attachment_upload_owners(
        &self,
        after: Option<&AttachmentUploadOwner>,
        limit: usize,
    ) -> StorageResult<Vec<AttachmentUploadOwner>> {
        let (token, group, message) = after.map_or((&[][..], "", ""), |owner| {
            (
                owner.token.as_slice(),
                owner.group_id_hex.as_str(),
                owner.message_id_hex.as_str(),
            )
        });
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT u.token,h.group_id_hex,h.message_id_hex,u.file_id
                 FROM outgoing_attachment_uploads u
                 JOIN attachment_history h ON h.group_id_hex=u.group_id_hex
                     AND h.source_epoch=u.source_epoch AND h.slot_json=u.slot_json
                 JOIN app_events a ON a.group_id_hex=h.group_id_hex AND a.message_id_hex=h.message_id_hex
                 JOIN account_groups g ON g.group_id_hex=h.group_id_hex
                 WHERE u.file_id IS NOT NULL AND h.visible=1 AND a.direction='sent'
                 AND g.pending_confirmation=0
                 AND (u.token,h.group_id_hex,h.message_id_hex)>(?1,?2,?3)
                 GROUP BY u.token,h.group_id_hex,h.message_id_hex
                 ORDER BY u.token,h.group_id_hex,h.message_id_hex LIMIT ?4",
            )
            .storage()?;
        let rows = stmt
            .query_map(
                params![
                    token,
                    group,
                    message,
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        Ok(rows
            .into_iter()
            .filter_map(|(token, group_id_hex, message_id_hex, file)| {
                Some(AttachmentUploadOwner {
                    token,
                    group_id_hex,
                    message_id_hex,
                    file: FileId::from_slice(&file)?,
                })
            })
            .collect())
    }

    /// Deletes upload `token` if its file `file` was lost (missing or
    /// corrupt): no owner can be served from it, so its messages fall back
    /// to downloading their own media. The lost row goes with it unless a
    /// slot still references it. Returns whether the upload was deleted.
    pub fn drop_lost_attachment_upload(&self, token: &[u8], file: FileId) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let deleted = self
                .lock()?
                .execute(
                    "DELETE FROM outgoing_attachment_uploads WHERE token=?1 AND file_id=?2
                     AND EXISTS(SELECT 1 FROM media_files WHERE id=?2 AND state=2)",
                    params![token, file.as_bytes().as_slice()],
                )
                .storage()?;
            Ok(deleted == 1)
        })
    }

    /// The stage target of the upload `token`.
    pub fn attachment_upload_stage(&self, token: &[u8]) -> AttachmentUploadStage {
        AttachmentUploadStage {
            storage: self.clone(),
            token: token.to_vec(),
        }
    }

    /// Promotion of upload `token`'s file into message `message` of `group`.
    /// `clock` gives Unix seconds for the retention fences; it must not block.
    pub fn attachment_upload_promotion(
        &self,
        group: &str,
        message: &str,
        token: &[u8],
        clock: fn() -> u64,
    ) -> AttachmentUploadPromotion {
        AttachmentUploadPromotion {
            storage: self.clone(),
            group: group.to_owned(),
            message: message.to_owned(),
            token: token.to_vec(),
            clock,
        }
    }
}

impl StageTarget for AttachmentUploadStage {
    fn commit_staged(&self, id: FileId, digest: &[u8; 32]) -> CatalogResult<StagedOutcome> {
        self.storage
            .connection
            .with_transaction(|| {
                let conn = self.storage.lock()?;
                let owned: bool = conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM outgoing_attachment_uploads WHERE token=?1)",
                        [&self.token],
                        |row| row.get(0),
                    )
                    .storage()?;
                if !owned {
                    return Ok(StagedOutcome::Superseded);
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
                conn.execute(
                    "UPDATE outgoing_attachment_uploads SET file_id=?2,plaintext_digest=?3 WHERE token=?1",
                    params![self.token, id.as_bytes().as_slice(), digest.as_slice()],
                )
                .storage()?;
                Ok(StagedOutcome::Staged)
            })
            .map_err(catalog_error)
    }

    fn release_staged(&self, id: FileId) -> CatalogResult<bool> {
        self.storage
            .connection
            .with_transaction(|| {
                let conn = self.storage.lock()?;
                let staged: bool = conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM outgoing_attachment_uploads u
                         JOIN media_files m ON m.id=u.file_id
                         WHERE u.token=?1 AND u.file_id=?2 AND m.state=?3)",
                        params![self.token, id.as_bytes().as_slice(), STATE_STAGED],
                        |row| row.get(0),
                    )
                    .storage()?;
                if !staged {
                    return Ok(false);
                }
                // Clearing the reference deletes the staged row (its key)
                // through `outgoing_upload_staged_replaced`.
                conn.execute(
                    "UPDATE outgoing_attachment_uploads SET file_id=NULL WHERE token=?1",
                    [&self.token],
                )
                .storage()?;
                Ok(true)
            })
            .map_err(catalog_error)
    }
}

/// One slot of the published message that this upload can fill.
struct Candidate {
    entry: crate::AttachmentHistoryEntry,
}

impl AttachmentUploadPromotion {
    /// The visible, confirmed, unexpired and not-removed slots of the message
    /// that carry this upload's source descriptor, one per attachment index.
    fn candidates(&self, now: u64) -> StorageResult<Vec<Candidate>> {
        let conn = self.storage.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT h.message_id_hex,h.attachment_index,h.source_message_id_hex,h.source_epoch,
                    h.sender,h.timeline_at,h.received_at,h.slot_json
                FROM attachment_history h JOIN app_events a USING(group_id_hex,message_id_hex)
                JOIN account_groups g USING(group_id_hex)
                JOIN outgoing_attachment_uploads u ON u.group_id_hex=h.group_id_hex
                    AND u.source_epoch=h.source_epoch AND u.slot_json=h.slot_json
                WHERE u.token=?3 AND h.group_id_hex=?1 AND h.message_id_hex=?2 AND h.visible=1
                AND a.direction='sent' AND g.pending_confirmation=0
                AND (a.retention_expires_at IS NULL OR a.retention_expires_at>?4)
                AND NOT EXISTS(SELECT 1 FROM attachment_removal_suppression r
                    WHERE r.group_id_hex=h.group_id_hex AND r.message_id_hex=h.message_id_hex
                    AND r.attachment_index=h.attachment_index)
                ORDER BY h.attachment_index",
            )
            .storage()?;
        let mut seen = std::collections::HashSet::new();
        let rows = stmt
            .query_map(
                params![self.group, self.message, self.token, u64_to_i64(now)?],
                |r| {
                    Ok(crate::AttachmentHistoryEntry {
                        emoji_tags: Vec::new(),
                        message_id_hex: r.get(0)?,
                        attachment_index: r.get::<_, u32>(1)? as usize,
                        source_message_id_hex: r.get(2)?,
                        source_epoch: Some(nonnegative(r, 3)?),
                        sender: r.get(4)?,
                        timeline_at: nonnegative(r, 5)?,
                        received_at: nonnegative(r, 6)?,
                        slot: serde_json::from_str(&r.get::<_, String>(7)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    })
                },
            )
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        Ok(rows
            .into_iter()
            .filter(|entry| seen.insert(entry.attachment_index))
            .map(|entry| Candidate { entry })
            .collect())
    }

    /// The upload's file and its digest, if it is still this upload's.
    fn owned_file(&self, conn: &Connection, id: FileId) -> StorageResult<Option<[u8; 32]>> {
        let digest: Option<Vec<u8>> = conn
            .query_row(
                "SELECT plaintext_digest FROM outgoing_attachment_uploads
                 WHERE token=?1 AND file_id=?2",
                params![self.token, id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .storage()?;
        digest
            .map(|digest| {
                digest
                    .try_into()
                    .map_err(|_| invalid("invalid outgoing attachment digest"))
            })
            .transpose()
    }

    fn commit(&self, id: FileId, present: Presence<'_>) -> StorageResult<PromotedOutcome> {
        let now = (self.clock)();
        let (digest, state) = {
            let conn = self.storage.lock()?;
            let Some(digest) = self.owned_file(&conn, id)? else {
                return Ok(PromotedOutcome::Superseded);
            };
            let row: Option<(i64, i64)> = conn
                .query_row(
                    "SELECT state,category FROM media_files WHERE id=?1",
                    [id.as_bytes().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .storage()?;
            (digest, row)
        };
        let Some((state, category)) = state else {
            return Ok(PromotedOutcome::Superseded);
        };
        let mut staged = match state {
            STATE_STAGED => true,
            1 => false,
            _ => return Ok(PromotedOutcome::Superseded),
        };
        let mut file = id;
        let mut outcome = PromotedOutcome::Superseded;
        // A slot that already holds its body needs nothing from this upload,
        // but still counts toward consuming it.
        let mut satisfied = false;
        for Candidate { entry } in self.candidates(now)? {
            let AttachmentDemand::Requested(asset) =
                self.storage
                    .request_attachment_acquisition(&self.group, &entry, digest, now)?
            else {
                continue;
            };
            let conn = self.storage.lock()?;
            // The legacy path also fences quarantined uploads; a file-backed
            // upload is never quarantined (its body is authenticated by the
            // store on every read), so that conjunct does not apply here.
            let (eligible, already): (bool, bool) = conn
                .query_row(
                    "SELECT NOT EXISTS(SELECT 1 FROM retained_attachment_files f WHERE f.token=?1 AND f.completed=0)
                     AND cancelled=0 AND (state<>4 OR body_completed=1),
                     state=3 AND (EXISTS(SELECT 1 FROM retained_attachment_bytes rb WHERE rb.token=?1)
                         OR EXISTS(SELECT 1 FROM media_file_refs mr JOIN media_files mf ON mf.id=mr.file_id
                             WHERE mr.token=?1 AND mf.state=1))
                     FROM attachment_acquisition WHERE token=?1",
                    [&asset.token],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .storage()?;
            if !eligible {
                continue;
            }
            if already {
                satisfied = true;
                continue;
            }
            if staged {
                // The first slot makes the file ready: an identical ready
                // file on disk is attached instead and this copy dropped.
                let twin: Option<(Vec<u8>, i64)> = conn
                    .query_row(
                        "SELECT id,byte_len FROM media_files
                         WHERE category=?3 AND plaintext_digest=?1 AND state=1 AND id<>?2",
                        params![digest.as_slice(), id.as_bytes().as_slice(), category],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()
                    .storage()?;
                let twin = twin.and_then(|(twin, len)| {
                    Some((FileId::from_slice(&twin)?, u64::try_from(len).ok()?))
                });
                if let Some((twin, len)) = twin {
                    match present(twin, len).map_err(storage_from_catalog)? {
                        FilePresence::Present => {
                            conn.execute(
                                "DELETE FROM media_files WHERE id=?1 AND state=?2",
                                params![id.as_bytes().as_slice(), STATE_STAGED],
                            )
                            .storage()?;
                            conn.execute(
                                "UPDATE outgoing_attachment_uploads SET file_id=?2 WHERE token=?1",
                                params![self.token, twin.as_bytes().as_slice()],
                            )
                            .storage()?;
                            file = twin;
                            outcome = PromotedOutcome::Existing(twin);
                        }
                        FilePresence::Absent => {
                            crate::app::media_catalog::mark_lost_in(&conn, twin)?;
                        }
                    }
                }
                if file == id {
                    conn.execute(
                        "UPDATE media_files SET state=1 WHERE id=?1 AND state=?2",
                        params![id.as_bytes().as_slice(), STATE_STAGED],
                    )
                    .storage()?;
                    outcome = PromotedOutcome::Ready;
                }
                staged = false;
            } else if outcome == PromotedOutcome::Superseded {
                outcome = PromotedOutcome::Ready;
            }
            attach_slot(&conn, &asset.token, file)?;
            conn.execute(
                "UPDATE attachment_acquisition SET state=3,body_completed=1,due=NULL,attempt=NULL,
                 permission_paused=0 WHERE token=?1",
                [&asset.token],
            )
            .storage()?;
        }
        if outcome != PromotedOutcome::Superseded || satisfied {
            let conn = self.storage.lock()?;
            // The upload is consumed unless another message still needs it.
            if !staging_has_unfulfilled_owner(&conn, &self.token, now, None)? {
                conn.execute(
                    "DELETE FROM outgoing_attachment_uploads WHERE token=?1",
                    [&self.token],
                )
                .storage()?;
                if outcome == PromotedOutcome::Superseded {
                    // Nothing was attached. A still-staged file went with its
                    // upload; an already promoted one is kept by its slots.
                    outcome = if staged {
                        PromotedOutcome::Released
                    } else {
                        PromotedOutcome::Ready
                    };
                }
            }
        }
        Ok(outcome)
    }
}

fn storage_from_catalog(error: media_store::CatalogError) -> StorageError {
    match error {
        media_store::CatalogError::Closed => StorageError::Closed("media catalog is closed".into()),
        media_store::CatalogError::Capacity => {
            StorageError::Capacity("media catalog is full".into())
        }
        media_store::CatalogError::Backend(message) => StorageError::Backend(message),
    }
}

impl PromoteTarget for AttachmentUploadPromotion {
    fn commit_promoted(&self, id: FileId, present: Presence<'_>) -> CatalogResult<PromotedOutcome> {
        self.storage
            .connection
            .with_transaction(|| self.commit(id, present))
            .map_err(catalog_error)
    }
}
