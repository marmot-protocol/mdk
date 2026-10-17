//! Download checkpoints. The ciphertext prefix lives in an append-only
//! `.wire` file in the media store; this row records its identity, the
//! length received so far and the wire file's id (mdk#2314 step 2b). The
//! media store drives the file and the ordering through
//! [`AttachmentCheckpoint`](super::AttachmentCheckpoint); these are its row
//! operations, each under the job's attempt fences.
use crate::SqliteAppStorage;
use media_store::{CheckpointStart, FileId};

use super::*;

/// Bytes a download saves per checkpoint append: the media store's largest
/// append, which bounds what a crash can leave unrecorded.
pub const ATTACHMENT_CHECKPOINT_BYTES: usize = media_store::CHECKPOINT_APPEND_MAX;
/// Idle expiry of a checkpoint, measured from its last progress. Parking a job
/// for disk space, readmitting it and explicitly retrying it all refresh this
/// deadline, so a prefix kept through a long park is still loadable when the
/// job resumes by any of those paths.
pub(super) const PARTIAL_TTL_SECONDS: u64 = 24 * 60 * 60;
/// Longest a storage-parked job keeps its prefix, measured from its latest
/// park. A parked prefix is exempt from the idle expiry until then, so it
/// survives while the user frees space, but it cannot hold its disk and its
/// quota reservation forever, for instance while automatic acquisition stays
/// disabled. Past it, the prefix is pruned and the row stays parked without
/// one; its next attempt starts the body over.
pub const STORAGE_PARKED_PREFIX_MAX_AGE_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Whether the row is storage-parked: the state an explicit retry or a
/// readmission resumes from with the parked prefix.
pub(super) fn storage_parked(conn: &Connection, token: &[u8]) -> StorageResult<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM attachment_acquisition WHERE token=?1
         AND state=4 AND cancelled=0 AND storage_blocked_headroom IS NOT NULL)",
        [token],
        |row| row.get(0),
    )
    .storage()
}

/// Give a prefix that is about to be resumed a fresh idle expiry, never a
/// shorter one.
pub(super) fn refresh_partial_expiry(
    conn: &Connection,
    token: &[u8],
    now: u64,
) -> StorageResult<()> {
    conn.execute(
        "UPDATE attachment_partial SET expires_at=max(expires_at,?2) WHERE token=?1",
        params![token, u64_to_i64(now.saturating_add(PARTIAL_TTL_SECONDS))?],
    )
    .storage()?;
    Ok(())
}

/// HTTP validator is opaque and protected; do not log this identity.
#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentPartialIdentity {
    pub ciphertext_digest: [u8; 32],
    pub locator_digest: [u8; 32],
    pub etag: String,
    pub total: u64,
}
/// A checkpoint's metadata: `received` bytes of this representation are
/// durable in the wire file `wire_file`. Never plaintext or permission to
/// display.
pub struct AttachmentPartial {
    pub identity: AttachmentPartialIdentity,
    pub received: u64,
    pub wire_file: FileId,
}

fn validate_identity(identity: &AttachmentPartialIdentity) -> StorageResult<()> {
    if identity.total == 0
        || identity.total > MAX_RETAINED_FILE_ATTACHMENT_BYTES
        || identity.etag.len() > 1024
        || identity.etag.len() < 2
        || !identity.etag.starts_with('"')
        || !identity.etag.ends_with('"')
        || !identity.etag.as_bytes()[1..identity.etag.len() - 1]
            .iter()
            .all(|b| *b == 0x21 || (0x23..=0x7e).contains(b))
    {
        return Err(invalid("invalid partial checkpoint"));
    }
    Ok(())
}

pub(super) fn valid_attempt(
    conn: &Connection,
    job: &AttachmentAcquisition,
    now: u64,
) -> StorageResult<bool> {
    if !valid_publication_attempt(conn, job, now)? {
        return Ok(false);
    }
    conn.query_row(
        "SELECT permission_paused=0 FROM attachment_acquisition WHERE token=?1",
        [&job.reference.token],
        |r| r.get(0),
    )
    .storage()
}

/// Network revocation cannot invalidate publication of an already verified body.
pub(super) fn valid_publication_attempt(
    conn: &Connection,
    job: &AttachmentAcquisition,
    now: u64,
) -> StorageResult<bool> {
    if !matches_store(conn, &job.reference)? {
        return Ok(false);
    }
    conn.query_row(
        &format!(
            "SELECT EXISTS(SELECT 1 FROM attachment_acquisition q
        WHERE token=?1 AND state=1 AND attempt=?2 AND due>?3 AND {SOURCE_MATCH} AND {ACCEPTED}
        AND (expires_at IS NULL OR expires_at>?3))"
        ),
        params![job.reference.token, job.attempt, u64_to_i64(now)?],
        |r| r.get(0),
    )
    .storage()
}

impl SqliteAppStorage {
    /// Inspect a current checkpoint without reading or allocating its body.
    /// This is sink selection only; the selected loader still authenticates chunks.
    pub fn attachment_partial_total(
        &self,
        job: &AttachmentAcquisition,
        now: u64,
        expected: (&[u8; 32], &[u8; 32]),
    ) -> StorageResult<Option<u64>> {
        Ok(self
            .attachment_partial_extent(job, now, expected)?
            .map(|(total, _)| total))
    }

    /// The checkpoint's declared total and the bytes saved so far, without
    /// reading its body. Capacity checks size a restore from both.
    pub fn attachment_partial_extent(
        &self,
        job: &AttachmentAcquisition,
        now: u64,
        expected: (&[u8; 32], &[u8; 32]),
    ) -> StorageResult<Option<(u64, u64)>> {
        let conn = self.lock()?;
        if !valid_attempt(&conn, job, now)? {
            return Ok(None);
        }
        conn.query_row(
            "SELECT total,received FROM attachment_partial WHERE token=?1
             AND ciphertext_digest=?2 AND locator_digest=?3 AND expires_at>?4
             AND received<=total AND total<=?5",
            params![
                job.reference.token,
                &expected.0[..],
                &expected.1[..],
                u64_to_i64(now)?,
                u64_to_i64(MAX_RETAINED_FILE_ATTACHMENT_BYTES)?
            ],
            |row| Ok((nonnegative(row, 0)?, nonnegative(row, 1)?)),
        )
        .optional()
        .storage()
    }

    /// Starts a new checkpoint for this attempt, replacing any earlier one,
    /// and returns the wire file to create and the replaced one's. The row
    /// commits before that file exists, with nothing received. `None` means
    /// the attempt no longer owns the job.
    pub(crate) fn begin_attachment_partial(
        &self,
        job: &AttachmentAcquisition,
        identity: &AttachmentPartialIdentity,
        now: u64,
    ) -> StorageResult<Option<CheckpointStart>> {
        validate_identity(identity)?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if !valid_attempt(&conn, job, now)? {
                return Ok(None);
            }
            // Re-receiving the prefix this replaces is not forward progress.
            let replaced: Option<(u64, Option<Vec<u8>>)> = conn
                .query_row(
                    "SELECT max(received,progress_floor),wire_file_id FROM attachment_partial
                     WHERE token=?1",
                    [&job.reference.token],
                    |row| Ok((nonnegative(row, 0)?, row.get(1)?)),
                )
                .optional()
                .storage()?;
            let floor = replaced.as_ref().map_or(0, |(floor, _)| *floor);
            let replaced = replaced
                .and_then(|(_, wire)| wire)
                .and_then(|wire| FileId::from_slice(&wire));
            conn.execute(
                "DELETE FROM attachment_partial WHERE token=?1",
                [&job.reference.token],
            )
            .storage()?;
            let wire: Vec<u8> = conn
                .query_row(
                    "INSERT INTO attachment_partial(
                         token,ciphertext_digest,locator_digest,etag,total,expires_at,wire_file_id,
                         progress_floor)
                     VALUES(?1,?2,?3,?4,?5,?6,randomblob(16),?7) RETURNING wire_file_id",
                    params![
                        job.reference.token,
                        identity.ciphertext_digest.as_slice(),
                        identity.locator_digest.as_slice(),
                        identity.etag,
                        u64_to_i64(identity.total)?,
                        u64_to_i64(now.saturating_add(PARTIAL_TTL_SECONDS))?,
                        u64_to_i64(floor)?
                    ],
                    |row| row.get(0),
                )
                .storage()?;
            let wire =
                FileId::from_slice(&wire).ok_or_else(|| invalid("invalid partial wire file"))?;
            Ok(Some(CheckpointStart { wire, replaced }))
        })
    }

    /// Records that the wire file `wire_file` now durably holds the first
    /// `received` bytes of this checkpoint's representation. The caller has
    /// appended and synced them first. Only growth of this attempt's own
    /// checkpoint is accepted.
    pub(crate) fn record_attachment_partial(
        &self,
        job: &AttachmentAcquisition,
        identity: &AttachmentPartialIdentity,
        wire_file: &FileId,
        received: u64,
        now: u64,
    ) -> StorageResult<bool> {
        if received > identity.total {
            return Err(invalid("invalid partial checkpoint"));
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if !valid_attempt(&conn, job, now)? {
                return Ok(false);
            }
            let old = conn
                .query_row(
                    "SELECT ciphertext_digest,locator_digest,etag,total,received,wire_file_id,
                         progress_floor
                     FROM attachment_partial WHERE token=?1",
                    [&job.reference.token],
                    |r| {
                        Ok((
                            r.get::<_, Vec<u8>>(0)?,
                            r.get::<_, Vec<u8>>(1)?,
                            r.get::<_, String>(2)?,
                            nonnegative(r, 3)?,
                            nonnegative(r, 4)?,
                            r.get::<_, Option<Vec<u8>>>(5)?,
                            nonnegative(r, 6)?,
                        ))
                    },
                )
                .optional()
                .storage()?;
            let Some(old) = old else {
                return Ok(false);
            };
            if old.0 != identity.ciphertext_digest
                || old.1 != identity.locator_digest
                || old.2 != identity.etag
                || old.3 != identity.total
                || old.5.as_deref() != Some(wire_file.as_bytes().as_slice())
                || received <= old.4
            {
                return Ok(false);
            }
            // Only newly retained resumable bytes break the failure streak and
            // the storage-park streak. Re-receiving a prefix that a restarted
            // checkpoint replaced must not suppress backoff.
            if received > old.6 {
                conn.execute(
                    "UPDATE attachment_acquisition SET attempts=1,storage_park_count=0 WHERE token=?1",
                    [&job.reference.token],
                )
                .storage()?;
            }
            conn.execute(
                "UPDATE attachment_partial SET received=?2,expires_at=?3 WHERE token=?1",
                params![
                    job.reference.token,
                    u64_to_i64(received)?,
                    u64_to_i64(now.saturating_add(PARTIAL_TTL_SECONDS))?
                ],
            )
            .storage()?;
            Ok(true)
        })
    }

    /// The checkpoint to resume, under a current attempt. The expected
    /// identity is checked when given. Expiry, a size over `max_bytes` or an
    /// inconsistent row discards the checkpoint. The caller opens the wire
    /// file at `received` and clears the checkpoint if that fails.
    pub fn load_attachment_partial(
        &self,
        job: &AttachmentAcquisition,
        now: u64,
        max_bytes: u64,
        expected: Option<(&[u8; 32], &[u8; 32])>,
    ) -> StorageResult<Option<AttachmentPartial>> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if !valid_attempt(&conn, job, now)? {
                return Ok(None);
            }
            let row = conn
                .query_row(
                    "SELECT ciphertext_digest,locator_digest,etag,total,received,expires_at,wire_file_id
                 FROM attachment_partial WHERE token=?1",
                    [&job.reference.token],
                    |r| {
                        Ok((
                            r.get::<_, Vec<u8>>(0)?,
                            r.get::<_, Vec<u8>>(1)?,
                            r.get::<_, String>(2)?,
                            nonnegative(r, 3)?,
                            nonnegative(r, 4)?,
                            nonnegative(r, 5)?,
                            r.get::<_, Option<Vec<u8>>>(6)?,
                        ))
                    },
                )
                .optional()
                .storage()?;
            let Some((cipher, locator, etag, total, received, expiry, wire)) = row else {
                return Ok(None);
            };
            let wire = wire.as_deref().and_then(FileId::from_slice);
            let (Some(wire), true) = (
                wire,
                expiry > now
                    && total <= max_bytes
                    && received <= total
                    && total <= MAX_RETAINED_FILE_ATTACHMENT_BYTES,
            ) else {
                conn.execute(
                    "DELETE FROM attachment_partial WHERE token=?1",
                    [&job.reference.token],
                )
                .storage()?;
                return Ok(None);
            };
            if expected.is_some_and(|(c, l)| cipher != c || locator != l) {
                return Ok(None);
            }
            Ok(Some(AttachmentPartial {
                identity: AttachmentPartialIdentity {
                    ciphertext_digest: cipher
                        .try_into()
                        .map_err(|_| invalid("invalid partial digest"))?,
                    locator_digest: locator
                        .try_into()
                        .map_err(|_| invalid("invalid partial locator"))?,
                    etag,
                    total,
                },
                received,
                wire_file: wire,
            }))
        })
    }

    /// Clear only this live attempt's checkpoint; stale/cancelled work cannot
    /// erase a newer attempt's progress. Candidate failures must supply the
    /// expected ciphertext/locator identity; None is for whole-job cleanup.
    /// Returns the removed checkpoint's wire file, for the store to unlink.
    pub(crate) fn clear_attachment_partial(
        &self,
        job: &AttachmentAcquisition,
        now: u64,
        expected: Option<(&[u8; 32], &[u8; 32])>,
    ) -> StorageResult<Option<FileId>> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if !valid_attempt(&conn, job, now)? {
                return Ok(None);
            }
            let wire: Option<Option<Vec<u8>>> = if let Some((ciphertext, locator)) = expected {
                conn.query_row(
                    "DELETE FROM attachment_partial WHERE token=?1
                     AND ciphertext_digest=?2 AND locator_digest=?3 RETURNING wire_file_id",
                    params![
                        job.reference.token,
                        ciphertext.as_slice(),
                        locator.as_slice()
                    ],
                    |row| row.get(0),
                )
            } else {
                conn.query_row(
                    "DELETE FROM attachment_partial WHERE token=?1 RETURNING wire_file_id",
                    [&job.reference.token],
                    |row| row.get(0),
                )
            }
            .optional()
            .storage()?;
            Ok(wire.flatten().and_then(|wire| FileId::from_slice(&wire)))
        })
    }

    /// This attempt's checkpoint for the media store: its wire file and
    /// recorded length, if it matches `expected` and has not expired. Reads
    /// only; an expired row is left for pruning.
    pub(crate) fn current_attachment_partial(
        &self,
        job: &AttachmentAcquisition,
        now: u64,
        expected: Option<(&[u8; 32], &[u8; 32])>,
        identity: Option<&AttachmentPartialIdentity>,
    ) -> StorageResult<Option<(FileId, u64)>> {
        let conn = self.lock()?;
        if !valid_attempt(&conn, job, now)? {
            return Ok(None);
        }
        let row = conn
            .query_row(
                "SELECT ciphertext_digest,locator_digest,etag,total,received,wire_file_id
                 FROM attachment_partial WHERE token=?1 AND expires_at>?2 AND received<=total",
                params![job.reference.token, u64_to_i64(now)?],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, String>(2)?,
                        nonnegative(r, 3)?,
                        nonnegative(r, 4)?,
                        r.get::<_, Option<Vec<u8>>>(5)?,
                    ))
                },
            )
            .optional()
            .storage()?;
        let Some((cipher, locator, etag, total, received, wire)) = row else {
            return Ok(None);
        };
        if expected.is_some_and(|(c, l)| cipher != c || locator != l)
            || identity.is_some_and(|identity| {
                cipher != identity.ciphertext_digest
                    || locator != identity.locator_digest
                    || etag != identity.etag
                    || total != identity.total
            })
        {
            return Ok(None);
        }
        Ok(wire
            .as_deref()
            .and_then(FileId::from_slice)
            .map(|wire| (wire, received)))
    }

    /// Storage-parked jobs are exempt until
    /// [`STORAGE_PARKED_PREFIX_MAX_AGE_SECONDS`] after their latest park: the
    /// prefix is what makes readmission local work. A park sets the prefix's
    /// idle expiry to one TTL past the park, so the exemption ends once that
    /// expiry is more than the remaining age in the past. Cancellation clears
    /// the parked marker, so a cancelled prefix expires as before. A job whose
    /// aged prefix is pruned stays parked; its next attempt parks again at its
    /// first capacity check if the recorded target no longer covers it.
    pub fn prune_attachment_partials(&self, now: u64, limit: usize) -> StorageResult<usize> {
        if limit == 0 || limit > ATTACHMENT_ACQUISITION_BATCH_LIMIT {
            return Err(invalid("invalid partial prune limit"));
        }
        let exempt_after = now
            .saturating_add(PARTIAL_TTL_SECONDS)
            .saturating_sub(STORAGE_PARKED_PREFIX_MAX_AGE_SECONDS);
        self.lock()?
            .execute(
                "DELETE FROM attachment_partial WHERE token IN (
                 SELECT p.token FROM attachment_partial p WHERE p.expires_at<=?1
                 AND NOT (p.expires_at>?3 AND EXISTS(SELECT 1 FROM attachment_acquisition q
                     WHERE q.token=p.token AND q.state=4 AND q.cancelled=0
                     AND q.storage_blocked_headroom IS NOT NULL))
                 ORDER BY p.expires_at,p.token LIMIT ?2)",
                params![u64_to_i64(now)?, limit as i64, u64_to_i64(exempt_after)?],
            )
            .storage()
    }

    /// Bytes `reference`'s checkpoint has recorded, if it has one. Unfenced:
    /// worker admission credits them against what a resumed download still
    /// writes, and the attempt's own checks repeat under its fences.
    pub fn attachment_checkpoint_recorded(
        &self,
        reference: &AttachmentAssetRef,
    ) -> StorageResult<Option<u64>> {
        self.lock()?
            .query_row(
                "SELECT received FROM attachment_partial WHERE token=?1",
                [&reference.token],
                |row| nonnegative(row, 0),
            )
            .optional()
            .storage()
    }

    /// Bytes recorded in ciphertext checkpoints. Test support for free-space
    /// models that charge checkpoint growth to the volume.
    #[cfg(any(test, feature = "test-support"))]
    pub fn attachment_partial_bytes_for_test(&self) -> StorageResult<u64> {
        self.lock()?
            .query_row(
                "SELECT coalesce(sum(received),0) FROM attachment_partial",
                [],
                |row| nonnegative(row, 0),
            )
            .storage()
    }
}
