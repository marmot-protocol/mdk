//! Protected ciphertext checkpoints. Metadata and chunks share the account DB.
use super::*;

pub const ATTACHMENT_CHECKPOINT_BYTES: usize = 1024 * 1024;
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
/// A validated, contiguous ciphertext prefix. Never plaintext or permission to display.
pub struct AttachmentPartial {
    pub identity: AttachmentPartialIdentity,
    pub bytes: Vec<u8>,
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

impl SqliteAccountStorage {
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

    /// Restore a verified ciphertext prefix into a bounded writer rather than
    /// returning a whole-file array. Lease and expiry gates include caller I/O.
    pub fn load_attachment_partial_to_writer(
        &self,
        job: &AttachmentAcquisition,
        now: u64,
        max_bytes: u64,
        expected: (&[u8; 32], &[u8; 32]),
        writer: &mut dyn std::io::Write,
    ) -> StorageResult<Option<(AttachmentPartialIdentity, u64)>> {
        let started = std::time::Instant::now();
        let current_time = || now.saturating_add(started.elapsed().as_secs());
        let metadata = |conn: &Connection| {
            conn.query_row(
                "SELECT ciphertext_digest,locator_digest,etag,total,received,expires_at
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
                    ))
                },
            )
            .optional()
            .storage()
        };
        let snapshot = self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let now = current_time();
            if !valid_attempt(&conn, job, now)? {
                return Ok(None);
            }
            let Some(row) = metadata(&conn)? else {
                return Ok(None);
            };
            if row.0 != expected.0 || row.1 != expected.1 {
                return Ok(None);
            }
            if row.5 <= now
                || row.3 > max_bytes
                || row.3 > MAX_RETAINED_FILE_ATTACHMENT_BYTES
                || row.4 > row.3
            {
                conn.execute(
                    "DELETE FROM attachment_partial WHERE token=?1",
                    [&job.reference.token],
                )
                .storage()?;
                return Ok(None);
            }
            Ok(Some(row))
        })?;
        let Some(snapshot) = snapshot else {
            return Ok(None);
        };
        let identity = AttachmentPartialIdentity {
            ciphertext_digest: snapshot
                .0
                .clone()
                .try_into()
                .map_err(|_| invalid("invalid partial digest"))?,
            locator_digest: snapshot
                .1
                .clone()
                .try_into()
                .map_err(|_| invalid("invalid partial locator"))?,
            etag: snapshot.2.clone(),
            total: snapshot.3,
        };
        // Recheck the frozen representation as well as the attempt/source before
        // each bounded read and once after the last caller write. Neither the
        // account guard nor its transaction survives into hashing or caller I/O.
        let mut copied = 0u64;
        let mut previous_offset = -1i64;
        loop {
            let next = self.connection.with_transaction(|| {
                let conn = self.lock()?;
                let now = current_time();
                if !valid_attempt(&conn, job, now)? || metadata(&conn)?.as_ref() != Some(&snapshot)
                {
                    return Ok(None);
                }
                if snapshot.5 <= now {
                    conn.execute(
                        "DELETE FROM attachment_partial WHERE token=?1",
                        [&job.reference.token],
                    )
                    .storage()?;
                    return Ok(None);
                }
                let chunk = conn
                    .query_row(
                        "SELECT offset,bytes,digest FROM attachment_partial_chunk
                     WHERE token=?1 AND offset>?2 ORDER BY offset LIMIT 1",
                        params![job.reference.token, previous_offset],
                        |r| {
                            Ok((
                                nonnegative(r, 0)?,
                                r.get::<_, Vec<u8>>(1)?,
                                r.get::<_, Vec<u8>>(2)?,
                            ))
                        },
                    )
                    .optional()
                    .storage()?;
                Ok(Some(chunk))
            })?;
            let Some(next) = next else {
                return Ok(None);
            };
            let corrupt = match &next {
                Some((offset, bytes, digest)) => {
                    *offset != copied
                        || bytes.is_empty()
                        || bytes.len() > ATTACHMENT_CHECKPOINT_BYTES
                        || copied.saturating_add(bytes.len() as u64) > snapshot.4
                        || Sha256::digest(bytes).as_slice() != digest
                }
                None => copied != snapshot.4,
            };
            if corrupt {
                // A cancelled loader must not clear a replacement checkpoint.
                self.connection.with_transaction(|| {
                    let conn = self.lock()?;
                    if valid_attempt(&conn, job, current_time())?
                        && metadata(&conn)?.as_ref() == Some(&snapshot)
                    {
                        conn.execute(
                            "DELETE FROM attachment_partial WHERE token=?1",
                            [&job.reference.token],
                        )
                        .storage()?;
                    }
                    Ok(())
                })?;
                return Ok(None);
            }
            let Some((offset, bytes, _)) = next else {
                return Ok(Some((identity, copied)));
            };
            writer
                .write_all(&bytes)
                .map_err(|_| invalid("partial checkpoint copy failed"))?;
            previous_offset = u64_to_i64(offset)?;
            copied += bytes.len() as u64;
        }
    }

    /// Append at an exact offset, in bounded chunks. A new zero-offset checkpoint
    /// atomically replaces the prior representation. Source/attempt/quota checks
    /// precede all writes; a late task cannot recreate a removed source.
    pub fn checkpoint_attachment_partial(
        &self,
        job: &AttachmentAcquisition,
        identity: &AttachmentPartialIdentity,
        offset: u64,
        bytes: &[u8],
        now: u64,
        byte_budget: u64,
    ) -> StorageResult<bool> {
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| invalid("partial offset overflow"))?;
        if bytes.is_empty()
            || bytes.len() > ATTACHMENT_CHECKPOINT_BYTES
            || end > identity.total
            || identity.total > MAX_RETAINED_FILE_ATTACHMENT_BYTES
            || identity.etag.len() > 1024
            || !identity.etag.starts_with('"')
            || !identity.etag.ends_with('"')
            || identity.etag.len() < 2
            || !identity.etag.as_bytes()[1..identity.etag.len() - 1]
                .iter()
                .all(|b| *b == 0x21 || (0x23..=0x7e).contains(b))
        {
            return Err(invalid("invalid partial checkpoint"));
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if !valid_attempt(&conn, job, now)? {
                return Ok(false);
            }
            let old = conn
                .query_row(
                    "SELECT ciphertext_digest, locator_digest, etag, total, received
                 FROM attachment_partial WHERE token=?1",
                    [&job.reference.token],
                    |r| {
                        Ok((
                            r.get::<_, Vec<u8>>(0)?,
                            r.get::<_, Vec<u8>>(1)?,
                            r.get::<_, String>(2)?,
                            nonnegative(r, 3)?,
                            nonnegative(r, 4)?,
                        ))
                    },
                )
                .optional()
                .storage()?;
            if offset > 0
                && !old.as_ref().is_some_and(|v| {
                    v.0 == identity.ciphertext_digest
                        && v.1 == identity.locator_digest
                        && v.2 == identity.etag
                        && v.3 == identity.total
                        && v.4 == offset
                })
            {
                return Ok(false);
            }
            let used = reserved_bytes(&conn)?;
            let replaced = old.as_ref().map_or(0, |v| v.3);
            // Reserve the complete representation on its first checkpoint.
            // Other interrupted jobs cannot consume space needed to finish it.
            if used.saturating_sub(replaced).saturating_add(identity.total) > byte_budget {
                return Ok(false);
            }
            if offset == 0 {
                conn.execute(
                    "DELETE FROM attachment_partial WHERE token=?1",
                    [&job.reference.token],
                )
                .storage()?;
                conn.execute(
                    "INSERT INTO attachment_partial(
                         token,ciphertext_digest,locator_digest,etag,total,expires_at)
                     VALUES(?1,?2,?3,?4,?5,?6)",
                    params![
                        job.reference.token,
                        identity.ciphertext_digest.as_slice(),
                        identity.locator_digest.as_slice(),
                        identity.etag,
                        u64_to_i64(identity.total)?,
                        u64_to_i64(now.saturating_add(PARTIAL_TTL_SECONDS))?
                    ],
                )
                .storage()?;
            }
            conn.execute(
                "INSERT INTO attachment_partial_chunk(token,offset,bytes,digest)
                 VALUES(?1,?2,?3,?4)",
                params![
                    job.reference.token,
                    u64_to_i64(offset)?,
                    bytes,
                    Sha256::digest(bytes).as_slice()
                ],
            )
            .storage()?;
            // Only newly retained resumable bytes break the failure streak and
            // the storage-park streak. Re-reading/replacing the same prefix
            // must not suppress backoff.
            if end > old.as_ref().map_or(0, |old| old.4) {
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
                    u64_to_i64(end)?,
                    u64_to_i64(now.saturating_add(PARTIAL_TTL_SECONDS))?
                ],
            )
            .storage()?;
            Ok(true)
        })
    }

    /// Account bytes committed to retained data and complete partial representations.
    /// Existing prefixes keep their reservation; new transfers reserve the policy cap.
    pub fn attachment_acquisition_fits_budget(
        &self,
        reference: &AttachmentAssetRef,
        maximum: u64,
        budget: u64,
    ) -> StorageResult<bool> {
        let conn = self.lock()?;
        if !matches_store(&conn, reference)? {
            return Ok(false);
        }
        let own: u64 = conn
            .query_row(
                "SELECT coalesce((SELECT total FROM attachment_partial WHERE token=?1),0)",
                [&reference.token],
                |r| nonnegative(r, 0),
            )
            .storage()?;
        let own_import: u64 = conn.query_row(
            "SELECT coalesce((SELECT byte_len FROM retained_attachment_files WHERE token=?1 AND completed=0),0)",
            [&reference.token], |r| nonnegative(r,0),
        ).storage()?;
        let required = if own > 0 { own.min(maximum) } else { maximum };
        Ok(reserved_bytes(&conn)?
            .saturating_sub(own)
            .saturating_sub(own_import)
            .saturating_add(required)
            <= budget)
    }

    /// Read only under a current attempt. Optional expected identity is checked
    /// before reading chunks. Corruption, expiry or policy shrink discards the prefix.
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
                    "SELECT ciphertext_digest,locator_digest,etag,total,received,expires_at
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
                        ))
                    },
                )
                .optional()
                .storage()?;
            let Some((cipher, locator, etag, total, received, expiry)) = row else {
                return Ok(None);
            };
            let discard = || {
                conn.execute(
                    "DELETE FROM attachment_partial WHERE token=?1",
                    [&job.reference.token],
                )
                .storage()
            };
            if expiry <= now
                || total > max_bytes
                || received > total
                || total > MAX_RETAINED_FILE_ATTACHMENT_BYTES
            {
                discard()?;
                return Ok(None);
            }
            if expected.is_some_and(|(c, l)| cipher != c || locator != l) {
                return Ok(None);
            }
            // The legacy array API cannot restore a large prefix. Leave it
            // intact for the file-backed API rather than destroying resumability.
            if total > MAX_RETAINED_ATTACHMENT_BYTES as u64 {
                return Ok(None);
            }
            let mut stmt = conn
                .prepare(
                    "SELECT offset,bytes,digest FROM attachment_partial_chunk
                 WHERE token=?1 ORDER BY offset",
                )
                .storage()?;
            let mut rows = stmt.query([&job.reference.token]).storage()?;
            // Size the prefix for the complete representation once, so neither
            // this reassembly nor the resumed body grows it by doubling. A
            // failed reservation is a backend error the runtime retries later.
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(total as usize).map_err(|_| {
                StorageError::Backend("partial checkpoint buffer unavailable".into())
            })?;
            let mut corrupt = false;
            while let Some(row) = rows.next().storage()? {
                let offset = nonnegative(row, 0).storage()?;
                let chunk: Vec<u8> = row.get(1).storage()?;
                let digest: Vec<u8> = row.get(2).storage()?;
                if offset != bytes.len() as u64
                    || chunk.is_empty()
                    || chunk.len() > ATTACHMENT_CHECKPOINT_BYTES
                    || offset.saturating_add(chunk.len() as u64) > received
                    || Sha256::digest(&chunk).as_slice() != digest
                {
                    corrupt = true;
                    break;
                }
                bytes.extend_from_slice(&chunk);
            }
            drop(rows);
            drop(stmt);
            if corrupt || bytes.len() as u64 != received {
                discard()?;
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
                bytes,
            }))
        })
    }

    /// Clear only this live attempt's checkpoint; stale/cancelled work cannot
    /// erase a newer attempt's progress. Candidate failures must supply the
    /// expected ciphertext/locator identity; None is for whole-job cleanup.
    pub fn clear_attachment_partial(
        &self,
        job: &AttachmentAcquisition,
        now: u64,
        expected: Option<(&[u8; 32], &[u8; 32])>,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if !valid_attempt(&conn, job, now)? {
                return Ok(false);
            }
            let removed = if let Some((ciphertext, locator)) = expected {
                conn.execute(
                    "DELETE FROM attachment_partial WHERE token=?1
                     AND ciphertext_digest=?2 AND locator_digest=?3",
                    params![
                        job.reference.token,
                        ciphertext.as_slice(),
                        locator.as_slice()
                    ],
                )
            } else {
                conn.execute(
                    "DELETE FROM attachment_partial WHERE token=?1",
                    [&job.reference.token],
                )
            }
            .storage()?;
            Ok(removed > 0)
        })
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

    /// Bytes currently held in ciphertext checkpoints. Test support for
    /// free-space models that charge checkpoint growth to the volume.
    #[cfg(any(test, feature = "test-support"))]
    pub fn attachment_partial_bytes_for_test(&self) -> StorageResult<u64> {
        self.lock()?
            .query_row(
                "SELECT coalesce(sum(length(bytes)),0) FROM attachment_partial_chunk",
                [],
                |row| nonnegative(row, 0),
            )
            .storage()
    }
}

fn reserved_bytes(conn: &Connection) -> StorageResult<u64> {
    conn.query_row(
        "SELECT r.byte_count+p.reserved_bytes
         FROM attachment_retention_usage r,attachment_partial_usage p
         WHERE r.id=1 AND p.id=1",
        [],
        |r| nonnegative(r, 0),
    )
    .storage()
}
