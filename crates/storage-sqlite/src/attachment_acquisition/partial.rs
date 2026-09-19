//! Protected ciphertext checkpoints. Metadata and chunks share the account DB.
use super::*;

pub const ATTACHMENT_CHECKPOINT_BYTES: usize = 1024 * 1024;
const PARTIAL_TTL_SECONDS: u64 = 24 * 60 * 60;

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
            || identity.total > MAX_RETAINED_ATTACHMENT_BYTES as u64
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
            // Only newly retained resumable bytes break the failure streak.
            // Re-reading/replacing the same prefix must not suppress backoff.
            if end > old.as_ref().map_or(0, |old| old.4) {
                conn.execute(
                    "UPDATE attachment_acquisition SET attempts=1 WHERE token=?1",
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
        let required = if own > 0 { own.min(maximum) } else { maximum };
        Ok(reserved_bytes(&conn)?
            .saturating_sub(own)
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
                || total > MAX_RETAINED_ATTACHMENT_BYTES as u64
            {
                discard()?;
                return Ok(None);
            }
            if expected.is_some_and(|(c, l)| cipher != c || locator != l) {
                return Ok(None);
            }
            let mut stmt = conn
                .prepare(
                    "SELECT offset,bytes,digest FROM attachment_partial_chunk
                 WHERE token=?1 ORDER BY offset",
                )
                .storage()?;
            let mut rows = stmt.query([&job.reference.token]).storage()?;
            let mut bytes = Vec::new();
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

    pub fn prune_attachment_partials(&self, now: u64, limit: usize) -> StorageResult<usize> {
        if limit == 0 || limit > ATTACHMENT_ACQUISITION_BATCH_LIMIT {
            return Err(invalid("invalid partial prune limit"));
        }
        self.lock()?
            .execute(
                "DELETE FROM attachment_partial WHERE token IN (
                 SELECT token FROM attachment_partial WHERE expires_at<=?1
                 ORDER BY expires_at,token LIMIT ?2)",
                params![u64_to_i64(now)?, limit as i64],
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
