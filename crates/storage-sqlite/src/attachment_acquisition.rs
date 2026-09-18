//! C8-C storage foundation. No network, parser, secret warming or scheduler.
//! Callers request only shared-parser accepted references, reserve media capacity
//! before claiming, and authenticate/decrypt the complete body before publishing.
//! Bytes stay in the account's SQLCipher store; there is no attachment LRU.
use crate::chat_presentation::nonnegative;
use crate::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt, u64_to_i64};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Storage plaintext safety ceiling, independent of transport admission. The
/// current transport also caps ciphertext at 512 MiB, including its AEAD overhead;
/// transport-valid plaintext is therefore smaller. This is not a size negotiation.
pub const MAX_RETAINED_ATTACHMENT_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_ATTACHMENT_LOCAL_READ_BYTES: usize = 1024 * 1024;
pub const ATTACHMENT_ACQUISITION_BATCH_LIMIT: usize = 64;
const MAX_DESCRIPTOR_BYTES: usize = 16384;

#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentAssetRef {
    store_epoch: Vec<u8>,
    token: Vec<u8>,
}
impl std::fmt::Debug for AttachmentAssetRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentAssetRef").finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachmentAcquisitionState {
    Queued,
    Fetching,
    RetryScheduled,
    Ready,
    /// Failed until explicit retry; ordinary demand preserves this state.
    Blocked,
    /// Temporarily ineligible at claim time; eligible demand requeues it.
    Parked,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttachmentDemand {
    /// Existing or newly admitted demand. Inspect status for ready/failed work;
    /// this does not imply that a download is currently queued.
    Requested(AttachmentAssetRef),
    Suppressed,
    Unavailable,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentAcquisitionStatus {
    pub state: AttachmentAcquisitionState,
    pub attempts: u64,
    pub due: Option<u64>,
    pub byte_count: u64,
}
/// Opaque completion fence, scoped to the store and a single attempt. Source
/// locators remain protected in SQLite; Debug never exposes their contents.
#[derive(Clone)]
pub struct AttachmentAcquisition {
    pub reference: AttachmentAssetRef,
    pub group_id_hex: String,
    pub message_id_hex: String,
    pub attachment_index: u32,
    pub source_message_id_hex: String,
    pub source_epoch: u64,
    pub slot: serde_json::Value,
    attempt: Vec<u8>,
    digest: Vec<u8>,
}
impl std::fmt::Debug for AttachmentAcquisition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentAcquisition")
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachmentPublishResult {
    Published,
    Superseded,
    /// No bytes were committed or evicted. The caller must persist a retry or
    /// blocked outcome and pause admission until capacity is available.
    CapacityBlocked,
}
fn invalid(message: &str) -> StorageError {
    StorageError::Backend(message.into())
}
fn epoch(conn: &Connection) -> StorageResult<Vec<u8>> {
    conn.query_row(
        "SELECT store_epoch FROM chat_presentation_meta WHERE id=1",
        [],
        |r| r.get(0),
    )
    .storage()
}
fn matches_store(conn: &Connection, reference: &AttachmentAssetRef) -> StorageResult<bool> {
    Ok(epoch(conn)? == reference.store_epoch)
}

// Deliberately independent of timeline row identity and sort/received timestamps.
// Repairs may recreate rows; only changed attachment source material invalidates.
const SOURCE_MATCH: &str = "EXISTS(SELECT 1 FROM attachment_history h
 WHERE h.group_id_hex=q.group_id_hex AND h.message_id_hex=q.message_id_hex
 AND h.attachment_index=q.attachment_index AND h.source_message_id_hex=q.source_message_id_hex
 AND h.source_epoch=q.source_epoch AND h.slot_json=q.slot_json AND h.visible=1)";
const ACCEPTED: &str = "EXISTS(SELECT 1 FROM account_groups g
 WHERE g.group_id_hex=q.group_id_hex AND g.pending_confirmation=0)";

/// Called after whole-group rebuild (never during its DELETE/INSERT interval).
pub(crate) fn reconcile_attachment_acquisition_tx(
    conn: &Connection,
    group: &str,
    message: Option<&str>,
) -> StorageResult<()> {
    // Historical migrations invoke timeline rebuild before migration 83 exists.
    let present: bool = conn
        .query_row_cached(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master
         WHERE type='table' AND name='attachment_acquisition')",
            [],
            |r| r.get(0),
        )
        .storage()?;
    if !present {
        return Ok(());
    }
    let message_filter = if message.is_some() {
        "AND message_id_hex=?2"
    } else {
        ""
    };
    let query = format!(
        "DELETE FROM attachment_acquisition WHERE group_id_hex=?1 {message_filter} AND NOT EXISTS(
        SELECT 1 FROM attachment_history h WHERE h.group_id_hex=attachment_acquisition.group_id_hex
        AND h.message_id_hex=attachment_acquisition.message_id_hex
        AND h.attachment_index=attachment_acquisition.attachment_index
        AND h.source_message_id_hex=attachment_acquisition.source_message_id_hex
        AND h.source_epoch=attachment_acquisition.source_epoch
        AND h.slot_json=attachment_acquisition.slot_json)"
    );
    let mut args = vec![rusqlite::types::Value::Text(group.to_owned())];
    if let Some(message) = message {
        args.push(rusqlite::types::Value::Text(message.to_owned()));
    }
    conn.execute(&query, rusqlite::params_from_iter(args))
        .storage()?;
    Ok(())
}

/// A bounded parser work item. Its generation fences acknowledgement against
/// a source update or rebuild that arrives while the caller is parsing it.
pub struct AttachmentWorkerDemand {
    pub group_id_hex: String,
    pub entry: crate::AttachmentHistoryEntry,
    generation: Vec<u8>,
}

/// Source material for local preparation. This is not a lease or permission to
/// fetch; claim must still succeed for this exact asset before network work.
pub struct AttachmentAcquisitionSource {
    pub group_id_hex: String,
    pub source_epoch: u64,
    pub slot: serde_json::Value,
}

impl AttachmentAcquisition {
    /// Deterministic publication validation, distinct from transient DB errors.
    pub fn verify_plaintext(&self, plaintext: &[u8]) -> StorageResult<()> {
        if plaintext.len() > MAX_RETAINED_ATTACHMENT_BYTES {
            return Err(invalid("retained attachment exceeds storage bound"));
        }
        if Sha256::digest(plaintext).as_slice() != self.digest {
            return Err(invalid("attachment plaintext digest mismatch"));
        }
        Ok(())
    }
}

impl SqliteAccountStorage {
    /// Read source changes without a history scan. Oversized descriptors are
    /// represented as null so the shared parser rejects them without allocation.
    pub fn attachment_worker_demands(
        &self,
        limit: usize,
    ) -> StorageResult<Vec<AttachmentWorkerDemand>> {
        if limit == 0 || limit > ATTACHMENT_ACQUISITION_BATCH_LIMIT {
            return Err(invalid("invalid attachment demand limit"));
        }
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT d.group_id_hex,d.generation,h.message_id_hex,
            h.attachment_index,h.source_message_id_hex,h.source_epoch,h.sender,h.timeline_at,h.received_at,
            CASE WHEN length(CAST(h.slot_json AS BLOB))<=16384 THEN h.slot_json ELSE 'null' END
            FROM attachment_worker_demand d JOIN attachment_history h
            USING(group_id_hex,message_id_hex,attachment_index)
            ORDER BY d.group_id_hex,d.message_id_hex,d.attachment_index LIMIT ?1").storage()?;
        stmt.query_map([limit as i64], |r| {
            let slot: String = r.get(9)?;
            Ok(AttachmentWorkerDemand {
                group_id_hex: r.get(0)?,
                generation: r.get(1)?,
                entry: crate::AttachmentHistoryEntry {
                    message_id_hex: r.get(2)?,
                    attachment_index: r.get::<_, u32>(3)? as usize,
                    source_message_id_hex: r.get(4)?,
                    source_epoch: r.get::<_, Option<i64>>(5)?.map(|v| v as u64),
                    sender: r.get(6)?,
                    timeline_at: nonnegative(r, 7)?,
                    received_at: nonnegative(r, 8)?,
                    slot: serde_json::from_str(&slot).unwrap_or(serde_json::Value::Null),
                },
            })
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()
    }

    pub fn acknowledge_attachment_worker_demand(
        &self,
        demand: &AttachmentWorkerDemand,
    ) -> StorageResult<()> {
        self.lock()?
            .execute(
                "DELETE FROM attachment_worker_demand
            WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=?3 AND generation=?4",
                params![
                    demand.group_id_hex,
                    demand.entry.message_id_hex,
                    demand.entry.attachment_index as i64,
                    demand.generation
                ],
            )
            .storage()?;
        Ok(())
    }

    /// Persist source-bound demand after the app has validated this exact slot
    /// and its plaintext digest with the shared parser. Pending invitations,
    /// hidden/expired/missing sources and legacy unknown epochs are not admitted.
    /// Repeated demand preserves ready assets, active attempts, retry deadlines
    /// and explicit-retry failures; it resumes a temporarily parked job.
    ///
    /// The digest MUST be the shared parser's plaintext hash for `selected.slot`.
    /// Storage verifies source identity, not imeta semantics. A mismatched digest
    /// is an unrecoverable caller bug, not a transport failure to retry; the caller
    /// must re-parse that same authoritative slot and submit corrected demand.
    pub fn request_attachment_acquisition(
        &self,
        group: &str,
        selected: &crate::AttachmentHistoryEntry,
        plaintext_digest: [u8; 32],
        now: u64,
    ) -> StorageResult<AttachmentDemand> {
        let message = selected.message_id_hex.as_str();
        let index = u32::try_from(selected.attachment_index)
            .map_err(|_| invalid("invalid attachment index"))?;
        let now = u64_to_i64(now)?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let suppressed: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM attachment_removal_suppression
                 WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=?3)",
                    params![group, message, index],
                    |r| r.get(0),
                )
                .storage()?;
            if suppressed {
                return Ok(AttachmentDemand::Suppressed);
            }
            let source = conn.query_row(
                "SELECT h.source_message_id_hex,h.source_epoch,h.slot_json,a.retention_expires_at
                 FROM attachment_history h JOIN app_events a USING(group_id_hex,message_id_hex)
                 JOIN account_groups g USING(group_id_hex)
                 WHERE h.group_id_hex=?1 AND h.message_id_hex=?2 AND h.attachment_index=?3
                   AND h.visible=1 AND h.source_epoch IS NOT NULL AND g.pending_confirmation=0
                   AND (a.retention_expires_at IS NULL OR a.retention_expires_at>?4)",
                params![group, message, index, now],
                |r| Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                )),
            ).optional().storage()?;
            let Some((source, source_epoch, slot, expires)) = source else {
                return Ok(AttachmentDemand::Unavailable);
            };
            if slot.len() > MAX_DESCRIPTOR_BYTES || source_epoch < 0 {
                return Err(invalid("attachment descriptor exceeds storage bounds"));
            }
            let current_slot: serde_json::Value = serde_json::from_str(&slot)
                .map_err(|_| invalid("invalid stored attachment slot"))?;
            if selected.source_message_id_hex != source
                || selected.source_epoch != Some(source_epoch as u64)
                || selected.slot != current_slot
            {
                return Ok(AttachmentDemand::Unavailable);
            }
            conn.execute(
                "DELETE FROM attachment_acquisition
                 WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=?3
                   AND (source_message_id_hex<>?4 OR source_epoch<>?5
                        OR slot_json<>?6 OR plaintext_digest<>?7)",
                params![
                    group,
                    message,
                    index,
                    source,
                    source_epoch,
                    slot,
                    &plaintext_digest[..]
                ],
            )
            .storage()?;
            // Only policy parking is resumable through ordinary demand. Failed
            // jobs still require explicit retry; backoff and leases stay intact.
            conn.execute(
                "INSERT INTO attachment_acquisition(
                    token,group_id_hex,message_id_hex,attachment_index,
                    source_message_id_hex,source_epoch,slot_json,plaintext_digest,expires_at,due)
                 VALUES(randomblob(16),?1,?2,?3,?4,?5,?6,?7,?8,?9)
                 ON CONFLICT(group_id_hex,message_id_hex,attachment_index)
                 DO UPDATE SET state=0,due=excluded.due
                 WHERE attachment_acquisition.state=5",
                params![
                    group,
                    message,
                    index,
                    source,
                    source_epoch,
                    slot,
                    &plaintext_digest[..],
                    expires,
                    now
                ],
            )
            .storage()?;
            let token = conn
                .query_row(
                    "SELECT token FROM attachment_acquisition
                 WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=?3",
                    params![group, message, index],
                    |r| r.get(0),
                )
                .storage()?;
            Ok(AttachmentDemand::Requested(AttachmentAssetRef {
                store_epoch: epoch(&conn)?,
                token,
            }))
        })
    }

    /// Bounded candidates, including expired leases. Reserve worker/media capacity
    /// before claim. A candidate is not a permission to fetch; claim rechecks it.
    pub fn due_attachment_acquisitions(
        &self,
        now: u64,
        limit: usize,
    ) -> StorageResult<Vec<AttachmentAssetRef>> {
        if limit == 0 || limit > ATTACHMENT_ACQUISITION_BATCH_LIMIT {
            return Err(invalid("invalid attachment job page limit"));
        }
        let conn = self.lock()?;
        let store_epoch = epoch(&conn)?;
        let mut statement = conn.prepare(
            "SELECT token FROM attachment_acquisition WHERE due<=?1 ORDER BY due,token LIMIT ?2",
        ).storage()?;
        let tokens = statement
            .query_map(params![u64_to_i64(now)?, limit as i64], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        Ok(tokens
            .into_iter()
            .map(|token| AttachmentAssetRef {
                store_epoch: store_epoch.clone(),
                token,
            })
            .collect())
    }

    /// Reclaim abandoned attempts once, under the new account worker's exclusive
    /// ownership, before it starts any transfers. Bounded and attempt-fenced;
    /// scheduled retries, terminal failures and ready bytes are unchanged.
    pub fn resume_attachment_acquisitions(&self, now: u64, limit: usize) -> StorageResult<usize> {
        if limit == 0 || limit > ATTACHMENT_ACQUISITION_BATCH_LIMIT {
            return Err(invalid("invalid attachment resume limit"));
        }
        self.lock()?.execute("UPDATE attachment_acquisition SET state=0,due=?1,attempt=NULL
            WHERE token IN (SELECT token FROM attachment_acquisition WHERE state=1 ORDER BY token LIMIT ?2)",
            params![u64_to_i64(now)?,limit as i64]).storage()
    }

    /// Select a due source without incrementing attempts. Ineligible sources are
    /// parked just as at claim time, so stale rows cannot obstruct the due page.
    pub fn prepare_attachment_acquisition(
        &self,
        reference: &AttachmentAssetRef,
        now: u64,
    ) -> StorageResult<Option<AttachmentAcquisitionSource>> {
        let now = u64_to_i64(now)?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if !matches_store(&conn, reference)? { return Ok(None); }
            let row = conn.query_row(&format!("SELECT group_id_hex,source_epoch,slot_json
                FROM attachment_acquisition q WHERE token=?1 AND due<=?2 AND {SOURCE_MATCH} AND {ACCEPTED}
                AND (expires_at IS NULL OR expires_at>?2)"), params![reference.token,now], |r|
                Ok((r.get::<_,String>(0)?,nonnegative(r,1)?,r.get::<_,String>(2)?))).optional().storage()?;
            let Some((group_id_hex,source_epoch,slot)) = row else {
                conn.execute("UPDATE attachment_acquisition SET state=5,due=NULL,attempt=NULL
                    WHERE token=?1 AND due<=?2",params![reference.token,now]).storage()?;
                return Ok(None);
            };
            Ok(Some(AttachmentAcquisitionSource { group_id_hex,source_epoch,
                slot: serde_json::from_str(&slot).map_err(|_| invalid("invalid stored attachment slot"))? }))
        })
    }

    /// Defer readiness checks without recording a transfer attempt, or block a
    /// structurally invalid source. Never replace an active lease or newer job.
    pub fn finish_attachment_preparation(
        &self,
        reference: &AttachmentAssetRef,
        now: u64,
        retry_at: Option<u64>,
    ) -> StorageResult<()> {
        let due = retry_at.map(u64_to_i64).transpose()?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if !matches_store(&conn, reference)? {
                return Ok(());
            }
            conn.execute(
                "UPDATE attachment_acquisition SET state=?3,due=?4
                WHERE token=?1 AND due<=?2 AND state IN (0,2)",
                params![
                    reference.token,
                    u64_to_i64(now)?,
                    if due.is_some() { 2 } else { 4 },
                    due
                ],
            )
            .storage()?;
            Ok(())
        })
    }

    /// Lease deadlines are chosen by the runtime transfer policy. Expired leases
    /// can be reclaimed after process death; the new attempt fences late results.
    pub fn claim_attachment_acquisition(
        &self,
        reference: &AttachmentAssetRef,
        now: u64,
        lease_until: u64,
    ) -> StorageResult<Option<AttachmentAcquisition>> {
        if lease_until <= now {
            return Err(invalid("attachment lease must end after now"));
        }
        let now = u64_to_i64(now)?;
        let deadline = u64_to_i64(lease_until)?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if !matches_store(&conn, reference)? {
                return Ok(None);
            }
            let claimable: bool = conn
                .query_row(
                    &format!(
                        "SELECT EXISTS(SELECT 1 FROM attachment_acquisition q
                    WHERE token=?1 AND due<=?2 AND {SOURCE_MATCH} AND {ACCEPTED}
                    AND (expires_at IS NULL OR expires_at>?2))"
                    ),
                    params![reference.token, now],
                    |r| r.get(0),
                )
                .storage()?;
            if !claimable {
                // Keep ineligible work off the due page without conflating it
                // with terminal failure. Re-admission after policy change
                // requeues a parked job while preserving explicit removal.
                conn.execute(
                    "UPDATE attachment_acquisition SET state=5,due=NULL,attempt=NULL
                     WHERE token=?1 AND due<=?2",
                    params![reference.token, now],
                )
                .storage()?;
                return Ok(None);
            }
            conn.execute(
                "UPDATE attachment_acquisition SET state=1,due=?2,attempt=randomblob(16),
                    attempts=min(attempts+1,2147483647) WHERE token=?1",
                params![reference.token, deadline],
            )
            .storage()?;
            let job = conn
                .query_row(
                    "SELECT group_id_hex,message_id_hex,attachment_index,source_message_id_hex,
                    source_epoch,slot_json,attempt,plaintext_digest
                 FROM attachment_acquisition WHERE token=?1",
                    [&reference.token],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, u32>(2)?,
                            r.get::<_, String>(3)?,
                            nonnegative(r, 4)?,
                            r.get::<_, String>(5)?,
                            r.get::<_, Vec<u8>>(6)?,
                            r.get::<_, Vec<u8>>(7)?,
                        ))
                    },
                )
                .storage()?;
            Ok(Some(AttachmentAcquisition {
                reference: reference.clone(),
                group_id_hex: job.0,
                message_id_hex: job.1,
                attachment_index: job.2,
                source_message_id_hex: job.3,
                source_epoch: job.4,
                slot: serde_json::from_str(&job.5)
                    .map_err(|_| invalid("invalid stored attachment slot"))?,
                attempt: job.6,
                digest: job.7,
            }))
        })
    }

    /// Commit only fully authenticated/decrypted plaintext. Storage additionally
    /// verifies the parser-supplied plaintext hash, but cannot authenticate AEAD.
    /// Quota counts retained plaintext bytes, not SQLite/WAL filesystem overhead;
    /// runtime disk-pressure admission must reserve that overhead separately.
    /// Publication binds the complete plaintext and SQLite may copy it; the
    /// runtime must budget full-object memory, unlike incremental local reads.
    pub fn complete_attachment_acquisition(
        &self,
        job: &AttachmentAcquisition,
        plaintext: &[u8],
        now: u64,
        byte_budget: u64,
    ) -> StorageResult<AttachmentPublishResult> {
        job.verify_plaintext(plaintext)?;
        let now = u64_to_i64(now)?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if !matches_store(&conn, &job.reference)? {
                return Ok(AttachmentPublishResult::Superseded);
            }
            let valid: bool = conn
                .query_row(
                    &format!(
                        "SELECT EXISTS(SELECT 1 FROM attachment_acquisition q
                    WHERE token=?1 AND state=1 AND attempt=?2 AND due>?3
                    AND {SOURCE_MATCH} AND {ACCEPTED}
                    AND (expires_at IS NULL OR expires_at>?3))"
                    ),
                    params![job.reference.token, job.attempt, now],
                    |r| r.get(0),
                )
                .storage()?;
            if !valid {
                return Ok(AttachmentPublishResult::Superseded);
            }
            let used: u64 = conn
                .query_row(
                    "SELECT byte_count FROM attachment_retention_usage WHERE id=1",
                    [],
                    |r| nonnegative(r, 0),
                )
                .storage()?;
            let partial_used: u64 = conn
                .query_row(
                    "SELECT reserved_bytes FROM attachment_partial_usage WHERE id=1",
                    [],
                    |r| nonnegative(r, 0),
                )
                .storage()?;
            let own_partial: u64 = conn
                .query_row(
                    "SELECT coalesce((SELECT total FROM attachment_partial WHERE token=?1),0)",
                    [&job.reference.token],
                    |r| nonnegative(r, 0),
                )
                .storage()?;
            if used
                .saturating_add(partial_used.saturating_sub(own_partial))
                .saturating_add(plaintext.len() as u64)
                > byte_budget
            {
                return Ok(AttachmentPublishResult::CapacityBlocked);
            }
            conn.execute(
                "INSERT INTO retained_attachment_bytes(token,bytes) VALUES(?1,?2)",
                params![job.reference.token, plaintext],
            )
            .storage()?;
            conn.execute(
                "UPDATE attachment_acquisition SET state=3,due=NULL,attempt=NULL WHERE token=?1",
                [&job.reference.token],
            )
            .storage()?;
            Ok(AttachmentPublishResult::Published)
        })
    }

    /// None blocks until an explicit retry; Some schedules a later attempt. Never
    /// persist an error string, URL, secret or decrypted content as job metadata.
    pub fn fail_attachment_acquisition(
        &self,
        job: &AttachmentAcquisition,
        retry_at: Option<u64>,
    ) -> StorageResult<bool> {
        let due = retry_at.map(u64_to_i64).transpose()?;
        let conn = self.lock()?;
        if !matches_store(&conn, &job.reference)? {
            return Ok(false);
        }
        Ok(conn
            .execute(
                "UPDATE attachment_acquisition SET state=?3,due=?4,attempt=NULL
             WHERE token=?1 AND state=1 AND attempt=?2",
                params![
                    job.reference.token,
                    job.attempt,
                    if due.is_some() { 2 } else { 4 },
                    due
                ],
            )
            .storage()?
            == 1)
    }
    /// Explicit retry of an existing failed/parked/delayed job. Ready bytes and active
    /// attempts are not changed; this never clears explicit-removal suppression.
    pub fn retry_attachment_acquisition(
        &self,
        reference: &AttachmentAssetRef,
        now: u64,
    ) -> StorageResult<bool> {
        let conn = self.lock()?;
        if !matches_store(&conn, reference)? {
            return Ok(false);
        }
        Ok(conn
            .execute(
                "UPDATE attachment_acquisition SET state=0,due=?2,attempt=NULL
             WHERE token=?1 AND state IN (2,4,5)",
                params![reference.token, u64_to_i64(now)?],
            )
            .storage()?
            == 1)
    }

    /// Suppress this original message slot durably even when it has no bytes yet.
    /// Raw-source retention/deletion owns tombstone cleanup; timeline rebuild,
    /// revalidation and ordinary demand cannot clear the user's intent.
    pub fn remove_local_attachment(
        &self,
        group: &str,
        message: &str,
        index: u32,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM attachment_history
                 WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=?3)
                 OR EXISTS(SELECT 1 FROM attachment_acquisition
                 WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=?3)
                 OR EXISTS(SELECT 1 FROM attachment_removal_suppression
                 WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=?3)",
                params![group, message, index],
                |r| r.get(0),
            ).storage()?;
            if !exists {
                return Ok(false);
            }
            conn.execute(
                "INSERT INTO attachment_removal_suppression VALUES(?1,?2,?3) ON CONFLICT DO NOTHING",
                params![group, message, index],
            ).storage()?;
            conn.execute(
                "DELETE FROM attachment_acquisition
                 WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=?3",
                params![group, message, index],
            ).storage()?;
            Ok(true)
        })
    }
    /// User-authorized download-again only. Clearing suppression and requesting
    /// the currently authoritative source share one transaction.
    pub fn request_attachment_download_again(
        &self,
        group: &str,
        selected: &crate::AttachmentHistoryEntry,
        digest: [u8; 32],
        now: u64,
    ) -> StorageResult<AttachmentDemand> {
        let index = u32::try_from(selected.attachment_index)
            .map_err(|_| invalid("invalid attachment index"))?;
        self.connection.with_transaction(|| {
            self.lock()?
                .execute(
                    "DELETE FROM attachment_removal_suppression
                 WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=?3",
                    params![group, selected.message_id_hex, index],
                )
                .storage()?;
            self.request_attachment_acquisition(group, selected, digest, now)
        })
    }

    /// Persisted progress metadata only. Visibility/expiry may make ready bytes
    /// unreadable until maintenance updates this state; use the local-read gate.
    pub fn attachment_acquisition_status(
        &self,
        reference: &AttachmentAssetRef,
    ) -> StorageResult<Option<AttachmentAcquisitionStatus>> {
        let conn = self.lock()?;
        if !matches_store(&conn, reference)? {
            return Ok(None);
        }
        let row = conn.query_row(
            "SELECT state,attempts,due,
                COALESCE((SELECT length(bytes) FROM retained_attachment_bytes b WHERE b.token=q.token),0)
             FROM attachment_acquisition q WHERE token=?1",
            [&reference.token],
            |r| Ok((
                r.get::<_, u8>(0)?,
                nonnegative(r, 1)?,
                r.get::<_, Option<i64>>(2)?,
                nonnegative(r, 3)?,
            )),
        ).optional().storage()?;
        row.map(|(state, attempts, due, byte_count)| {
            Ok(AttachmentAcquisitionStatus {
                state: match state {
                    0 => AttachmentAcquisitionState::Queued,
                    1 => AttachmentAcquisitionState::Fetching,
                    2 => AttachmentAcquisitionState::RetryScheduled,
                    3 => AttachmentAcquisitionState::Ready,
                    4 => AttachmentAcquisitionState::Blocked,
                    5 => AttachmentAcquisitionState::Parked,
                    _ => return Err(invalid("invalid attachment state")),
                },
                attempts,
                due: due
                    .map(|value| {
                        u64::try_from(value).map_err(|_| invalid("invalid attachment due time"))
                    })
                    .transpose()?,
                byte_count,
            })
        })
        .transpose()
    }
    /// Bounded local read after source visibility/expiry checks. No download is
    /// started; None means unavailable or obsolete. Returned plaintext is wiped
    /// on drop. Hosts must not interpret a handle as a permanent authorization.
    pub fn read_retained_attachment(
        &self,
        reference: &AttachmentAssetRef,
        now: u64,
        offset: u64,
        limit: usize,
    ) -> StorageResult<Option<Zeroizing<Vec<u8>>>> {
        if limit == 0 || limit > MAX_ATTACHMENT_LOCAL_READ_BYTES {
            return Err(invalid("invalid attachment local read limit"));
        }
        let offset = usize::try_from(u64_to_i64(offset)?)
            .map_err(|_| invalid("invalid attachment offset"))?;
        let now = u64_to_i64(now)?;
        self.connection.with_deferred_read(|conn| {
            if !matches_store(conn, reference)? {
                return Ok(None);
            }
            // Select only the row identity. SQL substr(bytes, ...) materializes
            // the whole value inside SQLite before slicing it.
            let row_id: Option<i64> = conn
                .query_row(
                    &format!(
                        "SELECT b.rowid FROM attachment_acquisition q
                    JOIN retained_attachment_bytes b USING(token)
                    WHERE token=?1 AND state=3 AND {SOURCE_MATCH}
                    AND (expires_at IS NULL OR expires_at>?2)"
                    ),
                    params![reference.token, now],
                    |r| r.get(0),
                )
                .optional()
                .storage()?;
            let Some(row_id) = row_id else {
                return Ok(None);
            };
            let blob = conn
                .blob_open("main", "retained_attachment_bytes", "bytes", row_id, true)
                .storage()?;
            let count = blob.len().saturating_sub(offset).min(limit);
            let mut bytes = Zeroizing::new(vec![0; count]);
            if count != 0 {
                blob.read_at_exact(&mut bytes, offset).storage()?;
            }
            blob.close().storage()?;
            Ok(Some(bytes))
        })
    }
    /// One bounded maintenance pass. Source pruning separately cascades deletion;
    /// this releases bytes at the deadline even before the normal source sweep.
    pub fn prune_expired_attachment_acquisitions(
        &self,
        now: u64,
        limit: usize,
    ) -> StorageResult<usize> {
        if limit == 0 || limit > ATTACHMENT_ACQUISITION_BATCH_LIMIT {
            return Err(invalid("invalid attachment cleanup limit"));
        }
        self.lock()?
            .execute(
                "DELETE FROM attachment_acquisition WHERE token IN (
                SELECT token FROM attachment_acquisition WHERE expires_at<=?1
                ORDER BY expires_at,token LIMIT ?2)",
                params![u64_to_i64(now)?, limit as i64],
            )
            .storage()
    }
    pub fn retained_attachment_byte_count(&self) -> StorageResult<u64> {
        self.lock()?
            .query_row(
                "SELECT byte_count FROM attachment_retention_usage WHERE id=1",
                [],
                |r| nonnegative(r, 0),
            )
            .storage()
    }
}
#[cfg(test)]
mod tests;

mod partial;
pub use partial::{ATTACHMENT_CHECKPOINT_BYTES, AttachmentPartial, AttachmentPartialIdentity};

mod access;
pub use access::RetainedAttachmentAsset;
