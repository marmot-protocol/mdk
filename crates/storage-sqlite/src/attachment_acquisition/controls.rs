//! Durable user intent and coalesced transfer metadata, in the existing job store.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentDownloadPolicy {
    pub automatic: bool,
    pub retained_bytes: u64,
    pub disk_reserve: u64,
    pub transfer_limit: u64,
}
impl AttachmentDownloadPolicy {
    pub fn validate(&self) -> StorageResult<()> {
        if self.retained_bytes < self.transfer_limit
            || self.retained_bytes > i64::MAX as u64
            || self.disk_reserve
                > (i64::MAX as u64).saturating_sub(4 * MAX_RETAINED_ATTACHMENT_BYTES as u64)
            || self.transfer_limit == 0
            || self.transfer_limit > MAX_RETAINED_ATTACHMENT_BYTES as u64
        {
            return Err(invalid("invalid attachment download policy"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachmentTransferState {
    NotRequested,
    Queued,
    Downloading,
    VerifyingCiphertext,
    Decrypting,
    VerifyingPlaintext,
    Ready,
    RetryScheduled,
    Failed,
    Cancelled,
    Paused,
    Removed,
    PolicyBlocked,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentTransferStatus {
    pub reference: Option<AttachmentAssetRef>,
    pub state: AttachmentTransferState,
    /// Changes on claim and later HTTP-body restarts (including locator fallback).
    pub attempt: u64,
    pub received: u64,
    pub total: Option<u64>,
    pub retry_at: Option<u64>,
}

impl SqliteAccountStorage {
    /// Capture store identity and all bounded source slots under one read transaction.
    pub fn attachment_transfer_snapshot(
        &self,
        group: &str,
        targets: &[(&str, &str, u32)],
        now: u64,
        automatic: bool,
    ) -> StorageResult<(Vec<u8>, Vec<Option<AttachmentTransferStatus>>)> {
        if targets.len() > 64 {
            return Err(invalid("too many attachment targets"));
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let identity = epoch(&conn)?;
            drop(conn); // The outer transaction remains owned by this thread.
            let rows = targets
                .iter()
                .map(|(message, source, index)| {
                    self.attachment_transfer_status(group, message, source, *index, now, automatic)
                })
                .collect::<StorageResult<Vec<_>>>()?;
            Ok((identity, rows))
        })
    }
    pub fn attachment_download_policy(
        &self,
        fallback: &AttachmentDownloadPolicy,
    ) -> StorageResult<AttachmentDownloadPolicy> {
        fallback.validate()?;
        self.lock()?.query_row("SELECT automatic,retained_bytes,disk_reserve,transfer_limit FROM attachment_download_policy WHERE id=1",[],|r| Ok(AttachmentDownloadPolicy {
            automatic:r.get(0)?,retained_bytes:nonnegative(r,1)?,disk_reserve:nonnegative(r,2)?,transfer_limit:nonnegative(r,3)?,
        })).optional().storage().map(|p| p.unwrap_or_else(||fallback.clone()))
    }

    /// Persist policy and invalidate active automatic leases atomically. Explicit
    /// requests and ready assets are unaffected. A late completion cannot publish.
    pub fn set_attachment_download_policy(
        &self,
        policy: &AttachmentDownloadPolicy,
        now: u64,
    ) -> StorageResult<()> {
        policy.validate()?;
        self.connection.with_transaction(|| {
            let conn=self.lock()?;
            let unchanged:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM attachment_download_policy WHERE id=1 AND automatic=?1 AND retained_bytes=?2 AND disk_reserve=?3 AND transfer_limit=?4)",params![policy.automatic,u64_to_i64(policy.retained_bytes)?,u64_to_i64(policy.disk_reserve)?,u64_to_i64(policy.transfer_limit)?],|r|r.get(0)).storage()?;
            if unchanged {return Ok(());}
            conn.execute("INSERT INTO attachment_download_policy VALUES(1,?1,?2,?3,?4)
                ON CONFLICT(id) DO UPDATE SET automatic=excluded.automatic,retained_bytes=excluded.retained_bytes,
                disk_reserve=excluded.disk_reserve,transfer_limit=excluded.transfer_limit",
                params![policy.automatic,u64_to_i64(policy.retained_bytes)?,u64_to_i64(policy.disk_reserve)?,u64_to_i64(policy.transfer_limit)?]).storage()?;
            // All active automatic work re-enters admission when a policy changes.
            conn.execute("UPDATE attachment_acquisition SET state=0,due=?1,attempt=NULL WHERE state=1 AND explicit_request=0",[u64_to_i64(now)?]).storage()?;
            conn.execute("UPDATE attachment_acquisition SET state=0,due=?1,size_blocked_max=NULL
                WHERE cancelled=0 AND state=4 AND size_blocked_max IS NOT NULL AND size_blocked_max<?2",
                params![u64_to_i64(now)?,u64_to_i64(policy.transfer_limit)?]).storage()?;
            Ok(())
        })
    }

    pub fn cancel_attachment_acquisition(
        &self,
        reference: &AttachmentAssetRef,
    ) -> StorageResult<bool> {
        let conn = self.lock()?;
        if !matches_store(&conn, reference)? {
            return Ok(false);
        }
        Ok(conn.execute("UPDATE attachment_acquisition SET cancelled=1,state=4,due=NULL,attempt=NULL,explicit_request=0
            WHERE token=?1 AND state<>3",[&reference.token]).storage()?==1)
    }

    /// Explicit retry also admits a queued automatic job while automatic work is disabled.
    pub fn explicitly_retry_attachment(
        &self,
        reference: &AttachmentAssetRef,
        now: u64,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn=self.lock()?;
            if !matches_store(&conn,reference)? {return Ok(false);}
            Ok(conn.execute(&format!("UPDATE attachment_acquisition AS q SET cancelled=0,state=CASE WHEN state=1 THEN 1 ELSE 0 END,due=CASE WHEN state=1 THEN due ELSE ?2 END,attempt=CASE WHEN state=1 THEN attempt ELSE NULL END,explicit_request=1,size_blocked_max=NULL
                WHERE token=?1 AND state IN(0,1,2,4,5) AND {SOURCE_MATCH} AND {ACCEPTED} AND (expires_at IS NULL OR expires_at>?2)"),
                params![reference.token,u64_to_i64(now)?]).storage()?==1)
        })
    }

    pub fn remove_attachment_reference(
        &self,
        reference: &AttachmentAssetRef,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn=self.lock()?;
            if !matches_store(&conn,reference)? {return Ok(false);}
            let source=conn.query_row("SELECT group_id_hex,message_id_hex,attachment_index FROM attachment_acquisition WHERE token=?1",[&reference.token],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,u32>(2)?))).optional().storage()?;
            drop(conn); // Nested storage calls must acquire their own connection guard.
            match source { Some((g,m,i))=>self.remove_local_attachment(&g,&m,i),None=>Ok(false) }
        })
    }

    /// No network permission is conveyed by a due candidate. Claim checks again.
    pub fn attachment_transfer_candidates(
        &self,
        now: u64,
        limit: usize,
        automatic: bool,
    ) -> StorageResult<Vec<AttachmentAssetRef>> {
        if limit == 0 || limit > ATTACHMENT_ACQUISITION_BATCH_LIMIT {
            return Err(invalid("invalid attachment candidate limit"));
        }
        let conn = self.lock()?;
        let epoch = epoch(&conn)?;
        // A concrete predicate lets SQLite seek directly into explicit work when
        // automatic acquisition is disabled, without scanning the paused backlog.
        let explicit_filter = if automatic {
            ""
        } else {
            " AND explicit_request=1"
        };
        let sql = format!(
            "SELECT token FROM attachment_acquisition INDEXED BY attachment_acquisition_priority
            WHERE due IS NOT NULL AND due<=?1 AND cancelled=0{explicit_filter}
            ORDER BY explicit_request DESC,priority_at DESC,due,token LIMIT ?2"
        );
        let mut stmt = conn.prepare(&sql).storage()?;
        stmt.query_map(params![u64_to_i64(now)?, limit as i64], |r| {
            Ok(AttachmentAssetRef {
                store_epoch: epoch.clone(),
                token: r.get(0)?,
            })
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()
    }

    pub fn attachment_request_is_explicit(
        &self,
        reference: &AttachmentAssetRef,
    ) -> StorageResult<bool> {
        let conn = self.lock()?;
        if !matches_store(&conn, reference)? {
            return Ok(false);
        }
        conn.query_row("SELECT COALESCE((SELECT explicit_request FROM attachment_acquisition WHERE token=?1),0)",[&reference.token],|r|r.get(0)).storage()
    }

    pub fn attachment_transfer_is_active(
        &self,
        job: &AttachmentAcquisition,
        now: u64,
    ) -> StorageResult<bool> {
        let conn = self.lock()?;
        partial::valid_attempt(&conn, job, now)
    }

    pub fn block_attachment_size_policy(
        &self,
        job: &AttachmentAcquisition,
        max: u64,
        now: u64,
    ) -> StorageResult<()> {
        let conn = self.lock()?;
        if !matches_store(&conn, &job.reference)? {
            return Ok(());
        }
        conn.execute(
            "UPDATE attachment_acquisition SET
            state=CASE WHEN explicit_request=1 AND ?3<536870912 THEN 0 ELSE 4 END,
            due=CASE WHEN explicit_request=1 AND ?3<536870912 THEN ?4 ELSE NULL END,
            attempt=NULL,size_blocked_max=CASE WHEN explicit_request=1 AND ?3<536870912 THEN NULL ELSE ?3 END
            WHERE token=?1 AND state=1 AND attempt=?2",
            params![job.reference.token, job.attempt, u64_to_i64(max)?,u64_to_i64(now)?],
        )
        .storage()?;
        Ok(())
    }

    /// Called at most four times/second for bytes; phase changes bypass coalescing.
    /// Restart explicitly advances the generation so hosts never merge old counters.
    pub fn update_attachment_progress(
        &self,
        job: &AttachmentAcquisition,
        now: u64,
        phase: u8,
        received: u64,
        total: Option<u64>,
        restart: bool,
    ) -> StorageResult<bool> {
        if phase > 4
            || received > MAX_RETAINED_ATTACHMENT_BYTES as u64
            || total.is_some_and(|t| t < received || t > MAX_RETAINED_ATTACHMENT_BYTES as u64)
        {
            return Err(invalid("invalid attachment progress"));
        }
        self.connection.with_transaction(|| {
            let conn=self.lock()?;
            if !partial::valid_attempt(&conn,job,now)? {return Ok(false);}
            Ok(conn.execute("UPDATE attachment_acquisition SET progress_epoch=progress_epoch+CASE WHEN ?2 AND progress_phase<>0 THEN 1 ELSE 0 END,progress_received=?3,progress_total=?4,progress_phase=?5
                WHERE token=?1 AND (?2 OR progress_received<=?3)",params![job.reference.token,restart,u64_to_i64(received)?,total.map(u64_to_i64).transpose()?,phase]).storage()?==1)
        })
    }

    /// Source-bound metadata; missing/hidden/expired sources return None. A batch
    /// consumer must still revalidate each local-byte read.
    pub fn attachment_transfer_status(
        &self,
        group: &str,
        message: &str,
        source: &str,
        index: u32,
        now: u64,
        automatic: bool,
    ) -> StorageResult<Option<AttachmentTransferStatus>> {
        self.connection.with_transaction(|| {
            let conn=self.lock()?;
            let visible:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM attachment_history h JOIN app_events a USING(group_id_hex,message_id_hex)
                WHERE h.group_id_hex=?1 AND h.message_id_hex=?2 AND h.source_message_id_hex=?3 AND h.attachment_index=?4 AND h.visible=1
                AND (a.retention_expires_at IS NULL OR a.retention_expires_at>?5))",params![group,message,source,index,u64_to_i64(now)?],|r|r.get(0)).storage()?;
            if !visible {return Ok(None);}
            let removed:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM attachment_removal_suppression WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=?3)",params![group,message,index],|r|r.get(0)).storage()?;
            let status=conn.query_row(&format!("SELECT token,state,cancelled,explicit_request,size_blocked_max,progress_epoch,progress_received,progress_total,progress_phase,due
                FROM attachment_acquisition q WHERE group_id_hex=?1 AND message_id_hex=?2 AND source_message_id_hex=?3 AND attachment_index=?4 AND {SOURCE_MATCH}"),params![group,message,source,index],|r| {
                let stored_state = r.get::<_,u8>(1)?;
                let cancelled = r.get::<_,bool>(2)?;
                let explicit = r.get::<_,bool>(3)?;
                let size_blocked = r.get::<_,Option<i64>>(4)?.is_some();
                let phase = r.get::<_,u8>(8)?;
                let state = match stored_state {
                    3 => AttachmentTransferState::Ready,
                    _ if cancelled => AttachmentTransferState::Cancelled,
                    _ if size_blocked => AttachmentTransferState::PolicyBlocked,
                    4 => AttachmentTransferState::Failed,
                    _ if !automatic && !explicit => AttachmentTransferState::Paused,
                    0 => AttachmentTransferState::Queued,
                    1 => match phase {
                        2 => AttachmentTransferState::VerifyingCiphertext,
                        3 => AttachmentTransferState::Decrypting,
                        4 => AttachmentTransferState::VerifyingPlaintext,
                        _ => AttachmentTransferState::Downloading,
                    },
                    2 => AttachmentTransferState::RetryScheduled,
                    5 => AttachmentTransferState::Paused,
                    _ => AttachmentTransferState::Failed,
                };
                Ok((
                    r.get::<_,Vec<u8>>(0)?, state, nonnegative(r,5)?, nonnegative(r,6)?,
                    r.get::<_,Option<i64>>(7)?.map(|v|v as u64),
                    r.get::<_,Option<i64>>(9)?.map(|v|v as u64),
                ))
            }).optional().storage()?;
            Ok(Some(match status {
                Some((token,state,attempt,received,total,retry_at))=>AttachmentTransferStatus {reference:Some(AttachmentAssetRef{store_epoch:epoch(&conn)?,token}),state,attempt,received,total,retry_at:if state==AttachmentTransferState::RetryScheduled {retry_at}else{None}},
                None=>AttachmentTransferStatus {reference:None,state:if removed {AttachmentTransferState::Removed}else{AttachmentTransferState::NotRequested},attempt:0,received:0,total:None,retry_at:None}
            }))
        })
    }
}

impl SqliteAccountStorage {
    pub fn attachment_control_entry(
        &self,
        group: &str,
        message: &str,
        source: &str,
        index: u32,
        now: u64,
    ) -> StorageResult<Option<crate::AttachmentHistoryEntry>> {
        self.lock()?.query_row("SELECT h.source_epoch,h.sender,h.timeline_at,h.received_at,h.slot_json FROM attachment_history h
            JOIN app_events a USING(group_id_hex,message_id_hex) JOIN account_groups g USING(group_id_hex)
            WHERE h.group_id_hex=?1 AND h.message_id_hex=?2 AND h.source_message_id_hex=?3 AND h.attachment_index=?4
            AND h.visible=1 AND g.pending_confirmation=0 AND length(CAST(h.slot_json AS BLOB))<=16384
            AND (a.retention_expires_at IS NULL OR a.retention_expires_at>?5)",params![group,message,source,index,u64_to_i64(now)?],|r| {
                let slot:String=r.get(4)?;
                Ok(crate::AttachmentHistoryEntry {message_id_hex:message.into(),source_message_id_hex:source.into(),attachment_index:index as usize,
                    source_epoch:r.get::<_,Option<i64>>(0)?.map(|v|v as u64),sender:r.get(1)?,timeline_at:nonnegative(r,2)?,received_at:nonnegative(r,3)?,
                    slot:serde_json::from_str(&slot).unwrap_or(serde_json::Value::Null)})
            }).optional().storage()
    }

    pub fn update_attachment_phase(
        &self,
        job: &AttachmentAcquisition,
        now: u64,
        phase: u8,
    ) -> StorageResult<bool> {
        if !(2..=4).contains(&phase) {
            return Err(invalid("invalid attachment phase"));
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if !partial::valid_attempt(&conn, job, now)? {
                return Ok(false);
            }
            conn.execute(
                "UPDATE attachment_acquisition SET progress_phase=?2 WHERE token=?1",
                params![job.reference.token, phase],
            )
            .storage()?;
            Ok(true)
        })
    }
}
