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
    PreviouslyAcquiredUnavailable,
    CompletedUnretained,
    RetryExhausted,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentTransferStatus {
    pub reference: Option<AttachmentAssetRef>,
    /// Source MIME for automatic policy evaluation; None for explicit requests.
    pub automatic_media_type: Option<String>,
    pub state: AttachmentTransferState,
    /// Changes on claim and later HTTP-body restarts (including locator fallback).
    pub attempt: u64,
    pub received: u64,
    pub total: Option<u64>,
    pub retry_at: Option<u64>,
}

/// One consistent metadata frame plus the next local visibility deadline.
#[derive(Clone, Debug)]
pub struct AttachmentTransferFrame {
    pub store_epoch: Vec<u8>,
    pub rows: Vec<Option<AttachmentTransferStatus>>,
    pub next_expiry: Option<u64>,
}

impl SqliteAccountStorage {
    /// Pause automatic network work without invalidating verified publication.
    /// Interrupted claims are refunded once; actual HTTP attempts remain charged.
    pub fn pause_automatic_attachments(&self, now: u64) -> StorageResult<()> {
        self.lock()?.execute("UPDATE attachment_acquisition SET
            acquisition_attempts=max(0,acquisition_attempts-CASE WHEN state=1 THEN 1 ELSE 0 END),
            retry_not_before=CASE WHEN state=1 THEN ?1+15 ELSE COALESCE(due,retry_not_before) END,
            due=CASE WHEN state=1 THEN due ELSE NULL END,
            state=CASE WHEN state=1 THEN 1 ELSE 5 END,permission_paused=1
            WHERE state IN (0,1,2) AND explicit_request=0 AND permission_paused=0 AND body_completed=0", [u64_to_i64(now)?]).storage()?;
        Ok(())
    }

    /// Park an unclaimed candidate without a timer or consuming a retry. A later
    /// permission update readmits it while preserving its existing backoff.
    pub fn park_attachment_permission(&self, reference: &AttachmentAssetRef) -> StorageResult<()> {
        let conn = self.lock()?;
        if !matches_store(&conn, reference)? {
            return Ok(());
        }
        conn.execute(
            "UPDATE attachment_acquisition SET permission_paused=1,
            retry_not_before=COALESCE(due,retry_not_before),state=5,due=NULL
            WHERE token=?1 AND state IN (0,2) AND explicit_request=0",
            [&reference.token],
        )
        .storage()?;
        Ok(())
    }

    /// Readmit at most one bounded page of permission-paused jobs. This does not
    /// reset budgets or deadlines and does not create demand for unseen sources.
    pub fn resume_permitted_attachments(
        &self,
        now: u64,
        allowed_categories: [bool; 4],
    ) -> StorageResult<usize> {
        if !allowed_categories.into_iter().any(|allowed| allowed) {
            return Ok(0);
        }
        // The common worker tick stays read-only. A concurrent pause after this
        // check is picked up by the next tick; the transaction reselects rows.
        let paused: bool = self.lock()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM attachment_acquisition WHERE permission_paused=1 AND state=5)",
            [], |row| row.get(0),
        ).storage()?;
        if !paused {
            return Ok(0);
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let mut tokens = Vec::new();
            for (category, allowed) in allowed_categories.into_iter().enumerate() {
                if !allowed { continue; }
                let mut stmt = conn.prepare("SELECT token FROM attachment_acquisition
                    WHERE permission_paused=1 AND state=5 AND permission_category=?1 ORDER BY token LIMIT ?2").storage()?;
                let selected = stmt.query_map(params![category as i64,(ATTACHMENT_ACQUISITION_BATCH_LIMIT-tokens.len()) as i64], |r| r.get::<_,Vec<u8>>(0)).storage()?;
                tokens.extend(selected.collect::<Result<Vec<_>,_>>().storage()?);
            }
            for token in &tokens {
                conn.execute("UPDATE attachment_acquisition SET state=0,due=max(?2,retry_not_before),permission_paused=0
                    WHERE token=?1", params![token,u64_to_i64(now)?]).storage()?;
            }
            Ok(tokens.len())
        })
    }
    /// Opaque store incarnation for runtime-only permission scoping. Never log it.
    pub fn attachment_store_identity(&self) -> StorageResult<Vec<u8>> {
        let conn = self.lock()?;
        epoch(&conn)
    }

    /// Opt a restored job into host-managed history without resetting its state.
    /// Native workers never call this; adopting hosts do so before claiming work.
    pub fn enable_attachment_automatic_history(
        &self,
        reference: &AttachmentAssetRef,
    ) -> StorageResult<()> {
        let conn = self.lock()?;
        if matches_store(&conn, reference)? {
            conn.execute("UPDATE attachment_acquisition SET automatic_history=1 WHERE token=?1 AND automatic_history=0", [&reference.token]).storage()?;
        }
        Ok(())
    }

    /// Charge every outbound HTTP attempt, including range restarts and locator
    /// fallback. This counter never resets on checkpoints or worker recovery.
    pub fn begin_attachment_network_attempt(
        &self,
        job: &AttachmentAcquisition,
        now: u64,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if !partial::valid_attempt(&conn, job, now)? { return Ok(false); }
            Ok(conn.execute("UPDATE attachment_acquisition SET network_attempts=min(network_attempts+automatic_history,2147483647)
                WHERE token=?1 AND (automatic_history=0 OR body_completed=0) AND cancelled=0
                AND (automatic_history=0 OR network_attempts<64) AND permission_paused=0 AND (explicit_request=1 OR COALESCE((SELECT automatic FROM attachment_download_policy WHERE id=1),1)=1)",
                [&job.reference.token]).storage()? == 1)
        })
    }

    /// Record a verified body receipt before publication. A crash or retention
    /// failure after this point cannot turn an opted-in completed body into demand.
    pub fn mark_attachment_body_completed(
        &self,
        job: &AttachmentAcquisition,
        now: u64,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            if !partial::valid_publication_attempt(&conn, job, now)? {
                return Ok(false);
            }
            Ok(conn
                .execute(
                    "UPDATE attachment_acquisition SET body_completed=1 WHERE token=?1",
                    [&job.reference.token],
                )
                .storage()?
                == 1)
        })
    }

    /// Policy, source validation, idempotent demand and returned status share a
    /// transaction. The caller holds its runtime permission fence for this call.
    pub fn request_automatic_attachment(
        &self,
        group: &str,
        selected: &crate::AttachmentHistoryEntry,
        digest: [u8; 32],
        now: u64,
        policy: (&AttachmentDownloadPolicy, bool),
    ) -> StorageResult<(Option<AttachmentTransferStatus>, bool)> {
        let index = u32::try_from(selected.attachment_index)
            .map_err(|_| invalid("invalid attachment index"))?;
        self.connection.with_transaction(|| {
            let current = self.attachment_control_entry(
                group,
                &selected.message_id_hex,
                &selected.source_message_id_hex,
                index,
                now,
            )?;
            if !current.is_some_and(|entry| {
                entry.slot == selected.slot && entry.source_epoch == selected.source_epoch
            }) {
                return Ok((None, false));
            }
            self.lock()?.execute("UPDATE attachment_acquisition SET automatic_history=1
                WHERE group_id_hex=?1 AND message_id_hex=?2 AND source_message_id_hex=?3 AND attachment_index=?4 AND automatic_history=0",
                params![group,selected.message_id_hex,selected.source_message_id_hex,index]).storage()?;
            let automatic = policy.1 && self.attachment_download_policy(policy.0)?.automatic;
            let status = self.attachment_transfer_status(
                group,
                &selected.message_id_hex,
                &selected.source_message_id_hex,
                index,
                now,
                automatic,
            )?;
            // Existing state (including cancellation, loss of bytes and retry
            // deadlines) wins over demand and is never reset by a screen render.
            if status.as_ref().is_none_or(|s| {
                !matches!(
                    s.state,
                    AttachmentTransferState::NotRequested | AttachmentTransferState::Paused
                )
            }) {
                return Ok((status, false));
            }
            if let Some(reference) = status.as_ref().and_then(|s| s.reference.as_ref()) {
                let paused: bool = self.lock()?.query_row("SELECT permission_paused FROM attachment_acquisition WHERE token=?1", [&reference.token], |r| r.get(0)).storage()?;
                if paused { return Ok((status, false)); }
            }
            if !automatic {
                return Ok((
                    status.map(|mut s| {
                        if s.state == AttachmentTransferState::NotRequested {
                            s.state = AttachmentTransferState::PolicyBlocked;
                        }
                        s
                    }),
                    false,
                ));
            }
            match self.request_attachment_acquisition(group, selected, digest, now)? {
                AttachmentDemand::Requested(reference) => {
                    self.lock()?.execute("UPDATE attachment_acquisition SET automatic_history=1 WHERE token=?1", [&reference.token]).storage()?;
                    Ok((
                    self.attachment_transfer_status(
                        group,
                        &selected.message_id_hex,
                        &selected.source_message_id_hex,
                        index,
                        now,
                        automatic,
                    )?,
                    true,
                ))
                },
                AttachmentDemand::Suppressed | AttachmentDemand::Unavailable => Ok((None, false)),
            }
        })
    }

    /// Capture store identity and all bounded source slots under one read transaction.
    pub fn attachment_transfer_snapshot(
        &self,
        group: &str,
        targets: &[(&str, &str, u32)],
        now: u64,
        automatic: bool,
    ) -> StorageResult<AttachmentTransferFrame> {
        if targets.len() > 64 {
            return Err(invalid("too many attachment targets"));
        }
        self.connection.with_deferred_read(|conn| {
            let identity = epoch(conn)?;
            let mut next_expiry = None;
            let rows = targets
                .iter()
                .map(|target| {
                    transfer_status(
                        conn,
                        &identity,
                        group,
                        *target,
                        now,
                        automatic,
                        &mut next_expiry,
                    )
                })
                .collect::<StorageResult<Vec<_>>>()?;
            Ok(AttachmentTransferFrame {
                store_epoch: identity,
                rows,
                next_expiry,
            })
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
    /// requests and ready assets are unaffected. Verified bodies may still publish.
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
            drop(conn);
            self.pause_automatic_attachments(now)?;
            let conn = self.lock()?;
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
            Ok(conn.execute(&format!("UPDATE attachment_acquisition AS q SET cancelled=0,state=CASE WHEN state=1 THEN 1 ELSE 0 END,due=CASE WHEN state=1 THEN due ELSE ?2 END,attempt=CASE WHEN state=1 THEN attempt ELSE NULL END,explicit_request=1,size_blocked_max=NULL,permission_paused=0,retry_not_before=0,acquisition_attempts=CASE WHEN state=1 THEN acquisition_attempts ELSE 0 END,network_attempts=CASE WHEN state=1 THEN network_attempts ELSE 0 END,body_completed=CASE WHEN state=1 THEN body_completed ELSE 0 END
                WHERE token=?1 AND (state IN(0,1,2,4,5) OR (state=3 AND NOT EXISTS(SELECT 1 FROM retained_attachment_bytes b WHERE b.token=q.token))) AND {SOURCE_MATCH} AND {ACCEPTED} AND (expires_at IS NULL OR expires_at>?2)"),
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
        // Seek only due work before ordering eligible candidates by priority. The
        // explicit-only index also skips paused automatic work. Future backoff
        // and live leases must not be visited on every worker wakeup.
        let (index, explicit_filter) = if automatic {
            ("attachment_acquisition_due", "")
        } else {
            ("attachment_acquisition_priority", " AND explicit_request=1")
        };
        let sql = format!(
            "SELECT token FROM attachment_acquisition INDEXED BY {index}
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
            state=CASE WHEN explicit_request=1 AND ?3<?5 THEN 0 ELSE 4 END,
            due=CASE WHEN explicit_request=1 AND ?3<?5 THEN ?4 ELSE NULL END,
            attempt=NULL,size_blocked_max=CASE WHEN explicit_request=1 AND ?3<?5 THEN NULL ELSE ?3 END
            WHERE token=?1 AND state=1 AND attempt=?2",
            params![job.reference.token, job.attempt, u64_to_i64(max)?,u64_to_i64(now)?, MAX_RETAINED_ATTACHMENT_BYTES as i64],
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
        self.connection.with_deferred_read(|conn| {
            transfer_status(
                conn,
                &epoch(conn)?,
                group,
                (message, source, index),
                now,
                automatic,
                &mut None,
            )
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

fn transfer_status(
    conn: &rusqlite::Connection,
    identity: &[u8],
    group: &str,
    target: (&str, &str, u32),
    now: u64,
    automatic: bool,
    next_expiry: &mut Option<u64>,
) -> StorageResult<Option<AttachmentTransferStatus>> {
    let (message, source, index) = target;
    let source_row: Option<(Option<i64>,String)> = conn.query_row("SELECT a.retention_expires_at,CASE WHEN length(CAST(h.slot_json AS BLOB))<=16384 THEN h.slot_json ELSE '[]' END
        FROM attachment_history h JOIN app_events a USING(group_id_hex,message_id_hex)
        WHERE h.group_id_hex=?1 AND h.message_id_hex=?2 AND h.source_message_id_hex=?3 AND h.attachment_index=?4 AND h.visible=1
        AND (a.retention_expires_at IS NULL OR a.retention_expires_at>?5)",params![group,message,source,index,u64_to_i64(now)?],|r|Ok((r.get(0)?,r.get(1)?))).optional().storage()?;
    let Some((expiry, slot)) = source_row else {
        return Ok(None);
    };
    if let Some(expiry) = expiry {
        let expiry = expiry as u64;
        *next_expiry = Some(next_expiry.map_or(expiry, |old| old.min(expiry)));
    }

    let removed:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM attachment_removal_suppression WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=?3)",params![group,message,index],|r|r.get(0)).storage()?;
    let status=conn.query_row(&format!("SELECT token,state,cancelled,explicit_request,size_blocked_max,progress_epoch,progress_received,progress_total,progress_phase,due,body_completed,network_attempts,EXISTS(SELECT 1 FROM retained_attachment_bytes b WHERE b.token=q.token),acquisition_attempts,automatic_history,permission_paused
                FROM attachment_acquisition q WHERE group_id_hex=?1 AND message_id_hex=?2 AND source_message_id_hex=?3 AND attachment_index=?4 AND {SOURCE_MATCH}"),params![group,message,source,index],|r| {
                let stored_state = r.get::<_,u8>(1)?;
                let cancelled = r.get::<_,bool>(2)?;
                let explicit = r.get::<_,bool>(3)?;
                let size_blocked = r.get::<_,Option<i64>>(4)?.is_some();
                let phase = r.get::<_,u8>(8)?;
                let state = match stored_state {
                    3 if !r.get::<_,bool>(12)? => AttachmentTransferState::PreviouslyAcquiredUnavailable,
                    3 => AttachmentTransferState::Ready,
                    _ if cancelled => AttachmentTransferState::Cancelled,
                    _ if r.get::<_,bool>(14)? && r.get::<_,bool>(10)? && stored_state!=1 => AttachmentTransferState::CompletedUnretained,
                    _ if size_blocked => AttachmentTransferState::PolicyBlocked,
                    _ if r.get::<_,bool>(14)? && (nonnegative(r,11)? >= 64 || nonnegative(r,13)? >= 4) && stored_state!=1 => AttachmentTransferState::RetryExhausted,
                    _ if r.get::<_,bool>(15)? && !r.get::<_,bool>(10)? => AttachmentTransferState::Paused,
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
                    r.get::<_,Option<i64>>(9)?.map(|v|v as u64),explicit,
                ))
            }).optional().storage()?;
    Ok(Some(match status {
        Some((token, state, attempt, received, total, retry_at, explicit)) => {
            AttachmentTransferStatus {
                reference: Some(AttachmentAssetRef {
                    store_epoch: identity.to_vec(),
                    token,
                }),
                automatic_media_type: (!explicit).then(|| slot_media_type(&slot)),
                state,
                attempt,
                received,
                total,
                retry_at: if state == AttachmentTransferState::RetryScheduled {
                    retry_at
                } else {
                    None
                },
            }
        }
        None => AttachmentTransferStatus {
            reference: None,
            automatic_media_type: Some(slot_media_type(&slot)),
            state: if removed {
                AttachmentTransferState::Removed
            } else {
                AttachmentTransferState::NotRequested
            },
            attempt: 0,
            received: 0,
            total: None,
            retry_at: None,
        },
    }))
}

/// Read only the MIME field needed for policy; the acquisition parser remains
/// authoritative for source validity and cryptographic descriptors.
pub(super) fn slot_media_type(slot: &str) -> String {
    serde_json::from_str::<Vec<String>>(slot)
        .ok()
        .and_then(|fields| {
            fields
                .into_iter()
                .find_map(|field| field.strip_prefix("m ").map(str::to_owned))
        })
        .unwrap_or_default()
}
