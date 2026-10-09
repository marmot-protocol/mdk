//! Optional outgoing retention after upload; publication and acquisition remain independent.
use super::*;

/// Valid staged bytes always win over HTTP; deliberate Retry may reacquire a quarantined body.
pub(super) const STAGED_UPLOAD_MATCH: &str = "NOT EXISTS(SELECT 1 FROM outgoing_attachment_uploads u JOIN attachment_history h ON h.group_id_hex=u.group_id_hex AND h.source_epoch=u.source_epoch AND h.slot_json=u.slot_json JOIN app_events a ON a.group_id_hex=h.group_id_hex AND a.message_id_hex=h.message_id_hex WHERE h.group_id_hex=q.group_id_hex AND h.message_id_hex=q.message_id_hex AND h.attachment_index=q.attachment_index AND a.direction='sent' AND (u.quarantined=0 OR q.explicit_request=0))";

const UPLOAD_TTL_SECONDS: u64 = 7 * 24 * 3600;
const MAX_STAGED_UPLOADS: i64 = 256;
/// Every file-backed staging/promotion copy moves at most this many bytes per step.
pub const ATTACHMENT_STAGING_CHUNK_BYTES: usize = 64 * 1024;
const BODY_TABLE: &str = "outgoing_attachment_upload_bodies";

/// One caller-owned private plaintext snapshot for bounded staging. Storage
/// reads exactly `len` bytes, requires end-of-file afterwards and verifies the
/// digest before commit; the reader is never retained.
pub struct AttachmentUploadSource<'a> {
    pub reader: &'a mut dyn std::io::Read,
    pub len: u64,
    pub digest: [u8; 32],
}

impl std::fmt::Debug for AttachmentUploadSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentUploadSource")
            .finish_non_exhaustive()
    }
}

impl SqliteAccountStorage {
    /// Reserve the complete outgoing batch, then import private snapshots in
    /// short, bounded transactions. Tokens become bindable only after every
    /// body verifies. Errors release the whole batch; an enclosing caller
    /// transaction retains its original atomic commit/rollback semantics.
    pub fn stage_attachment_upload_files(
        &self,
        group: &str,
        source_epoch: u64,
        sources: &mut [AttachmentUploadSource<'_>],
        now: u64,
        byte_budget: u64,
        cancelled: &dyn Fn() -> bool,
    ) -> StorageResult<Vec<Vec<u8>>> {
        super::file_staging::stage(
            self,
            group,
            source_epoch,
            sources,
            now,
            byte_budget,
            cancelled,
        )
    }

    /// Privately reserve a bounded successful-upload batch for optional retention.
    /// No source identity or local-readable asset is invented here.
    /// Unowned failures expire; accepted pending sends protect their reservation.
    pub fn stage_attachment_uploads(
        &self,
        group: &str,
        source_epoch: u64,
        plaintext: &[&[u8]],
        now: u64,
        byte_budget: u64,
    ) -> StorageResult<Vec<Vec<u8>>> {
        if plaintext.is_empty()
            || plaintext.len() > 64
            || plaintext
                .iter()
                .any(|bytes| bytes.is_empty() || bytes.len() > MAX_RETAINED_ATTACHMENT_BYTES)
        {
            return Err(invalid("invalid outgoing attachment batch"));
        }
        let incoming = plaintext
            .iter()
            .try_fold(0u64, |sum, bytes| sum.checked_add(bytes.len() as u64))
            .ok_or_else(|| invalid("outgoing attachment size overflow"))?;
        self.connection.with_transaction(|| {
            let conn=self.lock()?;
            let accepted: bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM account_groups WHERE group_id_hex=?1)",[group],|row|row.get(0)).storage()?;
            if !accepted { return Err(invalid("outgoing attachment group unavailable")); }
            let (used,partial,count):(u64,u64,i64)=conn.query_row("SELECT (SELECT byte_count FROM attachment_retention_usage WHERE id=1),(SELECT reserved_bytes FROM attachment_partial_usage WHERE id=1),(SELECT count(*) FROM outgoing_attachment_uploads)",[],|r|Ok((nonnegative(r,0)?,nonnegative(r,1)?,r.get(2)?))).storage()?;
            if used.saturating_add(partial).saturating_add(incoming)>byte_budget || count+plaintext.len() as i64>MAX_STAGED_UPLOADS {
                return Err(invalid("outgoing attachment retention capacity unavailable"));
            }
            let mut tokens=Vec::with_capacity(plaintext.len());
            for bytes in plaintext {
                let token:Vec<u8>=conn.query_row("SELECT randomblob(16)",[],|r|r.get(0)).storage()?;
                let digest=Sha256::digest(bytes);
                conn.execute("INSERT INTO outgoing_attachment_uploads(token,group_id_hex,source_epoch,plaintext_digest,bytes,expires_at) VALUES(?1,?2,?3,?4,?5,?6)",params![token,group,u64_to_i64(source_epoch)?,&digest[..],bytes,u64_to_i64(now.saturating_add(UPLOAD_TTL_SECONDS))?]).storage()?;
                tokens.push(token);
            }
            Ok(tokens)
        })
    }

    /// Bind each successful upload to its exact parsed imeta source descriptor.
    /// A malformed/mismatched completion rolls back the entire batch binding.
    pub fn bind_attachment_uploads(
        &self,
        tokens: &[Vec<u8>],
        slots: &[(serde_json::Value, [u8; 32])],
    ) -> StorageResult<()> {
        if tokens.len() != slots.len() {
            return Err(invalid("outgoing attachment completion mismatch"));
        }
        self.connection.with_transaction(|| {
            let conn=self.lock()?;
            for (token,(slot,digest)) in tokens.iter().zip(slots) {
                let slot=serde_json::to_string(slot).map_err(|_|invalid("invalid outgoing attachment slot"))?;
                if slot.len()>MAX_DESCRIPTOR_BYTES {return Err(invalid("outgoing attachment descriptor exceeds bound"));}
                if conn.execute("UPDATE outgoing_attachment_uploads SET slot_json=?2 WHERE token=?1 AND plaintext_digest=?3",params![token,slot,&digest[..]]).storage()?!=1 {
                    return Err(invalid("outgoing attachment reservation unavailable"));
                }
            }
            Ok(())
        })
    }

    /// Pending projection owns staged bytes, without exposing them as a retained
    /// source. The relation survives token handoff to the engine's durable queue.
    /// All owners commit together; standalone callers also roll back on failure.
    pub fn protect_attachment_uploads(
        &self,
        group: &str,
        message: &str,
        tags: &[Vec<String>],
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            for tag in tags
                .iter()
                .filter(|tag| tag.first().is_some_and(|kind| kind == "imeta"))
            {
                let slot = serde_json::to_string(tag)
                    .map_err(|_| invalid("invalid outgoing attachment slot"))?;
                conn.execute("INSERT INTO outgoing_attachment_upload_owners SELECT token,?1,?2 FROM outgoing_attachment_uploads WHERE group_id_hex=?1 AND slot_json=?3 ON CONFLICT DO NOTHING",params![group,message,slot]).storage()?;
            }
            Ok(())
        })
    }

    /// Run optional ownership and promotion only after the outermost source
    /// transaction commits. Rollback discards the callback; retention errors
    /// never change the committed message or confirmation outcome.
    pub fn retain_attachment_uploads_after_commit(
        &self,
        group: &str,
        message: &str,
        now: u64,
        fallback_budget: u64,
    ) {
        let store = self.clone();
        let group = group.to_owned();
        let message = message.to_owned();
        self.connection.after_commit(move || {
            let result = (|| -> StorageResult<()> {
                let tags: Option<String> = store.lock()?.query_row(
                    "SELECT tags_json FROM app_events WHERE group_id_hex=?1 AND message_id_hex=?2 AND direction='sent'",
                    params![group, message], |row| row.get(0),
                ).optional().storage()?;
                if let Some(tags) = tags {
                    let tags: Vec<Vec<String>> = serde_json::from_str(&tags).map_err(|_| invalid("invalid outgoing attachment tags"))?;
                    store.protect_attachment_uploads(&group, &message, &tags)?;
                    store.promote_attachment_uploads(&group, &message, now, fallback_budget)?;
                }
                Ok(())
            })();
            if result.is_err() {
                tracing::warn!(target: "storage_sqlite::attachments", method = "outgoing_retention_after_commit",
                    "optional outgoing retention deferred");
            }
        });
    }

    /// Promote optional outgoing bytes in an independent transaction. Fences
    /// active fetches, preserves removal intent and never republishes a message.
    pub fn promote_attachment_uploads(
        &self,
        group: &str,
        message: &str,
        now: u64,
        fallback_budget: u64,
    ) -> StorageResult<usize> {
        let started = std::time::Instant::now();
        let verified_files = super::file_staging::verify(self, group, message)?;
        self.connection.with_transaction(|| {
            let conn=self.lock()?;
            let now = now.saturating_add(started.elapsed().as_secs());
            let mut stmt=conn.prepare("SELECT h.message_id_hex,h.attachment_index,h.source_message_id_hex,h.source_epoch,h.sender,h.timeline_at,h.received_at,h.slot_json,u.token,u.plaintext_digest,coalesce((SELECT uf.byte_len FROM outgoing_attachment_upload_files uf WHERE uf.token=u.token),(SELECT ub.byte_len FROM outgoing_attachment_upload_bodies ub WHERE ub.token=u.token),length(u.bytes)),u.quarantined
                FROM attachment_history h JOIN app_events a USING(group_id_hex,message_id_hex)
                JOIN account_groups g USING(group_id_hex)
                JOIN outgoing_attachment_uploads u ON u.group_id_hex=h.group_id_hex AND u.source_epoch=h.source_epoch AND u.slot_json=h.slot_json
                WHERE h.group_id_hex=?1 AND h.message_id_hex=?2 AND h.visible=1 AND a.direction='sent' AND g.pending_confirmation=0
                AND (a.retention_expires_at IS NULL OR a.retention_expires_at>?3)
                AND NOT EXISTS(SELECT 1 FROM attachment_removal_suppression r WHERE r.group_id_hex=h.group_id_hex AND r.message_id_hex=h.message_id_hex AND r.attachment_index=h.attachment_index)
                ORDER BY h.attachment_index,u.token").storage()?;
            let rows=stmt.query_map(params![group,message,u64_to_i64(now)?],|r|Ok((crate::AttachmentHistoryEntry { emoji_tags: Vec::new(),
                message_id_hex:r.get(0)?,attachment_index:r.get::<_,u32>(1)? as usize,source_message_id_hex:r.get(2)?,source_epoch:Some(nonnegative(r,3)?),sender:r.get(4)?,timeline_at:nonnegative(r,5)?,received_at:nonnegative(r,6)?,slot:serde_json::from_str(&r.get::<_,String>(7)?).map_err(|_|rusqlite::Error::InvalidQuery)?,
            },r.get::<_,Vec<u8>>(8)?,r.get::<_,Vec<u8>>(9)?,nonnegative(r,10)?,r.get::<_,bool>(11)?))).storage()?.collect::<Result<Vec<_>,_>>().storage()?;
            drop(stmt);drop(conn);
            let mut consumed=std::collections::HashMap::new();let mut slots=std::collections::HashSet::new();let mut promoted=0;
            for (entry,token,digest,size,quarantined) in rows {
                // Binding can add a file after the verification snapshot. Defer
                // it before claiming its slot; an absent check is not corruption.
                let checked_nonce = verified_files.get(&token).map(|(nonce, _)| nonce.as_slice());
                let checked: bool = self.lock()?.query_row(
                    "SELECT NOT EXISTS(SELECT 1 FROM outgoing_attachment_upload_files WHERE token=?1 AND (completed=0 OR nonce IS NOT ?2))",
                    params![token, checked_nonce], |row| row.get(0),
                ).storage()?;
                if !checked { continue; }
                if !slots.insert(entry.attachment_index) {continue;}
                let digest:[u8;32]=digest.try_into().map_err(|_|invalid("invalid outgoing attachment digest"))?;
                let AttachmentDemand::Requested(asset)=self.request_attachment_acquisition(group,&entry,digest,now)? else {continue;};
                let conn=self.lock()?;
                let eligible:bool=conn.query_row("SELECT NOT EXISTS(SELECT 1 FROM retained_attachment_files f WHERE f.token=?1 AND f.completed=0) AND cancelled=0 AND (state<>4 OR body_completed=1) AND NOT(?2 AND explicit_request=1 AND body_completed=0) FROM attachment_acquisition WHERE token=?1",params![asset.token,quarantined],|r|r.get(0)).storage()?;
                if !eligible {continue;}
                // The staged bytes already reserve their quota. Convert once the
                // complete message is processed; repeated slots need extra quota.
                let (used,partial,already,own_partial):(u64,u64,bool,u64)=conn.query_row("SELECT (SELECT byte_count FROM attachment_retention_usage WHERE id=1),(SELECT reserved_bytes FROM attachment_partial_usage WHERE id=1),EXISTS(SELECT 1 FROM retained_attachment_bytes WHERE token=?1),coalesce((SELECT total FROM attachment_partial WHERE token=?1),0)",[&asset.token],|r|Ok((nonnegative(r,0)?,nonnegative(r,1)?,r.get(2)?,nonnegative(r,3)?))).storage()?;
                let budget:Option<u64>=conn.query_row("SELECT retained_bytes FROM attachment_download_policy WHERE id=1",[],|r|nonnegative(r,0)).optional().storage()?;
                let keep_staged=staging_has_unfulfilled_owner(&conn,&token,now,Some((message,entry.attachment_index)))?;
                let credit=if keep_staged || consumed.contains_key(&token) {0}else{size};
                if !already && credit != size && used.saturating_add(partial.saturating_sub(own_partial)).saturating_add(size).saturating_sub(credit).saturating_sub(consumed.values().copied().sum::<u64>())>budget.unwrap_or(fallback_budget) {
                    conn.execute("UPDATE attachment_acquisition SET automatic_history=1,body_completed=1,state=4,due=NULL,attempt=NULL WHERE token=?1",[&asset.token]).storage()?;
                    continue;
                }
                if !already && (quarantined || !verify_staged_upload(&conn,&token,&digest,size,&verified_files)?) {
                    // Discard proven-corrupt bytes, keeping only metadata until
                    // every live source has a durable unavailable receipt.
                    conn.execute("DELETE FROM outgoing_attachment_upload_bodies WHERE token=?1",[&token]).storage()?;
                    conn.execute("DELETE FROM outgoing_attachment_upload_files WHERE token=?1",[&token]).storage()?;
                    conn.execute("UPDATE outgoing_attachment_uploads SET bytes=x'',quarantined=1 WHERE token=?1",[&token]).storage()?;
                    conn.execute("UPDATE attachment_acquisition SET automatic_history=1,body_completed=1,state=4,due=NULL,attempt=NULL WHERE token=?1",[&asset.token]).storage()?;
                    continue;
                }
                // INSERT ... SELECT bytes would materialize the whole value in
                // SQLite; copy through bounded incremental BLOB I/O instead.
                if !already {copy_staged_body(&conn,&token,&asset.token,size)?;}
                conn.execute("UPDATE attachment_acquisition SET state=3,body_completed=1,due=NULL,attempt=NULL,permission_paused=0 WHERE token=?1",[&asset.token]).storage()?;
                if !keep_staged {consumed.insert(token,size);} promoted+=1;
            }
            let conn=self.lock()?;
            for token in consumed.into_keys() {conn.execute("DELETE FROM outgoing_attachment_uploads WHERE token=?1",[token]).storage()?;}
            Ok(promoted)
        })
    }

    /// Release known failed upload reservations, preserving anything already
    /// owned by an admitted message. TTL handles only unobserved crash orphans.
    pub fn abandon_attachment_uploads(&self, tokens: &[Vec<u8>]) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            for token in tokens {
                if !staging_has_unfulfilled_owner(&conn, token, outgoing_now(), None)? {
                    conn.execute(
                        "DELETE FROM outgoing_attachment_uploads WHERE token=?1",
                        [token],
                    )
                    .storage()?;
                }
            }
            Ok(())
        })
    }

    /// Release exact successful upload descriptors after failed local admission.
    /// An existing pending or engine-owned message always protects its upload.
    pub fn abandon_bound_attachment_uploads(
        &self,
        group: &str,
        slots: &[serde_json::Value],
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            for slot in slots {
                let slot = serde_json::to_string(slot)
                    .map_err(|_| invalid("invalid outgoing attachment slot"))?;
                let mut stmt = conn.prepare("SELECT token FROM outgoing_attachment_uploads WHERE group_id_hex=?1 AND slot_json=?2").storage()?;
                let tokens = stmt.query_map(params![group,slot],|row|row.get::<_,Vec<u8>>(0)).storage()?.collect::<Result<Vec<_>,_>>().storage()?;
                drop(stmt);
                for token in tokens {
                    if !staging_has_unfulfilled_owner(&conn,&token,outgoing_now(),None)? {
                        conn.execute("DELETE FROM outgoing_attachment_uploads WHERE token=?1",[token]).storage()?;
                    }
                }
            }
            Ok(())
        })
    }

    /// Suppress automatic network demand while this confirmed outgoing slot has
    /// private uploaded bytes (or a quarantine receipt) awaiting local promotion.
    pub fn attachment_source_has_upload(
        &self,
        group: &str,
        message: &str,
        index: usize,
    ) -> StorageResult<bool> {
        self.lock()?.query_row("SELECT EXISTS(SELECT 1 FROM attachment_history h JOIN app_events a USING(group_id_hex,message_id_hex) JOIN outgoing_attachment_uploads u ON u.group_id_hex=h.group_id_hex AND u.source_epoch=h.source_epoch AND u.slot_json=h.slot_json WHERE h.group_id_hex=?1 AND h.message_id_hex=?2 AND h.attachment_index=?3 AND a.direction='sent')",params![group,message,index as i64],|row|row.get(0)).storage()
    }

    /// Recover confirmed staged sources after quota recovery without network
    /// admission or republishing. Owner selection and cursor advancement share
    /// one transaction, including blocked owners; each source promotes separately.
    pub fn recover_attachment_uploads(
        &self,
        now: u64,
        limit: usize,
        fallback_budget: u64,
    ) -> StorageResult<usize> {
        if limit == 0 || limit > 64 {
            return Err(invalid("invalid outgoing attachment recovery limit"));
        }
        let owners = self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let cursor: (String,String,Vec<u8>) = conn.query_row(
                "SELECT group_id_hex,message_id_hex,upload_token FROM outgoing_attachment_recovery_cursor WHERE id=1",[],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).storage()?;
            let mut uploads = Vec::new();
            // Both token ranges use the primary-key index; no full-table sort.
            for after in [true,false] {
                let query = if after {
                    "SELECT token,group_id_hex,source_epoch,slot_json,quarantined,recovery_message_id_hex,recovery_attachment_index FROM outgoing_attachment_uploads WHERE token>?1 ORDER BY token LIMIT ?2"
                } else {
                    "SELECT token,group_id_hex,source_epoch,slot_json,quarantined,recovery_message_id_hex,recovery_attachment_index FROM outgoing_attachment_uploads WHERE token<=?1 ORDER BY token LIMIT ?2"
                };
                let mut stmt=conn.prepare(query).storage()?;
                let remaining=limit-uploads.len();
                uploads.extend(stmt.query_map(params![cursor.2,remaining as i64],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,bool>(4)?,r.get::<_,String>(5)?,r.get::<_,i64>(6)?))).storage()?.collect::<Result<Vec<_>,_>>().storage()?);
                if uploads.len()==limit {break;}
            }
            let mut candidates=std::collections::BTreeSet::new();
            let mut last_upload = None;
            for (token, group, epoch, slot, quarantined, message, index) in &uploads {
                last_upload = Some(token);
                let Some(slot)=slot else {continue;};
                let mut inspected=Vec::new();
                // Page raw identities, advancing even through completed or ineligible sources.
                // The descriptor/index seek bounds work, not just the eligible output size.
                for after in [true,false] {
                    let query=if after {
                        "SELECT message_id_hex,attachment_index FROM attachment_history WHERE group_id_hex=?1 AND source_epoch=?2 AND slot_json=?3 AND (message_id_hex,attachment_index)>(?4,?5) ORDER BY message_id_hex,attachment_index LIMIT ?6"
                    } else {
                        "SELECT message_id_hex,attachment_index FROM attachment_history WHERE group_id_hex=?1 AND source_epoch=?2 AND slot_json=?3 AND (message_id_hex,attachment_index)<=(?4,?5) ORDER BY message_id_hex,attachment_index LIMIT ?6"
                    };
                    let mut stmt=conn.prepare(query).storage()?;
                    let remaining=limit-inspected.len();
                    inspected.extend(stmt.query_map(params![group,epoch,slot,message,index,remaining as i64],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?))).storage()?.collect::<Result<Vec<_>,_>>().storage()?);
                    if inspected.len()==limit {break;}
                }
                for (message, index) in inspected {
                    conn.execute("UPDATE outgoing_attachment_uploads SET recovery_message_id_hex=?2,recovery_attachment_index=?3 WHERE token=?1",params![token,message,index]).storage()?;
                    let eligible:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM attachment_history h JOIN app_events a USING(group_id_hex,message_id_hex) WHERE h.group_id_hex=?1 AND h.message_id_hex=?2 AND h.attachment_index=?3 AND h.visible=1 AND a.direction='sent' AND NOT EXISTS(SELECT 1 FROM attachment_acquisition q WHERE q.group_id_hex=h.group_id_hex AND q.message_id_hex=h.message_id_hex AND q.attachment_index=h.attachment_index AND ((q.state=3 AND EXISTS(SELECT 1 FROM retained_attachment_bytes b WHERE b.token=q.token)) OR (?4 AND q.body_completed=1))))",params![group,message,index,quarantined],|r|r.get(0)).storage()?;
                    if eligible {
                        candidates.insert((group.clone(), message));
                    }
                    if candidates.len() == limit { break; }
                }
                if candidates.len() == limit { break; }
            }
            let owners = candidates.iter().filter(|owner|**owner>(cursor.0.clone(),cursor.1.clone())).chain(candidates.iter().filter(|owner|**owner<=(cursor.0.clone(),cursor.1.clone()))).take(limit).cloned().collect::<Vec<_>>();
            if let Some(token) = last_upload {
                let (group,message)=owners.last().cloned().unwrap_or((cursor.0,cursor.1));
                conn.execute("UPDATE outgoing_attachment_recovery_cursor SET group_id_hex=?1,message_id_hex=?2,upload_token=?3 WHERE id=1",params![group,message,token]).storage()?;
            }
            Ok::<_, StorageError>(owners)
        })?;
        let mut recovered = 0;
        let mut failure = None;
        for (group, message) in owners {
            match self.promote_attachment_uploads(&group, &message, now, fallback_budget) {
                Ok(count) => recovered += count,
                Err(error) => failure = Some(error),
            }
        }
        failure.map_or(Ok(recovered), Err)
    }

    /// Bounded orphan sweep. A visible unexpired pending/confirmed message keeps
    /// its reservation until source promotion succeeds or invalidation releases it.
    pub fn prune_attachment_uploads(&self, now: u64, limit: usize) -> StorageResult<usize> {
        if limit == 0 || limit > 64 {
            return Err(invalid("invalid outgoing attachment cleanup limit"));
        }
        self.connection.with_transaction(|| {
            let conn=self.lock()?;
            let mut stmt=conn.prepare("SELECT token,expires_at,EXISTS(SELECT 1 FROM outgoing_attachment_upload_owners o WHERE o.token=u.token) FROM outgoing_attachment_uploads u ORDER BY expires_at,token").storage()?;
            let rows=stmt.query_map([],|r|Ok((r.get::<_,Vec<u8>>(0)?,nonnegative(r,1)?,r.get::<_,bool>(2)?))).storage()?.collect::<Result<Vec<_>,_>>().storage()?;
            drop(stmt);
            let mut removed=0;
            for (token,expiry,owned) in rows {
                if removed>=limit {break;}
                if (owned || expiry<=now) && !staging_has_unfulfilled_owner(&conn,&token,now,None)? {
                    removed+=conn.execute("DELETE FROM outgoing_attachment_uploads WHERE token=?1",[token]).storage()?;
                }
            }
            Ok(removed)
        })
    }
}

/// Check staged integrity with SQLite incremental BLOB reads and bounded plaintext buffers.
fn verify_staged_upload(
    conn: &Connection,
    token: &[u8],
    digest: &[u8; 32],
    size: u64,
    verified: &super::file_staging::Verification,
) -> StorageResult<bool> {
    let file: Option<(Vec<u8>, u64, bool)> = conn
        .query_row(
            "SELECT nonce,byte_len,completed FROM outgoing_attachment_upload_files WHERE token=?1",
            [token],
            |r| Ok((r.get(0)?, nonnegative(r, 1)?, r.get(2)?)),
        )
        .optional()
        .storage()?;
    if let Some((nonce, len, completed)) = file {
        return Ok(completed
            && len == size
            && verified
                .get(token)
                .is_some_and(|(checked, valid)| checked == &nonce && *valid));
    }
    let (table, rowid) = staged_body(conn, token)?;
    let blob = conn
        .blob_open("main", table, "bytes", rowid, true)
        .storage()?;
    if blob.len() as u64 != size {
        return Ok(false);
    }
    let mut hash = Sha256::new();
    let mut offset = 0usize;
    let mut bytes = Zeroizing::new(vec![0u8; blob.len().min(MAX_ATTACHMENT_LOCAL_READ_BYTES)]);
    while offset < blob.len() {
        let count = bytes.len().min(blob.len() - offset);
        blob.read_at_exact(&mut bytes[..count], offset).storage()?;
        hash.update(&bytes[..count]);
        offset += count;
    }
    blob.close().storage()?;
    Ok(hash.finalize().as_slice() == digest)
}

/// Locate staged plaintext by row identity only: a file-backed body row first,
/// otherwise the legacy in-row value. Neither lookup reads the body.
fn staged_body(conn: &Connection, token: &[u8]) -> StorageResult<(&'static str, i64)> {
    let body: Option<i64> = conn
        .query_row(
            "SELECT rowid FROM outgoing_attachment_upload_bodies WHERE token=?1",
            [token],
            |r| r.get(0),
        )
        .optional()
        .storage()?;
    if let Some(rowid) = body {
        return Ok((BODY_TABLE, rowid));
    }
    let rowid = conn
        .query_row(
            "SELECT rowid FROM outgoing_attachment_uploads WHERE token=?1",
            [token],
            |r| r.get(0),
        )
        .storage()?;
    Ok(("outgoing_attachment_uploads", rowid))
}

/// Publish verified staged plaintext into retained bytes without SQL-level
/// materialization: reserve a `zeroblob` tail value, then copy bounded chunks.
/// The caller's transaction rolls the reservation back on any failure.
fn copy_staged_body(
    conn: &Connection,
    staged: &[u8],
    retained: &[u8],
    size: u64,
) -> StorageResult<()> {
    let size_usize = usize::try_from(size)
        .map_err(|_| StorageError::InvalidAttachmentBody("invalid outgoing attachment size"))?;
    if size_usize as u64 > MAX_RETAINED_FILE_ATTACHMENT_BYTES {
        return Err(invalid("retained attachment exceeds storage bound"));
    }
    let file: Option<(Vec<u8>, u64, bool)> = conn
        .query_row(
            "SELECT nonce,byte_len,completed FROM outgoing_attachment_upload_files WHERE token=?1",
            [staged],
            |r| Ok((r.get(0)?, nonnegative(r, 1)?, r.get(2)?)),
        )
        .optional()
        .storage()?;
    if let Some((nonce, len, completed)) = file {
        if !completed || len != size {
            return Err(invalid("outgoing attachment file unavailable"));
        }
        conn.execute(
            "INSERT INTO retained_attachment_bytes(token,byte_len,bytes) VALUES(?1,0,x'')",
            [retained],
        )
        .storage()?;
        // Shared immutable chunks avoid a second whole-file SQLCipher copy.
        conn.execute("INSERT INTO retained_attachment_files(token,nonce,attempt,byte_len,completed) VALUES(?1,?2,zeroblob(16),?3,1)",params![retained,nonce,u64_to_i64(size)?]).storage()?;
        return Ok(());
    }
    let (table, rowid) = staged_body(conn, staged)?;
    conn.execute(
        "INSERT INTO retained_attachment_bytes(token,byte_len,bytes) VALUES(?1,?2,zeroblob(?2))",
        params![retained, u64_to_i64(size)?],
    )
    .storage()?;
    let target_rowid: i64 = conn
        .query_row(
            "SELECT rowid FROM retained_attachment_bytes WHERE token=?1",
            [retained],
            |r| r.get(0),
        )
        .storage()?;
    let source = conn
        .blob_open("main", table, "bytes", rowid, true)
        .storage()?;
    let mut target = conn
        .blob_open(
            "main",
            "retained_attachment_bytes",
            "bytes",
            target_rowid,
            false,
        )
        .storage()?;
    if source.len() != size_usize || target.len() != size_usize {
        return Err(invalid("outgoing attachment length changed"));
    }
    let mut buffer = Zeroizing::new(vec![
        0u8;
        ATTACHMENT_STAGING_CHUNK_BYTES.min(size_usize.max(1))
    ]);
    let mut offset = 0usize;
    while offset < size_usize {
        let count = buffer.len().min(size_usize - offset);
        source
            .read_at_exact(&mut buffer[..count], offset)
            .storage()?;
        target.write_at(&buffer[..count], offset).storage()?;
        offset += count;
    }
    source.close().storage()?;
    target.close().storage()?;
    Ok(())
}

pub(super) fn read_some(reader: &mut dyn std::io::Read, buffer: &mut [u8]) -> StorageResult<usize> {
    loop {
        match reader.read(buffer) {
            Ok(count) => return Ok(count),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(invalid("outgoing attachment source unreadable")),
        }
    }
}

/// Only live unfulfilled source slots or pending sends need staging. A satisfied
/// or retired sibling cannot pin quota; exclusion anticipates the current copy.
fn staging_has_unfulfilled_owner(
    conn: &Connection,
    token: &[u8],
    now: u64,
    current: Option<(&str, usize)>,
) -> StorageResult<bool> {
    let (message, index) = current.map(|(m, i)| (m, i as i64)).unwrap_or(("", -1));
    conn.query_row(r#"SELECT EXISTS(
        SELECT 1 FROM outgoing_attachment_uploads u JOIN attachment_history h
        ON h.group_id_hex=u.group_id_hex AND h.source_epoch=u.source_epoch AND h.slot_json=u.slot_json
        JOIN app_events a ON a.group_id_hex=h.group_id_hex AND a.message_id_hex=h.message_id_hex
        LEFT JOIN attachment_acquisition q USING(group_id_hex,message_id_hex,attachment_index)
        WHERE u.token=?1 AND a.invalidated=0 AND a.direction='sent' AND h.visible=1
        AND (a.retention_expires_at IS NULL OR a.retention_expires_at>?2)
        AND NOT(h.message_id_hex=?3 AND h.attachment_index=?4)
        AND NOT EXISTS(SELECT 1 FROM attachment_removal_suppression r WHERE r.group_id_hex=h.group_id_hex AND r.message_id_hex=h.message_id_hex AND r.attachment_index=h.attachment_index)
        AND (u.quarantined=0 OR q.token IS NULL OR q.body_completed=0)
        AND (q.token IS NULL OR (q.cancelled=0 AND (q.state<>4 OR q.body_completed=1)))
        AND NOT EXISTS(SELECT 1 FROM retained_attachment_bytes b WHERE b.token=q.token AND q.state=3)
    ) OR EXISTS(
        SELECT 1 FROM outgoing_attachment_uploads u JOIN app_events a ON a.group_id_hex=u.group_id_hex
        WHERE u.token=?1 AND a.direction='sent' AND a.invalidated=0 AND a.source_message_id_hex IS NULL
        AND (a.retention_expires_at IS NULL OR a.retention_expires_at>?2)
        AND NOT EXISTS(SELECT 1 FROM local_message_submissions l WHERE l.group_id_hex=a.group_id_hex AND l.message_id_hex=a.message_id_hex AND l.state=3)
        AND (EXISTS(SELECT 1 FROM outgoing_attachment_upload_owners o WHERE o.token=u.token AND o.group_id_hex=a.group_id_hex AND o.message_id_hex=a.message_id_hex)
        OR EXISTS(SELECT 1 FROM json_each(a.tags_json) t WHERE json(t.value)=u.slot_json))
    )"#,params![token,u64_to_i64(now)?,message,index],|r|r.get(0)).storage()
}

/// Match source expiry against wall time when cleanup follows a failed host call.
fn outgoing_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
