//! Optional outgoing snapshots share immutable chunks with retained assets.
use super::*;

const UPLOAD_TTL: u64 = 7 * 24 * 3600;

struct Batch<'a> {
    store: &'a SqliteAccountStorage,
    reservations: Vec<(Vec<u8>, Vec<u8>)>,
    finished: bool,
}

impl Drop for Batch<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let result: StorageResult<()> = self.store.connection.with_transaction(|| {
            let conn = self.store.lock()?;
            for (token, nonce) in &self.reservations {
                conn.execute("DELETE FROM outgoing_attachment_uploads WHERE token=?1 AND EXISTS(SELECT 1 FROM outgoing_attachment_upload_files WHERE token=?1 AND nonce=?2 AND completed=0)", params![token,nonce]).storage()?;
            }
            Ok(())
        });
        if result.is_err() {
            tracing::debug!(target: "storage_sqlite::attachments", method = "file_staging_cleanup",
                "unbound upload cleanup deferred");
        }
    }
}

pub(super) fn stage(
    store: &SqliteAccountStorage,
    group: &str,
    epoch: u64,
    sources: &mut [AttachmentUploadSource<'_>],
    now: u64,
    budget: u64,
    cancelled: &dyn Fn() -> bool,
) -> StorageResult<Vec<Vec<u8>>> {
    if sources.is_empty()
        || sources.len() > 64
        || sources
            .iter()
            .any(|s| s.len == 0 || s.len > MAX_RETAINED_FILE_ATTACHMENT_BYTES)
    {
        return Err(invalid("invalid outgoing attachment batch"));
    }
    let incoming = sources
        .iter()
        .try_fold(0u64, |n, s| n.checked_add(s.len))
        .ok_or_else(|| invalid("outgoing attachment size overflow"))?;
    let reservations = store.connection.with_transaction(|| {
        let conn = store.lock()?;
        let accepted: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM account_groups WHERE group_id_hex=?1)", [group], |r| r.get(0)).storage()?;
        if !accepted { return Err(invalid("outgoing attachment group unavailable")); }
        let (used,partial,count): (u64,u64,i64) = conn.query_row("SELECT (SELECT byte_count FROM attachment_retention_usage WHERE id=1),(SELECT reserved_bytes FROM attachment_partial_usage WHERE id=1),(SELECT count(*) FROM outgoing_attachment_uploads)", [], |r| Ok((nonnegative(r,0)?,nonnegative(r,1)?,r.get(2)?))).storage()?;
        if used.saturating_add(partial).saturating_add(incoming)>budget || count+sources.len() as i64>256 {
            return Err(invalid("outgoing attachment retention capacity unavailable"));
        }
        let mut result = Vec::with_capacity(sources.len());
        for source in sources.iter() {
            let (token,nonce): (Vec<u8>,Vec<u8>) = conn.query_row("SELECT randomblob(16),randomblob(16)", [], |r| Ok((r.get(0)?,r.get(1)?))).storage()?;
            conn.execute("INSERT INTO attachment_chunk_bodies(nonce) VALUES(?1)", [&nonce]).storage()?;
            conn.execute("INSERT INTO outgoing_attachment_uploads(token,group_id_hex,source_epoch,plaintext_digest,bytes,expires_at) VALUES(?1,?2,?3,?4,x'',?5)", params![token,group,u64_to_i64(epoch)?,&source.digest[..],u64_to_i64(now.saturating_add(UPLOAD_TTL))?]).storage()?;
            conn.execute("INSERT INTO outgoing_attachment_upload_files(token,nonce,byte_len) VALUES(?1,?2,?3)", params![token,nonce,u64_to_i64(source.len)?]).storage()?;
            result.push((token,nonce));
        }
        Ok(result)
    })?;
    let mut batch = Batch {
        store,
        reservations,
        finished: false,
    };
    let mut buffer = Zeroizing::new(vec![0u8; 1024 * 1024]);
    for (source, (token, nonce)) in sources.iter_mut().zip(&batch.reservations) {
        let mut offset = 0u64;
        let mut hash = Sha256::new();
        while offset < source.len {
            let want = (source.len - offset).min(buffer.len() as u64) as usize;
            let mut count = 0;
            while count < want {
                if cancelled() {
                    return Err(invalid("outgoing attachment staging cancelled"));
                }
                let end = (count + ATTACHMENT_STAGING_CHUNK_BYTES).min(want);
                let read = outgoing::read_some(source.reader, &mut buffer[count..end])?;
                if read == 0 {
                    return Err(StorageError::InvalidAttachmentBody(
                        "outgoing attachment source truncated",
                    ));
                }
                count += read;
            }
            hash.update(&buffer[..count]);
            store.connection.with_transaction(|| {
                let conn = store.lock()?;
                if !owns(&conn,token,nonce)? { return Err(invalid("outgoing attachment reservation unavailable")); }
                for (index,chunk) in buffer[..count].chunks(ATTACHMENT_STAGING_CHUNK_BYTES).enumerate() {
                    conn.execute("INSERT INTO retained_attachment_chunks(token,offset,bytes) VALUES(?1,?2,?3)", params![nonce,u64_to_i64(offset+(index*ATTACHMENT_STAGING_CHUNK_BYTES) as u64)?,chunk]).storage()?;
                }
                Ok(())
            })?;
            offset += count as u64;
        }
        let mut probe = [0u8; 1];
        if outgoing::read_some(source.reader, &mut probe)? != 0 {
            return Err(StorageError::InvalidAttachmentBody(
                "outgoing attachment source grew",
            ));
        }
        if hash.finalize().as_slice() != source.digest {
            return Err(StorageError::InvalidAttachmentBody(
                "outgoing attachment digest mismatch",
            ));
        }
    }
    if cancelled() {
        return Err(invalid("outgoing attachment staging cancelled"));
    }
    store.connection.with_transaction(|| {
        let conn=store.lock()?;
        let accepted:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM account_groups WHERE group_id_hex=?1)",[group],|r|r.get(0)).storage()?;
        if !accepted { return Err(invalid("outgoing attachment group unavailable")); }
        for (token,nonce) in &batch.reservations {
            if !owns(&conn,token,nonce)? { return Err(invalid("outgoing attachment reservation unavailable")); }
            conn.execute("UPDATE outgoing_attachment_upload_files SET completed=1 WHERE token=?1 AND nonce=?2",params![token,nonce]).storage()?;
        }
        Ok(())
    })?;
    batch.finished = true;
    Ok(batch
        .reservations
        .iter()
        .map(|(token, _)| token.clone())
        .collect())
}

fn owns(conn: &Connection, token: &[u8], nonce: &[u8]) -> StorageResult<bool> {
    conn.query_row("SELECT EXISTS(SELECT 1 FROM outgoing_attachment_upload_files WHERE token=?1 AND nonce=?2 AND completed=0)",params![token,nonce],|r|r.get(0)).storage()
}

pub(super) type Verification = std::collections::HashMap<Vec<u8>, (Vec<u8>, bool)>;

/// Verify completed file bodies before acquiring promotion's write transaction.
/// Every read releases the connection; a stale body identity cannot satisfy the
/// later promotion. Legacy staged blobs keep their original verification path.
pub(super) fn verify(
    store: &SqliteAccountStorage,
    group: &str,
    message: &str,
) -> StorageResult<Verification> {
    let candidates = {
        let conn = store.lock()?;
        let mut stmt=conn.prepare("SELECT DISTINCT f.token,f.nonce,f.byte_len,f.completed,u.plaintext_digest FROM outgoing_attachment_upload_files f JOIN outgoing_attachment_uploads u USING(token) JOIN attachment_history h ON h.group_id_hex=u.group_id_hex AND h.source_epoch=u.source_epoch AND h.slot_json=u.slot_json WHERE h.group_id_hex=?1 AND h.message_id_hex=?2").storage()?;
        stmt.query_map(params![group, message], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                nonnegative(r, 2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, Vec<u8>>(4)?,
            ))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?
    };
    let mut result = Verification::new();
    for (token, nonce, len, completed, digest) in candidates {
        if !completed {
            continue;
        }
        let mut offset = 0u64;
        let mut hash = Sha256::new();
        let mut valid = true;
        while offset < len {
            let chunk = {
                let conn = store.lock()?;
                conn.query_row(
                    "SELECT bytes FROM retained_attachment_chunks WHERE token=?1 AND offset=?2",
                    params![nonce, u64_to_i64(offset)?],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .optional()
                .storage()?
            };
            let Some(chunk) = chunk else {
                valid = false;
                break;
            };
            let chunk = Zeroizing::new(chunk);
            if chunk.is_empty()
                || chunk.len() > ATTACHMENT_STAGING_CHUNK_BYTES
                || offset + chunk.len() as u64 > len
            {
                valid = false;
                break;
            }
            hash.update(&chunk);
            offset += chunk.len() as u64;
        }
        valid &= hash.finalize().as_slice() == digest;
        result.insert(token, (nonce, valid));
    }
    Ok(result)
}
