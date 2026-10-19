//! Protected chunk imports: slow caller I/O never owns the account transaction.
use super::*;

struct Reservation<'a> {
    store: &'a SqliteAppStorage,
    token: &'a [u8],
    nonce: Vec<u8>,
    published: bool,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        // The nonce prevents a cancelled/late importer deleting a replacement
        // attempt. Close or a storage error leaves an unreadable reservation
        // for the next admitted lease to reclaim.
        let result: StorageResult<()> = self.store.connection.with_transaction(|| {
            self.store.lock()?.execute(
                "DELETE FROM retained_attachment_bytes WHERE token=?1 AND EXISTS(
                    SELECT 1 FROM retained_attachment_files f WHERE f.token=?1 AND f.nonce=?2 AND f.completed=0)",
                params![self.token, self.nonce],
            ).storage()?;
            Ok(())
        });
        if result.is_err() {
            tracing::debug!(target: "storage_sqlite::app::attachment_acquisition::file_import", method = "file_import_cleanup",
                "unpublished import cleanup deferred");
        }
    }
}

pub(super) fn complete(
    store: &SqliteAppStorage,
    job: &AttachmentAcquisition,
    reader: &mut dyn std::io::Read,
    len: u64,
    clock: &dyn Fn() -> u64,
    budget: u64,
    cancelled: &dyn Fn() -> bool,
) -> StorageResult<AttachmentPublishResult> {
    if len > MAX_RETAINED_FILE_ATTACHMENT_BYTES {
        return Err(StorageError::InvalidAttachmentBody(
            "retained attachment exceeds storage bound",
        ));
    }
    let digest: [u8; 32] =
        job.digest.as_slice().try_into().map_err(|_| {
            StorageError::InvalidAttachmentBody("attachment plaintext digest mismatch")
        })?;
    let reservation = store.connection.with_transaction(|| {
        let conn = store.lock()?;
        let now = u64_to_i64(clock())?;
        if let Some(refused) = publication_refusal(&conn, job, now, len, budget)? {
            return Ok(Err(refused));
        }
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM retained_attachment_bytes WHERE token=?1)",
                [&job.reference.token],
                |row| row.get(0),
            )
            .storage()?;
        if exists {
            return Ok(Err(AttachmentPublishResult::Superseded));
        }
        Ok(Ok(reserve_chunked_file(&conn, job, len)?))
    })?;
    let nonce = match reservation {
        Ok(nonce) => nonce,
        Err(refused) => return Ok(refused),
    };
    let mut reservation = Reservation {
        store,
        token: &job.reference.token,
        nonce,
        published: false,
    };
    // Batch at most one MiB per transaction without ever asking the caller
    // for more than one 64 KiB staging chunk.
    let mut buffer = Zeroizing::new(vec![0u8; 1024 * 1024]);
    let mut hasher = Sha256::new();
    let mut offset = 0u64;
    while offset < len {
        if cancelled() {
            return Err(invalid("attachment import cancelled"));
        }
        let want = (len - offset).min(buffer.len() as u64) as usize;
        let mut count = 0;
        while count < want {
            let end = (count + ATTACHMENT_STAGING_CHUNK_BYTES).min(want);
            let read = outgoing::read_some(reader, &mut buffer[count..end])?;
            if read == 0 {
                return Err(StorageError::InvalidAttachmentBody(
                    "attachment source truncated",
                ));
            }
            count += read;
            if cancelled() {
                return Err(invalid("attachment import cancelled"));
            }
        }
        hasher.update(&buffer[..count]);
        let refusal = store.connection.with_transaction(|| {
            let conn = store.lock()?;
            if !owns(&conn, job, &reservation.nonce)? {
                return Ok(Some(AttachmentPublishResult::Superseded));
            }
            // This import already reserves its full length. Do not charge it
            // again, but retain all source, permission, lease and quota checks.
            if let Some(refused) = publication_refusal(&conn, job, u64_to_i64(clock())?, 0, budget)?
            {
                return Ok(Some(refused));
            }
            insert_chunks(&conn, &reservation.nonce, offset, &buffer[..count])?;
            Ok(None)
        })?;
        if let Some(refused) = refusal {
            return Ok(refused);
        }
        offset += count as u64;
    }
    let mut probe = [0u8; 1];
    if outgoing::read_some(reader, &mut probe)? != 0 {
        return Err(StorageError::InvalidAttachmentBody(
            "attachment source grew",
        ));
    }
    if hasher.finalize().as_slice() != digest {
        return Err(StorageError::InvalidAttachmentBody(
            "attachment plaintext digest mismatch",
        ));
    }
    if cancelled() {
        return Err(invalid("attachment import cancelled"));
    }
    let result = store.connection.with_transaction(|| {
        let conn = store.lock()?;
        if !owns(&conn, job, &reservation.nonce)? {
            return Ok(AttachmentPublishResult::Superseded);
        }
        if let Some(refused) = publication_refusal(&conn, job, u64_to_i64(clock())?, 0, budget)? {
            return Ok(refused);
        }
        seal_chunked_file(&conn, &job.reference.token, &reservation.nonce)?;
        conn.execute(
            "UPDATE attachment_acquisition SET state=3,due=NULL,attempt=NULL,storage_blocked_headroom=NULL,storage_park_count=0 WHERE token=?1",
            [&job.reference.token],
        )
        .storage()?;
        Ok(AttachmentPublishResult::Published)
    })?;
    reservation.published = result == AttachmentPublishResult::Published;
    Ok(result)
}

/// Reserve a chunked retained file for `job`: a fresh chunk-body nonce, an
/// empty placeholder that keeps source and deletion ownership, and the
/// unfinished file row, whose metadata (not the placeholder) charges the
/// complete length to the quota exactly once. Returns the chunks' nonce.
pub(super) fn reserve_chunked_file(
    conn: &Connection,
    job: &AttachmentAcquisition,
    len: u64,
) -> StorageResult<Vec<u8>> {
    let nonce: Vec<u8> = conn
        .query_row("SELECT randomblob(16)", [], |row| row.get(0))
        .storage()?;
    conn.execute(
        "INSERT INTO attachment_chunk_bodies(nonce) VALUES(?1)",
        [&nonce],
    )
    .storage()?;
    conn.execute(
        "INSERT INTO retained_attachment_bytes(token,byte_len,bytes) VALUES(?1,0,x'')",
        [&job.reference.token],
    )
    .storage()?;
    conn.execute(
        "INSERT INTO retained_attachment_files(token,nonce,attempt,byte_len) VALUES(?1,?2,?3,?4)",
        params![job.reference.token, nonce, job.attempt, u64_to_i64(len)?],
    )
    .storage()?;
    Ok(nonce)
}

/// Write `bytes` at `offset` of a reserved file, one staging chunk per row.
pub(super) fn insert_chunks(
    conn: &Connection,
    nonce: &[u8],
    offset: u64,
    bytes: &[u8],
) -> StorageResult<()> {
    for (index, chunk) in bytes.chunks(ATTACHMENT_STAGING_CHUNK_BYTES).enumerate() {
        conn.execute_cached(
            "INSERT INTO retained_attachment_chunks(token,offset,bytes) VALUES(?1,?2,?3)",
            params![
                nonce,
                u64_to_i64(offset + (index * ATTACHMENT_STAGING_CHUNK_BYTES) as u64)?,
                chunk
            ],
        )
        .storage()?;
    }
    Ok(())
}

/// Seal a reserved file after its last chunk, since completed chunks are
/// immutable, and before the job leaves its attempt, which discards an
/// unfinished file.
pub(super) fn seal_chunked_file(
    conn: &Connection,
    token: &[u8],
    nonce: &[u8],
) -> StorageResult<()> {
    conn.execute(
        "UPDATE retained_attachment_files SET completed=1 WHERE token=?1 AND nonce=?2",
        params![token, nonce],
    )
    .storage()?;
    Ok(())
}

fn owns(conn: &Connection, job: &AttachmentAcquisition, nonce: &[u8]) -> StorageResult<bool> {
    conn.query_row("SELECT EXISTS(SELECT 1 FROM retained_attachment_files WHERE token=?1 AND nonce=?2 AND attempt=?3 AND completed=0)",
        params![job.reference.token, nonce, job.attempt], |row| row.get(0)).storage()
}

/// None selects the legacy blob reader. Chunked files use the same source gate
/// and at most one local-read window plus a single staging chunk in memory.
pub(super) fn read(
    conn: &Connection,
    token: &[u8],
    offset: usize,
    limit: usize,
) -> StorageResult<Option<Zeroizing<Vec<u8>>>> {
    let file: Option<(u64, bool, Vec<u8>)> = conn
        .query_row(
            "SELECT byte_len,completed,nonce FROM retained_attachment_files WHERE token=?1",
            [token],
            |row| Ok((nonnegative(row, 0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .storage()?;
    let Some((len, completed, nonce)) = file else {
        return Ok(None);
    };
    if !completed {
        return Err(invalid("attachment import is incomplete"));
    }
    let count = len.saturating_sub(offset as u64).min(limit as u64) as usize;
    let mut result = Zeroizing::new(Vec::with_capacity(count));
    if count == 0 {
        return Ok(Some(result));
    }
    let end = offset + count;
    let mut statement = conn.prepare("SELECT offset,bytes FROM retained_attachment_chunks WHERE token=?1 AND offset<?3 AND offset>=max(0,?2-65536) ORDER BY offset").storage()?;
    let mut rows = statement
        .query(params![nonce, offset as i64, end as i64])
        .storage()?;
    let mut next = offset;
    while let Some(row) = rows.next().storage()? {
        let start = nonnegative(row, 0).storage()? as usize;
        let bytes = Zeroizing::new(row.get::<_, Vec<u8>>(1).storage()?);
        if start + bytes.len() <= next {
            continue;
        }
        if start > next || bytes.is_empty() || bytes.len() > ATTACHMENT_STAGING_CHUNK_BYTES {
            // Completed chunks are immutable: this never repairs itself.
            return Err(StorageError::InvalidAttachmentBody(
                "invalid retained attachment chunks",
            ));
        }
        let take = (end - next).min(start + bytes.len() - next);
        result.extend_from_slice(&bytes[next - start..next - start + take]);
        next += take;
        if next == end {
            break;
        }
    }
    if next != end {
        return Err(StorageError::InvalidAttachmentBody(
            "retained attachment chunks truncated",
        ));
    }
    Ok(Some(result))
}
