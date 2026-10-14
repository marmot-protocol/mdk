//! Least-recently-used eviction of retained attachment bodies.
//!
//! The retained budget counts retained bodies, staged outgoing uploads and
//! checkpoint reservations. When new bytes would exceed it, the bodies used
//! least recently are released, oldest first, so the newest demand can still
//! publish. Staged uploads and checkpoints are never evicted here.
//!
//! An evicted row stays Ready without bytes, which hosts see as
//! `PreviouslyAcquiredUnavailable`. Ordinary automatic demand never re-arms
//! it, so eviction cannot start a download loop; explicit download-again
//! restores it from the original source.
use super::*;

/// A body published or read this recently is never evicted, so an attachment
/// that is on screen or being installed survives a burst of new downloads.
pub const ATTACHMENT_EVICTION_PROTECTION_SECONDS: u64 = 60 * 60;
/// Local reads refresh a body's last use at most this often.
pub(super) const ATTACHMENT_USE_REFRESH_SECONDS: i64 = 60;
/// Most bodies one admission may release, bounding its transaction. High enough
/// that many small files (emoji, stickers) can still make room for one large one;
/// the index scan stops at the first protected body or once the deficit is covered.
const ATTACHMENT_EVICTION_VICTIM_LIMIT: i64 = 4096;

/// Oldest-used Ready bodies, served by migration 0110's partial index.
pub(super) const VICTIMS_SQL: &str = "SELECT q.token,
        CASE WHEN b.byte_len>=0 THEN b.byte_len ELSE length(b.bytes) END
        + coalesce((SELECT f.byte_len FROM retained_attachment_files f WHERE f.token=q.token),0)
     FROM attachment_acquisition q JOIN retained_attachment_bytes b ON b.token=q.token
     WHERE q.state=3 AND q.retained_used_at<=?1
       AND NOT EXISTS(SELECT 1 FROM retained_attachment_files f
           WHERE f.token=q.token AND f.completed=0)
     ORDER BY q.retained_used_at,q.rowid LIMIT ?2";

/// Least-recently-used evictable bodies whose charged bytes cover `deficit`,
/// or None when every evictable body together cannot cover it. A body's charge
/// matches what its deletion releases from `attachment_retention_usage`: the
/// array row plus, for a chunked file, the file row's length.
fn victims(conn: &Connection, deficit: u64, now: i64) -> StorageResult<Option<Vec<Vec<u8>>>> {
    let used_before =
        now.saturating_sub(i64::try_from(ATTACHMENT_EVICTION_PROTECTION_SECONDS).unwrap_or(0));
    let mut statement = conn.prepare_cached(VICTIMS_SQL).storage()?;
    let mut rows = statement
        .query(params![used_before, ATTACHMENT_EVICTION_VICTIM_LIMIT])
        .storage()?;
    let mut tokens = Vec::new();
    let mut released = 0u64;
    while let Some(row) = rows.next().storage()? {
        tokens.push(row.get::<_, Vec<u8>>(0).storage()?);
        released = released.saturating_add(nonnegative(row, 1).storage()?);
        if released >= deficit {
            return Ok(Some(tokens));
        }
    }
    Ok(None)
}

/// Whether `projected` retained bytes fit `budget`, possibly after eviction.
/// Read-only: admission only checks, and the transfer evicts once it knows
/// the body's real size.
pub(super) fn can_make_room(
    conn: &Connection,
    projected: u64,
    budget: u64,
    now: i64,
) -> StorageResult<bool> {
    Ok(projected <= budget || victims(conn, projected - budget, now)?.is_some())
}

/// Make `projected` retained bytes fit `budget` by releasing the
/// least-recently-used bodies. Validates before mutating: when eviction cannot
/// cover the whole deficit nothing is released, and the caller refuses as
/// before. Call inside the caller's transaction, so the release commits only
/// with the bytes it made room for.
pub(super) fn make_room(
    conn: &Connection,
    projected: u64,
    budget: u64,
    now: i64,
) -> StorageResult<bool> {
    if projected <= budget {
        return Ok(true);
    }
    let Some(tokens) = victims(conn, projected - budget, now)? else {
        return Ok(false);
    };
    for token in &tokens {
        // Cascades to the chunked file row; the usage triggers release both.
        conn.execute_cached(
            "DELETE FROM retained_attachment_bytes WHERE token=?1",
            [token],
        )
        .storage()?;
    }
    tracing::debug!(
        target: "storage_sqlite::attachments",
        method = "attachment_eviction",
        evicted = tokens.len(),
        "released least-recently-used attachment bodies"
    );
    Ok(true)
}

/// Record a local read as a use, at most once per refresh interval.
pub(super) fn touch(conn: &Connection, token: &[u8], now: i64) -> StorageResult<()> {
    conn.execute_cached(
        "UPDATE attachment_acquisition SET retained_used_at=?2
         WHERE token=?1 AND state=3 AND retained_used_at<?3",
        params![
            token,
            now,
            now.saturating_sub(ATTACHMENT_USE_REFRESH_SECONDS)
        ],
    )
    .storage()?;
    Ok(())
}
