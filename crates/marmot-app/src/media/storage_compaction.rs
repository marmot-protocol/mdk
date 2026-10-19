//! Returning the account database's free pages to the filesystem (mdk#2314
//! step 6).
//!
//! Moving legacy attachment bodies out of the database, and removing
//! attachments, frees pages inside the database file, not on the volume.
//! On each maintenance tick, on the blocking pool:
//!
//! - Before compaction, the database cannot return pages on its own. Once
//!   enough of it is free, the volume has room and the live database is
//!   small enough, it is compacted once (`auto_vacuum=INCREMENTAL` plus a
//!   full `VACUUM`), at most once per worker ownership. The account worker
//!   awaits it on the blocking pool, so its own storage calls wait without
//!   holding an async thread. Usage reads report `Compacting` meanwhile, from
//!   a snapshot taken just before, and attachment observers wake when it
//!   starts and ends.
//! - After compaction, each batch and each bulk removal returns freed pages
//!   in bounded steps, so moving bodies out keeps disk use flat.
//!
//! If the volume is too tight even for compaction, the migration's own pause
//! asks the user to prune; nothing is deleted to make room.
use storage_sqlite::{DatabaseSpace, SqliteAppStorage};

use super::legacy_migration::SharedLegacyMigration;

const MIB: u64 = 1024 * 1024;
/// Compact once free pages are at least this percentage of the file.
const COMPACTION_MIN_FREE_PERCENT: u64 = 25;
/// The `VACUUM` builds its copy in memory (`temp_store=MEMORY`), so a larger
/// live database is not compacted: the memory spike would risk the process.
/// Under this cap, "256 MiB free" already means at least half the file is
/// free, so the 25% rule alone decides.
const COMPACTION_MAX_LIVE_BYTES: u64 = 256 * MIB;
/// Free pages one reclaim step returns at most, bounding how long it holds
/// the account connection.
const RECLAIM_MAX_BYTES: u64 = 64 * MIB;
const TRACE_TARGET: &str = "marmot_app::storage_maintenance";

/// Whether the one-time compaction should run now, with `free` bytes free
/// on the volume and `reserve` to keep. A `VACUUM` in WAL mode writes the
/// live database twice before the old pages go: its copy into the WAL, then
/// the checkpoint.
pub(crate) fn compaction_due(space: &DatabaseSpace, reserve: u64, free: u64) -> bool {
    let live = space.live_bytes();
    !space.incremental
        && space.free_pages > 0
        && space.free_bytes().saturating_mul(100)
            >= space
                .file_bytes()
                .saturating_mul(COMPACTION_MIN_FREE_PERCENT)
        && live <= COMPACTION_MAX_LIVE_BYTES
        && free >= reserve.saturating_add(live.saturating_mul(2))
}

/// Returns up to [`RECLAIM_MAX_BYTES`] of free pages once the database is
/// incremental, and finishes any WAL truncate a reader blocked earlier, so
/// the pages leave the file; a no-op before compaction. Best effort.
/// Blocking.
pub(crate) fn reclaim(storage: &SqliteAppStorage) {
    match storage.database_space() {
        Ok(space) if space.incremental && space.free_pages > 0 => {
            match storage.reclaim_free_pages(RECLAIM_MAX_BYTES / space.page_size.max(1)) {
                Ok(reclaim) if reclaim.pages > 0 => {
                    tracing::debug!(target: TRACE_TARGET, method = "reclaim_free_pages",
                        freed = reclaim.pages, truncated = reclaim.truncated,
                        "returned free database pages to the filesystem");
                }
                Ok(_) => {}
                Err(_) => {
                    tracing::warn!(target: TRACE_TARGET, method = "reclaim_free_pages",
                        "database page reclaim deferred");
                }
            }
        }
        Ok(_) => {}
        Err(_) => {
            tracing::warn!(target: TRACE_TARGET, method = "reclaim_free_pages",
                "database page reclaim deferred");
        }
    }
    // The storage records every truncate's result under the connection
    // lock, so this reads the latest attempt; repeating a truncate is safe.
    if storage.wal_truncate_pending() {
        let _ = storage.truncate_wal();
    }
}

/// What [`compact_if_due`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactionAttempt {
    /// Not due; check again next tick.
    NotDue,
    /// Ran (or failed for good): not again this worker ownership.
    Done,
    /// Another connection held the database, so the `VACUUM` rolled back
    /// before copying anything; the next tick may try again.
    Busy,
}

/// The one-time compaction, when it is due. `wake` tells attachment
/// observers that it started and ended.
///
/// Blocking, and the `VACUUM` holds the account connection until it ends:
/// the account worker awaits this on the blocking pool instead of making its
/// own storage calls meanwhile, so no async thread waits on the connection.
pub(crate) fn compact_if_due(
    storage: &SqliteAppStorage,
    reserve: u64,
    free: &dyn Fn() -> std::io::Result<u64>,
    progress: &SharedLegacyMigration,
    wake: &dyn Fn(),
) -> CompactionAttempt {
    let space = match storage.database_space() {
        Ok(space) => space,
        Err(_) => {
            tracing::warn!(target: TRACE_TARGET, method = "compact_database",
                "database compaction check deferred");
            return CompactionAttempt::NotDue;
        }
    };
    let Ok(available) = free() else {
        return CompactionAttempt::NotDue;
    };
    if !compaction_due(&space, reserve, available) {
        return CompactionAttempt::NotDue;
    }
    let Ok(snapshot) = storage.attachment_storage_usage(crate::unix_now_seconds()) else {
        return CompactionAttempt::NotDue;
    };
    set_compacting(progress, Some(snapshot));
    wake();
    let started = std::time::Instant::now();
    let result = storage.compact_database();
    set_compacting(progress, None);
    wake();
    let duration_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(truncated) => {
            let file_bytes = storage
                .database_space()
                .map_or(space.file_bytes(), |after| after.file_bytes());
            tracing::info!(target: TRACE_TARGET, method = "compact_database",
                reclaimed_bytes = space.file_bytes().saturating_sub(file_bytes),
                wal_truncated = truncated, duration_ms, "compacted the account database");
            CompactionAttempt::Done
        }
        Err(error) if error.is_transient() => {
            tracing::info!(target: TRACE_TARGET, method = "compact_database", duration_ms,
                retry_scheduled = true, "database compaction found the database busy");
            CompactionAttempt::Busy
        }
        Err(_) => {
            tracing::warn!(target: TRACE_TARGET, method = "compact_database", duration_ms,
                "database compaction failed; it is not retried until the worker restarts");
            CompactionAttempt::Done
        }
    }
}

fn set_compacting(
    progress: &SharedLegacyMigration,
    snapshot: Option<storage_sqlite::AttachmentStorageUsage>,
) {
    progress
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .compacting = snapshot;
}

#[cfg(test)]
#[path = "storage_compaction_tests.rs"]
mod tests;
