//! Returning the account database's free pages to the filesystem (mdk#2314
//! step 6).
//!
//! Moving legacy attachment bodies out of the database, and removing
//! attachments, frees pages inside the database file, not on the volume.
//! After each maintenance batch, on the blocking pool:
//!
//! - Before compaction, the database cannot return pages on its own. Once
//!   enough of it is free, the volume has room and the live database is
//!   small enough, it is compacted once (`auto_vacuum=INCREMENTAL` plus a
//!   full `VACUUM`), at most once per worker ownership. Usage reads report
//!   `Compacting` meanwhile, from a snapshot taken just before, and
//!   attachment observers wake when it starts and ends.
//! - After compaction, each batch and each bulk removal returns freed pages
//!   in bounded steps, so moving bodies out keeps disk use flat.
//!
//! If the volume is too tight even for compaction, the migration's own pause
//! asks the user to prune; nothing is deleted to make room.
use std::sync::atomic::{AtomicBool, Ordering};

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
/// incremental; a no-op before compaction. Best effort. Blocking.
pub(crate) fn reclaim(storage: &SqliteAppStorage) {
    let pages = match storage.database_space() {
        Ok(space) if space.incremental && space.free_pages > 0 => {
            RECLAIM_MAX_BYTES / space.page_size.max(1)
        }
        Ok(_) => return,
        Err(_) => {
            tracing::warn!(target: TRACE_TARGET, method = "reclaim_free_pages",
                "database page reclaim deferred");
            return;
        }
    };
    match storage.reclaim_free_pages(pages) {
        Ok(freed) if freed > 0 => {
            tracing::debug!(target: TRACE_TARGET, method = "reclaim_free_pages", freed,
                "returned free database pages to the filesystem");
        }
        Ok(_) => {}
        Err(_) => {
            tracing::warn!(target: TRACE_TARGET, method = "reclaim_free_pages",
                "database page reclaim deferred");
        }
    }
}

/// After a maintenance batch: reclaim freed pages, or run the one-time
/// compaction when it is due and this worker has not attempted it yet.
/// `wake` tells attachment observers that compaction started or ended.
/// Blocking: call it only on the blocking pool.
pub(crate) fn maintain(
    storage: &SqliteAppStorage,
    reserve: u64,
    free: &dyn Fn() -> std::io::Result<u64>,
    progress: &SharedLegacyMigration,
    attempted: &AtomicBool,
    wake: &dyn Fn(),
) {
    let space = match storage.database_space() {
        Ok(space) => space,
        Err(_) => {
            tracing::warn!(target: TRACE_TARGET, method = "compact_database",
                "database maintenance deferred");
            return;
        }
    };
    if space.incremental {
        reclaim(storage);
        return;
    }
    if attempted.load(Ordering::Acquire) {
        return;
    }
    let Ok(available) = free() else {
        return;
    };
    if !compaction_due(&space, reserve, available) {
        return;
    }
    let Ok(snapshot) = storage.attachment_storage_usage(crate::unix_now_seconds()) else {
        return;
    };
    attempted.store(true, Ordering::Release);
    set_compacting(progress, Some(snapshot));
    wake();
    let started = std::time::Instant::now();
    let result = storage.compact_database();
    set_compacting(progress, None);
    wake();
    let duration_ms = started.elapsed().as_millis() as u64;
    match result.and_then(|()| storage.database_space()) {
        Ok(after) => {
            tracing::info!(target: TRACE_TARGET, method = "compact_database",
                reclaimed_bytes = space.file_bytes().saturating_sub(after.file_bytes()),
                duration_ms, "compacted the account database");
        }
        Err(_) => {
            tracing::warn!(target: TRACE_TARGET, method = "compact_database", duration_ms,
                "database compaction failed; it is not retried until the worker restarts");
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
