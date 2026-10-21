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
/// The `VACUUM` builds its copy in memory (`temp_store=MEMORY`), and its
/// final write-back of that copy cannot be interrupted, so a close (a host
/// about to suspend) that lands there waits for it. A larger live database
/// is not compacted: this bounds both the memory spike and that wait (about
/// a second on a recent iPhone). Attachment bodies moved out by the
/// migration are free pages, not live data, so heavy attachment accounts
/// fall under it once their bodies have moved.
const COMPACTION_MAX_LIVE_BYTES: u64 = 64 * MIB;
/// Free pages one reclaim step returns at most, bounding how long it holds
/// the account connection.
const RECLAIM_MAX_BYTES: u64 = 64 * MIB;
const TRACE_TARGET: &str = "marmot_app::storage_maintenance";

/// Whether the one-time compaction should run now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactionGate {
    Due,
    /// Already incremental, or too little of the file is free.
    NotWorthwhile,
    /// Worth doing, but the live database is over [`COMPACTION_MAX_LIVE_BYTES`].
    LiveTooLarge,
    /// Worth doing, but the volume cannot hold the copy.
    DiskTooTight,
}

/// The gates for the one-time compaction, with `free` bytes free on the
/// volume and `reserve` to keep. A `VACUUM` in WAL mode writes the live
/// database twice before the old pages go: its copy into the WAL, then the
/// checkpoint.
pub(crate) fn compaction_gate(space: &DatabaseSpace, reserve: u64, free: u64) -> CompactionGate {
    let live = space.live_bytes();
    let worthwhile = !space.incremental
        && space.free_pages > 0
        && space.free_bytes().saturating_mul(100)
            >= space
                .file_bytes()
                .saturating_mul(COMPACTION_MIN_FREE_PERCENT);
    if !worthwhile {
        CompactionGate::NotWorthwhile
    } else if live > COMPACTION_MAX_LIVE_BYTES {
        CompactionGate::LiveTooLarge
    } else if free < reserve.saturating_add(live.saturating_mul(2)) {
        CompactionGate::DiskTooTight
    } else {
        CompactionGate::Due
    }
}

/// Live database size rounded up to a power-of-two number of MiB: an
/// aggregate that shows how far over the cap accounts sit, nothing more.
fn live_mib_bucket(space: &DatabaseSpace) -> u64 {
    space.live_bytes().div_ceil(MIB).max(1).next_power_of_two()
}

/// Returns up to [`RECLAIM_MAX_BYTES`] of free pages once the database is
/// incremental, and finishes any WAL truncate a reader blocked earlier, so
/// the pages leave the file; a no-op before compaction. `startup` (the
/// first pass of a worker ownership) also truncates once on an incremental
/// database: a truncate owed when an earlier process ended is not recorded
/// anywhere. Best effort. Blocking. Returns whether that startup truncate
/// is settled: tried, or not needed because the database is not
/// incremental. A failed read leaves it for the next pass.
pub(crate) fn reclaim(storage: &SqliteAppStorage, startup: bool) -> bool {
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
    let incremental = if startup {
        match storage.database_space() {
            Ok(space) => space.incremental,
            Err(_) => return false,
        }
    } else {
        false
    };
    if incremental || storage.wal_truncate_pending() {
        // A busy or failed truncate is recorded as owed by the storage, so
        // later passes retry it.
        let _ = storage.truncate_wal();
    }
    true
}

/// Whether the one-time compaction is due now, reading only the database's
/// page figures and the volume's free space; it logs an account the live-size
/// cap holds back once its migration has nothing left to move. The page
/// figures when due. Blocking, but brief: the maintenance task runs it every
/// tick, and only a due result makes the account worker wait for a
/// compaction.
pub(crate) fn compaction_check(
    storage: &SqliteAppStorage,
    reserve: u64,
    free: &dyn Fn() -> std::io::Result<u64>,
    progress: &SharedLegacyMigration,
) -> Option<DatabaseSpace> {
    let space = match storage.database_space() {
        Ok(space) => space,
        Err(_) => {
            tracing::warn!(target: TRACE_TARGET, method = "compact_database",
                "database compaction check deferred");
            return None;
        }
    };
    let Ok(available) = free() else {
        return None;
    };
    match compaction_gate(&space, reserve, available) {
        CompactionGate::Due => Some(space),
        CompactionGate::LiveTooLarge => {
            // While legacy bodies or database-held avatar images remain, the
            // migrations are still shrinking the live database: only an
            // account over the cap with nothing left to move stays there. Log
            // those once per account per process: they keep their freed pages
            // inside the file, and this is how we learn how many there are
            // and by how much they miss.
            if storage
                .legacy_attachment_bytes()
                .map_or(true, |bytes| bytes > 0)
                || storage
                    .database_avatar_bytes()
                    .map_or(true, |bytes| bytes > 0)
            {
                return None;
            }
            let first = !std::mem::replace(
                &mut progress
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .compaction_cap_logged,
                true,
            );
            if first {
                tracing::info!(target: TRACE_TARGET, method = "compact_database",
                    live_mib_bucket = live_mib_bucket(&space),
                    cap_mib = COMPACTION_MAX_LIVE_BYTES / MIB,
                    "database compaction held back by the live-size cap");
            }
            None
        }
        CompactionGate::NotWorthwhile | CompactionGate::DiskTooTight => None,
    }
}

/// What [`compact_if_due`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactionAttempt {
    /// Not due; check again next tick.
    NotDue,
    /// Ran (or failed for good): not again this worker ownership.
    Done,
    /// The `VACUUM` rolled back (another connection held the database, the
    /// volume filled, or it failed otherwise): the database is as it was,
    /// and a later tick may try again.
    RolledBack,
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
    let Some(space) = compaction_check(storage, reserve, free, progress) else {
        return CompactionAttempt::NotDue;
    };
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
        // A failed VACUUM rolls back. Unless the switch somehow committed,
        // the database is as it was and the gates may pass again later.
        Err(_)
            if !storage
                .database_space()
                .is_ok_and(|after| after.incremental) =>
        {
            tracing::warn!(target: TRACE_TARGET, method = "compact_database", duration_ms,
                retry_scheduled = true, "database compaction rolled back");
            CompactionAttempt::RolledBack
        }
        Err(_) => {
            tracing::warn!(target: TRACE_TARGET, method = "compact_database", duration_ms,
                "database compaction committed but its follow-up failed");
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
