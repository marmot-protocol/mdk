//! Moving legacy attachment bodies out of the account database into the
//! encrypted media store (mdk#2314 step 6).
//!
//! The account worker runs one small batch per maintenance tick, after
//! readiness, on the blocking pool. Each body is admitted against free disk,
//! streamed from its rows into the store (identical content already there is
//! attached instead), and then its rows are deleted in one transaction. A
//! crash between the publish and the delete leaves both copies: reads prefer
//! the file, and the next batch only deletes the rows.
//!
//! When the smallest remaining body does not fit, the move pauses, the usage
//! summary reports how much more free space it needs, and attachment
//! observers wake. Each tick checks again. Nothing is ever deleted to make
//! room. A body that fails its digest or cannot be read back as stored is
//! dropped: its slot shows as unavailable with download-again allowed, as a
//! lost media file does, and the move continues.
use std::sync::{Arc, Mutex};

use media_store::{Admission, Category, DiskPolicy, MediaError, PublishOutcome};
use storage_sqlite::{AttachmentMigrationState, LegacyAttachmentBody, SqliteAppStorage};

use crate::AccountMediaStore;

/// Most bodies one batch moves.
pub(crate) const LEGACY_MIGRATION_BATCH: usize = 64;
/// A batch stops starting new bodies once it has moved this many bytes.
const LEGACY_MIGRATION_BATCH_BYTES: u64 = 64 * 1024 * 1024;
const TRACE_TARGET: &str = "marmot_app::storage_maintenance";

/// What this runtime's batches saw for one account. The database knows what
/// is left; this adds whether the move is paused and whether it moved
/// anything.
#[derive(Debug, Default)]
pub(crate) struct LegacyMigrationProgress {
    paused: Option<u64>,
    moved: bool,
    /// Observers heard that the move finished; reset when it moves again.
    complete_announced: bool,
    /// While the database compacts: the usage measured just before, which
    /// usage reads return instead of waiting for the busy database.
    pub(crate) compacting: Option<storage_sqlite::AttachmentStorageUsage>,
    /// The live-size cap holding compaction back was logged for this
    /// account in this process.
    pub(crate) compaction_cap_logged: bool,
}

pub(crate) type SharedLegacyMigration = Arc<Mutex<LegacyMigrationProgress>>;

impl LegacyMigrationProgress {
    /// The state to report, given the database's view of it.
    pub(crate) fn state(&self, stored: AttachmentMigrationState) -> AttachmentMigrationState {
        if self.compacting.is_some() {
            return AttachmentMigrationState::Compacting;
        }
        match stored {
            AttachmentMigrationState::NotNeeded if self.moved => AttachmentMigrationState::Complete,
            AttachmentMigrationState::Running { .. } => match self.paused {
                Some(needed_bytes) => AttachmentMigrationState::Paused { needed_bytes },
                None => stored,
            },
            other => other,
        }
    }
}

/// The result of one batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LegacyMigrationBatch {
    /// No legacy bodies are left.
    Complete,
    /// Bodies were moved or dropped. `more` when the batch stopped before
    /// it ran out of legacy bodies.
    Progress {
        moved: usize,
        moved_bytes: u64,
        dropped_corrupt: usize,
        more: bool,
    },
    /// The next body does not fit: free `needed_bytes` more. Anything moved
    /// earlier in the batch is counted.
    Paused {
        needed_bytes: u64,
        moved: usize,
        dropped_corrupt: usize,
    },
    /// A store, database or free-space failure; the next tick retries.
    Deferred {
        moved: usize,
        dropped_corrupt: usize,
    },
}

impl LegacyMigrationBatch {
    /// Bodies moved and corrupt bodies dropped.
    fn counts(&self) -> (usize, usize) {
        match *self {
            Self::Complete => (0, 0),
            Self::Progress {
                moved,
                dropped_corrupt,
                ..
            }
            | Self::Paused {
                moved,
                dropped_corrupt,
                ..
            }
            | Self::Deferred {
                moved,
                dropped_corrupt,
            } => (moved, dropped_corrupt),
        }
    }
}

enum BodyOutcome {
    Moved,
    /// Nothing moved this time: the rows changed underneath the move (a
    /// removal), or the stored file it would rely on failed verification and
    /// the next batch writes a fresh one.
    Skipped,
    Corrupt,
    Paused(u64),
    Deferred,
}

/// Moves up to one batch of legacy bodies, smallest first. `free` measures
/// the volume holding the media store; `reserve` stays free. Blocking: call
/// it only on the blocking pool.
pub(crate) fn migrate_batch(
    storage: &SqliteAppStorage,
    media: &AccountMediaStore,
    reserve: u64,
    free: &dyn Fn() -> std::io::Result<u64>,
    now: u64,
) -> LegacyMigrationBatch {
    let bodies = match storage.legacy_attachment_bodies(LEGACY_MIGRATION_BATCH) {
        Ok(bodies) => bodies,
        Err(_) => {
            return LegacyMigrationBatch::Deferred {
                moved: 0,
                dropped_corrupt: 0,
            };
        }
    };
    if bodies.is_empty() {
        return LegacyMigrationBatch::Complete;
    }
    let policy = DiskPolicy {
        reserve_bytes: reserve,
    };
    let (mut moved, mut moved_bytes, mut dropped_corrupt) = (0, 0_u64, 0);
    let mut more = bodies.len() == LEGACY_MIGRATION_BATCH;
    for body in &bodies {
        if moved_bytes >= LEGACY_MIGRATION_BATCH_BYTES {
            more = true;
            break;
        }
        match migrate_body(storage, media, &policy, free, now, body) {
            BodyOutcome::Moved => {
                moved += 1;
                moved_bytes = moved_bytes.saturating_add(body.byte_len());
            }
            BodyOutcome::Skipped => {}
            BodyOutcome::Corrupt => {
                if storage.drop_corrupt_legacy_body(body).is_err() {
                    return LegacyMigrationBatch::Deferred {
                        moved,
                        dropped_corrupt,
                    };
                }
                dropped_corrupt += 1;
            }
            BodyOutcome::Paused(needed_bytes) => {
                return LegacyMigrationBatch::Paused {
                    needed_bytes,
                    moved,
                    dropped_corrupt,
                };
            }
            BodyOutcome::Deferred => {
                return LegacyMigrationBatch::Deferred {
                    moved,
                    dropped_corrupt,
                };
            }
        }
    }
    LegacyMigrationBatch::Progress {
        moved,
        moved_bytes,
        dropped_corrupt,
        more,
    }
}

fn migrate_body(
    storage: &SqliteAppStorage,
    media: &AccountMediaStore,
    policy: &DiskPolicy,
    free: &dyn Fn() -> std::io::Result<u64>,
    now: u64,
    body: &LegacyAttachmentBody,
) -> BodyOutcome {
    let Some(digest) = body.digest() else {
        return BodyOutcome::Corrupt;
    };
    // An earlier move published the file and stopped before deleting the
    // rows. Drop them only once the whole file authenticates and hashes to
    // the slot's digest; a file that fails is marked lost, and the body
    // moves again.
    if let Some(id) = body.media_file() {
        match media.verify(&id, &digest) {
            Ok(true) => return dropped(storage.drop_migrated_legacy_body(body)),
            Ok(false) => {}
            Err(_) => return BodyOutcome::Deferred,
        }
    }
    let need = DiskPolicy::migration_need(body.byte_len());
    // The need is the whole store file, never zero, so the shortfall the
    // pause reports is always enough to clear it.
    let shortfall = |free: u64| {
        let short = policy
            .reserve_bytes
            .saturating_add(need)
            .saturating_sub(free);
        if short == 0 { need } else { short }
    };
    let Ok(available) = free() else {
        // Unknown free space admits nothing, as for downloads.
        return BodyOutcome::Deferred;
    };
    if policy.admit(available, need) != Admission::Admitted {
        return BodyOutcome::Paused(shortfall(available));
    }
    let mut reader = storage.legacy_attachment_reader(body);
    let published = media.publish(
        &storage.legacy_attachment_publication(body),
        Category::Retained,
        &mut reader,
        body.byte_len(),
        digest,
        now,
        &|| false,
    );
    match published {
        // Written and hashed just now, from these very rows.
        Ok(PublishOutcome::Published(_)) => dropped(storage.drop_migrated_legacy_body(body)),
        // A stored twin was only checked for presence and length: read it all
        // before giving up the database copy. One that fails is now lost, so
        // the next batch writes a fresh file from the rows.
        Ok(PublishOutcome::Existing(twin)) => match media.verify(&twin, &digest) {
            Ok(true) => dropped(storage.drop_migrated_legacy_body(body)),
            Ok(false) => BodyOutcome::Skipped,
            Err(_) => BodyOutcome::Deferred,
        },
        Ok(PublishOutcome::Superseded) => BodyOutcome::Skipped,
        Err(MediaError::InvalidBody(_)) => BodyOutcome::Corrupt,
        Err(MediaError::Io(_)) if reader.body_invalid() => BodyOutcome::Corrupt,
        // The volume filled during the write: pause with what it lacks now.
        // The next tick measures again before writing anything.
        Err(MediaError::Capacity) => match free() {
            Ok(available) => BodyOutcome::Paused(shortfall(available)),
            Err(_) => BodyOutcome::Deferred,
        },
        Err(_) => BodyOutcome::Deferred,
    }
}

fn dropped(result: cgka_traits::StorageResult<bool>) -> BodyOutcome {
    match result {
        Ok(true) => BodyOutcome::Moved,
        Ok(false) => BodyOutcome::Skipped,
        Err(_) => BodyOutcome::Deferred,
    }
}

/// Runs one batch and records it in `progress`. `true` when attachment
/// observers should hear about it: the move paused, resumed or finished, or
/// a corrupt body's slot became unavailable.
pub(crate) fn run_batch(
    storage: &SqliteAppStorage,
    media: &AccountMediaStore,
    reserve: u64,
    free: &dyn Fn() -> std::io::Result<u64>,
    progress: &SharedLegacyMigration,
) -> bool {
    let started = std::time::Instant::now();
    let batch = migrate_batch(storage, media, reserve, free, crate::unix_now_seconds());
    let mut progress = progress
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let was_paused = progress.paused.is_some();
    let (moved, dropped_corrupt) = batch.counts();
    if moved + dropped_corrupt > 0 {
        progress.moved = true;
        progress.complete_announced = false;
    }
    let finished = match batch {
        LegacyMigrationBatch::Complete => true,
        LegacyMigrationBatch::Progress {
            moved_bytes, more, ..
        } => {
            tracing::info!(target: TRACE_TARGET, method = "migrate_legacy_attachments",
                moved, moved_bytes, dropped_corrupt,
                duration_ms = started.elapsed().as_millis() as u64,
                "moved one bounded batch of legacy attachment bodies");
            !more
        }
        LegacyMigrationBatch::Paused { needed_bytes, .. } => {
            progress.paused = Some(needed_bytes);
            if !was_paused {
                tracing::info!(target: TRACE_TARGET, method = "migrate_legacy_attachments",
                    moved, dropped_corrupt, needed_bytes,
                    "legacy attachment migration paused for free space");
            }
            false
        }
        LegacyMigrationBatch::Deferred { .. } => {
            tracing::warn!(target: TRACE_TARGET, method = "migrate_legacy_attachments",
                moved, dropped_corrupt, retry_scheduled = true,
                "legacy attachment migration batch deferred");
            false
        }
    };
    // A pause is reported only while the latest batch saw one.
    if !matches!(batch, LegacyMigrationBatch::Paused { .. }) {
        progress.paused = None;
    }
    let mut wake = dropped_corrupt > 0;
    if finished && progress.moved && !progress.complete_announced {
        progress.complete_announced = true;
        wake = true;
        tracing::info!(target: TRACE_TARGET, method = "migrate_legacy_attachments",
            "legacy attachment migration is complete");
    }
    wake || was_paused != progress.paused.is_some()
}

#[cfg(test)]
#[path = "legacy_migration_tests.rs"]
mod tests;
