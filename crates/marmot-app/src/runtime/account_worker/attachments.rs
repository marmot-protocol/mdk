//! Durable automatic acquisition. Parsing and admission run under the
//! account worker; HTTP/crypto use the existing cancellable media executor.
//! Bodies are retained in the account's encrypted media store (mdk#2314),
//! whose blocking file I/O, hashing and AEAD always run on the blocking pool.
use super::*;
use crate::AccountMediaStore;
use crate::media::AttachmentDownloadFailure;
use crate::runtime::attachment_controls::AttachmentUpdates;
use media_store::{Category, MediaError};
use storage_sqlite::SqliteAppStorage;
use storage_sqlite::{
    ATTACHMENT_ACQUISITION_BATCH_LIMIT, AttachmentAcquisition, SqliteAccountStorage,
};

const DEMAND_BATCH: usize = 32;
// Background HTTP has a two-minute whole-transfer deadline. Leave publication margin.
const LEASE_SECONDS: u64 = 3 * 60;
const EXPLICIT_LEASE_SECONDS: u64 = 20 * 60;
/// Compaction attempts that may roll back under one worker ownership.
const MAX_COMPACTION_ROLLBACKS: u32 = 3;
/// Rows, then file names, per media sweep batch.
const MEDIA_SWEEP_BATCH: usize = 256;
/// How often the "Keep media" sweep runs after worker start. Its windows are
/// measured in days, so a sweep every tick would only rescan.
const KEEP_MEDIA_SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// How long one "Keep media" pass removes before leaving the rest to the
/// next tick.
const KEEP_MEDIA_SWEEP_BUDGET: Duration = Duration::from_millis(250);
/// How often deferred housekeeping is checked again once nothing else is
/// owed: free-page reclaim, an owed WAL truncate, and a compaction that was
/// not yet worthwhile or did not fit (mdk#2923 §4). Deletions recheck sooner.
const HOUSEKEEPING_RECHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

type PermitWait = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<OwnedSemaphorePermit, tokio::sync::AcquireError>>
            + Send,
    >,
>;

/// One admitted attachment transfer's hold on runtime capacity: its global
/// permit, and the disk its download may still write. Both are held until the
/// transfer's result is stored (or it ends without one), then released together.
pub(super) struct TransferSlot {
    _permit: OwnedSemaphorePermit,
    _reserved: Option<DiskReservation>,
}

/// Disk an admitted download may still write, counted in the runtime's shared
/// total until dropped. Admission sets that total aside from measured free
/// space: a transfer in flight may not have written its body yet, and other
/// accounts' transfers may have different limits.
struct DiskReservation {
    bytes: u64,
    total: Arc<std::sync::atomic::AtomicU64>,
}

impl DiskReservation {
    fn new(total: &Arc<std::sync::atomic::AtomicU64>, bytes: u64) -> Self {
        total.fetch_add(bytes, std::sync::atomic::Ordering::AcqRel);
        Self {
            bytes,
            total: total.clone(),
        }
    }
}

impl Drop for DiskReservation {
    fn drop(&mut self) {
        self.total
            .fetch_sub(self.bytes, std::sync::atomic::Ordering::AcqRel);
    }
}

/// At most one queued permit request per active account. Keeping the future
/// across worker select turns preserves Tokio semaphore FIFO fairness.
#[derive(Default)]
pub(super) struct Admission {
    resumed: bool,
    waiting: Option<PermitWait>,
    permit: Option<OwnedSemaphorePermit>,
    /// The media sweep running on the blocking pool, if any.
    media_sweep: Option<tokio::task::JoinHandle<()>>,
    /// The outgoing upload promotion pass running on the blocking pool, if
    /// any, and where the next one resumes.
    upload_promotion:
        Option<tokio::task::JoinHandle<(Option<storage_sqlite::AttachmentUploadOwner>, bool)>>,
    upload_cursor: Option<storage_sqlite::AttachmentUploadOwner>,
    /// A pass skipped the batch in `upload_promotion`. That pass may have
    /// come for an owner the batch's read missed, so the batch's completion
    /// runs one more pass even when it was idle (mdk#3378).
    upload_skipped: bool,
    /// The legacy body migration batch running on the blocking pool, if any.
    legacy_migration: Option<tokio::task::JoinHandle<()>>,
    /// The one-time database compaction ran under this worker; it is not
    /// attempted again until the next worker ownership.
    compaction_attempted: bool,
    /// The maintenance task found the one-time compaction due. Only then
    /// does the worker wait on the blocking pool for it; a tick with nothing
    /// due costs the worker nothing.
    compaction_due: Arc<std::sync::atomic::AtomicBool>,
    /// Compactions that rolled back under this worker. After
    /// [`MAX_COMPACTION_ROLLBACKS`] it is not attempted again until the next
    /// worker ownership, so a failure that repeats cannot rebuild the
    /// in-memory copy every tick.
    compaction_rollbacks: u32,
    /// This worker settled the WAL truncate an earlier process may have left
    /// owed (recorded nowhere): set only once a maintenance pass tried it,
    /// so a pass that failed before that leaves it for the next one.
    startup_wal_settled: Arc<std::sync::atomic::AtomicBool>,
    /// When the "Keep media" sweep (mdk#2314 step 10) next runs: `None` at
    /// worker start, then hourly.
    keep_media_due: Option<std::time::Instant>,
    /// A sweep stopped at its time budget with attachments still past the
    /// window, or failed: the next tick runs it again.
    keep_media_more: Arc<std::sync::atomic::AtomicBool>,
    /// What idle housekeeping has derived from the opened database's data
    /// (mdk#2923 §4): finished one-time work stops, and the media sweep runs
    /// only when something may have left work for it.
    pub(super) latches: HousekeepingLatches,
}

/// Housekeeping state derived from one opened account database. Keyed to its
/// [`SqliteAppStorage::connection_serial`]: a reopened, reset or replaced
/// database starts unlatched and derives everything again from its data.
/// Only terminal outcomes latch; deferred ones are rechecked on a deadline.
#[derive(Default)]
pub(super) struct HousekeepingLatches {
    serial: Option<u64>,
    /// No legacy attachment body and no legacy upload that could add one.
    legacy_bodies_done: Arc<std::sync::atomic::AtomicBool>,
    /// No avatar image held in the database; nothing writes one any more.
    database_avatars_done: Arc<std::sync::atomic::AtomicBool>,
    /// The database is already incremental, so the one-time compaction can
    /// never be due on it.
    compaction_settled: Arc<std::sync::atomic::AtomicBool>,
    /// When deferred housekeeping (reclaim, an owed WAL truncate, a
    /// compaction not yet worthwhile, too large or too tight) is checked
    /// again. `None` means now.
    recheck_due: Option<std::time::Instant>,
    /// The deletion count the last housekeeping batch saw: a deletion frees
    /// pages, so reclaim checks again.
    batch_cleanup_seen: Option<i64>,
    /// The deletion count, and the other-connection commit count, the last
    /// media sweep started from. `None` means a sweep is owed.
    sweep_cleanup_seen: Option<i64>,
    sweep_foreign_seen: Option<i64>,
    /// The last sweep batch did not reach the end of the store, or failed.
    sweep_unfinished: Arc<std::sync::atomic::AtomicBool>,
    /// A batch failed. Its cursor may have moved past what it failed on, so
    /// a full pass from the start is owed. Finishing the current pass does
    /// not clear it; only starting that rescan does.
    sweep_rescan: Arc<std::sync::atomic::AtomicBool>,
    /// When the owed rescan runs: one housekeeping recheck after the
    /// failure, so a failure that persists costs one pass per recheck, not
    /// one per tick.
    sweep_rescan_due: Option<std::time::Instant>,
}

impl HousekeepingLatches {
    /// Resets everything when `storage` is not the database these were
    /// derived from.
    pub(super) fn bind(&mut self, storage: &SqliteAppStorage) {
        let serial = storage.connection_serial();
        if self.serial != Some(serial) {
            *self = Self {
                serial: Some(serial),
                ..Self::default()
            };
        }
    }

    fn done(flag: &std::sync::atomic::AtomicBool) -> bool {
        flag.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Starts a media sweep on the blocking pool unless one is still running:
/// to completion when the worker takes ownership, otherwise one batch, and
/// then only while something may have left work for it (mdk#2923 §4):
/// - this connection deleted a `media_files` or `attachment_partial` row,
///   which can leave a file with no row;
/// - another connection or process committed (`PRAGMA data_version`);
/// - the media store reports a best-effort unlink, truncate or abandon that
///   failed;
/// - the last batch did not reach the end of the store, or failed.
///
/// A crash leaves its orphans to the sweep that runs when the next worker
/// takes ownership.
fn spawn_media_sweep(
    admission: &mut Admission,
    storage: &SqliteAppStorage,
    media: AccountMediaStore,
    until_complete: bool,
    telemetry: &marmot_observability::PerformanceRecorder,
) {
    use std::sync::atomic::Ordering;
    if admission
        .media_sweep
        .as_ref()
        .is_some_and(|task| !task.is_finished())
    {
        return;
    }
    let latches = &mut admission.latches;
    latches.bind(storage);
    // A failed batch owes a rescan from the start on the next recheck.
    let mut rescan_now = false;
    if latches.sweep_rescan.load(Ordering::Acquire) {
        let now = std::time::Instant::now();
        match latches.sweep_rescan_due {
            None => latches.sweep_rescan_due = Some(now + HOUSEKEEPING_RECHECK_INTERVAL),
            Some(due) if now >= due => rescan_now = true,
            Some(_) => {}
        }
    }
    // Read before the batch starts, so a deletion while it runs is seen.
    // A failed read counts as a change.
    let cleanup = storage.media_cleanup_epoch().ok();
    let foreign = storage.foreign_commit_version().ok();
    // A failed unlink, truncate or abandon may have left its file behind the
    // cursor of a pass in progress, so it owes a pass from the start.
    let store_owed = media.take_sweep_owed();
    let owed = until_complete
        | rescan_now
        | store_owed
        | latches.sweep_unfinished.load(Ordering::Acquire)
        | latches.sweep_cleanup_seen.is_none()
        | (cleanup.is_none() || cleanup != latches.sweep_cleanup_seen)
        | (foreign.is_none() || foreign != latches.sweep_foreign_seen);
    if !owed {
        return;
    }
    latches.sweep_cleanup_seen = cleanup;
    latches.sweep_foreign_seen = foreign;
    // Each is a full pass from the start, which is what was owed. The
    // cursor restart takes the store's sweep lock, which an earlier batch
    // may still hold, so it runs on the blocking pool with the sweep.
    let restart = rescan_now || until_complete || store_owed;
    if restart {
        latches.sweep_rescan.store(false, Ordering::Release);
        latches.sweep_rescan_due = None;
    }
    let unfinished = latches.sweep_unfinished.clone();
    let rescan = latches.sweep_rescan.clone();
    // Timed on the blocking pool (mdk#2923); a batch that never runs or
    // panics drops its span, which records it as cancelled.
    let batch = telemetry.observe(RuntimeOp::WorkerMediaSweep);
    admission.media_sweep = Some(tokio::task::spawn_blocking(move || {
        if restart {
            media.restart_sweep();
        }
        let outcome = loop {
            match media.sweep(MEDIA_SWEEP_BATCH) {
                Ok(report) if until_complete && !report.complete => {}
                Ok(report) => {
                    unfinished.store(!report.complete, Ordering::Release);
                    break TelemetryOutcome::Success;
                }
                Err(_) => {
                    // Not again next tick: a failure that persists would
                    // repeat every 15 s. A full rescan is owed instead, on
                    // the next recheck.
                    unfinished.store(false, Ordering::Release);
                    rescan.store(true, Ordering::Release);
                    tracing::warn!(target: "marmot_app::runtime", method = "media_sweep",
                        "media store sweep deferred");
                    break TelemetryOutcome::Failure;
                }
            }
        };
        batch.finish(outcome);
    }));
}
/// Starts one page of outgoing upload promotion on the blocking pool unless
/// one is still running. Each run resumes after the last, so uploads that
/// cannot promote yet never starve the rest; a promotion wakes attachment
/// observers with a state change. A batch requests another worker pass on
/// completion when it promoted, left a page, or a pass skipped it.
fn spawn_upload_promotion(
    admission: &mut Admission,
    storage: SqliteAccountStorage,
    media: AccountMediaStore,
    updates: AttachmentUpdates,
    telemetry: &marmot_observability::PerformanceRecorder,
) {
    // Consume even a finished batch through ready(), preserving its wakeup,
    // and owe the skipped pass a follow-up.
    if admission.upload_promotion.is_some() {
        admission.upload_skipped = true;
        return;
    }
    // Only a file-backed upload promotes. With none, and no page in
    // progress, there is nothing to page (mdk#2923). A failed read still
    // runs the pass.
    if admission.upload_cursor.is_none()
        && matches!(storage.app_storage().has_file_backed_uploads(), Ok(false))
    {
        return;
    }
    let after = admission.upload_cursor.take();
    let batch = telemetry.observe(RuntimeOp::WorkerUploadPromotion);
    admission.upload_promotion = Some(tokio::task::spawn_blocking(move || {
        match crate::media::outgoing::promote_uploads(
            &storage.app_storage(),
            &media,
            after.as_ref(),
            crate::media::outgoing::UPLOAD_PROMOTION_BATCH,
        ) {
            Ok((next, promoted)) => {
                let more = next.is_some() || promoted;
                if promoted {
                    updates.state_changed();
                }
                batch.finish(TelemetryOutcome::Success);
                (next, more)
            }
            Err(_) => {
                tracing::warn!(target: "marmot_app::runtime", method = "outgoing_upload_promotion",
                    "outgoing upload promotion deferred");
                batch.finish(TelemetryOutcome::Failure);
                (None, false)
            }
        }
    }));
}

/// Starts one housekeeping batch on the blocking pool, unless one is still
/// running or none of its parts is owed (mdk#2923 §4):
/// - the "Keep media" setting (mdk#2314 step 10), at worker start, then
///   hourly, or again while a pass left more;
/// - moving legacy database bodies, then database-held avatar images, into
///   the media store (mdk#2314 steps 6 and 9), until the data shows none is
///   left;
/// - returning freed database pages to the filesystem once the database is
///   incremental, and a WAL truncate the startup or an earlier pass owes;
/// - checking whether the one-time compaction is due, until the database is
///   incremental.
///
/// Finished work latches for the life of the opened database; a deferred
/// outcome never does. Keep-media more runs again on the next tick. An owed
/// WAL truncate is retried hourly or after a deletion. The compaction check
/// (not worthwhile, too large or too tight) runs on every batch while a
/// migration is owed, otherwise hourly or after a deletion. The startup
/// truncate runs on the first batch. A batch that pauses for free space, resumes, finishes,
/// or drops a corrupt body wakes attachment observers.
pub(super) fn spawn_legacy_migration(
    client: &AppClient,
    shared: &RuntimeSharedServices,
    admission: &mut Admission,
) {
    use std::sync::atomic::Ordering;
    if client.app.config.cursor_persistence == crate::CursorPersistence::Frozen
        || admission
            .legacy_migration
            .as_ref()
            .is_some_and(|task| !task.is_finished())
    {
        return;
    }
    let Ok(storage) = client.app.account_storage(&client.state.label) else {
        return;
    };
    let app_storage = storage.app_storage();
    admission.latches.bind(&app_storage);
    let now = std::time::Instant::now();
    let sweep_keep_media = admission.keep_media_more.load(Ordering::Acquire)
        || admission.keep_media_due.is_none_or(|due| now >= due);
    let latches = &mut admission.latches;
    let legacy_owed = !HousekeepingLatches::done(&latches.legacy_bodies_done);
    let avatars_owed = !HousekeepingLatches::done(&latches.database_avatars_done);
    let startup = !admission.startup_wal_settled.load(Ordering::Acquire);
    let recheck = latches.recheck_due.is_none_or(|due| now >= due);
    // A deletion frees pages: reclaim checks again. A failed read counts as
    // one, so the batch still runs.
    let cleanup = app_storage.media_cleanup_epoch().ok();
    let deleted = cleanup.is_none() || cleanup != latches.batch_cleanup_seen;
    // An owed WAL truncate is not a trigger of its own: every batch retries
    // it, so it waits for the hourly recheck or a deletion. A reader that
    // keeps blocking it then costs one batch per recheck, not one per tick.
    if !(sweep_keep_media || legacy_owed || avatars_owed || startup || recheck || deleted) {
        return;
    }
    if sweep_keep_media {
        admission.keep_media_more.store(false, Ordering::Release);
        admission.keep_media_due = Some(now + KEEP_MEDIA_SWEEP_INTERVAL);
    }
    latches.batch_cleanup_seen = cleanup;
    if recheck {
        latches.recheck_due = Some(now + HOUSEKEEPING_RECHECK_INTERVAL);
    }
    // While a migration is owed, every batch checks: the batch that frees
    // the pages also sees them, after its legacy and avatar steps. A
    // deletion frees pages too. Neither happens on an idle tick, so this
    // costs an idle account nothing.
    let check_compaction = (recheck || deleted || legacy_owed || avatars_owed)
        && !admission.compaction_attempted
        && !HousekeepingLatches::done(&latches.compaction_settled);
    let legacy_done = latches.legacy_bodies_done.clone();
    let avatars_done = latches.database_avatars_done.clone();
    let compaction_settled = latches.compaction_settled.clone();
    let app = client.app.clone();
    let label = client.state.label.clone();
    let updates = shared.attachment_updates.clone();
    let startup_wal_settled = admission.startup_wal_settled.clone();
    let compaction_due = admission.compaction_due.clone();
    let keep_media_more = admission.keep_media_more.clone();
    let batch = shared
        .observer
        .performance()
        .observe(RuntimeOp::WorkerMaintenanceHousekeepingBatch);
    admission.legacy_migration = Some(tokio::task::spawn_blocking(move || {
        let started = (|| {
            let storage = app.account_storage(&label)?;
            let media = app.account_media_store(&label, &storage)?;
            let reserve = storage
                .app_storage()
                .attachment_download_policy(&super::super::attachment_controls::default_policy(
                    &app.config,
                ))?
                .disk_reserve;
            Ok::<_, AppError>((storage, media, reserve))
        })();
        let Ok((storage, media, reserve)) = started else {
            if sweep_keep_media {
                keep_media_more.store(true, Ordering::Release);
            }
            tracing::warn!(target: "marmot_app::storage_maintenance",
                method = "migrate_legacy_attachments",
                "legacy attachment migration batch deferred");
            batch.finish(TelemetryOutcome::Failure);
            return;
        };
        let account_dir = app.account_dir(&label);
        let free = || crate::media::attachment_resume::available_space(&account_dir);
        let progress = app.legacy_media_migration(&label);
        let app_storage = storage.app_storage();
        // "Keep media" first, so bodies past the window are not moved only
        // to be removed.
        let mut outcome = TelemetryOutcome::Success;
        if sweep_keep_media {
            let deadline = std::time::Instant::now() + KEEP_MEDIA_SWEEP_BUDGET;
            match super::super::attachment_storage::clean_past_keep_window(
                &app_storage,
                &media,
                Some(deadline),
            ) {
                Ok((removed, more)) => {
                    if more {
                        keep_media_more.store(true, Ordering::Release);
                    }
                    if removed > 0 {
                        tracing::info!(target: "marmot_app::storage_maintenance",
                            method = "keep_media_sweep", removed, more,
                            "attachments past the keep media window removed");
                        // Rows leave Ready for CleanedBySetting.
                        updates.state_changed();
                    }
                }
                Err(_) => {
                    // Deferred by an error: the batch still runs the rest,
                    // but its span reports the failure.
                    outcome = TelemetryOutcome::Failure;
                    keep_media_more.store(true, Ordering::Release);
                    tracing::warn!(target: "marmot_app::storage_maintenance",
                        method = "keep_media_sweep",
                        "keep media sweep deferred");
                }
            }
        }
        if legacy_owed {
            let changed = crate::media::legacy_migration::run_batch(
                &app_storage,
                &media,
                reserve,
                &free,
                &progress,
            );
            if changed {
                // A moved, paused or dropped body: a dropped one leaves Ready.
                updates.state_changed();
            }
            // Finished only when the data shows nothing left, including a
            // legacy upload whose promotion would add a body; a pause or a
            // deferral leaves it owed.
            if matches!(app_storage.has_legacy_attachment_work(), Ok(false)) {
                legacy_done.store(true, Ordering::Release);
            }
        }
        // Then images still held in the database move into cache files
        // (mdk#2314 step 9), so compaction can return their pages.
        if avatars_owed {
            if crate::media::avatar_files::run_batch(&app_storage, &media, reserve, &free) {
                app.presentation_signals.wake();
                let _ = app.presentation_signals.avatars.send(label.clone());
            }
            if matches!(app_storage.has_database_held_avatars(), Ok(false)) {
                avatars_done.store(true, Ordering::Release);
            }
        }
        if crate::media::storage_compaction::reclaim(&app_storage, startup) && startup {
            startup_wal_settled.store(true, Ordering::Release);
        }
        if check_compaction {
            // An incremental database never needs the one-time compaction:
            // that is terminal. Anything else is checked again later.
            if matches!(app_storage.database_space(), Ok(space) if space.incremental) {
                compaction_settled.store(true, Ordering::Release);
            } else if crate::media::storage_compaction::compaction_check(
                &app_storage,
                reserve,
                &free,
                &progress,
            )
            .is_some()
            {
                compaction_due.store(true, Ordering::Release);
            }
        }
        batch.finish(outcome);
    }));
}

/// The one-time database compaction (mdk#2314 step 6), once the maintenance
/// task found it due and this worker has not attempted it, awaited on the
/// blocking pool. The worker makes no storage calls while it waits, so the
/// `VACUUM` holding the account connection never parks an async thread.
/// Skipped while a migration batch still runs; the next tick checks again.
/// When nothing is due the worker does not wait at all.
pub(super) async fn compact_if_due(
    client: &AppClient,
    shared: &RuntimeSharedServices,
    admission: &mut Admission,
) {
    if client.app.config.cursor_persistence == crate::CursorPersistence::Frozen
        || admission.compaction_attempted
        || !admission
            .compaction_due
            .load(std::sync::atomic::Ordering::Acquire)
        || admission
            .legacy_migration
            .as_ref()
            .is_some_and(|task| !task.is_finished())
    {
        return;
    }
    admission
        .compaction_due
        .store(false, std::sync::atomic::Ordering::Release);
    let app = client.app.clone();
    let label = client.state.label.clone();
    let updates = shared.attachment_updates.clone();
    let attempted = tokio::task::spawn_blocking(move || {
        let storage = app.account_storage(&label).ok()?;
        let reserve = storage
            .app_storage()
            .attachment_download_policy(&super::super::attachment_controls::default_policy(
                &app.config,
            ))
            .ok()?
            .disk_reserve;
        let account_dir = app.account_dir(&label);
        Some(crate::media::storage_compaction::compact_if_due(
            &storage.app_storage(),
            reserve,
            &|| crate::media::attachment_resume::available_space(&account_dir),
            &app.legacy_media_migration(&label),
            // Rare, twice per compaction: reported as a state change, which
            // costs observers one read each.
            &|| updates.state_changed(),
        ))
    })
    .await;
    if let Ok(Some(attempt)) = attempted {
        admission.record_compaction(attempt);
    }
}

impl Admission {
    /// Counts a compaction attempt: one that ran is not repeated under this
    /// worker, and rollbacks stop being retried after
    /// [`MAX_COMPACTION_ROLLBACKS`].
    pub(super) fn record_compaction(
        &mut self,
        attempt: crate::media::storage_compaction::CompactionAttempt,
    ) {
        use crate::media::storage_compaction::CompactionAttempt;
        match attempt {
            CompactionAttempt::Done => self.compaction_attempted = true,
            CompactionAttempt::RolledBack => {
                self.compaction_rollbacks += 1;
                self.compaction_attempted = self.compaction_rollbacks >= MAX_COMPACTION_ROLLBACKS;
                // A rollback is not the idle path: check again on the next
                // tick, not after the hourly recheck.
                self.latches.recheck_due = None;
            }
            CompactionAttempt::NotDue => {}
        }
    }

    pub(super) fn is_waiting(&self) -> bool {
        self.waiting.is_some() || self.upload_promotion.is_some()
    }
    pub(super) async fn ready(&mut self) -> bool {
        tokio::select! {
            permit = async { self.waiting.as_mut().unwrap().await }, if self.waiting.is_some() => {
                self.permit = permit.ok();
                self.waiting = None;
                true
            }
            result = async { self.upload_promotion.as_mut().unwrap().await }, if self.upload_promotion.is_some() => {
                self.upload_promotion = None;
                let (next, more) = result.unwrap_or_default();
                self.upload_cursor = next;
                // Clear the skip even when `more` already wakes the worker.
                let skipped = std::mem::take(&mut self.upload_skipped);
                more || skipped
            }
            else => false,
        }
    }
}

fn reference(
    slot: &serde_json::Value,
    epoch: u64,
    loopback: bool,
) -> Option<crate::MediaAttachmentReference> {
    let tag = serde_json::from_value::<Vec<String>>(slot.clone()).ok()?;
    crate::parse_media_attachment(&tag, Some(epoch), loopback).ok()
}

fn admit_demands(storage: &SqliteAppStorage, now: u64, loopback: bool) -> Result<bool, AppError> {
    let demands = storage.attachment_worker_demands(DEMAND_BATCH)?;
    let more = demands.len() == DEMAND_BATCH;
    for demand in demands {
        if storage.attachment_source_has_upload(
            &demand.group_id_hex,
            &demand.entry.message_id_hex,
            demand.entry.attachment_index,
        ).unwrap_or_else(|_| {
            tracing::warn!(target: "marmot_app::runtime", method = "outgoing_retention_lookup", "optional outgoing retention lookup deferred");
            false
        }) {
            storage.acknowledge_attachment_worker_demand(&demand)?;
            continue;
        }
        if let Some(epoch) = demand.entry.source_epoch
            && let Some(reference) = reference(&demand.entry.slot, epoch, loopback)
        {
            // One parser result supplies both the download reference and digest.
            // Claim reparses the exact source-fenced slot, never client metadata.
            let digest = crate::media::media_hash_from_reference(&reference)?;
            storage.request_automatic_acquisition(
                &demand.group_id_hex,
                &demand.entry,
                digest,
                now,
            )?;
        }
        storage.acknowledge_attachment_worker_demand(&demand)?;
    }
    Ok(more)
}

/// Admits a download of up to `max` body bytes under the app's
/// [`media_store::DiskPolicy`]: the reserve plus what
/// [`DiskPolicy::download_need`](media_store::DiskPolicy::download_need) says
/// the download still writes. A job with a checkpoint (`recorded` bytes) is
/// credited one more append ([`media_store::CHECKPOINT_APPEND_MAX`]): a crash
/// between an append and its record can leave that much on disk unrecorded,
/// and free space already excludes it. The attempt cuts any such tail off
/// before its own checks, which use the exact length; worker admission and
/// readmission both decide through this function.
fn capacity(
    policy: &storage_sqlite::AttachmentDownloadPolicy,
    max: u64,
    recorded: Option<u64>,
    free: u64,
) -> bool {
    let disk = media_store::DiskPolicy {
        reserve_bytes: policy.disk_reserve,
    };
    admissible_limit(max)
        && disk.admit(free, admission_need(max, recorded)) == media_store::Admission::Admitted
}

/// What a download of up to `max` body bytes may still write, crediting a
/// recorded checkpoint with one unrecorded append (see [`capacity`]).
fn admission_need(max: u64, recorded: Option<u64>) -> u64 {
    let on_disk = recorded.map_or(0, |recorded| {
        recorded.saturating_add(media_store::CHECKPOINT_APPEND_MAX as u64)
    });
    media_store::DiskPolicy::download_need(max, on_disk)
}

fn admissible_limit(max: u64) -> bool {
    max > 0 && max <= crate::media::MAX_ENCRYPTED_MEDIA_BLOB_BYTES
}

/// [`capacity`] for every parked job at once, as the one checkpoint
/// threshold readmission filters by before it limits its page: the inverse
/// of the same need rule, with the same unrecorded-append credit. The two
/// must agree for every recorded length (see the unit test).
fn readmit_admission(
    policy: &storage_sqlite::AttachmentDownloadPolicy,
    free: u64,
) -> storage_sqlite::ReadmitAdmission {
    let max = policy.transfer_limit;
    let needed = free
        .checked_sub(policy.disk_reserve)
        .filter(|_| admissible_limit(max))
        .and_then(|available| media_store::DiskPolicy::checkpoint_needed(max, available));
    match needed {
        Some(needed) => storage_sqlite::ReadmitAdmission {
            checkpointed_at_least: needed.saturating_sub(media_store::CHECKPOINT_APPEND_MAX as u64),
            uncheckpointed: needed == 0,
        },
        None => storage_sqlite::ReadmitAdmission::NONE,
    }
}

/// Complete one real storage observation before deciding whether work is cancelled.
async fn cancellation_observed(
    storage: &SqliteAccountStorage,
    job: &AttachmentAcquisition,
    permission: Option<&super::super::attachment_permission::PermissionLease>,
) -> bool {
    let store = storage.app_storage();
    let current = job.clone();
    let active = tokio::task::spawn_blocking(move || {
        Ok::<_, cgka_traits::StorageError>((
            store.attachment_transfer_is_active(&current, crate::unix_now_seconds())?,
            store.attachment_request_is_explicit(&current.reference)?,
        ))
    })
    .await;
    // Failure to observe is not cancellation. The transfer deadline and
    // publication fence still bound work while a storage read is unavailable.
    matches!(active, Ok(Ok((false, _))))
        || (permission.is_some_and(|p| !p.allowed()) && !matches!(active, Ok(Ok((_, true)))))
}

async fn cancelled(
    storage: SqliteAccountStorage,
    job: AttachmentAcquisition,
    mut updates: watch::Receiver<()>,
    permission: Option<super::super::attachment_permission::PermissionLease>,
) {
    loop {
        if cancellation_observed(&storage, &job, permission.as_ref()).await {
            return;
        }
        tokio::select! {
            _ = updates.changed()=>{},
            _ = tokio::time::sleep(Duration::from_secs(1))=>{},
        }
    }
}

fn retry_at(storage: &SqliteAppStorage, job: &AttachmentAcquisition, now: u64) -> u64 {
    let attempts = storage
        .attachment_acquisition_status(&job.reference)
        .ok()
        .flatten()
        .map_or(1, |s| s.attempts);
    now.saturating_add(
        15_u64
            .saturating_mul(1_u64 << attempts.saturating_sub(1).min(8))
            .min(3600),
    )
}

/// The scheduler's clock. Tests may pin it per account directory to cross
/// readmission backoffs without sleeping; transfers, leases and publication
/// keep wall time.
#[cfg_attr(not(test), allow(unused_variables))]
fn scheduler_now(client: &AppClient) -> u64 {
    let now = crate::unix_now_seconds();
    #[cfg(test)]
    let now = test_clock::adjust(&client.app.account_dir(&client.state.label), now);
    now
}

pub(super) fn schedule(
    client: &AppClient,
    shared: &RuntimeSharedServices,
    http: &MediaHttpContext,
    admission: &mut Admission,
) -> Result<bool, AppError> {
    // Release an acquired global permit on every early/error return.
    let held_permit = admission.permit.take();
    if client.app.config.cursor_persistence == crate::CursorPersistence::Frozen {
        admission.waiting = None;
        return Ok(false);
    }
    let storage = client.app.account_storage(&client.state.label)?;
    let now = scheduler_now(client);
    // Abandoned ciphertext expires even after automatic acquisition is disabled.
    let partials = storage.app_storage().prune_attachment_partials(now, 64)?;
    let orphan_uploads = storage
        .app_storage()
        .prune_attachment_uploads(now, 64)
        .unwrap_or_else(|_| {
            tracing::warn!(target: "marmot_app::runtime", method = "outgoing_retention_prune",
            "optional outgoing retention cleanup deferred");
            0
        });
    let policy = storage.app_storage().attachment_download_policy(
        &super::super::attachment_controls::default_policy(&client.app.config),
    )?;
    if !admission.resumed {
        if storage
            .app_storage()
            .resume_attachment_acquisitions(now, 64)?
            == 64
        {
            return Ok(true);
        }
        admission.resumed = true;
        // Private file-transfer snapshots cannot be deleted by RAII after a
        // crash; sweep stale ones once per worker ownership (bounded, local).
        crate::media::file_transfer::sweep_stale_media_staging(
            &crate::media::file_transfer::media_staging_directory(&client.app, &client.state.label),
        );
        // Handoff copies an earlier process lent out cannot be released any
        // more; this process's live leases are spared.
        let handoffs = crate::media::handoff::handoff_directory(&client.app, &client.state.label);
        tokio::task::spawn_blocking(move || crate::media::handoff::wipe_stale(&handoffs));
        // Reclaim whatever a crash left in the media store before new work.
        spawn_media_sweep(
            admission,
            &storage.app_storage(),
            client
                .app
                .account_media_store(&client.state.label, &storage)?,
            true,
            shared.observer.performance(),
        );
    } else {
        spawn_media_sweep(
            admission,
            &storage.app_storage(),
            client
                .app
                .account_media_store(&client.state.label, &storage)?,
            false,
            shared.observer.performance(),
        );
    }
    let expired = storage
        .app_storage()
        .prune_expired_attachment_acquisitions(now, 64)?;
    let host_managed = client.app.config.attachment_acquisition_mode
        == crate::AttachmentAcquisitionMode::HostManaged;
    let identity = storage.app_storage().attachment_store_identity()?;
    // Legacy uploads (bodies in SQLCipher) keep their own recovery until
    // they expire; file-backed ones promote through the media store.
    if storage
        .app_storage()
        .recover_attachment_uploads(now, 32, policy.retained_bytes)
        .is_err()
    {
        tracing::warn!(target: "marmot_app::runtime", method = "outgoing_retention_recovery",
            "optional outgoing retention recovery deferred");
    }
    spawn_upload_promotion(
        admission,
        storage.clone(),
        client
            .app
            .account_media_store(&client.state.label, &storage)?,
        shared.attachment_updates.clone(),
        shared.observer.performance(),
    );
    let resumed = if policy.automatic {
        storage.app_storage().resume_permitted_attachments(
            now,
            if host_managed {
                shared.attachment_permissions.categories(&identity)
            } else {
                [true; 4]
            },
        )?
    } else {
        0
    };
    let more = resumed == ATTACHMENT_ACQUISITION_BATCH_LIMIT
        || (policy.automatic
            && !host_managed
            && admit_demands(
                &storage.app_storage(),
                now,
                client.app.config.allow_loopback_blob_endpoints,
            )?)
        || expired == 64
        || partials == 64
        || orphan_uploads == 64;
    // Metadata and expiry maintenance continue when disk or network slots are full.
    // Admission never evicts an acquired asset and never increments attempts while paused.
    if http.permits.available_permits() <= 1 {
        admission.waiting = None;
        return Ok(more);
    }
    // Transfers already admitted, in any account, may not have written their
    // bodies yet: set aside what each reserved, so passes that run back to
    // back cannot all admit against the same free bytes. Readmission and
    // admission decide on this same figure.
    let reserved = shared
        .attachment_reserved_bytes
        .load(std::sync::atomic::Ordering::Acquire);
    let free = crate::media::attachment_resume::available_space(
        &client.app.account_dir(&client.state.label),
    )
    .ok()
    .map(|free| free.saturating_sub(reserved));
    // Jobs parked for disk space rejoin the due page only once the device can
    // publish them; their checkpoints make the readmitted attempt local work.
    // Unknown free space readmits nothing, as it admits nothing below.
    let readmitted = match free {
        Some(free) => storage.app_storage().readmit_storage_blocked_attachments(
            now,
            policy.disk_reserve,
            free,
            policy.automatic,
            readmit_admission(&policy, free),
        )?,
        None => 0,
    };
    if readmitted > 0 {
        // Parked jobs leave StorageBlocked.
        shared.attachment_updates.state_changed();
    }
    let more = more || readmitted == ATTACHMENT_ACQUISITION_BATCH_LIMIT;
    let free = free.unwrap_or(0);
    let candidates =
        storage
            .app_storage()
            .attachment_transfer_candidates(now, 32, policy.automatic)?;
    if candidates.is_empty() {
        admission.waiting = None;
        return Ok(more);
    }
    let Some(background_permit) = held_permit else {
        if admission.waiting.is_none() {
            admission.waiting = Some(Box::pin(shared.attachment_transfer.clone().acquire_owned()));
        }
        return Ok(more);
    };
    let Ok(permit) = http.permits.clone().try_acquire_owned() else {
        return Ok(more);
    };
    // Each pass starts one transfer. Once it is claimed (off the due page),
    // a later candidate asks the worker for another pass, which admits it
    // while global and HTTP capacity remain. A candidate that stays due must
    // not ask, or the next pass would select it again at once.
    let count = candidates.len();
    for (position, candidate) in candidates.into_iter().enumerate() {
        let started = more || position + 1 < count;
        let explicit = storage
            .app_storage()
            .attachment_request_is_explicit(&candidate)?;
        let max = if explicit {
            crate::MAX_FILE_MEDIA_CIPHERTEXT_BYTES
        } else {
            policy.transfer_limit
        };
        let Some(source) = storage
            .app_storage()
            .prepare_attachment_acquisition(&candidate, now)?
        else {
            continue;
        };
        let Some(reference) = reference(
            &source.slot,
            source.source_epoch,
            client.app.config.allow_loopback_blob_endpoints,
        ) else {
            storage
                .app_storage()
                .finish_attachment_preparation(&candidate, now, None)?;
            continue;
        };
        let permission = if host_managed && !explicit {
            let Some(lease) = shared
                .attachment_permissions
                .lease(&identity, &reference.media_type)
            else {
                storage
                    .app_storage()
                    .park_attachment_permission(&candidate)?;
                continue;
            };
            Some(lease)
        } else {
            None
        };
        let lease_until = now.saturating_add(if explicit {
            EXPLICIT_LEASE_SECONDS
        } else {
            LEASE_SECONDS
        });
        // Content another slot already retains needs no download: attach it
        // before the download-only gates (disk headroom for a new body,
        // source-key preparation) can defer or fail this job. The database
        // records the twin; the blocking task confirms its file is on disk.
        if storage
            .app_storage()
            .attachment_media_twin_recorded(&candidate)?
        {
            if permission.as_ref().is_some_and(|p| !p.allowed()) {
                continue;
            }
            if host_managed && !explicit {
                storage
                    .app_storage()
                    .enable_attachment_automatic_history(&candidate)?;
            }
            let Some(job) =
                storage
                    .app_storage()
                    .claim_attachment_acquisition(&candidate, now, lease_until)?
            else {
                continue;
            };
            let background_permit = TransferSlot {
                _permit: background_permit,
                _reserved: None,
            };
            let media = client
                .app
                .account_media_store(&client.state.label, &storage)?;
            let storage = storage.clone();
            let updates = shared.attachment_updates.clone();
            // Claimed: the row leaves Queued.
            updates.state_changed();
            spawn_media_http(
                http,
                permit,
                async move {
                    let attached = {
                        let job = job.clone();
                        tokio::task::spawn_blocking(move || {
                            attach_existing_body(&media, &storage.app_storage(), &job)
                        })
                    };
                    let result = if attached.await.unwrap_or(false) {
                        Ok(crate::client::AcquiredMediaBody::Retained)
                    } else {
                        // The recorded file was gone and is now marked lost:
                        // retry through the ordinary download path.
                        Err(AttachmentDownloadFailure::Retry(AppError::BlobStore(
                            "retained attachment copy unavailable".to_owned(),
                        )))
                    };
                    // The twin is attached (Ready) or the job retries.
                    updates.state_changed();
                    MediaHttpCompletion::Attachment {
                        job,
                        result,
                        background_permit,
                    }
                },
                |completion| completion,
            );
            return Ok(started);
        }
        // References do not declare a trustworthy size. Reserve the configured
        // automatic-sized object even for explicit work, then enforce actual
        // checkpoint/publication capacity as the transfer grows.
        let reservation = policy.transfer_limit;
        let recorded = storage
            .app_storage()
            .attachment_checkpoint_recorded(&candidate)?;
        if !capacity(&policy, reservation, recorded, free) {
            storage.app_storage().finish_attachment_preparation(
                &candidate,
                now,
                Some(now.saturating_add(15)),
            )?;
            continue;
        }
        // Free disk is the only gate (mdk#2314): retained media has no byte
        // budget, so a full budget can no longer stall downloads.
        let group = match hex::decode(&source.group_id_hex) {
            Ok(bytes) => GroupId::new(bytes),
            Err(_) => {
                storage
                    .app_storage()
                    .finish_attachment_preparation(&candidate, now, None)?;
                continue;
            }
        };
        let Some(ciphertext_digest) = hex::decode(&reference.ciphertext_sha256)
            .ok()
            .and_then(|v| v.try_into().ok())
        else {
            storage
                .app_storage()
                .finish_attachment_preparation(&candidate, now, None)?;
            continue;
        };
        // Queued explicit work (Retry, download again) derives a missing
        // source-epoch key from the retained anchor; automatic work reads only
        // what projection and sync cached.
        let message = Some(source.message_id_hex.as_str());
        let prepared = if explicit {
            client
                .cache_attachment_source_epoch_secret(&group, &source.message_id_hex, &reference)
                .and_then(|()| {
                    client.prepare_background_attachment_download_for_message(
                        &group, message, reference, max,
                    )
                })
        } else {
            client
                .prepare_background_attachment_download_for_message(&group, message, reference, max)
        };
        let prepared = match prepared {
            Ok(Some(prepared)) => prepared,
            // Local readiness is not a failed transfer. Defer only this candidate,
            // preserving siblings and their attempts. The deferral streak is
            // bounded: material that never arrives fails the job, not the loop.
            Ok(None) | Err(_) => {
                if storage
                    .app_storage()
                    .defer_attachment_preparation(&candidate, now)?
                {
                    tracing::warn!(
                        target: "marmot_app::runtime",
                        method = "attachment_acquisition",
                        "attachment decryption material stayed unavailable; acquisition failed"
                    );
                }
                return Ok(more);
            }
        };
        // A source change replaces the asset token. Claim rechecks the same
        // token/source after preparation, so stale prepared material cannot run.
        if permission.as_ref().is_some_and(|p| !p.allowed()) {
            continue;
        }
        if host_managed && !explicit {
            storage
                .app_storage()
                .enable_attachment_automatic_history(&candidate)?;
        }
        let Some(job) =
            storage
                .app_storage()
                .claim_attachment_acquisition(&candidate, now, lease_until)?
        else {
            continue;
        };
        let background_permit = TransferSlot {
            _permit: background_permit,
            _reserved: Some(DiskReservation::new(
                &shared.attachment_reserved_bytes,
                admission_need(reservation, recorded),
            )),
        };
        let media = client
            .app
            .account_media_store(&client.state.label, &storage)?;
        let resume = crate::media::attachment_resume::AttachmentResume {
            explicit_permission: Default::default(),
            storage: storage.clone(),
            job: job.clone(),
            ciphertext_digest,
            media: media.clone(),
            directory: client.app.account_dir(&client.state.label),
            policy: policy.clone(),
            automatic: !explicit,
            permission: permission.clone(),
            finishing: Default::default(),
            updates: Some(shared.attachment_updates.clone()),
        };
        let cancel = cancelled(
            storage.clone(),
            job.clone(),
            shared.attachment_cancellations.subscribe(),
            permission,
        );
        let updates = shared.attachment_updates.clone();
        // Claimed: the row leaves Queued.
        updates.state_changed();
        spawn_media_http(
            http,
            permit,
            async move {
                let finishing = resume.finishing.clone();
                // Identical content already in the store is attached without
                // downloading; the check runs on the blocking pool.
                let reuse = {
                    let (media, storage, job) = (media, storage.clone(), job.clone());
                    tokio::task::spawn_blocking(move || {
                        attach_existing_body(&media, &storage.app_storage(), &job)
                    })
                };
                let result = if reuse.await.unwrap_or(false) {
                    Ok(crate::client::AcquiredMediaBody::Retained)
                } else {
                    finish_or_cancel(prepared.run_acquisition(resume), cancel, finishing).await
                };
                // The attempt ended, with or without a body.
                updates.state_changed();
                MediaHttpCompletion::Attachment {
                    job,
                    result,
                    background_permit,
                }
            },
            |completion| completion,
        );
        return Ok(started);
    }
    Ok(more)
}

/// Prefer a finished result over cancellation. Once verification starts its
/// receipt, let that finite local step return the body to the publication owner.
async fn finish_or_cancel<F, C, T>(
    download: F,
    cancel: C,
    finishing: Arc<std::sync::atomic::AtomicBool>,
) -> Result<T, AttachmentDownloadFailure>
where
    F: std::future::Future<Output = Result<T, AttachmentDownloadFailure>>,
    C: std::future::Future<Output = ()>,
{
    tokio::pin!(download);
    tokio::select! {
        biased;
        result = &mut download => result,
        _ = cancel => {
            if finishing.load(std::sync::atomic::Ordering::Acquire) {
                download.await
            } else {
                Err(AttachmentDownloadFailure::Retry(AppError::BlobStore("attachment transfer cancelled".to_owned())))
            }
        },
    }
}

/// Whether `job` was completed from a ready media file with the same content
/// (or no longer needs a body). Blocking.
fn attach_existing_body(
    media: &AccountMediaStore,
    storage: &SqliteAppStorage,
    job: &AttachmentAcquisition,
) -> bool {
    let Ok(digest) = job.plaintext_digest() else {
        return false;
    };
    let clock = crate::unix_now_seconds;
    matches!(
        media.attach_existing(
            &storage.attachment_publication(job, &clock),
            Category::Retained,
            &digest,
        ),
        Ok(Some(_))
    )
}

/// Finishes a job inline. Blocking when it carries a body: production only
/// calls it with failures and runs bodies through `complete_acquired_stored`
/// on the blocking pool.
pub(super) fn complete_acquired(
    client: &AppClient,
    job: &AttachmentAcquisition,
    result: Result<crate::client::AcquiredMediaBody, AttachmentDownloadFailure>,
) -> Result<(), AppError> {
    let storage = client.app.account_storage(&client.state.label)?;
    let media = client
        .app
        .account_media_store(&client.state.label, &storage)?;
    let fallback = super::super::attachment_controls::default_policy(&client.app.config);
    complete_acquired_stored(
        &storage,
        &media,
        &fallback,
        &client.app.account_dir(&client.state.label),
        job,
        result,
        &|| false,
    )
}

/// Headroom a job records when the disk filled while publishing a
/// `plaintext`-byte body. The target is the `required` space a retried
/// attempt needs beyond the reserve in the worker's frame, but never less
/// than the free space measured at the refusal plus one more body:
/// readmission then waits until the volume has actually gained room, rather
/// than refetching onto the same full disk whenever free space looked
/// sufficient. `held` is staging this attempt still occupies at the
/// measurement, which the worker frame does not.
fn full_disk_headroom(
    directory: &std::path::Path,
    policy: &storage_sqlite::AttachmentDownloadPolicy,
    plaintext: u64,
    required: u64,
    held: u64,
) -> u64 {
    match crate::media::attachment_resume::available_space(directory) {
        Ok(free) => required.max(
            free.saturating_add(held)
                .saturating_sub(policy.disk_reserve)
                .saturating_add(plaintext),
        ),
        Err(_) => required,
    }
}

/// Publishes a downloaded body into the media store and records the job's
/// outcome. Blocking: run it on the blocking pool.
#[allow(clippy::too_many_arguments)]
pub(super) fn complete_acquired_stored(
    storage: &SqliteAccountStorage,
    media: &AccountMediaStore,
    fallback: &storage_sqlite::AttachmentDownloadPolicy,
    directory: &std::path::Path,
    job: &AttachmentAcquisition,
    result: Result<crate::client::AcquiredMediaBody, AttachmentDownloadFailure>,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), AppError> {
    let app = storage.app_storage();
    let now = crate::unix_now_seconds();
    let body = match result {
        Ok(crate::client::AcquiredMediaBody::Retained) => return Ok(()),
        Ok(body) => body,
        Err(AttachmentDownloadFailure::Retry(_)) => {
            app.fail_attachment_acquisition(job, Some(retry_at(&app, job, now)))?;
            return Ok(());
        }
        Err(AttachmentDownloadFailure::SizeLimit(_, limit)) => {
            app.block_attachment_size_policy(job, limit, now)?;
            return Ok(());
        }
        // Disk, not the network, is the blocker: park with the checkpoint until
        // free space covers the reserve or the user retries, never on a timer.
        Err(AttachmentDownloadFailure::StorageBlocked { headroom }) => {
            app.block_attachment_storage(job, headroom, now)?;
            return Ok(());
        }
        Err(AttachmentDownloadFailure::Stop(_) | AttachmentDownloadFailure::FileRequired) => {
            app.fail_attachment_acquisition(job, None)?;
            return Ok(());
        }
    };
    let policy = app.attachment_download_policy(fallback)?;
    let digest = job.plaintext_digest()?;
    let clock = crate::unix_now_seconds;
    let target = app.attachment_publication(job, &clock);
    // A retried attempt of either sink needs its store file and whatever of
    // its ciphertext is not checkpointed: the checkpoint stays on disk, a
    // file body's staging does not. That staging is held until the headroom
    // is measured below.
    let saved = app
        .attachment_checkpoint_recorded(&job.reference)
        .ok()
        .flatten()
        .unwrap_or(0);
    let (published, len, held, staged) = match body {
        crate::client::AcquiredMediaBody::File(mut file) => {
            let len = file.plaintext_len;
            let published = match file.plaintext_reader() {
                Ok(mut reader) => media.publish(
                    &target,
                    Category::Retained,
                    &mut reader,
                    len,
                    digest,
                    now,
                    cancelled,
                ),
                Err(_) => Err(MediaError::Io(std::io::ErrorKind::InvalidData)),
            };
            let held = file.ciphertext.staged_bytes();
            (published, len, held, Some(file))
        }
        crate::client::AcquiredMediaBody::Memory(result) => {
            let plaintext = zeroize::Zeroizing::new(result.plaintext);
            let len = plaintext.len() as u64;
            let published = media.publish(
                &target,
                Category::Retained,
                &mut std::io::Cursor::new(&plaintext[..]),
                len,
                digest,
                now,
                cancelled,
            );
            (published, len, 0, None)
        }
        crate::client::AcquiredMediaBody::Retained => return Ok(()),
    };
    match published {
        // Published, reused or superseded: the store and the job agree.
        Ok(_) => {}
        Err(MediaError::InvalidBody(_)) => {
            app.fail_attachment_acquisition(job, None)?;
        }
        // The disk (or database) is full: park, never retry on a timer.
        Err(MediaError::Capacity) => {
            let required = media_store::DiskPolicy::download_need(len, saved);
            let headroom = full_disk_headroom(directory, &policy, len, required, held);
            app.block_attachment_storage(job, headroom, now)?;
        }
        // Shutting down: the durable lease lets the next worker resume it.
        Err(MediaError::Closed) => {}
        Err(_) => {
            app.fail_attachment_acquisition(job, Some(retry_at(&app, job, now)))?;
        }
    }
    // Only now, with the job's outcome recorded: a published job's wire file
    // goes (its row went with the publication), staging is deleted.
    if let Some(file) = staged {
        file.ciphertext.finish();
    }
    Ok(())
}

#[cfg(test)]
fn complete(
    client: &AppClient,
    job: &AttachmentAcquisition,
    result: Result<MediaDownloadResult, AttachmentDownloadFailure>,
) -> Result<(), AppError> {
    complete_acquired(
        client,
        job,
        result.map(crate::client::AcquiredMediaBody::Memory),
    )
}

/// Per-account-directory pinned scheduler clocks for tests, read by
/// [`scheduler_now`].
#[cfg(test)]
pub(super) mod test_clock {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    static CLOCKS: Mutex<BTreeMap<PathBuf, u64>> = Mutex::new(BTreeMap::new());

    /// Pin the scheduler for `root` and everything beneath it at `at`, so due
    /// times compare exactly.
    pub(crate) fn set_now(root: &Path, at: u64) {
        CLOCKS.lock().unwrap().insert(root.to_path_buf(), at);
    }
    /// Return `root` to wall time.
    pub(crate) fn clear(root: &Path) {
        CLOCKS.lock().unwrap().remove(root);
    }
    /// The scheduler's reading for `path` when wall time is `now`.
    pub(super) fn adjust(path: &Path, now: u64) -> u64 {
        CLOCKS
            .lock()
            .unwrap()
            .iter()
            .find(|(root, _)| path.starts_with(root))
            .map_or(now, |(_, at)| *at)
    }
}

#[cfg(test)]
mod tests;
