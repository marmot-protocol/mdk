//! Durable automatic acquisition. Parsing and admission run under the
//! account worker; HTTP/crypto use the existing cancellable media executor.
//! Bodies are retained in the account's encrypted media store (mdk#2314),
//! whose blocking file I/O, hashing and AEAD always run on the blocking pool.
use super::*;
use crate::AccountMediaStore;
use crate::media::AttachmentDownloadFailure;
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

type PermitWait = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<OwnedSemaphorePermit, tokio::sync::AcquireError>>
            + Send,
    >,
>;

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
    upload_promotion: Option<tokio::task::JoinHandle<()>>,
    upload_cursor: Arc<std::sync::Mutex<Option<storage_sqlite::AttachmentUploadOwner>>>,
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
}

/// Starts a media sweep on the blocking pool unless one is still running:
/// to completion when the worker takes ownership, otherwise one batch.
fn spawn_media_sweep(admission: &mut Admission, media: AccountMediaStore, until_complete: bool) {
    if admission
        .media_sweep
        .as_ref()
        .is_some_and(|task| !task.is_finished())
    {
        return;
    }
    admission.media_sweep = Some(tokio::task::spawn_blocking(move || {
        loop {
            match media.sweep(MEDIA_SWEEP_BATCH) {
                Ok(report) if until_complete && !report.complete => {}
                Ok(_) => break,
                Err(_) => {
                    tracing::warn!(target: "marmot_app::runtime", method = "media_sweep",
                        "media store sweep deferred");
                    break;
                }
            }
        }
    }));
}
/// Starts one page of outgoing upload promotion on the blocking pool unless
/// one is still running. Each run resumes after the last, so uploads that
/// cannot promote yet never starve the rest; a promotion wakes attachment
/// observers.
fn spawn_upload_promotion(
    admission: &mut Admission,
    storage: SqliteAccountStorage,
    media: AccountMediaStore,
    updates: tokio::sync::watch::Sender<()>,
) {
    if admission
        .upload_promotion
        .as_ref()
        .is_some_and(|task| !task.is_finished())
    {
        return;
    }
    let cursor = admission.upload_cursor.clone();
    admission.upload_promotion = Some(tokio::task::spawn_blocking(move || {
        let after = cursor
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        match crate::media::outgoing::promote_uploads(
            &storage.app_storage(),
            &media,
            after.as_ref(),
            crate::media::outgoing::UPLOAD_PROMOTION_BATCH,
        ) {
            Ok((next, promoted)) => {
                *cursor
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = next;
                if promoted {
                    updates.send_modify(|_| {});
                }
            }
            Err(_) => {
                tracing::warn!(target: "marmot_app::runtime", method = "outgoing_upload_promotion",
                    "outgoing upload promotion deferred");
            }
        }
    }));
}

/// Starts one batch of moving legacy database bodies into the media store
/// (mdk#2314 step 6) on the blocking pool, unless one is still running, and
/// then returns freed database pages to the filesystem once the database is
/// incremental. The account worker calls this once per maintenance tick,
/// after readiness. A batch that pauses for free space, resumes, finishes,
/// or drops a corrupt body wakes attachment observers. At worker start and
/// then hourly, the batch first applies the "Keep media" setting (mdk#2314
/// step 10) for up to [`KEEP_MEDIA_SWEEP_BUDGET`].
pub(super) fn spawn_legacy_migration(
    client: &AppClient,
    shared: &RuntimeSharedServices,
    admission: &mut Admission,
) {
    if client.app.config.cursor_persistence == crate::CursorPersistence::Frozen
        || admission
            .legacy_migration
            .as_ref()
            .is_some_and(|task| !task.is_finished())
    {
        return;
    }
    let app = client.app.clone();
    let label = client.state.label.clone();
    let updates = shared.attachment_updates.clone();
    let startup_wal_settled = admission.startup_wal_settled.clone();
    let compaction_due = admission.compaction_due.clone();
    let check_compaction = !admission.compaction_attempted;
    let now = std::time::Instant::now();
    let sweep_keep_media = admission
        .keep_media_more
        .swap(false, std::sync::atomic::Ordering::AcqRel)
        || admission.keep_media_due.is_none_or(|due| now >= due);
    if sweep_keep_media {
        admission.keep_media_due = Some(now + KEEP_MEDIA_SWEEP_INTERVAL);
    }
    let keep_media_more = admission.keep_media_more.clone();
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
                keep_media_more.store(true, std::sync::atomic::Ordering::Release);
            }
            tracing::warn!(target: "marmot_app::storage_maintenance",
                method = "migrate_legacy_attachments",
                "legacy attachment migration batch deferred");
            return;
        };
        let account_dir = app.account_dir(&label);
        let free = || crate::media::attachment_resume::available_space(&account_dir);
        let progress = app.legacy_media_migration(&label);
        let app_storage = storage.app_storage();
        // "Keep media" first, so bodies past the window are not moved only
        // to be removed.
        if sweep_keep_media {
            let deadline = std::time::Instant::now() + KEEP_MEDIA_SWEEP_BUDGET;
            match super::super::attachment_storage::clean_past_keep_window(
                &app_storage,
                &media,
                Some(deadline),
            ) {
                Ok((removed, more)) => {
                    if more {
                        keep_media_more.store(true, std::sync::atomic::Ordering::Release);
                    }
                    if removed > 0 {
                        tracing::info!(target: "marmot_app::storage_maintenance",
                            method = "keep_media_sweep", removed, more,
                            "attachments past the keep media window removed");
                        updates.send_modify(|_| {});
                    }
                }
                Err(_) => {
                    keep_media_more.store(true, std::sync::atomic::Ordering::Release);
                    tracing::warn!(target: "marmot_app::storage_maintenance",
                        method = "keep_media_sweep",
                        "keep media sweep deferred");
                }
            }
        }
        let changed = crate::media::legacy_migration::run_batch(
            &app_storage,
            &media,
            reserve,
            &free,
            &progress,
        );
        if changed {
            updates.send_modify(|_| {});
        }
        // Then images still held in the database move into cache files
        // (mdk#2314 step 9), so compaction can return their pages.
        if crate::media::avatar_files::run_batch(&app_storage, &media, reserve, &free) {
            app.presentation_signals.wake();
            let _ = app.presentation_signals.avatars.send(label.clone());
        }
        let startup = !startup_wal_settled.load(std::sync::atomic::Ordering::Acquire);
        if crate::media::storage_compaction::reclaim(&app_storage, startup) && startup {
            startup_wal_settled.store(true, std::sync::atomic::Ordering::Release);
        }
        if check_compaction
            && crate::media::storage_compaction::compaction_check(
                &app_storage,
                reserve,
                &free,
                &progress,
            )
            .is_some()
        {
            compaction_due.store(true, std::sync::atomic::Ordering::Release);
        }
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
            &|| updates.send_modify(|_| {}),
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
            }
            CompactionAttempt::NotDue => {}
        }
    }

    pub(super) fn is_waiting(&self) -> bool {
        self.waiting.is_some()
    }
    pub(super) async fn ready(&mut self) {
        if let Some(waiting) = self.waiting.as_mut() {
            self.permit = waiting.await.ok();
            self.waiting = None;
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
    let on_disk = recorded.map_or(0, |recorded| {
        recorded.saturating_add(media_store::CHECKPOINT_APPEND_MAX as u64)
    });
    let needed = media_store::DiskPolicy::download_need(max, on_disk);
    admissible_limit(max) && disk.admit(free, needed) == media_store::Admission::Admitted
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

async fn cancelled(
    storage: SqliteAccountStorage,
    job: AttachmentAcquisition,
    mut updates: watch::Receiver<()>,
    permission: Option<super::super::attachment_permission::PermissionLease>,
) {
    loop {
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
        if matches!(active, Ok(Ok((false, _))))
            || (permission.as_ref().is_some_and(|p| !p.allowed())
                && !matches!(active, Ok(Ok((_, true)))))
        {
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
            client
                .app
                .account_media_store(&client.state.label, &storage)?,
            true,
        );
    } else {
        spawn_media_sweep(
            admission,
            client
                .app
                .account_media_store(&client.state.label, &storage)?,
            false,
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
    let free = crate::media::attachment_resume::available_space(
        &client.app.account_dir(&client.state.label),
    )
    .ok();
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
        shared.attachment_updates.send_modify(|_| {});
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
    for candidate in candidates {
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
            let media = client
                .app
                .account_media_store(&client.state.label, &storage)?;
            let storage = storage.clone();
            let updates = shared.attachment_updates.clone();
            updates.send_modify(|_| {});
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
                    updates.send_modify(|_| {});
                    MediaHttpCompletion::Attachment {
                        job,
                        result,
                        background_permit,
                    }
                },
                |completion| completion,
            );
            return Ok(more);
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
        let prepared = if explicit {
            client
                .cache_attachment_source_epoch_secret(&group, &reference)
                .and_then(|()| {
                    client.prepare_background_attachment_download(&group, reference, max)
                })
        } else {
            client.prepare_background_attachment_download(&group, reference, max)
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
        updates.send_modify(|_| {});
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
                updates.send_modify(|_| {});
                MediaHttpCompletion::Attachment {
                    job,
                    result,
                    background_permit,
                }
            },
            |completion| completion,
        );
        return Ok(more);
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
