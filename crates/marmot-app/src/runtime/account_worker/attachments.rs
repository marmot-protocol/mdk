//! Durable automatic acquisition. Parsing/admission and publication run under
//! the account worker; HTTP/crypto use the existing cancellable media executor.
use super::*;
use crate::media::AttachmentDownloadFailure;
use storage_sqlite::{
    ATTACHMENT_ACQUISITION_BATCH_LIMIT, AttachmentAcquisition, AttachmentPublishResult,
    SqliteAccountStorage,
};

const DEMAND_BATCH: usize = 32;
// Background HTTP has a two-minute whole-transfer deadline. Leave publication margin.
const LEASE_SECONDS: u64 = 3 * 60;
const EXPLICIT_LEASE_SECONDS: u64 = 20 * 60;

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
}
impl Admission {
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

fn admit_demands(
    storage: &SqliteAccountStorage,
    now: u64,
    loopback: bool,
) -> Result<bool, AppError> {
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
            storage.request_attachment_acquisition(
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

fn capacity(policy: &storage_sqlite::AttachmentDownloadPolicy, max: u64, free: u64) -> bool {
    max > 0
        && max <= crate::media::MAX_ENCRYPTED_MEDIA_BLOB_BYTES
        && free >= policy.disk_reserve.saturating_add(max.saturating_mul(4))
}

async fn cancelled(
    storage: SqliteAccountStorage,
    job: AttachmentAcquisition,
    mut updates: watch::Receiver<()>,
    permission: Option<super::super::attachment_permission::PermissionLease>,
) {
    loop {
        let store = storage.clone();
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

fn retry_at(storage: &SqliteAccountStorage, job: &AttachmentAcquisition, now: u64) -> u64 {
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
    let partials = storage.prune_attachment_partials(now, 64)?;
    let orphan_uploads = storage
        .prune_attachment_uploads(now, 64)
        .unwrap_or_else(|_| {
            tracing::warn!(target: "marmot_app::runtime", method = "outgoing_retention_prune",
            "optional outgoing retention cleanup deferred");
            0
        });
    let policy = storage.attachment_download_policy(
        &super::super::attachment_controls::default_policy(&client.app.config),
    )?;
    if !admission.resumed {
        if storage.resume_attachment_acquisitions(now, 64)? == 64 {
            return Ok(true);
        }
        admission.resumed = true;
        // Private file-transfer snapshots cannot be deleted by RAII after a
        // crash; sweep stale ones once per worker ownership (bounded, local).
        crate::media::file_transfer::sweep_stale_media_staging(
            &crate::media::file_transfer::media_staging_directory(&client.app, &client.state.label),
        );
    }
    let expired = storage.prune_expired_attachment_acquisitions(now, 64)?;
    let host_managed = client.app.config.attachment_acquisition_mode
        == crate::AttachmentAcquisitionMode::HostManaged;
    let identity = storage.attachment_store_identity()?;
    if storage
        .recover_attachment_uploads(now, 32, policy.retained_bytes)
        .is_err()
    {
        tracing::warn!(target: "marmot_app::runtime", method = "outgoing_retention_recovery",
            "optional outgoing retention recovery deferred");
    }
    let resumed = if policy.automatic {
        storage.resume_permitted_attachments(
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
                &storage,
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
        Some(free) => storage.readmit_storage_blocked_attachments(
            now,
            policy.disk_reserve,
            free,
            policy.transfer_limit,
            policy.automatic,
        )?,
        None => 0,
    };
    if readmitted > 0 {
        shared.attachment_updates.send_modify(|_| {});
    }
    let more = more || readmitted == ATTACHMENT_ACQUISITION_BATCH_LIMIT;
    let free = free.unwrap_or(0);
    let candidates = storage.attachment_transfer_candidates(now, 32, policy.automatic)?;
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
        let explicit = storage.attachment_request_is_explicit(&candidate)?;
        let max = if explicit {
            crate::MAX_FILE_MEDIA_CIPHERTEXT_BYTES
        } else {
            policy.transfer_limit
        };
        let Some(source) = storage.prepare_attachment_acquisition(&candidate, now)? else {
            continue;
        };
        let Some(reference) = reference(
            &source.slot,
            source.source_epoch,
            client.app.config.allow_loopback_blob_endpoints,
        ) else {
            storage.finish_attachment_preparation(&candidate, now, None)?;
            continue;
        };
        let permission = if host_managed && !explicit {
            let Some(lease) = shared
                .attachment_permissions
                .lease(&identity, &reference.media_type)
            else {
                storage.park_attachment_permission(&candidate)?;
                continue;
            };
            Some(lease)
        } else {
            None
        };
        // References do not declare a trustworthy size. Reserve the configured
        // automatic-sized object even for explicit work, then enforce actual
        // checkpoint/publication capacity as the transfer grows.
        let reservation = policy.transfer_limit;
        if !capacity(&policy, reservation, free) {
            storage.finish_attachment_preparation(&candidate, now, Some(now.saturating_add(15)))?;
            continue;
        }
        if !storage.attachment_acquisition_fits_budget(
            &candidate,
            reservation,
            policy.retained_bytes,
        )? {
            // Defer without spending an attempt. This also lets reserved prefixes
            // beyond the bounded candidate page reach the worker under pressure.
            storage.finish_attachment_preparation(&candidate, now, Some(now.saturating_add(15)))?;
            continue;
        }
        let group = match hex::decode(&source.group_id_hex) {
            Ok(bytes) => GroupId::new(bytes),
            Err(_) => {
                storage.finish_attachment_preparation(&candidate, now, None)?;
                continue;
            }
        };
        let Some(ciphertext_digest) = hex::decode(&reference.ciphertext_sha256)
            .ok()
            .and_then(|v| v.try_into().ok())
        else {
            storage.finish_attachment_preparation(&candidate, now, None)?;
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
                if storage.defer_attachment_preparation(&candidate, now)? {
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
            storage.enable_attachment_automatic_history(&candidate)?;
        }
        let Some(job) = storage.claim_attachment_acquisition(
            &candidate,
            now,
            now.saturating_add(if explicit {
                EXPLICIT_LEASE_SECONDS
            } else {
                LEASE_SECONDS
            }),
        )?
        else {
            continue;
        };
        let byte_budget = policy.retained_bytes;
        let resume = crate::media::attachment_resume::AttachmentResume {
            explicit_permission: Default::default(),
            storage: storage.clone(),
            job: job.clone(),
            ciphertext_digest,
            budget: byte_budget,
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
                let result =
                    finish_or_cancel(prepared.run_acquisition(resume), cancel, finishing).await;
                updates.send_modify(|_| {});
                MediaHttpCompletion::Attachment {
                    job,
                    result,
                    byte_budget,
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

pub(super) fn complete_acquired(
    client: &AppClient,
    job: &AttachmentAcquisition,
    result: Result<crate::client::AcquiredMediaBody, AttachmentDownloadFailure>,
    byte_budget: u64,
) -> Result<(), AppError> {
    let storage = client.app.account_storage(&client.state.label)?;
    let fallback = super::super::attachment_controls::default_policy(&client.app.config);
    complete_acquired_stored(
        &storage,
        &fallback,
        &client.app.account_dir(&client.state.label),
        job,
        result,
        byte_budget,
        &|| false,
    )
}

/// Headroom a job records when the database reports it is full while
/// publishing a `plaintext`-byte body. The disk itself is the likely cause, so
/// the target is the publication reserve a retried attempt needs in the
/// worker's frame (`multiple` bodies), but never less than the free space
/// measured at the refusal plus one more body: readmission then waits until
/// the volume has actually gained room, rather than refetching into the same
/// full database whenever free space looked sufficient. `held` is staging this
/// attempt still occupies at the measurement, which the worker frame does not.
fn full_database_headroom(
    directory: &std::path::Path,
    policy: &storage_sqlite::AttachmentDownloadPolicy,
    plaintext: u64,
    multiple: u64,
    held: u64,
) -> u64 {
    let required = plaintext.saturating_mul(multiple);
    match crate::media::attachment_resume::available_space(directory) {
        Ok(free) => required.max(
            free.saturating_add(held)
                .saturating_sub(policy.disk_reserve)
                .saturating_add(plaintext),
        ),
        Err(_) => required,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn complete_acquired_stored(
    storage: &SqliteAccountStorage,
    fallback: &storage_sqlite::AttachmentDownloadPolicy,
    directory: &std::path::Path,
    job: &AttachmentAcquisition,
    result: Result<crate::client::AcquiredMediaBody, AttachmentDownloadFailure>,
    byte_budget: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), AppError> {
    let now = crate::unix_now_seconds();
    match result {
        Ok(crate::client::AcquiredMediaBody::File(file)) => {
            let policy = storage.attachment_download_policy(fallback)?;
            let mut reader = file.reader()?;
            match storage.complete_attachment_acquisition_from_reader_with_clock(
                job,
                &mut reader,
                file.len,
                &crate::unix_now_seconds,
                byte_budget.min(policy.retained_bytes),
                cancelled,
            ) {
                Ok(AttachmentPublishResult::Published | AttachmentPublishResult::Superseded) => {}
                Err(cgka_traits::StorageError::InvalidAttachmentBody(_)) => {
                    storage.fail_attachment_acquisition(job, None)?;
                }
                // The database itself ran out of room: park, never retry on a
                // timer. A retried file attempt stages the body again before
                // publishing it, so it needs five bodies; the decrypted file
                // this attempt still holds is released before the worker looks.
                Err(cgka_traits::StorageError::Capacity(_)) => {
                    let headroom =
                        full_database_headroom(directory, &policy, file.len, 5, file.len);
                    storage.block_attachment_storage(job, headroom, now)?;
                }
                _ => {
                    storage.fail_attachment_acquisition(job, Some(retry_at(storage, job, now)))?;
                }
            }
        }
        Ok(crate::client::AcquiredMediaBody::Memory(result)) => {
            let plaintext = zeroize::Zeroizing::new(result.plaintext);
            if job.verify_plaintext(&plaintext).is_err() {
                storage.fail_attachment_acquisition(job, None)?;
                return Ok(());
            }
            let policy = storage.attachment_download_policy(fallback)?;
            let byte_budget = byte_budget.min(policy.retained_bytes);
            match storage.complete_attachment_acquisition(job, &plaintext, now, byte_budget) {
                Ok(AttachmentPublishResult::Published | AttachmentPublishResult::Superseded) => {}
                // A full database parks like a failed free-space check would;
                // the in-memory sink holds no staging on disk.
                Err(cgka_traits::StorageError::Capacity(_)) => {
                    let headroom =
                        full_database_headroom(directory, &policy, plaintext.len() as u64, 4, 0);
                    storage.block_attachment_storage(job, headroom, now)?;
                }
                Ok(AttachmentPublishResult::CapacityBlocked) | Err(_) => {
                    storage.fail_attachment_acquisition(job, Some(retry_at(storage, job, now)))?;
                }
            }
        }
        Err(AttachmentDownloadFailure::Retry(_)) => {
            storage.fail_attachment_acquisition(job, Some(retry_at(storage, job, now)))?;
        }
        Err(AttachmentDownloadFailure::SizeLimit(_, limit)) => {
            storage.block_attachment_size_policy(job, limit, now)?;
        }
        // Disk, not the network, is the blocker: park with the checkpoint until
        // free space covers the reserve or the user retries, never on a timer.
        Err(AttachmentDownloadFailure::StorageBlocked { headroom }) => {
            storage.block_attachment_storage(job, headroom, now)?;
        }
        Err(AttachmentDownloadFailure::Stop(_)) => {
            storage.fail_attachment_acquisition(job, None)?;
        }
        Err(AttachmentDownloadFailure::FileRequired) => {
            storage.fail_attachment_acquisition(job, None)?;
        }
    }
    Ok(())
}

#[cfg(test)]
fn complete(
    client: &AppClient,
    job: &AttachmentAcquisition,
    result: Result<MediaDownloadResult, AttachmentDownloadFailure>,
    byte_budget: u64,
) -> Result<(), AppError> {
    complete_acquired(
        client,
        job,
        result.map(crate::client::AcquiredMediaBody::Memory),
        byte_budget,
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
