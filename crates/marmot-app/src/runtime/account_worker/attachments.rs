//! Durable automatic acquisition. Parsing/admission and publication run under
//! the account worker; HTTP/crypto use the existing cancellable media executor.
use super::*;
use crate::media::AttachmentDownloadFailure;
use storage_sqlite::{AttachmentAcquisition, AttachmentPublishResult, SqliteAccountStorage};

const DEMAND_BATCH: usize = 32;
// Shared HTTP has a 15 minute whole-transfer deadline. Leave publication margin.
const LEASE_SECONDS: u64 = 20 * 60;

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

fn capacity(policy: &crate::AttachmentAcquisitionPolicy, free: u64) -> bool {
    let max = policy.maximum_transfer_bytes;
    max > 0 && max <= crate::media::MAX_ENCRYPTED_MEDIA_BLOB_BYTES
        // Conservative full-object reservation for SQLite pages, journal and WAL.
        && free >= policy.minimum_free_disk_bytes.saturating_add(max.saturating_mul(4))
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
    let now = crate::unix_now_seconds();
    // Abandoned ciphertext expires even after automatic acquisition is disabled.
    let partials = storage.prune_attachment_partials(now, 64)?;
    let Some(policy) = &client.app.config.attachment_acquisition else {
        admission.waiting = None;
        return Ok(partials == 64);
    };
    if !admission.resumed {
        if storage.resume_attachment_acquisitions(now, 64)? == 64 {
            return Ok(true);
        }
        admission.resumed = true;
    }
    let expired = storage.prune_expired_attachment_acquisitions(now, 64)?;
    let more = admit_demands(
        &storage,
        now,
        client.app.config.allow_loopback_blob_endpoints,
    )? || expired == 64
        || partials == 64;
    // Metadata and expiry maintenance continue when disk or network slots are full.
    // Admission never evicts an acquired asset and never increments attempts while paused.
    if http.permits.available_permits() <= 1 {
        admission.waiting = None;
        return Ok(more);
    }
    let free = fs4::available_space(client.app.account_dir(&client.state.label)).unwrap_or(0);
    if !capacity(policy, free) {
        admission.waiting = None;
        return Ok(more);
    }
    let candidates = storage.due_attachment_acquisitions(now, 32)?;
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
        if !storage.attachment_acquisition_fits_budget(
            &candidate,
            policy.maximum_transfer_bytes,
            policy.retained_bytes_per_account,
        )? {
            // Defer without spending an attempt. This also lets reserved prefixes
            // beyond the bounded candidate page reach the worker under pressure.
            storage.finish_attachment_preparation(&candidate, now, Some(now.saturating_add(15)))?;
            continue;
        }
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
        let group = match hex::decode(&source.group_id_hex) {
            Ok(bytes) => GroupId::new(bytes),
            Err(_) => {
                storage.finish_attachment_preparation(&candidate, now, None)?;
                continue;
            }
        };
        let ciphertext_digest = hex::decode(&reference.ciphertext_sha256)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| AppError::InvalidEncryptedMedia("invalid ciphertext digest".into()))?;
        let prepared = match client.prepare_background_attachment_download(
            &group,
            reference,
            policy.maximum_transfer_bytes,
        ) {
            Ok(Some(prepared)) => prepared,
            // Local readiness is not a failed transfer. Defer only this candidate
            // for one maintenance tick, preserving siblings and their attempts.
            Ok(None) | Err(_) => {
                storage.finish_attachment_preparation(
                    &candidate,
                    now,
                    Some(now.saturating_add(15)),
                )?;
                return Ok(more);
            }
        };
        // A source change replaces the asset token. Claim rechecks the same
        // token/source after preparation, so stale prepared material cannot run.
        let Some(job) = storage.claim_attachment_acquisition(
            &candidate,
            now,
            now.saturating_add(LEASE_SECONDS),
        )?
        else {
            continue;
        };
        let byte_budget = policy.retained_bytes_per_account;
        let resume = crate::media::attachment_resume::AttachmentResume {
            storage: storage.clone(),
            job: job.clone(),
            ciphertext_digest,
            budget: byte_budget,
            directory: client.app.account_dir(&client.state.label),
            disk_reserve: policy.minimum_free_disk_bytes,
        };
        spawn_media_http(
            http,
            permit,
            async move {
                let result = prepared.run_classified(resume).await;
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

pub(super) fn complete(
    client: &AppClient,
    job: &AttachmentAcquisition,
    result: Result<MediaDownloadResult, AttachmentDownloadFailure>,
    byte_budget: u64,
) -> Result<(), AppError> {
    let storage = client.app.account_storage(&client.state.label)?;
    let now = crate::unix_now_seconds();
    match result {
        Ok(result) => {
            let plaintext = zeroize::Zeroizing::new(result.plaintext);
            if job.verify_plaintext(&plaintext).is_err() {
                storage.fail_attachment_acquisition(job, None)?;
                return Ok(());
            }
            // Other writers may consume disk while HTTP is in flight. Recheck
            // before starting a full-object SQLite write, without evicting data.
            let reserve = client
                .app
                .config
                .attachment_acquisition
                .as_ref()
                .map_or(u64::MAX, |p| p.minimum_free_disk_bytes);
            let free =
                fs4::available_space(client.app.account_dir(&client.state.label)).unwrap_or(0);
            if free < reserve.saturating_add((plaintext.len() as u64).saturating_mul(4)) {
                storage.fail_attachment_acquisition(job, Some(retry_at(&storage, job, now)))?;
                return Ok(());
            }
            match storage.complete_attachment_acquisition(job, &plaintext, now, byte_budget) {
                Ok(AttachmentPublishResult::Published | AttachmentPublishResult::Superseded) => {}
                Ok(AttachmentPublishResult::CapacityBlocked) | Err(_) => {
                    storage.fail_attachment_acquisition(job, Some(retry_at(&storage, job, now)))?;
                }
            }
        }
        Err(AttachmentDownloadFailure::Retry(_)) => {
            storage.fail_attachment_acquisition(job, Some(retry_at(&storage, job, now)))?;
        }
        Err(AttachmentDownloadFailure::Stop(_)) => {
            storage.fail_attachment_acquisition(job, None)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
