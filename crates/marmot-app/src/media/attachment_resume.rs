//! Durable ciphertext only. Native byte/progress access remains a separate contract.
use super::AttachmentDownloadFailure;
use crate::{AccountMediaStore, AppError};
use media_store::{Admission, DiskPolicy};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
};
use storage_sqlite::{
    ATTACHMENT_CHECKPOINT_BYTES, AttachmentAcquisition, AttachmentPartial,
    AttachmentPartialIdentity, SqliteAccountStorage,
};

/// A checkpoint's metadata and the ciphertext prefix read back from its wire
/// file, for the in-memory sink.
pub(super) type RestoredPartial = (AttachmentPartial, Vec<u8>);

/// The file sink's restored checkpoint: its identity, the bytes its wire file
/// records, and their running hash.
pub(crate) struct WirePrefix {
    pub(crate) identity: AttachmentPartialIdentity,
    pub(crate) received: u64,
    pub(crate) hash: Sha256,
}

pub(crate) const AUTOMATIC_TRANSFER_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(120);
pub(super) const BODY_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const PROGRESS_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

#[derive(Clone)]
pub(crate) struct AttachmentResume {
    pub storage: SqliteAccountStorage,
    pub job: AttachmentAcquisition,
    pub ciphertext_digest: [u8; 32],
    /// The account's media store, which holds this job's `.wire` checkpoint.
    pub media: AccountMediaStore,
    pub directory: PathBuf,
    pub policy: storage_sqlite::AttachmentDownloadPolicy,
    pub automatic: bool,
    /// Cache the monotonic explicit-intent upgrade, scoped to this attempt.
    pub explicit_permission: Arc<AtomicBool>,
    pub permission: Option<crate::runtime::attachment_permission::PermissionLease>,
    /// Once verification finishes, cancellation waits for the receipt and result.
    pub finishing: Arc<AtomicBool>,
    pub updates: Option<tokio::sync::watch::Sender<()>>,
}
fn retry(message: &str) -> AttachmentDownloadFailure {
    AttachmentDownloadFailure::Retry(AppError::BlobStore(message.into()))
}
fn stop(message: &str) -> AttachmentDownloadFailure {
    AttachmentDownloadFailure::Stop(AppError::BlobStore(message.into()))
}
/// Below the space a body needs, the job parks as `StorageBlocked` with its
/// checkpoint instead of re-fetching on a timer. The payload is the headroom
/// beyond the reserve a retried attempt needs, in the worker's frame.
fn storage_blocked(headroom: u64) -> AttachmentDownloadFailure {
    AttachmentDownloadFailure::StorageBlocked { headroom }
}

/// Free bytes on the volume holding `path`, as every capacity decision and the
/// worker's readmission measure it. Tests pin a value per account directory so
/// window tests do not depend on the host's live free space.
pub(crate) fn available_space(path: &std::path::Path) -> std::io::Result<u64> {
    #[cfg(test)]
    if let Some(free) = test_free_space::lookup(path) {
        return Ok(free);
    }
    media_store::free_space(path)
}

/// Jobs whose checkpoint a blocking task is reading or writing. A cancelled
/// download does not stop a checkpoint task already on the blocking pool, so
/// a stale attempt's task could otherwise open the wire file at its own
/// recorded length after a newer attempt recorded more, truncating that
/// suffix or writing over it. Each checkpoint operation holds its job here
/// from the metadata lookup through the file change and the record, so the
/// file's recorded prefix is always the one the operation read.
static CHECKPOINT_JOBS: std::sync::Mutex<Vec<storage_sqlite::AttachmentAssetRef>> =
    std::sync::Mutex::new(Vec::new());
static CHECKPOINT_RELEASED: std::sync::Condvar = std::sync::Condvar::new();

struct CheckpointLock(storage_sqlite::AttachmentAssetRef);

impl CheckpointLock {
    /// Blocks until no other checkpoint operation holds `job`'s asset.
    fn acquire(job: &AttachmentAcquisition) -> Self {
        let mut held = CHECKPOINT_JOBS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while held.contains(&job.reference) {
            held = CHECKPOINT_RELEASED
                .wait(held)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        held.push(job.reference.clone());
        Self(job.reference.clone())
    }
}

impl Drop for CheckpointLock {
    fn drop(&mut self) {
        let mut held = CHECKPOINT_JOBS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(index) = held.iter().position(|reference| *reference == self.0) {
            held.swap_remove(index);
        }
        CHECKPOINT_RELEASED.notify_all();
    }
}

/// Test hooks run between a checkpoint write's metadata lookup and its file
/// change, keyed by job so parallel tests do not see each other's hooks.
#[cfg(test)]
pub(crate) mod checkpoint_hooks {
    use storage_sqlite::AttachmentAssetRef;

    type Hook = Box<dyn FnOnce() + Send>;
    static HOOKS: std::sync::Mutex<Vec<(AttachmentAssetRef, Hook)>> =
        std::sync::Mutex::new(Vec::new());

    pub(crate) fn after_lookup(
        reference: &AttachmentAssetRef,
        hook: impl FnOnce() + Send + 'static,
    ) {
        HOOKS
            .lock()
            .unwrap()
            .push((reference.clone(), Box::new(hook)));
    }

    pub(super) fn run(reference: &AttachmentAssetRef) {
        let hook = {
            let mut hooks = HOOKS.lock().unwrap();
            hooks
                .iter()
                .position(|(held, _)| held == reference)
                .map(|index| hooks.swap_remove(index).1)
        };
        if let Some(hook) = hook {
            hook();
        }
    }
}

/// Appends `bytes` at `offset` to this attempt's `.wire` checkpoint and
/// records the new length (mdk#2314 step 2b). Offset zero starts a new
/// checkpoint, replacing any earlier one: its row commits before its file is
/// created. Bytes reach the file and are synced before the row records them,
/// so a crash leaves at most an unrecorded tail that the next open truncates.
/// `false` means the attempt no longer owns a matching checkpoint.
/// Blocking.
pub(crate) fn write_checkpoint(
    storage: &SqliteAccountStorage,
    media: &AccountMediaStore,
    job: &AttachmentAcquisition,
    identity: &AttachmentPartialIdentity,
    offset: u64,
    bytes: &[u8],
    now: u64,
) -> Result<bool, AppError> {
    let _lock = CheckpointLock::acquire(job);
    let (id, mut wire) = if offset == 0 {
        let previous = storage.load_attachment_partial(job, now, u64::MAX, None)?;
        let Some(id) = storage.begin_attachment_partial(job, identity, now)? else {
            return Ok(false);
        };
        if let Some(previous) = previous {
            media.remove_wire(&previous.wire_file);
        }
        (id, media.create_wire(&id).map_err(media_error)?)
    } else {
        let expected = (&identity.ciphertext_digest, &identity.locator_digest);
        let Some(part) = storage.load_attachment_partial(job, now, u64::MAX, Some(expected))?
        else {
            return Ok(false);
        };
        if part.received != offset || part.identity != *identity {
            return Ok(false);
        }
        #[cfg(test)]
        checkpoint_hooks::run(&job.reference);
        let Some(wire) = media
            .open_wire(&part.wire_file, offset)
            .map_err(media_error)?
        else {
            return Ok(false);
        };
        (part.wire_file, wire)
    };
    wire.append(bytes).map_err(media_error)?;
    let received = offset.saturating_add(bytes.len() as u64);
    Ok(storage.record_attachment_partial(job, identity, &id, received, now)?)
}

/// The current checkpoint and its recorded prefix, read from its wire file.
/// A wire file that is missing or shorter than its row records discards the
/// checkpoint. The prefix buffer is reserved fallibly. Blocking.
pub(crate) fn read_checkpoint(
    storage: &SqliteAccountStorage,
    media: &AccountMediaStore,
    job: &AttachmentAcquisition,
    now: u64,
    max: u64,
    expected: Option<(&[u8; 32], &[u8; 32])>,
) -> Result<Option<RestoredPartial>, AppError> {
    let _lock = CheckpointLock::acquire(job);
    let Some(part) = storage.load_attachment_partial(job, now, max, expected)? else {
        return Ok(None);
    };
    let Some(mut wire) = media
        .open_wire(&part.wire_file, part.received)
        .map_err(media_error)?
    else {
        discard_checkpoint(storage, media, job, now, &part)?;
        return Ok(None);
    };
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(usize::try_from(part.received).unwrap_or(usize::MAX))
        .map_err(|_| AppError::BlobStore("attachment checkpoint buffer unavailable".into()))?;
    wire.copy_to(&mut bytes).map_err(media_error)?;
    Ok(Some((part, bytes)))
}

/// Removes this attempt's checkpoint row, then its wire file. Candidate
/// failures pass the expected identity; `None` clears whatever the job holds.
/// The media sweep removes a wire file this misses. Blocking.
pub(crate) fn clear_checkpoint(
    storage: &SqliteAccountStorage,
    media: &AccountMediaStore,
    job: &AttachmentAcquisition,
    now: u64,
    expected: Option<(&[u8; 32], &[u8; 32])>,
) -> Result<(), AppError> {
    let _lock = CheckpointLock::acquire(job);
    let part = storage.load_attachment_partial(job, now, u64::MAX, expected)?;
    if storage.clear_attachment_partial(job, now, expected)?
        && let Some(part) = part
    {
        media.remove_wire(&part.wire_file);
    }
    Ok(())
}

fn discard_checkpoint(
    storage: &SqliteAccountStorage,
    media: &AccountMediaStore,
    job: &AttachmentAcquisition,
    now: u64,
    part: &AttachmentPartial,
) -> Result<(), AppError> {
    let identity = (
        &part.identity.ciphertext_digest,
        &part.identity.locator_digest,
    );
    if storage.clear_attachment_partial(job, now, Some(identity))? {
        media.remove_wire(&part.wire_file);
    }
    Ok(())
}

fn media_error(_: media_store::MediaError) -> AppError {
    AppError::BlobStore("attachment checkpoint file unavailable".into())
}

/// Distinguish revocation from transport errors without nesting Result values.
pub(crate) enum NetworkPollError<E> {
    Revoked(AttachmentDownloadFailure),
    Operation(E),
}

impl AttachmentResume {
    /// Resolve revoked automatic permission against durable explicit intent once.
    /// Attempt/source/cancellation fences still apply at every admission/publication.
    async fn promoted_permission(&self) -> bool {
        if self.explicit_permission.load(Ordering::Acquire) {
            return true;
        }
        let this = self.clone();
        let promoted = tokio::task::spawn_blocking(move || {
            Ok::<_, cgka_traits::StorageError>(
                this.storage
                    .attachment_request_is_explicit(&this.job.reference)?
                    && this
                        .storage
                        .attachment_transfer_is_active(&this.job, crate::unix_now_seconds())?,
            )
        })
        .await;
        if matches!(promoted, Ok(Ok(true))) {
            self.explicit_permission.store(true, Ordering::Release);
            return true;
        }
        false
    }

    /// Check automatic approval before polling HTTP, honoring a durable upgrade
    /// without changing this transport's original size or deadline.
    pub(crate) async fn with_permission<F, T, E>(&self, future: F) -> Result<T, NetworkPollError<E>>
    where
        F: Future<Output = Result<T, E>>,
    {
        let mut future = std::pin::pin!(future);
        loop {
            let result = std::future::poll_fn(|cx| {
                if !self.explicit_permission.load(Ordering::Acquire)
                    && self
                        .permission
                        .as_ref()
                        .is_some_and(|permission| !permission.allowed())
                {
                    return Poll::Ready(Err(NetworkPollError::Revoked(retry(
                        "automatic attachment permission revoked",
                    ))));
                }
                future
                    .as_mut()
                    .poll(cx)
                    .map(|result| result.map_err(NetworkPollError::Operation))
            })
            .await;
            if matches!(result, Err(NetworkPollError::Revoked(_)))
                && self.promoted_permission().await
            {
                continue;
            }
            return result;
        }
    }
    pub(crate) async fn before_network(&self) -> Result<(), AttachmentDownloadFailure> {
        if self.permission.as_ref().is_some_and(|p| !p.allowed())
            && !self.promoted_permission().await
        {
            return Err(retry("automatic attachment permission revoked"));
        }
        let this = self.clone();
        let allowed = tokio::task::spawn_blocking(move || {
            this.storage
                .begin_attachment_network_attempt(&this.job, crate::unix_now_seconds())
        })
        .await
        .map_err(|_| stop("attachment admission task failed"))?
        .map_err(|_| stop("attachment admission failed"))?;
        if !allowed {
            return Err(stop("attachment network attempt not admitted"));
        }
        Ok(())
    }
    /// Final progress keeps ciphertext units; only the receipt uses plaintext length.
    /// The decrypted file is this attempt's own staging at the receipt.
    /// The ciphertext is on disk now (its wire checkpoint, or `held` bytes of
    /// staging for a body without a validator), so only the store file is
    /// still to be written.
    pub(crate) async fn completed_file_body(
        &self,
        plaintext_len: u64,
        held: u64,
    ) -> Result<(), AttachmentDownloadFailure> {
        let ciphertext_len = plaintext_len
            .checked_add(super::file_transfer::MEDIA_AEAD_TAG_BYTES)
            .ok_or_else(|| stop("attachment length overflow"))?;
        self.progress(ciphertext_len, Some(ciphertext_len), false)
            .await?;
        self.record_completed_body(plaintext_len, held).await
    }

    /// The in-memory sink's receipt. Its checkpoint is already on disk and
    /// stops growing, so only the store file is still to be written.
    pub(crate) async fn completed_body(
        &self,
        plaintext_len: usize,
    ) -> Result<(), AttachmentDownloadFailure> {
        self.record_completed_body(plaintext_len as u64, 0).await
    }

    /// `held` is the staging this attempt occupies at the receipt.
    async fn record_completed_body(
        &self,
        needed: u64,
        held: u64,
    ) -> Result<(), AttachmentDownloadFailure> {
        self.finishing.store(true, Ordering::Release);
        let this = self.clone();
        let recorded = tokio::task::spawn_blocking(move || {
            // Park on disk pressure before recording a completed receipt, so a
            // blocked job never becomes an opted-in body with no retention.
            // Stable retention quota failures after this boundary remain terminal.
            this.check_capacity(needed, held)?;
            this.storage
                .mark_attachment_body_completed(&this.job, crate::unix_now_seconds())
                .map_err(|_| stop("attachment receipt failed"))
        })
        .await
        .map_err(|_| stop("attachment receipt task failed"))??;
        if !recorded {
            return Err(stop("attachment receipt superseded"));
        }
        Ok(())
    }

    /// Admits `needed` more bytes on the account's volume under the
    /// [`DiskPolicy`] built from the durable policy's reserve. A shortage
    /// parks the job with `needed + held` as its headroom; `held` is the
    /// staging this attempt already occupies, which the worker's free-space
    /// measurement (taken once that staging is gone) does not see. Unknown
    /// free space is a transient failure.
    fn check_capacity(&self, needed: u64, held: u64) -> Result<(), AttachmentDownloadFailure> {
        let policy = self
            .storage
            .attachment_download_policy(&self.policy)
            .map_err(|_| retry("attachment publication policy unavailable"))?;
        let free =
            available_space(&self.directory).map_err(|_| retry("free disk space unavailable"))?;
        let disk = DiskPolicy {
            reserve_bytes: policy.disk_reserve,
        };
        match disk.admit(free, needed) {
            Admission::Admitted => Ok(()),
            Admission::StorageFull { headroom } => {
                Err(storage_blocked(headroom.saturating_add(held)))
            }
        }
    }

    /// A download of a `bytes`-byte body needs the reserve plus twice
    /// `bytes` free, for its ciphertext (wire checkpoint or staging) and its
    /// store file, less the `on_disk` ciphertext bytes free space already
    /// excludes. Both sinks apply this as soon as a size is known, again as a
    /// body grows, and once more before the completed-body receipt.
    ///
    /// `held` is the staging this attempt occupies, which the worker's
    /// free-space measurement (taken once that staging is gone) does not see;
    /// a wire checkpoint stays, so it is never held. A shortage parks the job
    /// with the headroom a retried attempt needs beyond the reserve: the need
    /// plus `held`. Readmission requires that headroom in the worker's frame
    /// plus a margin wider than the sub-MiB tail a checkpointed body still
    /// re-requests, so the first check a readmitted attempt reaches passes.
    /// Each park records the need its own check proved; saved progress may
    /// lower a later one, since the next attempt then has less left to write.
    /// Unknown free space is a transient failure.
    fn check_download_capacity(
        &self,
        bytes: u64,
        on_disk: u64,
        held: u64,
    ) -> Result<(), AttachmentDownloadFailure> {
        self.check_capacity(download_bytes(bytes, on_disk), held)
    }

    /// Check download headroom without recording a completed-body receipt.
    pub(crate) async fn publication_capacity(
        self: &Arc<Self>,
        bytes: u64,
        on_disk: u64,
        held: u64,
    ) -> Result<(), AttachmentDownloadFailure> {
        let this = Arc::clone(self);
        tokio::task::spawn_blocking(move || this.check_download_capacity(bytes, on_disk, held))
            .await
            .map_err(|_| retry("attachment capacity task failed"))?
    }

    /// Early in-memory capacity check under the download rule. A definite
    /// shortage parks the job, but an unobservable policy or free-space figure
    /// must not mask a later cryptographic verdict. The completed-body receipt
    /// repeats the check authoritatively.
    async fn early_publication_capacity(
        self: &Arc<Self>,
        bytes: u64,
        on_disk: u64,
    ) -> Result<(), AttachmentDownloadFailure> {
        match self.publication_capacity(bytes, on_disk, 0).await {
            Err(blocked @ AttachmentDownloadFailure::StorageBlocked { .. }) => Err(blocked),
            _ => Ok(()),
        }
    }

    /// Largest ciphertext body an explicit acquisition buffers in memory: the
    /// same bound automatic work already has. Larger explicit bodies stream
    /// through the private file sink, so receiving never holds a whole-file
    /// array beyond the configured transfer limit.
    pub(super) fn memory_sink_limit(&self) -> u64 {
        self.policy
            .transfer_limit
            .min(super::blossom::MAX_ENCRYPTED_MEDIA_BLOB_BYTES)
    }

    pub(crate) async fn progress(
        &self,
        received: u64,
        total: Option<u64>,
        restart: bool,
    ) -> Result<(), AttachmentDownloadFailure> {
        let this = self.clone();
        let updated = tokio::task::spawn_blocking(move || {
            this.storage.update_attachment_progress(
                &this.job,
                crate::unix_now_seconds(),
                1,
                received,
                total,
                restart,
            )
        })
        .await;
        // Observation failures must not mask a cryptographic terminal outcome.
        // The worker cancellation monitor and publication gate still fence bytes.
        if matches!(updated, Ok(Ok(false))) {
            return Err(retry("transfer no longer admitted"));
        }
        if let Some(updates) = &self.updates {
            updates.send_modify(|_| {});
        }
        Ok(())
    }
    pub(crate) async fn phase(&self, phase: u8) -> Result<(), AttachmentDownloadFailure> {
        let this = self.clone();
        let updated = tokio::task::spawn_blocking(move || {
            this.storage
                .update_attachment_phase(&this.job, crate::unix_now_seconds(), phase)
        })
        .await;
        // Observation failures must not mask a cryptographic terminal outcome.
        // The worker cancellation monitor and publication gate still fence bytes.
        if matches!(updated, Ok(Ok(false))) {
            return Err(retry("transfer no longer admitted"));
        }
        if let Some(updates) = &self.updates {
            updates.send_modify(|_| {});
        }
        Ok(())
    }

    pub(super) async fn checkpoint_total(
        &self,
        url: &url::Url,
    ) -> Result<Option<u64>, AttachmentDownloadFailure> {
        let this = self.clone();
        let locator_digest = Sha256::digest(url.as_str().as_bytes()).into();
        tokio::task::spawn_blocking(move || {
            this.storage.attachment_partial_total(
                &this.job,
                crate::unix_now_seconds(),
                (&this.ciphertext_digest, &locator_digest),
            )
        })
        .await
        .map_err(|_| retry("partial checkpoint task failed"))?
        .map_err(|_| retry("partial checkpoint metadata unavailable"))
    }

    pub(super) async fn load(
        &self,
        url: &url::Url,
        max: u64,
    ) -> Result<Option<RestoredPartial>, AttachmentDownloadFailure> {
        let this = self.clone();
        let locator_digest = Sha256::digest(url.as_str().as_bytes()).into();
        tokio::task::spawn_blocking(move || {
            read_checkpoint(
                &this.storage,
                &this.media,
                &this.job,
                crate::unix_now_seconds(),
                max,
                Some((&this.ciphertext_digest, &locator_digest)),
            )
        })
        .await
        .map_err(|_| retry("partial checkpoint task failed"))?
        .map_err(|_| retry("partial checkpoint read failed"))
    }
    pub(crate) async fn clear(
        &self,
        url: Option<&url::Url>,
    ) -> Result<(), AttachmentDownloadFailure> {
        let this = self.clone();
        let identity = url.map(|url| {
            (
                self.ciphertext_digest,
                <[u8; 32]>::from(Sha256::digest(url.as_str().as_bytes())),
            )
        });
        tokio::task::spawn_blocking(move || {
            clear_checkpoint(
                &this.storage,
                &this.media,
                &this.job,
                crate::unix_now_seconds(),
                identity.as_ref().map(|(c, l)| (c, l)),
            )
        })
        .await
        .map_err(|_| retry("partial checkpoint task failed"))?
        .map_err(|_| retry("partial checkpoint cleanup failed"))?;
        Ok(())
    }
    pub(super) async fn save(
        &self,
        identity: AttachmentPartialIdentity,
        offset: usize,
        bytes: Vec<u8>,
    ) -> Result<(), AttachmentDownloadFailure> {
        let this = self.clone();
        let saved = tokio::task::spawn_blocking(move || {
            // A checkpoint write keeps the reserve free, like every other
            // write on the account's volume.
            let free = available_space(&this.directory).unwrap_or(0);
            let disk = DiskPolicy {
                reserve_bytes: this.policy.disk_reserve,
            };
            if disk.admit(free, bytes.len() as u64) != Admission::Admitted {
                return Ok(false);
            }
            write_checkpoint(
                &this.storage,
                &this.media,
                &this.job,
                &identity,
                offset as u64,
                &bytes,
                crate::unix_now_seconds(),
            )
        })
        .await
        .map_err(|_| retry("partial checkpoint task failed"))?
        .map_err(|_| retry("partial checkpoint write failed"))?;
        if !saved {
            return Err(retry("partial checkpoint no longer admitted"));
        }
        Ok(())
    }

    /// The file sink's checkpoint for `url`, hashed in place: nothing is
    /// copied, so restoring a prefix needs no disk space. A wire file that is
    /// missing or shorter than its row discards the checkpoint.
    pub(crate) async fn load_wire(
        &self,
        url: &url::Url,
        max: u64,
        control: Arc<super::file_transfer::MediaFileTransferControl>,
    ) -> Result<Option<WirePrefix>, AttachmentDownloadFailure> {
        let this = self.clone();
        let locator_digest: [u8; 32] = Sha256::digest(url.as_str().as_bytes()).into();
        tokio::task::spawn_blocking(move || {
            let _lock = CheckpointLock::acquire(&this.job);
            let now = crate::unix_now_seconds();
            let expected = (&this.ciphertext_digest, &locator_digest);
            let Some(part) = this
                .storage
                .load_attachment_partial(&this.job, now, max, Some(expected))
                .map_err(|_| retry("partial file checkpoint unavailable"))?
            else {
                return Ok(None);
            };
            let Some(wire) = this
                .media
                .open_wire(&part.wire_file, part.received)
                .map_err(|_| retry("partial file checkpoint unavailable"))?
            else {
                discard_checkpoint(&this.storage, &this.media, &this.job, now, &part)
                    .map_err(|_| retry("partial file checkpoint cleanup failed"))?;
                return Ok(None);
            };
            let mut reader = wire
                .into_reader()
                .map_err(|_| retry("partial file checkpoint unavailable"))?;
            let mut hash = Sha256::new();
            let mut buffer = vec![0u8; super::file_transfer::FILE_TRANSFER_BUFFER_BYTES];
            loop {
                control.check()?;
                let count = std::io::Read::read(&mut reader, &mut buffer)
                    .map_err(|_| retry("partial file checkpoint unavailable"))?;
                if count == 0 {
                    break;
                }
                hash.update(&buffer[..count]);
            }
            Ok(Some(WirePrefix {
                identity: part.identity,
                received: part.received,
                hash,
            }))
        })
        .await
        .map_err(|_| retry("partial file checkpoint task failed"))?
    }

    /// The wire file holding this attempt's complete `len`-byte ciphertext
    /// for `url`, once its checkpoint records every byte.
    pub(crate) async fn completed_wire(
        &self,
        url: &url::Url,
        len: u64,
    ) -> Result<media_store::FileId, AttachmentDownloadFailure> {
        let this = self.clone();
        let locator_digest: [u8; 32] = Sha256::digest(url.as_str().as_bytes()).into();
        tokio::task::spawn_blocking(move || {
            let part = this
                .storage
                .load_attachment_partial(
                    &this.job,
                    crate::unix_now_seconds(),
                    u64::MAX,
                    Some((&this.ciphertext_digest, &locator_digest)),
                )
                .map_err(|_| retry("file checkpoint unavailable"))?
                .filter(|part| part.received == len && part.identity.total == len)
                .ok_or_else(|| retry("file checkpoint incomplete"))?;
            Ok(part.wire_file)
        })
        .await
        .map_err(|_| retry("file checkpoint task failed"))?
    }
}

pub(super) fn strong_etag(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let mut values = headers.get_all(reqwest::header::ETAG).iter();
    let tag = values.next()?.to_str().ok()?;
    if values.next().is_some()
        || tag.len() < 2
        || tag.len() > 1024
        || !tag.starts_with('"')
        || !tag.ends_with('"')
        || !tag.as_bytes()[1..tag.len() - 1]
            .iter()
            .all(|b| *b == 0x21 || (0x23..=0x7e).contains(b))
    {
        return None;
    }
    Some(tag.to_owned())
}

/// Accept only a single exact suffix of the saved representation. Unknown totals,
/// multipart, shortened/overlapping ranges and duplicate range headers fail closed.
pub(super) fn valid_range(response: &reqwest::Response, part: &AttachmentPartial) -> bool {
    let mut ranges = response
        .headers()
        .get_all(reqwest::header::CONTENT_RANGE)
        .iter();
    let Some(raw) = ranges.next().and_then(|h| h.to_str().ok()) else {
        return false;
    };
    if ranges.next().is_some() {
        return false;
    }
    let expected = format!(
        "bytes {}-{}/{}",
        part.received,
        part.identity.total - 1,
        part.identity.total
    );
    raw == expected
        && response
            .content_length()
            .is_none_or(|n| n == part.identity.total - part.received)
}

pub(super) async fn read_body(
    mut response: reqwest::Response,
    url: &url::Url,
    max: u64,
    first_byte_deadline: tokio::time::Instant,
    context: &Arc<AttachmentResume>,
    prefix: Option<RestoredPartial>,
) -> Result<Vec<u8>, AttachmentDownloadFailure> {
    if response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .is_some_and(|v| v.as_bytes() != b"identity")
    {
        return Err(stop("encoded response cannot be resumed"));
    }
    let (mut bytes, identity) = if let Some((part, bytes)) = prefix {
        (bytes, Some(part.identity))
    } else {
        // A replacement checkpoint atomically replaces the old locator's prefix.
        // Preserve it if this fallback fails before saving any useful bytes.
        let identity = strong_etag(response.headers())
            .zip(response.content_length())
            .filter(|(_, n)| *n > 0 && *n <= max)
            .map(|(etag, total)| AttachmentPartialIdentity {
                ciphertext_digest: context.ciphertext_digest,
                locator_digest: Sha256::digest(url.as_str().as_bytes()).into(),
                etag,
                total,
            });
        (Vec::new(), identity)
    };
    let expected_total = identity
        .as_ref()
        .map(|i| i.total)
        .or_else(|| response.content_length());
    if expected_total.is_some_and(|n| n > max) {
        return Err(AttachmentDownloadFailure::SizeLimit(
            AppError::BlobStore("download exceeds size limit".into()),
            max,
        ));
    }
    if let Some(total) = expected_total {
        // The size is known now: refuse before fetching a body the device
        // cannot checkpoint and publish, and reserve the buffer once so it
        // never doubles. A peer-declared length must not abort the process on
        // allocation.
        context
            .early_publication_capacity(
                total.saturating_sub(super::file_transfer::MEDIA_AEAD_TAG_BYTES),
                bytes.len() as u64,
            )
            .await?;
        bytes
            .try_reserve_exact((total as usize).saturating_sub(bytes.len()))
            .map_err(|_| retry("attachment body buffer unavailable"))?;
    }
    context
        .progress(bytes.len() as u64, expected_total, true)
        .await?;
    let mut reported = tokio::time::Instant::now();
    let mut saved = bytes.len();
    let mut first = true;
    loop {
        let next = if first {
            tokio::time::timeout_at(first_byte_deadline, response.chunk())
                .await
                .map_err(|_| retry("request timed out"))?
                .map_err(|_| retry("body transfer failed"))
        } else {
            tokio::time::timeout(BODY_IDLE_TIMEOUT, response.chunk())
                .await
                .map_err(|_| retry("body idle timeout"))
                .and_then(|r| r.map_err(|_| retry("body transfer failed")))
        };
        let chunk = match next {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(err) => {
                if let Some(identity) = &identity {
                    checkpoint_tail(context, identity, &bytes, &mut saved).await?;
                }
                return Err(err);
            }
        };
        first = false;
        let size = bytes.len().saturating_add(chunk.len()) as u64;
        if size > max {
            return Err(AttachmentDownloadFailure::SizeLimit(
                AppError::BlobStore("download exceeds size limit".into()),
                max,
            ));
        }
        if expected_total.is_some_and(|n| size > n) {
            return Err(stop("download exceeds response size bound"));
        }
        if bytes.capacity() < bytes.len() + chunk.len() {
            // A failed reservation never aborts.
            let wanted =
                next_body_capacity(bytes.capacity(), bytes.len() + chunk.len(), max as usize);
            bytes
                .try_reserve_exact(wanted - bytes.len())
                .map_err(|_| retry("attachment body buffer unavailable"))?;
        }
        bytes.extend_from_slice(&chunk);
        if reported.elapsed() >= PROGRESS_INTERVAL {
            context
                .progress(bytes.len() as u64, expected_total, false)
                .await?;
            reported = tokio::time::Instant::now();
        }
        if let Some(identity) = &identity {
            while bytes.len() - saved >= ATTACHMENT_CHECKPOINT_BYTES {
                let end = saved + ATTACHMENT_CHECKPOINT_BYTES;
                context
                    .save(identity.clone(), saved, bytes[saved..end].to_vec())
                    .await?;
                saved = end;
            }
        }
    }
    if expected_total.is_some_and(|n| bytes.len() as u64 != n) {
        if let Some(identity) = &identity {
            checkpoint_tail(context, identity, &bytes, &mut saved).await?;
        }
        return Err(retry("incomplete media body"));
    }
    // Space may have shrunk during the transfer. Keep the complete ciphertext
    // checkpointed, so readmission verifies it locally without another request.
    if let Err(error) = context
        .early_publication_capacity(
            (bytes.len() as u64).saturating_sub(super::file_transfer::MEDIA_AEAD_TAG_BYTES),
            saved as u64,
        )
        .await
    {
        if let Some(identity) = &identity {
            let _ = checkpoint_tail(context, identity, &bytes, &mut saved).await;
        }
        return Err(error);
    }
    // Complete bodies go straight to verification/publication. Do not write a
    // final tiny checkpoint only to delete it on success.
    context
        .progress(bytes.len() as u64, expected_total, false)
        .await?;
    Ok(bytes)
}
/// What a download needs free beyond the reserve for a body of `bytes`: its
/// ciphertext and its store file, less the `on_disk` ciphertext bytes already
/// written, and never less than the store file.
fn download_bytes(bytes: u64, on_disk: u64) -> u64 {
    DiskPolicy::download_bytes(bytes)
        .saturating_sub(on_disk)
        .max(bytes)
}

/// Next buffer capacity for an undeclared-length body that needs `needed`
/// bytes, growing from `capacity` under the admitted `limit`: doubling up to
/// half the limit, then one step to the limit itself. Growth copies the old
/// buffer into the new one, so the buffer never exceeds the limit and the
/// transient peak during a copy never exceeds 1.5 times it.
pub(crate) fn next_body_capacity(capacity: usize, needed: usize, limit: usize) -> usize {
    let half = limit.div_ceil(2);
    if needed <= half {
        capacity.saturating_mul(2).max(needed).min(half)
    } else {
        limit
    }
}

async fn checkpoint_tail(
    context: &AttachmentResume,
    identity: &AttachmentPartialIdentity,
    bytes: &[u8],
    saved: &mut usize,
) -> Result<(), AttachmentDownloadFailure> {
    if bytes.len() > *saved {
        context
            .save(identity.clone(), *saved, bytes[*saved..].to_vec())
            .await?;
        *saved = bytes.len();
    }
    Ok(())
}

/// Per-directory free-space pins for tests, read by [`available_space`].
///
/// A modeled pin behaves like a volume holding the account: it reports the
/// pinned figure less every byte currently staged under the account's media
/// staging directory and less what the checkpoint table grew by since the pin.
/// The pinned figure is therefore free space in the worker's frame (no
/// attempt staging), and an attempt's own staging and checkpoint writes
/// consume the space its later capacity checks see, as on a real device.
#[cfg(test)]
pub(crate) mod test_free_space {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use storage_sqlite::SqliteAccountStorage;

    #[derive(Clone)]
    struct Model {
        staging: PathBuf,
        storage: SqliteAccountStorage,
        checkpoint_base: u64,
    }

    #[derive(Clone)]
    struct Pin {
        free: u64,
        model: Option<Model>,
    }

    static PINS: Mutex<BTreeMap<PathBuf, Pin>> = Mutex::new(BTreeMap::new());

    /// Pin a constant free-space figure for `root` and everything beneath it.
    pub(crate) fn set(root: &Path, free: u64) {
        PINS.lock()
            .unwrap()
            .insert(root.to_path_buf(), Pin { free, model: None });
    }

    /// Pin `free` in the worker's frame for `root`, charging live staging
    /// under `staging` and checkpoint growth in `storage` against it.
    pub(crate) fn set_modeled(
        root: &Path,
        free: u64,
        staging: &Path,
        storage: &SqliteAccountStorage,
    ) {
        let checkpoint_base = storage.attachment_partial_bytes_for_test().unwrap();
        PINS.lock().unwrap().insert(
            root.to_path_buf(),
            Pin {
                free,
                model: Some(Model {
                    staging: staging.to_path_buf(),
                    storage: storage.clone(),
                    checkpoint_base,
                }),
            },
        );
    }

    /// Drop the pin for `root`, returning it to live measurements.
    pub(crate) fn clear(root: &Path) {
        PINS.lock().unwrap().remove(root);
    }

    /// The modeled free space of the pinned root that contains `path`, if any.
    pub(crate) fn lookup(path: &Path) -> Option<u64> {
        // Copy the pin out first: the model queries storage and the file
        // system, and must not do so under this lock.
        let pin = PINS
            .lock()
            .unwrap()
            .iter()
            .find(|(root, _)| path.starts_with(root))
            .map(|(_, pin)| pin.clone())?;
        let Some(model) = pin.model else {
            return Some(pin.free);
        };
        let staged: u64 = std::fs::read_dir(&model.staging)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.metadata().ok())
            .filter(|metadata| metadata.is_file())
            .map(|metadata| metadata.len())
            .sum();
        let grown = model
            .storage
            .attachment_partial_bytes_for_test()
            .unwrap_or(model.checkpoint_base)
            .saturating_sub(model.checkpoint_base);
        Some(pin.free.saturating_sub(staged).saturating_sub(grown))
    }
}
