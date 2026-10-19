//! Bounded local transfer observation and durable controls over existing acquisition jobs.
use super::{
    AttachmentAssetRef, AttachmentLocalTarget, MarmotAppRuntime, wait_for_runtime_shutdown,
};
use crate::{AppError, CursorPersistence, MarmotAppConfig};
use cgka_traits::GroupId;
use std::{sync::Arc, time::Duration};
pub use storage_sqlite::{
    AttachmentDownloadPolicy, AttachmentTransferState, AttachmentTransferStatus,
};
use tokio::sync::{Mutex, broadcast, watch};

#[derive(Clone, Copy, Debug)]
pub enum AttachmentControl {
    Cancel,
    Retry,
    Remove,
}

/// Derive the shared admission/retention defaults for receive and upload paths.
pub(crate) fn default_policy(config: &MarmotAppConfig) -> AttachmentDownloadPolicy {
    let p = config.attachment_acquisition.clone().unwrap_or_default();
    AttachmentDownloadPolicy {
        automatic: config.attachment_acquisition.is_some(),
        retained_bytes: p.retained_bytes_per_account,
        disk_reserve: p.minimum_free_disk_bytes,
        transfer_limit: p.maximum_transfer_bytes,
    }
}
fn validate_policy(policy: &AttachmentDownloadPolicy) -> Result<(), AppError> {
    policy
        .validate()
        .map_err(|_| AppError::InvalidEncryptedMedia("invalid attachment download policy".into()))
}

impl MarmotAppRuntime {
    pub async fn attachment_download_policy(
        &self,
        account_ref: &str,
    ) -> Result<AttachmentDownloadPolicy, AppError> {
        let fallback = default_policy(&self.accounts.app.config);
        validate_policy(&fallback)?;
        self.attachment_read(account_ref, move |s, _| {
            Ok(s.app_storage().attachment_download_policy(&fallback)?)
        })
        .await
    }
    /// Durable, per-account override. Disable pauses automatic work, not explicit
    /// requests or local reads. Cached bytes and individual cancel/removal survive.
    pub async fn set_attachment_download_policy(
        &self,
        account_ref: &str,
        policy: AttachmentDownloadPolicy,
    ) -> Result<(), AppError> {
        validate_policy(&policy)?;
        self.attachment_read(account_ref, move |s, _| {
            Ok(s.app_storage()
                .set_attachment_download_policy(&policy, crate::unix_now_seconds())?)
        })
        .await?;
        self.wake_attachment_work();
        Ok(())
    }
    pub(super) fn wake_attachment_work(&self) {
        self.shared.attachment_updates.send_modify(|_| {});
        self.shared.attachment_cancellations.send_modify(|_| {});
        self.accounts.app.presentation_signals.wake();
    }
    /// Opaque job references come from transfer snapshots (including non-ready jobs).
    /// Cancellation does not erase ready bytes; removal explicitly does.
    pub async fn control_attachment(
        &self,
        account_ref: &str,
        reference: AttachmentAssetRef,
        control: AttachmentControl,
    ) -> Result<bool, AppError> {
        let changed = self
            .attachment_read_with(account_ref, move |app, label, s, _| {
                Ok(match control {
                    AttachmentControl::Cancel => {
                        s.app_storage().cancel_attachment_acquisition(&reference)?
                    }
                    AttachmentControl::Retry => s
                        .app_storage()
                        .explicitly_retry_attachment(&reference, crate::unix_now_seconds())?,
                    // The released media files are unlinked now, not at the
                    // next sweep, so removal frees file-backed space at once.
                    AttachmentControl::Remove => {
                        match s
                            .app_storage()
                            .remove_attachment_reference_releasing(&reference)?
                        {
                            Some(released) => {
                                if !released.is_empty() {
                                    app.account_media_store(label, &s)?
                                        .unlink_released(&released);
                                }
                                true
                            }
                            None => false,
                        }
                    }
                })
            })
            .await?;
        self.wake_attachment_work();
        Ok(changed)
    }
    /// Join or promote the current source without retrying cancelled/failed
    /// work, resetting budgets or extending an active transfer deadline.
    /// A retained source remains local; use Retry/Download again for recovery.
    pub async fn request_explicit_attachment(
        &self,
        account_ref: &str,
        group: &GroupId,
        mut target: AttachmentLocalTarget,
    ) -> Result<Option<AttachmentAssetRef>, AppError> {
        super::attachment_access::validate_targets(std::slice::from_mut(&mut target))?;
        let group = hex::encode(group.as_slice());
        let result = self
            .attachment_read(account_ref, move |s, loopback| {
                let now = crate::unix_now_seconds();
                let Some(entry) = s.app_storage().attachment_control_entry(
                    &group,
                    &target.message_id_hex,
                    &target.source_message_id_hex,
                    target.attachment_index,
                    now,
                )?
                else {
                    return Ok(None);
                };
                let Some(epoch) = entry.source_epoch else {
                    return Ok(None);
                };
                let tag: Vec<String> =
                    serde_json::from_value(entry.slot.clone()).map_err(|_| {
                        AppError::InvalidEncryptedMedia("invalid attachment slot".into())
                    })?;
                let parsed = crate::parse_media_attachment(&tag, Some(epoch), loopback)?;
                let digest = crate::media::media_hash_from_reference(&parsed)?;
                match s
                    .app_storage()
                    .request_explicit_attachment(&group, &entry, digest, now)?
                {
                    storage_sqlite::AttachmentDemand::Requested(reference) => Ok(Some(reference)),
                    _ => Ok(None),
                }
            })
            .await?;
        self.wake_attachment_work();
        Ok(result)
    }
    /// Explicitly request the exact current source, clearing removal/cancellation.
    /// This persists demand; it does not wait for a worker or network readiness.
    pub async fn download_attachment_again(
        &self,
        account_ref: &str,
        group: &GroupId,
        mut target: AttachmentLocalTarget,
    ) -> Result<Option<AttachmentAssetRef>, AppError> {
        super::attachment_access::validate_targets(std::slice::from_mut(&mut target))?;
        let group = hex::encode(group.as_slice());
        let result = self
            .attachment_read(account_ref, move |s, loopback| {
                let now = crate::unix_now_seconds();
                let Some(entry) = s.app_storage().attachment_control_entry(
                    &group,
                    &target.message_id_hex,
                    &target.source_message_id_hex,
                    target.attachment_index,
                    now,
                )?
                else {
                    return Ok(None);
                };
                let Some(epoch) = entry.source_epoch else {
                    return Ok(None);
                };
                let tag: Vec<String> =
                    serde_json::from_value(entry.slot.clone()).map_err(|_| {
                        AppError::InvalidEncryptedMedia("invalid attachment slot".into())
                    })?;
                let reference = crate::parse_media_attachment(&tag, Some(epoch), loopback)?;
                let digest = crate::media::media_hash_from_reference(&reference)?;
                match s
                    .app_storage()
                    .request_attachment_download_again(&group, &entry, digest, now)?
                {
                    storage_sqlite::AttachmentDemand::Requested(reference) => Ok(Some(reference)),
                    _ => Ok(None),
                }
            })
            .await?;
        self.wake_attachment_work();
        Ok(result)
    }
    async fn attachment_transfer_frame(
        &self,
        account_ref: &str,
        group: &GroupId,
        mut targets: Vec<AttachmentLocalTarget>,
    ) -> Result<storage_sqlite::AttachmentTransferFrame, AppError> {
        super::attachment_access::validate_targets(&mut targets)?;
        let group = hex::encode(group.as_slice());
        let fallback = default_policy(&self.accounts.app.config);
        let frozen = self.accounts.app.config.cursor_persistence == CursorPersistence::Frozen;
        let host_managed = self.accounts.app.config.attachment_acquisition_mode
            == crate::AttachmentAcquisitionMode::HostManaged;
        let permissions = self.shared.attachment_permissions.clone();
        self.attachment_read(account_ref, move |s, _| {
            let policy = s.app_storage().attachment_download_policy(&fallback)?;
            let targets = targets
                .iter()
                .map(|t| {
                    (
                        t.message_id_hex.as_str(),
                        t.source_message_id_hex.as_str(),
                        t.attachment_index,
                    )
                })
                .collect::<Vec<_>>();
            let mut frame = s.app_storage().attachment_transfer_snapshot(
                &group,
                &targets,
                crate::unix_now_seconds(),
                policy.automatic && !frozen,
            )?;
            if host_managed {
                for status in frame.rows.iter_mut().flatten() {
                    if matches!(
                        status.state,
                        AttachmentTransferState::Queued
                            | AttachmentTransferState::RetryScheduled
                            | AttachmentTransferState::Downloading
                            | AttachmentTransferState::VerifyingCiphertext
                            | AttachmentTransferState::Decrypting
                            | AttachmentTransferState::VerifyingPlaintext
                    ) && status
                        .automatic_media_type
                        .as_ref()
                        .is_some_and(|mime| !permissions.allows(&frame.store_epoch, mime))
                    {
                        status.state = AttachmentTransferState::Paused;
                        status.retry_at = None;
                    }
                }
            }
            Ok(frame)
        })
        .await
    }
    /// Local metadata only, at most 64 original slots in input order. None means
    /// unavailable/obsolete source, not failure. Does not start acquisition.
    pub async fn attachment_transfer_snapshot(
        &self,
        account_ref: &str,
        group: &GroupId,
        targets: Vec<AttachmentLocalTarget>,
    ) -> Result<Vec<Option<AttachmentTransferStatus>>, AppError> {
        self.attachment_transfer_frame(account_ref, group, targets)
            .await
            .map(|frame| frame.rows)
    }
    /// Initial snapshot followed by replacement snapshots. A row that appears,
    /// disappears or enters another transfer state is delivered as soon as the
    /// transfer is reported; progress-only changes are coalesced to at most four
    /// per second. No unbounded event queue or per-byte FFI callback. Drop/close
    /// terminates observation; it does not cancel the underlying download.
    pub async fn subscribe_attachment_transfers(
        &self,
        account_ref: &str,
        group: &GroupId,
        targets: Vec<AttachmentLocalTarget>,
    ) -> Result<Arc<RuntimeAttachmentTransferSubscription>, AppError> {
        let updates = self.shared.attachment_updates.subscribe();
        let presentation = self.accounts.app.presentation_signals.updates.subscribe();
        let storage_sqlite::AttachmentTransferFrame {
            store_epoch: identity,
            rows,
            next_expiry,
        } = self
            .attachment_transfer_frame(account_ref, group, targets.clone())
            .await?;
        Ok(Arc::new(RuntimeAttachmentTransferSubscription {
            runtime: self.clone(),
            account: account_ref.into(),
            group: group.clone(),
            targets,
            identity,
            closed: watch::channel(false).0,
            state: Mutex::new(TransferSubscriptionState {
                updates,
                presentation,
                next_expiry,
                rows,
                initial: true,
                last: tokio::time::Instant::now(),
                read: tokio::time::Instant::now(),
                owed: None,
                held: None,
                reading: None,
            }),
            #[cfg(test)]
            read_gate: Default::default(),
            #[cfg(test)]
            waits: watch::channel(None).0,
        }))
    }
}

struct TransferSubscriptionState {
    updates: watch::Receiver<()>,
    presentation: broadcast::Receiver<crate::chat_presentation::signals::PresentationInvalidation>,
    next_expiry: Option<u64>,
    rows: Vec<Option<AttachmentTransferStatus>>,
    initial: bool,
    /// When the last frame was delivered: progress-only frames keep their spacing from it.
    last: tokio::time::Instant,
    /// When the frame was last read: wakes keep their spacing from it.
    read: tokio::time::Instant,
    /// When a read, or the delivery of held rows, is owed: set by a wake or by
    /// progress waiting out the window, and cleared once it happens. It
    /// outlives a cancelled `next()` — a C timeout drops the future — so the
    /// next call acts on it instead of waiting for another wake.
    owed: Option<tokio::time::Instant>,
    /// Progress rows read while the window was still open, delivered when it
    /// ends without reading them again. A transfer notification before then
    /// drops them, since the rows may have moved on. Like `owed`, they outlive
    /// a cancelled `next()`.
    held: Option<Vec<Option<AttachmentTransferStatus>>>,
    /// The read in flight. A `next()` cancelled mid-read leaves it running, and
    /// the next call collects it first, before it waits or consumes a
    /// notification, rather than starting another, so caller timeouts never
    /// stack reads or lose a notification that came after the read began.
    reading: Option<FrameRead>,
}

type FrameRead = tokio::task::JoinHandle<Result<storage_sqlite::AttachmentTransferFrame, AppError>>;

/// Holds a subscription's reads until `open` is true, before they touch the
/// database or, with `after_read`, once they have taken their snapshot, and
/// records when each one started, so a test can cancel `next()` mid-read or
/// check how far apart reads start.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct ReadGateForTest {
    pub(crate) starts: Arc<std::sync::Mutex<Vec<tokio::time::Instant>>>,
    pub(crate) open: Arc<watch::Sender<bool>>,
    after_read: bool,
}

/// What a pending `next()` waits for, published as the wait begins so a test
/// acts once it is in place rather than after a sleep.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransferWaitForTest {
    /// A wake: a transfer notification, presentation churn or the idle fallback.
    Wake,
    /// A read owed this long after the previous read.
    Read(Duration),
    /// Progress rows held until the window ends.
    Held,
}
pub struct RuntimeAttachmentTransferSubscription {
    runtime: MarmotAppRuntime,
    account: String,
    group: GroupId,
    targets: Vec<AttachmentLocalTarget>,
    identity: Vec<u8>,
    closed: watch::Sender<bool>,
    state: Mutex<TransferSubscriptionState>,
    #[cfg(test)]
    read_gate: std::sync::Mutex<Option<ReadGateForTest>>,
    #[cfg(test)]
    waits: watch::Sender<Option<TransferWaitForTest>>,
}
impl RuntimeAttachmentTransferSubscription {
    pub fn close(&self) {
        self.closed.send_replace(true);
    }

    /// Hold this subscription's later reads, before they touch the database,
    /// until the returned gate opens.
    #[cfg(test)]
    pub(crate) fn gate_reads_for_test(&self) -> ReadGateForTest {
        self.install_read_gate(false)
    }

    /// Hold the results of this subscription's later reads, snapshot already
    /// taken, until the returned gate opens.
    #[cfg(test)]
    pub(crate) fn gate_read_results_for_test(&self) -> ReadGateForTest {
        self.install_read_gate(true)
    }

    /// Installs a read gate that holds reads before or after their snapshot.
    #[cfg(test)]
    fn install_read_gate(&self, after_read: bool) -> ReadGateForTest {
        let gate = ReadGateForTest {
            starts: Default::default(),
            open: Arc::new(watch::channel(false).0),
            after_read,
        };
        *self.read_gate.lock().unwrap() = Some(gate.clone());
        gate
    }

    /// The waits a pending `next()` enters, latest first.
    #[cfg(test)]
    pub(crate) fn waits_for_test(&self) -> watch::Receiver<Option<TransferWaitForTest>> {
        self.waits.subscribe()
    }

    /// Read the current frame, resuming the read a cancelled call left in
    /// flight instead of starting another: one handle never runs two reads.
    async fn read_frame(
        &self,
        reading: &mut Option<FrameRead>,
    ) -> Result<storage_sqlite::AttachmentTransferFrame, AppError> {
        let read = reading.get_or_insert_with(|| {
            let runtime = self.runtime.clone();
            let (account, group, targets) = (
                self.account.clone(),
                self.group.clone(),
                self.targets.clone(),
            );
            #[cfg(test)]
            let gate = self.read_gate.lock().unwrap().clone();
            tokio::spawn(async move {
                #[cfg(test)]
                if let Some(gate) = &gate {
                    gate.starts
                        .lock()
                        .unwrap()
                        .push(tokio::time::Instant::now());
                    if !gate.after_read {
                        let _ = gate.open.subscribe().wait_for(|open| *open).await;
                    }
                }
                let frame = runtime
                    .attachment_transfer_frame(&account, &group, targets)
                    .await;
                #[cfg(test)]
                if let Some(gate) = gate.filter(|gate| gate.after_read) {
                    let _ = gate.open.subscribe().wait_for(|open| *open).await;
                }
                frame
            })
        });
        let frame = read.await;
        *reading = None;
        frame.map_err(|error| AppError::BlockingTask(error.to_string()))?
    }
    pub async fn next(&self) -> Result<Option<Vec<Option<AttachmentTransferStatus>>>, AppError> {
        let mut closed = self.closed.subscribe();
        let mut stopping = self.runtime.shared.lifecycle().subscribe_shutdown();
        let mut state = self.state.lock().await;
        if *closed.borrow() || self.runtime.shared.lifecycle().ensure_running().is_err() {
            return Ok(None);
        }
        if state.initial {
            // A handle may sit unused across deletion or account reconstruction.
            // Revalidate before exposing its first metadata frame too.
            let storage_sqlite::AttachmentTransferFrame {
                store_epoch: identity,
                rows,
                next_expiry,
            } = self.read_frame(&mut state.reading).await?;
            if identity != self.identity
                || *closed.borrow()
                || self.runtime.shared.lifecycle().ensure_running().is_err()
            {
                self.close();
                return Ok(None);
            }
            state.rows = rows;
            state.next_expiry = next_expiry;
            state.initial = false;
            state.last = tokio::time::Instant::now();
            state.read = state.last;
            return Ok(Some(state.rows.clone()));
        }
        loop {
            // A read a cancelled call left in flight is collected before this
            // call waits for anything: its snapshot may predate notifications
            // that arrived since, and consuming them first would leave a state
            // change behind stale rows until another wake.
            if state.reading.is_none() {
                let mut at = match state.owed {
                    Some(at) => at,
                    None => {
                        #[cfg(test)]
                        self.waits.send_replace(Some(TransferWaitForTest::Wake));
                        let interval = refresh_interval(
                            &state.rows,
                            state.next_expiry,
                            crate::unix_now_seconds(),
                        );
                        let TransferSubscriptionState {
                            updates,
                            presentation,
                            ..
                        } = &mut *state;
                        // Both senders live in the runtime this handle holds, so
                        // neither channel can close under it.
                        let spacing = tokio::select! {
                            biased;
                            _ = closed.changed()=>return Ok(None),
                            _ = wait_for_runtime_shutdown(&mut stopping)=>return Ok(None),
                            _ = updates.changed()=>TRANSFER_READ_FLOOR,
                            // Presentation churn and the idle fallback keep the
                            // window before they read, so they never read more than
                            // four times a second.
                            _ = presentation.recv()=>TRANSFER_FRAME_INTERVAL,
                            // Slow idle fallback covers external writers; known
                            // expiry gets its own deadline even when every row is
                            // already ready.
                            _ = tokio::time::sleep(interval)=>TRANSFER_FRAME_INTERVAL,
                        };
                        state.owed = Some(state.read + spacing);
                        state.read + spacing
                    }
                };
                #[cfg(test)]
                self.waits.send_replace(Some(match state.held {
                    Some(_) => TransferWaitForTest::Held,
                    None => TransferWaitForTest::Read(at.saturating_duration_since(state.read)),
                }));
                // A transfer notification moves the read to the read floor: forward,
                // so a state change is never held behind presentation churn or
                // behind progress waiting out the window, and never closer to the
                // previous read than the floor.
                loop {
                    let TransferSubscriptionState { updates, .. } = &mut *state;
                    let notified = tokio::select! {
                        biased;
                        _ = closed.changed()=>return Ok(None),
                        _ = wait_for_runtime_shutdown(&mut stopping)=>return Ok(None),
                        // Ahead of the deadline, so a notification that lands as
                        // it passes still counts: held rows are delivered only
                        // when nothing was reported since.
                        _ = updates.changed()=>true,
                        _ = tokio::time::sleep_until(at)=>false,
                    };
                    if !notified {
                        break;
                    }
                    state.held = None;
                    at = state.read + TRANSFER_READ_FLOOR;
                    state.owed = Some(at);
                }
                if let Some(rows) = state.held.take() {
                    if *closed.borrow() || self.runtime.shared.lifecycle().ensure_running().is_err()
                    {
                        self.close();
                        return Ok(None);
                    }
                    state.owed = None;
                    state.last = tokio::time::Instant::now();
                    state.rows = rows.clone();
                    return Ok(Some(rows));
                }
            }
            let storage_sqlite::AttachmentTransferFrame {
                store_epoch: identity,
                rows,
                next_expiry,
            } = self.read_frame(&mut state.reading).await?;
            if identity != self.identity
                || *closed.borrow()
                || self.runtime.shared.lifecycle().ensure_running().is_err()
            {
                self.close();
                return Ok(None);
            }
            state.read = tokio::time::Instant::now();
            state.owed = None;
            state.next_expiry = next_expiry;
            if rows == state.rows {
                continue;
            }
            let deadline = state.last + TRANSFER_FRAME_INTERVAL;
            if changes_transfer_state(&state.rows, &rows) || state.read >= deadline {
                state.last = state.read;
                state.rows = rows.clone();
                return Ok(Some(rows));
            }
            // Progress alone waits out the window: the rows are delivered at its
            // end, or read again on a transfer notification before then.
            state.held = Some(rows);
            state.owed = Some(deadline);
        }
    }
}

/// Minimum spacing of frames that only advance progress (byte counts,
/// totals, attempts or retry times): at most four per second.
const TRANSFER_FRAME_INTERVAL: Duration = Duration::from_millis(250);

/// Minimum spacing of the reads transfer notifications trigger. Workers
/// throttle their progress writes, but every account's transfers wake every
/// subscription, so a handle bounds its own reads rather than rely on that.
const TRANSFER_READ_FLOOR: Duration = Duration::from_millis(25);

/// Whether a replacement frame changes what a row is rather than how far it
/// has got: a row appearing, disappearing or entering another transfer state.
/// Such frames skip the progress coalescing window. A transfer that restarts
/// in the state it was in, such as a new download attempt, counts as progress.
fn changes_transfer_state(
    previous: &[Option<AttachmentTransferStatus>],
    next: &[Option<AttachmentTransferStatus>],
) -> bool {
    previous.len() != next.len()
        || previous
            .iter()
            .zip(next)
            .any(|(previous, next)| match (previous, next) {
                (Some(previous), Some(next)) => previous.state != next.state,
                (None, None) => false,
                _ => true,
            })
}

fn refresh_interval(
    rows: &[Option<AttachmentTransferStatus>],
    next_expiry: Option<u64>,
    now: u64,
) -> Duration {
    let active = rows.iter().flatten().any(|row| {
        matches!(
            row.state,
            AttachmentTransferState::Queued
                | AttachmentTransferState::Downloading
                | AttachmentTransferState::VerifyingCiphertext
                | AttachmentTransferState::Decrypting
                | AttachmentTransferState::VerifyingPlaintext
                | AttachmentTransferState::RetryScheduled
        )
    });
    let seconds = if active { 1 } else { 30 };
    Duration::from_secs(
        next_expiry.map_or(seconds, |expiry| seconds.min(expiry.saturating_sub(now))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Only a row appearing, disappearing or changing transfer state skips the
    /// progress window; bytes, totals, attempts and retry times do not.
    #[test]
    fn only_state_and_presence_changes_skip_the_progress_window() {
        let row = |state, received| {
            Some(AttachmentTransferStatus {
                reference: None,
                automatic_media_type: None,
                state,
                attempt: 1,
                received,
                total: Some(100),
                retry_at: None,
            })
        };
        let downloading = vec![row(AttachmentTransferState::Downloading, 10)];
        let mut progressed = vec![row(AttachmentTransferState::Downloading, 90)];
        assert!(!changes_transfer_state(&downloading, &progressed));
        progressed[0].as_mut().unwrap().attempt = 2;
        progressed[0].as_mut().unwrap().retry_at = Some(5);
        assert!(!changes_transfer_state(&downloading, &progressed));
        let ready = vec![row(AttachmentTransferState::Ready, 100)];
        assert!(changes_transfer_state(&downloading, &ready));
        assert!(changes_transfer_state(&downloading, &[None]));
        assert!(changes_transfer_state(&[None], &downloading));
        assert!(!changes_transfer_state(&[None], &[None]));
        assert!(changes_transfer_state(&downloading, &[]));
    }

    #[test]
    fn attachment_idle_refresh_is_slow_but_never_misses_known_expiry() {
        let mut rows = vec![Some(AttachmentTransferStatus {
            reference: None,
            automatic_media_type: None,
            state: AttachmentTransferState::Ready,
            attempt: 0,
            received: 0,
            total: None,
            retry_at: None,
        })];
        assert_eq!(refresh_interval(&rows, None, 10), Duration::from_secs(30));
        assert_eq!(
            refresh_interval(&rows, Some(12), 10),
            Duration::from_secs(2)
        );
        assert_eq!(refresh_interval(&rows, Some(10), 10), Duration::ZERO);
        rows[0].as_mut().unwrap().state = AttachmentTransferState::Downloading;
        assert_eq!(refresh_interval(&rows, None, 10), Duration::from_secs(1));
    }
}
