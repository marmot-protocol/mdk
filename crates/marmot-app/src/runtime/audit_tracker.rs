//! Forensic audit-log tracker upload worker and one-shot tracker update.

use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::time::{Instant, sleep_until};

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use super::{RuntimeLifecycle, runtime_shutdown_requested, wait_for_runtime_shutdown};
use crate::audit_log::{AUDIT_LOG_UPLOAD_MAX_BYTES, AuditUploadAttempt, AuditUploadOutcome};
use crate::{
    AppError, AuditLogFile, AuditLogTrackerConfig, AuditLogTrackerUpdateResult, MarmotApp,
};

/// Only one follow-up batch is queued while a pass is in flight.
const APP_RUNTIME_AUDIT_TRACKER_QUEUE: usize = 1;
const AUDIT_BATCH_WINDOW: Duration = Duration::from_secs(30);
const AUDIT_RETRY_INITIAL: Duration = Duration::from_secs(60);
const AUDIT_RETRY_MAX: Duration = Duration::from_secs(300);

#[derive(Default)]
struct AuditPassSchedule {
    pending: bool,
    retry_after: Option<Duration>,
}

impl AuditPassSchedule {
    fn failed(&mut self, minimum: Duration) {
        self.retry_after = Some(self.retry_after.unwrap_or_default().max(minimum));
    }
}

#[derive(Clone)]
pub(crate) struct AuditLogTrackerUploader {
    app: MarmotApp,
    config: Arc<StdMutex<AuditLogTrackerConfig>>,
    lifecycle: RuntimeLifecycle,
    worker: Arc<StdMutex<Option<AuditLogTrackerWorker>>>,
}

struct AuditLogTrackerWorker {
    commands: mpsc::Sender<&'static str>,
    handle: JoinHandle<()>,
}

impl AuditLogTrackerUploader {
    pub(crate) fn new(
        app: MarmotApp,
        config: Arc<StdMutex<AuditLogTrackerConfig>>,
        lifecycle: RuntimeLifecycle,
    ) -> Self {
        Self {
            app,
            config,
            lifecycle,
            worker: Arc::new(StdMutex::new(None)),
        }
    }

    pub(crate) fn schedule(&self, trigger: &'static str) {
        let mut worker = self
            .worker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if worker
            .as_ref()
            .is_none_or(|worker| worker.handle.is_finished())
        {
            let (commands, receiver) = mpsc::channel(APP_RUNTIME_AUDIT_TRACKER_QUEUE);
            let stopping = self.lifecycle.subscribe_shutdown();
            let handle = tokio::spawn(run_audit_log_tracker_uploader(
                self.app.clone(),
                self.config.clone(),
                receiver,
                stopping,
            ));
            *worker = Some(AuditLogTrackerWorker { commands, handle });
        }
        let Some(worker) = worker.as_ref() else {
            return;
        };

        match worker.commands.try_send(trigger) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_trigger)) => {
                tracing::debug!(
                    target: "marmot_app::audit_log",
                    method = "schedule_audit_log_tracker_update",
                    "coalesced forensic audit log tracker update trigger"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_trigger)) => {
                tracing::debug!(
                    target: "marmot_app::audit_log",
                    method = "schedule_audit_log_tracker_update",
                    "ignored forensic audit log tracker update trigger after uploader shutdown"
                );
            }
        }
    }

    pub(crate) async fn shutdown(&self) {
        let worker = self
            .worker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(worker) = worker {
            match worker.handle.await {
                Ok(()) => {}
                Err(err) => {
                    tracing::debug!(
                        target: "marmot_app::audit_log",
                        method = "shutdown",
                        error_kind = if err.is_panic() { "panic" } else { "cancelled" },
                        "audit log tracker uploader exited during shutdown"
                    );
                }
            }
        }
    }
}

async fn run_audit_log_tracker_uploader(
    app: MarmotApp,
    config: Arc<StdMutex<AuditLogTrackerConfig>>,
    commands: mpsc::Receiver<&'static str>,
    stopping: watch::Receiver<bool>,
) {
    run_batched_audit_uploads(commands, stopping, || async {
        let config = config.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        let mut schedule = AuditPassSchedule::default();
        if config.upload_allowed_with_endpoints(app.service_endpoints())
            && post_audit_log_tracker_update(&app, config, true, &mut schedule).await.is_err()
        {
            tracing::warn!(target: "marmot_app::audit_log", method = "schedule_audit_log_tracker_update",
                error_kind = "audit_log_tracker_update_failed", "automatic audit upload pass failed");
            schedule.failed(Duration::ZERO);
        }
        schedule
    }).await;
}

/// Fixed windows, not debounce: additional triggers never postpone the deadline.
/// Incomplete snapshots get a quick retry, then back off while idle. Fresh activity
/// restores their normal cadence, but cannot shorten a failure cooldown.
async fn run_batched_audit_uploads<F, Fut>(
    mut commands: mpsc::Receiver<&'static str>,
    mut stopping: watch::Receiver<bool>,
    mut upload: F,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = AuditPassSchedule>,
{
    let mut deadline = None;
    let mut failure_cooldown = false;
    let mut retry_delay = AUDIT_RETRY_INITIAL;
    let mut pending_delay = AUDIT_BATCH_WINDOW;
    loop {
        if runtime_shutdown_requested(&stopping) {
            return;
        }
        let mut due = match deadline {
            Some(due) => due,
            None => {
                tokio::select! {
                    biased;
                    _ = wait_for_runtime_shutdown(&mut stopping) => return,
                    trigger = commands.recv() => if trigger.is_none() { return; },
                }
                Instant::now() + AUDIT_BATCH_WINDOW
            }
        };
        let mut fresh_activity = false;
        loop {
            tokio::select! {
                biased;
                _ = wait_for_runtime_shutdown(&mut stopping) => return,
                _ = sleep_until(due) => break,
                trigger = commands.recv() => {
                    if trigger.is_none() { return; }
                    fresh_activity = true;
                    if !failure_cooldown { due = due.min(Instant::now() + AUDIT_BATCH_WINDOW); }
                },
            }
        }
        // Consume activity already covered by the snapshot about to be taken.
        fresh_activity |= commands.try_recv().is_ok();
        if fresh_activity {
            pending_delay = AUDIT_BATCH_WINDOW;
        }
        let schedule = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => return,
            result = upload() => result,
        };
        failure_cooldown = schedule.retry_after.is_some();
        deadline = if let Some(minimum) = schedule.retry_after {
            pending_delay = AUDIT_BATCH_WINDOW;
            let delay = retry_delay.max(minimum);
            retry_delay = (retry_delay * 2).min(AUDIT_RETRY_MAX);
            Some(Instant::now() + delay)
        } else {
            retry_delay = AUDIT_RETRY_INITIAL;
            match commands.try_recv() {
                Ok(_) => {
                    pending_delay = AUDIT_BATCH_WINDOW;
                    Some(Instant::now() + AUDIT_BATCH_WINDOW)
                }
                Err(mpsc::error::TryRecvError::Empty) if schedule.pending => {
                    let delay = pending_delay;
                    pending_delay = (pending_delay * 2).min(AUDIT_RETRY_MAX);
                    Some(Instant::now() + delay)
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    pending_delay = AUDIT_BATCH_WINDOW;
                    None
                }
                Err(mpsc::error::TryRecvError::Disconnected) => return,
            }
        };
    }
}

pub(crate) async fn post_audit_log_tracker_update_for_app(
    app: &MarmotApp,
    config: AuditLogTrackerConfig,
) -> Result<AuditLogTrackerUpdateResult, AppError> {
    post_audit_log_tracker_update(app, config, false, &mut AuditPassSchedule::default()).await
}

async fn post_audit_log_tracker_update(
    app: &MarmotApp,
    config: AuditLogTrackerConfig,
    automatic: bool,
    schedule: &mut AuditPassSchedule,
) -> Result<AuditLogTrackerUpdateResult, AppError> {
    if !app.audit_log_settings()?.enabled {
        return Ok(AuditLogTrackerUpdateResult {
            enabled: false,
            uploaded: Vec::new(),
            skipped_reason: Some("audit logging disabled".to_owned()),
        });
    }

    if config.resolved_endpoint(app.service_endpoints()).is_none() {
        return Ok(AuditLogTrackerUpdateResult {
            enabled: true,
            uploaded: Vec::new(),
            skipped_reason: Some("audit log tracker endpoint missing".to_owned()),
        });
    }
    if config.authorization_bearer_token.is_none() {
        return Ok(AuditLogTrackerUpdateResult {
            enabled: true,
            uploaded: Vec::new(),
            skipped_reason: Some("audit log tracker authorization token missing".to_owned()),
        });
    }
    if !config.upload_allowed_with_endpoints(app.service_endpoints()) {
        return Ok(AuditLogTrackerUpdateResult {
            enabled: true,
            uploaded: Vec::new(),
            skipped_reason: Some("audit log tracker not configured".to_owned()),
        });
    }

    let files = app.audit_log_files()?;
    if files.is_empty() {
        return Ok(AuditLogTrackerUpdateResult {
            enabled: true,
            uploaded: Vec::new(),
            skipped_reason: Some("audit log files missing".to_owned()),
        });
    }

    let mut stop_batch = false;
    let mut uploaded = Vec::new();
    let mut failed = 0_usize;
    let mut acknowledged = 0_usize;
    let mut too_large_recorded = 0_usize;
    let mut too_large_known = 0_usize;
    // `audit_log_files` sorts by account first, so each account's files arrive
    // as one contiguous run and its checkpoint is loaded and stored once.
    for account_files in group_by_account(files) {
        let account_ref = account_files[0].account_ref.clone();
        let mut checkpoint = app.audit_upload_checkpoint(&account_ref);
        let mut checkpoint_changed =
            checkpoint.retain_present(account_files.iter().map(|file| file.file_name.as_str()));
        for (file_index, file) in account_files.iter().enumerate() {
            if file.size_bytes == 0 {
                continue;
            }
            // An acknowledged file is never re-read or re-posted. Sealed
            // segments normally stop growing; the metadata check also covers a
            // recorder appending after failed rotation compensation. A successful
            // complete snapshot acknowledges their whole content; the active file changes on
            // every append and therefore re-transfers in full each trigger.
            // That residual is accepted by design and is bounded by the
            // recorder's segment threshold — a byte-offset acknowledgment
            // protocol was considered and rejected as overkill (mdk#1181).
            // Both outcomes skip the file, but they are not the same fact: one
            // means the endpoint has the content, the other means it never
            // will. Keep them apart in the aggregates so an operator reading
            // the counts is not told a permanently untransferable file was
            // delivered.
            match checkpoint.acknowledged(file) {
                Some(AuditUploadOutcome::Uploaded) => {
                    acknowledged += 1;
                    continue;
                }
                Some(AuditUploadOutcome::TooLargeToUpload) => {
                    too_large_known += 1;
                    continue;
                }
                None => {}
            }
            if file.size_bytes > AUDIT_LOG_UPLOAD_MAX_BYTES {
                // Upgrade path: a file grown past the per-request ceiling by a
                // build without segment rotation. Rotation keeps new files well
                // under the ceiling, so this can only be a legacy artifact.
                // Splitting it is out of scope; record the verdict so it
                // surfaces once instead of failing silently on every trigger,
                // and keep going so it never wedges the other files.
                //
                // There is no app-level escape hatch: `post_audit_log_file`
                // enforces the same ceiling before it opens a body
                // (`audit_log.rs`, pinned by
                // `post_audit_log_file_rejects_oversized_files_before_upload`),
                // so a file this size is not transferable through any app API.
                // It stays on disk for manual handling, and deleting it belongs
                // to mdk#1014.
                too_large_recorded += 1;
                checkpoint.acknowledge(file, file.size_bytes, AuditUploadOutcome::TooLargeToUpload);
                checkpoint_changed = true;
                tracing::warn!(
                    target: "marmot_app::audit_log",
                    method = "post_audit_log_tracker_update",
                    file_index,
                    size_bytes = file.size_bytes,
                    limit_bytes = AUDIT_LOG_UPLOAD_MAX_BYTES,
                    "skipped forensic audit log file larger than the tracker request limit"
                );
                continue;
            }
            match app.post_audit_log_snapshot(&file.path, &config).await {
                Ok(AuditUploadAttempt::Uploaded(receipt)) => {
                    if receipt.complete
                        && receipt.observed_bytes == file.size_bytes
                        && receipt.modified_at_ms == file.modified_at_ms
                    {
                        checkpoint.acknowledge(
                            file,
                            receipt.result.bytes_sent,
                            AuditUploadOutcome::Uploaded,
                        );
                        checkpoint_changed = true;
                    } else {
                        schedule.pending = true;
                    }
                    uploaded.push(receipt.result);
                }
                // No complete row yet: no request, checkpoint, or failure warning.
                Ok(AuditUploadAttempt::Deferred) => {
                    schedule.pending = true;
                }
                Ok(AuditUploadAttempt::Rejected {
                    status,
                    retry_after: minimum,
                }) => {
                    failed += 1;
                    let delay = minimum
                        .unwrap_or_default()
                        .max(if matches!(status, 401 | 403) {
                            AUDIT_RETRY_MAX
                        } else {
                            Duration::ZERO
                        });
                    schedule.failed(delay);
                    if automatic && matches!(status, 401 | 403 | 429 | 500..=599) {
                        stop_batch = true;
                    }
                    tracing::warn!(target: "marmot_app::audit_log", method = "post_audit_log_tracker_update", http_status = status,
                        "forensic audit upload rejected");
                }
                Err(err) => {
                    schedule.failed(Duration::ZERO);
                    stop_batch = automatic && matches!(err, AppError::AuditLogUpload(_));
                    // Unacknowledged: left out of the checkpoint so the next
                    // trigger retries it.
                    failed += 1;
                    tracing::warn!(
                        target: "marmot_app::audit_log",
                        method = "post_audit_log_tracker_update",
                        file_index,
                        "failed to post forensic audit log file to tracker"
                    );
                }
            }
            if stop_batch {
                break;
            }
        }
        // Recorded after the effects it mirrors, so a crash before this point
        // costs one repeat transfer rather than dropping forensic data.
        if checkpoint_changed
            && let Err(err) = app.store_audit_upload_checkpoint(&account_ref, &checkpoint)
        {
            schedule.failed(Duration::ZERO);
            tracing::warn!(
                target: "marmot_app::audit_log",
                method = "post_audit_log_tracker_update",
                error_kind = err.privacy_safe_kind(),
                "failed to persist forensic audit log upload checkpoint"
            );
        }
        if stop_batch {
            break;
        }
    }
    // Only a newly recorded over-ceiling file warrants a warning: one already
    // in the checkpoint has been reported, and re-warning every trigger is the
    // noise this contract removes. Counts only — no file names or paths.
    if failed > 0 || too_large_recorded > 0 {
        tracing::warn!(
            target: "marmot_app::audit_log",
            method = "post_audit_log_tracker_update",
            uploaded = uploaded.len(),
            uploaded_bytes = uploaded.iter().map(|upload| upload.bytes_sent).sum::<u64>(),
            acknowledged,
            too_large_recorded,
            too_large_known,
            failed,
            "completed forensic audit log tracker update with file upload failures"
        );
    } else {
        tracing::debug!(
            target: "marmot_app::audit_log",
            method = "post_audit_log_tracker_update",
            uploaded = uploaded.len(),
            uploaded_bytes = uploaded.iter().map(|upload| upload.bytes_sent).sum::<u64>(),
            acknowledged,
            too_large_known,
            "completed forensic audit log tracker update"
        );
    }
    Ok(AuditLogTrackerUpdateResult {
        enabled: true,
        uploaded,
        skipped_reason: None,
    })
}

/// Split the account-sorted enumeration into one non-empty run per account.
fn group_by_account(files: Vec<AuditLogFile>) -> Vec<Vec<AuditLogFile>> {
    let mut grouped: Vec<Vec<AuditLogFile>> = Vec::new();
    for file in files {
        match grouped.last_mut() {
            Some(run) if run[0].account_ref == file.account_ref => run.push(file),
            _ => grouped.push(vec![file]),
        }
    }
    grouped
}

#[cfg(test)]
#[path = "audit_tracker_tests.rs"]
mod tests;
