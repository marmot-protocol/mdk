//! Forensic audit-log tracker upload worker and one-shot tracker update.

use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use super::{RuntimeLifecycle, runtime_shutdown_requested, wait_for_runtime_shutdown};
use crate::audit_log::{AUDIT_LOG_UPLOAD_MAX_BYTES, AuditUploadOutcome};
use crate::{
    AppError, AuditLogFile, AuditLogTrackerConfig, AuditLogTrackerUpdateResult, MarmotApp,
};

/// Trigger queue depth. One slot is the coalescing contract (mdk#1181): a
/// burst of send/receive/convergence triggers arriving while an update is
/// scheduled or running collapses into exactly one follow-up run — `schedule`
/// drops triggers that find the slot full, and the worker never starts a second
/// update concurrently because it drains the slot only between runs.
const APP_RUNTIME_AUDIT_TRACKER_QUEUE: usize = 1;

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
    mut commands: mpsc::Receiver<&'static str>,
    mut stopping: watch::Receiver<bool>,
) {
    loop {
        if runtime_shutdown_requested(&stopping) {
            break;
        }
        let Some(mut trigger) = (tokio::select! {
            _ = wait_for_runtime_shutdown(&mut stopping) => None,
            trigger = commands.recv() => trigger,
        }) else {
            break;
        };

        loop {
            let config = config
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            if config.upload_allowed_with_endpoints(app.service_endpoints()) {
                match post_audit_log_tracker_update_for_app(&app, config).await {
                    Ok(result) => {
                        if let Some(skipped_reason) = result.skipped_reason.as_deref() {
                            tracing::debug!(
                                target: "marmot_app::audit_log",
                                method = "schedule_audit_log_tracker_update",
                                trigger,
                                skipped_reason,
                                "skipped forensic audit log tracker update"
                            );
                        } else {
                            tracing::debug!(
                                target: "marmot_app::audit_log",
                                method = "schedule_audit_log_tracker_update",
                                trigger,
                                uploaded = result.uploaded.len(),
                                "posted forensic audit log tracker update"
                            );
                        }
                    }
                    Err(_err) => {
                        tracing::warn!(
                            target: "marmot_app::audit_log",
                            method = "schedule_audit_log_tracker_update",
                            trigger,
                            error = "audit_log_tracker_update_failed",
                            "failed to post forensic audit log tracker update"
                        );
                    }
                }
            }

            if runtime_shutdown_requested(&stopping) {
                return;
            }
            match commands.try_recv() {
                Ok(next) => trigger = next,
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => return,
            }
        }
    }
}

pub(crate) async fn post_audit_log_tracker_update_for_app(
    app: &MarmotApp,
    config: AuditLogTrackerConfig,
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

    let mut uploaded = Vec::new();
    let mut failed = 0_usize;
    let mut acknowledged = 0_usize;
    let mut too_large = 0_usize;
    // `audit_log_files` sorts by account first, so each account's files arrive
    // as one contiguous run and its checkpoint is loaded and stored once.
    for account_files in group_by_account(files) {
        let account_ref = account_files[0].account_ref.clone();
        let mut checkpoint = app.audit_upload_checkpoint(&account_ref);
        let mut checkpoint_changed =
            checkpoint.retain_present(account_files.iter().map(|file| file.file_name.as_str()));
        for (file_index, file) in account_files.iter().enumerate() {
            // An acknowledged file is never re-read or re-posted. Sealed
            // segments are immutable, so a single 200 is a durable
            // acknowledgment of their whole content; the active file changes on
            // every append and therefore re-transfers in full each trigger.
            // That residual is accepted by design and is bounded by the
            // recorder's segment threshold — a byte-offset acknowledgment
            // protocol was considered and rejected as overkill (mdk#1181).
            if checkpoint.acknowledged(file).is_some() {
                acknowledged += 1;
                continue;
            }
            if file.size_bytes > AUDIT_LOG_UPLOAD_MAX_BYTES {
                // Upgrade path: a file grown past the per-request ceiling by a
                // build without segment rotation. Rotation keeps new files well
                // under the ceiling, so this can only be a legacy artifact.
                // Splitting it is out of scope; record the verdict so it
                // surfaces once instead of failing silently on every trigger,
                // and keep going so it never wedges the other files. A host can
                // still transfer it deliberately via `post_audit_log_file`, and
                // deleting it belongs to mdk#1014.
                too_large += 1;
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
            match app
                .post_audit_log_file_with_tracker_config(&file.path, &config)
                .await
            {
                Ok(result) => {
                    checkpoint.acknowledge(file, result.bytes_sent, AuditUploadOutcome::Uploaded);
                    checkpoint_changed = true;
                    uploaded.push(result);
                }
                Err(_err) => {
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
        }
        // Recorded after the effects it mirrors, so a crash before this point
        // costs one repeat transfer rather than dropping forensic data.
        if checkpoint_changed
            && let Err(err) = app.store_audit_upload_checkpoint(&account_ref, &checkpoint)
        {
            tracing::warn!(
                target: "marmot_app::audit_log",
                method = "post_audit_log_tracker_update",
                error_kind = err.privacy_safe_kind(),
                "failed to persist forensic audit log upload checkpoint"
            );
        }
    }
    if failed > 0 || too_large > 0 {
        tracing::warn!(
            target: "marmot_app::audit_log",
            method = "post_audit_log_tracker_update",
            uploaded = uploaded.len(),
            acknowledged,
            too_large,
            failed,
            "completed forensic audit log tracker update with file upload failures"
        );
    } else {
        tracing::debug!(
            target: "marmot_app::audit_log",
            method = "post_audit_log_tracker_update",
            uploaded = uploaded.len(),
            acknowledged,
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
