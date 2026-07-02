//! Forensic audit-log tracker upload worker and one-shot tracker update.

use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use super::{RuntimeLifecycle, runtime_shutdown_requested, wait_for_runtime_shutdown};
use crate::{AppError, AuditLogTrackerConfig, AuditLogTrackerUpdateResult, MarmotApp};

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
                        error = %err,
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
    for (file_index, file) in files.into_iter().enumerate() {
        match app
            .post_audit_log_file_with_tracker_config(&file.path, &config)
            .await
        {
            Ok(result) => uploaded.push(result),
            Err(_err) => {
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
    if failed > 0 {
        tracing::warn!(
            target: "marmot_app::audit_log",
            method = "post_audit_log_tracker_update",
            uploaded = uploaded.len(),
            failed,
            "completed forensic audit log tracker update with file upload failures"
        );
    }
    Ok(AuditLogTrackerUpdateResult {
        enabled: true,
        uploaded,
        skipped_reason: None,
    })
}
