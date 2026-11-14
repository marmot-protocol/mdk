//! The forensic audit-log tracker: the activity-triggered worker and the
//! one-shot manual pass, both of which run v5 OTLP delivery.

use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::time::{Instant, sleep_until};

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use super::audit_delivery_status::{audit_delivery_paused, classify_attempt_error};
use super::{AttemptStatus, AuditOtlpAttemptOutcome, attempt_audit_otlp_once};
use super::{RuntimeLifecycle, runtime_shutdown_requested, wait_for_runtime_shutdown};
use crate::audit_log::{AuditOtlpTrackerResult, AuditRetentionWorker};
use crate::{AppError, AuditDeliveryFailureKind, AuditLogTrackerUpdateResult, MarmotApp};
use marmot_forensics::local_delivery::DeliveryStep;
use marmot_observability::AuditOtlpSendResult;
use marmot_observability::AuditOtlpSender;

/// Only one follow-up batch is queued while a pass is in flight.
const APP_RUNTIME_AUDIT_TRACKER_QUEUE: usize = 1;
const AUDIT_BATCH_WINDOW: Duration = Duration::from_secs(30);
const AUDIT_RETRY_INITIAL: Duration = Duration::from_secs(60);
const AUDIT_RETRY_MAX: Duration = Duration::from_secs(300);

/// What a finished pass asks of the scheduler: `retry` arms the backoff timer.
#[derive(Default)]
struct AuditPassSchedule {
    retry: bool,
}

impl AuditPassSchedule {
    fn failed(&mut self) {
        self.retry = true;
    }
}

#[derive(Clone, Default)]
struct AuditBatchWindow {
    #[cfg(any(test, feature = "test-policy-overrides"))]
    override_duration: Arc<StdMutex<Option<Duration>>>,
}

impl AuditBatchWindow {
    fn duration(&self) -> Duration {
        #[cfg(any(test, feature = "test-policy-overrides"))]
        if let Some(duration) = *self.override_duration.lock().unwrap() {
            return duration;
        }
        AUDIT_BATCH_WINDOW
    }
}

#[derive(Clone)]
pub(crate) struct AuditLogTrackerUploader {
    app: MarmotApp,
    otlp_sender: Arc<StdMutex<Option<Arc<AuditOtlpSender>>>>,
    lifecycle: RuntimeLifecycle,
    retention: AuditRetentionWorker,
    batch_window: AuditBatchWindow,
    worker: Arc<StdMutex<Option<AuditLogTrackerWorker>>>,
}

struct AuditLogTrackerWorker {
    commands: mpsc::Sender<&'static str>,
    handle: JoinHandle<()>,
}

impl AuditLogTrackerUploader {
    pub(crate) fn new(
        app: MarmotApp,
        otlp_sender: Arc<StdMutex<Option<Arc<AuditOtlpSender>>>>,
        lifecycle: RuntimeLifecycle,
        retention: AuditRetentionWorker,
    ) -> Self {
        Self {
            app,
            otlp_sender,
            lifecycle,
            retention,
            batch_window: AuditBatchWindow::default(),
            worker: Arc::new(StdMutex::new(None)),
        }
    }

    #[cfg(any(test, feature = "test-policy-overrides"))]
    pub(crate) fn set_batch_window_for_test(&self, duration: Duration) {
        *self.batch_window.override_duration.lock().unwrap() = Some(duration);
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
                self.otlp_sender.clone(),
                self.lifecycle.clone(),
                self.retention.clone(),
                receiver,
                stopping,
                self.batch_window.clone(),
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
    otlp_sender: Arc<StdMutex<Option<Arc<AuditOtlpSender>>>>,
    lifecycle: RuntimeLifecycle,
    retention: AuditRetentionWorker,
    commands: mpsc::Receiver<&'static str>,
    stopping: watch::Receiver<bool>,
    window: AuditBatchWindow,
) {
    run_batched_audit_uploads(commands, stopping, window, |trigger| {
        let app = &app;
        let otlp_sender_config = otlp_sender.clone();
        let otlp_sender = otlp_sender
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let lifecycle = lifecycle.clone();
        let retention = retention.clone();
        async move {
            let mut schedule = AuditPassSchedule::default();
            match post_audit_log_tracker_update(
                app,
                otlp_sender.as_deref(),
                Some(&otlp_sender_config),
                &lifecycle,
                true,
                &mut schedule,
            )
            .await
            {
                Ok(result) => {
                    let v5 = result.v5.unwrap_or_default();
                    tracing::debug!(
                        target: "marmot_app::audit_log",
                        method = "schedule_audit_log_tracker_update",
                        trigger,
                        skipped_reason = v5.skipped_reason.as_deref(),
                        accepted_batches = v5.accepted_batches,
                        "completed automatic audit delivery pass"
                    );
                }
                Err(_) => {
                    tracing::warn!(
                        target: "marmot_app::audit_log",
                        method = "schedule_audit_log_tracker_update",
                        trigger,
                        error_kind = "audit_log_tracker_update_failed",
                        "automatic audit delivery pass failed"
                    );
                    schedule.failed();
                }
            }
            // Delivered segments are now evictable under the size budget.
            retention.request_budget_check();
            schedule
        }
    })
    .await;
}

/// Additional triggers join a fixed window without postponing its deadline or
/// shortening a failure cooldown. Incomplete rows wait for the next activity.
async fn run_batched_audit_uploads<F, Fut>(
    mut commands: mpsc::Receiver<&'static str>,
    mut stopping: watch::Receiver<bool>,
    window: AuditBatchWindow,
    mut upload: F,
) where
    F: FnMut(&'static str) -> Fut,
    Fut: Future<Output = AuditPassSchedule>,
{
    let mut deadline = None;
    let mut trigger = "retry";
    let mut retry_delay = AUDIT_RETRY_INITIAL;
    loop {
        if runtime_shutdown_requested(&stopping) {
            return;
        }
        let due = match deadline {
            Some(due) => due,
            None => {
                trigger = tokio::select! {
                    biased;
                    _ = wait_for_runtime_shutdown(&mut stopping) => return,
                    next = commands.recv() => match next { Some(next) => next, None => return },
                };
                Instant::now() + window.duration()
            }
        };
        loop {
            tokio::select! {
                biased;
                _ = wait_for_runtime_shutdown(&mut stopping) => return,
                _ = sleep_until(due) => break,
                next = commands.recv() => if next.is_none() { return; },
            }
        }
        let _ = commands.try_recv();
        let schedule = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => return,
            result = upload(trigger) => result,
        };
        deadline = if schedule.retry {
            trigger = "retry";
            let delay = retry_delay;
            retry_delay = (retry_delay * 2).min(AUDIT_RETRY_MAX);
            Some(Instant::now() + delay)
        } else {
            retry_delay = AUDIT_RETRY_INITIAL;
            match commands.try_recv() {
                Ok(next) => {
                    trigger = next;
                    Some(Instant::now() + window.duration())
                }
                Err(mpsc::error::TryRecvError::Empty) => None,
                Err(mpsc::error::TryRecvError::Disconnected) => return,
            }
        };
    }
}

pub(crate) async fn post_audit_log_tracker_update_for_runtime(
    app: &MarmotApp,
    sender: Option<&AuditOtlpSender>,
    configured_sender: &Arc<StdMutex<Option<Arc<AuditOtlpSender>>>>,
    lifecycle: &RuntimeLifecycle,
) -> Result<AuditLogTrackerUpdateResult, AppError> {
    post_audit_log_tracker_update(
        app,
        sender,
        Some(configured_sender),
        lifecycle,
        false,
        &mut AuditPassSchedule::default(),
    )
    .await
}

/// One tracker pass: v5 OTLP delivery when a sender is configured. A failed
/// pass is reported as skipped and arms the retry timer.
async fn post_audit_log_tracker_update(
    app: &MarmotApp,
    sender: Option<&AuditOtlpSender>,
    configured_sender: Option<&Arc<StdMutex<Option<Arc<AuditOtlpSender>>>>>,
    lifecycle: &RuntimeLifecycle,
    automatic: bool,
    schedule: &mut AuditPassSchedule,
) -> Result<AuditLogTrackerUpdateResult, AppError> {
    let enabled = app.audit_log_settings()?.enabled;
    let Some(sender) = sender else {
        return Ok(AuditLogTrackerUpdateResult { enabled, v5: None });
    };
    let v5 = match post_v5_audit_tracker_update(
        app,
        sender,
        configured_sender,
        lifecycle,
        automatic,
        schedule,
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            schedule.failed();
            AuditOtlpTrackerResult {
                skipped_reason: Some("v5 delivery pass failed".to_owned()),
                ..Default::default()
            }
        }
    };
    Ok(AuditLogTrackerUpdateResult {
        enabled,
        v5: Some(v5),
    })
}

/// Automatic passes skip an account whose delivery is paused after a receiver
/// block; a manual pass (`automatic == false`) is the host's retry and always
/// attempts it. Each attempt records its outcome as the account's delivery status.
async fn post_v5_audit_tracker_update(
    app: &MarmotApp,
    sender: &AuditOtlpSender,
    configured_sender: Option<&Arc<StdMutex<Option<Arc<AuditOtlpSender>>>>>,
    lifecycle: &RuntimeLifecycle,
    automatic: bool,
    schedule: &mut AuditPassSchedule,
) -> Result<AuditOtlpTrackerResult, AppError> {
    let mut summary = AuditOtlpTrackerResult::default();
    if !app.audit_log_settings()?.enabled {
        summary.skipped_reason = Some("audit logging disabled".to_owned());
        return Ok(summary);
    }
    // A pass drains bounded batches so a quiet account with several sealed
    // segments is not stranded waiting for another activity trigger.
    const MAX_BATCHES_PER_ACCOUNT_PASS: usize = 256;
    for account in app.account_home().accounts()? {
        if automatic && audit_delivery_paused(app, &account.label, sender) {
            summary.blocked_accounts += 1;
            continue;
        }
        let mut reached_limit = true;
        for _ in 0..MAX_BATCHES_PER_ACCOUNT_PASS {
            let report = match attempt_audit_otlp_once(
                app,
                lifecycle,
                &account.label,
                sender,
                configured_sender,
                if automatic {
                    AttemptStatus::Automatic
                } else {
                    AttemptStatus::Manual
                },
            )
            .await
            {
                Ok(report) => report,
                Err(error) => {
                    log_v5_delivery_failure(automatic, classify_attempt_error(&error), None);
                    summary.blocked_accounts += 1;
                    schedule.failed();
                    reached_limit = false;
                    break;
                }
            };
            if report.paused {
                summary.blocked_accounts += 1;
                reached_limit = false;
                break;
            }
            if let Some((kind, http_status)) = report.failure {
                log_v5_delivery_failure(automatic, kind, http_status);
            }
            match report.outcome {
                AuditOtlpAttemptOutcome::Sent {
                    receiver: AuditOtlpSendResult::Complete,
                    local: Some(DeliveryStep::Accepted),
                } => summary.accepted_batches += 1,
                // A rejected batch was halved, or a gap was recorded and
                // passed: later records are ready now.
                AuditOtlpAttemptOutcome::Sent {
                    local: Some(DeliveryStep::Split | DeliveryStep::Gap),
                    ..
                }
                | AuditOtlpAttemptOutcome::Local(DeliveryStep::Gap) => {}
                AuditOtlpAttemptOutcome::Local(DeliveryStep::Idle) => {
                    summary.idle_accounts += 1;
                    reached_limit = false;
                    break;
                }
                AuditOtlpAttemptOutcome::Sent {
                    receiver: AuditOtlpSendResult::Blocked { .. },
                    ..
                }
                | AuditOtlpAttemptOutcome::Sent {
                    local: Some(DeliveryStep::Blocked),
                    ..
                }
                | AuditOtlpAttemptOutcome::Local(DeliveryStep::Blocked) => {
                    summary.blocked_accounts += 1;
                    reached_limit = false;
                    break;
                }
                AuditOtlpAttemptOutcome::Cancelled => {
                    summary.pending_accounts += 1;
                    reached_limit = false;
                    break;
                }
                _ => {
                    summary.pending_accounts += 1;
                    schedule.failed();
                    reached_limit = false;
                    break;
                }
            }
        }
        if reached_limit {
            summary.pending_accounts += 1;
            schedule.failed();
        }
    }
    Ok(summary)
}

fn log_v5_delivery_failure(
    automatic: bool,
    kind: AuditDeliveryFailureKind,
    http_status: Option<u16>,
) {
    tracing::warn!(
        target: "marmot_app::audit_log",
        method = "post_v5_audit_tracker_update",
        automatic,
        failure_kind = kind.as_str(),
        http_status,
        "v5 audit delivery attempt failed"
    );
}

#[cfg(test)]
#[path = "audit_tracker_tests.rs"]
mod tests;
