//! One v5 audit export attempt shared by manual and scheduled tracker passes.

use std::sync::{Arc, Mutex as StdMutex};

use marmot_forensics::local_delivery::{
    DeliveryBacklog, DeliveryStep, LocalAuditDelivery, Preparation,
};

use crate::audit_export_lifecycle::AuditExportAttempt;
use crate::{AppError, AuditDeliveryFailureKind, MarmotApp};
use marmot_observability::{AuditOtlpSendResult, AuditOtlpSender};

use super::audit_delivery_status::{
    AuditDeliveryObservation, AuditDeliveryStatusTarget, audit_delivery_state_dir,
    classify_attempt_error, paused_for_target, record_observation,
};
use super::{MarmotAppRuntime, RuntimeLifecycle, blocking_app_task};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditOtlpAttemptOutcome {
    Busy,
    Cancelled,
    Local(DeliveryStep),
    Sent {
        receiver: AuditOtlpSendResult,
        local: Option<DeliveryStep>,
    },
}

impl MarmotAppRuntime {
    /// Deliver at most one prepared v5 batch for this account with the supplied
    /// dedicated sender. Calling this is an explicit host opt-in; the same
    /// attempt is used by the configured tracker worker.
    pub async fn send_audit_otlp_once(
        &self,
        account_ref: &str,
        sender: &AuditOtlpSender,
    ) -> Result<AuditOtlpAttemptOutcome, AppError> {
        send_audit_otlp_once_for_app(
            &self.accounts.app,
            &self.shared.lifecycle(),
            account_ref,
            sender,
            None,
        )
        .await
    }
}

pub(crate) async fn send_audit_otlp_once_for_app(
    app: &MarmotApp,
    lifecycle: &RuntimeLifecycle,
    account_ref: &str,
    sender: &AuditOtlpSender,
    configured_sender: Option<&Arc<StdMutex<Option<Arc<AuditOtlpSender>>>>>,
) -> Result<AuditOtlpAttemptOutcome, AppError> {
    attempt_audit_otlp_once(
        app,
        lifecycle,
        account_ref,
        sender,
        configured_sender,
        AttemptStatus::Untracked,
    )
    .await
    .map(|report| report.outcome)
}

/// Whether an attempt records delivery status, and whether it honors a pause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttemptStatus {
    /// A host's direct one-shot attempt: no status.
    Untracked,
    /// A manual tracker update: records status and retries a paused account.
    Manual,
    /// The activity scheduler: records status and skips a paused account.
    Automatic,
}

/// An attempt's outcome and the failure it recorded, for the tracker's log.
pub(crate) struct AttemptReport {
    pub(crate) outcome: AuditOtlpAttemptOutcome,
    pub(crate) failure: Option<(AuditDeliveryFailureKind, Option<u16>)>,
    /// An automatic attempt found the account paused and sent nothing.
    pub(crate) paused: bool,
}

impl AttemptReport {
    fn new(outcome: AuditOtlpAttemptOutcome) -> Self {
        Self {
            outcome,
            failure: None,
            paused: false,
        }
    }
}

type LoggedFailure = Option<(AuditDeliveryFailureKind, Option<u16>)>;

enum Prepared {
    Paused,
    Ready(Preparation, DeliveryBacklog, LoggedFailure),
}

/// Journal block reasons `LocalAuditDelivery::finish` records for receiver
/// verdicts. Any other reason is a local fault.
const RECEIVER_VERDICT_BLOCKS: [&str; 2] = [
    "permanent receiver rejection",
    marmot_forensics::local_delivery::PARTIAL_RECEIVER_BLOCK,
];

enum Reservation {
    Reserved {
        attempt: AuditExportAttempt,
        account_id: String,
        account_label: String,
    },
    Unavailable(AuditOtlpAttemptOutcome),
}

async fn reserve(
    app: &MarmotApp,
    lifecycle: &RuntimeLifecycle,
    account_ref: &str,
    sender: &AuditOtlpSender,
    configured_sender: Option<&Arc<StdMutex<Option<Arc<AuditOtlpSender>>>>>,
) -> Result<Reservation, AppError> {
    lifecycle.ensure_running()?;
    let account = app.account_home().account(account_ref)?;
    // Open shared storage before nested local admission. Its cached read
    // then cannot recursively acquire storage_lifecycle behind a writer.
    if !app.audit_log_settings()?.enabled {
        return Ok(Reservation::Unavailable(AuditOtlpAttemptOutcome::Cancelled));
    }
    let directory = blocking_app_task({
        let directory = app.account_dir(&account.label);
        move || Ok(std::fs::canonicalize(directory)?)
    })
    .await?;
    // A scheduled pass may have captured this sender before a host changes
    // configuration. Hold the config lock through reservation so either its
    // attempt is fenced by mutate_all or it never starts under an old sender.
    let attempt = if let Some(configured_sender) = configured_sender {
        let configured = configured_sender
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !configured
            .as_deref()
            .is_some_and(|current| std::ptr::eq(current, sender))
        {
            return Ok(Reservation::Unavailable(AuditOtlpAttemptOutcome::Cancelled));
        }
        app.audit_export_lifecycle.reserve(
            &account.account_id_hex,
            marmot_observability::wiring::audit_destination(sender),
            &directory,
        )
    } else {
        app.audit_export_lifecycle.reserve(
            &account.account_id_hex,
            marmot_observability::wiring::audit_destination(sender),
            &directory,
        )
    };
    Ok(match attempt {
        Some(attempt) => Reservation::Reserved {
            attempt,
            account_id: account.account_id_hex,
            account_label: account.label,
        },
        None => Reservation::Unavailable(AuditOtlpAttemptOutcome::Busy),
    })
}

/// One attempt. A tracked attempt records what it observed as the account's
/// delivery status inside its own admission, before releasing its
/// reservation, so status writes follow the order of attempts. An automatic
/// attempt rechecks the pause under that admission.
pub(crate) async fn attempt_audit_otlp_once(
    app: &MarmotApp,
    lifecycle: &RuntimeLifecycle,
    account_ref: &str,
    sender: &AuditOtlpSender,
    configured_sender: Option<&Arc<StdMutex<Option<Arc<AuditOtlpSender>>>>>,
    mode: AttemptStatus,
) -> Result<AttemptReport, AppError> {
    let app = app.clone();
    let lifecycle = lifecycle.clone();
    let status = (mode != AttemptStatus::Untracked).then(|| AuditDeliveryStatusTarget::new(sender));
    let (attempt, account_id, account_label) =
        match reserve(&app, &lifecycle, account_ref, sender, configured_sender).await? {
            Reservation::Reserved {
                attempt,
                account_id,
                account_label,
            } => (attempt, account_id, account_label),
            Reservation::Unavailable(outcome) => return Ok(AttemptReport::new(outcome)),
        };
    let (attempt, prepared) = blocking_app_task({
        let app = app.clone();
        let lifecycle = lifecycle.clone();
        let account_id = account_id.clone();
        let account_label = account_label.clone();
        let status = status.clone();
        move || {
            let preparation = app
                .with_audit_export_admission(&attempt, || {
                    if !check_live(&app, &lifecycle, &account_id, &account_label)? {
                        return Ok(None);
                    }
                    let state_dir = audit_delivery_state_dir(&app, &account_label);
                    if mode == AttemptStatus::Automatic
                        && status
                            .as_ref()
                            .is_some_and(|target| paused_for_target(target, &state_dir))
                    {
                        return Ok(Some(Prepared::Paused));
                    }
                    let prepared = (|| {
                        let active = app.audit_delivery_active_path(&account_label)?;
                        let mut local =
                            LocalAuditDelivery::open(active, &state_dir, attempt.destination())?;
                        let preparation = local.prepare_once()?;
                        let blocked = local.blocked();
                        let blocked_by_receiver = !blocked.is_empty()
                            && blocked
                                .iter()
                                .all(|(_, reason)| RECEIVER_VERDICT_BLOCKS.contains(reason));
                        if let Preparation::Batch(batch) = &preparation {
                            let source =
                                local
                                    .prepared_source_identity(&batch.token)
                                    .ok_or_else(|| {
                                        AppError::AuditLogUpload(
                                            "prepared audit source missing".into(),
                                        )
                                    })?;
                            app.audit_export_lifecycle.prepared_source(&attempt, source);
                        }
                        Ok::<_, AppError>((preparation, local.backlog(), blocked_by_receiver))
                    })();
                    let mut observation = AuditDeliveryObservation::default();
                    let (preparation, backlog) = match prepared {
                        Ok((preparation, backlog, blocked_by_receiver)) => {
                            match &preparation {
                                Preparation::Step(DeliveryStep::Idle) => observation.caught_up(),
                                Preparation::Step(DeliveryStep::Blocked) if blocked_by_receiver => {
                                    observation.stalled_on_rejection();
                                }
                                Preparation::Step(DeliveryStep::Blocked) => {
                                    observation.failed(AuditDeliveryFailureKind::LocalBlocked, None)
                                }
                                _ => {}
                            }
                            (preparation, backlog)
                        }
                        Err(error) => {
                            observation.failed(classify_attempt_error(&error), None);
                            record_observation(status.as_ref(), &state_dir, &observation);
                            return Err(error);
                        }
                    };
                    // A prepared batch records once the receiver has answered.
                    if matches!(preparation, Preparation::Step(_)) {
                        observation.observed(backlog);
                        record_observation(status.as_ref(), &state_dir, &observation);
                    }
                    Ok(Some(Prepared::Ready(
                        preparation,
                        backlog,
                        observation.logged_failure(),
                    )))
                })?
                .flatten();
            Ok((attempt, preparation))
        }
    })
    .await?;
    let (preparation, backlog, failure) = match prepared {
        None => return Ok(AttemptReport::new(AuditOtlpAttemptOutcome::Cancelled)),
        Some(Prepared::Paused) => {
            return Ok(AttemptReport {
                paused: true,
                ..AttemptReport::new(AuditOtlpAttemptOutcome::Cancelled)
            });
        }
        Some(Prepared::Ready(preparation, backlog, failure)) => (preparation, backlog, failure),
    };
    let Preparation::Batch(batch) = preparation else {
        let Preparation::Step(step) = preparation else {
            unreachable!()
        };
        return Ok(AttemptReport {
            failure,
            ..AttemptReport::new(AuditOtlpAttemptOutcome::Local(step))
        });
    };
    let token = batch.token.clone();

    // Check immediately before HTTP. The local admission and all file/DB
    // handles are released when this blocking task returns.
    let (attempt, still_live) = blocking_app_task({
        let app = app.clone();
        let lifecycle = lifecycle.clone();
        let account_id = account_id.clone();
        let account_label = account_label.clone();
        move || {
            let live = app
                .with_audit_export_admission(&attempt, || {
                    check_live(&app, &lifecycle, &account_id, &account_label)
                })?
                .unwrap_or(false);
            Ok((attempt, live))
        }
    })
    .await?;
    if !still_live {
        return Ok(AttemptReport::new(AuditOtlpAttemptOutcome::Cancelled));
    }
    let receiver = sender.send(batch).await;
    let mut observation = AuditDeliveryObservation::default();
    // A rejected multi-record batch is split and its rows retried, so only
    // the final single-record rejection, recorded as a gap, is a loss.
    let mut rejected_status = None;
    match receiver {
        AuditOtlpSendResult::Complete => {}
        AuditOtlpSendResult::Retryable { http_status } => observation.failed(
            AuditDeliveryFailureKind::ReceiverRetryable,
            Some(http_status),
        ),
        AuditOtlpSendResult::Rejected { http_status } => rejected_status = Some(http_status),
        AuditOtlpSendResult::Blocked { http_status } => {
            observation.failed(AuditDeliveryFailureKind::ReceiverBlocked, http_status)
        }
        AuditOtlpSendResult::Unknown => {
            observation.failed(AuditDeliveryFailureKind::NoResponse, None)
        }
    }
    // Each rejected request is still logged as one.
    let failure =
        observation.logged_failure().or(rejected_status
            .map(|status| (AuditDeliveryFailureKind::ReceiverRejected, Some(status))));
    let Some(action) = receiver.for_finish() else {
        // No local finish: record the verdict (the pause, for a block) under
        // this attempt's admission before its reservation is released.
        if status.is_some() {
            let app = app.clone();
            let lifecycle = lifecycle.clone();
            let recorded = blocking_app_task(move || {
                app.with_audit_export_admission(&attempt, || {
                    if check_live(&app, &lifecycle, &account_id, &account_label)? {
                        observation.observed(backlog);
                        record_observation(
                            status.as_ref(),
                            &audit_delivery_state_dir(&app, &account_label),
                            &observation,
                        );
                    }
                    Ok(())
                })
            })
            .await;
            // Status is advisory; a fenced or closing account skips it.
            let _ = recorded;
        }
        return Ok(AttemptReport {
            failure,
            ..AttemptReport::new(AuditOtlpAttemptOutcome::Sent {
                receiver,
                local: None,
            })
        });
    };
    let finish_lifecycle = lifecycle.clone();
    let app_for_close = app.clone();
    let local = blocking_app_task(move || {
        app.with_audit_export_admission(&attempt, || {
            if !check_live(&app, &finish_lifecycle, &account_id, &account_label)? {
                return Ok(None);
            }
            let state_dir = audit_delivery_state_dir(&app, &account_label);
            let finished = (|| {
                let active = app.audit_delivery_active_path(&account_label)?;
                let mut owner =
                    LocalAuditDelivery::open(active, &state_dir, attempt.destination())?;
                let step = owner.finish(&token, action)?;
                Ok::<_, AppError>((step, owner.backlog()))
            })();
            match finished {
                Ok((step, backlog)) => {
                    if step == DeliveryStep::Accepted {
                        observation.delivered();
                    }
                    if let Some(http_status) = rejected_status.filter(|_| step == DeliveryStep::Gap)
                    {
                        observation.rejected(http_status);
                    }
                    observation.observed(backlog);
                    record_observation(status.as_ref(), &state_dir, &observation);
                    Ok(Some(step))
                }
                Err(error) => {
                    // The receiver's verdict stands; the local failure is
                    // what keeps the range from moving.
                    observation.failed(classify_attempt_error(&error), None);
                    record_observation(status.as_ref(), &state_dir, &observation);
                    Err(error)
                }
            }
        })
    })
    .await;
    // A terminal close can start between HTTP completion and this local
    // admission. It is cancellation, never permission to reopen storage.
    let local = match local {
        Ok(step) => step.flatten(),
        Err(_)
            if app_for_close
                .storage_closed
                .load(std::sync::atomic::Ordering::Acquire)
                || lifecycle.is_stopping() =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    Ok(AttemptReport {
        failure,
        ..AttemptReport::new(AuditOtlpAttemptOutcome::Sent { receiver, local })
    })
}

fn check_live(
    app: &MarmotApp,
    lifecycle: &RuntimeLifecycle,
    account_id: &str,
    label: &str,
) -> Result<bool, AppError> {
    if lifecycle.is_stopping() {
        return Ok(false);
    }
    let Ok(account) = app.account_home().account(label) else {
        return Ok(false);
    };
    Ok(account.account_id_hex == account_id && app.audit_log_settings()?.enabled)
}

#[cfg(test)]
mod tests;
