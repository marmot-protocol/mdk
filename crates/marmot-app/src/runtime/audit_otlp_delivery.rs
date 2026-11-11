//! One v5 audit export attempt shared by manual and scheduled tracker passes.

use std::sync::{Arc, Mutex as StdMutex};

use marmot_forensics::local_delivery::{
    DeliveryBacklog, DeliveryStep, LocalAuditDelivery, Preparation,
};

use crate::audit_export_lifecycle::AuditExportAttempt;
use crate::{AppError, MarmotApp};
use marmot_observability::{AuditOtlpSendResult, AuditOtlpSender};

use super::audit_delivery_status::{AuditDeliveryPass, audit_delivery_state_dir, record_pass};
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
    attempt_audit_otlp_once(app, lifecycle, account_ref, sender, configured_sender)
        .await
        .map(|(outcome, _)| outcome)
}

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

/// Fold one tracker pass into the account's persisted delivery status under
/// the same admission as cursor work. A busy or fenced account skips the
/// write; its own pass records the newer outcome.
pub(crate) async fn record_audit_delivery_pass(
    app: &MarmotApp,
    lifecycle: &RuntimeLifecycle,
    account_ref: &str,
    sender: &Arc<AuditOtlpSender>,
    configured_sender: Option<&Arc<StdMutex<Option<Arc<AuditOtlpSender>>>>>,
    pass: AuditDeliveryPass,
) -> Result<(), AppError> {
    if pass.is_empty() {
        return Ok(());
    }
    let Reservation::Reserved {
        attempt,
        account_id,
        account_label,
    } = reserve(app, lifecycle, account_ref, sender, configured_sender).await?
    else {
        return Ok(());
    };
    let app = app.clone();
    let lifecycle = lifecycle.clone();
    let sender = sender.clone();
    blocking_app_task(move || {
        app.with_audit_export_admission(&attempt, || {
            if !check_live(&app, &lifecycle, &account_id, &account_label)? {
                return Ok(());
            }
            record_pass(
                &audit_delivery_state_dir(&app, &account_label),
                &sender,
                &pass,
            )
        })
        .map(|_| ())
    })
    .await
}

/// One attempt, plus the cursor's backlog as last observed under admission.
pub(crate) async fn attempt_audit_otlp_once(
    app: &MarmotApp,
    lifecycle: &RuntimeLifecycle,
    account_ref: &str,
    sender: &AuditOtlpSender,
    configured_sender: Option<&Arc<StdMutex<Option<Arc<AuditOtlpSender>>>>>,
) -> Result<(AuditOtlpAttemptOutcome, Option<DeliveryBacklog>), AppError> {
    let app = app.clone();
    let lifecycle = lifecycle.clone();
    let (attempt, account_id, account_label) =
        match reserve(&app, &lifecycle, account_ref, sender, configured_sender).await? {
            Reservation::Reserved {
                attempt,
                account_id,
                account_label,
            } => (attempt, account_id, account_label),
            Reservation::Unavailable(outcome) => return Ok((outcome, None)),
        };
    let (attempt, prepared) = blocking_app_task({
        let app = app.clone();
        let lifecycle = lifecycle.clone();
        let account_id = account_id.clone();
        let account_label = account_label.clone();
        move || {
            let preparation = app
                .with_audit_export_admission(&attempt, || {
                    if !check_live(&app, &lifecycle, &account_id, &account_label)? {
                        return Ok(None);
                    }
                    let active = app.audit_delivery_active_path(&account_label)?;
                    let state_dir = audit_delivery_state_dir(&app, &account_label);
                    let mut local =
                        LocalAuditDelivery::open(active, state_dir, attempt.destination())?;
                    let preparation = local.prepare_once()?;
                    let backlog = local.backlog();
                    if let Preparation::Batch(batch) = &preparation {
                        let source =
                            local
                                .prepared_source_identity(&batch.token)
                                .ok_or_else(|| {
                                    AppError::AuditLogUpload("prepared audit source missing".into())
                                })?;
                        app.audit_export_lifecycle.prepared_source(&attempt, source);
                    }
                    Ok(Some((preparation, backlog)))
                })?
                .flatten();
            Ok((attempt, preparation))
        }
    })
    .await?;
    let Some((preparation, backlog)) = prepared else {
        return Ok((AuditOtlpAttemptOutcome::Cancelled, None));
    };
    let Preparation::Batch(batch) = preparation else {
        let Preparation::Step(step) = preparation else {
            unreachable!()
        };
        return Ok((AuditOtlpAttemptOutcome::Local(step), Some(backlog)));
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
        return Ok((AuditOtlpAttemptOutcome::Cancelled, Some(backlog)));
    }
    let receiver = sender.send(batch).await;
    let Some(action) = receiver.for_finish() else {
        return Ok((
            AuditOtlpAttemptOutcome::Sent {
                receiver,
                local: None,
            },
            Some(backlog),
        ));
    };
    let finish_lifecycle = lifecycle.clone();
    let app_for_close = app.clone();
    let local = blocking_app_task(move || {
        app.with_audit_export_admission(&attempt, || {
            if !check_live(&app, &finish_lifecycle, &account_id, &account_label)? {
                return Ok(None);
            }
            let active = app.audit_delivery_active_path(&account_label)?;
            let state_dir = audit_delivery_state_dir(&app, &account_label);
            let mut owner = LocalAuditDelivery::open(active, state_dir, attempt.destination())?;
            let step = owner.finish(&token, action)?;
            Ok(Some((step, owner.backlog())))
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
    let (local, backlog) = match local {
        Some((step, finished)) => (Some(step), finished),
        None => (None, backlog),
    };
    Ok((
        AuditOtlpAttemptOutcome::Sent { receiver, local },
        Some(backlog),
    ))
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
