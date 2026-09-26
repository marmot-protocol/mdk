//! One v5 audit export attempt shared by manual and scheduled tracker passes.

use std::sync::{Arc, Mutex as StdMutex};

use marmot_forensics::local_delivery::{DeliveryStep, LocalAuditDelivery, Preparation};

use crate::audit_otlp_sender::{AuditOtlpSendResult, AuditOtlpSender};
use crate::{AppError, MarmotApp};

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
    let app = app.clone();
    let lifecycle = lifecycle.clone();
    lifecycle.ensure_running()?;
    let account = app.account_home().account(account_ref)?;
    // Open shared storage before nested local admission. Its cached read
    // then cannot recursively acquire storage_lifecycle behind a writer.
    if !app.audit_log_settings()?.enabled {
        return Ok(AuditOtlpAttemptOutcome::Cancelled);
    }
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
            return Ok(AuditOtlpAttemptOutcome::Cancelled);
        }
        app.audit_export_lifecycle
            .reserve(&account.account_id_hex, sender.destination())
    } else {
        app.audit_export_lifecycle
            .reserve(&account.account_id_hex, sender.destination())
    };
    let Some(attempt) = attempt else {
        return Ok(AuditOtlpAttemptOutcome::Busy);
    };
    let account_id = account.account_id_hex;
    let account_label = account.label;
    let (attempt, preparation) = blocking_app_task({
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
                    let state_dir = app
                        .account_dir(&account_label)
                        .join("audit-otlp-delivery-v5");
                    let mut local =
                        LocalAuditDelivery::open(active, state_dir, attempt.destination())?;
                    Ok(Some(local.prepare_once()?))
                })?
                .flatten();
            Ok((attempt, preparation))
        }
    })
    .await?;
    let Some(preparation) = preparation else {
        return Ok(AuditOtlpAttemptOutcome::Cancelled);
    };
    let Preparation::Batch(batch) = preparation else {
        let Preparation::Step(step) = preparation else {
            unreachable!()
        };
        return Ok(AuditOtlpAttemptOutcome::Local(step));
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
        return Ok(AuditOtlpAttemptOutcome::Cancelled);
    }
    let receiver = sender.send(batch).await;
    let Some(action) = receiver.for_finish() else {
        return Ok(AuditOtlpAttemptOutcome::Sent {
            receiver,
            local: None,
        });
    };
    let finish_lifecycle = lifecycle.clone();
    let app_for_close = app.clone();
    let local = blocking_app_task(move || {
        app.with_audit_export_admission(&attempt, || {
            if !check_live(&app, &finish_lifecycle, &account_id, &account_label)? {
                return Ok(None);
            }
            let active = app.audit_delivery_active_path(&account_label)?;
            let state_dir = app
                .account_dir(&account_label)
                .join("audit-otlp-delivery-v5");
            let mut owner = LocalAuditDelivery::open(active, state_dir, attempt.destination())?;
            Ok(Some(owner.finish(&token, action)?))
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
    Ok(AuditOtlpAttemptOutcome::Sent { receiver, local })
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
