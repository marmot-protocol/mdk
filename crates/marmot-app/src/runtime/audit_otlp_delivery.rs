//! One explicit audit export attempt. No scheduler or native activation.

use marmot_forensics::local_delivery::{DeliveryStep, LocalAuditDelivery, Preparation};

use crate::audit_otlp_sender::{AuditOtlpSendResult, AuditOtlpSender};
use crate::{AppError, MarmotApp};

use super::{MarmotAppRuntime, RuntimeLifecycle, blocking_app_task};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuditOtlpAttemptOutcome {
    Busy,
    Cancelled,
    Local(DeliveryStep),
    Sent {
        receiver: AuditOtlpSendResult,
        local: Option<DeliveryStep>,
    },
}

impl MarmotAppRuntime {
    /// Runs at most one prepared batch for an explicitly supplied account and
    /// sender. The sender is not stored by the runtime; no automatic pass can
    /// be started by enabling recording or changing aggregate telemetry.
    #[allow(dead_code)] // Inactive until an independently reviewed caller is added.
    pub(crate) async fn send_audit_otlp_once(
        &self,
        account_ref: &str,
        sender: &AuditOtlpSender,
    ) -> Result<AuditOtlpAttemptOutcome, AppError> {
        let app = self.accounts.app.clone();
        let lifecycle = self.shared.lifecycle();
        lifecycle.ensure_running()?;
        let account = app.account_home().account(account_ref)?;
        // Open shared storage before nested local admission. Its cached read
        // then cannot recursively acquire storage_lifecycle behind a writer.
        if !app.audit_log_settings()?.enabled {
            return Ok(AuditOtlpAttemptOutcome::Cancelled);
        }
        let Some(attempt) = app
            .audit_export_lifecycle
            .reserve(&account.account_id_hex, sender.destination())
        else {
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
                        let state_dir = app.account_dir(&account_label).join("audit-otlp-delivery");
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
        let local = blocking_app_task(move || {
            app.with_audit_export_admission(&attempt, || {
                if !check_live(&app, &finish_lifecycle, &account_id, &account_label)? {
                    return Ok(None);
                }
                let active = app.audit_delivery_active_path(&account_label)?;
                let state_dir = app.account_dir(&account_label).join("audit-otlp-delivery");
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
                if self
                    .accounts
                    .app
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
