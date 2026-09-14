//! Explicit recovery of opaque or exhausted onboarding checkpoints.
use super::*;
use rand::{RngCore, rngs::OsRng};

#[derive(Serialize, Deserialize)]
pub(super) struct OnboardingRecovery {
    version: u32,
    account_id: String,
    pub(super) epoch: String,
    completed: bool,
    // Latest recovery only, accessible through AccountHome's journal reader.
    // These are opaque evidence, never inputs to automatic replay.
    active: Option<Vec<u8>>,
    cancelled: Option<Vec<u8>>,
    #[serde(default)]
    previous_recovery: Option<Vec<u8>>,
}

impl AccountManager {
    pub(super) fn read_onboarding_recovery(
        &self,
        account_ref: &str,
    ) -> Result<Option<OnboardingRecovery>, AppError> {
        let account = self.resolve(account_ref)?;
        let Some(bytes) = self
            .app
            .account_home()
            .account_onboarding_recovery(&account.label)?
        else {
            return Ok(None);
        };
        let recovery: OnboardingRecovery =
            serde_json::from_slice(&bytes).map_err(|_| onboarding_error())?;
        if recovery.version != 1
            || recovery.account_id != account.account_id_hex
            || recovery.epoch.len() != 64
            || !recovery.epoch.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(onboarding_error());
        }
        Ok(Some(recovery))
    }

    pub(super) fn onboarding_recovery_pending(&self, account_ref: &str) -> Result<bool, AppError> {
        Ok(self
            .read_onboarding_recovery(account_ref)?
            .is_some_and(|r| !r.completed))
    }

    /// Hosts can offer explicit recovery when begin/cancel returns
    /// OnboardingActionUnavailable and this query returns true. Recovery is not
    /// automatic and never interprets unknown bytes as approval or retry intent.
    pub fn onboarding_recovery_required(&self, account_ref: &str) -> Result<bool, AppError> {
        let account = self.resolve(account_ref)?;
        match self.read_onboarding_recovery(&account.label) {
            Ok(Some(r)) if !r.completed => return Ok(true),
            Err(_) => return Ok(true),
            _ => {}
        }
        let home = self.app.account_home();
        let active = home.account_onboarding(&account.label)?;
        let cancelled = home.cancelled_account_onboarding(&account.label)?;
        if active.is_none()
            && cancelled.is_none()
            && self.read_onboarding_recovery(&account.label)?.is_some()
        {
            return Ok(true);
        }
        for bytes in [active, cancelled].into_iter().flatten() {
            match decode_onboarding_checkpoint(&bytes, &account.account_id_hex) {
                Ok(c) if c.high_water() < u64::MAX => {}
                _ => return Ok(true),
            }
        }
        Ok(false)
    }

    /// Retire unreadable/unsupported or exhausted onboarding state explicitly.
    /// Retains exact opaque bytes in the latest private recovery journal, keeps
    /// identity/setup data, signs out and reaps the worker. The returned epoch
    /// must accompany future approval/device-acknowledgment calls. A separate
    /// begin is required; recovery never inherits a proposal or sends a repair.
    ///
    /// A true acknowledgment accepts latest-only evidence retention. Older
    /// recovery evidence may be replaced by a later explicit recovery. Dropping
    /// this caller does not stop owned cleanup; retry or reconcile completes it.
    pub async fn recover_onboarding(
        &self,
        account_ref: &str,
        acknowledge_latest_only_evidence: bool,
    ) -> Result<String, AppError> {
        self.shared.lifecycle().ensure_running()?;
        if !acknowledge_latest_only_evidence {
            return Err(onboarding_error());
        }
        let account = self.resolve(account_ref)?;
        let (receive, epoch) = {
            let mut tasks = self
                .onboarding_cancellations
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if !tasks.accepting {
                return Err(onboarding_error());
            }
            let state = self.onboarding_state_lock(&account.account_id_hex);
            let _state = state.lock().unwrap_or_else(|p| p.into_inner());
            self.shared.lifecycle().ensure_running()?;
            let home = self.app.account_home();
            // An unreadable recovery journal is evidence too. Explicit recovery
            // may replace it only after retaining its exact opaque bytes.
            let previous = self.read_onboarding_recovery(&account.label);
            let previous_recovery = if previous.is_err() {
                home.account_onboarding_recovery(&account.label)?
            } else {
                None
            };
            let previous = previous.ok().flatten();
            let recovery = if let Some(pending) = previous.filter(|r| !r.completed) {
                pending
            } else {
                if !self.onboarding_recovery_required(&account.label)? {
                    // Retrying a completed recovery before an explicit begin is
                    // harmless. Never retire a healthy new attempt on retry.
                    if home.account_onboarding(&account.label)?.is_none()
                        && let Some(previous) = self.read_onboarding_recovery(&account.label)?
                        && let Some(cancelled) =
                            self.read_cancelled_onboarding_checkpoint_for(&account)?
                        && cancelled.high_water() == 0
                        && cancelled.snapshot.recovery_epoch.as_deref()
                            == Some(previous.epoch.as_str())
                    {
                        return Ok(previous.epoch);
                    }
                    return Err(onboarding_error());
                }
                let mut random = [0u8; 32];
                OsRng.fill_bytes(&mut random);
                let recovery = OnboardingRecovery {
                    version: 1,
                    account_id: account.account_id_hex.clone(),
                    epoch: hex::encode(random),
                    completed: false,
                    active: home.account_onboarding(&account.label)?,
                    cancelled: home.cancelled_account_onboarding(&account.label)?,
                    previous_recovery,
                };
                home.set_account_onboarding_recovery(
                    &account.label,
                    &serde_json::to_vec(&recovery)?,
                )?;
                recovery
            };
            // Different epochs retire every old live waiter, including legacy
            // generation zero. The new epoch begins at revision one, above zero.
            use sha2::{Digest, Sha256};
            self.publish_onboarding_retirement(
                &account.account_id_hex,
                OnboardingAttempt {
                    revision: 0,
                    epoch: Some(Sha256::digest(recovery.epoch.as_bytes()).into()),
                },
            );
            self.onboarding_updates
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&account.account_id_hex);
            let epoch = recovery.epoch;
            let (send, receive) = tokio::sync::oneshot::channel();
            let manager = self.clone();
            let account = account.clone();
            retain_unfinished_onboarding_handles(&mut tasks);
            tasks.handles.push(tokio::spawn(async move {
                let result = async {
                    let _workers = timeout(
                        ONBOARDING_CANCELLATION_WAIT,
                        manager.worker_transactions.lock(),
                    )
                    .await
                    .map_err(|_| AppError::AccountWorkerResponseTimedOut)?;
                    manager.finish_onboarding_recovery_locked(&account).await
                }
                .await;
                let _ = send.send(result);
            }));
            (receive, epoch)
        };
        timeout(ONBOARDING_CANCELLATION_WAIT, receive)
            .await
            .map_err(|_| AppError::AccountWorkerResponseTimedOut)?
            .map_err(|_| onboarding_error())??;
        Ok(epoch)
    }

    // Every caller holds worker_transactions. Removed workers enter the same
    // runtime-owned reaper tracking as cancellation, before any await.
    pub(super) async fn finish_onboarding_recovery_locked(
        &self,
        account: &AccountSummary,
    ) -> Result<(), AppError> {
        self.shared.lifecycle().ensure_running()?;
        let Some(mut recovery) = self
            .read_onboarding_recovery(&account.label)?
            .filter(|r| !r.completed)
        else {
            return Ok(());
        };
        self.app
            .account_home()
            .set_account_signed_out(&account.label, true)?;
        if let Some(worker) = self.workers.lock().await.remove(&account.account_id_hex) {
            self.start_tracked_worker_reap(
                &account.account_id_hex,
                worker,
                crate::APP_RUNTIME_ACCOUNT_SHUTDOWN_WAIT,
            );
        }
        self.await_tracked_worker_reap(&account.account_id_hex, ONBOARDING_CANCELLATION_WAIT)
            .await?;
        self.app.drop_account_caches(&account.label);
        let state = self.onboarding_state_lock(&account.account_id_hex);
        let _state = state.lock().unwrap_or_else(|p| p.into_inner());
        // Terminal close can release the root lease while a reaper is pending.
        // Leave intent for the next runtime instead of writing a late tombstone
        // over state that a newly opened runtime may already have recovered.
        self.shared.lifecycle().ensure_running()?;
        let mut tombstone = OnboardingCheckpoint::new(
            account,
            OnboardingOptions {
                default_relays: Vec::new(),
                discovery_relays: Vec::new(),
            },
        );
        tombstone.version = RECOVERED_ONBOARDING_VERSION;
        tombstone.snapshot.recovery_epoch = Some(recovery.epoch.clone());
        tombstone.snapshot.cancellation_pending = true;
        self.app
            .account_home()
            .finish_recovered_account_onboarding(
                &account.label,
                &serde_json::to_vec(&tombstone)?,
            )?;
        recovery.completed = true;
        self.app
            .account_home()
            .set_account_onboarding_recovery(&account.label, &serde_json::to_vec(&recovery)?)?;
        Ok(())
    }
}

use super::cancellation::retain_unfinished_onboarding_handles;
