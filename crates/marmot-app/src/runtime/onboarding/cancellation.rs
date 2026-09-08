//! Reversible exit from onboarding; no relay deletions or local identity wipe.
use super::*;
use crate::APP_RUNTIME_ACCOUNT_SHUTDOWN_WAIT;
use crate::runtime::ManagedAccountWorker;

impl AccountManager {
    /// Cancel an interactive onboarding attempt at any step, including approved
    /// or ready checkpoints. The identity stays signed out. Already-sent events
    /// are not rolled back; the local journal and signed bytes are retained.
    pub async fn cancel_onboarding(&self, account_ref: &str) -> Result<(), AppError> {
        self.shared.lifecycle().ensure_running()?;
        let Some((account, attempt)) = self.persist_onboarding_cancellation_intent(account_ref)?
        else {
            return Ok(());
        };
        self.await_onboarding_cancellation(&account, attempt, ONBOARDING_CANCELLATION_WAIT)
            .await
    }

    pub(crate) async fn finish_pending_onboarding_cancellations(&self) {
        #[cfg(test)]
        self.await_onboarding_test_hold(&self.onboarding_test_holds.cancellation_recovery)
            .await;
        let accounts = match self.app.account_home().accounts() {
            Ok(accounts) => accounts,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::onboarding",
                    method = "finish_pending_onboarding_cancellations",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "failed to list accounts while finishing pending cancellations"
                );
                return;
            }
        };
        for account in accounts {
            if self
                .onboarding_recovery_pending(&account.label)
                .unwrap_or(true)
            {
                if self
                    .finish_onboarding_recovery_locked(&account)
                    .await
                    .is_err()
                {
                    tracing::warn!(target: "marmot_app::onboarding", method = "finish_pending_onboarding_cancellations", "left pending onboarding recovery gated");
                }
                continue;
            }
            let pending = match self.read_onboarding_checkpoint_for(&account) {
                Ok(Some(checkpoint)) if checkpoint.snapshot.cancellation_pending => {
                    Some(checkpoint.attempt())
                }
                Ok(_) => None,
                Err(error) => {
                    tracing::warn!(
                        target: "marmot_app::onboarding",
                        method = "finish_pending_onboarding_cancellations",
                        error_kind = error.privacy_safe_kind(),
                        "left one account gated after an unreadable pending cancellation"
                    );
                    None
                }
            };
            if let Some(attempt) = pending
                && let Err(error) = self
                    .complete_onboarding_cancellation(&account, attempt, true)
                    .await
            {
                tracing::warn!(
                    target: "marmot_app::onboarding",
                    method = "finish_pending_onboarding_cancellations",
                    error_kind = error.privacy_safe_kind(),
                    "left one account gated after a pending cancellation failed"
                );
            }
        }
    }

    fn persist_onboarding_cancellation_intent(
        &self,
        account_ref: &str,
    ) -> Result<Option<(AccountSummary, OnboardingAttempt)>, AppError> {
        let account = self.resolve(account_ref)?;
        let state = self.onboarding_state_lock(&account.account_id_hex);
        let _state = state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(mut checkpoint) = self.read_onboarding_checkpoint_for(&account)? else {
            return Ok(None);
        };
        let setup = self
            .app
            .account_home()
            .account_setup_state(&account.label)?;
        if setup
            .as_ref()
            .is_some_and(|s| s.account_id_hex != account.account_id_hex)
        {
            return Err(onboarding_error());
        }
        if checkpoint.snapshot.cancellation_pending {
            return Ok(Some((account, checkpoint.attempt())));
        }
        checkpoint.snapshot.cancellation_pending = true;
        checkpoint.snapshot.ready = false;
        for step in &mut checkpoint.snapshot.steps {
            step.actions = vec![OnboardingAction::CancelOnboarding];
        }
        self.save_onboarding_locked(&mut checkpoint)?;
        self.publish_onboarding_retirement(&account.account_id_hex, checkpoint.attempt());
        Ok(Some((account, checkpoint.attempt())))
    }

    async fn await_onboarding_cancellation(
        &self,
        account: &AccountSummary,
        attempt: OnboardingAttempt,
        budget: Duration,
    ) -> Result<(), AppError> {
        let receiver = self.ensure_onboarding_cancellation_task(account, attempt);
        match timeout(budget, wait_for_cancel_outcome(receiver)).await {
            Ok(OnboardingCancelOutcome::Succeeded) => Ok(()),
            Ok(OnboardingCancelOutcome::TimedOut) | Err(_) => {
                Err(AppError::AccountWorkerResponseTimedOut)
            }
            Ok(OnboardingCancelOutcome::Failed) => Err(onboarding_error()),
        }
    }

    fn ensure_onboarding_cancellation_task(
        &self,
        account: &AccountSummary,
        attempt: OnboardingAttempt,
    ) -> watch::Receiver<Option<OnboardingCancelOutcome>> {
        let mut tasks = self
            .onboarding_cancellations
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(existing) = tasks.inflight.get(&account.account_id_hex)
            && existing.attempt == attempt
        {
            return existing.outcome.subscribe();
        }
        if !tasks.accepting {
            let (_, receiver) = watch::channel(Some(OnboardingCancelOutcome::Failed));
            return receiver;
        }
        let (sender, receiver) = watch::channel(None);
        tasks.inflight.insert(
            account.account_id_hex.clone(),
            OnboardingCancellationInflight {
                attempt,
                outcome: sender.clone(),
            },
        );
        let manager = self.clone();
        let account = account.clone();
        retain_unfinished_onboarding_handles(&mut tasks);
        tasks.handles.push(tokio::spawn(async move {
            let outcome = match manager
                .complete_onboarding_cancellation(&account, attempt, false)
                .await
            {
                Ok(()) => OnboardingCancelOutcome::Succeeded,
                Err(AppError::AccountWorkerResponseTimedOut) => OnboardingCancelOutcome::TimedOut,
                Err(_) => OnboardingCancelOutcome::Failed,
            };
            let _ = sender.send(Some(outcome));
            let mut tasks = manager
                .onboarding_cancellations
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(current) = tasks.inflight.get(&account.account_id_hex)
                && current.attempt == attempt
            {
                tasks.inflight.remove(&account.account_id_hex);
            }
        }));
        receiver
    }

    async fn complete_onboarding_cancellation(
        &self,
        account: &AccountSummary,
        attempt: OnboardingAttempt,
        workers_already_locked: bool,
    ) -> Result<(), AppError> {
        let started = Instant::now();
        let remaining = || ONBOARDING_CANCELLATION_WAIT.saturating_sub(started.elapsed());
        if remaining().is_zero() {
            return Err(AppError::AccountWorkerResponseTimedOut);
        }
        let _worker_guard = if workers_already_locked {
            None
        } else {
            Some(
                timeout(remaining(), self.worker_transactions.lock())
                    .await
                    .map_err(|_| AppError::AccountWorkerResponseTimedOut)?,
            )
        };
        self.finish_onboarding_cancellation_locked(account, attempt, remaining())
            .await
    }

    async fn finish_onboarding_cancellation_locked(
        &self,
        account: &AccountSummary,
        attempt: OnboardingAttempt,
        budget: Duration,
    ) -> Result<(), AppError> {
        let Some(checkpoint) = self.read_onboarding_checkpoint_for(account)? else {
            return Ok(());
        };
        if checkpoint.attempt() != attempt || !checkpoint.snapshot.cancellation_pending {
            return Ok(());
        }
        self.app
            .account_home()
            .set_account_signed_out(&account.label, true)?;
        self.set_account_tearing_down(&account.account_id_hex, true);
        let result = async {
            let worker = self.workers.lock().await.remove(&account.account_id_hex);
            if let Some(worker) = worker {
                self.start_tracked_worker_reap(
                    &account.account_id_hex,
                    worker,
                    budget.min(APP_RUNTIME_ACCOUNT_SHUTDOWN_WAIT),
                );
            }
            self.await_tracked_worker_reap(
                &account.account_id_hex,
                budget.min(APP_RUNTIME_ACCOUNT_SHUTDOWN_WAIT),
            )
            .await?;
            self.app.drop_account_caches(&account.label);
            let setup = self
                .app
                .account_home()
                .account_setup_state(&account.label)?;
            if let Some(setup) = setup.filter(|s| s.kind == AccountSetupKind::InteractiveIdentity) {
                self.app.account_home().begin_account_setup_with(
                    account,
                    setup.reused_account_id_credential,
                    if account.local_signing {
                        AccountSetupKind::ImportedIdentity
                    } else {
                        AccountSetupKind::ExternalSigner
                    },
                    setup.phase,
                )?;
            }
            self.app
                .account_home()
                .archive_account_onboarding(&account.label)?;
            self.close_onboarding_subscription(&account.account_id_hex, &checkpoint.snapshot);
            tracing::debug!(
                target: "marmot_app::onboarding",
                method = "cancel_onboarding",
                "cancelled onboarding and retained the signed-out identity"
            );
            Ok(())
        }
        .await;
        self.set_account_tearing_down(&account.account_id_hex, false);
        result
    }

    pub(super) fn start_tracked_worker_reap(
        &self,
        account_id: &str,
        worker: ManagedAccountWorker,
        budget: Duration,
    ) {
        let mut tasks = self
            .onboarding_cancellations
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // Each registration owns its worker, including defensive duplicates.
        // Chain completion without changing the previous observer's meaning.
        let previous = tasks.reaping.get(account_id).map(watch::Sender::subscribe);
        let (sender, _) = watch::channel(false);
        tasks.reaping.insert(account_id.to_owned(), sender.clone());
        #[cfg(test)]
        let hold = self
            .onboarding_test_holds
            .worker_reap
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        retain_unfinished_onboarding_handles(&mut tasks);
        tasks.handles.push(tokio::spawn(async move {
            #[cfg(test)]
            if let Some(hold) = hold {
                hold.entered.notify_one();
                hold.release.notified().await;
            }
            worker.shutdown_with_timeout(budget).await;
            if let Some(mut previous) = previous {
                // The previous tracked task owns its bounded shutdown. A closed
                // channel means that task has exited (including unwinding).
                let _ = previous.wait_for(|done| *done).await;
            }
            sender.send_replace(true);
        }));
    }

    pub(super) async fn await_tracked_worker_reap(
        &self,
        account_id: &str,
        budget: Duration,
    ) -> Result<(), AppError> {
        timeout(budget, async {
            loop {
                let mut receiver = {
                    let tasks = self
                        .onboarding_cancellations
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    match tasks.reaping.get(account_id) {
                        Some(sender) => sender.subscribe(),
                        None => return Ok(()),
                    }
                };
                receiver
                    .wait_for(|done| *done)
                    .await
                    .map_err(|_| onboarding_error())?;
                let mut tasks = self
                    .onboarding_cancellations
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                // A duplicate may have chained another worker while we waited.
                // Only the latest completion covers every registered worker.
                match tasks.reaping.get(account_id) {
                    Some(sender) if !*sender.borrow() => continue,
                    _ => {
                        tasks.reaping.remove(account_id);
                        return Ok(());
                    }
                }
            }
        })
        .await
        .map_err(|_| AppError::AccountWorkerResponseTimedOut)?
    }

    fn close_onboarding_subscription(&self, account_id: &str, snapshot: &OnboardingSnapshot) {
        let mut updates = self
            .onboarding_updates
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(sender) = updates.get(account_id) {
            sender.send_replace(snapshot.clone());
        }
        updates.remove(account_id);
    }
}

pub(super) fn retain_unfinished_onboarding_handles(tasks: &mut OnboardingCancellationTasks) {
    tasks.handles.retain(|handle| !handle.is_finished());
}

async fn wait_for_cancel_outcome(
    mut receiver: watch::Receiver<Option<OnboardingCancelOutcome>>,
) -> OnboardingCancelOutcome {
    loop {
        if let Some(outcome) = *receiver.borrow() {
            return outcome;
        }
        if receiver.changed().await.is_err() {
            return OnboardingCancelOutcome::Failed;
        }
    }
}
