//! Reversible exit from onboarding; no relay deletions or local identity wipe.
use super::*;

impl AccountManager {
    /// Cancel an unfinished workflow and retain the identity signed out.
    /// Completed repairs are not undone. An approved, unfinished repair must
    /// first be resumed, since its exact publication may already be exposed.
    /// Retrying cancellation after interruption finishes the same local intent.
    pub async fn cancel_onboarding(&self, account_ref: &str) -> Result<(), AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.resolve(account_ref)?;
        let transaction = self.onboarding_transaction(&account.account_id_hex);
        let _transaction = transaction.lock().await;
        let Some(mut checkpoint) = self.read_onboarding_checkpoint(&account.label)? else {
            return Ok(());
        };
        if checkpoint.approved || checkpoint.snapshot.ready {
            return Err(onboarding_error());
        }
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
        let _workers = self.worker_transactions.lock().await;
        checkpoint.snapshot.cancellation_pending = true;
        for state in &mut checkpoint.snapshot.steps {
            state.actions = vec![OnboardingAction::CancelOnboarding];
        }
        self.save_onboarding(&mut checkpoint)?;
        self.app
            .account_home()
            .set_account_signed_out(&account.label, true)?;
        self.reconcile_locked().await?;
        // Cancellation is reversible, like sign-out. Keep the host's signer
        // attached so explicit sign-in can reuse it; removal owns detachment.
        // Keep the setup phase and private KeyPackage journal intact so a later
        // legacy sign-in can resume it. Only relinquish interactive ownership.
        if let Some(setup) = setup.filter(|s| s.kind == AccountSetupKind::InteractiveIdentity) {
            self.app.account_home().begin_account_setup_with(
                &account,
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
        self.onboarding_updates
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&account.account_id_hex);
        tracing::debug!(target: "marmot_app::onboarding", method = "cancel_onboarding", "cancelled onboarding and retained the signed-out identity");
        Ok(())
    }
}
