use super::*;
use crate::{Nip46Error, Nip46Session};

impl MarmotAppRuntime {
    /// Prepare an offline remote signer. Permission approval precedes connection.
    pub fn nip46_new(&self, config_json: &str) -> Result<Nip46Session, AppError> {
        self.shared.lifecycle().ensure_running()?;
        Ok(Nip46Session::new(&self.accounts.app, config_json)?)
    }

    /// Bind the remotely verified user and persist its communication key before setup signs.
    pub async fn nip46_login(
        &self,
        session: Nip46Session,
        default_relays: Vec<TransportEndpoint>,
        bootstrap_relays: Vec<TransportEndpoint>,
        inbox_relays: Vec<TransportEndpoint>,
    ) -> Result<AccountSummary, AppError> {
        self.shared.lifecycle().ensure_running()?;
        if !session.belongs_to(&self.accounts.app) {
            return Err(Nip46Error::Mismatch.into());
        }
        let public_key = session.connect_async().await?;
        let gate = self.accounts.onboarding_transaction(&public_key);
        let _transaction = gate.lock().await;
        self.check_nip46_slot(&public_key, &session)?;
        let request = AccountSetupRequest {
            default_relays,
            bootstrap_relays,
            inbox_relays,
            discovery_relays: self.accounts.app.discovery_indexer_relays(),
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
            ..Default::default()
        };
        let result = self
            .accounts
            .login_with_external(public_key, session.clone(), request, Some(session))
            .await?;
        Ok(result.account)
    }

    /// Attach a connected remote session to an existing external account.
    pub async fn nip46_register(
        &self,
        account_ref: &str,
        session: Nip46Session,
    ) -> Result<(), AppError> {
        self.shared.lifecycle().ensure_running()?;
        if !session.belongs_to(&self.accounts.app) {
            return Err(Nip46Error::Mismatch.into());
        }
        let account = self.accounts.resolve(account_ref)?;
        if !account.external_signing {
            return Err(Nip46Error::Mismatch.into());
        }
        let gate = self
            .accounts
            .onboarding_transaction(&account.account_id_hex);
        let _transaction = gate.lock().await;
        self.check_nip46_slot(&account.account_id_hex, &session)?;
        let accounts = self.accounts.clone();
        let label = account.label.clone();
        blocking_app_task(move || accounts.track_nip46_session(&label, session)).await?;
        self.accounts
            .retry_and_reconcile_for_account(&account.account_id_hex)
            .await
    }

    /// Rehydrate locally; the first signer operation reconnects with a bounded deadline.
    pub async fn nip46_resume(&self, account_ref: &str) -> Result<Nip46Session, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let gate = self
            .accounts
            .onboarding_transaction(&account.account_id_hex);
        let _transaction = gate.lock().await;
        self.load_nip46_session(&account)
            .await?
            .ok_or_else(|| Nip46Error::Unavailable.into())
    }

    /// Remove local pairing material without deleting the account's encrypted history.
    pub async fn nip46_remove(&self, account_ref: &str) -> Result<(), AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let gate = self
            .accounts
            .onboarding_transaction(&account.account_id_hex);
        let _transaction = gate.lock().await;
        let accounts = self.accounts.clone();
        let label = account.label;
        blocking_app_task(move || {
            accounts.erase_nip46_session(&label, Nip46Removal::IncludingOrphaned)
        })
        .await?;
        self.accounts.reconcile().await
    }

    fn check_nip46_slot(&self, id: &str, session: &Nip46Session) -> Result<(), AppError> {
        let sessions = self
            .accounts
            .app
            .nip46_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if sessions
            .get(id)
            .is_some_and(|current| !current.same_session(session))
        {
            return Err(Nip46Error::Busy.into());
        }
        Ok(())
    }

    async fn load_nip46_session(
        &self,
        account: &AccountSummary,
    ) -> Result<Option<Nip46Session>, AppError> {
        if !account.external_signing || account.signed_out || account.unlinked {
            return Ok(None);
        }
        let app = self.accounts.app.clone();
        let label = account.label.clone();
        blocking_app_task(move || {
            let mut sessions = app
                .nip46_sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let account = app.account_home().account(&label)?;
            if account.signed_out || account.unlinked {
                return Ok(None);
            }
            if let Some(session) = sessions.get(&account.account_id_hex)
                && !matches!(
                    session.status().state,
                    crate::Nip46State::Cancelled | crate::Nip46State::LoggedOut
                )
            {
                return Ok(Some(session.clone()));
            }
            let Some((keys, record)) = app
                .account_home()
                .load_nip46_session(&label)
                .map_err(|_| AppError::from(Nip46Error::Storage))?
            else {
                return Ok(None);
            };
            if sessions.iter().any(|(id, session)| {
                id != &account.account_id_hex
                    && session.client_public_key().ok() == Some(keys.public_key())
            }) {
                return Err(Nip46Error::Busy.into());
            }
            let session = Nip46Session::restore(&app, keys, record)?;
            app.pin_external_signer(
                &account.account_id_hex,
                session.public_key()?,
                Arc::new(session.clone()),
            );
            sessions.insert(account.account_id_hex, session.clone());
            Ok(Some(session))
        })
        .await
    }

    pub(super) async fn restore_nip46_sessions(&self) -> Result<(), AppError> {
        for account in self.accounts.app.account_home().accounts()? {
            let gate = self
                .accounts
                .onboarding_transaction(&account.account_id_hex);
            let _transaction = gate.lock().await;
            if let Err(error) = self.load_nip46_session(&account).await {
                let _ = self
                    .events
                    .send(MarmotAppEvent::AccountError(RuntimeAccountError {
                        account_id_hex: account.account_id_hex,
                        account_label: account.label,
                        message: error.privacy_safe_kind().into(),
                    }));
            }
        }
        Ok(())
    }
}

impl AccountManager {
    pub(super) fn track_nip46_session(
        &self,
        account_ref: &str,
        session: Nip46Session,
    ) -> Result<(), AppError> {
        let mut sessions = self
            .app
            .nip46_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let account = self.resolve(account_ref)?;
        if sessions
            .get(&account.account_id_hex)
            .is_some_and(|current| !current.same_session(&session))
        {
            return Err(Nip46Error::Busy.into());
        }
        let client_key = session.client_public_key()?;
        if sessions.iter().any(|(id, current)| {
            id != &account.account_id_hex && current.client_public_key().ok() == Some(client_key)
        }) {
            return Err(Nip46Error::Busy.into());
        }
        let public_key = session.public_key()?;
        if public_key.to_hex() != account.account_id_hex {
            return Err(Nip46Error::Mismatch.into());
        }
        session.bind_account(&account.label)?;
        self.app.pin_external_signer(
            &account.account_id_hex,
            public_key,
            Arc::new(session.clone()),
        );
        sessions.insert(account.account_id_hex, session);
        Ok(())
    }

    pub(super) fn erase_nip46_session(
        &self,
        account_ref: &str,
        removal: Nip46Removal,
    ) -> Result<(), AppError> {
        let account = self.resolve(account_ref)?;
        if !account.external_signing {
            return Ok(());
        }
        let mut sessions = self
            .app
            .nip46_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(session) = sessions.get(&account.account_id_hex) {
            session.erase_local()?;
            sessions.remove(&account.account_id_hex);
            self.app.forget_external_signer(&account.account_id_hex);
        } else {
            self.app
                .account_home()
                .remove_nip46_session(&account.label, removal)
                .map_err(|_| Nip46Error::Storage)?;
        }
        Ok(())
    }
}
