use super::*;
use crate::{Nip46Error, Nip46Session};
use nostr::prelude::PublicKey;

pub(super) enum Nip46AdoptionScope {
    Runtime,
    App,
    Account(PublicKey),
}

struct Nip46Erasure {
    account: AccountSummary,
    session: Option<Nip46Session>,
}

impl MarmotAppRuntime {
    /// Prepare an offline remote signer. Permission approval precedes connection.
    pub fn nip46_new(&self, config_json: &str) -> Result<Nip46Session, AppError> {
        self.shared.lifecycle().ensure_running()?;
        Ok(Nip46Session::new(&self.accounts.app, config_json)?)
    }

    /// Adopt a verified Ready signer; complete explicit pairing before this call.
    /// Persist it before setup signs. Once adoption starts,
    /// dropping this waiter does not cancel it; use the session's explicit controls.
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
        let public_key = session.public_key()?;
        let status = session.status();
        if status.state != crate::Nip46State::Ready {
            return Err(Nip46Error::Unavailable.into());
        }
        let generation = status.generation;
        let public_key = public_key.to_hex();
        let request = AccountSetupRequest {
            default_relays,
            bootstrap_relays,
            inbox_relays,
            discovery_relays: self.accounts.app.discovery_indexer_relays(),
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
            ..Default::default()
        };
        let runtime = self.clone();
        self.own_nip46_adoption(session.clone(), generation, async move {
            let result = runtime
                .accounts
                .login_with_external(
                    public_key,
                    ExternalSetupSigner::Nip46 {
                        session,
                        generation,
                    },
                    request,
                )
                .await?;
            Ok(result.account)
        })
        .await
    }

    /// Attach a connected remote session. Adoption survives dropping this waiter.
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
        let generation = session.status().generation;
        let runtime = self.clone();
        self.own_nip46_adoption(session.clone(), generation, async move {
            runtime
                .attach_nip46_session(account, session, generation)
                .await
        })
        .await
    }

    async fn own_nip46_adoption<T: Send + 'static>(
        &self,
        session: Nip46Session,
        generation: u64,
        work: impl Future<Output = Result<T, AppError>> + Send + 'static,
    ) -> Result<T, AppError> {
        let task = {
            let mut adoptions = self
                .accounts
                .app
                .nip46_adoptions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.shared.lifecycle().ensure_running()?;
            self.accounts.app.ensure_storage_open("NIP-46 adoption")?;
            if adoptions.closed {
                return Err(Nip46Error::Cancelled.into());
            }
            let user = session.public_key()?;
            if session.status().generation != generation {
                return Err(Nip46Error::Disconnected.into());
            }
            adoptions.active.retain(|adoption| !adoption.finished());
            let (completion, completed) = watch::channel(false);
            let registry = Arc::downgrade(&self.accounts.app.nip46_adoptions);
            let task = tokio::spawn(async move {
                let result = work.await;
                completion.send_replace(true);
                if let Some(registry) = registry.upgrade() {
                    registry
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .active
                        .retain(|adoption| !adoption.finished());
                }
                result
            });
            adoptions.active.push(crate::Nip46Adoption {
                owner: Arc::downgrade(&self.accounts.nip46_adoption_owner),
                user,
                session,
                completed,
            });
            task
        };
        task.await
            .map_err(|_| AppError::BlockingTask("NIP-46 adoption task failed".into()))?
    }

    async fn attach_nip46_session(
        &self,
        account: AccountSummary,
        session: Nip46Session,
        generation: u64,
    ) -> Result<(), AppError> {
        let gate = self
            .accounts
            .onboarding_transaction(&account.account_id_hex);
        let observer = (session.clone(), generation);
        let _transaction =
            Nip46Session::during_adoption(Some(&observer), async { Ok(gate.lock().await) }).await?;
        self.shared.lifecycle().ensure_running()?;
        self.accounts.app.ensure_storage_open("NIP-46 adoption")?;
        let accounts = self.accounts.clone();
        let label = account.label.clone();
        let binding =
            blocking_app_task(move || accounts.track_nip46_session(&label, session, generation))
                .await?;
        let result = Nip46Session::during_adoption(
            Some(&observer),
            self.accounts
                .retry_and_reconcile_for_account(&account.account_id_hex),
        )
        .await;
        if result.is_err()
            && let Some(binding) = binding
            && binding.previous_signer.is_some()
        {
            let cleanup = blocking_app_task(move || {
                binding
                    .session
                    .unbind_account(&binding.previous, binding.previous_signer)
                    .map_err(AppError::from)
            })
            .await;
            let reconciliation = self
                .accounts
                .reconcile_nip46_cleanup(&account.account_id_hex)
                .await;
            cleanup?;
            reconciliation?;
        }
        result
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
        let _transaction = self.accounts.lock_nip46_removal(gate, &account).await;
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(&account.account_id_hex)?;
        let account_id = account.account_id_hex.clone();
        let target = self.accounts.nip46_erase_target(account);
        let accounts = self.accounts.clone();
        blocking_app_task(move || {
            accounts.erase_nip46_target(target, Nip46Removal::IncludingOrphaned)
        })
        .await?;
        self.accounts.reconcile_nip46_cleanup(&account_id).await
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
                session.registered_signer(),
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
    async fn lock_nip46_removal(
        &self,
        gate: Arc<Mutex<()>>,
        account: &AccountSummary,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        let user = PublicKey::from_hex(&account.account_id_hex).ok();
        let acquisition = gate.lock_owned();
        tokio::pin!(acquisition);
        let ready = {
            let adoptions = self
                .app
                .nip46_adoptions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Queue before releasing admission: later adoptions must wait behind removal.
            let ready = futures::FutureExt::now_or_never(acquisition.as_mut());
            for adoption in &adoptions.active {
                if Some(adoption.user) == user {
                    adoption.session.cancel();
                }
            }
            ready
        };
        match ready {
            Some(guard) => guard,
            None => acquisition.await,
        }
    }

    pub(super) async fn finish_nip46_adoptions(&self, scope: Nip46AdoptionScope) {
        let owner = Arc::downgrade(&self.nip46_adoption_owner);
        let mut active = {
            let mut adoptions = self
                .app
                .nip46_adoptions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if matches!(scope, Nip46AdoptionScope::App) {
                adoptions.closed = true;
            }
            adoptions.active.retain(|adoption| !adoption.finished());
            adoptions
                .active
                .iter()
                .filter(|adoption| match scope {
                    Nip46AdoptionScope::Runtime => adoption.owner.ptr_eq(&owner),
                    Nip46AdoptionScope::App => true,
                    Nip46AdoptionScope::Account(user) => adoption.user == user,
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        for adoption in &active {
            adoption.session.cancel();
        }
        for adoption in &mut active {
            while !*adoption.completed.borrow_and_update() {
                if adoption.completed.changed().await.is_err() {
                    break;
                }
            }
        }
    }

    pub(super) async fn finish_nip46_account(&self, account: &AccountSummary) {
        // A malformed stored id cannot own a verified adoption; erasure still works.
        if let Ok(user) = PublicKey::from_hex(&account.account_id_hex) {
            self.finish_nip46_adoptions(Nip46AdoptionScope::Account(user))
                .await;
        }
    }

    pub(super) async fn reconcile_nip46_cleanup(&self, account: &str) -> Result<(), AppError> {
        let closing = self
            .app
            .nip46_adoptions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .closed;
        if closing || self.shared.lifecycle().is_stopping() {
            return Ok(());
        }
        self.reconcile_for_account(account).await
    }

    pub(super) fn track_nip46_session(
        &self,
        account_ref: &str,
        session: Nip46Session,
        generation: u64,
    ) -> Result<Option<Nip46Binding>, AppError> {
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
        let previous = session.bind_account(&account.label, generation)?;
        let signer = session.registered_signer();
        let previous_signer =
            self.app
                .pin_external_signer(&account.account_id_hex, public_key, signer.clone());
        let already_attached = previous_signer
            .as_ref()
            .is_some_and(|previous| Arc::ptr_eq(previous, &signer));
        sessions.insert(account.account_id_hex, session.clone());
        if already_attached {
            return Ok(None);
        }
        Ok(Some(Nip46Binding {
            session,
            previous,
            previous_signer,
        }))
    }

    pub(super) fn erase_nip46_session(
        &self,
        account_ref: &str,
        removal: Nip46Removal,
    ) -> Result<(), AppError> {
        let account = self.resolve(account_ref)?;
        self.erase_nip46_target(self.nip46_erase_target(account), removal)
    }

    fn nip46_erase_target(&self, account: AccountSummary) -> Nip46Erasure {
        let session = self
            .app
            .nip46_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&account.account_id_hex)
            .cloned();
        Nip46Erasure { account, session }
    }

    fn erase_nip46_target(
        &self,
        target: Nip46Erasure,
        removal: Nip46Removal,
    ) -> Result<(), AppError> {
        if !target.account.external_signing {
            return Ok(());
        }
        if let Some(session) = target.session {
            session.erase_local()?;
        } else {
            let sessions = self
                .app
                .nip46_sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if sessions.contains_key(&target.account.account_id_hex) {
                return Ok(());
            }
            self.app
                .account_home()
                .remove_nip46_session(&target.account.label, removal)
                .map_err(|_| Nip46Error::Storage)?;
        }
        Ok(())
    }
}
