//! Generated setup: the procedures behind `create_identity` and its
//! local-ready variants. They stay `MarmotAppRuntime` methods; living in setup's
//! module tree lets them reach its transaction and background task registry.
use super::generated_setup_tasks::GeneratedSetupGate;
use super::*;

const GENERATED_SETUP_BACKGROUND_MAX_ATTEMPTS: usize = 3;
const GENERATED_SETUP_BACKGROUND_RETRY_BASE_DELAY: Duration = Duration::from_millis(100);

#[derive(Clone, Copy)]
enum GeneratedSetupHandoff {
    Foreground,
    Background,
}

#[derive(Clone, Copy)]
enum InitialPublication {
    Requested,
    Skipped,
}

enum GeneratedSetupPreparation {
    Pending(AccountSetupResult, GeneratedAccountSetupContext),
    Complete(AccountSetupResult),
}

impl MarmotAppRuntime {
    pub(in crate::runtime) async fn resume_generated_account_setup(&self) -> Result<(), AppError> {
        let Some(account) = self
            .accounts
            .app
            .account_home()
            .resumable_generated_account_setup()?
        else {
            return Ok(());
        };
        let account = match self
            .accounts
            .pending_generated_account(&account.account_id_hex)
        {
            Ok(Some(account)) => account,
            Ok(None) | Err(AppError::AccountHome(AccountHomeError::UnknownAccount(_))) => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let bytes = match self
            .accounts
            .app
            .account_home()
            .account_setup_context(&account.label)
        {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                match self
                    .accounts
                    .pending_generated_account(&account.account_id_hex)
                {
                    Ok(Some(_)) => self
                        .report_generated_setup_resume_deferred(&account, "setup_context_missing"),
                    Ok(None) | Err(AppError::AccountHome(AccountHomeError::UnknownAccount(_))) => {}
                    Err(error) => return Err(error),
                }
                return Ok(());
            }
            Err(AccountHomeError::UnknownAccount(_)) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let context = match serde_json::from_slice::<GeneratedAccountSetupContext>(&bytes) {
            Ok(context) => context,
            Err(_) => {
                self.report_generated_setup_resume_deferred(&account, "setup_context_unreadable");
                return Ok(());
            }
        };
        if let Err(error) = self
            .create_generated_account_local_ready(
                context.request(),
                true,
                None,
                GeneratedIdentity::Continue(&account.account_id_hex),
            )
            .await
        {
            if matches!(
                error,
                AppError::AccountHome(AccountHomeError::UnknownAccount(_))
            ) {
                return Ok(());
            }
            self.report_generated_setup_resume_deferred(&account, error.privacy_safe_kind());
        }
        Ok(())
    }

    fn report_generated_setup_resume_deferred(
        &self,
        account: &AccountSummary,
        error_kind: &'static str,
    ) {
        tracing::warn!(
            target: "marmot_app::runtime",
            method = "resume_generated_account_setup",
            error_kind,
            "generated account setup resume deferred"
        );
        let _ = self
            .events
            .send(MarmotAppEvent::AccountError(RuntimeAccountError {
                account_id_hex: account.account_id_hex.clone(),
                account_label: account.label.clone(),
                message: format!("generated account setup resume deferred: {error_kind}"),
            }));
    }

    pub(in crate::runtime) async fn create_generated_account_local_ready(
        &self,
        request: AccountSetupRequest,
        schedule_background: bool,
        initial_profile: Option<UserProfileMetadata>,
        generated: GeneratedIdentity<'_>,
    ) -> Result<AccountSetupResult, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let _generated_setup_transaction =
            self.setup.generated_setup_local_transaction.lock().await;
        let handoff = if schedule_background {
            GeneratedSetupHandoff::Background
        } else {
            GeneratedSetupHandoff::Foreground
        };
        match self
            .prepare_generated_account(request, handoff, initial_profile, generated)
            .await?
        {
            GeneratedSetupPreparation::Pending(local, context) => {
                if schedule_background {
                    self.schedule_generated_account_setup(local.account.clone(), context);
                }
                Ok(local)
            }
            GeneratedSetupPreparation::Complete(complete) => Ok(complete),
        }
    }

    // The caller holds local admission through the returned future.
    // Resolve and validate its identity and context before async preparation.
    fn prepare_generated_account<'a>(
        &'a self,
        request: AccountSetupRequest,
        handoff: GeneratedSetupHandoff,
        initial_profile: Option<UserProfileMetadata>,
        generated: GeneratedIdentity<'a>,
    ) -> impl Future<Output = Result<GeneratedSetupPreparation, AppError>> + Send + 'a {
        let observed = self.shared.observer.product().observed(
            crate::ProductFamily::Account,
            "local_ready",
            crate::ProductUnit::Attempt,
        );
        let selection = (|| {
            self.shared.lifecycle().ensure_running()?;
            validate_account_setup_request(&request, AccountSetupOperation::CreateOrImport)?;

            let resumable = match generated {
                GeneratedIdentity::ResumeOrCreate => self
                    .accounts
                    .app
                    .account_home()
                    .resumable_generated_account_setup()?,
                GeneratedIdentity::Fresh => None,
                GeneratedIdentity::Continue(id) => {
                    let account = self.accounts.app.account_home().account(id)?;
                    if account.account_id_hex != id
                        || account.signed_out
                        || account.unlinked
                        || !account.local_signing
                    {
                        return Err(AccountHomeError::UnknownAccount(id.to_owned()).into());
                    }
                    Some(account)
                }
            };
            // Persisted relays win on resume so every retry retains the exact
            // locally prepared initial KeyPackage and its publication targets.
            let context = match resumable.as_ref() {
                Some(account) => match self
                    .accounts
                    .app
                    .account_home()
                    .account_setup_context(&account.label)?
                {
                    Some(bytes) => serde_json::from_slice::<GeneratedAccountSetupContext>(&bytes)?,
                    None => GeneratedAccountSetupContext::from_request(&request),
                },
                None => GeneratedAccountSetupContext::from_request(&request),
            };
            let effective_request = context.request();
            let bootstrap = AccountRelayListBootstrap::new(
                effective_request.default_relays.clone(),
                effective_request.bootstrap_relays.clone(),
            )
            .with_inbox_relays(effective_request.inbox_relays.clone());
            if bootstrap.default_relays.is_empty() {
                return Err(AppError::MissingDefaultRelays);
            }
            self.accounts
                .app
                .validate_account_relay_list_declarations(&bootstrap, None)?;
            Ok::<_, AppError>((resumable, context, effective_request))
        })();
        let work = async move {
            let (resumable, context, effective_request) = selection?;
            let publication = if effective_request.publish_initial_key_package {
                InitialPublication::Requested
            } else {
                InitialPublication::Skipped
            };

            // A fresh selection stays fresh even if sign-in makes a journal
            // eligible before creation. Existing selections stay on their ID.
            let generated = resumable
                .as_ref()
                .map_or(GeneratedIdentity::Fresh, |account| {
                    GeneratedIdentity::Continue(&account.account_id_hex)
                });
            let result = async {
                let identity_started = Instant::now();
                let identity_result = self
                    .accounts
                    .create_nostr_account_from_setup(&effective_request, generated);
                self.shared.observer.performance().record(
                    AppPerformanceOperation::AccountSetupIdentityLocal,
                    identity_started.elapsed(),
                    identity_result.is_ok(),
                );
                let (account, _) = identity_result?;
                if self
                    .accounts
                    .app
                    .account_home()
                    .account_setup_context(&account.label)?
                    .is_none()
                {
                    self.accounts.app.account_home().set_account_setup_context(
                        &account.label,
                        &serde_json::to_vec(&context)?,
                    )?;
                }
                let storage_started = Instant::now();
                let storage_result = self.accounts.app.account_storage(&account.label);
                self.shared.observer.performance().record(
                    AppPerformanceOperation::AccountSetupStorageLocal,
                    storage_started.elapsed(),
                    storage_result.is_ok(),
                );
                storage_result?;
                let phase = self
                    .accounts
                    .app
                    .account_home()
                    .account_setup_state(&account.label)?
                    .map(|state| state.phase)
                    .ok_or(AppError::AccountSetupRetryRequired)?;

                let profile_started = Instant::now();
                let profile_result = (|| {
                    let cached = self
                        .accounts
                        .app
                        .directory()
                        .directory_entry_for_account_id(&account.account_id_hex)?
                        .and_then(|entry| entry.profile);
                    let (profile, store) = generated_setup_profile(
                        &account.account_id_hex,
                        phase,
                        cached,
                        initial_profile,
                        unix_now_seconds(),
                    );
                    if store {
                        self.accounts
                            .app
                            .directory()
                            .remember_directory_profile(&account.account_id_hex, &profile)?;
                    }
                    Ok::<_, AppError>(profile)
                })();
                self.shared.observer.performance().record(
                    AppPerformanceOperation::AccountSetupProfileLocal,
                    profile_started.elapsed(),
                    profile_result.is_ok(),
                );
                let profile = profile_result?;

                let key_package_started = Instant::now();
                let key_package_result = async {
                    if phase == AccountSetupPhase::LocalStateCreated {
                        let mut client = self
                            .accounts
                            .app
                            .local_client_with_relay_plane(
                                &account.label,
                                self.shared.relay_plane(),
                                Some(self.shared.lifecycle()),
                            )
                            .await?;
                        let key_package = client
                            .prepare_initial_key_package(effective_request.default_relays.to_vec())
                            .await?;
                        let bytes = key_package.bytes().len();
                        drop(client);
                        self.accounts.app.account_home().set_account_setup_phase(
                            &account.label,
                            AccountSetupPhase::LocalReady,
                        )?;
                        self.accounts.app.presentation_signals.catalog_changed();
                        Ok(bytes)
                    } else {
                        let lifecycle = self
                            .accounts
                            .app
                            .account_storage(&account.label)?
                            .key_package_lifecycle()?
                            .ok_or(AppError::AccountSetupRetryRequired)?;
                        lifecycle
                            .pending_replacement
                            .as_ref()
                            .map(|pending| pending.key_package.bytes().len())
                            .or_else(|| {
                                lifecycle
                                    .current_key_package
                                    .as_ref()
                                    .map(|key_package| key_package.bytes().len())
                            })
                            .ok_or(AppError::AccountSetupRetryRequired)
                    }
                }
                .await;
                self.shared.observer.performance().record(
                    AppPerformanceOperation::AccountSetupKeyPackageLocal,
                    key_package_started.elapsed(),
                    key_package_result.is_ok(),
                );
                let key_package_bytes = key_package_result?;
                if phase == AccountSetupPhase::LocalStateCreated
                    && matches!(handoff, GeneratedSetupHandoff::Foreground)
                {
                    self.accounts
                        .reset_startup_retry(&account.account_id_hex)
                        .await;
                }

                let relay_lists = self
                    .accounts
                    .app
                    .account_relay_list_status(&account.label)?;
                let readiness = self.account_setup_readiness(&account.label)?;
                if matches!(handoff, GeneratedSetupHandoff::Background) {
                    let handoff_started_at = Instant::now();
                    let handoff_result = if phase == AccountSetupPhase::LocalStateCreated {
                        self.accounts
                            .retry_and_reconcile_for_account(&account.account_id_hex)
                            .await
                    } else {
                        self.accounts
                            .reconcile_for_account(&account.account_id_hex)
                            .await
                    };
                    self.shared.observer.performance().record(
                        AppPerformanceOperation::AccountSetupLocalReadyHandoff,
                        handoff_started_at.elapsed(),
                        handoff_result.is_ok(),
                    );
                    handoff_result?;
                }
                Ok(AccountSetupResult {
                    account,
                    relay_lists,
                    key_package_bytes: effective_request
                        .publish_initial_key_package
                        .then_some(key_package_bytes),
                    profile: Some(profile),
                    readiness,
                })
            }
            .await;
            let local = match result {
                Ok(local) => local,
                Err(
                    error @ (AppError::AccountHome(
                        AccountHomeError::UnknownAccount(_)
                        | AccountHomeError::AccountSetupStateMissing,
                    )
                    | AppError::AccountSetupRetryRequired),
                ) => {
                    if let Some(account) = resumable.as_ref()
                        && let Some(complete) =
                            self.completed_generated_setup(&account.account_id_hex, publication)?
                    {
                        return Ok(GeneratedSetupPreparation::Complete(complete));
                    }
                    return Err(error);
                }
                Err(error) => return Err(error),
            };
            if local.readiness == AccountSetupReadiness::NetworkReady
                && let Some(complete) =
                    self.completed_generated_setup(&local.account.account_id_hex, publication)?
            {
                return Ok(GeneratedSetupPreparation::Complete(complete));
            }
            Ok(GeneratedSetupPreparation::Pending(local, context))
        };
        observed.run_async(work, marmot_observability::success_or_failure)
    }

    pub(in crate::runtime) async fn create_generated_account_network_ready(
        &self,
        request: AccountSetupRequest,
    ) -> Result<AccountSetupResult, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let preparation = {
            let _generated_setup_transaction =
                self.setup.generated_setup_local_transaction.lock().await;
            self.prepare_generated_account(
                request,
                GeneratedSetupHandoff::Foreground,
                None,
                GeneratedIdentity::ResumeOrCreate,
            )
            .await?
        };
        match preparation {
            GeneratedSetupPreparation::Pending(local, context) => {
                self.finish_generated_setup(local, context).await
            }
            GeneratedSetupPreparation::Complete(complete) => Ok(complete),
        }
    }

    pub(super) async fn finish_generated_setup(
        &self,
        local: AccountSetupResult,
        context: GeneratedAccountSetupContext,
    ) -> Result<AccountSetupResult, AppError> {
        let started_at = Instant::now();
        let setup = self.account_setup();
        let transaction = setup.onboarding_transaction(&local.account.account_id_hex);
        let _transaction = transaction.lock().await;
        let request = context.request();
        let publication = if request.publish_initial_key_package {
            InitialPublication::Requested
        } else {
            InitialPublication::Skipped
        };
        let result = self
            .accounts
            .continue_generated_account_setup(&local.account.account_id_hex, request)
            .await;
        let result = match result {
            Ok(mut result) => {
                if result.profile.is_none() {
                    result.profile = local.profile;
                }
                Ok(result)
            }
            Err(
                error @ (AppError::AccountHome(
                    AccountHomeError::UnknownAccount(_)
                    | AccountHomeError::AccountSetupStateMissing,
                )
                | AppError::AccountSetupRetryRequired),
            ) => self
                .completed_generated_setup(&local.account.account_id_hex, publication)
                .and_then(|complete| complete.ok_or(error)),
            Err(error) => Err(error),
        };
        self.shared.observer.performance().record(
            AppPerformanceOperation::AccountSetupNetworkReady,
            started_at.elapsed(),
            result.is_ok(),
        );
        result
    }

    fn completed_generated_setup(
        &self,
        account_id_hex: &str,
        publication: InitialPublication,
    ) -> Result<Option<AccountSetupResult>, AppError> {
        let home = self.accounts.app.account_home();
        let account = home.account(account_id_hex)?;
        if account.account_id_hex != account_id_hex
            || account.signed_out
            || account.unlinked
            || !account.local_signing
        {
            return Err(AccountHomeError::UnknownAccount(account_id_hex.to_owned()).into());
        }
        if home.account_setup_state(&account.label)?.is_some() {
            return Ok(None);
        }
        let readiness = self.account_setup_readiness(&account.label)?;
        if readiness != AccountSetupReadiness::NetworkReady {
            return Ok(None);
        }
        let relay_lists = self
            .accounts
            .app
            .account_relay_list_status(&account.label)?;
        let profile = self
            .accounts
            .app
            .directory()
            .directory_entry_for_account_id(account_id_hex)?
            .and_then(|entry| entry.profile);
        let key_package_bytes = if matches!(publication, InitialPublication::Requested) {
            Some(
                self.accounts
                    .confirmed_setup_key_package_bytes(&account.label)?
                    .ok_or(AppError::AccountSetupRetryRequired)?,
            )
        } else {
            None
        };
        Ok(Some(AccountSetupResult {
            account,
            relay_lists,
            key_package_bytes,
            profile,
            readiness,
        }))
    }

    /// Publish `account`'s generated setup in the background. The task
    /// continues that account only: it ends once the account is removed,
    /// signed out or set up, and never resumes or creates another identity.
    /// Every attempt runs through the account's gate, so a teardown's fence
    /// cancels the attempt in flight and holds the task until the teardown
    /// returns (`generated_setup_tasks`).
    fn schedule_generated_account_setup(
        &self,
        account: AccountSummary,
        context: GeneratedAccountSetupContext,
    ) {
        let manager = self.clone();
        let account_id_hex = account.account_id_hex.clone();
        self.setup
            .generated_setup_tasks
            .spawn(&account_id_hex, move |gate| async move {
                manager
                    .run_generated_account_setup(gate, account, context)
                    .await;
            });
    }

    async fn run_generated_account_setup(
        &self,
        gate: GeneratedSetupGate,
        account: AccountSummary,
        context: GeneratedAccountSetupContext,
    ) {
        // Only a definite answer ends the task: the account was removed,
        // signed out or set up. A failed lookup is retried and reported like
        // any failed attempt, and the attempt itself never resumes or creates
        // another identity.
        let gone = || {
            matches!(
                self.accounts
                    .pending_generated_account(&account.account_id_hex),
                Ok(None)
            )
        };
        let mut failures = 0;
        loop {
            gate.wait_unfenced().await;
            if gate.end_if(gone) {
                return;
            }
            let started_at = Instant::now();
            let Some(result) = gate
                .attempt(
                    self.accounts.continue_generated_account_setup(
                        &account.account_id_hex,
                        context.request(),
                    ),
                )
                .await
            else {
                // A teardown fenced the account; check again once it returns.
                continue;
            };
            self.shared.observer.performance().record(
                AppPerformanceOperation::AccountSetupNetworkReady,
                started_at.elapsed(),
                result.is_ok(),
            );
            let error = match result {
                Ok(_) => return,
                // An account that went away mid-attempt has nothing left to
                // retry or report.
                Err(_) if gate.end_if(gone) => return,
                Err(error) => error,
            };
            failures += 1;
            let final_attempt = failures == GENERATED_SETUP_BACKGROUND_MAX_ATTEMPTS;
            let status = if final_attempt {
                "deferred"
            } else {
                "retry scheduled"
            };
            let _ = self
                .events
                .send(MarmotAppEvent::AccountError(RuntimeAccountError {
                    account_id_hex: account.account_id_hex.clone(),
                    account_label: account.label.clone(),
                    message: format!(
                        "generated account publication {status}: {}",
                        error.privacy_safe_kind()
                    ),
                }));
            if final_attempt {
                return;
            }
            let multiplier = 1_u32
                .checked_shl(u32::try_from(failures - 1).unwrap_or(u32::MAX))
                .unwrap_or(u32::MAX);
            tokio::time::sleep(
                GENERATED_SETUP_BACKGROUND_RETRY_BASE_DELAY.saturating_mul(multiplier),
            )
            .await;
        }
    }

    /// Start publishing `account_id_hex` again if its generated setup is
    /// still pending, as after it is signed back in: its sign-out ended the
    /// task. A missing or unreadable setup context waits for the next
    /// runtime start, as resume does.
    pub(in crate::runtime) fn continue_pending_generated_setup(&self, account_id_hex: &str) {
        let Ok(Some(account)) = self.accounts.pending_generated_account(account_id_hex) else {
            return;
        };
        let Ok(Some(bytes)) = self
            .accounts
            .app
            .account_home()
            .account_setup_context(&account.label)
        else {
            return;
        };
        if let Ok(context) = serde_json::from_slice::<GeneratedAccountSetupContext>(&bytes) {
            self.schedule_generated_account_setup(account, context);
        }
    }
}

#[cfg(test)]
mod selection_tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sign_in_keeps_fresh_selection() {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open_with_secret_store(
            dir.path(),
            Arc::new(marmot_account::LocalFileSecretStore::new(dir.path())),
        );
        let runtime = MarmotAppRuntime::new(MarmotApp::with_relays_and_account_home(
            dir.path(),
            vec!["wss://original.example".into()],
            home,
        ));
        let request = |relay: &str| AccountSetupRequest {
            default_relays: vec![TransportEndpoint(relay.into())],
            bootstrap_relays: vec![TransportEndpoint(relay.into())],
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        };
        let original = runtime
            .create_generated_account_local_ready(
                request("wss://original.example"),
                false,
                None,
                GeneratedIdentity::ResumeOrCreate,
            )
            .await
            .unwrap();
        let home = runtime.accounts.app.account_home();
        let original_context = home.account_setup_context(&original.account.label).unwrap();
        let original_storage = runtime
            .accounts
            .app
            .account_storage(&original.account.label)
            .unwrap();
        let original_package = original_storage
            .key_package_lifecycle()
            .unwrap()
            .unwrap()
            .pending_replacement
            .unwrap()
            .key_package;
        home.set_account_signed_out(&original.account.label, true)
            .unwrap();

        let admission = runtime.setup.generated_setup_local_transaction.lock().await;
        let preparation = runtime.prepare_generated_account(
            request("wss://new.example"),
            GeneratedSetupHandoff::Foreground,
            None,
            GeneratedIdentity::ResumeOrCreate,
        );
        // Land sign-in's durable transition after selection and before creation.
        home.set_account_signed_out(&original.account.label, false)
            .unwrap();
        let GeneratedSetupPreparation::Pending(local, context) =
            tokio::time::timeout(Duration::from_secs(30), preparation)
                .await
                .unwrap()
                .unwrap()
        else {
            panic!("fresh preparation must not report the old account as complete");
        };
        drop(admission);

        assert_ne!(
            local.account.account_id_hex,
            original.account.account_id_hex
        );
        assert_eq!(context.default_relays, vec!["wss://new.example".to_owned()]);
        assert_eq!(
            home.account_setup_context(&local.account.label).unwrap(),
            Some(serde_json::to_vec(&context).unwrap())
        );
        assert_eq!(
            home.account(&original.account.label).unwrap(),
            original.account
        );
        assert_eq!(
            home.account_setup_context(&original.account.label).unwrap(),
            original_context
        );
        assert_eq!(
            original_storage
                .key_package_lifecycle()
                .unwrap()
                .unwrap()
                .pending_replacement
                .unwrap()
                .key_package
                .bytes(),
            original_package.bytes()
        );
        let mut expected = vec![original.account, local.account];
        expected.sort_by(|a, b| a.account_id_hex.cmp(&b.account_id_hex));
        assert_eq!(home.accounts().unwrap(), expected);
        drop(original_storage);
        runtime.shutdown_and_close().await.unwrap();
    }
}
