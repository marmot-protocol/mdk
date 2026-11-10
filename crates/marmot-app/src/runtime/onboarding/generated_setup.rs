//! Generated setup: the procedures behind `create_identity` and its
//! local-ready variants. They stay `MarmotAppRuntime` methods; living in setup's
//! module tree lets them reach its transaction and background task registry.
use super::*;

const GENERATED_SETUP_BACKGROUND_MAX_ATTEMPTS: usize = 3;
const GENERATED_SETUP_BACKGROUND_RETRY_BASE_DELAY: Duration = Duration::from_millis(100);

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
        let Some(bytes) = self
            .accounts
            .app
            .account_home()
            .account_setup_context(&account.label)?
        else {
            self.report_generated_setup_resume_deferred(&account, "setup_context_missing");
            return Ok(());
        };
        let context = match serde_json::from_slice::<GeneratedAccountSetupContext>(&bytes) {
            Ok(context) => context,
            Err(_) => {
                self.report_generated_setup_resume_deferred(&account, "setup_context_unreadable");
                return Ok(());
            }
        };
        if let Err(error) = self
            .create_generated_account_local_ready(context.request(), true, None)
            .await
        {
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
    ) -> Result<AccountSetupResult, AppError> {
        let observed = self.shared.observer.product().observed(
            crate::ProductFamily::Account,
            "local_ready",
            crate::ProductUnit::Attempt,
        );
        let work = async move {
            self.shared.lifecycle().ensure_running()?;
            let _generated_setup_transaction =
                self.setup.generated_setup_local_transaction.lock().await;
            validate_account_setup_request(&request, AccountSetupOperation::CreateOrImport)?;

            let resumable = self
                .accounts
                .app
                .account_home()
                .resumable_generated_account_setup()?;
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

            let identity_started = Instant::now();
            let identity_result = self
                .accounts
                .create_nostr_account_from_setup(&effective_request);
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
                self.accounts
                    .app
                    .account_home()
                    .set_account_setup_context(&account.label, &serde_json::to_vec(&context)?)?;
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
                    self.accounts
                        .app
                        .account_home()
                        .set_account_setup_phase(&account.label, AccountSetupPhase::LocalReady)?;
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
            if phase == AccountSetupPhase::LocalStateCreated && !schedule_background {
                self.accounts
                    .reset_startup_retry(&account.account_id_hex)
                    .await;
            }

            let relay_lists = self
                .accounts
                .app
                .account_relay_list_status(&account.label)?;
            let readiness = self.account_setup_readiness(&account.label)?;
            if schedule_background {
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
                self.schedule_generated_account_setup(account.clone(), context);
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
        };
        observed
            .run_async(work, marmot_observability::success_or_failure)
            .await
    }

    pub(in crate::runtime) async fn create_generated_account_network_ready(
        &self,
        request: AccountSetupRequest,
    ) -> Result<AccountSetupResult, AppError> {
        let local = self
            .create_generated_account_local_ready(request, false, None)
            .await?;
        let context = self
            .accounts
            .app
            .account_home()
            .account_setup_context(&local.account.label)?
            .ok_or(AppError::AccountSetupRetryRequired)
            .and_then(|bytes| {
                serde_json::from_slice::<GeneratedAccountSetupContext>(&bytes)
                    .map_err(AppError::from)
            })?;
        let started_at = Instant::now();
        let result = self
            .create_or_import_account_network_ready(context.request())
            .await;
        self.shared.observer.performance().record(
            AppPerformanceOperation::AccountSetupNetworkReady,
            started_at.elapsed(),
            result.is_ok(),
        );
        let mut result = result?;
        if result.profile.is_none() {
            result.profile = local.profile;
        }
        Ok(result)
    }

    fn schedule_generated_account_setup(
        &self,
        account: AccountSummary,
        context: GeneratedAccountSetupContext,
    ) {
        let mut tasks = self
            .setup
            .generated_setup_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tasks.handles.retain(|handle| !handle.is_finished());
        if !tasks.accepting || !tasks.active_accounts.insert(account.account_id_hex.clone()) {
            return;
        }
        let manager = self.clone();
        let active = self.setup.generated_setup_tasks.clone();
        let account_id_hex = account.account_id_hex.clone();
        let account_label = account.label.clone();
        let handle = tokio::spawn(async move {
            for attempt in 0..GENERATED_SETUP_BACKGROUND_MAX_ATTEMPTS {
                let started_at = Instant::now();
                let result = manager
                    .create_or_import_account_network_ready(context.request())
                    .await;
                manager.shared.observer.performance().record(
                    AppPerformanceOperation::AccountSetupNetworkReady,
                    started_at.elapsed(),
                    result.is_ok(),
                );
                match result {
                    Ok(_) => break,
                    Err(error) => {
                        let final_attempt = attempt + 1 == GENERATED_SETUP_BACKGROUND_MAX_ATTEMPTS;
                        let status = if final_attempt {
                            "deferred"
                        } else {
                            "retry scheduled"
                        };
                        let _ = manager.events.send(MarmotAppEvent::AccountError(
                            RuntimeAccountError {
                                account_id_hex: account_id_hex.clone(),
                                account_label: account_label.clone(),
                                message: format!(
                                    "generated account publication {status}: {}",
                                    error.privacy_safe_kind()
                                ),
                            },
                        ));
                        if final_attempt {
                            break;
                        }
                        let multiplier = 1_u32
                            .checked_shl(u32::try_from(attempt).unwrap_or(u32::MAX))
                            .unwrap_or(u32::MAX);
                        tokio::time::sleep(
                            GENERATED_SETUP_BACKGROUND_RETRY_BASE_DELAY.saturating_mul(multiplier),
                        )
                        .await;
                    }
                }
            }
            active
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .active_accounts
                .remove(&account_id_hex);
        });
        tasks.handles.push(handle);
    }
}
