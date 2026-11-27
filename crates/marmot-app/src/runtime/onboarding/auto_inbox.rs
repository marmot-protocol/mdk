//! Direct, restart-safe automatic creation of a missing kind-10050 inbox list.
//!
//! Automatic creation stays separate from the user-facing proposal/approval
//! state machine: no synthetic `OnboardingRepairProposal` is exposed, the local
//! happy path uses one discovery lookup, and the three persisted phases separate
//! pre-send freshness verification, post-send exact-byte retries, and
//! post-acceptance ingestion/route verification.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct PendingAutoInbox {
    /// Recommended inbox relays advertised in the kind-10050 event.
    pub(super) relays: Vec<String>,
    /// Publish targets confirmed during complete discovery (never unchecked fallbacks).
    pub(super) targets: Vec<String>,
    pub(super) phase: PendingAutoInboxPhase,
    /// Whether any publish attempt of the signed event may have reached a relay.
    /// `Some(false)` means no attempt has been exposed yet; `None` (legacy) or
    /// `Some(true)` stays conservatively exposed and preserves exact-byte retries.
    #[serde(default)]
    pub(super) may_have_published: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) enum PendingAutoInboxPhase {
    /// Signed event bytes are durably checkpointed, and no network send has
    /// started yet. After an asynchronous external signature or a restart before
    /// send, one freshness check runs so any newly discovered kind-10050 takes
    /// precedence instead of being overwritten.
    Signed { event: NostrTransportEvent },
    /// Network send has started for these exact signed bytes. Every retry must
    /// republish these exact bytes without discarding or re-signing them.
    Sending { event: NostrTransportEvent },
    /// Relay acceptance has been checkpointed for these exact signed bytes
    /// before directory ingestion and kind-1059 inbox route verification.
    Verifying {
        event: NostrTransportEvent,
        #[serde(default)]
        accepted_endpoints: Vec<String>,
    },
}

impl PendingAutoInbox {
    pub(super) fn send_started(&self) -> bool {
        matches!(
            self.phase,
            PendingAutoInboxPhase::Sending { .. } | PendingAutoInboxPhase::Verifying { .. }
        )
    }

    /// Whether this pending automatic inbox send is definitively unexposed
    /// (every target refused or failed pre-send, with no prior exposed attempt),
    /// unlocking `EditRelays` / `CancelRepair` / `EditDiscoveryRelays` while
    /// preserving the original signed bytes for `Retry`.
    pub(super) fn unexposed_sending_refusal(&self, status: OnboardingStatus) -> bool {
        matches!(self.phase, PendingAutoInboxPhase::Sending { .. })
            && self.may_have_published == Some(false)
            && status == OnboardingStatus::RetryableFailure
    }
}

pub(super) struct AutoInboxCandidate {
    pub(super) relays: Vec<String>,
    pub(super) targets: Vec<String>,
}

pub(super) fn auto_inbox_discovery_complete(
    sources: &[String],
    completed: &HashMap<String, CompletedInspectionSource>,
    recommended: &str,
) -> bool {
    completed.contains_key(&relay_key(recommended))
        && sources
            .iter()
            .all(|endpoint| completed.contains_key(&relay_key(endpoint)))
}

impl AccountSetup<'_> {
    /// First policy-allowed, non-onion recommended inbox relay from
    /// `options.defaults_for(OnboardingStep::InboxRelays)`.
    pub(super) fn recommended_inbox_relay(&self, c: &OnboardingCheckpoint) -> Option<String> {
        self.app()
            .relay_plane
            .classify_relay_endpoints(c.options.defaults_for(OnboardingStep::InboxRelays).to_vec())
            .into_iter()
            .find(|classified| {
                classified.policy == RelayEndpointPolicy::Allowed
                    && !is_onion_relay(&classified.endpoint)
            })
            .map(|classified| classified.endpoint.trim().to_owned())
    }

    /// Discovery sources for `InboxRelays`, including the recommended inbox
    /// relay when automatic creation is enabled so an existing list on that
    /// relay is always discovered before publication. Returns
    /// `(all_sources_with_indexers, non_indexer_candidates)`.
    pub(super) async fn inbox_discovery_sources(
        &self,
        c: &OnboardingCheckpoint,
        recommended: Option<&str>,
    ) -> (Vec<String>, Vec<String>) {
        let indexers = if c.explicit_discovery {
            Vec::new()
        } else {
            self.app().discovery_indexer_relays()
        };
        let mut non_indexers = self
            .onboarding_sources_with(c, OnboardingStep::InboxRelays, &[])
            .await;
        if let Some(relay) = recommended
            && !non_indexers
                .iter()
                .any(|existing| relay_key(existing) == relay_key(relay))
        {
            non_indexers.push(relay.to_owned());
        }
        let mut sources = non_indexers.clone();
        append_public_indexers(&mut sources, &c.options, &indexers);
        (sources, non_indexers)
    }

    /// Whether the local directory cache already holds a signed or legacy
    /// kind-10050 inbox list for this account. Fails closed on directory read
    /// errors.
    pub(super) fn has_cached_inbox_list(&self, account_id: &str) -> bool {
        match self
            .app()
            .directory()
            .account_relay_list_status_for_account_id(account_id)
        {
            Ok(status) => status.inbox.created_at > 0 || !status.inbox.relays.is_empty(),
            Err(_) => true,
        }
    }

    /// Returns the local directory's effective kind-10050 inbox list when it
    /// supersedes `event` under the directory's replaceable-event ordering
    /// (strictly newer `created_at`, or equal nonzero `created_at` with a
    /// different relay set).
    pub(super) fn cached_effective_inbox_supersedes(
        &self,
        account_id: &str,
        event: &NostrTransportEvent,
    ) -> Result<Option<crate::AccountRelayListState>, AppError> {
        let status = self
            .app()
            .directory()
            .account_relay_list_status_for_account_id(account_id)?;
        let cached = status.inbox;
        if cached.created_at == 0 {
            return Ok(None);
        }
        if cached.created_at > event.created_at {
            return Ok(Some(cached));
        }
        if cached.created_at == event.created_at {
            let event_keys: HashSet<String> = crate::relay_list_state_from_event(event)
                .map(|state| state.relays.iter().map(|r| relay_key(r)).collect())
                .unwrap_or_default();
            let cached_keys: HashSet<String> = cached.relays.iter().map(|r| relay_key(r)).collect();
            if cached_keys != event_keys {
                return Ok(Some(cached));
            }
        }
        Ok(None)
    }

    /// Non-indexer publish targets from `non_indexer_sources` that completed
    /// discovery and satisfy dial policy, guaranteed to include `recommended`
    /// (otherwise empty).
    pub(super) fn checked_auto_inbox_targets(
        &self,
        non_indexer_sources: Vec<String>,
        recommended: &str,
        completed: &HashMap<String, CompletedInspectionSource>,
    ) -> Vec<String> {
        let candidates: Vec<TransportEndpoint> = non_indexer_sources
            .into_iter()
            .filter(|endpoint| completed.contains_key(&relay_key(endpoint)))
            .map(TransportEndpoint)
            .collect();
        let safe = self
            .app()
            .relay_plane
            .retain_safe_discovered_endpoints(candidates, "onboarding auto inbox");
        let targets: Vec<String> = safe.into_iter().map(|endpoint| endpoint.0).collect();
        if targets
            .iter()
            .any(|endpoint| relay_key(endpoint) == relay_key(recommended))
        {
            targets
        } else {
            Vec::new()
        }
    }

    /// Sign a fresh automatic kind-10050 candidate, durably checkpoint it as
    /// `Signed`, and drive publication. Nothing is stored in `c.auto_inbox`
    /// until signing succeeds.
    pub(super) async fn begin_auto_inbox_creation(
        &self,
        c: &mut OnboardingCheckpoint,
        candidate: AutoInboxCandidate,
    ) -> Result<bool, AppError> {
        let account = self.records().resolve(&c.snapshot.account_id_hex)?;
        let signer = match self.app().account_signer_for_summary(&account) {
            Ok(signer) => signer.as_nostr_signer(),
            Err(error) => {
                set_operation_error(c, OnboardingStep::InboxRelays, &error);
                self.save_onboarding(c)?;
                return Ok(false);
            }
        };
        self.require_live_onboarding_attempt(c)?;
        if account.external_signing {
            c.set(
                OnboardingStep::InboxRelays,
                OnboardingStatus::WaitingForSigner,
                Vec::new(),
            );
            self.save_onboarding(c)?;
        }
        let tags: Vec<Vec<String>> = candidate
            .relays
            .iter()
            .map(|relay| vec!["relay".to_owned(), relay.clone()])
            .collect();
        let event = match self
            .sign_onboarding_event(
                c,
                OnboardingStep::InboxRelays,
                &account,
                &signer,
                tags,
                String::new(),
                unix_now_seconds(),
                "onboarding inbox creation",
            )
            .await?
        {
            Ok(event) => event,
            Err(AppError::ExternalSignerRejected) => {
                // The user declined automatic creation; fall back to manual
                // selection and do not re-prompt on retry.
                self.require_live_onboarding_attempt(c)?;
                c.auto_inbox = None;
                c.auto_inbox_declined = true;
                c.set(
                    OnboardingStep::InboxRelays,
                    OnboardingStatus::NeedsInput,
                    vec![missing_record_finding()],
                );
                self.save_onboarding(c)?;
                return Ok(false);
            }
            Err(error) => {
                self.require_live_onboarding_attempt(c)?;
                set_operation_error(c, OnboardingStep::InboxRelays, &error);
                self.save_onboarding(c)?;
                return Ok(false);
            }
        };
        c.auto_inbox = Some(PendingAutoInbox {
            relays: candidate.relays,
            targets: candidate.targets,
            phase: PendingAutoInboxPhase::Signed { event },
            may_have_published: Some(false),
        });
        c.set(
            OnboardingStep::InboxRelays,
            OnboardingStatus::Checking,
            Vec::new(),
        );
        // Durable checkpoint of exact signed bytes before any network send.
        self.save_onboarding(c)?;
        // Local signing ran synchronously after complete discovery; external
        // signing is asynchronous and requires one pre-send freshness check.
        self.drive_pending_auto_inbox(c, !account.external_signing)
            .await
    }

    /// Drive a durably checkpointed `PendingAutoInbox` (`Signed`, `Sending`, or
    /// `Verifying`) through pre-send freshness verification, publication,
    /// directory ingestion, and post-publish inbox-route validation.
    ///
    /// Returns `Ok(true)` when `InboxRelays` is settled and `Passed` so
    /// `run_onboarding_locked` can refresh expired prerequisites and continue.
    /// Returns `Ok(false)` when onboarding paused or the attempt was retired.
    pub(super) async fn drive_pending_auto_inbox(
        &self,
        c: &mut OnboardingCheckpoint,
        freshly_verified: bool,
    ) -> Result<bool, AppError> {
        let account_id = c.snapshot.account_id_hex.clone();
        let attempt = c.attempt();

        if !matches!(
            c.auto_inbox.as_ref().map(|pending| &pending.phase),
            Some(PendingAutoInboxPhase::Verifying { .. })
        ) {
            // Obtain the signer before committing `Signed -> Sending` so a
            // resumed checkpoint whose external signer is disconnected never
            // skips the pre-send freshness check after reconnection.
            let account = self.records().resolve(&account_id)?;
            let signer = match self.app().account_signer_for_summary(&account) {
                Ok(signer) => signer.as_nostr_signer(),
                Err(error) => {
                    set_operation_error(c, OnboardingStep::InboxRelays, &error);
                    self.save_onboarding(c)?;
                    return Ok(false);
                }
            };

            // Capture prior exposure BEFORE persisting in-flight `Sending` so a
            // first attempt whose targets all definitively refuse can still
            // unlock manual relay editing, while any interrupted or previously
            // uncertain attempt stays conservatively exposed.
            let prior_exposed = c
                .auto_inbox
                .as_ref()
                .is_none_or(|pending| pending.may_have_published != Some(false));

            // Phase 1: Signed -> Sending (with one freshness recheck when resumed or after external sign)
            if let Some(PendingAutoInbox {
                relays,
                targets,
                phase: PendingAutoInboxPhase::Signed { event },
                ..
            }) = c.auto_inbox.clone()
            {
                let targets = if freshly_verified {
                    targets
                } else {
                    let outcome = self
                        .await_while_onboarding_live(
                            &account_id,
                            attempt,
                            self.check_onboarding_step_outcome(c, OnboardingStep::InboxRelays),
                        )
                        .await??;
                    self.require_live_onboarding_attempt(c)?;
                    match outcome {
                        StepCheckOutcome::CreateMissingInbox(fresh) if fresh.relays == relays => {
                            fresh.targets
                        }
                        StepCheckOutcome::CreateMissingInbox(_) => {
                            // Recommended defaults changed (e.g. policy retired the
                            // pre-signed relay); abort instead of sending stale bytes.
                            c.auto_inbox = None;
                            c.set(
                                OnboardingStep::InboxRelays,
                                OnboardingStatus::NeedsInput,
                                vec![missing_record_finding()],
                            );
                            self.save_onboarding(c)?;
                            return Ok(false);
                        }
                        StepCheckOutcome::Checked {
                            status: OnboardingStatus::RetryableFailure,
                            findings,
                            event: None,
                        } => {
                            // Freshness check was incomplete with no list found:
                            // keep `Signed` so retry checks again without re-signing.
                            c.set(
                                OnboardingStep::InboxRelays,
                                OnboardingStatus::RetryableFailure,
                                findings,
                            );
                            self.save_onboarding(c)?;
                            return Ok(false);
                        }
                        StepCheckOutcome::Checked {
                            status,
                            findings,
                            event,
                        } => {
                            // An existing kind-10050 (valid, unusable, or future-dated)
                            // or previously seen/cached record takes precedence.
                            c.auto_inbox = None;
                            c.snapshot.created_inbox_list = None;
                            self.apply_checked_step(
                                c,
                                OnboardingStep::InboxRelays,
                                status,
                                findings,
                                event,
                            )?;
                            self.save_onboarding(c)?;
                            return Ok(status == OnboardingStatus::Passed);
                        }
                    }
                };

                self.require_live_onboarding_attempt(c)?;
                c.auto_inbox = Some(PendingAutoInbox {
                    relays,
                    targets,
                    phase: PendingAutoInboxPhase::Sending { event },
                    may_have_published: Some(true),
                });
                c.set(
                    OnboardingStep::InboxRelays,
                    OnboardingStatus::Checking,
                    Vec::new(),
                );
                // Persist `Sending` and in-flight exposure immediately before
                // invoking the publisher so a crash mid-send stays conservative
                // and retries republish these exact signed bytes.
                self.save_onboarding(c)?;
            } else if let Some(pending) = c.auto_inbox.as_mut()
                && pending.may_have_published != Some(true)
            {
                pending.may_have_published = Some(true);
                self.save_onboarding(c)?;
            }

            // Phase 2: Sending -> Verifying (after acceptance) or RetryableFailure
            let (relays, target_urls, event) = match c.auto_inbox.as_ref() {
                Some(PendingAutoInbox {
                    relays,
                    targets,
                    phase: PendingAutoInboxPhase::Sending { event },
                    ..
                }) => (relays.clone(), targets.clone(), event.clone()),
                _ => return Err(onboarding_error()),
            };
            let endpoints = self.app().relay_plane.retain_safe_discovered_endpoints(
                target_urls.iter().cloned().map(TransportEndpoint).collect(),
                "onboarding auto inbox",
            );
            if endpoints.is_empty() {
                if let Some(pending) = c.auto_inbox.as_mut() {
                    pending.may_have_published = Some(prior_exposed);
                }
                c.set(
                    OnboardingStep::InboxRelays,
                    OnboardingStatus::RetryableFailure,
                    vec![finding(OnboardingIssue::PublicationFailed).in_context(
                        OnboardingFindingContext::RepairPublication,
                        OnboardingCheckPurpose::EventPublication,
                    )],
                );
                self.save_onboarding(c)?;
                return Ok(false);
            }
            let Some(outcome) = self
                .publish_onboarding_event(c, &account, signer, &endpoints, &event)
                .await?
            else {
                return Ok(false);
            };
            let accepted = match outcome {
                Ok(outcome) if !outcome.accepted.is_empty() => outcome.accepted,
                outcome => {
                    let endpoint_failures = match outcome {
                        Ok(outcome) => outcome.failed,
                        Err(TransportAdapterError::PublishEndpoints(failure)) => {
                            failure.endpoint_failures
                        }
                        Err(error) => {
                            let app_error = AppError::from(error);
                            if matches!(
                                app_error,
                                AppError::ExternalSignerUnavailable(_)
                                    | AppError::ExternalSignerRejected
                            ) {
                                set_operation_error(c, OnboardingStep::InboxRelays, &app_error);
                                self.save_onboarding(c)?;
                                return Ok(false);
                            }
                            Vec::new()
                        }
                    };
                    let may_have_published =
                        prior_exposed || attempt_may_have_published(&endpoints, &endpoint_failures);
                    let findings = publish_failure_findings(
                        OnboardingFindingContext::RepairPublication,
                        None,
                        &endpoint_failures,
                    );
                    // Retain the original signed event in `auto_inbox` even on
                    // definitive refusal so `Retry` (including after restart)
                    // republishes the exact bytes without re-invoking the
                    // signer. `may_have_published == Some(false)` unlocks
                    // `EditRelays`, `CancelRepair`, and `EditDiscoveryRelays`.
                    if let Some(pending) = c.auto_inbox.as_mut() {
                        pending.may_have_published = Some(may_have_published);
                    }
                    c.set(
                        OnboardingStep::InboxRelays,
                        OnboardingStatus::RetryableFailure,
                        findings,
                    );
                    self.save_onboarding(c)?;
                    return Ok(false);
                }
            };
            let accepted_endpoints: Vec<String> = accepted
                .into_iter()
                .map(|receipt| receipt.endpoint.0)
                .collect();
            c.records[OnboardingStep::InboxRelays.index()] = Some(event.clone());
            c.seen_signed_inbox_list = true;
            c.snapshot.created_inbox_list = Some(OnboardingCreatedInboxList {
                relays: relays.clone(),
                event_id: event.id.clone(),
                published_at: event.created_at,
            });
            c.auto_inbox = Some(PendingAutoInbox {
                relays,
                targets: target_urls,
                phase: PendingAutoInboxPhase::Verifying {
                    event,
                    accepted_endpoints,
                },
                may_have_published: Some(true),
            });
            c.set(
                OnboardingStep::InboxRelays,
                OnboardingStatus::Checking,
                Vec::new(),
            );
            // Checkpoint publication acceptance BEFORE fallible directory
            // ingestion and kind-1059 route verification so an ingestion error
            // or crash after relay ACK never republishes or loses the receipt.
            self.save_onboarding(c)?;
        }

        // Phase 3: Verifying -> idempotently ingest accepted event into the
        // directory, verify it is still the effective declaration, and check
        // the effective kind-1059 inbox route before passing `InboxRelays`.
        let (targets, event, accepted_endpoints) = match c.auto_inbox.as_ref() {
            Some(PendingAutoInbox {
                targets,
                phase:
                    PendingAutoInboxPhase::Verifying {
                        event,
                        accepted_endpoints,
                    },
                ..
            }) => (targets.clone(), event.clone(), accepted_endpoints.clone()),
            _ => return Err(onboarding_error()),
        };
        let ingest_endpoints: Vec<TransportEndpoint> = if accepted_endpoints.is_empty() {
            targets.into_iter().map(TransportEndpoint).collect()
        } else {
            accepted_endpoints
                .into_iter()
                .map(TransportEndpoint)
                .collect()
        };
        self.app()
            .directory()
            .ingest_directory_relay_event(DirectoryRelayEventRecord {
                endpoints: ingest_endpoints,
                event: event.clone(),
            })?;

        // Check whether a newer or equal-timestamp different declaration in
        // the directory superseded this accepted event (e.g. a lagging relay
        // accepted older bytes while the directory already holds a newer list).
        if self
            .cached_effective_inbox_supersedes(&account_id, &event)?
            .is_some()
        {
            c.auto_inbox = None;
            c.snapshot.created_inbox_list = None;
            c.records[OnboardingStep::InboxRelays.index()] = None;
            self.save_onboarding(c)?;
            let outcome = self
                .await_while_onboarding_live(
                    &account_id,
                    attempt,
                    self.check_onboarding_step_outcome(c, OnboardingStep::InboxRelays),
                )
                .await??;
            self.require_live_onboarding_attempt(c)?;
            match outcome {
                StepCheckOutcome::Checked {
                    status,
                    findings,
                    event,
                } => {
                    self.apply_checked_step(
                        c,
                        OnboardingStep::InboxRelays,
                        status,
                        findings,
                        event,
                    )?;
                    if c.snapshot.ready {
                        c.setup_cleanup_pending = true;
                    }
                    self.save_onboarding(c)?;
                    return Ok(status == OnboardingStatus::Passed);
                }
                StepCheckOutcome::CreateMissingInbox(_) => {
                    // `seen_signed_inbox_list` is already true, so this arm is
                    // unreachable; fail closed to manual selection.
                    c.set(
                        OnboardingStep::InboxRelays,
                        OnboardingStatus::NeedsInput,
                        vec![missing_record_finding()],
                    );
                    self.save_onboarding(c)?;
                    return Ok(false);
                }
            }
        }

        let (status, findings, _) = self
            .await_while_onboarding_live(
                &account_id,
                attempt,
                self.evaluate_onboarding_record(
                    c,
                    OnboardingStep::InboxRelays,
                    event,
                    Vec::new(),
                    None,
                ),
            )
            .await?;
        self.require_live_onboarding_attempt(c)?;
        c.auto_inbox = None;
        c.set(OnboardingStep::InboxRelays, status, findings);
        if c.snapshot.ready {
            c.setup_cleanup_pending = true;
        }
        self.save_onboarding(c)?;
        Ok(status == OnboardingStatus::Passed)
    }
}
