//! Advisory installation detection without opening a worker or publishing.
use super::*;

impl AccountManager {
    pub(super) async fn check_onboarding_single_device(
        &self,
        checkpoint: &mut OnboardingCheckpoint,
    ) -> Result<(), AppError> {
        let id = &checkpoint.snapshot.account_id_hex;
        let account = self.resolve(id)?;
        let storage = self.app.account_storage(&account.label)?;
        let owned = cgka_engine::key_package::durably_owned_key_packages(
            &storage,
            cgka_traits::group::ProtocolProfile::Current,
        )
        .map_err(cgka_session::SessionError::from)?;
        let local = self.app.local_key_package_records(&account.label, owned)?;
        let mut slots: HashSet<String> = local.iter().map(|p| p.key_package_id.clone()).collect();
        if let Some(lifecycle) = storage.key_package_lifecycle()? {
            slots.insert(lifecycle.stable_slot_id);
        }
        slots.remove("");
        let refs: HashSet<String> = local.into_iter().map(|p| p.key_package_ref_hex).collect();
        let sources = self
            .onboarding_sources(checkpoint, OnboardingStep::SingleDevice)
            .await;
        let (events, mut findings, completed) =
            self.inspect_onboarding_relays(id, 30443, sources).await;
        let now = unix_now_seconds();
        let mut packages = Vec::new();
        let mut seen_slots = HashSet::new();
        for event in events {
            // The inspector verifies authors/signatures and sorts newest first,
            // including Nostr's event-id tie break. Inspect only each slot's
            // newest record; a malformed replacement must not revive an old one.
            let Some(slot) = event
                .tag_value("d")
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
            else {
                findings.push(finding(OnboardingIssue::Malformed));
                continue;
            };
            if !seen_slots.insert(slot.clone()) {
                continue;
            }
            if slots.contains(&slot) {
                continue;
            }
            let event_id_hex = event.id.clone();
            let published_at = event.created_at;
            let parsed =
                crate::key_package_records::key_package_from_record(DirectoryRelayEventRecord {
                    endpoints: Vec::new(),
                    event,
                })
                .ok();
            let metadata = parsed
                .as_ref()
                .and_then(|f| crate::key_package_metadata(&f.key_package).ok());
            let reference = metadata.as_ref().map(|m| m.key_package_ref_hex.clone());
            if reference.as_ref().is_some_and(|r| refs.contains(r)) {
                continue;
            }
            let future = published_at > now + FUTURE_CLOCK_SKEW;
            if future {
                findings.push(finding(OnboardingIssue::FutureDated));
            }
            if metadata.is_none() {
                findings.push(finding(OnboardingIssue::Malformed));
            }
            // A verified account-authored foreign slot is evidence even when
            // its payload is unusable. Package validity is a separate property.
            packages.push(OnboardingDevicePackage {
                slot_id: slot,
                key_package_ref_hex: reference,
                event_id_hex,
                published_at,
                expires_at: metadata.as_ref().map(|m| m.not_after),
                usable: !future
                    && metadata
                        .as_ref()
                        .is_some_and(|m| m.not_before <= now && m.not_after > now),
            });
        }
        // Missing any selected source remains inconclusive even if others reached EOSE.
        let discovery_complete = completed > 0 && findings.is_empty();
        let discovery = if !packages.is_empty() {
            findings.push(finding(OnboardingIssue::OtherInstallationPossible));
            OnboardingDeviceDiscovery::OtherInstallationPossible
        } else if discovery_complete {
            OnboardingDeviceDiscovery::NoneFound
        } else {
            OnboardingDeviceDiscovery::Unknown
        };
        findings.insert(0, finding(OnboardingIssue::MultiDeviceUnsupported));
        checkpoint.snapshot.single_device_notice = Some(OnboardingSingleDeviceNotice {
            discovery,
            other_packages: packages,
            discovery_complete,
            acknowledged_at: None,
        });
        checkpoint.set(
            OnboardingStep::SingleDevice,
            OnboardingStatus::NeedsInput,
            findings,
        );
        Ok(())
    }

    /// Acknowledge the one-device limitation for this onboarding attempt. This
    /// authorizes normal setup publication, never deletion of another slot.
    /// Persist before resuming so cancellation/restart cannot lose the choice.
    pub async fn acknowledge_onboarding_single_device(
        &self,
        account_ref: &str,
        revision: u64,
    ) -> Result<OnboardingSnapshot, AppError> {
        self.acknowledge_onboarding_single_device_scoped(account_ref, revision, None)
            .await
    }

    /// Acknowledge the displayed device notice after explicit recovery.
    pub async fn acknowledge_onboarding_single_device_in_epoch(
        &self,
        account_ref: &str,
        revision: u64,
        recovery_epoch: &str,
    ) -> Result<OnboardingSnapshot, AppError> {
        self.acknowledge_onboarding_single_device_scoped(
            account_ref,
            revision,
            Some(recovery_epoch),
        )
        .await
    }

    async fn acknowledge_onboarding_single_device_scoped(
        &self,
        account_ref: &str,
        revision: u64,
        recovery_epoch: Option<&str>,
    ) -> Result<OnboardingSnapshot, AppError> {
        let (account_id, attempt) = self.peek_onboarding_attempt(account_ref)?;
        let transaction = self.onboarding_transaction(&account_id);
        let _transaction = transaction.lock().await;
        let mut checkpoint = self
            .onboarding_checkpoint(account_ref)?
            .ok_or_else(onboarding_error)?;
        self.require_captured_attempt(&checkpoint, attempt)?;
        let step = &checkpoint.snapshot.steps[OnboardingStep::SingleDevice.index()];
        if checkpoint.snapshot.recovery_epoch.as_deref() != recovery_epoch
            || checkpoint.snapshot.revision != revision
            || checkpoint.approved
            || checkpoint.snapshot.proposal.is_some()
            || checkpoint.single_device_acknowledged
            || checkpoint.snapshot.steps[..OnboardingStep::SingleDevice.index()]
                .iter()
                .any(|s| {
                    !matches!(
                        s.status,
                        OnboardingStatus::Passed | OnboardingStatus::Skipped
                    )
                })
            || step.status != OnboardingStatus::NeedsInput
            || !step.actions.contains(&OnboardingAction::ContinueAnyway)
        {
            return Err(onboarding_error());
        }
        let notice = checkpoint
            .snapshot
            .single_device_notice
            .as_mut()
            .ok_or_else(onboarding_error)?;
        notice.acknowledged_at = Some(unix_now_seconds());
        checkpoint.single_device_acknowledged = true;
        let findings = step.findings.clone();
        checkpoint.set(
            OnboardingStep::SingleDevice,
            OnboardingStatus::Passed,
            findings,
        );
        self.save_onboarding(&mut checkpoint)?;
        self.run_onboarding_locked(&mut checkpoint).await?;
        Ok(checkpoint.snapshot)
    }
}
