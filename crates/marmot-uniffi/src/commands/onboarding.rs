//! Identity-only sign-in and resumable preflight commands.
use crate::conversions::{
    OnboardingOptionsFfi, OnboardingSnapshotFfi, OnboardingStepFfi, UserProfileMetadataFfi,
};
use crate::external_signer::{ExternalAccountSignerAdapter, ExternalAccountSignerFfi};
use crate::{Marmot, MarmotKitError};
use std::sync::Arc;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

#[derive(uniffi::Object)]
pub struct OnboardingSubscription {
    snapshot: OnboardingSnapshotFfi,
    inner: Mutex<marmot_app::OnboardingSubscription>,
}
#[uniffi::export(async_runtime = "tokio")]
impl OnboardingSubscription {
    pub fn snapshot(&self) -> OnboardingSnapshotFfi {
        self.snapshot.clone()
    }
    pub async fn next(&self) -> Option<OnboardingSnapshotFfi> {
        self.inner.lock().await.recv().await.map(Into::into)
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Record Continue anyway for the displayed notice, then resume setup.
    pub async fn acknowledge_onboarding_single_device(
        &self,
        account_ref: String,
        revision: u64,
    ) -> Result<OnboardingSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .acknowledge_onboarding_single_device(&account_ref, revision)
            .await?
            .into())
    }
    /// Persist the identity and return before any network preflight or publication.
    pub async fn begin_onboarding(
        &self,
        nsec: String,
        options: OnboardingOptionsFfi,
    ) -> Result<OnboardingSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .begin_onboarding(Zeroizing::new(nsec), options.into())
            .await?
            .into())
    }
    pub async fn begin_external_signer_onboarding(
        &self,
        public_key: String,
        signer: Arc<dyn ExternalAccountSignerFfi>,
        options: OnboardingOptionsFfi,
    ) -> Result<OnboardingSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .begin_external_signer_onboarding(
                public_key,
                ExternalAccountSignerAdapter::new(signer),
                options.into(),
            )
            .await?
            .into())
    }
    pub fn onboarding_snapshot(
        &self,
        account_ref: String,
    ) -> Result<Option<OnboardingSnapshotFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .onboarding_snapshot(&account_ref)?
            .map(Into::into))
    }
    pub fn subscribe_onboarding(
        &self,
        account_ref: String,
    ) -> Result<Arc<OnboardingSubscription>, MarmotKitError> {
        let subscription = self.runtime.accounts().subscribe_onboarding(&account_ref)?;
        Ok(Arc::new(OnboardingSubscription {
            snapshot: subscription.snapshot.clone().into(),
            inner: Mutex::new(subscription),
        }))
    }
    pub async fn set_onboarding_discovery_relays(
        &self,
        account_ref: String,
        discovery_relays: Vec<String>,
    ) -> Result<OnboardingSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .set_onboarding_discovery_relays(&account_ref, discovery_relays)
            .await?
            .into())
    }
    pub async fn run_onboarding(
        &self,
        account_ref: String,
    ) -> Result<OnboardingSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .run_onboarding(&account_ref)
            .await?
            .into())
    }
    pub async fn retry_onboarding_step(
        &self,
        account_ref: String,
        step: OnboardingStepFfi,
    ) -> Result<OnboardingSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .retry_onboarding_step(&account_ref, step.into())
            .await?
            .into())
    }
    pub async fn continue_onboarding_without(
        &self,
        account_ref: String,
        step: OnboardingStepFfi,
    ) -> Result<OnboardingSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .continue_onboarding_without(&account_ref, step.into())
            .await?
            .into())
    }
    pub async fn propose_onboarding_recommended_relays(
        &self,
        account_ref: String,
        step: OnboardingStepFfi,
    ) -> Result<OnboardingSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .propose_onboarding_relays(&account_ref, step.into(), None)
            .await?
            .into())
    }
    pub async fn propose_onboarding_relays(
        &self,
        account_ref: String,
        step: OnboardingStepFfi,
        read_relays: Vec<String>,
        write_relays: Vec<String>,
    ) -> Result<OnboardingSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .propose_onboarding_relays(&account_ref, step.into(), Some((read_relays, write_relays)))
            .await?
            .into())
    }
    pub async fn propose_onboarding_profile(
        &self,
        account_ref: String,
        profile: UserProfileMetadataFfi,
    ) -> Result<OnboardingSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .propose_onboarding_profile(&account_ref, profile.into())
            .await?
            .into())
    }
    pub async fn propose_onboarding_follows(
        &self,
        account_ref: String,
        follows: Vec<String>,
    ) -> Result<OnboardingSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .propose_onboarding_follows(&account_ref, follows)
            .await?
            .into())
    }
    pub async fn approve_onboarding_repair(
        &self,
        account_ref: String,
        revision: u64,
    ) -> Result<OnboardingSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .approve_onboarding_repair(&account_ref, revision)
            .await?
            .into())
    }
    pub async fn cancel_onboarding_repair(
        &self,
        account_ref: String,
    ) -> Result<OnboardingSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .cancel_onboarding_repair(&account_ref)
            .await?
            .into())
    }
}
