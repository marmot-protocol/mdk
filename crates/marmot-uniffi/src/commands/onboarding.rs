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
    /// Whether an unreadable or exhausted checkpoint needs explicit recovery.
    pub fn onboarding_recovery_required(
        &self,
        account_ref: String,
    ) -> Result<bool, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .onboarding_recovery_required(&account_ref)?)
    }

    /// Preserve opaque evidence, sign out, and retire the old attempt. Hosts
    /// invalidate old UI callbacks first, acknowledge latest-only retention,
    /// then explicitly begin again and use the snapshot's recovery_epoch.
    pub async fn recover_onboarding(
        &self,
        account_ref: String,
        acknowledge_latest_only_evidence: bool,
    ) -> Result<String, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .recover_onboarding(&account_ref, acknowledge_latest_only_evidence)
            .await?)
    }

    /// Approve with the epoch and revision from the same displayed snapshot.
    pub async fn approve_onboarding_repair_in_epoch(
        &self,
        account_ref: String,
        revision: u64,
        recovery_epoch: String,
    ) -> Result<OnboardingSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .approve_onboarding_repair_in_epoch(&account_ref, revision, &recovery_epoch)
            .await?
            .into())
    }

    /// Acknowledge with the epoch and revision from the displayed device notice.
    pub async fn acknowledge_onboarding_single_device_in_epoch(
        &self,
        account_ref: String,
        revision: u64,
        recovery_epoch: String,
    ) -> Result<OnboardingSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .acknowledge_onboarding_single_device_in_epoch(&account_ref, revision, &recovery_epoch)
            .await?
            .into())
    }

    /// Cancel the current interactive onboarding attempt at any step, including
    /// approved or ready checkpoints. The identity stays signed out. Already
    /// journaled evidence is retained in the latest cancellation checkpoint;
    /// later cancellations replace it even if publication remains uncertain. A later explicit `begin_*_onboarding` starts a new attempt.
    /// Hosts should invalidate the UI attempt, ignore the old subscription, and
    /// await this call before beginning again. Open Chats stays host-owned.
    pub async fn cancel_onboarding(&self, account_ref: String) -> Result<(), MarmotKitError> {
        Ok(self
            .runtime
            .accounts()
            .cancel_onboarding(&account_ref)
            .await?)
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use marmot_app::MarmotApp;
    use nostr::prelude::ToBech32;
    use nostr_relay_builder::MockRelay;

    fn options(relay_url: String) -> OnboardingOptionsFfi {
        OnboardingOptionsFfi {
            default_relays: vec![relay_url.clone()],
            discovery_relays: vec![relay_url],
        }
    }

    fn patch_onboarding_checkpoint(
        root: &std::path::Path,
        id: &str,
        patch: impl FnOnce(&mut serde_json::Value),
    ) {
        let path = root.join("accounts").join(id).join("onboarding.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("checkpoint")).expect("json");
        patch(&mut value);
        std::fs::write(path, serde_json::to_vec(&value).expect("serialize")).expect("write");
    }

    fn repair_archive_count(root: &std::path::Path, id: &str) -> usize {
        usize::from(
            root.join("accounts")
                .join(id)
                .join("onboarding-cancelled.json")
                .is_file(),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancel_onboarding_maps_approved_and_ready_attempts_to_signed_out_unit() {
        let relay = MockRelay::run().await.expect("start mock relay");
        let relay_url = relay.url().await.to_string();
        let root = tempfile::tempdir().expect("tempdir");
        let app = MarmotApp::with_relay(root.path(), relay_url.clone());
        let runtime = app.runtime();
        let kit = Marmot { app, runtime };
        let keys = nostr::Keys::generate();
        let id = keys.public_key().to_hex();
        let snapshot = kit
            .begin_onboarding(
                keys.secret_key().to_bech32().unwrap(),
                options(relay_url.clone()),
            )
            .await
            .expect("begin");
        assert!(!snapshot.ready);
        patch_onboarding_checkpoint(root.path(), &id, |value| {
            value["snapshot"]["steps"][2]["status"] = serde_json::json!("NeedsInput");
        });
        let proposal = kit
            .propose_onboarding_recommended_relays(id.clone(), OnboardingStepFfi::Relays)
            .await
            .expect("propose");
        drop(relay);
        let approved = kit
            .approve_onboarding_repair(id.clone(), proposal.revision)
            .await
            .expect("approve after the relay is gone");
        assert!(approved.proposal.is_some());
        let subscription = kit
            .subscribe_onboarding(id.clone())
            .expect("subscribe approved");
        kit.cancel_onboarding(id.clone())
            .await
            .expect("cancel approved");
        let terminal = subscription.next().await.expect("terminal snapshot");
        assert!(terminal.cancellation_pending && !terminal.ready);
        assert!(subscription.next().await.is_none());
        kit.cancel_onboarding(id.clone())
            .await
            .expect("repeat cancel is a no-op");
        assert!(kit.onboarding_snapshot(id.clone()).unwrap().is_none());
        assert_eq!(repair_archive_count(root.path(), &id), 1);
        let again = kit
            .begin_onboarding(keys.secret_key().to_bech32().unwrap(), options(relay_url))
            .await
            .expect("explicit restart");
        assert!(!again.ready && !again.cancellation_pending && again.proposal.is_none());
        patch_onboarding_checkpoint(root.path(), &id, |value| {
            for step in value["snapshot"]["steps"].as_array_mut().expect("steps") {
                step["status"] = serde_json::json!("Passed");
            }
            value["snapshot"]["ready"] = serde_json::json!(true);
        });
        let ready = kit
            .onboarding_snapshot(id.clone())
            .expect("ready snapshot")
            .expect("present");
        assert!(ready.ready);
        kit.cancel_onboarding(id.clone())
            .await
            .expect("cancel ready");
        assert!(kit.onboarding_snapshot(id.clone()).unwrap().is_none());
        kit.runtime.shutdown().await;
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn recovery_exports_epoch_and_requires_scoped_repair_approval() {
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await.to_string();
        let root = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relay(root.path(), relay_url.clone());
        let kit = Marmot {
            runtime: app.runtime(),
            app,
        };
        let keys = nostr::Keys::generate();
        let id = keys.public_key().to_hex();
        kit.begin_onboarding(
            keys.secret_key().to_bech32().unwrap(),
            options(relay_url.clone()),
        )
        .await
        .unwrap();
        patch_onboarding_checkpoint(root.path(), &id, |value| {
            value["version"] = serde_json::json!(999)
        });
        assert!(kit.onboarding_recovery_required(id.clone()).unwrap());
        assert!(kit.recover_onboarding(id.clone(), false).await.is_err());
        let epoch = kit.recover_onboarding(id.clone(), true).await.unwrap();
        let fresh = kit
            .begin_onboarding(keys.secret_key().to_bech32().unwrap(), options(relay_url))
            .await
            .unwrap();
        assert_eq!(fresh.recovery_epoch.as_deref(), Some(epoch.as_str()));
        patch_onboarding_checkpoint(root.path(), &id, |value| {
            value["snapshot"]["steps"][2]["status"] = serde_json::json!("NeedsInput")
        });
        let proposal = kit
            .propose_onboarding_recommended_relays(id.clone(), OnboardingStepFfi::Relays)
            .await
            .unwrap();
        assert!(
            kit.approve_onboarding_repair(id.clone(), proposal.revision)
                .await
                .is_err()
        );
        assert!(
            kit.approve_onboarding_repair_in_epoch(id.clone(), proposal.revision, "stale".into())
                .await
                .is_err()
        );
        drop(relay);
        let approved = kit
            .approve_onboarding_repair_in_epoch(id.clone(), proposal.revision, epoch.clone())
            .await
            .unwrap();
        assert_eq!(approved.recovery_epoch.as_deref(), Some(epoch.as_str()));
        kit.cancel_onboarding(id.clone()).await.unwrap();
        assert!(kit.onboarding_snapshot(id).unwrap().is_none());
        kit.runtime.shutdown_and_close().await.unwrap();
    }
}
