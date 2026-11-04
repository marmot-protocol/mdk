//! Thin host commands; backup eligibility, secrets, import and work stay in MDK.
use crate::Marmot;
use crate::conversions::group_id_from_hex;
use crate::conversions::{
    BackgroundBackupOutcomeFfi, BackupHistoryAvailabilityFfi, BackupRestoreStatusFfi,
    BackupSettingsFfi, RecoveryWordsFfi,
};
use crate::errors::MarmotKitError;
use crate::subscriptions::BackupRestoreSubscription;
use marmot_app::{BackupRestoreId, BackupRestoreWords};
use std::sync::Arc;

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Generate new backup recovery words for one confirmation flow. Show once;
    /// never persist/log them. This is separate from restoring with old words.
    pub async fn begin_recovery_words(
        &self,
        account_ref: String,
    ) -> Result<RecoveryWordsFfi, MarmotKitError> {
        Ok(self
            .runtime
            .begin_recovery_words(&account_ref)
            .await?
            .into())
    }
    /// Confirm the two words at MDK's positions, in order. A busy/error result
    /// keeps the core confirmation flow; hosts clear their managed input copies.
    pub async fn confirm_recovery_words(
        &self,
        account_ref: String,
        answers: Vec<String>,
    ) -> Result<(), MarmotKitError> {
        Ok(self
            .runtime
            .confirm_recovery_words(&account_ref, answers)
            .await?)
    }
    /// Forget the pending confirmation flow; never changes current backups.
    pub async fn cancel_recovery_words(&self, account_ref: String) -> Result<(), MarmotKitError> {
        Ok(self.runtime.cancel_recovery_words(&account_ref).await?)
    }
    /// Disable future account backups. Previously written archives remain.
    pub async fn turn_off_backups(&self, account_ref: String) -> Result<(), MarmotKitError> {
        Ok(self.runtime.turn_off_backups(&account_ref).await?)
    }
    /// Current selected account settings, not confirmation or publication history.
    pub async fn backup_settings(
        &self,
        account_ref: String,
    ) -> Result<BackupSettingsFfi, MarmotKitError> {
        Ok(self.runtime.backup_settings(&account_ref).await?.into())
    }
    /// Report platform facts once per runtime, before workers exist and on
    /// changes. Same-runtime worker restarts retain them; a new runtime is closed.
    /// This starts no account worker. Admitted passes settle after false.
    pub async fn set_runtime_backup_background_conditions(
        &self,
        wifi: bool,
        charging: bool,
    ) -> Result<(), MarmotKitError> {
        Ok(self
            .runtime
            .set_runtime_backup_background_conditions(wifi, charging)?)
    }

    /// Compatibility wrapper for the runtime-wide report. Validates the
    /// existing active account first and never starts a worker.
    pub async fn set_backup_background_conditions(
        &self,
        account_ref: String,
        wifi: bool,
        charging: bool,
    ) -> Result<(), MarmotKitError> {
        Ok(self
            .runtime
            .set_backup_background_conditions(&account_ref, wifi, charging)
            .await?)
    }
    /// Join the current background pass or try due admission once. Finished
    /// means its serialized settlement attempt ended, not successful publication.
    /// Host cancellation detaches this wait; worker stop closes it. The host
    /// bounds its OS-task lifetime. This neither forces work nor waits for future due work.
    pub async fn run_due_backup_pass(
        &self,
        account_ref: String,
    ) -> Result<BackgroundBackupOutcomeFfi, MarmotKitError> {
        Ok(self.runtime.run_due_backup_pass(&account_ref).await?.into())
    }

    /// Start one manual history-only restore. Words move immediately into the
    /// redacted core guard; managed/generated input copies remain host-owned.
    /// This never changes the current recovery key or joins/re-adds a chat.
    pub async fn begin_backup_restore(
        &self,
        account_ref: String,
        words: String,
    ) -> Result<BackupRestoreStatusFfi, MarmotKitError> {
        let words = BackupRestoreWords::new(words);
        Ok(self
            .runtime
            .begin_backup_restore(&account_ref, words)
            .await?
            .into())
    }
    /// Cancel only the named operation. A stale valid token returns false;
    /// malformed tokens are InvalidHex. Committed history remains.
    pub async fn cancel_backup_restore(
        &self,
        account_ref: String,
        operation: String,
    ) -> Result<bool, MarmotKitError> {
        let operation =
            BackupRestoreId::from_hex(&operation).ok_or_else(|| MarmotKitError::InvalidHex {
                details: "invalid backup restore operation token".into(),
            })?;
        Ok(self
            .runtime
            .cancel_backup_restore(&account_ref, operation)
            .await?)
    }
    /// Read aggregate progress; Complete is eligible work settled, not global completeness.
    pub async fn backup_restore_status(
        &self,
        account_ref: String,
    ) -> Result<BackupRestoreStatusFfi, MarmotKitError> {
        Ok(self
            .runtime
            .backup_restore_status(&account_ref)
            .await?
            .into())
    }
    /// One initial snapshot and subsequent status/availability revision wakes.
    /// Closing this observer does not cancel the restore operation.
    pub async fn watch_backup_restore(
        &self,
        account_ref: String,
    ) -> Result<Arc<BackupRestoreSubscription>, MarmotKitError> {
        Ok(BackupRestoreSubscription::new(
            self.runtime.watch_backup_restore(&account_ref).await?,
        ))
    }
    /// Private words-again hints for this CURRENT chat; metadata never creates membership.
    pub async fn backup_history_availability(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<Vec<BackupHistoryAvailabilityFfi>, MarmotKitError> {
        let group = group_id_from_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .backup_history_availability(&account_ref, &group)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_relay_builder::builder::{PolicyResult, QueryPolicy};
    use nostr_relay_builder::{LocalRelay, RelayBuilder};
    use std::future::Future;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use tokio::sync::Notify;

    /// Hold only the actual backup-pointer query. No archive or restore
    /// outcome is fabricated by the relay; the core job is genuinely pending.
    #[derive(Clone, Debug, Default)]
    struct HeldPointer {
        entered: Arc<Notify>,
        release: Arc<Notify>,
    }
    impl QueryPolicy for HeldPointer {
        fn admit_query<'a>(
            &'a self,
            query: &'a nostr_relay_builder::prelude::Filter,
            _: &'a SocketAddr,
        ) -> Pin<Box<dyn Future<Output = PolicyResult> + Send + 'a>> {
            Box::pin(async move {
                if query
                    .kinds
                    .as_ref()
                    .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_u16() == 30078))
                {
                    self.entered.notify_one();
                    self.release.notified().await;
                }
                PolicyResult::Accept
            })
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn backup_bindings_preserve_the_gate_tokens_and_observer_lifetime() {
        let policy = HeldPointer::default();
        let relay = LocalRelay::new(RelayBuilder::default().query_policy(policy.clone()));
        relay.run().await.unwrap();
        let root = tempfile::tempdir().unwrap();
        marmot_account::AccountHome::open(root.path())
            .create_account("alice")
            .unwrap();
        let relay_url = relay.url().await.to_string();
        let app = marmot_app::MarmotApp::with_relay_and_config(
            root.path(),
            relay_url.clone(),
            marmot_app::MarmotAppConfig::white_noise()
                .with_allow_loopback_relay_endpoints(true)
                .with_directory_relay_urls(vec![relay_url])
                .with_dev_device_groups(true),
        );
        let kit = Marmot {
            runtime: app.runtime(),
            app,
        };
        kit.set_runtime_backup_background_conditions(false, false)
            .await
            .unwrap();
        assert_eq!(
            kit.run_due_backup_pass("alice".into()).await.unwrap(),
            BackgroundBackupOutcomeFfi::NotStarted
        );
        let observer = kit.watch_backup_restore("alice".into()).await.unwrap();
        assert_eq!(
            observer.snapshot().unwrap().phase,
            crate::conversions::BackupRestorePhaseFfi::Idle
        );
        assert!(
            observer.snapshot().is_none(),
            "the initial snapshot is consumed once"
        );
        assert!(
            matches!(kit.cancel_backup_restore("alice".into(), "bad".into()).await,
            Err(MarmotKitError::InvalidHex { ref details }) if details == "invalid backup restore operation token")
        );
        let words = match kit.begin_recovery_words("alice".into()).await {
            Ok(words) => words,
            Err(MarmotKitError::Runtime { details }) if details.contains("roster_unsupported") => {
                // A default dependency build cannot enable the experimental
                // core gate through this wrapper. CI's existing app-policy
                // feature union takes the active-operation branch below.
                assert!(
                    matches!(kit.begin_backup_restore("alice".into(), "not words".into()).await,
                    Err(MarmotKitError::Runtime { ref details }) if details.contains("roster_unsupported"))
                );
                kit.runtime.shutdown_and_close().await.unwrap();
                return;
            }
            Err(error) => panic!("unexpected recovery-word refusal: {error:?}"),
        };
        assert_eq!(words.words.len(), 12);
        assert_eq!(words.confirm_positions.len(), 2);
        let redaction_probe = RecoveryWordsFfi {
            words: vec!["<private-probe>".into(); words.words.len()],
            confirm_positions: words.confirm_positions.clone(),
        };
        assert!(
            format!("{words:?}") == format!("{redaction_probe:?}"),
            "recovery output Debug must be independent of secret words"
        );
        let answers = words
            .confirm_positions
            .iter()
            .map(|at| words.words[*at as usize - 1].clone())
            .collect();
        kit.confirm_recovery_words("alice".into(), answers)
            .await
            .unwrap();
        let settings = kit.backup_settings("alice".into()).await.unwrap();
        assert!(settings.enabled && settings.this_device_writes);
        kit.set_backup_background_conditions("alice".into(), false, false)
            .await
            .unwrap();
        assert_eq!(
            kit.run_due_backup_pass("alice".into()).await.unwrap(),
            BackgroundBackupOutcomeFfi::NotStarted,
            "the reported closed facts gate background work, not manual restore"
        );
        let phrase = words.words.join(" ");
        let first = kit
            .begin_backup_restore("alice".into(), phrase.clone())
            .await
            .unwrap()
            .operation
            .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            policy.entered.notified(),
        )
        .await
        .unwrap();
        drop(observer);
        let active = kit.backup_restore_status("alice".into()).await.unwrap();
        assert_eq!(active.operation.as_deref(), Some(first.as_str()));
        assert_eq!(
            active.phase,
            crate::conversions::BackupRestorePhaseFfi::Discovering,
            "closing a watch must not cancel a live operation held at real I/O"
        );
        assert!(
            kit.cancel_backup_restore("alice".into(), first.clone())
                .await
                .unwrap()
        );
        policy.release.notify_one();
        let second = kit
            .begin_backup_restore("alice".into(), phrase)
            .await
            .unwrap()
            .operation
            .unwrap();
        assert_ne!(first, second);
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            policy.entered.notified(),
        )
        .await
        .unwrap();
        assert!(
            !kit.cancel_backup_restore("alice".into(), first)
                .await
                .unwrap(),
            "a stale action cannot cancel a newer operation"
        );
        assert_eq!(
            kit.backup_restore_status("alice".into())
                .await
                .unwrap()
                .operation
                .as_deref(),
            Some(second.as_str())
        );
        let terminal = kit.watch_backup_restore("alice".into()).await.unwrap();
        assert!(
            kit.cancel_backup_restore("alice".into(), second)
                .await
                .unwrap()
        );
        policy.release.notify_one();
        assert_eq!(
            terminal.next().await.unwrap().phase,
            crate::conversions::BackupRestorePhaseFfi::Cancelled
        );
        assert!(
            kit.backup_history_availability("alice".into(), "aa".repeat(16))
                .await
                .unwrap()
                .is_empty(),
            "MLS ids are variable-length, not 32-byte routes"
        );
        assert_eq!(
            kit.backup_settings("alice".into()).await.unwrap(),
            settings,
            "restoring never changes the current recovery key/settings"
        );
        kit.runtime.shutdown_and_close().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while terminal.next().await.is_some() {}
        })
        .await
        .unwrap();
    }
}
