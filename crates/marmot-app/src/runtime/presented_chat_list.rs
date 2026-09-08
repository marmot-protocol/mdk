//! Complete selected chat rows, with the existing chat-list event routes as invalidations.
use super::{
    MarmotAppRuntime, RuntimeChatListSubscription, blocking_app_task, wait_for_runtime_shutdown,
};
use crate::chat_presentation::signals::PresentationInvalidation;
use crate::{AppError, MarmotApp, PresentedChatListSnapshot, PresentedChatRow};
use storage_sqlite::{ChatListQuery, SqliteAccountStorage};
use tokio::sync::{broadcast, watch};

/// A complete replacement. Sequence orders all row changes, even at equal presentation revisions.
#[derive(Clone, PartialEq, Eq)]
pub struct PresentedChatListUpdate {
    pub subscription_generation: String,
    pub sequence: u64,
    pub snapshot: PresentedChatListSnapshot,
}
impl std::fmt::Debug for PresentedChatListUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresentedChatListUpdate")
            .field("sequence", &self.sequence)
            .field("snapshot", &self.snapshot)
            .finish_non_exhaustive()
    }
}

/// The initial snapshot and an already attached subscription. Drop to cancel.
/// Each handle is bound to one account; open a new handle when switching accounts.
pub struct RuntimePresentedChatListSubscription {
    pub snapshot: PresentedChatListSnapshot,
    pub subscription_generation: String,
    app: MarmotApp,
    account_label: String,
    account_id: String,
    include_archived: bool,
    legacy: RuntimeChatListSubscription,
    presentation: broadcast::Receiver<PresentationInvalidation>,
    stopping: watch::Receiver<bool>,
    current: PresentedChatListSnapshot,
    sequence: u64,
    dirty: bool,
}
impl RuntimePresentedChatListSubscription {
    /// Cancellation and read errors retain the refresh obligation for the next call.
    pub async fn recv(&mut self) -> Result<Option<PresentedChatListUpdate>, AppError> {
        loop {
            if self.dirty {
                // These payloads are invalidations, not deltas to apply. The upcoming read
                // includes all committed changes already queued and cancellation keeps dirty.
                self.legacy.discard_pending_invalidations();
                let snapshot = tokio::select! {
                    biased;
                    _ = wait_for_runtime_shutdown(&mut self.stopping) => return Ok(None),
                    result = prepared_snapshot(self.app.clone(), self.account_label.clone(), self.account_id.clone(), self.include_archived, None) => result?,
                };
                if snapshot.presentation_version.store_epoch
                    != self.current.presentation_version.store_epoch
                {
                    return Ok(None);
                }
                self.dirty = false;
                if snapshot != self.current {
                    self.current = snapshot.clone();
                    self.sequence = self
                        .sequence
                        .checked_add(1)
                        .expect("subscription sequence exhausted");
                    return Ok(Some(PresentedChatListUpdate {
                        subscription_generation: self.subscription_generation.clone(),
                        sequence: self.sequence,
                        snapshot,
                    }));
                }
            }
            tokio::select! {
                biased;
                _ = wait_for_runtime_shutdown(&mut self.stopping) => return Ok(None),
                update = self.legacy.recv() => {
                    if update.is_none() { return Ok(None); }
                    self.dirty = true;
                }
                update = self.presentation.recv() => match update {
                    Ok(update) => {
                        if update.account_label == self.account_label && update.version != self.current.presentation_version { self.dirty = true; }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => self.dirty = true,
                    Err(broadcast::error::RecvError::Closed) => return Ok(None),
                }
            }
        }
    }
}

impl MarmotAppRuntime {
    /// Local complete rows. First use can asynchronously prepare missing selected values;
    /// ready reads perform no repair writes or network work.
    pub async fn presented_chat_list(
        &self,
        account_ref: &str,
        include_archived: bool,
    ) -> Result<PresentedChatListSnapshot, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => Err(AppError::RuntimeStopping),
            result = prepared_snapshot(self.accounts.app.clone(), account.label, account.account_id_hex, include_archived, None) => result,
        }
    }

    /// The same selected contract for creation/rebind paths; no full list is returned.
    pub async fn presented_chat_list_row(
        &self,
        account_ref: &str,
        group_id_hex: &str,
    ) -> Result<Option<PresentedChatRow>, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let group = crate::ids::normalize_group_id_hex_app(group_id_hex)?;
        let account = self.accounts.resolve(account_ref)?;
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let snapshot = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => return Err(AppError::RuntimeStopping),
            result = prepared_snapshot(self.accounts.app.clone(), account.label, account.account_id_hex, true, Some(group)) => result?,
        };
        Ok(snapshot.rows.into_iter().next())
    }

    /// Attach both invalidation sources before reading; queued changes reconcile against fresh
    /// local state, including lag recovery. The old row stream preserves mute expiry and all
    /// non-presentation event routes but its payload is never used as selected display.
    pub async fn open_presented_chat_list(
        &self,
        account_ref: &str,
        include_archived: bool,
    ) -> Result<RuntimePresentedChatListSubscription, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let presentation = self.accounts.app.presentation_signals.updates.subscribe();
        let mut legacy = self
            .subscribe_chat_list(&account.label, include_archived)
            .await?;
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let snapshot = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => return Err(AppError::RuntimeStopping),
            result = prepared_snapshot(self.accounts.app.clone(), account.label.clone(), account.account_id_hex.clone(), include_archived, None) => result?,
        };
        // Reusing legacy routing currently costs an extra initial row read. Discard that
        // snapshot: only its invalidations are consumed, never its display payload.
        legacy.snapshot.clear();
        Ok(RuntimePresentedChatListSubscription {
            current: snapshot.clone(),
            snapshot,
            subscription_generation: hex::encode(rand::random::<[u8; 16]>()),
            app: self.accounts.app.clone(),
            account_label: account.label,
            account_id: account.account_id_hex,
            include_archived,
            legacy,
            presentation,
            stopping: self.shared.lifecycle().subscribe_shutdown(),
            sequence: 0,
            dirty: false,
        })
    }
}

async fn prepared_snapshot(
    app: MarmotApp,
    label: String,
    account_id: String,
    include_archived: bool,
    group: Option<String>,
) -> Result<PresentedChatListSnapshot, AppError> {
    loop {
        let app = app.clone();
        let label = label.clone();
        let account_id = account_id.clone();
        let group = group.clone();
        let snapshot = blocking_app_task(move || {
            let account = app.account_home().account(&label)?;
            if account.account_id_hex != account_id {
                return Err(marmot_account::AccountHomeError::AccountIdMismatch.into());
            }
            app.ensure_account_state(&label)?;
            app.ensure_chat_list_projection(&account)?;
            let storage = app.account_storage(&label)?;
            let snapshot = read_or_prepare(
                &storage,
                ChatListQuery { include_archived },
                group.as_deref(),
                || {
                    let result = crate::chat_presentation::maintenance::prepare_batch(
                        &storage,
                        &app.shared_storage()?,
                        &account.account_id_hex,
                    );
                    app.presentation_signals.wake();
                    result
                },
            )?;
            snapshot
                .map(|mut snapshot| {
                    // Rows, selected identity and version are already one atomic snapshot.
                    // Preview sender/attachment enrichment is independent of that selection.
                    let mut rows = snapshot
                        .rows
                        .iter()
                        .map(|r| r.row.clone())
                        .collect::<Vec<_>>();
                    app.hydrate_chat_list_rows(&mut rows)?;
                    for (selected, row) in snapshot.rows.iter_mut().zip(rows) {
                        selected.row = row;
                    }
                    Ok(snapshot)
                })
                .transpose()
        })
        .await?;
        if let Some(snapshot) = snapshot {
            return Ok(snapshot);
        }
        // First-use preparation shares CAS-protected batches with the account worker.
        // Pace retries (including lost CAS attempts) instead of immediately contending
        // for the same connection again. Ready reads never enter this delay.
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

/// A ready read is read-only. First-use preparation also works before account workers start.
/// The same bounded batch implementation is used by the worker, with storage CAS protecting
/// concurrent preparers. Re-read before interpreting its progress flag: a lost CAS can mean
/// another caller completed the result, or advanced a multi-batch preparation.
fn read_or_prepare(
    storage: &SqliteAccountStorage,
    query: ChatListQuery,
    group: Option<&str>,
    prepare: impl FnOnce() -> Result<bool, AppError>,
) -> Result<Option<PresentedChatListSnapshot>, AppError> {
    if let Some(snapshot) = storage.read_presented_chat_list(query.clone(), group)? {
        return Ok(Some(snapshot));
    }
    let checkpoint = storage.chat_presentation_checkpoint()?;
    let progressed = prepare()?;
    if let Some(snapshot) = storage.read_presented_chat_list(query, group)? {
        return Ok(Some(snapshot));
    }
    if progressed || storage.chat_presentation_checkpoint()?.generation != checkpoint.generation {
        return Ok(None);
    }
    Err(AppError::ChatPresentationNotReady)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PresentationText, tests::ScriptedPushRelayClient};
    use marmot_account::AccountHome;
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn dropping_legacy_list_releases_pump_and_expired_mutes_read_correctly() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let group = client.create_group("Muted", &[]).await.unwrap();
        let id = hex::encode(group.as_slice());
        let runtime = MarmotAppRuntime::new(app.clone());
        runtime.set_chat_muted("alice", &id, None).unwrap();
        let before = runtime.events.receiver_count();
        let sub = runtime.subscribe_chat_list("alice", false).await.unwrap();
        assert!(sub.snapshot[0].muted);
        assert_eq!(runtime.events.receiver_count(), before + 1);
        drop(sub);
        tokio::time::timeout(Duration::from_secs(5), async {
            while runtime.events.receiver_count() != before {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping the handle must release the idle pump without another event");
        // Install an already-expired preference directly: there is no pump to refresh
        // the materialized row. Read-time derivation must still unmute it correctly.
        let storage = app.account_storage("alice").unwrap();
        storage
            .set_chat_muted(&id, Some(crate::notifications::unix_now_ms() - 1))
            .unwrap();
        let row = runtime
            .presented_chat_list_row("alice", &id)
            .await
            .unwrap()
            .unwrap();
        assert!(!row.row.muted);
        assert!(row.row.muted_until_ms.is_none());
        runtime.shutdown_and_close().await.unwrap();
    }

    #[tokio::test]
    async fn presented_preparation_observes_worker_progress_and_reports_stalled_work() {
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        client.create_group("Pending", &[]).await.unwrap();
        app.ensure_chat_list_projection(&account).unwrap();
        let storage = app.account_storage("alice").unwrap();
        let query = ChatListQuery {
            include_archived: true,
        };
        assert!(
            storage
                .read_presented_chat_list(query.clone(), None)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            read_or_prepare(&storage, query.clone(), None, || Ok(false)),
            Err(AppError::ChatPresentationNotReady)
        ));
        // Deterministic interleaving: the owner advances the checkpoint after the reader's
        // miss, but the reader's own stale CAS reports no progress. The result is not ready
        // yet, so retry only because the durable checkpoint really advanced.
        let mut worker = super::super::presentation::PresentationMaintenance::default();
        let partial = read_or_prepare(&storage, query.clone(), None, || {
            assert!(worker.run(&client, &account.account_id_hex)?);
            Ok(false)
        })
        .unwrap();
        assert!(partial.is_none());
        // The owner completes before the losing preparer returns false. Re-read wins
        // over that stale progress flag and returns the complete row without an error.
        let ready = read_or_prepare(&storage, query.clone(), None, || {
            while worker.run(&client, &account.account_id_hex)? {}
            Ok(false)
        })
        .unwrap()
        .unwrap();
        assert_eq!(ready.rows.len(), 1);
        let repeat = read_or_prepare(&storage, query, None, || {
            panic!("ready reads must not prepare")
        })
        .unwrap()
        .unwrap();
        assert_eq!(ready, repeat);
    }

    #[tokio::test]
    async fn presented_one_shot_warms_and_refreshes_legacy_projection() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let group = client.create_group("Before", &[]).await.unwrap();
        let id = hex::encode(group.as_slice());
        let runtime = MarmotAppRuntime::new(app.clone());
        // Neither legacy list reads nor a subscription have warmed the projection.
        let first = runtime.presented_chat_list("alice", false).await.unwrap();
        assert_eq!(first.rows.len(), 1);
        assert!(
            app.chat_list_projection_warmed
                .lock()
                .unwrap()
                .contains("alice")
        );
        let mut state = app.load_state("alice").unwrap();
        state.groups[0].profile.name = "After".into();
        app.save_state(&state).unwrap();
        let row = runtime
            .presented_chat_list_row("alice", &id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.row.group_name, "After");
        assert!(
            !app.chat_list_projection_stale
                .lock()
                .unwrap()
                .contains("alice")
        );
        runtime.shutdown_and_close().await.unwrap();
    }

    #[tokio::test]
    async fn presented_list_prepares_offline_and_orders_nonpresentation_updates() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        AccountHome::open(dir.path()).create_account("bob").unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let group = client.create_group("Initial name", &[]).await.unwrap();
        let id = hex::encode(group.as_slice());
        let runtime = MarmotAppRuntime::new(app.clone());
        let mut sub = runtime
            .open_presented_chat_list("alice", false)
            .await
            .unwrap();
        assert_eq!(sub.snapshot.rows.len(), 1);
        assert!(
            matches!(&sub.snapshot.rows[0].presentation.title, PresentationText::Literal(s) if s == "Initial name")
        );
        let version = sub.snapshot.presentation_version.clone();
        assert_eq!(
            runtime.presented_chat_list_row("alice", &id).await.unwrap(),
            Some(sub.snapshot.rows[0].clone())
        );
        assert!(
            runtime
                .presented_chat_list_row("bob", &id)
                .await
                .unwrap()
                .is_none()
        );
        // Mutation after open, before the consumer starts next(): no handoff gap.
        runtime
            .set_chat_manually_unread("alice", &id, true)
            .unwrap();
        let update = tokio::time::timeout(Duration::from_secs(5), sub.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(update.sequence, 1);
        assert_eq!(update.subscription_generation, sub.subscription_generation);
        assert_eq!(
            update.snapshot.presentation_version, version,
            "unread changes need their own sequence"
        );
        assert!(update.snapshot.rows[0].row.manually_marked_unread);
        runtime.set_chat_pinned("alice", &id, true).unwrap();
        let update = tokio::time::timeout(Duration::from_secs(5), sub.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(update.sequence, 2);
        assert!(update.snapshot.rows[0].row.pinned);
        // Independently owned handles never share a generation.
        let other = runtime
            .open_presented_chat_list("alice", false)
            .await
            .unwrap();
        assert_ne!(sub.subscription_generation, other.subscription_generation);
        runtime.shared.lifecycle().begin_shutdown();
        assert!(sub.recv().await.unwrap().is_none());
        drop(sub);
        drop(other);
        drop(client);
        runtime.shutdown_and_close().await.unwrap();
        drop(runtime);
        drop(app);
        let reopened = MarmotAppRuntime::new(
            MarmotApp::with_relay(dir.path(), "wss://relay.example")
                .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default())),
        );
        let restored = reopened.presented_chat_list("alice", false).await.unwrap();
        assert_eq!(restored.presentation_version, version);
        assert!(
            matches!(&restored.rows[0].presentation.title, PresentationText::Literal(s) if s == "Initial name")
        );
        reopened.shutdown_and_close().await.unwrap();
    }

    #[tokio::test]
    async fn presented_list_lag_recovers_current_selection_without_raw_row_events() {
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let group = client.create_group("Before", &[]).await.unwrap();
        let id = hex::encode(group.as_slice());
        let runtime = MarmotAppRuntime::new(app.clone());
        let mut sub = runtime
            .open_presented_chat_list("alice", false)
            .await
            .unwrap();
        let storage = app.account_storage("alice").unwrap();
        let mut state = storage.load_account_projection_state("alice", 100).unwrap();
        state.groups[0].profile_name = "After".into();
        storage
            .save_account_projection_state(&state, 100, 120)
            .unwrap();
        let mut worker = super::super::presentation::PresentationMaintenance::default();
        while worker.run(&client, &account.account_id_hex).unwrap() {}
        // Force presentation-channel overflow; lag must trigger a complete local refresh.
        for _ in 0..100 {
            let _ = app
                .presentation_signals
                .updates
                .send(PresentationInvalidation {
                    account_label: "unrelated".into(),
                    version: storage.chat_presentation_version().unwrap(),
                });
        }
        let update = tokio::time::timeout(Duration::from_secs(5), sub.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(update.snapshot.rows[0].row.group_id_hex, id);
        assert!(
            matches!(&update.snapshot.rows[0].presentation.title, PresentationText::Literal(s) if s == "After")
        );
        assert_eq!(update.sequence, 1);
        // A cancelled wait cannot close or consume a later change.
        assert!(
            tokio::time::timeout(Duration::from_millis(20), sub.recv())
                .await
                .is_err()
        );
        runtime
            .set_chat_manually_unread("alice", &id, true)
            .unwrap();
        let update = tokio::time::timeout(Duration::from_secs(5), sub.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(update.sequence, 2);
        assert!(update.snapshot.rows[0].row.manually_marked_unread);
        runtime.shared.lifecycle().begin_shutdown();
    }
}
