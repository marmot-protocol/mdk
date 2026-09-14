//! Independent command and receiver ownership across the native async boundary.
use super::{Mutex, StdMutex, take_snapshot};
use crate::MarmotKitError;
use crate::conversions::*;
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct ChatListWindowSubscription {
    snapshot: StdMutex<Option<ChatListWindowSnapshotFfi>>,
    commands: marmot_app::ChatListWindowHandle,
    receiver: Mutex<marmot_app::RuntimeChatListWindowSubscription>,
}
impl ChatListWindowSubscription {
    pub(crate) fn new(mut inner: marmot_app::RuntimeChatListWindowSubscription) -> Arc<Self> {
        let commands = inner.window_handle();
        let rows = std::mem::take(&mut inner.snapshot.rows);
        let mut snapshot = inner.snapshot.clone();
        snapshot.rows = rows;
        Arc::new(Self {
            snapshot: StdMutex::new(Some(snapshot.into())),
            commands,
            receiver: Mutex::new(inner),
        })
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl ChatListWindowSubscription {
    /// Take the initial complete replacement once, before driving next().
    pub fn snapshot(&self) -> Option<ChatListWindowSnapshotFfi> {
        take_snapshot(&self.snapshot)
    }
    /// One receiver per handle. Cancellation does not consume an update.
    pub async fn next(&self) -> Result<Option<ChatListWindowSnapshotFfi>, MarmotKitError> {
        Ok(self.receiver.lock().await.recv().await?.map(Into::into))
    }
    /// 1–100 rows, at most 200 retained. Uses the installed snapshot's sequence.
    /// This can run while next() waits; accepted commands survive caller cancellation.
    pub async fn page(
        &self,
        sequence: u64,
        direction: ChatListPageDirectionFfi,
        count: u32,
    ) -> Result<ChatListWindowSnapshotFfi, MarmotKitError> {
        Ok(self
            .commands
            .page(sequence, direction.into(), count as usize)
            .await?
            .into())
    }
    /// Stable row identity, not pixel offset. A missing/outside anchor is rejected.
    pub async fn set_visible_anchor(
        &self,
        sequence: u64,
        group_id_hex: String,
    ) -> Result<ChatListWindowSnapshotFfi, MarmotKitError> {
        Ok(self
            .commands
            .set_visible_anchor(sequence, &group_id_hex)
            .await?
            .into())
    }
    pub async fn return_to_top(
        &self,
        sequence: u64,
    ) -> Result<ChatListWindowSnapshotFfi, MarmotKitError> {
        Ok(self.commands.return_to_top(sequence).await?.into())
    }
}
#[derive(uniffi::Object)]
pub struct AccountAttentionSubscription {
    snapshot: StdMutex<Option<AccountAttentionSnapshotFfi>>,
    receiver: Mutex<marmot_app::RuntimeAccountAttentionSubscription>,
}
impl AccountAttentionSubscription {
    pub(crate) fn new(mut inner: marmot_app::RuntimeAccountAttentionSubscription) -> Arc<Self> {
        let accounts = std::mem::take(&mut inner.snapshot.accounts);
        let mut snapshot = inner.snapshot.clone();
        snapshot.accounts = accounts;
        Arc::new(Self {
            snapshot: StdMutex::new(Some(snapshot.into())),
            receiver: Mutex::new(inner),
        })
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl AccountAttentionSubscription {
    /// Take the initial account set once. Unavailable entries never contain invented totals.
    pub fn snapshot(&self) -> Option<AccountAttentionSnapshotFfi> {
        take_snapshot(&self.snapshot)
    }
    pub async fn next(&self) -> Result<Option<AccountAttentionSnapshotFfi>, MarmotKitError> {
        Ok(self
            .receiver
            .lock()
            .await
            .recv()
            .await
            .map_err(|e| MarmotKitError::from(e.as_ref()))?
            .map(Into::into))
    }
}
