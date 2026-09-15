//! Independent receiver/commands and explicit native lifetime/deadline controls.
use super::{Mutex, StdMutex, take_snapshot};
use crate::{MarmotKitError, conversions::*};
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;

pub(crate) async fn conversation_deadline<T>(
    timeout_ms: u32,
    future: impl std::future::Future<Output = Result<T, MarmotKitError>>,
) -> Result<T, MarmotKitError> {
    let duration = Duration::from_millis(if timeout_ms == 0 {
        30_000
    } else {
        timeout_ms as u64
    });
    tokio::time::timeout(duration, future)
        .await
        .map_err(|_| MarmotKitError::ConversationWindowTimedOut)?
}
#[derive(uniffi::Object)]
pub struct ConversationWindowSubscription {
    snapshot: StdMutex<Option<ConversationWindowSnapshotFfi>>,
    generation: String,
    commands: marmot_app::ConversationWindowHandle,
    receiver: Mutex<Option<marmot_app::RuntimeConversationWindowSubscription>>,
    closed: watch::Sender<bool>,
}
impl ConversationWindowSubscription {
    pub(crate) fn new(inner: marmot_app::RuntimeConversationWindowSubscription) -> Arc<Self> {
        let generation = inner.snapshot.revision.generation.clone();
        Arc::new(Self {
            snapshot: StdMutex::new(Some((&inner.snapshot).into())),
            generation,
            commands: inner.window_handle(),
            receiver: Mutex::new(Some(inner)),
            closed: watch::channel(false).0,
        })
    }
    fn revision(
        &self,
        v: ConversationWindowRevisionFfi,
    ) -> Result<marmot_app::ConversationWindowRevision, MarmotKitError> {
        if *self.closed.borrow() {
            return Err(MarmotKitError::ConversationWindowClosed);
        }
        if v.generation != self.generation {
            return Err(MarmotKitError::ConversationWindowWrongGeneration);
        }
        Ok(marmot_app::ConversationWindowRevision {
            generation: v.generation,
            sequence: v.sequence,
        })
    }
    async fn command(
        &self,
        timeout_ms: u32,
        future: impl std::future::Future<
            Output = Result<
                marmot_app::ConversationWindowSnapshot,
                marmot_app::ConversationWindowError,
            >,
        >,
    ) -> Result<ConversationWindowSnapshotFfi, MarmotKitError> {
        let mut closed = self.closed.subscribe();
        if *closed.borrow() {
            return Err(MarmotKitError::ConversationWindowClosed);
        }
        tokio::select! {
            biased;
            _ = closed.changed() => Err(MarmotKitError::ConversationWindowClosed),
            result = conversation_deadline(timeout_ms, async { Ok(future.await?.into()) }) => result,
        }
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl ConversationWindowSubscription {
    /// Take once before next(). Complete replacements include every visible identity.
    pub fn snapshot(&self) -> Option<ConversationWindowSnapshotFfi> {
        take_snapshot(&self.snapshot)
    }
    /// One receiver; cancellation leaves pending replacements available. Worker replacement
    /// is terminal: reopen the conversation after Closed/None with a fresh generation.
    pub async fn next(&self) -> Result<Option<ConversationWindowSnapshotFfi>, MarmotKitError> {
        let mut closed = self.closed.subscribe();
        if *closed.borrow() {
            return Ok(None);
        }
        tokio::select! {
            biased;
            _ = closed.changed() => Ok(None),
            result = async {
                let mut guard = self.receiver.lock().await;
                match guard.as_mut() {
                    Some(inner) => Ok(inner.recv().await?.map(Into::into)),
                    None => Ok(None),
                }
            } => result,
        }
    }
    /// Wake receivers/commands and release the retained runtime window. Idempotent.
    /// Drop the native object too when finished. Previously returned snapshots stay valid.
    pub async fn cancel(&self) {
        self.closed.send_replace(true);
        self.receiver.lock().await.take();
        take_snapshot(&self.snapshot);
    }
    /// 1–200 rows, at most 200 retained; report a new visible anchor to page beyond
    /// saturated context. Zero timeout uses 30 seconds. After timeout/cancellation an
    /// accepted command may still complete through next(); refresh before retrying.
    pub async fn page(
        &self,
        revision: ConversationWindowRevisionFfi,
        direction: ConversationPageDirectionFfi,
        count: u32,
        timeout_ms: u32,
    ) -> Result<ConversationWindowSnapshotFfi, MarmotKitError> {
        let revision = self.revision(revision)?;
        let direction = match direction {
            ConversationPageDirectionFfi::Older => marmot_app::ConversationPageDirection::Older,
            ConversationPageDirectionFfi::Newer => marmot_app::ConversationPageDirection::Newer,
        };
        self.command(
            timeout_ms,
            self.commands.page(&revision, direction, count as usize),
        )
        .await
    }
    /// Report a row in the installed replacement, not a pixel offset. No read acknowledgement.
    pub async fn set_visible_anchor(
        &self,
        revision: ConversationWindowRevisionFfi,
        message_id_hex: String,
        timeout_ms: u32,
    ) -> Result<ConversationWindowSnapshotFfi, MarmotKitError> {
        let revision = self.revision(revision)?;
        let id = crate::optional_message_id_hex(Some(message_id_hex))?
            .ok_or(MarmotKitError::ConversationWindowInvalidTarget)?;
        self.command(timeout_ms, self.commands.set_visible_anchor(&revision, &id))
            .await
    }
    /// Resume following new arrivals. Retains the current row budget (up to 200).
    pub async fn return_to_latest(
        &self,
        revision: ConversationWindowRevisionFfi,
        timeout_ms: u32,
    ) -> Result<ConversationWindowSnapshotFfi, MarmotKitError> {
        let revision = self.revision(revision)?;
        self.command(timeout_ms, self.commands.return_to_latest(&revision))
            .await
    }
    /// Missing targets fail explicitly. Commands may run while next() waits.
    pub async fn jump_to_message(
        &self,
        revision: ConversationWindowRevisionFfi,
        message_id_hex: String,
        timeout_ms: u32,
    ) -> Result<ConversationWindowSnapshotFfi, MarmotKitError> {
        let revision = self.revision(revision)?;
        let id = crate::optional_message_id_hex(Some(message_id_hex))?
            .ok_or(MarmotKitError::ConversationWindowInvalidTarget)?;
        self.command(timeout_ms, self.commands.jump_to_message(&revision, &id))
            .await
    }
}
