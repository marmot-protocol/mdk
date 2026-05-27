//! UniFFI subscription objects.
//!
//! Each subscription wraps one of marmot-app's `Runtime*Subscription` types
//! (or a `broadcast::Receiver` for the top-level event firehose) and exposes
//! host-friendly methods:
//!
//! - `snapshot()` returns the initial state exactly once (subsequent calls
//!   yield the empty case).
//! - `next()` is an async fn host apps can drive in a loop
//!   to receive subsequent updates; it returns `None` when the underlying
//!   sender drops.
//!
//! All inner state lives behind a `tokio::sync::Mutex` because UniFFI passes
//! these objects via `Arc<Self>` and `recv()` requires `&mut`.

use std::sync::Arc;
use std::sync::Mutex as StdMutex;

use marmot_app::{
    RuntimeAgentStreamWatch, RuntimeChatListSubscription, RuntimeChatsSubscription,
    RuntimeEventsSubscription, RuntimeGroupStateSubscription, RuntimeMessagesSubscription,
    RuntimeNotificationsSubscription, RuntimeTimelineMessagesSubscription,
};
use tokio::sync::Mutex;

use crate::conversions::{
    AgentStreamUpdateFfi, AppGroupRecordFfi, AppMessageRecordFfi, ChatListRowFfi, MarmotEventFfi,
    MessageUpdateFfi, NotificationUpdateFfi, TimelinePageFfi,
};

#[derive(uniffi::Object)]
pub struct ChatsSubscription {
    snapshot: StdMutex<Option<Vec<AppGroupRecordFfi>>>,
    inner: Mutex<RuntimeChatsSubscription>,
}

impl ChatsSubscription {
    pub(crate) fn new(mut inner: RuntimeChatsSubscription) -> Arc<Self> {
        let snapshot: Vec<AppGroupRecordFfi> = std::mem::take(&mut inner.snapshot)
            .into_iter()
            .map(Into::into)
            .collect();
        Arc::new(Self {
            snapshot: StdMutex::new(Some(snapshot)),
            inner: Mutex::new(inner),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl ChatsSubscription {
    pub fn snapshot(&self) -> Vec<AppGroupRecordFfi> {
        take_snapshot(&self.snapshot).unwrap_or_default()
    }

    pub async fn next(&self) -> Option<AppGroupRecordFfi> {
        let mut inner = self.inner.lock().await;
        inner.recv().await.map(Into::into)
    }
}

#[derive(uniffi::Object)]
pub struct ChatListSubscription {
    snapshot: StdMutex<Option<Vec<ChatListRowFfi>>>,
    inner: Mutex<RuntimeChatListSubscription>,
}

impl ChatListSubscription {
    pub(crate) fn new(mut inner: RuntimeChatListSubscription) -> Arc<Self> {
        let snapshot: Vec<ChatListRowFfi> = std::mem::take(&mut inner.snapshot)
            .into_iter()
            .map(Into::into)
            .collect();
        Arc::new(Self {
            snapshot: StdMutex::new(Some(snapshot)),
            inner: Mutex::new(inner),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl ChatListSubscription {
    pub fn snapshot(&self) -> Vec<ChatListRowFfi> {
        take_snapshot(&self.snapshot).unwrap_or_default()
    }

    pub async fn next(&self) -> Option<ChatListRowFfi> {
        let mut inner = self.inner.lock().await;
        inner.recv().await.map(Into::into)
    }
}

#[derive(uniffi::Object)]
pub struct MessagesSubscription {
    snapshot: StdMutex<Option<Vec<AppMessageRecordFfi>>>,
    inner: Mutex<RuntimeMessagesSubscription>,
}

impl MessagesSubscription {
    pub(crate) fn new(mut inner: RuntimeMessagesSubscription) -> Arc<Self> {
        let snapshot: Vec<AppMessageRecordFfi> = std::mem::take(&mut inner.snapshot)
            .into_iter()
            .map(Into::into)
            .collect();
        Arc::new(Self {
            snapshot: StdMutex::new(Some(snapshot)),
            inner: Mutex::new(inner),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl MessagesSubscription {
    pub fn snapshot(&self) -> Vec<AppMessageRecordFfi> {
        take_snapshot(&self.snapshot).unwrap_or_default()
    }

    pub async fn next(&self) -> Option<MessageUpdateFfi> {
        let mut inner = self.inner.lock().await;
        inner.recv().await.map(Into::into)
    }
}

#[derive(uniffi::Object)]
pub struct TimelineMessagesSubscription {
    snapshot: StdMutex<Option<TimelinePageFfi>>,
    inner: Mutex<RuntimeTimelineMessagesSubscription>,
}

impl TimelineMessagesSubscription {
    pub(crate) fn new(inner: RuntimeTimelineMessagesSubscription) -> Arc<Self> {
        Arc::new(Self {
            snapshot: StdMutex::new(Some(inner.snapshot.clone().into())),
            inner: Mutex::new(inner),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl TimelineMessagesSubscription {
    pub fn snapshot(&self) -> Option<TimelinePageFfi> {
        take_snapshot(&self.snapshot)
    }

    pub async fn next(&self) -> Option<TimelinePageFfi> {
        let mut inner = self.inner.lock().await;
        inner.recv().await.map(|update| update.page.into())
    }
}

#[derive(uniffi::Object)]
pub struct GroupStateSubscription {
    snapshot: StdMutex<Option<AppGroupRecordFfi>>,
    inner: Mutex<RuntimeGroupStateSubscription>,
}

impl GroupStateSubscription {
    pub(crate) fn new(inner: RuntimeGroupStateSubscription) -> Arc<Self> {
        let snapshot = AppGroupRecordFfi::from(inner.snapshot.clone());
        Arc::new(Self {
            snapshot: StdMutex::new(Some(snapshot)),
            inner: Mutex::new(inner),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl GroupStateSubscription {
    pub fn snapshot(&self) -> Option<AppGroupRecordFfi> {
        take_snapshot(&self.snapshot)
    }

    pub async fn next(&self) -> Option<AppGroupRecordFfi> {
        let mut inner = self.inner.lock().await;
        inner.recv().await.map(Into::into)
    }
}

/// Top-level firehose of all events the runtime emits across every account.
/// Lags are silently skipped (broadcast channels have a bounded backlog and
/// `RecvError::Lagged` is non-fatal — the iOS side will catch back up via
/// the per-account chats/messages subscriptions).
#[derive(uniffi::Object)]
pub struct EventsSubscription {
    inner: Mutex<RuntimeEventsSubscription>,
}

impl EventsSubscription {
    pub(crate) fn new(inner: RuntimeEventsSubscription) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(inner),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl EventsSubscription {
    pub async fn next(&self) -> Option<MarmotEventFfi> {
        let mut inner = self.inner.lock().await;
        inner.recv().await.map(Into::into)
    }
}

#[derive(uniffi::Object)]
pub struct NotificationsSubscription {
    inner: Mutex<RuntimeNotificationsSubscription>,
}

impl NotificationsSubscription {
    pub(crate) fn new(inner: RuntimeNotificationsSubscription) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(inner),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl NotificationsSubscription {
    pub async fn next(&self) -> Option<NotificationUpdateFfi> {
        let mut inner = self.inner.lock().await;
        inner.recv().await.map(Into::into)
    }
}

/// A live agent-text-stream watch. Drive `next()` in a `while let` loop to fill
/// a bubble; it yields `Chunk` deltas then a terminal `Finished`/`Failed`,
/// after which it returns `None`.
#[derive(uniffi::Object)]
pub struct AgentStreamSubscription {
    stream_id_hex: String,
    inner: Mutex<RuntimeAgentStreamWatch>,
}

impl AgentStreamSubscription {
    pub(crate) fn new(inner: RuntimeAgentStreamWatch) -> Arc<Self> {
        Arc::new(Self {
            stream_id_hex: inner.stream_id_hex.clone(),
            inner: Mutex::new(inner),
        })
    }
}

fn take_snapshot<T>(snapshot: &StdMutex<Option<T>>) -> Option<T> {
    match snapshot.lock() {
        Ok(mut guard) => guard.take(),
        Err(poisoned) => poisoned.into_inner().take(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_snapshot_recovers_from_poisoned_lock() {
        let snapshot = StdMutex::new(Some("initial"));
        let _ = std::panic::catch_unwind(|| {
            let _guard = snapshot.lock().unwrap();
            panic!("poison snapshot lock");
        });

        assert_eq!(take_snapshot(&snapshot), Some("initial"));
        assert_eq!(take_snapshot(&snapshot), None);
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl AgentStreamSubscription {
    /// The resolved stream id this watch is following (hex).
    pub fn stream_id_hex(&self) -> String {
        self.stream_id_hex.clone()
    }

    pub async fn next(&self) -> Option<AgentStreamUpdateFfi> {
        let mut inner = self.inner.lock().await;
        inner.recv().await.map(Into::into)
    }
}
