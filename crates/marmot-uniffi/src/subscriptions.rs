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
    RuntimeNotificationsSubscription, RuntimeTimelineMessagesSubscription, TimelineWindowHandle,
};
use tokio::sync::Mutex;

use crate::MarmotKitError;
use crate::conversions::{
    AgentStreamUpdateFfi, AppGroupRecordFfi, AppMessageRecordFfi, ChatListRowFfi,
    ChatListSubscriptionUpdateFfi, MarmotEventFfi, MessageUpdateFfi, NotificationUpdateFfi,
    TimelinePageFfi, TimelineSubscriptionUpdateFfi,
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
        loop {
            match inner.recv().await? {
                marmot_app::RuntimeChatListUpdate::Row { row, .. } => return Some((*row).into()),
                marmot_app::RuntimeChatListUpdate::RemoveRow { .. } => continue,
            }
        }
    }

    pub async fn next_update(&self) -> Option<ChatListSubscriptionUpdateFfi> {
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

/// Host-facing handle to one conversation's materialized timeline window.
///
/// The runtime owns the authoritative, bounded window; this object exposes it.
/// The live-update receiver and the paginatable window are held behind separate
/// locks (`receiver` vs the runtime's internal window mutex, reached through the
/// cloned `window` handle), so a host can drive `next()`/`next_update()` on one
/// task while `paginate_backwards`/`paginate_forwards` runs on another without
/// either blocking the other.
#[derive(uniffi::Object)]
pub struct TimelineMessagesSubscription {
    snapshot: StdMutex<Option<TimelinePageFfi>>,
    window: TimelineWindowHandle,
    receiver: Mutex<RuntimeTimelineMessagesSubscription>,
}

impl TimelineMessagesSubscription {
    pub(crate) fn new(inner: RuntimeTimelineMessagesSubscription) -> Arc<Self> {
        let _span = tracing::debug_span!(
            target: "marmot_uniffi::subscriptions",
            "timeline_subscription_snapshot_conversion",
            method = "TimelineMessagesSubscription::new"
        )
        .entered();
        let window = inner.window_handle();
        let snapshot: TimelinePageFfi = inner.take_snapshot().into();
        Arc::new(Self {
            snapshot: StdMutex::new(Some(snapshot)),
            window,
            receiver: Mutex::new(inner),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl TimelineMessagesSubscription {
    pub fn snapshot(&self) -> Option<TimelinePageFfi> {
        take_snapshot(&self.snapshot)
    }

    /// Await the next live update and return the resulting authoritative window.
    /// Windowing (ordering, dedup, head-anchoring while scrolled back, and the
    /// cap) is owned by the runtime, so this returns exactly the bounded window
    /// pagination operates on — render it directly. Use
    /// [`next_update`](Self::next_update) instead to receive the raw delta.
    pub async fn next(&self) -> Option<TimelinePageFfi> {
        let mut receiver = self.receiver.lock().await;
        receiver.recv().await?;
        Some(self.window.snapshot().into())
    }

    pub async fn next_update(&self) -> Option<TimelineSubscriptionUpdateFfi> {
        let mut receiver = self.receiver.lock().await;
        receiver.recv().await.map(Into::into)
    }

    /// Extend the materialized window toward older history by up to `count`
    /// messages and return the new window. The returned page is already sorted,
    /// deduplicated, capped, and carries correct `has_more_before` /
    /// `has_more_after` flags — render it directly; no client-side merging or
    /// windowing is required. The store read runs off the caller thread and uses
    /// a different lock than `next()`, so a host driving `next()` on a background
    /// task can paginate without blocking (and this never blocks the UI thread,
    /// unlike the synchronous `Marmot::timeline_messages`).
    pub async fn paginate_backwards(&self, count: u32) -> Result<TimelinePageFfi, MarmotKitError> {
        Ok(self.window.paginate_backwards(count as usize).await?.into())
    }

    /// Extend the materialized window toward the live head by up to `count`
    /// messages and return the new window. Reaching the head re-anchors the
    /// window (`has_more_after` becomes false). Same windowing/threading
    /// guarantees as [`paginate_backwards`](Self::paginate_backwards).
    pub async fn paginate_forwards(&self, count: u32) -> Result<TimelinePageFfi, MarmotKitError> {
        Ok(self.window.paginate_forwards(count as usize).await?.into())
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

    // The timeline window's projection/cap/anchoring contract now lives and is
    // tested in `marmot-app` (`apply_projection_to_window`, `merge_timeline_window`,
    // `paginate_*`); the FFI no longer re-materializes the window, so its former
    // delta-application tests moved there.
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
