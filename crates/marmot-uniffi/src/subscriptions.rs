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

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::PoisonError;

use marmot_app::{
    RuntimeAgentStreamWatch, RuntimeChatListSubscription, RuntimeChatsSubscription,
    RuntimeEventsSubscription, RuntimeGroupStateSubscription, RuntimeMessagesSubscription,
    RuntimeNotificationsSubscription, RuntimeTimelineMessagesSubscription, TimelineMessageRecord,
    TimelinePage, TimelineWindowHandle, UserSearchSubscription as AppUserSearchSubscription,
};
use tokio::sync::Mutex;

use crate::MarmotKitError;
use crate::conversions::{
    AgentStreamUpdateFfi, AppGroupRecordFfi, AppMessageRecordFfi, ChatListRowFfi,
    ChatListSubscriptionUpdateFfi, MarmotEventFfi, MessageUpdateFfi, NotificationUpdateFfi,
    TimelineMessageRecordFfi, TimelinePageFfi, TimelineSubscriptionUpdateFfi, UserSearchUpdateFfi,
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
    state: Mutex<ChatListSubscriptionState>,
}

struct ChatListSubscriptionState {
    inner: RuntimeChatListSubscription,
    pending_rows: VecDeque<ChatListRowFfi>,
}

impl ChatListSubscription {
    pub(crate) fn new(mut inner: RuntimeChatListSubscription) -> Arc<Self> {
        let snapshot: Vec<ChatListRowFfi> = std::mem::take(&mut inner.snapshot)
            .into_iter()
            .map(Into::into)
            .collect();
        Arc::new(Self {
            snapshot: StdMutex::new(Some(snapshot)),
            state: Mutex::new(ChatListSubscriptionState {
                inner,
                pending_rows: VecDeque::new(),
            }),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl ChatListSubscription {
    pub fn snapshot(&self) -> Vec<ChatListRowFfi> {
        take_snapshot(&self.snapshot).unwrap_or_default()
    }

    /// Legacy row-only update stream.
    ///
    /// Atomic replacement snapshots are flattened into every visible row in
    /// authoritative order so existing clients can observe changed pin fields.
    /// This can yield many rows for one pin or archive operation and cannot
    /// express the replacement boundary or removals. New clients that need
    /// correct manual ordering and archive removals should use `next_update`.
    ///
    /// `next` and `next_update` consume the same stream and must not be mixed
    /// for the lifetime of one subscription.
    pub async fn next(&self) -> Option<ChatListRowFfi> {
        let mut state = self.state.lock().await;
        if let Some(row) = state.pending_rows.pop_front() {
            return Some(row);
        }
        loop {
            match state.inner.recv().await? {
                marmot_app::RuntimeChatListUpdate::Row { row, .. } => return Some((*row).into()),
                marmot_app::RuntimeChatListUpdate::RemoveRow { .. } => continue,
                marmot_app::RuntimeChatListUpdate::Snapshot { rows, .. } => {
                    state.pending_rows.extend(rows.into_iter().map(Into::into));
                    if let Some(row) = state.pending_rows.pop_front() {
                        return Some(row);
                    }
                }
            }
        }
    }

    /// Typed update stream, including atomic full-list replacement snapshots.
    ///
    /// Do not mix this with `next` on the same subscription: both consume the
    /// same underlying stream, while `next` may also hold flattened snapshot
    /// rows in its compatibility buffer.
    pub async fn next_update(&self) -> Option<ChatListSubscriptionUpdateFfi> {
        let mut state = self.state.lock().await;
        state.inner.recv().await.map(Into::into)
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
    /// Converted rows from the most recent window snapshot, keyed by
    /// `message_id_hex`. Converting a row is expensive (Markdown parse,
    /// imeta media resolution, reaction re-sort), and a live update usually
    /// changes one row in a window of hundreds, so `next()` and the paginate
    /// calls reuse the previous conversion for every row whose source record
    /// is unchanged.
    conversion_cache: StdMutex<HashMap<String, CachedTimelineRow>>,
}

struct CachedTimelineRow {
    source: TimelineMessageRecord,
    converted: TimelineMessageRecordFfi,
}

/// Convert a window snapshot to its FFI page, reusing cached conversions for
/// rows whose source record equals the one that produced them. The cache is
/// replaced with exactly the rows of this page, so rows that scrolled out of
/// the window are dropped and the cache never outgrows the window cap.
fn convert_timeline_page_cached(
    cache: &StdMutex<HashMap<String, CachedTimelineRow>>,
    page: TimelinePage,
) -> TimelinePageFfi {
    let mut cache = cache.lock().unwrap_or_else(PoisonError::into_inner);
    let mut retained = HashMap::with_capacity(page.messages.len());
    let messages = page
        .messages
        .into_iter()
        .map(|record| {
            let key = record.message_id_hex.clone();
            let row = match cache.remove(&key) {
                Some(cached) if cached.source == record => cached,
                _ => CachedTimelineRow {
                    source: record.clone(),
                    converted: record.into(),
                },
            };
            let converted = row.converted.clone();
            retained.insert(key, row);
            converted
        })
        .collect();
    *cache = retained;
    TimelinePageFfi {
        messages,
        has_more_before: page.has_more_before,
        has_more_after: page.has_more_after,
    }
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
        let conversion_cache = StdMutex::new(HashMap::new());
        let snapshot = convert_timeline_page_cached(&conversion_cache, inner.take_snapshot());
        Arc::new(Self {
            snapshot: StdMutex::new(Some(snapshot)),
            window,
            receiver: Mutex::new(inner),
            conversion_cache,
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
        Some(convert_timeline_page_cached(
            &self.conversion_cache,
            self.window.snapshot(),
        ))
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
        let page = self.window.paginate_backwards(count as usize).await?;
        Ok(convert_timeline_page_cached(&self.conversion_cache, page))
    }

    /// Extend the materialized window toward the live head by up to `count`
    /// messages and return the new window. Reaching the head re-anchors the
    /// window (`has_more_after` becomes false). Same windowing/threading
    /// guarantees as [`paginate_backwards`](Self::paginate_backwards).
    pub async fn paginate_forwards(&self, count: u32) -> Result<TimelinePageFfi, MarmotKitError> {
        let page = self.window.paginate_forwards(count as usize).await?;
        Ok(convert_timeline_page_cached(&self.conversion_cache, page))
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

    #[test]
    fn cached_conversion_reuses_unchanged_rows_and_never_serves_stale_content() {
        use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT;
        use marmot_app::TimelineReactionSummary;

        fn record(id: &str, plaintext: &str) -> TimelineMessageRecord {
            TimelineMessageRecord {
                message_id_hex: id.to_string(),
                source_message_id_hex: None,
                source_epoch: None,
                retention_seconds: None,
                retention_expires_at: None,
                direction: "received".to_string(),
                group_id_hex: "aa".to_string(),
                sender: "bb".to_string(),
                plaintext: plaintext.to_string(),
                kind: MARMOT_APP_EVENT_KIND_CHAT,
                tags: Vec::new(),
                timeline_at: 1,
                received_at: 1,
                reply_to_message_id_hex: None,
                reply_preview: None,
                media: None,
                agent_text_stream: None,
                reactions: TimelineReactionSummary::default(),
                deleted: false,
                deleted_by_message_id_hex: None,
                invalidation_status: None,
            }
        }

        fn page(messages: Vec<TimelineMessageRecord>) -> TimelinePage {
            TimelinePage {
                messages,
                has_more_before: false,
                has_more_after: false,
            }
        }

        let cache = StdMutex::new(HashMap::new());

        let first = convert_timeline_page_cached(
            &cache,
            page(vec![record("m1", "hello"), record("m2", "world")]),
        );
        assert_eq!(first.messages.len(), 2);
        assert_eq!(cache.lock().unwrap().len(), 2);

        // Unchanged rows come back identical from the cache.
        let second = convert_timeline_page_cached(
            &cache,
            page(vec![record("m1", "hello"), record("m2", "world")]),
        );
        assert_eq!(second.messages[0].plaintext, "hello");
        assert_eq!(second.messages[1].plaintext, "world");

        // A changed row is re-converted, never served stale: the new markdown
        // shows up in the tokens, not just the plaintext.
        let third = convert_timeline_page_cached(
            &cache,
            page(vec![record("m1", "edited **bold**"), record("m2", "world")]),
        );
        assert_eq!(third.messages[0].plaintext, "edited **bold**");
        assert!(!third.messages[0].content_tokens.blocks.is_empty());

        // Rows that leave the window are pruned so the cache tracks the
        // window cap, not history.
        let fourth = convert_timeline_page_cached(&cache, page(vec![record("m2", "world")]));
        assert_eq!(fourth.messages.len(), 1);
        let cache = cache.lock().unwrap();
        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key("m2"));
    }

    // The timeline window's projection/cap/anchoring contract now lives and is
    // tested in `marmot-app` (`apply_projection_to_window`, `merge_timeline_window`,
    // `paginate_*`); the FFI no longer re-materializes the window, so its former
    // delta-application tests moved there.
}

/// A live user search. Dropping it cancels the traversal.
///
/// Unlike the runtime subscriptions above there is no `snapshot()`: a search
/// has no initial state, only results that arrive as each radius resolves.
#[derive(uniffi::Object)]
pub struct UserSearchSubscription {
    inner: Mutex<AppUserSearchSubscription>,
}

impl UserSearchSubscription {
    pub(crate) fn new(inner: AppUserSearchSubscription) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(inner),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl UserSearchSubscription {
    /// Await the next step of the search, or `None` once it is over.
    ///
    /// `None` follows the `SearchCompleted` trigger, so a host can loop until
    /// either signal. Dropping this object stops the traversal at its next
    /// checkpoint.
    pub async fn next_update(&self) -> Option<UserSearchUpdateFfi> {
        let mut inner = self.inner.lock().await;
        inner.next_update().await.map(Into::into)
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
