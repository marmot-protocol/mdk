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
    AgentStreamUpdateFfi, AppGroupRecordFfi, AppMessageRecordFfi, ChatListRowFfi,
    ChatListSubscriptionUpdateFfi, MarmotEventFfi, MessageUpdateFfi, NotificationUpdateFfi,
    RuntimeProjectionUpdateFfi, TimelineMessageChangeFfi, TimelineMessageRecordFfi,
    TimelinePageFfi, TimelineProjectionUpdateFfi, TimelineSubscriptionUpdateFfi,
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

#[derive(uniffi::Object)]
pub struct TimelineMessagesSubscription {
    snapshot: StdMutex<Option<TimelinePageFfi>>,
    current_page: StdMutex<TimelinePageFfi>,
    inner: Mutex<RuntimeTimelineMessagesSubscription>,
}

impl TimelineMessagesSubscription {
    pub(crate) fn new(mut inner: RuntimeTimelineMessagesSubscription) -> Arc<Self> {
        let _span = tracing::debug_span!(
            target: "marmot_uniffi::conversion",
            "timeline_subscription_snapshot_conversion",
            method = "TimelineMessagesSubscription::new"
        )
        .entered();
        let snapshot: TimelinePageFfi = inner.take_snapshot().into();
        Arc::new(Self {
            snapshot: StdMutex::new(Some(snapshot.clone())),
            current_page: StdMutex::new(snapshot),
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
        let update = inner.recv().await?;
        let mut current_page = self
            .current_page
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match update {
            marmot_app::RuntimeTimelineMessageUpdate::Page { page } => {
                *current_page = page.into();
            }
            marmot_app::RuntimeTimelineMessageUpdate::Projection(update) => {
                let update = RuntimeProjectionUpdateFfi::from(update);
                apply_timeline_projection_update(&mut current_page, update.update);
            }
        }
        Some(current_page.clone())
    }

    pub async fn next_update(&self) -> Option<TimelineSubscriptionUpdateFfi> {
        let mut inner = self.inner.lock().await;
        inner.recv().await.map(Into::into)
    }
}

fn apply_timeline_projection_update(
    page: &mut TimelinePageFfi,
    update: TimelineProjectionUpdateFfi,
) {
    if update.changes.is_empty() {
        for message in update.messages {
            upsert_timeline_message(&mut page.messages, message);
        }
    } else {
        for change in update.changes {
            match change {
                TimelineMessageChangeFfi::Upsert { message, .. } => {
                    upsert_timeline_message(&mut page.messages, message);
                }
                TimelineMessageChangeFfi::Remove { message_id_hex, .. } => {
                    page.messages
                        .retain(|message| message.message_id_hex != message_id_hex);
                }
            }
        }
    }
    sort_timeline_messages(&mut page.messages);
}

fn upsert_timeline_message(
    messages: &mut Vec<TimelineMessageRecordFfi>,
    message: TimelineMessageRecordFfi,
) {
    if let Some(existing) = messages
        .iter_mut()
        .find(|existing| existing.message_id_hex == message.message_id_hex)
    {
        *existing = message;
    } else {
        messages.push(message);
    }
}

fn sort_timeline_messages(messages: &mut [TimelineMessageRecordFfi]) {
    messages.sort_by(|left, right| {
        left.timeline_at
            .cmp(&right.timeline_at)
            .then_with(|| left.message_id_hex.cmp(&right.message_id_hex))
    });
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
    use crate::conversions::{
        ChatListUpdateTriggerFfi, TimelineReactionSummaryFfi, TimelineRemoveReasonFfi,
        TimelineUpdateTriggerFfi,
    };
    use crate::markdown::parse_markdown_document;

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
    fn timeline_projection_update_upserts_into_retained_page() {
        let mut page = TimelinePageFfi {
            messages: vec![timeline_record("older", 10)],
            has_more_before: true,
            has_more_after: false,
        };

        apply_timeline_projection_update(
            &mut page,
            TimelineProjectionUpdateFfi {
                group_id_hex: "group".to_owned(),
                messages: Vec::new(),
                changes: vec![TimelineMessageChangeFfi::Upsert {
                    trigger: TimelineUpdateTriggerFfi::NewMessage,
                    message: timeline_record("newer", 20),
                }],
                chat_list_row: None,
                chat_list_trigger: ChatListUpdateTriggerFfi::NewLastMessage,
            },
        );

        assert_eq!(
            page.messages
                .iter()
                .map(|message| message.message_id_hex.as_str())
                .collect::<Vec<_>>(),
            vec!["older", "newer"]
        );
        assert!(page.has_more_before);
    }

    #[test]
    fn timeline_projection_update_removes_from_retained_page() {
        let mut page = TimelinePageFfi {
            messages: vec![timeline_record("keep", 10), timeline_record("remove", 20)],
            has_more_before: false,
            has_more_after: false,
        };

        apply_timeline_projection_update(
            &mut page,
            TimelineProjectionUpdateFfi {
                group_id_hex: "group".to_owned(),
                messages: Vec::new(),
                changes: vec![TimelineMessageChangeFfi::Remove {
                    message_id_hex: "remove".to_owned(),
                    reason: TimelineRemoveReasonFfi::Invalidated,
                }],
                chat_list_row: None,
                chat_list_trigger: ChatListUpdateTriggerFfi::LastMessageDeleted,
            },
        );

        assert_eq!(page.messages.len(), 1);
        assert_eq!(page.messages[0].message_id_hex, "keep");
    }

    fn timeline_record(message_id_hex: &str, timeline_at: u64) -> TimelineMessageRecordFfi {
        TimelineMessageRecordFfi {
            message_id_hex: message_id_hex.to_owned(),
            source_message_id_hex: None,
            direction: "sent".to_owned(),
            group_id_hex: "group".to_owned(),
            sender: "sender".to_owned(),
            plaintext: message_id_hex.to_owned(),
            content_tokens: parse_markdown_document(message_id_hex),
            kind: 9,
            tags: Vec::new(),
            timeline_at,
            received_at: timeline_at,
            reply_to_message_id_hex: None,
            reply_preview: None,
            media_json: None,
            agent_text_stream_json: None,
            reactions: TimelineReactionSummaryFfi {
                by_emoji: Vec::new(),
                user_reactions: Vec::new(),
            },
            deleted: false,
            deleted_by_message_id_hex: None,
            invalidation_status: None,
        }
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
