//! Live subscription wiring commands.
//!
//! These methods construct the long-lived `uniffi::Object` subscription
//! handles defined in [`crate::subscriptions`]; the streaming/state machinery
//! itself lives there.

use std::sync::Arc;

use marmot_app::{AppMessageQuery, TimelineMessageQuery, TimelinePagination};

use crate::errors::MarmotKitError;
use crate::subscriptions::{
    ChatListSubscription, ChatsSubscription, EventsSubscription, GroupStateSubscription,
    MessagesSubscription, NotificationsSubscription, TimelineMessagesSubscription,
};
use crate::{Marmot, optional_group_id_hex};

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    // -----------------------------------------------------------------------
    // Subscriptions
    // -----------------------------------------------------------------------

    /// Top-level event firehose. One subscription, every account, every event
    /// type. Useful for global diagnostics; specific UIs prefer the
    /// per-account chats/messages/group-state subscriptions below.
    pub fn subscribe_events(&self) -> Arc<EventsSubscription> {
        EventsSubscription::new(self.runtime.subscribe_events())
    }

    pub async fn subscribe_notifications(
        &self,
    ) -> Result<Arc<NotificationsSubscription>, MarmotKitError> {
        let inner = self.runtime.subscribe_notifications()?;
        Ok(NotificationsSubscription::new(inner))
    }

    /// Per-account chats list. Emits whenever a group's projection changes.
    ///
    /// `async` is required even though the body is synchronous: marmot-app's
    /// `subscribe_chats` spawns a background filter task via `tokio::spawn`,
    /// which panics ("no reactor running") if invoked outside a tokio
    /// runtime. UniFFI only enters the tokio runtime for `async` exports, so
    /// the subscribe methods that spawn must be async.
    pub async fn subscribe_chats(
        &self,
        account_ref: String,
        include_archived: bool,
    ) -> Result<Arc<ChatsSubscription>, MarmotKitError> {
        let inner = self
            .runtime
            .subscribe_chats(&account_ref, include_archived)?;
        Ok(ChatsSubscription::new(inner))
    }

    /// Per-account durable chat-list projection. Async for the same
    /// tokio-runtime reason as [`Marmot::subscribe_chats`].
    pub async fn subscribe_chat_list(
        &self,
        account_ref: String,
        include_archived: bool,
    ) -> Result<Arc<ChatListSubscription>, MarmotKitError> {
        let inner = self
            .runtime
            .subscribe_chat_list(&account_ref, include_archived)?;
        Ok(ChatListSubscription::new(inner))
    }

    /// Messages for a specific group (when `group_id_hex` is `Some`) or
    /// every message across the account (when `None`). `limit` caps the initial
    /// snapshot to the latest N rows; live updates continue after the snapshot.
    /// Async for the same tokio-runtime reason as [`Marmot::subscribe_chats`].
    pub async fn subscribe_messages(
        &self,
        account_ref: String,
        group_id_hex: Option<String>,
        limit: Option<u32>,
    ) -> Result<Arc<MessagesSubscription>, MarmotKitError> {
        let query = AppMessageQuery {
            group_id_hex: optional_group_id_hex(group_id_hex)?,
            limit: limit.map(|n| n as usize),
        };
        let inner = self.runtime.subscribe_messages(&account_ref, query).await?;
        Ok(MessagesSubscription::new(inner))
    }

    /// Live materialized timeline updates for a group or account-wide tail.
    /// The snapshot and each update are full pages for the supplied query.
    pub async fn subscribe_timeline_messages(
        &self,
        account_ref: String,
        group_id_hex: Option<String>,
        limit: Option<u32>,
    ) -> Result<Arc<TimelineMessagesSubscription>, MarmotKitError> {
        let query = TimelineMessageQuery {
            group_id_hex: optional_group_id_hex(group_id_hex)?,
            search: None,
            pagination: TimelinePagination {
                limit: limit.map(|value| value as usize),
                ..TimelinePagination::default()
            },
        };
        let inner = self
            .runtime
            .subscribe_timeline_messages(&account_ref, query)?;
        Ok(TimelineMessagesSubscription::new(inner))
    }

    /// Member/profile/roster changes for one group. Async for the same
    /// tokio-runtime reason as [`Marmot::subscribe_chats`].
    pub async fn subscribe_group_state(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<Arc<GroupStateSubscription>, MarmotKitError> {
        let inner = self
            .runtime
            .subscribe_group_state(&account_ref, &group_id_hex)?;
        Ok(GroupStateSubscription::new(inner))
    }
}
