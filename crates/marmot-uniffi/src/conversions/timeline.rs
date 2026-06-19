//! Timeline reaction, reply-preview, message-record, page, and
//! subscription-update FFI conversions.

use marmot_app::{
    AppProjectionUpdate, RuntimeProjectionUpdate, RuntimeTimelineMessageUpdate,
    TimelineMessageChange, TimelineMessageRecord, TimelinePage, TimelineReactionSummary,
    TimelineRemoveReason, TimelineReplyPreview, TimelineUpdateTrigger, TimelineUserReaction,
};

use super::chat_list::{ChatListRowFfi, ChatListUpdateTriggerFfi};
use super::common::{MessageTagFfi, markdown_content_tokens, message_tags_ffi};
use crate::markdown::MarkdownDocumentFfi;

#[derive(Clone, Debug, uniffi::Record)]
pub struct TimelineReactionEmojiFfi {
    pub emoji: String,
    pub senders: Vec<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct TimelineUserReactionFfi {
    pub reaction_message_id_hex: String,
    pub target_message_id_hex: String,
    pub sender: String,
    pub emoji: String,
    pub reacted_at: u64,
}

impl From<TimelineUserReaction> for TimelineUserReactionFfi {
    fn from(value: TimelineUserReaction) -> Self {
        Self {
            reaction_message_id_hex: value.reaction_message_id_hex,
            target_message_id_hex: value.target_message_id_hex,
            sender: value.sender,
            emoji: value.emoji,
            reacted_at: value.reacted_at,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct TimelineReactionSummaryFfi {
    pub by_emoji: Vec<TimelineReactionEmojiFfi>,
    pub user_reactions: Vec<TimelineUserReactionFfi>,
}

impl From<TimelineReactionSummary> for TimelineReactionSummaryFfi {
    fn from(value: TimelineReactionSummary) -> Self {
        Self {
            by_emoji: value
                .by_emoji
                .into_iter()
                .map(|(emoji, senders)| TimelineReactionEmojiFfi { emoji, senders })
                .collect(),
            user_reactions: value.user_reactions.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone, Debug, Default, uniffi::Record)]
pub struct TimelineMessageQueryFfi {
    pub group_id_hex: Option<String>,
    pub search: Option<String>,
    pub before: Option<u64>,
    pub before_message_id: Option<String>,
    pub after: Option<u64>,
    pub after_message_id: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct TimelineReplyPreviewFfi {
    pub message_id_hex: String,
    pub sender: String,
    pub plaintext: String,
    pub content_tokens: MarkdownDocumentFfi,
    pub kind: u64,
    pub media_json: Option<String>,
    pub agent_text_stream_json: Option<String>,
    pub deleted: bool,
}

impl From<TimelineReplyPreview> for TimelineReplyPreviewFfi {
    fn from(value: TimelineReplyPreview) -> Self {
        let content_tokens = markdown_content_tokens(value.kind, &value.plaintext);
        Self {
            message_id_hex: value.message_id_hex,
            sender: value.sender,
            plaintext: value.plaintext,
            content_tokens,
            kind: value.kind,
            media_json: value.media.map(|media| media.to_string()),
            agent_text_stream_json: value.agent_text_stream.map(|stream| stream.to_string()),
            deleted: value.deleted,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct TimelineMessageRecordFfi {
    pub message_id_hex: String,
    /// Delivery marker for own (`direction == "sent"`) messages. An own send
    /// commits and projects locally *before* it publishes, so a message that
    /// was committed but not yet delivered (e.g. sent offline / relay
    /// unreachable) carries `None` here — render it as pending/failed. On
    /// delivery/convergence the same row is upserted with `Some(..)` (the
    /// published source event id), so flip the UI to delivered once this
    /// becomes non-null. To re-drive delivery of a stuck pending message
    /// without minting a duplicate, call `retry_group_convergence` rather than
    /// re-sending the text. For received messages this is the originating event
    /// id and is always `Some(..)`.
    pub source_message_id_hex: Option<String>,
    pub direction: String,
    pub group_id_hex: String,
    pub sender: String,
    pub plaintext: String,
    pub content_tokens: MarkdownDocumentFfi,
    pub kind: u64,
    pub tags: Vec<MessageTagFfi>,
    pub timeline_at: u64,
    pub received_at: u64,
    pub reply_to_message_id_hex: Option<String>,
    pub reply_preview: Option<TimelineReplyPreviewFfi>,
    pub media_json: Option<String>,
    pub agent_text_stream_json: Option<String>,
    pub reactions: TimelineReactionSummaryFfi,
    pub deleted: bool,
    pub deleted_by_message_id_hex: Option<String>,
    /// Set when convergence invalidated this message (it landed on a losing
    /// branch). The message is kept as a "did not reach the group" tombstone
    /// instead of disappearing; the value is the engine invalidation reason
    /// (e.g. `LosingBranch`). `None` for delivered messages.
    pub invalidation_status: Option<String>,
}

impl From<TimelineMessageRecord> for TimelineMessageRecordFfi {
    fn from(value: TimelineMessageRecord) -> Self {
        let content_tokens = markdown_content_tokens(value.kind, &value.plaintext);
        Self {
            message_id_hex: value.message_id_hex,
            source_message_id_hex: value.source_message_id_hex,
            direction: value.direction,
            group_id_hex: value.group_id_hex,
            sender: value.sender,
            plaintext: value.plaintext,
            content_tokens,
            kind: value.kind,
            tags: message_tags_ffi(value.tags),
            timeline_at: value.timeline_at,
            received_at: value.received_at,
            reply_to_message_id_hex: value.reply_to_message_id_hex,
            reply_preview: value.reply_preview.map(Into::into),
            media_json: value.media.map(|media| media.to_string()),
            agent_text_stream_json: value.agent_text_stream.map(|stream| stream.to_string()),
            reactions: value.reactions.into(),
            deleted: value.deleted,
            deleted_by_message_id_hex: value.deleted_by_message_id_hex,
            invalidation_status: value.invalidation_status,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct TimelinePageFfi {
    pub messages: Vec<TimelineMessageRecordFfi>,
    pub has_more_before: bool,
    pub has_more_after: bool,
}

impl From<TimelinePage> for TimelinePageFfi {
    fn from(value: TimelinePage) -> Self {
        Self {
            messages: value.messages.into_iter().map(Into::into).collect(),
            has_more_before: value.has_more_before,
            has_more_after: value.has_more_after,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, uniffi::Enum)]
pub enum TimelineMessageChangeFfi {
    Upsert {
        trigger: TimelineUpdateTriggerFfi,
        message: TimelineMessageRecordFfi,
    },
    Remove {
        message_id_hex: String,
        reason: TimelineRemoveReasonFfi,
    },
}

impl From<TimelineMessageChange> for TimelineMessageChangeFfi {
    fn from(value: TimelineMessageChange) -> Self {
        match value {
            TimelineMessageChange::Upsert { trigger, message } => Self::Upsert {
                trigger: trigger.into(),
                message: (*message).into(),
            },
            TimelineMessageChange::Remove {
                message_id_hex,
                reason,
            } => Self::Remove {
                message_id_hex,
                reason: reason.into(),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum TimelineUpdateTriggerFfi {
    NewMessage,
    MessageEditedOrReprojected,
    ReactionAdded,
    ReactionRemoved,
    MessageDeleted,
    ReplyPreviewChanged,
    AgentStreamStarted,
    AgentStreamFinished,
    AgentActivity,
    AgentOperation,
    GroupSystem,
    DeliveryOrSendStateChanged,
    ReceiptChanged,
    SnapshotRefresh,
}

impl From<TimelineUpdateTrigger> for TimelineUpdateTriggerFfi {
    fn from(value: TimelineUpdateTrigger) -> Self {
        match value {
            TimelineUpdateTrigger::NewMessage => Self::NewMessage,
            TimelineUpdateTrigger::MessageEditedOrReprojected => Self::MessageEditedOrReprojected,
            TimelineUpdateTrigger::ReactionAdded => Self::ReactionAdded,
            TimelineUpdateTrigger::ReactionRemoved => Self::ReactionRemoved,
            TimelineUpdateTrigger::MessageDeleted => Self::MessageDeleted,
            TimelineUpdateTrigger::ReplyPreviewChanged => Self::ReplyPreviewChanged,
            TimelineUpdateTrigger::AgentStreamStarted => Self::AgentStreamStarted,
            TimelineUpdateTrigger::AgentStreamFinished => Self::AgentStreamFinished,
            TimelineUpdateTrigger::AgentActivity => Self::AgentActivity,
            TimelineUpdateTrigger::AgentOperation => Self::AgentOperation,
            TimelineUpdateTrigger::GroupSystem => Self::GroupSystem,
            TimelineUpdateTrigger::DeliveryOrSendStateChanged => Self::DeliveryOrSendStateChanged,
            TimelineUpdateTrigger::ReceiptChanged => Self::ReceiptChanged,
            TimelineUpdateTrigger::SnapshotRefresh => Self::SnapshotRefresh,
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum TimelineRemoveReasonFfi {
    Invalidated,
    Cleared,
    Pruned,
    NoLongerMatchesQuery,
}

impl From<TimelineRemoveReason> for TimelineRemoveReasonFfi {
    fn from(value: TimelineRemoveReason) -> Self {
        match value {
            TimelineRemoveReason::Invalidated => Self::Invalidated,
            TimelineRemoveReason::Cleared => Self::Cleared,
            TimelineRemoveReason::Pruned => Self::Pruned,
            TimelineRemoveReason::NoLongerMatchesQuery => Self::NoLongerMatchesQuery,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct TimelineProjectionUpdateFfi {
    pub group_id_hex: String,
    pub messages: Vec<TimelineMessageRecordFfi>,
    pub changes: Vec<TimelineMessageChangeFfi>,
    pub chat_list_row: Option<ChatListRowFfi>,
    pub chat_list_trigger: ChatListUpdateTriggerFfi,
}

impl From<AppProjectionUpdate> for TimelineProjectionUpdateFfi {
    fn from(value: AppProjectionUpdate) -> Self {
        Self {
            group_id_hex: value.group_id_hex,
            messages: value
                .timeline_messages
                .into_iter()
                .map(Into::into)
                .collect(),
            changes: value.timeline_changes.into_iter().map(Into::into).collect(),
            chat_list_row: value.chat_list_row.map(Into::into),
            chat_list_trigger: value.chat_list_trigger.into(),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct RuntimeProjectionUpdateFfi {
    pub account_id_hex: String,
    pub account_label: String,
    pub update: TimelineProjectionUpdateFfi,
}

impl From<RuntimeProjectionUpdate> for RuntimeProjectionUpdateFfi {
    fn from(value: RuntimeProjectionUpdate) -> Self {
        Self {
            account_id_hex: value.account_id_hex,
            account_label: value.account_label,
            update: value.update.into(),
        }
    }
}

// FFI enum: variants carry rich payloads by value because UniFFI doesn't
// support `Box` in the wire format — boxing here would not satisfy the lint
// in practice and would force every host language to dereference.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, uniffi::Enum)]
pub enum TimelineSubscriptionUpdateFfi {
    Page { page: TimelinePageFfi },
    Projection { update: RuntimeProjectionUpdateFfi },
}

impl From<RuntimeTimelineMessageUpdate> for TimelineSubscriptionUpdateFfi {
    fn from(value: RuntimeTimelineMessageUpdate) -> Self {
        match value {
            RuntimeTimelineMessageUpdate::Page { page } => Self::Page { page: page.into() },
            RuntimeTimelineMessageUpdate::Projection(update) => Self::Projection {
                update: update.into(),
            },
        }
    }
}
