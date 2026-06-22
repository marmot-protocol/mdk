//! Timeline reaction, reply-preview, message-record, page, and
//! subscription-update FFI conversions.

use marmot_app::{
    AppGroupSystemEvent, AppProjectionUpdate, RuntimeProjectionUpdate,
    RuntimeTimelineMessageUpdate, TimelineMessageChange, TimelineMessageRecord, TimelinePage,
    TimelineReactionSummary, TimelineRemoveReason, TimelineReplyPreview, TimelineUpdateTrigger,
    TimelineUserReaction, group_system_event_from_message,
};

use super::chat_list::{ChatListRowFfi, ChatListUpdateTriggerFfi};
use super::common::{MessageTagFfi, markdown_content_tokens, message_tags_ffi};
use super::media::{MediaAttachmentReferenceFfi, timeline_media_references_ffi};
use crate::markdown::MarkdownDocumentFfi;

#[derive(Clone, Debug, uniffi::Record)]
pub struct TimelineReactionEmojiFfi {
    pub emoji: String,
    /// Number of distinct senders that reacted with this emoji
    /// (`== senders.len()`), surfaced so clients render the tally without
    /// counting. This is the authenticated reaction count only; clients overlay
    /// their own optimistic react/unreact and "did I react" state on top.
    pub count: u32,
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
    /// Reaction tallies pre-sorted by `count` descending, ties broken by `emoji`
    /// ascending, so clients render a stable tally without re-sorting.
    pub by_emoji: Vec<TimelineReactionEmojiFfi>,
    pub user_reactions: Vec<TimelineUserReactionFfi>,
}

impl From<TimelineReactionSummary> for TimelineReactionSummaryFfi {
    fn from(value: TimelineReactionSummary) -> Self {
        let mut by_emoji = value
            .by_emoji
            .into_iter()
            .map(|(emoji, senders)| TimelineReactionEmojiFfi {
                count: senders.len().try_into().unwrap_or(u32::MAX),
                emoji,
                senders,
            })
            .collect::<Vec<_>>();
        by_emoji.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.emoji.cmp(&b.emoji)));
        Self {
            by_emoji,
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
    /// Fully-resolved, downloadable media references for the previewed message,
    /// built from its `imeta` tags + its own `source_epoch` using the same
    /// resolution and validation as `list_media`. Empty when the previewed
    /// message has no media or its `imeta` is malformed.
    pub media: Vec<MediaAttachmentReferenceFfi>,
    pub agent_text_stream_json: Option<String>,
    pub deleted: bool,
}

impl From<TimelineReplyPreview> for TimelineReplyPreviewFfi {
    fn from(value: TimelineReplyPreview) -> Self {
        let content_tokens = markdown_content_tokens(value.kind, &value.plaintext);
        let media = timeline_media_references_ffi(&value.media, value.source_epoch);
        Self {
            message_id_hex: value.message_id_hex,
            sender: value.sender,
            plaintext: value.plaintext,
            content_tokens,
            kind: value.kind,
            media_json: value.media.map(|media| media.to_string()),
            media,
            agent_text_stream_json: value.agent_text_stream.map(|stream| stream.to_string()),
            deleted: value.deleted,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupSystemEventFfi {
    pub system_type: String,
    /// Human-readable fallback from the row content. Prefer rendering from
    /// `system_type` plus the structured fields so clients can localize and
    /// render the local account as "you".
    pub text: String,
    pub actor_account_id_hex: Option<String>,
    pub subject_account_id_hex: Option<String>,
    pub name: Option<String>,
}

impl From<AppGroupSystemEvent> for GroupSystemEventFfi {
    fn from(value: AppGroupSystemEvent) -> Self {
        Self {
            system_type: value.system_type,
            text: value.text,
            actor_account_id_hex: value.actor_account_id_hex,
            subject_account_id_hex: value.subject_account_id_hex,
            name: value.name,
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
    /// Fully-resolved, downloadable media references for this message, built
    /// from its `imeta` tags + its own `source_epoch` using the same resolution
    /// and validation as `list_media` (a `list_media` record and this row's
    /// `media` resolve identically for the same message). Empty when the message
    /// has no media; a malformed `imeta` attachment is dropped while the message
    /// still appears as text.
    pub media: Vec<MediaAttachmentReferenceFfi>,
    pub agent_text_stream_json: Option<String>,
    /// Parsed view of kind-1210 group system rows. `None` for chat, reactions,
    /// stream rows, and malformed/free-text kind-1210 assertions.
    pub group_system: Option<GroupSystemEventFfi>,
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
        let group_system = group_system_event_from_message(value.kind, &value.plaintext);
        let media = timeline_media_references_ffi(&value.media, value.source_epoch);
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
            media,
            agent_text_stream_json: value.agent_text_stream.map(|stream| stream.to_string()),
            group_system: group_system.map(Into::into),
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn reaction_summary_ffi_carries_count_and_sorts_by_count_then_emoji() {
        let summary = TimelineReactionSummary {
            by_emoji: BTreeMap::from([
                ("👍".to_owned(), vec!["a".to_owned()]),
                (
                    "❤️".to_owned(),
                    vec!["a".to_owned(), "b".to_owned(), "c".to_owned()],
                ),
                ("😂".to_owned(), vec!["a".to_owned(), "b".to_owned()]),
                ("🎉".to_owned(), vec!["x".to_owned(), "y".to_owned()]),
            ]),
            user_reactions: Vec::new(),
        };

        let ffi: TimelineReactionSummaryFfi = summary.into();

        // count desc, then emoji asc for the two-way tie (🎉 U+1F389 < 😂 U+1F602).
        let order: Vec<(&str, u32)> = ffi
            .by_emoji
            .iter()
            .map(|entry| (entry.emoji.as_str(), entry.count))
            .collect();
        assert_eq!(order, vec![("❤️", 3), ("🎉", 2), ("😂", 2), ("👍", 1)]);
        // count mirrors the sender list exactly.
        assert!(
            ffi.by_emoji
                .iter()
                .all(|entry| entry.count as usize == entry.senders.len())
        );
    }

    fn imeta_tag(byte: u8, media_type: &str, file_name: &str) -> Vec<String> {
        vec![
            "imeta".to_owned(),
            "v encrypted-media-v1".to_owned(),
            format!(
                "locator blossom-v1 https://media.example/{}.bin",
                hex::encode([byte; 32])
            ),
            format!("ciphertext_sha256 {}", hex::encode([byte; 32])),
            format!(
                "plaintext_sha256 {}",
                hex::encode([byte.wrapping_add(1); 32])
            ),
            format!("nonce {}", hex::encode([byte; 12])),
            format!("m {media_type}"),
            format!("filename {file_name}"),
        ]
    }

    fn imeta_metadata(tags: &[Vec<String>]) -> serde_json::Value {
        serde_json::json!({ "imeta": tags })
    }

    fn record_with_media(
        source_epoch: Option<u64>,
        media: Option<serde_json::Value>,
        reply_preview: Option<TimelineReplyPreview>,
    ) -> TimelineMessageRecord {
        TimelineMessageRecord {
            message_id_hex: "msg".to_owned(),
            source_message_id_hex: None,
            source_epoch,
            direction: "received".to_owned(),
            group_id_hex: "11".repeat(32),
            sender: "alice".to_owned(),
            plaintext: "see attached".to_owned(),
            kind: 9,
            tags: Vec::new(),
            timeline_at: 10,
            received_at: 11,
            reply_to_message_id_hex: reply_preview.as_ref().map(|p| p.message_id_hex.clone()),
            reply_preview,
            media,
            agent_text_stream: None,
            reactions: TimelineReactionSummary::default(),
            deleted: false,
            deleted_by_message_id_hex: None,
            invalidation_status: None,
        }
    }

    #[test]
    fn timeline_message_record_ffi_resolves_media_with_source_epoch() {
        let media = imeta_metadata(&[imeta_tag(0x11, "image/png", "diagram.png")]);
        let record: TimelineMessageRecordFfi = record_with_media(Some(7), Some(media), None).into();

        assert_eq!(record.media.len(), 1);
        assert_eq!(record.media[0].file_name, "diagram.png");
        assert_eq!(record.media[0].source_epoch, 7);
        // Additive: the raw imeta JSON is still exposed during migration.
        assert!(record.media_json.is_some());
    }

    #[test]
    fn timeline_message_record_ffi_keeps_text_when_imeta_malformed() {
        let malformed = vec!["imeta".to_owned(), "v encrypted-media-v1".to_owned()];
        let media = imeta_metadata(&[malformed]);
        let record: TimelineMessageRecordFfi = record_with_media(Some(7), Some(media), None).into();

        assert!(record.media.is_empty());
        assert_eq!(record.plaintext, "see attached");
    }

    #[test]
    fn timeline_message_record_ffi_with_no_media_yields_empty() {
        let record: TimelineMessageRecordFfi = record_with_media(Some(7), None, None).into();
        assert!(record.media.is_empty());
    }

    #[test]
    fn timeline_reply_preview_ffi_resolves_media_with_its_own_source_epoch() {
        let preview = TimelineReplyPreview {
            message_id_hex: "parent".to_owned(),
            sender: "bob".to_owned(),
            plaintext: "original".to_owned(),
            kind: 9,
            // The previewed (target) message lives in its own epoch, distinct
            // from the replying message's epoch.
            source_epoch: Some(3),
            media: Some(imeta_metadata(&[imeta_tag(0x22, "video/mp4", "clip.mp4")])),
            agent_text_stream: None,
            deleted: false,
        };
        let record: TimelineMessageRecordFfi =
            record_with_media(Some(7), None, Some(preview)).into();

        let reply = record.reply_preview.expect("reply preview");
        assert_eq!(reply.media.len(), 1);
        assert_eq!(reply.media[0].file_name, "clip.mp4");
        assert_eq!(reply.media[0].source_epoch, 3);
    }
}
