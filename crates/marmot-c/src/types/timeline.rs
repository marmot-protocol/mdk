//! C mirrors of the materialized timeline conversions.

use std::ffi::c_char;

use marmot_uniffi::conversions::{
    GroupSystemEventFfi, RuntimeProjectionUpdateFfi, TimelineMessageChangeFfi,
    TimelineMessageQueryFfi, TimelineMessageRecordFfi, TimelinePageFfi,
    TimelineProjectionUpdateFfi, TimelineReactionEmojiFfi, TimelineReactionSummaryFfi,
    TimelineRemoveReasonFfi, TimelineReplyPreviewFfi, TimelineSubscriptionUpdateFfi,
    TimelineUpdateTriggerFfi, TimelineUserReactionFfi,
};

use super::chat_list::{MarmotChatListRow, MarmotChatListUpdateTrigger};
use super::common::MarmotMessageTag;
use super::markdown::MarmotMarkdownDocument;
use super::media::MarmotMediaAttachmentReference;
use crate::MarmotStatus;
use crate::macros::{c_enum, c_mirror};
use crate::memory::{CFree, c_bool, free_c_string, optional_str, owned_c_string};

/// Timeline read query. Borrowed input to `marmot_timeline_messages`;
/// NULL string fields and `has_x == false` scalars mean "unset".
#[repr(C)]
pub struct MarmotTimelineMessageQuery {
    /// Restrict to one group. Nullable for the account-wide tail.
    pub group_id_hex: *const c_char,
    /// Substring search. Nullable.
    pub search: *const c_char,
    /// Only messages before this timeline timestamp; set `has_before`
    /// (`uint8_t` boolean: nonzero is true, as for every `has_` flag here).
    pub has_before: u8,
    pub before: u64,
    /// Anchor message id for `before`. Nullable.
    pub before_message_id: *const c_char,
    /// Only messages after this timeline timestamp; set `has_after`.
    pub has_after: u8,
    pub after: u64,
    /// Anchor message id for `after`. Nullable.
    pub after_message_id: *const c_char,
    /// Page-size cap; set `has_limit`.
    pub has_limit: u8,
    pub limit: u32,
}

impl MarmotTimelineMessageQuery {
    /// # Safety
    /// Non-NULL strings must be valid NUL-terminated strings.
    pub(crate) unsafe fn to_ffi(&self) -> Result<TimelineMessageQueryFfi, MarmotStatus> {
        Ok(TimelineMessageQueryFfi {
            group_id_hex: unsafe { optional_str(self.group_id_hex) }?,
            search: unsafe { optional_str(self.search) }?,
            before: c_bool(self.has_before).then_some(self.before),
            before_message_id: unsafe { optional_str(self.before_message_id) }?,
            after: c_bool(self.has_after).then_some(self.after),
            after_message_id: unsafe { optional_str(self.after_message_id) }?,
            limit: c_bool(self.has_limit).then_some(self.limit),
        })
    }
}

c_mirror! {
    /// Preview of the message a timeline row replies to.
    MarmotTimelineReplyPreview from TimelineReplyPreviewFfi {
        str message_id_hex,
        str sender,
        str plaintext,
        rec content_tokens: MarmotMarkdownDocument,
        copy kind: u64,
        opt_str media_json,
        /// Fully-resolved media references for the previewed message.
        vec media/media_len: MarmotMediaAttachmentReference,
        opt_str agent_text_stream_json,
        copy deleted: bool,
        /// Convergence invalidation reason for the previewed message.
        /// Nullable.
        opt_str invalidation_status,
    }
}

c_mirror! {
    /// Parsed view of a kind-1210 group system row.
    MarmotGroupSystemEvent from GroupSystemEventFfi {
        str system_type,
        /// Human-readable fallback. Prefer rendering from `system_type`
        /// plus the structured fields so clients can localize.
        str text,
        opt_str actor_account_id_hex,
        opt_str subject_account_id_hex,
        opt_str name,
        opt_str old_name,
        /// Previous disappearing-message retention seconds; `0` means off.
        opt_copy has_old_retention_seconds/old_retention_seconds: u64,
        /// New disappearing-message retention seconds; `0` means off.
        opt_copy has_new_retention_seconds/new_retention_seconds: u64,
    }
}

c_mirror! {
    /// One emoji tally, pre-sorted by count desc then emoji asc.
    MarmotTimelineReactionEmoji from TimelineReactionEmojiFfi {
        str emoji,
        copy count: u32,
        str_vec senders/senders_len,
    }
}

c_mirror! {
    /// One individual authenticated reaction.
    MarmotTimelineUserReaction from TimelineUserReactionFfi {
        str reaction_message_id_hex,
        str target_message_id_hex,
        str sender,
        str emoji,
        copy reacted_at: u64,
    }
}

c_mirror! {
    /// A message's reaction summary.
    MarmotTimelineReactionSummary from TimelineReactionSummaryFfi {
        vec by_emoji/by_emoji_len: MarmotTimelineReactionEmoji,
        vec user_reactions/user_reactions_len: MarmotTimelineUserReaction,
    }
}

c_mirror! {
    /// One materialized timeline row.
    MarmotTimelineMessageRecord from TimelineMessageRecordFfi,
    free marmot_timeline_message_record_free {
        str message_id_hex,
        /// Delivery marker for own (`direction == "sent"`) messages: NULL
        /// while committed-but-undelivered (render as pending/failed),
        /// the published source event id once delivered. Always set for
        /// received messages.
        opt_str source_message_id_hex,
        /// Authenticated MLS source epoch behind this message's pinned
        /// retention and encrypted-media decisions.
        opt_copy has_source_epoch/source_epoch: u64,
        /// Unset means no recoverable source-epoch decision; `0` means
        /// retention explicitly disabled for this message.
        opt_copy has_retention_seconds/retention_seconds: u64,
        /// Exact pinned expiration timestamp, when finite.
        opt_copy has_retention_expires_at/retention_expires_at: u64,
        str direction,
        str group_id_hex,
        str sender,
        str plaintext,
        rec content_tokens: MarmotMarkdownDocument,
        copy kind: u64,
        vec tags/tags_len: MarmotMessageTag,
        /// Authenticated inner app-event time, or observation time for
        /// synthesized rows.
        copy timeline_at: u64,
        /// Local wall-clock time when this device observed the row.
        copy received_at: u64,
        opt_str reply_to_message_id_hex,
        opt_rec reply_preview: MarmotTimelineReplyPreview,
        opt_str media_json,
        /// Fully-resolved media references for this message; empty when
        /// it has no media.
        vec media/media_len: MarmotMediaAttachmentReference,
        opt_str agent_text_stream_json,
        /// Parsed view of kind-1210 group system rows. NULL for chat,
        /// reactions, stream rows, and malformed assertions.
        opt_rec group_system: MarmotGroupSystemEvent,
        rec reactions: MarmotTimelineReactionSummary,
        copy deleted: bool,
        opt_str deleted_by_message_id_hex,
        /// Convergence invalidation reason (e.g. `LosingBranch`); NULL
        /// for delivered messages.
        opt_str invalidation_status,
    }
}

c_mirror! {
    /// One rendered timeline window (sorted, deduplicated, capped).
    MarmotTimelinePage from TimelinePageFfi,
    free marmot_timeline_page_free {
        vec messages/messages_len: MarmotTimelineMessageRecord,
        copy has_more_before: bool,
        copy has_more_after: bool,
    }
}

c_enum! {
    /// Why a timeline delta fired.
    MarmotTimelineUpdateTrigger from TimelineUpdateTriggerFfi {
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
}

c_enum! {
    /// Why a timeline row was removed.
    MarmotTimelineRemoveReason from TimelineRemoveReasonFfi {
        Invalidated,
        Cleared,
        Pruned,
        NoLongerMatchesQuery,
    }
}

/// One timeline row change.
// The variant size skew is inherent to the C ABI: a boxed Upsert would
// change the exported layout.
#[allow(clippy::large_enum_variant)]
#[repr(C)]
pub enum MarmotTimelineMessageChange {
    Upsert {
        trigger: MarmotTimelineUpdateTrigger,
        message: MarmotTimelineMessageRecord,
    },
    Remove {
        message_id_hex: *mut c_char,
        reason: MarmotTimelineRemoveReason,
    },
}

impl From<TimelineMessageChangeFfi> for MarmotTimelineMessageChange {
    fn from(value: TimelineMessageChangeFfi) -> Self {
        match value {
            TimelineMessageChangeFfi::Upsert { trigger, message } => Self::Upsert {
                trigger: trigger.into(),
                message: message.into(),
            },
            TimelineMessageChangeFfi::Remove {
                message_id_hex,
                reason,
            } => Self::Remove {
                message_id_hex: owned_c_string(message_id_hex),
                reason: reason.into(),
            },
        }
    }
}

impl CFree for MarmotTimelineMessageChange {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            match self {
                Self::Upsert { message, .. } => message.free_in_place(),
                Self::Remove { message_id_hex, .. } => free_c_string(*message_id_hex),
            }
        }
    }
}

c_mirror! {
    /// One group's projection delta: the changed rows plus the refreshed
    /// chat-list row.
    MarmotTimelineProjectionUpdate from TimelineProjectionUpdateFfi {
        str group_id_hex,
        vec messages/messages_len: MarmotTimelineMessageRecord,
        vec changes/changes_len: MarmotTimelineMessageChange,
        opt_rec chat_list_row: MarmotChatListRow,
        copy chat_list_trigger: MarmotChatListUpdateTrigger,
    }
}

c_mirror! {
    /// A projection delta plus the account it belongs to.
    MarmotRuntimeProjectionUpdate from RuntimeProjectionUpdateFfi {
        str account_id_hex,
        str account_label,
        rec update: MarmotTimelineProjectionUpdate,
    }
}

/// One raw timeline-subscription delta: a full page replacement or a
/// projection update.
#[repr(C)]
pub enum MarmotTimelineSubscriptionUpdate {
    Page {
        page: MarmotTimelinePage,
    },
    Projection {
        update: MarmotRuntimeProjectionUpdate,
    },
}

impl From<TimelineSubscriptionUpdateFfi> for MarmotTimelineSubscriptionUpdate {
    fn from(value: TimelineSubscriptionUpdateFfi) -> Self {
        match value {
            TimelineSubscriptionUpdateFfi::Page { page } => Self::Page { page: page.into() },
            TimelineSubscriptionUpdateFfi::Projection { update } => Self::Projection {
                update: update.into(),
            },
        }
    }
}

impl CFree for MarmotTimelineSubscriptionUpdate {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            match self {
                Self::Page { page } => page.free_in_place(),
                Self::Projection { update } => update.free_in_place(),
            }
        }
    }
}

/// Free a timeline-subscription delta returned by this library. NULL is a
/// no-op.
///
/// # Safety
/// `update` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_timeline_subscription_update_free(
    update: *mut MarmotTimelineSubscriptionUpdate,
) {
    crate::memory::free_guard(|| unsafe { crate::memory::free_boxed(update) });
}
