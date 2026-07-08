//! C mirrors of the timeline conversions (`marmot-uniffi/src/conversions/timeline.rs`):
//! reaction tallies, reply previews, message records, pages, and the
//! projection/subscription update payloads.

use std::ffi::c_char;

use marmot_uniffi::conversions::{
    GroupSystemEventFfi, RuntimeProjectionUpdateFfi, TimelineMessageChangeFfi,
    TimelineMessageQueryFfi, TimelineMessageRecordFfi, TimelinePageFfi,
    TimelineProjectionUpdateFfi, TimelineReactionEmojiFfi, TimelineReactionSummaryFfi,
    TimelineRemoveReasonFfi, TimelineReplyPreviewFfi, TimelineSubscriptionUpdateFfi,
    TimelineUpdateTriggerFfi, TimelineUserReactionFfi,
};

use crate::MarmotStatus;
use crate::memory::{
    CFree, boxed_opt, free_boxed, free_c_string, free_vec, optional_str, owned_c_string,
    owned_opt_c_string, owned_vec,
};
use crate::types::chat_list::{MarmotChatListRow, MarmotChatListUpdateTrigger};
use crate::types::common::MarmotMessageTag;
use crate::types::markdown::MarmotMarkdownDocument;
use crate::types::media::MarmotMediaAttachmentReference;

/// One emoji tally inside a reaction summary.
#[repr(C)]
pub struct MarmotTimelineReactionEmoji {
    pub emoji: *mut c_char,
    /// Number of distinct senders that reacted with this emoji
    /// (`== senders_len`), surfaced so clients render the tally without
    /// counting. This is the authenticated reaction count only; clients
    /// overlay their own optimistic react/unreact and "did I react" state on
    /// top.
    pub count: u32,
    pub senders: *mut *mut c_char,
    pub senders_len: usize,
}

impl From<TimelineReactionEmojiFfi> for MarmotTimelineReactionEmoji {
    fn from(value: TimelineReactionEmojiFfi) -> Self {
        let (senders, senders_len) = owned_vec(
            value
                .senders
                .into_iter()
                .map(owned_c_string)
                .collect::<Vec<_>>(),
        );
        Self {
            emoji: owned_c_string(value.emoji),
            count: value.count,
            senders,
            senders_len,
        }
    }
}

impl CFree for MarmotTimelineReactionEmoji {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.emoji);
            free_vec(self.senders, self.senders_len);
        }
    }
}

/// One individual reaction event by one sender on one target message.
#[repr(C)]
pub struct MarmotTimelineUserReaction {
    pub reaction_message_id_hex: *mut c_char,
    pub target_message_id_hex: *mut c_char,
    pub sender: *mut c_char,
    pub emoji: *mut c_char,
    pub reacted_at: u64,
}

impl From<TimelineUserReactionFfi> for MarmotTimelineUserReaction {
    fn from(value: TimelineUserReactionFfi) -> Self {
        Self {
            reaction_message_id_hex: owned_c_string(value.reaction_message_id_hex),
            target_message_id_hex: owned_c_string(value.target_message_id_hex),
            sender: owned_c_string(value.sender),
            emoji: owned_c_string(value.emoji),
            reacted_at: value.reacted_at,
        }
    }
}

impl CFree for MarmotTimelineUserReaction {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.reaction_message_id_hex);
            free_c_string(self.target_message_id_hex);
            free_c_string(self.sender);
            free_c_string(self.emoji);
        }
    }
}

/// Aggregated reactions on one timeline message.
#[repr(C)]
pub struct MarmotTimelineReactionSummary {
    /// Reaction tallies pre-sorted by `count` descending, ties broken by
    /// `emoji` ascending, so clients render a stable tally without
    /// re-sorting.
    pub by_emoji: *mut MarmotTimelineReactionEmoji,
    pub by_emoji_len: usize,
    pub user_reactions: *mut MarmotTimelineUserReaction,
    pub user_reactions_len: usize,
}

impl From<TimelineReactionSummaryFfi> for MarmotTimelineReactionSummary {
    fn from(value: TimelineReactionSummaryFfi) -> Self {
        let (by_emoji, by_emoji_len) =
            owned_vec(value.by_emoji.into_iter().map(Into::into).collect());
        let (user_reactions, user_reactions_len) =
            owned_vec(value.user_reactions.into_iter().map(Into::into).collect());
        Self {
            by_emoji,
            by_emoji_len,
            user_reactions,
            user_reactions_len,
        }
    }
}

impl CFree for MarmotTimelineReactionSummary {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(self.by_emoji, self.by_emoji_len);
            free_vec(self.user_reactions, self.user_reactions_len);
        }
    }
}

/// Timeline query filter for `marmot_timeline_messages`. Caller-owned input;
/// this library never frees input structs. All fields optional: NULL strings
/// and `has_x == false` scalars mean "unset".
#[repr(C)]
pub struct MarmotTimelineMessageQuery {
    /// Restrict to one group (opaque MLS group id, hex). Nullable.
    pub group_id_hex: *mut c_char,
    /// Substring search over plaintext. Nullable.
    pub search: *mut c_char,
    /// Only messages before this timeline timestamp; set `has_before`.
    pub has_before: bool,
    pub before: u64,
    /// Cursor message id paired with `before`. Nullable.
    pub before_message_id: *mut c_char,
    /// Only messages after this timeline timestamp; set `has_after`.
    pub has_after: bool,
    pub after: u64,
    /// Cursor message id paired with `after`. Nullable.
    pub after_message_id: *mut c_char,
    /// Page-size cap; set `has_limit`.
    pub has_limit: bool,
    pub limit: u32,
}

impl From<TimelineMessageQueryFfi> for MarmotTimelineMessageQuery {
    fn from(value: TimelineMessageQueryFfi) -> Self {
        Self {
            group_id_hex: owned_opt_c_string(value.group_id_hex),
            search: owned_opt_c_string(value.search),
            has_before: value.before.is_some(),
            before: value.before.unwrap_or(0),
            before_message_id: owned_opt_c_string(value.before_message_id),
            has_after: value.after.is_some(),
            after: value.after.unwrap_or(0),
            after_message_id: owned_opt_c_string(value.after_message_id),
            has_limit: value.limit.is_some(),
            limit: value.limit.unwrap_or(0),
        }
    }
}

impl MarmotTimelineMessageQuery {
    /// Read a caller-owned query struct into the Ffi record without taking
    /// ownership of any caller memory.
    ///
    /// # Safety
    /// Every non-NULL string field must be a valid NUL-terminated string.
    pub(crate) unsafe fn to_ffi(&self) -> Result<TimelineMessageQueryFfi, MarmotStatus> {
        Ok(TimelineMessageQueryFfi {
            group_id_hex: unsafe { optional_str(self.group_id_hex.cast_const()) }?,
            search: unsafe { optional_str(self.search.cast_const()) }?,
            before: self.has_before.then_some(self.before),
            before_message_id: unsafe { optional_str(self.before_message_id.cast_const()) }?,
            after: self.has_after.then_some(self.after),
            after_message_id: unsafe { optional_str(self.after_message_id.cast_const()) }?,
            limit: self.has_limit.then_some(self.limit),
        })
    }
}

impl CFree for MarmotTimelineMessageQuery {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.group_id_hex);
            free_c_string(self.search);
            free_c_string(self.before_message_id);
            free_c_string(self.after_message_id);
        }
    }
}

/// Inline preview of the message a timeline row replies to.
#[repr(C)]
pub struct MarmotTimelineReplyPreview {
    pub message_id_hex: *mut c_char,
    pub sender: *mut c_char,
    pub plaintext: *mut c_char,
    pub content_tokens: MarmotMarkdownDocument,
    pub kind: u64,
    /// Raw `imeta` media JSON of the previewed message. Nullable.
    pub media_json: *mut c_char,
    /// Fully-resolved, downloadable media references for the previewed
    /// message, built from its `imeta` tags + its own `source_epoch` using
    /// the same resolution and validation as `marmot_list_media`. Empty when
    /// the previewed message has no media or its `imeta` is malformed.
    pub media: *mut MarmotMediaAttachmentReference,
    pub media_len: usize,
    /// Raw agent text-stream JSON of the previewed message. Nullable.
    pub agent_text_stream_json: *mut c_char,
    pub deleted: bool,
}

impl From<TimelineReplyPreviewFfi> for MarmotTimelineReplyPreview {
    fn from(value: TimelineReplyPreviewFfi) -> Self {
        let (media, media_len) = owned_vec(value.media.into_iter().map(Into::into).collect());
        Self {
            message_id_hex: owned_c_string(value.message_id_hex),
            sender: owned_c_string(value.sender),
            plaintext: owned_c_string(value.plaintext),
            content_tokens: value.content_tokens.into(),
            kind: value.kind,
            media_json: owned_opt_c_string(value.media_json),
            media,
            media_len,
            agent_text_stream_json: owned_opt_c_string(value.agent_text_stream_json),
            deleted: value.deleted,
        }
    }
}

impl CFree for MarmotTimelineReplyPreview {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.message_id_hex);
            free_c_string(self.sender);
            free_c_string(self.plaintext);
            self.content_tokens.free_in_place();
            free_c_string(self.media_json);
            free_vec(self.media, self.media_len);
            free_c_string(self.agent_text_stream_json);
        }
    }
}

/// Parsed view of a kind-1210 group system row (member added/removed,
/// rename, retention change, …).
#[repr(C)]
pub struct MarmotGroupSystemEvent {
    pub system_type: *mut c_char,
    /// Human-readable fallback from the row content. Prefer rendering from
    /// `system_type` plus the structured fields so clients can localize and
    /// render the local account as "you".
    pub text: *mut c_char,
    /// Account that performed the action. Nullable.
    pub actor_account_id_hex: *mut c_char,
    /// Account the action targeted. Nullable.
    pub subject_account_id_hex: *mut c_char,
    /// New group name for rename events. Nullable.
    pub name: *mut c_char,
    /// Previous group name for rename events. Nullable.
    pub old_name: *mut c_char,
    /// Previous disappearing-message retention in seconds; `0` means off.
    /// Only meaningful when `has_old_retention_seconds`.
    pub has_old_retention_seconds: bool,
    pub old_retention_seconds: u64,
    /// New disappearing-message retention in seconds; `0` means off.
    /// Only meaningful when `has_new_retention_seconds`.
    pub has_new_retention_seconds: bool,
    pub new_retention_seconds: u64,
}

impl From<GroupSystemEventFfi> for MarmotGroupSystemEvent {
    fn from(value: GroupSystemEventFfi) -> Self {
        Self {
            system_type: owned_c_string(value.system_type),
            text: owned_c_string(value.text),
            actor_account_id_hex: owned_opt_c_string(value.actor_account_id_hex),
            subject_account_id_hex: owned_opt_c_string(value.subject_account_id_hex),
            name: owned_opt_c_string(value.name),
            old_name: owned_opt_c_string(value.old_name),
            has_old_retention_seconds: value.old_retention_seconds.is_some(),
            old_retention_seconds: value.old_retention_seconds.unwrap_or(0),
            has_new_retention_seconds: value.new_retention_seconds.is_some(),
            new_retention_seconds: value.new_retention_seconds.unwrap_or(0),
        }
    }
}

impl CFree for MarmotGroupSystemEvent {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.system_type);
            free_c_string(self.text);
            free_c_string(self.actor_account_id_hex);
            free_c_string(self.subject_account_id_hex);
            free_c_string(self.name);
            free_c_string(self.old_name);
        }
    }
}

/// One projected timeline message row.
#[repr(C)]
pub struct MarmotTimelineMessageRecord {
    pub message_id_hex: *mut c_char,
    /// Delivery marker for own (`direction == "sent"`) messages. An own send
    /// commits and projects locally *before* it publishes, so a message that
    /// was committed but not yet delivered (e.g. sent offline / relay
    /// unreachable) carries NULL here — render it as pending/failed. On
    /// delivery/convergence the same row is upserted with the published
    /// source event id, so flip the UI to delivered once this becomes
    /// non-NULL. To re-drive delivery of a stuck pending message without
    /// minting a duplicate, call `marmot_retry_group_convergence` rather
    /// than re-sending the text. For received messages this is the
    /// originating event id and is always non-NULL.
    pub source_message_id_hex: *mut c_char,
    pub direction: *mut c_char,
    pub group_id_hex: *mut c_char,
    pub sender: *mut c_char,
    pub plaintext: *mut c_char,
    pub content_tokens: MarmotMarkdownDocument,
    pub kind: u64,
    pub tags: *mut MarmotMessageTag,
    pub tags_len: usize,
    pub timeline_at: u64,
    pub received_at: u64,
    /// Id of the message this row replies to. Nullable.
    pub reply_to_message_id_hex: *mut c_char,
    /// Inline preview of the replied-to message. Nullable.
    pub reply_preview: *mut MarmotTimelineReplyPreview,
    /// Raw `imeta` media JSON. Nullable.
    pub media_json: *mut c_char,
    /// Fully-resolved, downloadable media references for this message, built
    /// from its `imeta` tags + its own `source_epoch` using the same
    /// resolution and validation as `marmot_list_media` (a `list_media`
    /// record and this row's `media` resolve identically for the same
    /// message). Empty when the message has no media; a malformed `imeta`
    /// attachment is dropped while the message still appears as text.
    pub media: *mut MarmotMediaAttachmentReference,
    pub media_len: usize,
    /// Raw agent text-stream JSON. Nullable.
    pub agent_text_stream_json: *mut c_char,
    /// Parsed view of kind-1210 group system rows. NULL for chat, reactions,
    /// stream rows, and malformed/free-text kind-1210 assertions.
    pub group_system: *mut MarmotGroupSystemEvent,
    pub reactions: MarmotTimelineReactionSummary,
    pub deleted: bool,
    /// Id of the deletion event when `deleted`. Nullable.
    pub deleted_by_message_id_hex: *mut c_char,
    /// Set when convergence invalidated this message (it landed on a losing
    /// branch). The message is kept as a "did not reach the group" tombstone
    /// instead of disappearing; the value is the engine invalidation reason
    /// (e.g. `LosingBranch`). NULL for delivered messages.
    pub invalidation_status: *mut c_char,
}

impl From<TimelineMessageRecordFfi> for MarmotTimelineMessageRecord {
    fn from(value: TimelineMessageRecordFfi) -> Self {
        let (tags, tags_len) = owned_vec(value.tags.into_iter().map(Into::into).collect());
        let (media, media_len) = owned_vec(value.media.into_iter().map(Into::into).collect());
        Self {
            message_id_hex: owned_c_string(value.message_id_hex),
            source_message_id_hex: owned_opt_c_string(value.source_message_id_hex),
            direction: owned_c_string(value.direction),
            group_id_hex: owned_c_string(value.group_id_hex),
            sender: owned_c_string(value.sender),
            plaintext: owned_c_string(value.plaintext),
            content_tokens: value.content_tokens.into(),
            kind: value.kind,
            tags,
            tags_len,
            timeline_at: value.timeline_at,
            received_at: value.received_at,
            reply_to_message_id_hex: owned_opt_c_string(value.reply_to_message_id_hex),
            reply_preview: boxed_opt(value.reply_preview.map(Into::into)),
            media_json: owned_opt_c_string(value.media_json),
            media,
            media_len,
            agent_text_stream_json: owned_opt_c_string(value.agent_text_stream_json),
            group_system: boxed_opt(value.group_system.map(Into::into)),
            reactions: value.reactions.into(),
            deleted: value.deleted,
            deleted_by_message_id_hex: owned_opt_c_string(value.deleted_by_message_id_hex),
            invalidation_status: owned_opt_c_string(value.invalidation_status),
        }
    }
}

impl CFree for MarmotTimelineMessageRecord {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.message_id_hex);
            free_c_string(self.source_message_id_hex);
            free_c_string(self.direction);
            free_c_string(self.group_id_hex);
            free_c_string(self.sender);
            free_c_string(self.plaintext);
            self.content_tokens.free_in_place();
            free_vec(self.tags, self.tags_len);
            free_c_string(self.reply_to_message_id_hex);
            free_boxed(self.reply_preview);
            free_c_string(self.media_json);
            free_vec(self.media, self.media_len);
            free_c_string(self.agent_text_stream_json);
            free_boxed(self.group_system);
            self.reactions.free_in_place();
            free_c_string(self.deleted_by_message_id_hex);
            free_c_string(self.invalidation_status);
        }
    }
}

/// Free a single message record root. NULL is a no-op. Records nested inside
/// a page or update are owned by that root and freed with it — never
/// individually.
///
/// # Safety
/// `record` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_timeline_message_record_free(
    record: *mut MarmotTimelineMessageRecord,
) {
    crate::memory::free_guard(|| unsafe { free_boxed(record) });
}

/// One page of timeline messages (`marmot_timeline_messages`, subscription
/// snapshot/next/paginate).
#[repr(C)]
pub struct MarmotTimelinePage {
    pub messages: *mut MarmotTimelineMessageRecord,
    pub messages_len: usize,
    pub has_more_before: bool,
    pub has_more_after: bool,
}

impl From<TimelinePageFfi> for MarmotTimelinePage {
    fn from(value: TimelinePageFfi) -> Self {
        let (messages, messages_len) =
            owned_vec(value.messages.into_iter().map(Into::into).collect());
        Self {
            messages,
            messages_len,
            has_more_before: value.has_more_before,
            has_more_after: value.has_more_after,
        }
    }
}

impl CFree for MarmotTimelinePage {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.messages, self.messages_len) };
    }
}

/// Free a timeline page root. NULL is a no-op.
///
/// # Safety
/// `page` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_timeline_page_free(page: *mut MarmotTimelinePage) {
    crate::memory::free_guard(|| unsafe { free_boxed(page) });
}

/// Why the timeline subscription raised an upsert.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarmotTimelineUpdateTrigger {
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

impl From<TimelineUpdateTriggerFfi> for MarmotTimelineUpdateTrigger {
    fn from(value: TimelineUpdateTriggerFfi) -> Self {
        match value {
            TimelineUpdateTriggerFfi::NewMessage => Self::NewMessage,
            TimelineUpdateTriggerFfi::MessageEditedOrReprojected => {
                Self::MessageEditedOrReprojected
            }
            TimelineUpdateTriggerFfi::ReactionAdded => Self::ReactionAdded,
            TimelineUpdateTriggerFfi::ReactionRemoved => Self::ReactionRemoved,
            TimelineUpdateTriggerFfi::MessageDeleted => Self::MessageDeleted,
            TimelineUpdateTriggerFfi::ReplyPreviewChanged => Self::ReplyPreviewChanged,
            TimelineUpdateTriggerFfi::AgentStreamStarted => Self::AgentStreamStarted,
            TimelineUpdateTriggerFfi::AgentStreamFinished => Self::AgentStreamFinished,
            TimelineUpdateTriggerFfi::AgentActivity => Self::AgentActivity,
            TimelineUpdateTriggerFfi::AgentOperation => Self::AgentOperation,
            TimelineUpdateTriggerFfi::GroupSystem => Self::GroupSystem,
            TimelineUpdateTriggerFfi::DeliveryOrSendStateChanged => {
                Self::DeliveryOrSendStateChanged
            }
            TimelineUpdateTriggerFfi::ReceiptChanged => Self::ReceiptChanged,
            TimelineUpdateTriggerFfi::SnapshotRefresh => Self::SnapshotRefresh,
        }
    }
}

impl CFree for MarmotTimelineUpdateTrigger {
    unsafe fn free_in_place(&mut self) {}
}

/// Why a message left the subscribed timeline window.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarmotTimelineRemoveReason {
    Invalidated,
    Cleared,
    Pruned,
    NoLongerMatchesQuery,
}

impl From<TimelineRemoveReasonFfi> for MarmotTimelineRemoveReason {
    fn from(value: TimelineRemoveReasonFfi) -> Self {
        match value {
            TimelineRemoveReasonFfi::Invalidated => Self::Invalidated,
            TimelineRemoveReasonFfi::Cleared => Self::Cleared,
            TimelineRemoveReasonFfi::Pruned => Self::Pruned,
            TimelineRemoveReasonFfi::NoLongerMatchesQuery => Self::NoLongerMatchesQuery,
        }
    }
}

impl CFree for MarmotTimelineRemoveReason {
    unsafe fn free_in_place(&mut self) {}
}

/// One incremental change to a subscribed timeline window: a row upsert
/// (with the full replacement record) or a row removal.
#[repr(C)]
#[allow(clippy::large_enum_variant)]
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
        match self {
            Self::Upsert { message, .. } => unsafe { message.free_in_place() },
            Self::Remove { message_id_hex, .. } => unsafe { free_c_string(*message_id_hex) },
        }
    }
}

/// One projection update for a single group: the refreshed window plus the
/// incremental changes that produced it, and the group's refreshed chat-list
/// row when it changed.
#[repr(C)]
pub struct MarmotTimelineProjectionUpdate {
    pub group_id_hex: *mut c_char,
    pub messages: *mut MarmotTimelineMessageRecord,
    pub messages_len: usize,
    pub changes: *mut MarmotTimelineMessageChange,
    pub changes_len: usize,
    /// Refreshed chat-list row for this group. Nullable.
    pub chat_list_row: *mut MarmotChatListRow,
    pub chat_list_trigger: MarmotChatListUpdateTrigger,
}

impl From<TimelineProjectionUpdateFfi> for MarmotTimelineProjectionUpdate {
    fn from(value: TimelineProjectionUpdateFfi) -> Self {
        let (messages, messages_len) =
            owned_vec(value.messages.into_iter().map(Into::into).collect());
        let (changes, changes_len) = owned_vec(value.changes.into_iter().map(Into::into).collect());
        Self {
            group_id_hex: owned_c_string(value.group_id_hex),
            messages,
            messages_len,
            changes,
            changes_len,
            chat_list_row: boxed_opt(value.chat_list_row.map(Into::into)),
            chat_list_trigger: value.chat_list_trigger.into(),
        }
    }
}

impl CFree for MarmotTimelineProjectionUpdate {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.group_id_hex);
            free_vec(self.messages, self.messages_len);
            free_vec(self.changes, self.changes_len);
            free_boxed(self.chat_list_row);
        }
    }
}

/// A projection update tagged with the account it belongs to, for
/// runtime-wide subscriptions that span accounts.
#[repr(C)]
pub struct MarmotRuntimeProjectionUpdate {
    pub account_id_hex: *mut c_char,
    pub account_label: *mut c_char,
    pub update: MarmotTimelineProjectionUpdate,
}

impl From<RuntimeProjectionUpdateFfi> for MarmotRuntimeProjectionUpdate {
    fn from(value: RuntimeProjectionUpdateFfi) -> Self {
        Self {
            account_id_hex: owned_c_string(value.account_id_hex),
            account_label: owned_c_string(value.account_label),
            update: value.update.into(),
        }
    }
}

impl CFree for MarmotRuntimeProjectionUpdate {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.account_id_hex);
            free_c_string(self.account_label);
            self.update.free_in_place();
        }
    }
}

/// One timeline subscription update: a full replacement page or an
/// incremental projection update. Variants carry rich payloads by value so
/// hosts read them without extra dereferences.
#[repr(C)]
#[allow(clippy::large_enum_variant)]
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
        match self {
            Self::Page { page } => unsafe { page.free_in_place() },
            Self::Projection { update } => unsafe { update.free_in_place() },
        }
    }
}

/// Free a subscription update root (timeline subscription `next_update`).
/// NULL is a no-op.
///
/// # Safety
/// `update` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_timeline_subscription_update_free(
    update: *mut MarmotTimelineSubscriptionUpdate,
) {
    crate::memory::free_guard(|| unsafe { free_boxed(update) });
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use marmot_uniffi::conversions::{
        ChatListRowFfi, ChatListUpdateTriggerFfi, MediaAttachmentReferenceFfi, MediaLocatorFfi,
        MessageTagFfi, SelfMembershipFfi,
    };
    use marmot_uniffi::{MarkdownBlockFfi, MarkdownDocumentFfi, MarkdownInlineFfi};

    use super::*;
    use crate::memory::boxed;

    fn sample_markdown() -> MarkdownDocumentFfi {
        MarkdownDocumentFfi {
            blocks: vec![MarkdownBlockFfi::Paragraph {
                inlines: vec![MarkdownInlineFfi::Text {
                    content: "hello burrow".to_owned(),
                }],
            }],
            truncated: false,
        }
    }

    fn sample_media_reference() -> MediaAttachmentReferenceFfi {
        MediaAttachmentReferenceFfi {
            locators: vec![MediaLocatorFfi {
                kind: "blossom-v1".to_owned(),
                value: "https://media.example/blob.bin".to_owned(),
            }],
            ciphertext_sha256: "aa".repeat(32),
            plaintext_sha256: "bb".repeat(32),
            nonce_hex: "cc".repeat(12),
            file_name: "diagram.png".to_owned(),
            media_type: "image/png".to_owned(),
            version: "encrypted-media-v1".to_owned(),
            source_epoch: 7,
            dim: Some("640x480".to_owned()),
            thumbhash: Some("thumb".to_owned()),
        }
    }

    fn sample_reaction_summary() -> TimelineReactionSummaryFfi {
        TimelineReactionSummaryFfi {
            by_emoji: vec![TimelineReactionEmojiFfi {
                emoji: "👍".to_owned(),
                count: 2,
                senders: vec!["alice".to_owned(), "bob".to_owned()],
            }],
            user_reactions: vec![TimelineUserReactionFfi {
                reaction_message_id_hex: "r1".to_owned(),
                target_message_id_hex: "m1".to_owned(),
                sender: "alice".to_owned(),
                emoji: "👍".to_owned(),
                reacted_at: 41,
            }],
        }
    }

    fn sample_reply_preview() -> TimelineReplyPreviewFfi {
        TimelineReplyPreviewFfi {
            message_id_hex: "parent".to_owned(),
            sender: "bob".to_owned(),
            plaintext: "original".to_owned(),
            content_tokens: sample_markdown(),
            kind: 9,
            media_json: Some("{\"imeta\":[]}".to_owned()),
            media: vec![sample_media_reference()],
            agent_text_stream_json: Some("{\"stream\":\"s\"}".to_owned()),
            deleted: false,
        }
    }

    fn sample_group_system_event() -> GroupSystemEventFfi {
        GroupSystemEventFfi {
            system_type: "retention_changed".to_owned(),
            text: "alice set messages to disappear".to_owned(),
            actor_account_id_hex: Some("aa".repeat(32)),
            subject_account_id_hex: Some("bb".repeat(32)),
            name: Some("Burrow".to_owned()),
            old_name: Some("Old Burrow".to_owned()),
            old_retention_seconds: Some(0),
            new_retention_seconds: Some(86_400),
        }
    }

    fn sample_message_record() -> TimelineMessageRecordFfi {
        TimelineMessageRecordFfi {
            message_id_hex: "m1".to_owned(),
            source_message_id_hex: Some("src1".to_owned()),
            direction: "received".to_owned(),
            group_id_hex: "11".repeat(16),
            sender: "alice".to_owned(),
            plaintext: "hello burrow".to_owned(),
            content_tokens: sample_markdown(),
            kind: 9,
            tags: vec![MessageTagFfi {
                values: vec!["e".to_owned(), "abcd".to_owned()],
            }],
            timeline_at: 10,
            received_at: 11,
            reply_to_message_id_hex: Some("parent".to_owned()),
            reply_preview: Some(sample_reply_preview()),
            media_json: Some("{\"imeta\":[]}".to_owned()),
            media: vec![sample_media_reference()],
            agent_text_stream_json: Some("{\"stream\":\"s\"}".to_owned()),
            group_system: Some(sample_group_system_event()),
            reactions: sample_reaction_summary(),
            deleted: true,
            deleted_by_message_id_hex: Some("del1".to_owned()),
            invalidation_status: Some("LosingBranch".to_owned()),
        }
    }

    fn sample_chat_list_row() -> ChatListRowFfi {
        ChatListRowFfi {
            group_id_hex: "11".repeat(16),
            archived: false,
            pending_confirmation: false,
            title: "Burrow".to_owned(),
            group_name: "Burrow".to_owned(),
            avatar_url: None,
            avatar: None,
            last_message: None,
            unread_count: 1,
            has_unread: true,
            unread_mention_count: 0,
            unread_mention: false,
            first_unread_message_id_hex: None,
            last_read_message_id_hex: None,
            last_read_timeline_at: None,
            updated_at: 12,
            self_membership: SelfMembershipFfi::Member,
        }
    }

    fn sample_runtime_projection_update() -> RuntimeProjectionUpdateFfi {
        RuntimeProjectionUpdateFfi {
            account_id_hex: "cc".repeat(32),
            account_label: "marmy".to_owned(),
            update: TimelineProjectionUpdateFfi {
                group_id_hex: "11".repeat(16),
                messages: vec![sample_message_record()],
                changes: vec![
                    TimelineMessageChangeFfi::Upsert {
                        trigger: TimelineUpdateTriggerFfi::NewMessage,
                        message: sample_message_record(),
                    },
                    TimelineMessageChangeFfi::Remove {
                        message_id_hex: "gone".to_owned(),
                        reason: TimelineRemoveReasonFfi::Pruned,
                    },
                ],
                chat_list_row: Some(sample_chat_list_row()),
                chat_list_trigger: ChatListUpdateTriggerFfi::NewLastMessage,
            },
        }
    }

    #[test]
    fn timeline_message_record_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotTimelineMessageRecord = sample_message_record().into();
        assert_eq!(
            unsafe { CStr::from_ptr(mirror.message_id_hex) }.to_str(),
            Ok("m1")
        );
        assert!(!mirror.source_message_id_hex.is_null());
        assert_eq!(mirror.content_tokens.blocks_len, 1);
        assert_eq!(mirror.tags_len, 1);
        assert_eq!(mirror.media_len, 1);
        assert!(!mirror.reply_preview.is_null());
        let preview = unsafe { &*mirror.reply_preview };
        assert_eq!(preview.media_len, 1);
        assert!(!preview.agent_text_stream_json.is_null());
        assert!(!mirror.group_system.is_null());
        let system = unsafe { &*mirror.group_system };
        assert!(system.has_new_retention_seconds);
        assert_eq!(system.new_retention_seconds, 86_400);
        assert!(system.has_old_retention_seconds);
        assert_eq!(system.old_retention_seconds, 0);
        assert_eq!(mirror.reactions.by_emoji_len, 1);
        assert_eq!(mirror.reactions.user_reactions_len, 1);
        let tally = unsafe { &*mirror.reactions.by_emoji };
        assert_eq!(tally.count, 2);
        assert_eq!(tally.senders_len, 2);
        assert!(mirror.deleted);
        assert!(!mirror.invalidation_status.is_null());
        let root = boxed(mirror);
        unsafe { marmot_timeline_message_record_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn timeline_page_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let page: MarmotTimelinePage = TimelinePageFfi {
            messages: vec![sample_message_record(), sample_message_record()],
            has_more_before: true,
            has_more_after: false,
        }
        .into();
        assert_eq!(page.messages_len, 2);
        assert!(page.has_more_before);
        assert!(!page.has_more_after);
        let root = boxed(page);
        unsafe { marmot_timeline_page_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn subscription_update_roundtrips_both_variants() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let page_update: MarmotTimelineSubscriptionUpdate = TimelineSubscriptionUpdateFfi::Page {
            page: TimelinePageFfi {
                messages: vec![sample_message_record()],
                has_more_before: false,
                has_more_after: true,
            },
        }
        .into();
        match &page_update {
            MarmotTimelineSubscriptionUpdate::Page { page } => {
                assert_eq!(page.messages_len, 1);
                assert!(page.has_more_after);
            }
            MarmotTimelineSubscriptionUpdate::Projection { .. } => {
                panic!("expected Page variant")
            }
        }
        let root = boxed(page_update);
        unsafe { marmot_timeline_subscription_update_free(root) };

        let projection: MarmotTimelineSubscriptionUpdate =
            TimelineSubscriptionUpdateFfi::Projection {
                update: sample_runtime_projection_update(),
            }
            .into();
        match &projection {
            MarmotTimelineSubscriptionUpdate::Projection { update } => {
                assert_eq!(
                    unsafe { CStr::from_ptr(update.account_label) }.to_str(),
                    Ok("marmy")
                );
                assert_eq!(update.update.messages_len, 1);
                assert_eq!(update.update.changes_len, 2);
                assert!(!update.update.chat_list_row.is_null());
                let changes = unsafe {
                    std::slice::from_raw_parts(update.update.changes, update.update.changes_len)
                };
                match &changes[0] {
                    MarmotTimelineMessageChange::Upsert { trigger, message } => {
                        assert_eq!(*trigger, MarmotTimelineUpdateTrigger::NewMessage);
                        assert_eq!(message.kind, 9);
                    }
                    MarmotTimelineMessageChange::Remove { .. } => {
                        panic!("expected Upsert change")
                    }
                }
                match &changes[1] {
                    MarmotTimelineMessageChange::Remove {
                        message_id_hex,
                        reason,
                    } => {
                        assert_eq!(
                            unsafe { CStr::from_ptr(*message_id_hex) }.to_str(),
                            Ok("gone")
                        );
                        assert_eq!(*reason, MarmotTimelineRemoveReason::Pruned);
                    }
                    MarmotTimelineMessageChange::Upsert { .. } => {
                        panic!("expected Remove change")
                    }
                }
            }
            MarmotTimelineSubscriptionUpdate::Page { .. } => {
                panic!("expected Projection variant")
            }
        }
        let root = boxed(projection);
        unsafe { marmot_timeline_subscription_update_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn query_input_roundtrips_borrowed_fields() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let owned: MarmotTimelineMessageQuery = TimelineMessageQueryFfi {
            group_id_hex: Some("11".repeat(16)),
            search: Some("burrow".to_owned()),
            before: Some(99),
            before_message_id: Some("b1".to_owned()),
            after: None,
            after_message_id: None,
            limit: Some(50),
        }
        .into();
        let ffi = unsafe { owned.to_ffi() }.expect("valid strings");
        assert_eq!(ffi.group_id_hex.as_deref(), Some("11".repeat(16).as_str()));
        assert_eq!(ffi.search.as_deref(), Some("burrow"));
        assert_eq!(ffi.before, Some(99));
        assert_eq!(ffi.before_message_id.as_deref(), Some("b1"));
        assert_eq!(ffi.after, None);
        assert_eq!(ffi.after_message_id, None);
        assert_eq!(ffi.limit, Some(50));
        let root = boxed(owned);
        unsafe { free_boxed(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn empty_and_none_fields_convert_to_null() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let page: MarmotTimelinePage = TimelinePageFfi {
            messages: Vec::new(),
            has_more_before: false,
            has_more_after: false,
        }
        .into();
        assert!(page.messages.is_null());
        assert_eq!(page.messages_len, 0);
        let root = boxed(page);
        unsafe { marmot_timeline_page_free(root) };

        let record: MarmotTimelineMessageRecord = TimelineMessageRecordFfi {
            message_id_hex: "m1".to_owned(),
            source_message_id_hex: None,
            direction: "sent".to_owned(),
            group_id_hex: "11".repeat(16),
            sender: "me".to_owned(),
            plaintext: "hi".to_owned(),
            content_tokens: MarkdownDocumentFfi {
                blocks: Vec::new(),
                truncated: false,
            },
            kind: 9,
            tags: Vec::new(),
            timeline_at: 1,
            received_at: 2,
            reply_to_message_id_hex: None,
            reply_preview: None,
            media_json: None,
            media: Vec::new(),
            agent_text_stream_json: None,
            group_system: None,
            reactions: TimelineReactionSummaryFfi {
                by_emoji: Vec::new(),
                user_reactions: Vec::new(),
            },
            deleted: false,
            deleted_by_message_id_hex: None,
            invalidation_status: None,
        }
        .into();
        assert!(record.source_message_id_hex.is_null());
        assert!(record.tags.is_null());
        assert!(record.reply_to_message_id_hex.is_null());
        assert!(record.reply_preview.is_null());
        assert!(record.media_json.is_null());
        assert!(record.media.is_null());
        assert!(record.agent_text_stream_json.is_null());
        assert!(record.group_system.is_null());
        assert!(record.reactions.by_emoji.is_null());
        assert!(record.invalidation_status.is_null());
        let root = boxed(record);
        unsafe { marmot_timeline_message_record_free(root) };

        let query: MarmotTimelineMessageQuery = TimelineMessageQueryFfi::default().into();
        assert!(query.group_id_hex.is_null());
        assert!(query.search.is_null());
        assert!(!query.has_before);
        assert!(!query.has_after);
        assert!(!query.has_limit);
        let ffi = unsafe { query.to_ffi() }.expect("all-NULL query is valid");
        assert_eq!(ffi.before, None);
        assert_eq!(ffi.limit, None);
        let root = boxed(query);
        unsafe { free_boxed(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }
}
