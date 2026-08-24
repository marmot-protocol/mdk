//! C mirrors of the durable chat-list projection conversions.

use marmot_uniffi::conversions::{
    ChatConversationKindFfi, ChatListAttachmentKindFfi, ChatListAvatarFfi,
    ChatListMessageDeliveryStateFfi, ChatListMessagePreviewFfi, ChatListRowFfi,
    ChatListSubscriptionUpdateFfi, ChatListUpdateTriggerFfi,
};

use super::group::{MarmotDisbandRequest, MarmotGroupLifecycleState, MarmotSelfMembership};
use super::markdown::MarmotMarkdownDocument;
use crate::macros::{c_enum, c_mirror};
use crate::memory::{CFree, free_c_string, free_vec, owned_c_string, owned_vec};

c_mirror! {
    /// Encrypted Blossom avatar reference for a chat row.
    MarmotChatListAvatar from ChatListAvatarFfi {
        str image_hash_hex,
        str image_key_hex,
        str image_nonce_hex,
        str image_upload_key_hex,
        opt_str media_type,
    }
}

c_enum! {
    /// Kind of the last message's attachments.
    MarmotChatListAttachmentKind from ChatListAttachmentKindFfi {
        Photo,
        Video,
        Audio,
        File,
        Mixed,
    }
}

// Derived Default would need a #[default] variant attr the c_enum! spec
// grammar doesn't carry; manual impl is equivalent.
#[allow(clippy::derivable_impls)]
impl Default for MarmotChatListAttachmentKind {
    fn default() -> Self {
        Self::File
    }
}

c_enum! {
    /// Delivery state of the row's latest own message.
    MarmotChatListMessageDeliveryState from ChatListMessageDeliveryStateFfi {
        NotApplicable,
        Pending,
        Delivered,
        Failed,
    }
}

c_enum! {
    /// Coarse conversation classification.
    MarmotChatConversationKind from ChatConversationKindFfi {
        Unknown,
        Direct,
        Group,
    }
}

c_mirror! {
    /// Preview of a chat row's last message.
    MarmotChatListMessagePreview from ChatListMessagePreviewFfi {
        str message_id_hex,
        str sender,
        opt_str sender_display_name,
        str plaintext,
        rec content_tokens: MarmotMarkdownDocument,
        copy kind: u64,
        copy timeline_at: u64,
        copy deleted: bool,
        opt_copy has_attachment_kind/attachment_kind: MarmotChatListAttachmentKind,
        copy attachment_count: u32,
        copy delivery_state: MarmotChatListMessageDeliveryState,
    }
}

c_mirror! {
    /// One durable chat-list row.
    MarmotChatListRow from ChatListRowFfi,
    free marmot_chat_list_row_free,
    list(MarmotChatListRowList, marmot_chat_list_row_list_free) {
        str group_id_hex,
        copy pinned: bool,
        opt_copy has_pinned_position/pinned_position: u32,
        copy archived: bool,
        copy pending_confirmation: bool,
        copy lifecycle_state: MarmotGroupLifecycleState,
        /// Hide/disable the message composer while terminal convergence is
        /// in progress.
        copy disbanding: bool,
        /// This account's durable disband request outcome, if any.
        opt_rec disband_request: MarmotDisbandRequest,
        str title,
        str group_name,
        opt_str avatar_url,
        opt_rec avatar: MarmotChatListAvatar,
        opt_rec last_message: MarmotChatListMessagePreview,
        copy unread_count: u64,
        copy has_unread: bool,
        /// User-created unread reminder independent of unread messages.
        copy manually_marked_unread: bool,
        copy unread_mention_count: u64,
        copy unread_mention: bool,
        opt_str first_unread_message_id_hex,
        opt_str last_read_message_id_hex,
        opt_copy has_last_read_timeline_at/last_read_timeline_at: u64,
        copy conversation_created_at: u64,
        copy activity_sort_at: u64,
        copy updated_at: u64,
        copy self_membership: MarmotSelfMembership,
        copy conversation_kind: MarmotChatConversationKind,
        /// Effective MDK mute state (separate from host notification
        /// modes).
        copy muted: bool,
        /// Absolute Unix epoch milliseconds for a finite mute. Unset is
        /// indefinite when `muted`, unmuted otherwise.
        opt_copy has_muted_until_ms/muted_until_ms: i64,
        /// The local account asked to leave and the request has not
        /// resolved yet. Render as leaving; do not offer Leave again.
        /// Orthogonal to `self_membership`. Always equal to
        /// `has_leave_requested_at_ms`.
        copy leave_request_pending: bool,
        opt_copy has_leave_requested_at_ms/leave_requested_at_ms: u64,
    }
}

c_enum! {
    /// Why a chat-list delta fired.
    MarmotChatListUpdateTrigger from ChatListUpdateTriggerFfi {
        NewGroup,
        NewLastMessage,
        LastMessageDeleted,
        ArchiveChanged,
        PendingConfirmationChanged,
        MembershipChanged,
        UnreadChanged,
        ManualUnreadChanged,
        MuteChanged,
        ConversationKindChanged,
        LatestMessageDeliveryChanged,
        PinOrderChanged,
        SnapshotRefresh,
        Removed,
    }
}

/// One raw chat-list delta: a row upsert, a row removal, or a full
/// snapshot replacement (atomically replace all held rows).
#[repr(C)]
pub enum MarmotChatListSubscriptionUpdate {
    Row {
        trigger: MarmotChatListUpdateTrigger,
        row: MarmotChatListRow,
    },
    RemoveRow {
        trigger: MarmotChatListUpdateTrigger,
        group_id_hex: *mut ::std::ffi::c_char,
    },
    Snapshot {
        trigger: MarmotChatListUpdateTrigger,
        rows: *mut MarmotChatListRow,
        rows_len: usize,
    },
}

impl From<ChatListSubscriptionUpdateFfi> for MarmotChatListSubscriptionUpdate {
    fn from(value: ChatListSubscriptionUpdateFfi) -> Self {
        match value {
            ChatListSubscriptionUpdateFfi::Row { trigger, row } => Self::Row {
                trigger: trigger.into(),
                row: row.into(),
            },
            ChatListSubscriptionUpdateFfi::RemoveRow {
                trigger,
                group_id_hex,
            } => Self::RemoveRow {
                trigger: trigger.into(),
                group_id_hex: owned_c_string(group_id_hex),
            },
            ChatListSubscriptionUpdateFfi::Snapshot { trigger, rows } => {
                let (rows, rows_len) = owned_vec(rows.into_iter().map(Into::into).collect());
                Self::Snapshot {
                    trigger: trigger.into(),
                    rows,
                    rows_len,
                }
            }
        }
    }
}

impl CFree for MarmotChatListSubscriptionUpdate {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            match self {
                Self::Row { row, .. } => row.free_in_place(),
                Self::RemoveRow { group_id_hex, .. } => free_c_string(*group_id_hex),
                Self::Snapshot { rows, rows_len, .. } => free_vec(*rows, *rows_len),
            }
        }
    }
}

/// Free a chat-list delta returned by this library. NULL is a no-op.
///
/// # Safety
/// `update` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_subscription_update_free(
    update: *mut MarmotChatListSubscriptionUpdate,
) {
    crate::memory::free_guard(|| unsafe { crate::memory::free_boxed(update) });
}
