//! C mirrors of the durable chat-list projection conversions.

use marmot_uniffi::conversions::{
    ChatConversationKindFfi, ChatListAttachmentKindFfi, ChatListAvatarFfi,
    ChatListMessageDeliveryStateFfi, ChatListMessagePreviewFfi, ChatListRowFfi,
    ChatListSubscriptionUpdateFfi, ChatListUpdateTriggerFfi, ChatNotificationSettingsFfi,
    ChatPinStateFfi, DirectPeerPresentationFfi, DirectPeerPresentationStateFfi,
    ExistingDirectConversationFfi,
};

use super::group::{MarmotDisbandRequest, MarmotGroupLifecycleState, MarmotSelfMembership};
use super::markdown::MarmotMarkdownDocument;
use crate::macros::{c_enum, c_mirror};
use crate::memory::{CFree, free_c_string, free_vec, owned_c_string, owned_vec};

c_mirror! {
    /// An existing one-to-one conversation with a peer. `reusable` is
    /// the only field a caller needs to decide whether to open this
    /// group or create a new one; the rest explain why.
    MarmotExistingDirectConversation from ExistingDirectConversationFfi,
    free marmot_existing_direct_conversation_free {
        str group_id_hex,
        copy reusable: bool,
        copy lifecycle_state: MarmotGroupLifecycleState,
        copy self_membership: MarmotSelfMembership,
        copy pending_confirmation: bool,
        copy leave_request_pending: bool,
        copy disbanding: bool,
        copy archived: bool,
        copy activity_sort_at: u64,
    }
}

c_mirror! {
    /// The account's pinned chats, in display order.
    MarmotChatPinState from ChatPinStateFfi,
    free marmot_chat_pin_state_free {
        /// Group ids in normalized zero-based display order.
        str_vec ordered_group_ids/ordered_group_ids_len,
    }
}

c_mirror! {
    /// One conversation's local mute state.
    MarmotChatNotificationSettings from ChatNotificationSettingsFfi,
    free marmot_chat_notification_settings_free {
        str account_ref,
        str account_id_hex,
        str group_id_hex,
        copy muted: bool,
        /// Timed mute expiry; unset means muted indefinitely.
        opt_copy has_muted_until_ms/muted_until_ms: i64,
        copy updated_at_ms: i64,
    }
}

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

c_enum! {
    /// Freshness/provenance of Direct peer display metadata.
    MarmotDirectPeerPresentationState from DirectPeerPresentationStateFfi {
        Absent,
        Current,
        LastKnown,
        Invalidated,
    }
}

c_mirror! {
    /// Versioned, display-only metadata for the exact peer of one Direct chat.
    MarmotDirectPeerPresentation from DirectPeerPresentationFfi {
        copy schema_version: u16,
        opt_str peer_account_id_hex,
        opt_str display_name,
        opt_str avatar_url,
        opt_copy has_profile_created_at/profile_created_at: u64,
        copy state: MarmotDirectPeerPresentationState,
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
        /// Appended to preserve the offsets of every pre-existing field in
        /// this stable C mirror.
        opt_rec direct_peer_presentation: MarmotDirectPeerPresentation,
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
        DirectPeerPresentationChanged,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::boxed;

    #[test]
    fn pin_state_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotChatPinState = ChatPinStateFfi {
            ordered_group_ids: vec!["aabb".into(), "ccdd".into()],
        }
        .into();
        assert_eq!(mirror.ordered_group_ids_len, 2);

        unsafe { marmot_chat_pin_state_free(boxed(mirror)) };
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn notification_settings_carry_the_timed_mute_flag() {
        let _guard = crate::memory::audit::test_lock();

        let indefinite: MarmotChatNotificationSettings = ChatNotificationSettingsFfi {
            account_ref: "npub1".into(),
            account_id_hex: "00".into(),
            group_id_hex: "aabb".into(),
            muted: true,
            muted_until_ms: None,
            updated_at_ms: 7,
        }
        .into();
        assert!(indefinite.muted && !indefinite.has_muted_until_ms);
        assert_eq!(indefinite.muted_until_ms, 0);
        unsafe { marmot_chat_notification_settings_free(boxed(indefinite)) };

        let timed: MarmotChatNotificationSettings = ChatNotificationSettingsFfi {
            account_ref: "npub1".into(),
            account_id_hex: "00".into(),
            group_id_hex: "aabb".into(),
            muted: true,
            muted_until_ms: Some(1_700_000_000_000),
            updated_at_ms: 7,
        }
        .into();
        assert!(timed.has_muted_until_ms);
        assert_eq!(timed.muted_until_ms, 1_700_000_000_000);
        unsafe { marmot_chat_notification_settings_free(boxed(timed)) };
    }

    #[test]
    fn direct_peer_presentation_deep_free_releases_owned_strings() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mut mirror: MarmotDirectPeerPresentation = DirectPeerPresentationFfi {
            schema_version: 1,
            peer_account_id_hex: Some("bb".repeat(32)),
            display_name: Some("Remote Otter".to_owned()),
            avatar_url: Some("https://cdn.example.com/remote.png".to_owned()),
            profile_created_at: Some(42),
            state: DirectPeerPresentationStateFfi::Current,
        }
        .into();
        assert!(!mirror.peer_account_id_hex.is_null());
        assert!(mirror.has_profile_created_at);
        assert_eq!(mirror.profile_created_at, 42);

        unsafe { mirror.free_in_place() };
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }
}
