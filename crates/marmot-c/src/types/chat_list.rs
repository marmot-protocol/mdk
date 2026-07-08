//! C mirrors of the chat-list conversions (`marmot-uniffi/src/conversions/chat_list.rs`).
//!
//! All chat-list types are outputs only: rows come back from
//! `marmot_chat_list` / read-state commands and from the chat-list
//! subscription; nothing here is read back from caller memory.

use std::ffi::c_char;

use marmot_uniffi::conversions::{
    ChatListAvatarFfi, ChatListMessagePreviewFfi, ChatListRowFfi, ChatListSubscriptionUpdateFfi,
    ChatListUpdateTriggerFfi,
};

use crate::memory::{
    CFree, boxed_opt, free_boxed, free_c_string, free_vec, owned_c_string, owned_opt_c_string,
    owned_vec,
};
use crate::types::common::MarmotSelfMembership;
use crate::types::markdown::MarmotMarkdownDocument;

/// Group avatar reference. `image_key_hex` is the symmetric key that decrypts
/// the avatar blob and `image_upload_key_hex` is the Blossom upload secret —
/// both are key material. Host apps must not log or otherwise stringify this
/// struct; there is no redaction at the C ABI.
#[repr(C)]
pub struct MarmotChatListAvatar {
    pub image_hash_hex: *mut c_char,
    /// Symmetric key that decrypts the avatar blob. Key material — do not log.
    pub image_key_hex: *mut c_char,
    pub image_nonce_hex: *mut c_char,
    /// Blossom upload secret. Key material — do not log.
    pub image_upload_key_hex: *mut c_char,
    /// MIME type of the avatar blob, when known. Nullable.
    pub media_type: *mut c_char,
}

impl From<ChatListAvatarFfi> for MarmotChatListAvatar {
    fn from(value: ChatListAvatarFfi) -> Self {
        Self {
            image_hash_hex: owned_c_string(value.image_hash_hex),
            image_key_hex: owned_c_string(value.image_key_hex),
            image_nonce_hex: owned_c_string(value.image_nonce_hex),
            image_upload_key_hex: owned_c_string(value.image_upload_key_hex),
            media_type: owned_opt_c_string(value.media_type),
        }
    }
}

impl CFree for MarmotChatListAvatar {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.image_hash_hex);
            free_c_string(self.image_key_hex);
            free_c_string(self.image_nonce_hex);
            free_c_string(self.image_upload_key_hex);
            free_c_string(self.media_type);
        }
    }
}

/// Preview of the most recent message in a conversation, shown on the
/// chat-list row.
#[repr(C)]
pub struct MarmotChatListMessagePreview {
    pub message_id_hex: *mut c_char,
    pub sender: *mut c_char,
    /// Resolved display name of the sender, when known. Nullable.
    pub sender_display_name: *mut c_char,
    pub plaintext: *mut c_char,
    /// Parsed Markdown display tokens for the preview text. Owned by this
    /// struct and freed with it — never individually.
    pub content_tokens: MarmotMarkdownDocument,
    /// Inner Marmot app event kind of the previewed message.
    pub kind: u64,
    pub timeline_at: u64,
    pub deleted: bool,
}

impl From<ChatListMessagePreviewFfi> for MarmotChatListMessagePreview {
    fn from(value: ChatListMessagePreviewFfi) -> Self {
        Self {
            message_id_hex: owned_c_string(value.message_id_hex),
            sender: owned_c_string(value.sender),
            sender_display_name: owned_opt_c_string(value.sender_display_name),
            plaintext: owned_c_string(value.plaintext),
            content_tokens: value.content_tokens.into(),
            kind: value.kind,
            timeline_at: value.timeline_at,
            deleted: value.deleted,
        }
    }
}

impl CFree for MarmotChatListMessagePreview {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.message_id_hex);
            free_c_string(self.sender);
            free_c_string(self.sender_display_name);
            free_c_string(self.plaintext);
            self.content_tokens.free_in_place();
        }
    }
}

/// One conversation row on the chat list: identity, display fields, unread
/// counters, and the latest message preview.
#[repr(C)]
pub struct MarmotChatListRow {
    pub group_id_hex: *mut c_char,
    pub archived: bool,
    pub pending_confirmation: bool,
    pub title: *mut c_char,
    pub group_name: *mut c_char,
    /// Plain avatar URL, when set. Nullable.
    pub avatar_url: *mut c_char,
    /// Encrypted group avatar reference, when set. Nullable; owned by the row.
    pub avatar: *mut MarmotChatListAvatar,
    /// Most recent message preview, when the group has one. Nullable; owned
    /// by the row.
    pub last_message: *mut MarmotChatListMessagePreview,
    pub unread_count: u64,
    pub has_unread: bool,
    pub unread_mention_count: u64,
    pub unread_mention: bool,
    /// First unread message id, when known. Nullable.
    pub first_unread_message_id_hex: *mut c_char,
    /// Last read message id, when known. Nullable.
    pub last_read_message_id_hex: *mut c_char,
    /// `last_read_timeline_at` is only meaningful when
    /// `has_last_read_timeline_at` is true; otherwise it is zero.
    pub has_last_read_timeline_at: bool,
    pub last_read_timeline_at: u64,
    pub updated_at: u64,
    /// Whether the local account is still a member of this group, and if not,
    /// whether it left voluntarily or was removed.
    pub self_membership: MarmotSelfMembership,
}

impl From<ChatListRowFfi> for MarmotChatListRow {
    fn from(value: ChatListRowFfi) -> Self {
        Self {
            group_id_hex: owned_c_string(value.group_id_hex),
            archived: value.archived,
            pending_confirmation: value.pending_confirmation,
            title: owned_c_string(value.title),
            group_name: owned_c_string(value.group_name),
            avatar_url: owned_opt_c_string(value.avatar_url),
            avatar: boxed_opt(value.avatar.map(Into::into)),
            last_message: boxed_opt(value.last_message.map(Into::into)),
            unread_count: value.unread_count,
            has_unread: value.has_unread,
            unread_mention_count: value.unread_mention_count,
            unread_mention: value.unread_mention,
            first_unread_message_id_hex: owned_opt_c_string(value.first_unread_message_id_hex),
            last_read_message_id_hex: owned_opt_c_string(value.last_read_message_id_hex),
            has_last_read_timeline_at: value.last_read_timeline_at.is_some(),
            last_read_timeline_at: value.last_read_timeline_at.unwrap_or(0),
            updated_at: value.updated_at,
            self_membership: value.self_membership.into(),
        }
    }
}

impl CFree for MarmotChatListRow {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.group_id_hex);
            free_c_string(self.title);
            free_c_string(self.group_name);
            free_c_string(self.avatar_url);
            free_boxed(self.avatar);
            free_boxed(self.last_message);
            free_c_string(self.first_unread_message_id_hex);
            free_c_string(self.last_read_message_id_hex);
        }
    }
}

/// Free a single chat-list row root (e.g. from
/// `marmot_initialize_chat_read_state` or `marmot_mark_timeline_message_read`).
/// Never call on rows embedded inside a list or subscription update. NULL is
/// a no-op.
///
/// # Safety
/// `row` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_row_free(row: *mut MarmotChatListRow) {
    crate::memory::free_guard(|| unsafe { free_boxed(row) });
}

/// Owned list of chat-list rows (`marmot_chat_list` and the chat-list
/// subscription snapshot).
#[repr(C)]
pub struct MarmotChatListRowList {
    pub items: *mut MarmotChatListRow,
    pub len: usize,
}

impl From<Vec<ChatListRowFfi>> for MarmotChatListRowList {
    fn from(value: Vec<ChatListRowFfi>) -> Self {
        let (items, len) = owned_vec(value.into_iter().map(Into::into).collect());
        Self { items, len }
    }
}

impl CFree for MarmotChatListRowList {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.items, self.len) };
    }
}

/// Free a chat-list row list returned by this library. NULL is a no-op.
///
/// # Safety
/// `list` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_row_list_free(list: *mut MarmotChatListRowList) {
    crate::memory::free_guard(|| unsafe { free_boxed(list) });
}

/// Why a chat-list subscription update fired.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarmotChatListUpdateTrigger {
    NewGroup,
    NewLastMessage,
    LastMessageDeleted,
    ArchiveChanged,
    PendingConfirmationChanged,
    MembershipChanged,
    UnreadChanged,
    SnapshotRefresh,
    Removed,
}

impl From<ChatListUpdateTriggerFfi> for MarmotChatListUpdateTrigger {
    fn from(value: ChatListUpdateTriggerFfi) -> Self {
        match value {
            ChatListUpdateTriggerFfi::NewGroup => Self::NewGroup,
            ChatListUpdateTriggerFfi::NewLastMessage => Self::NewLastMessage,
            ChatListUpdateTriggerFfi::LastMessageDeleted => Self::LastMessageDeleted,
            ChatListUpdateTriggerFfi::ArchiveChanged => Self::ArchiveChanged,
            ChatListUpdateTriggerFfi::PendingConfirmationChanged => {
                Self::PendingConfirmationChanged
            }
            ChatListUpdateTriggerFfi::MembershipChanged => Self::MembershipChanged,
            ChatListUpdateTriggerFfi::UnreadChanged => Self::UnreadChanged,
            ChatListUpdateTriggerFfi::SnapshotRefresh => Self::SnapshotRefresh,
            ChatListUpdateTriggerFfi::Removed => Self::Removed,
        }
    }
}

impl CFree for MarmotChatListUpdateTrigger {
    unsafe fn free_in_place(&mut self) {}
}

/// One incremental chat-list subscription update: either a fresh row to
/// upsert or a group id whose row should be removed.
#[repr(C)]
pub enum MarmotChatListSubscriptionUpdate {
    /// Upsert this row into the chat list.
    Row {
        trigger: MarmotChatListUpdateTrigger,
        row: MarmotChatListRow,
    },
    /// Remove the row for this group from the chat list.
    RemoveRow {
        trigger: MarmotChatListUpdateTrigger,
        group_id_hex: *mut c_char,
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
        }
    }
}

impl CFree for MarmotChatListSubscriptionUpdate {
    unsafe fn free_in_place(&mut self) {
        match self {
            Self::Row { row, .. } => unsafe { row.free_in_place() },
            Self::RemoveRow { group_id_hex, .. } => unsafe { free_c_string(*group_id_hex) },
        }
    }
}

/// Free a chat-list subscription update root (`*_next_update`). NULL is a
/// no-op.
///
/// # Safety
/// `update` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_list_subscription_update_free(
    update: *mut MarmotChatListSubscriptionUpdate,
) {
    crate::memory::free_guard(|| unsafe { free_boxed(update) });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::boxed;
    use marmot_uniffi::conversions::SelfMembershipFfi;
    use marmot_uniffi::{MarkdownBlockFfi, MarkdownDocumentFfi, MarkdownInlineFfi};

    fn c_str_eq(ptr: *mut c_char, expected: &str) -> bool {
        assert!(!ptr.is_null());
        unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_str()
            .expect("valid UTF-8")
            == expected
    }

    fn sample_document() -> MarkdownDocumentFfi {
        MarkdownDocumentFfi {
            blocks: vec![MarkdownBlockFfi::Paragraph {
                inlines: vec![MarkdownInlineFfi::Text {
                    content: "see you at the burrow".into(),
                }],
            }],
            truncated: false,
        }
    }

    fn sample_preview() -> ChatListMessagePreviewFfi {
        ChatListMessagePreviewFfi {
            message_id_hex: "ee".repeat(32),
            sender: "ff".repeat(32),
            sender_display_name: Some("Marmy".into()),
            plaintext: "see you at the burrow".into(),
            content_tokens: sample_document(),
            kind: 9,
            timeline_at: 1_700_000_100,
            deleted: false,
        }
    }

    fn sample_row() -> ChatListRowFfi {
        ChatListRowFfi {
            group_id_hex: "aa".repeat(16),
            archived: false,
            pending_confirmation: true,
            title: "Burrow crew".into(),
            group_name: "burrow-crew".into(),
            avatar_url: Some("https://example.com/a.png".into()),
            avatar: Some(ChatListAvatarFfi {
                image_hash_hex: "cc".repeat(32),
                image_key_hex: "11".repeat(32),
                image_nonce_hex: "22".repeat(12),
                image_upload_key_hex: "33".repeat(32),
                media_type: Some("image/png".into()),
            }),
            last_message: Some(sample_preview()),
            unread_count: 4,
            has_unread: true,
            unread_mention_count: 1,
            unread_mention: true,
            first_unread_message_id_hex: Some("44".repeat(32)),
            last_read_message_id_hex: Some("55".repeat(32)),
            last_read_timeline_at: Some(1_700_000_000),
            updated_at: 1_700_000_200,
            self_membership: SelfMembershipFfi::Member,
        }
    }

    #[test]
    fn chat_list_row_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotChatListRow = sample_row().into();
        assert!(c_str_eq(mirror.group_id_hex, &"aa".repeat(16)));
        assert!(!mirror.archived);
        assert!(mirror.pending_confirmation);
        assert!(c_str_eq(mirror.title, "Burrow crew"));
        assert!(c_str_eq(mirror.group_name, "burrow-crew"));
        assert!(c_str_eq(mirror.avatar_url, "https://example.com/a.png"));

        assert!(!mirror.avatar.is_null());
        let avatar = unsafe { &*mirror.avatar };
        assert!(c_str_eq(avatar.image_hash_hex, &"cc".repeat(32)));
        assert!(c_str_eq(avatar.image_key_hex, &"11".repeat(32)));
        assert!(c_str_eq(avatar.image_nonce_hex, &"22".repeat(12)));
        assert!(c_str_eq(avatar.image_upload_key_hex, &"33".repeat(32)));
        assert!(c_str_eq(avatar.media_type, "image/png"));

        assert!(!mirror.last_message.is_null());
        let preview = unsafe { &*mirror.last_message };
        assert!(c_str_eq(preview.message_id_hex, &"ee".repeat(32)));
        assert!(c_str_eq(preview.sender, &"ff".repeat(32)));
        assert!(c_str_eq(preview.sender_display_name, "Marmy"));
        assert!(c_str_eq(preview.plaintext, "see you at the burrow"));
        assert_eq!(preview.content_tokens.blocks_len, 1);
        assert!(!preview.content_tokens.blocks.is_null());
        assert_eq!(preview.kind, 9);
        assert_eq!(preview.timeline_at, 1_700_000_100);
        assert!(!preview.deleted);

        assert_eq!(mirror.unread_count, 4);
        assert!(mirror.has_unread);
        assert_eq!(mirror.unread_mention_count, 1);
        assert!(mirror.unread_mention);
        assert!(c_str_eq(
            mirror.first_unread_message_id_hex,
            &"44".repeat(32)
        ));
        assert!(c_str_eq(mirror.last_read_message_id_hex, &"55".repeat(32)));
        assert!(mirror.has_last_read_timeline_at);
        assert_eq!(mirror.last_read_timeline_at, 1_700_000_000);
        assert_eq!(mirror.updated_at, 1_700_000_200);
        assert_eq!(mirror.self_membership, MarmotSelfMembership::Member);

        let root = boxed(mirror);
        unsafe { marmot_chat_list_row_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn chat_list_row_list_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let list: MarmotChatListRowList = vec![sample_row(), sample_row()].into();
        assert_eq!(list.len, 2);
        assert!(!list.items.is_null());
        let first = unsafe { &*list.items };
        assert!(c_str_eq(first.title, "Burrow crew"));
        let root = boxed(list);
        unsafe { marmot_chat_list_row_list_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn subscription_update_row_variant_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotChatListSubscriptionUpdate = ChatListSubscriptionUpdateFfi::Row {
            trigger: ChatListUpdateTriggerFfi::NewLastMessage,
            row: sample_row(),
        }
        .into();
        let MarmotChatListSubscriptionUpdate::Row { trigger, row } = &mirror else {
            panic!("expected row variant");
        };
        assert_eq!(*trigger, MarmotChatListUpdateTrigger::NewLastMessage);
        assert!(c_str_eq(row.group_id_hex, &"aa".repeat(16)));
        assert!(!row.last_message.is_null());

        let root = boxed(mirror);
        unsafe { marmot_chat_list_subscription_update_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn subscription_update_remove_row_variant_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotChatListSubscriptionUpdate = ChatListSubscriptionUpdateFfi::RemoveRow {
            trigger: ChatListUpdateTriggerFfi::Removed,
            group_id_hex: "bb".repeat(16),
        }
        .into();
        let MarmotChatListSubscriptionUpdate::RemoveRow {
            trigger,
            group_id_hex,
        } = &mirror
        else {
            panic!("expected remove-row variant");
        };
        assert_eq!(*trigger, MarmotChatListUpdateTrigger::Removed);
        assert!(c_str_eq(*group_id_hex, &"bb".repeat(16)));

        let root = boxed(mirror);
        unsafe { marmot_chat_list_subscription_update_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn update_trigger_maps_all_variants() {
        let _guard = crate::memory::audit::test_lock();
        let cases = [
            (
                ChatListUpdateTriggerFfi::NewGroup,
                MarmotChatListUpdateTrigger::NewGroup,
            ),
            (
                ChatListUpdateTriggerFfi::NewLastMessage,
                MarmotChatListUpdateTrigger::NewLastMessage,
            ),
            (
                ChatListUpdateTriggerFfi::LastMessageDeleted,
                MarmotChatListUpdateTrigger::LastMessageDeleted,
            ),
            (
                ChatListUpdateTriggerFfi::ArchiveChanged,
                MarmotChatListUpdateTrigger::ArchiveChanged,
            ),
            (
                ChatListUpdateTriggerFfi::PendingConfirmationChanged,
                MarmotChatListUpdateTrigger::PendingConfirmationChanged,
            ),
            (
                ChatListUpdateTriggerFfi::MembershipChanged,
                MarmotChatListUpdateTrigger::MembershipChanged,
            ),
            (
                ChatListUpdateTriggerFfi::UnreadChanged,
                MarmotChatListUpdateTrigger::UnreadChanged,
            ),
            (
                ChatListUpdateTriggerFfi::SnapshotRefresh,
                MarmotChatListUpdateTrigger::SnapshotRefresh,
            ),
            (
                ChatListUpdateTriggerFfi::Removed,
                MarmotChatListUpdateTrigger::Removed,
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(MarmotChatListUpdateTrigger::from(input), expected);
        }
    }

    #[test]
    fn empty_lists_and_none_fields_convert_to_null() {
        // Allocates, so it holds the global audit lock like every other test
        // here (the process-global counter is shared across modules).
        let _guard = crate::memory::audit::test_lock();

        let list: MarmotChatListRowList = Vec::<ChatListRowFfi>::new().into();
        assert!(list.items.is_null());
        assert_eq!(list.len, 0);
        let root = boxed(list);
        unsafe { marmot_chat_list_row_list_free(root) };

        let mut bare = sample_row();
        bare.avatar_url = None;
        bare.avatar = None;
        bare.last_message = None;
        bare.first_unread_message_id_hex = None;
        bare.last_read_message_id_hex = None;
        bare.last_read_timeline_at = None;
        let mirror: MarmotChatListRow = bare.into();
        assert!(mirror.avatar_url.is_null());
        assert!(mirror.avatar.is_null());
        assert!(mirror.last_message.is_null());
        assert!(mirror.first_unread_message_id_hex.is_null());
        assert!(mirror.last_read_message_id_hex.is_null());
        assert!(!mirror.has_last_read_timeline_at);
        assert_eq!(mirror.last_read_timeline_at, 0);
        let root = boxed(mirror);
        unsafe { marmot_chat_list_row_free(root) };

        let preview: MarmotChatListMessagePreview = ChatListMessagePreviewFfi {
            sender_display_name: None,
            ..sample_preview()
        }
        .into();
        assert!(preview.sender_display_name.is_null());
        let mut preview = preview;
        unsafe { preview.free_in_place() };
    }
}
