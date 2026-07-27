//! Chat-list avatar, row, message-preview, and subscription-update FFI conversions.

use marmot_app::{ChatListAvatar, ChatListMessagePreview, ChatListRow, RuntimeChatListUpdate};

use super::common::{SelfMembershipFfi, markdown_content_tokens};
use crate::markdown::MarkdownDocumentFfi;

/// Group avatar reference. `image_key_hex` is the symmetric key that decrypts
/// the avatar blob and `image_upload_key_hex` is the Blossom upload secret;
/// the hand-written `Debug` impl below redacts both so a Rust-side `{:?}`
/// never prints key material.
///
/// Host-language stringification is NOT covered: uniffi 0.28 generates plain
/// record types (e.g. Kotlin data classes) whose default `toString` prints
/// all fields, and `#[uniffi::export(Debug)]` on records requires uniffi
/// >= 0.29. Host apps must not log this record until that upgrade lands.
#[derive(Clone, uniffi::Record)]
pub struct ChatListAvatarFfi {
    pub image_hash_hex: String,
    pub image_key_hex: String,
    pub image_nonce_hex: String,
    pub image_upload_key_hex: String,
    pub media_type: Option<String>,
}

impl std::fmt::Debug for ChatListAvatarFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatListAvatarFfi")
            .field("image_hash_hex", &self.image_hash_hex)
            .field("image_key_hex", &"<redacted>")
            .field("image_nonce_hex", &self.image_nonce_hex)
            .field("image_upload_key_hex", &"<redacted>")
            .field("media_type", &self.media_type)
            .finish()
    }
}

impl From<ChatListAvatar> for ChatListAvatarFfi {
    fn from(value: ChatListAvatar) -> Self {
        Self {
            image_hash_hex: value.image_hash_hex,
            image_key_hex: value.image_key_hex,
            image_nonce_hex: value.image_nonce_hex,
            image_upload_key_hex: value.image_upload_key_hex,
            media_type: value.media_type,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ChatListMessagePreviewFfi {
    pub message_id_hex: String,
    pub sender: String,
    pub sender_display_name: Option<String>,
    pub plaintext: String,
    pub content_tokens: MarkdownDocumentFfi,
    pub kind: u64,
    pub timeline_at: u64,
    pub deleted: bool,
}

impl From<ChatListMessagePreview> for ChatListMessagePreviewFfi {
    fn from(value: ChatListMessagePreview) -> Self {
        let content_tokens = markdown_content_tokens(value.kind, &value.plaintext);
        Self {
            message_id_hex: value.message_id_hex,
            sender: value.sender,
            sender_display_name: value.sender_display_name,
            plaintext: value.plaintext,
            content_tokens,
            kind: value.kind,
            timeline_at: value.timeline_at,
            deleted: value.deleted,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ChatListRowFfi {
    pub group_id_hex: String,
    pub archived: bool,
    pub pending_confirmation: bool,
    pub title: String,
    pub group_name: String,
    pub avatar_url: Option<String>,
    pub avatar: Option<ChatListAvatarFfi>,
    pub last_message: Option<ChatListMessagePreviewFfi>,
    pub unread_count: u64,
    pub has_unread: bool,
    pub unread_mention_count: u64,
    pub unread_mention: bool,
    pub first_unread_message_id_hex: Option<String>,
    pub last_read_message_id_hex: Option<String>,
    pub last_read_timeline_at: Option<u64>,
    pub conversation_created_at: u64,
    pub activity_sort_at: u64,
    pub updated_at: u64,
    /// Whether the local account is still a member of this group, and if not,
    /// whether it left voluntarily or was removed.
    pub self_membership: SelfMembershipFfi,
    /// The local account asked to leave this group and the request has not
    /// resolved yet. Render the conversation as leaving, and do not offer Leave
    /// again — see `GroupManagementStateFfi::can_leave`.
    ///
    /// Durable unresolved *intent*, which survives a failed publish and app
    /// termination — so a cold launch can rediscover it. Read this rather than
    /// `self_membership` to decide whether to show a leave in progress.
    ///
    /// This is orthogonal to `self_membership`, not a precursor to it. The two
    /// answer different questions and combine freely:
    ///
    /// | `self_membership` | this flag | meaning |
    /// |---|---|---|
    /// | `Member` | `true`  | leave requested, publish failed or was interrupted |
    /// | `Left`   | `true`  | leave published, still waiting for a member to commit it |
    /// | `Left`   | `false` | leave resolved |
    /// | `Removed`| `false` | removed by someone else |
    ///
    /// `self_membership` is the locally *classified departure* — `Left` is
    /// recorded as soon as the SelfRemove proposal publishes, so it does **not**
    /// imply a commit removed the member, and `Removed` marks an involuntary
    /// removal. This flag is about whether the request is still outstanding.
    ///
    /// Always equal to `leave_requested_at_ms != null`.
    pub leave_request_pending: bool,
    /// When the local account asked to leave, in milliseconds since the Unix
    /// epoch; `null` when no leave is pending.
    pub leave_requested_at_ms: Option<u64>,
}

impl From<ChatListRow> for ChatListRowFfi {
    fn from(value: ChatListRow) -> Self {
        Self {
            group_id_hex: value.group_id_hex,
            archived: value.archived,
            pending_confirmation: value.pending_confirmation,
            title: value.title,
            group_name: value.group_name,
            avatar_url: value.avatar_url,
            avatar: value.avatar.map(Into::into),
            last_message: value.last_message.map(Into::into),
            unread_count: value.unread_count,
            has_unread: value.has_unread,
            unread_mention_count: value.unread_mention_count,
            unread_mention: value.has_unread_mention,
            first_unread_message_id_hex: value.first_unread_message_id_hex,
            last_read_message_id_hex: value.last_read_message_id_hex,
            last_read_timeline_at: value.last_read_timeline_at,
            conversation_created_at: value.conversation_created_at,
            activity_sort_at: value.activity_sort_at,
            updated_at: value.updated_at,
            self_membership: value.self_membership.into(),
            leave_request_pending: value.leave_requested_at_ms.is_some(),
            leave_requested_at_ms: value.leave_requested_at_ms,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, uniffi::Enum)]
pub enum ChatListSubscriptionUpdateFfi {
    Row {
        trigger: ChatListUpdateTriggerFfi,
        row: ChatListRowFfi,
    },
    RemoveRow {
        trigger: ChatListUpdateTriggerFfi,
        group_id_hex: String,
    },
}

impl From<RuntimeChatListUpdate> for ChatListSubscriptionUpdateFfi {
    fn from(value: RuntimeChatListUpdate) -> Self {
        match value {
            RuntimeChatListUpdate::Row { trigger, row } => Self::Row {
                trigger: trigger.into(),
                row: (*row).into(),
            },
            RuntimeChatListUpdate::RemoveRow {
                trigger,
                group_id_hex,
            } => Self::RemoveRow {
                trigger: trigger.into(),
                group_id_hex,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum ChatListUpdateTriggerFfi {
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

impl From<marmot_app::ChatListUpdateTrigger> for ChatListUpdateTriggerFfi {
    fn from(value: marmot_app::ChatListUpdateTrigger) -> Self {
        match value {
            marmot_app::ChatListUpdateTrigger::NewGroup => Self::NewGroup,
            marmot_app::ChatListUpdateTrigger::NewLastMessage => Self::NewLastMessage,
            marmot_app::ChatListUpdateTrigger::LastMessageDeleted => Self::LastMessageDeleted,
            marmot_app::ChatListUpdateTrigger::ArchiveChanged => Self::ArchiveChanged,
            marmot_app::ChatListUpdateTrigger::PendingConfirmationChanged => {
                Self::PendingConfirmationChanged
            }
            marmot_app::ChatListUpdateTrigger::MembershipChanged => Self::MembershipChanged,
            marmot_app::ChatListUpdateTrigger::UnreadChanged => Self::UnreadChanged,
            marmot_app::ChatListUpdateTrigger::SnapshotRefresh => Self::SnapshotRefresh,
            marmot_app::ChatListUpdateTrigger::Removed => Self::Removed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_row() -> ChatListRow {
        ChatListRow {
            group_id_hex: "11".to_owned(),
            archived: false,
            pending_confirmation: false,
            title: "Marmot Lab".to_owned(),
            group_name: "Marmot Lab".to_owned(),
            avatar_url: None,
            avatar: None,
            last_message: None,
            unread_count: 0,
            has_unread: false,
            unread_mention_count: 0,
            has_unread_mention: false,
            first_unread_message_id_hex: None,
            last_read_message_id_hex: None,
            last_read_timeline_at: None,
            conversation_created_at: 100,
            activity_sort_at: 200,
            updated_at: 300,
            self_membership: marmot_app::SelfMembership::Member,
            leave_requested_at_ms: None,
        }
    }

    #[test]
    fn chat_list_row_exports_semantic_timestamps() {
        let ffi = ChatListRowFfi::from(sample_row());

        assert_eq!(ffi.conversation_created_at, 100);
        assert_eq!(ffi.activity_sort_at, 200);
        assert_eq!(ffi.updated_at, 300);
    }

    #[test]
    fn chat_list_row_exports_pending_leave_alongside_active_membership() {
        // The pair must stay consistent: hosts branch on the bool and render the
        // timestamp, so a `true` with no timestamp (or vice versa) would be a
        // contradiction. Also note membership is still `Member` here — that is the
        // whole window this field exists to cover.
        let ffi = ChatListRowFfi::from(ChatListRow {
            leave_requested_at_ms: Some(1_700_000_000_123),
            ..sample_row()
        });

        assert!(ffi.leave_request_pending);
        assert_eq!(ffi.leave_requested_at_ms, Some(1_700_000_000_123));
        assert!(matches!(ffi.self_membership, SelfMembershipFfi::Member));

        let ffi = ChatListRowFfi::from(sample_row());
        assert!(!ffi.leave_request_pending);
        assert_eq!(ffi.leave_requested_at_ms, None);
    }

    #[test]
    fn chat_list_avatar_debug_redacts_key_material() {
        let key_hex = "aa".repeat(32);
        let upload_key_hex = "bb".repeat(32);
        let avatar = ChatListAvatarFfi {
            image_hash_hex: "cc".repeat(32),
            image_key_hex: key_hex.clone(),
            image_nonce_hex: "dd".repeat(12),
            image_upload_key_hex: upload_key_hex.clone(),
            media_type: Some("image/png".to_owned()),
        };
        let rendered = format!("{avatar:?}");
        assert!(!rendered.contains(&key_hex), "{rendered}");
        assert!(!rendered.contains(&upload_key_hex), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        // Non-secret fields stay visible for diagnostics.
        assert!(rendered.contains(&"cc".repeat(32)), "{rendered}");
    }
}
