//! Chat-list avatar, row, message-preview, and subscription-update FFI conversions.

use marmot_app::{ChatListAvatar, ChatListMessagePreview, ChatListRow, RuntimeChatListUpdate};

use super::common::markdown_content_tokens;
use crate::markdown::MarkdownDocumentFfi;

#[derive(Clone, Debug, uniffi::Record)]
pub struct ChatListAvatarFfi {
    pub image_hash_hex: String,
    pub image_key_hex: String,
    pub image_nonce_hex: String,
    pub image_upload_key_hex: String,
    pub media_type: Option<String>,
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
    pub updated_at: u64,
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
            updated_at: value.updated_at,
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
