//! Chat-list avatar, row, message-preview, and subscription-update FFI conversions.

use marmot_app::{
    AppDisbandRequest, ChatConversationKind, ChatListAttachmentKind, ChatListAvatar,
    ChatListMessageDeliveryState, ChatListMessagePreview, ChatListRow, ChatNotificationSettings,
    ChatPinState, DirectPeerPresentation, DirectPeerPresentationState, ExistingDirectConversation,
    RuntimeChatListUpdate,
};

use super::common::{SelfMembershipFfi, markdown_content_tokens};
use super::group::GroupLifecycleStateFfi;
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
    pub attachment_kind: Option<ChatListAttachmentKindFfi>,
    pub attachment_count: u32,
    pub delivery_state: ChatListMessageDeliveryStateFfi,
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum ChatListAttachmentKindFfi {
    Photo,
    Video,
    Audio,
    File,
    Mixed,
}

impl From<ChatListAttachmentKind> for ChatListAttachmentKindFfi {
    fn from(value: ChatListAttachmentKind) -> Self {
        match value {
            ChatListAttachmentKind::Photo => Self::Photo,
            ChatListAttachmentKind::Video => Self::Video,
            ChatListAttachmentKind::Audio => Self::Audio,
            ChatListAttachmentKind::File => Self::File,
            ChatListAttachmentKind::Mixed => Self::Mixed,
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum ChatListMessageDeliveryStateFfi {
    NotApplicable,
    Pending,
    Delivered,
    Failed,
}

impl From<ChatListMessageDeliveryState> for ChatListMessageDeliveryStateFfi {
    fn from(value: ChatListMessageDeliveryState) -> Self {
        match value {
            ChatListMessageDeliveryState::NotApplicable => Self::NotApplicable,
            ChatListMessageDeliveryState::Pending => Self::Pending,
            ChatListMessageDeliveryState::Delivered => Self::Delivered,
            ChatListMessageDeliveryState::Failed => Self::Failed,
        }
    }
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
            attachment_kind: value.attachment_kind.map(Into::into),
            attachment_count: value.attachment_count,
            delivery_state: value.delivery_state.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum ChatConversationKindFfi {
    Unknown,
    Direct,
    Group,
}

impl From<ChatConversationKind> for ChatConversationKindFfi {
    fn from(value: ChatConversationKind) -> Self {
        match value {
            ChatConversationKind::Unknown => Self::Unknown,
            ChatConversationKind::Direct => Self::Direct,
            ChatConversationKind::Group => Self::Group,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum DirectPeerPresentationStateFfi {
    Absent,
    Current,
    LastKnown,
    Invalidated,
}

impl From<DirectPeerPresentationState> for DirectPeerPresentationStateFfi {
    fn from(value: DirectPeerPresentationState) -> Self {
        match value {
            DirectPeerPresentationState::Absent => Self::Absent,
            DirectPeerPresentationState::Current => Self::Current,
            DirectPeerPresentationState::LastKnown => Self::LastKnown,
            DirectPeerPresentationState::Invalidated => Self::Invalidated,
        }
    }
}

/// Versioned, display-only metadata for the exact peer of one Direct chat.
/// Membership decisions must continue to use MDK's authoritative group state.
#[derive(Clone, uniffi::Record)]
pub struct DirectPeerPresentationFfi {
    pub schema_version: u16,
    pub peer_account_id_hex: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub profile_created_at: Option<u64>,
    pub state: DirectPeerPresentationStateFfi,
}

impl std::fmt::Debug for DirectPeerPresentationFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectPeerPresentationFfi")
            .field("schema_version", &self.schema_version)
            .field(
                "peer_account_id_hex",
                &self.peer_account_id_hex.as_ref().map(|_| "<redacted>"),
            )
            .field("has_display_name", &self.display_name.is_some())
            .field("has_avatar_url", &self.avatar_url.is_some())
            .field("has_profile_created_at", &self.profile_created_at.is_some())
            .field("state", &self.state)
            .finish()
    }
}

impl From<DirectPeerPresentation> for DirectPeerPresentationFfi {
    fn from(value: DirectPeerPresentation) -> Self {
        Self {
            schema_version: value.schema_version,
            peer_account_id_hex: value.peer_account_id_hex,
            display_name: value.display_name,
            avatar_url: value.avatar_url,
            profile_created_at: value.profile_created_at,
            state: value.state.into(),
        }
    }
}

/// Authoritative reuse decision for one existing direct conversation.
///
/// Returned by [`crate::Marmot::existing_direct_conversation`]. `reusable` is
/// true only when MDK policy says this group can be opened instead of creating
/// another direct conversation with the same peer.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ExistingDirectConversationFfi {
    pub group_id_hex: String,
    pub reusable: bool,
    pub lifecycle_state: GroupLifecycleStateFfi,
    pub self_membership: SelfMembershipFfi,
    pub pending_confirmation: bool,
    pub leave_request_pending: bool,
    pub disbanding: bool,
    pub archived: bool,
    pub activity_sort_at: u64,
}

impl From<ExistingDirectConversation> for ExistingDirectConversationFfi {
    fn from(value: ExistingDirectConversation) -> Self {
        Self {
            group_id_hex: value.group_id_hex,
            reusable: value.reusable,
            lifecycle_state: value.lifecycle_state.into(),
            self_membership: value.self_membership.into(),
            pending_confirmation: value.pending_confirmation,
            leave_request_pending: value.leave_request_pending,
            disbanding: value.disbanding,
            archived: value.archived,
            activity_sort_at: value.activity_sort_at,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ChatListRowFfi {
    pub group_id_hex: String,
    pub pinned: bool,
    pub pinned_position: Option<u32>,
    pub archived: bool,
    pub pending_confirmation: bool,
    pub lifecycle_state: GroupLifecycleStateFfi,
    /// Hide/disable the message composer while terminal convergence is in
    /// progress. This also covers another admin's inbound candidate.
    pub disbanding: bool,
    /// This account's durable request outcome, if any.
    pub disband_request: Option<super::group::DisbandRequestFfi>,
    pub title: String,
    pub group_name: String,
    pub avatar_url: Option<String>,
    pub avatar: Option<ChatListAvatarFfi>,
    #[uniffi(default = None)]
    pub direct_peer_presentation: Option<DirectPeerPresentationFfi>,
    pub last_message: Option<ChatListMessagePreviewFfi>,
    pub unread_count: u64,
    pub has_unread: bool,
    /// User-created unread reminder independent of unread incoming messages.
    pub manually_marked_unread: bool,
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
    pub conversation_kind: ChatConversationKindFfi,
    /// Effective MDK mute state. This is separate from host notification modes
    /// such as all/mentions/nothing.
    pub muted: bool,
    /// Absolute Unix epoch milliseconds for a finite mute. `None` is
    /// indefinite when `muted` is true and unmuted when it is false.
    pub muted_until_ms: Option<i64>,
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
            pinned: value.pinned,
            pinned_position: value.pinned_position,
            archived: value.archived,
            pending_confirmation: value.pending_confirmation,
            lifecycle_state: value.lifecycle_state.into(),
            disbanding: value.disbanding,
            disband_request: value
                .disband_request
                .map(AppDisbandRequest::from)
                .map(Into::into),
            title: value.title,
            group_name: value.group_name,
            avatar_url: value.avatar_url,
            avatar: value.avatar.map(Into::into),
            direct_peer_presentation: value.direct_peer_presentation.map(Into::into),
            last_message: value.last_message.map(Into::into),
            unread_count: value.unread_count,
            has_unread: value.has_unread,
            manually_marked_unread: value.manually_marked_unread,
            unread_mention_count: value.unread_mention_count,
            unread_mention: value.has_unread_mention,
            first_unread_message_id_hex: value.first_unread_message_id_hex,
            last_read_message_id_hex: value.last_read_message_id_hex,
            last_read_timeline_at: value.last_read_timeline_at,
            conversation_created_at: value.conversation_created_at,
            activity_sort_at: value.activity_sort_at,
            updated_at: value.updated_at,
            self_membership: value.self_membership.into(),
            conversation_kind: value.conversation_kind.into(),
            muted: value.muted,
            muted_until_ms: value.muted_until_ms,
            leave_request_pending: value.leave_requested_at_ms.is_some(),
            leave_requested_at_ms: value.leave_requested_at_ms,
        }
    }
}

/// Authoritative device-local order of every currently pinned chat.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ChatPinStateFfi {
    /// Group ids in normalized zero-based display order.
    pub ordered_group_ids: Vec<String>,
}

impl From<ChatPinState> for ChatPinStateFfi {
    fn from(value: ChatPinState) -> Self {
        Self {
            ordered_group_ids: value.ordered_group_ids,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ChatNotificationSettingsFfi {
    pub account_ref: String,
    pub account_id_hex: String,
    pub group_id_hex: String,
    pub muted: bool,
    pub muted_until_ms: Option<i64>,
    pub updated_at_ms: i64,
}

impl From<ChatNotificationSettings> for ChatNotificationSettingsFfi {
    fn from(value: ChatNotificationSettings) -> Self {
        Self {
            account_ref: value.account_ref,
            account_id_hex: value.account_id_hex,
            group_id_hex: value.group_id_hex,
            muted: value.muted,
            // Normalize the storage layer's unmuted sentinel. `muted`
            // disambiguates unmuted from indefinite at the FFI boundary.
            muted_until_ms: value.muted.then_some(value.muted_until_ms).flatten(),
            updated_at_ms: value.updated_at_ms,
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
    /// Full replacement for the subscribed visible chat list.
    ///
    /// Swift and Kotlin hosts must atomically replace their locally held rows
    /// with `rows` and drop any prior row absent from this value.
    Snapshot {
        trigger: ChatListUpdateTriggerFfi,
        rows: Vec<ChatListRowFfi>,
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
            RuntimeChatListUpdate::Snapshot { trigger, rows } => Self::Snapshot {
                trigger: trigger.into(),
                rows: rows.into_iter().map(Into::into).collect(),
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
    ManualUnreadChanged,
    MuteChanged,
    ConversationKindChanged,
    LatestMessageDeliveryChanged,
    PinOrderChanged,
    SnapshotRefresh,
    Removed,
    DirectPeerPresentationChanged,
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
            marmot_app::ChatListUpdateTrigger::ManualUnreadChanged => Self::ManualUnreadChanged,
            marmot_app::ChatListUpdateTrigger::MuteChanged => Self::MuteChanged,
            marmot_app::ChatListUpdateTrigger::ConversationKindChanged => {
                Self::ConversationKindChanged
            }
            marmot_app::ChatListUpdateTrigger::DirectPeerPresentationChanged => {
                Self::DirectPeerPresentationChanged
            }
            marmot_app::ChatListUpdateTrigger::LatestMessageDeliveryChanged => {
                Self::LatestMessageDeliveryChanged
            }
            marmot_app::ChatListUpdateTrigger::PinOrderChanged => Self::PinOrderChanged,
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
            pinned: false,
            pinned_position: None,
            archived: false,
            pending_confirmation: false,
            lifecycle_state: cgka_traits::GroupLifecycleState::Stable,
            disbanding: false,
            disband_request: None,
            title: "Marmot Lab".to_owned(),
            group_name: "Marmot Lab".to_owned(),
            avatar_url: None,
            avatar: None,
            direct_peer_presentation: None,
            last_message: None,
            unread_count: 0,
            has_unread: false,
            manually_marked_unread: false,
            unread_mention_count: 0,
            has_unread_mention: false,
            first_unread_message_id_hex: None,
            last_read_message_id_hex: None,
            last_read_timeline_at: None,
            conversation_created_at: 100,
            activity_sort_at: 200,
            updated_at: 300,
            self_membership: marmot_app::SelfMembership::Member,
            conversation_kind: marmot_app::ChatConversationKind::Unknown,
            muted: false,
            muted_until_ms: None,
            leave_requested_at_ms: None,
        }
    }

    #[test]
    fn existing_direct_conversation_exports_reuse_state() {
        let ffi = ExistingDirectConversationFfi::from(ExistingDirectConversation {
            group_id_hex: "11".to_owned(),
            reusable: true,
            lifecycle_state: cgka_traits::GroupLifecycleState::Stable,
            self_membership: marmot_app::SelfMembership::Member,
            pending_confirmation: true,
            leave_request_pending: false,
            disbanding: false,
            archived: true,
            activity_sort_at: 200,
        });

        assert_eq!(ffi.group_id_hex, "11");
        assert!(ffi.reusable);
        assert!(matches!(
            ffi.lifecycle_state,
            GroupLifecycleStateFfi::Stable
        ));
        assert!(matches!(ffi.self_membership, SelfMembershipFfi::Member));
        assert!(ffi.pending_confirmation);
        assert!(!ffi.leave_request_pending);
        assert!(!ffi.disbanding);
        assert!(ffi.archived);
        assert_eq!(ffi.activity_sort_at, 200);
    }

    #[test]
    fn chat_list_row_exports_semantic_timestamps() {
        let ffi = ChatListRowFfi::from(sample_row());

        assert_eq!(ffi.conversation_created_at, 100);
        assert_eq!(ffi.activity_sort_at, 200);
        assert_eq!(ffi.updated_at, 300);
    }

    #[test]
    fn direct_peer_presentation_round_trips_to_ffi() {
        let cases = [
            (
                marmot_app::DirectPeerPresentationState::Absent,
                DirectPeerPresentationStateFfi::Absent,
                Some("bb".repeat(32)),
                None,
                None,
                None,
            ),
            (
                marmot_app::DirectPeerPresentationState::Current,
                DirectPeerPresentationStateFfi::Current,
                Some("bb".repeat(32)),
                Some("Remote Otter".to_owned()),
                Some("https://cdn.example.com/remote.png".to_owned()),
                Some(42),
            ),
            (
                marmot_app::DirectPeerPresentationState::LastKnown,
                DirectPeerPresentationStateFfi::LastKnown,
                Some("bb".repeat(32)),
                Some("Remote Otter".to_owned()),
                Some("https://cdn.example.com/remote.png".to_owned()),
                Some(42),
            ),
            (
                marmot_app::DirectPeerPresentationState::Invalidated,
                DirectPeerPresentationStateFfi::Invalidated,
                None,
                None,
                None,
                None,
            ),
        ];

        for (state, expected_state, peer_id, display_name, avatar_url, profile_created_at) in cases
        {
            let ffi = ChatListRowFfi::from(ChatListRow {
                direct_peer_presentation: Some(marmot_app::DirectPeerPresentation {
                    schema_version: marmot_app::DIRECT_PEER_PRESENTATION_SCHEMA_VERSION,
                    peer_account_id_hex: peer_id.clone(),
                    display_name: display_name.clone(),
                    avatar_url: avatar_url.clone(),
                    profile_created_at,
                    state,
                }),
                ..sample_row()
            });
            let presentation = ffi
                .direct_peer_presentation
                .expect("direct-peer presentation");
            assert_eq!(presentation.schema_version, 1);
            assert_eq!(presentation.peer_account_id_hex, peer_id);
            assert_eq!(presentation.display_name, display_name);
            assert_eq!(presentation.avatar_url, avatar_url);
            assert_eq!(presentation.profile_created_at, profile_created_at);
            assert_eq!(presentation.state, expected_state);
        }
    }

    #[test]
    fn chat_list_row_exports_manual_kind_and_mute_state() {
        let ffi = ChatListRowFfi::from(ChatListRow {
            manually_marked_unread: true,
            has_unread: true,
            conversation_kind: marmot_app::ChatConversationKind::Direct,
            muted: true,
            muted_until_ms: Some(1_700_000_000_000),
            ..sample_row()
        });

        assert!(ffi.manually_marked_unread);
        assert!(ffi.has_unread);
        assert!(matches!(
            ffi.conversation_kind,
            ChatConversationKindFfi::Direct
        ));
        assert!(ffi.muted);
        assert_eq!(ffi.muted_until_ms, Some(1_700_000_000_000));
    }

    #[test]
    fn chat_notification_settings_normalize_unmuted_sentinel() {
        let ffi = ChatNotificationSettingsFfi::from(ChatNotificationSettings {
            account_ref: "alice".to_owned(),
            account_id_hex: "aa".to_owned(),
            group_id_hex: "11".to_owned(),
            muted: false,
            muted_until_ms: Some(0),
            updated_at_ms: 0,
        });
        assert!(!ffi.muted);
        assert_eq!(ffi.muted_until_ms, None);

        let indefinite = ChatNotificationSettingsFfi::from(ChatNotificationSettings {
            muted: true,
            muted_until_ms: None,
            account_ref: "alice".to_owned(),
            account_id_hex: "aa".to_owned(),
            group_id_hex: "11".to_owned(),
            updated_at_ms: 1,
        });
        assert!(indefinite.muted);
        assert_eq!(indefinite.muted_until_ms, None);
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
    fn chat_list_row_exports_pending_disband_for_composer_gating() {
        let request = cgka_traits::DisbandRequest {
            group_id: cgka_traits::GroupId::new(vec![0x11]),
            requested_at_ms: 1_700_000_000_456,
            status: cgka_traits::DisbandRequestStatus::Pending,
            last_prepared_epoch: None,
        };
        let ffi = ChatListRowFfi::from(ChatListRow {
            disbanding: true,
            disband_request: Some(request),
            ..sample_row()
        });

        assert!(ffi.disbanding);
        assert!(matches!(
            ffi.disband_request,
            Some(super::super::group::DisbandRequestFfi::Pending {
                requested_at_ms: 1_700_000_000_456
            })
        ));
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
