//! Owned C mirrors of the prepared conversation contract.
use crate::macros::{c_enum, c_mirror};
use crate::memory::{CFree, boxed, free_boxed};
use crate::types::{group::*, presentation::*, timeline::*};
use marmot_uniffi::conversions::*;
use std::sync::Arc;
c_enum! { MarmotConversationOpenMode from ConversationOpenModeFfi { Automatic, Latest, Message, } }
impl MarmotConversationOpenMode {
    pub(crate) fn to_ffi(self) -> ConversationOpenModeFfi {
        match self {
            Self::Automatic => ConversationOpenModeFfi::Automatic,
            Self::Latest => ConversationOpenModeFfi::Latest,
            Self::Message => ConversationOpenModeFfi::Message,
        }
    }
}
c_enum! { MarmotConversationPageDirection from ConversationPageDirectionFfi { Older, Newer, } }
impl MarmotConversationPageDirection {
    pub(crate) fn to_ffi(self) -> ConversationPageDirectionFfi {
        match self {
            Self::Older => ConversationPageDirectionFfi::Older,
            Self::Newer => ConversationPageDirectionFfi::Newer,
        }
    }
}
c_enum! { MarmotConversationParticipation from ConversationParticipationFfi { PendingInvitation, Active, Leaving, Left, Removed, Disbanded, Unavailable, } }
c_enum! { MarmotConversationAnchorKind from ConversationAnchorKindFfi { Empty, Latest, FirstUnread, Message, Retained, RecoveredNext, RecoveredPrevious, } }
c_mirror! { MarmotConversationCapabilities from ConversationCapabilitiesFfi {
copy participation: MarmotConversationParticipation,
copy is_self_admin: bool,
copy is_last_admin: bool,
copy can_send: bool,
copy can_invite: bool,
copy can_edit_group: bool,
copy can_leave: bool,
copy requires_self_demote_before_leave: bool,
copy can_enable_disbanding: bool,
copy can_disband: bool,
} }
c_mirror! { MarmotConversationHeader from ConversationHeaderFfi {
rec selected: MarmotConversationPresentation,
opt_copy has_member_count/member_count: u64,
copy archived: bool,
opt_copy has_epoch/epoch: u64,
copy lifecycle: MarmotGroupLifecycleState,
copy disbanding: bool,
copy unrecoverable: bool,
rec capabilities: MarmotConversationCapabilities,
} }
c_mirror! { MarmotConversationIdentity from ConversationIdentityFfi {
str account_id_hex,
str display_name,
rec avatar: MarmotSelectedAvatar,
copy has_cached_profile: bool,
} }
c_mirror! { MarmotConversationSystemReferences from ConversationSystemReferencesFfi {
str system_type,
opt_str actor,
opt_str subject,
} }
c_mirror! { MarmotConversationReaction from ConversationReactionFfi {
str emoji,
copy count: u64,
str_vec reactors/reactors_len,
} }
c_mirror! { MarmotConversationReactions from ConversationReactionsFfi {
copy total_count: u64,
copy total_kinds: u64,
vec items/items_len: MarmotConversationReaction,
copy omitted_kinds: u64,
} }
c_mirror! { MarmotConversationMessageReferences from ConversationMessageReferencesFfi {
str message_id_hex,
opt_str sender,
opt_str reply_author,
str_vec mentions/mentions_len,
copy mentions_truncated: bool,
str_vec reply_mentions/reply_mentions_len,
copy reply_mentions_truncated: bool,
opt_rec system: MarmotConversationSystemReferences,
rec reactions: MarmotConversationReactions,
} }
c_mirror! { MarmotConversationOpenReadState from ConversationOpenReadStateFfi {
copy initialized: bool,
opt_str last_read_message_id_hex,
opt_copy has_last_read_timeline_at/last_read_timeline_at: u64,
copy manually_marked_unread: bool,
copy unread_count: u64,
copy unread_mention_count: u64,
opt_str first_unread_message_id_hex,
} }
c_mirror! { MarmotSelectedMessageDraftAttachment from SelectedMessageDraftAttachmentFfi {
str id,
str file_name,
str media_type,
copy plaintext_size: u64,
opt_str dim,
opt_str thumbhash,
opt_copy has_duration_seconds/duration_seconds: f64,
prim_vec waveform_samples/waveform_samples_len: f64,
} }
c_mirror! { MarmotSelectedMessageDraftContent from SelectedMessageDraftContentFfi {
str group_id_hex,
str content,
opt_str reply_to_message_id_hex,
vec media_attachments/media_attachments_len: MarmotSelectedMessageDraftAttachment,
copy created_at_ms: i64,
copy updated_at_ms: i64,
} }
c_mirror! { MarmotConversationWindowRevision from ConversationWindowRevisionFfi {
str generation,
copy sequence: u64,
} }
c_mirror! { MarmotConversationAnchorOutcome from ConversationAnchorOutcomeFfi {
copy kind: MarmotConversationAnchorKind,
opt_copy has_index/index: u32,
} }

/// Opaque token owned by its SelectedMessageDraft; borrow only while that draft remains live.
pub struct MarmotMessageDraftRevision {
    pub(crate) inner: Arc<MessageDraftRevisionFfi>,
}
#[repr(C)]
pub struct MarmotSelectedMessageDraft {
    pub revision: *mut MarmotMessageDraftRevision,
    pub draft: *mut MarmotSelectedMessageDraftContent,
}
impl From<SelectedMessageDraftFfi> for MarmotSelectedMessageDraft {
    fn from(v: SelectedMessageDraftFfi) -> Self {
        Self {
            revision: boxed(MarmotMessageDraftRevision { inner: v.revision }),
            draft: v
                .draft
                .map(|d| boxed(d.into()))
                .unwrap_or(std::ptr::null_mut()),
        }
    }
}
impl CFree for MarmotSelectedMessageDraft {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_boxed(self.revision);
            free_boxed(self.draft);
        }
    }
}
/// Deep-free a selected draft and its opaque revision. NULL is allowed.
/// # Safety
/// p must be NULL or a library-owned unfreed selected draft.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selected_message_draft_free(p: *mut MarmotSelectedMessageDraft) {
    crate::memory::free_guard(|| unsafe { free_boxed(p) });
}
c_mirror! { MarmotConversationMessage from ConversationMessageFfi {
rec timeline: MarmotTimelineMessageRecord,
rec references: MarmotConversationMessageReferences,
} }
c_mirror! { MarmotConversationWindowSnapshot from ConversationWindowSnapshotFfi, free marmot_conversation_window_snapshot_free {
rec revision: MarmotConversationWindowRevision,
rec header: MarmotConversationHeader,
vec messages/messages_len: MarmotConversationMessage,
vec identities/identities_len: MarmotConversationIdentity,
rec read_state: MarmotConversationOpenReadState,
rec draft: MarmotSelectedMessageDraft,
copy pending_confirmation: bool,
rec anchor: MarmotConversationAnchorOutcome,
copy has_more_before: bool,
copy has_more_after: bool,
} }

impl CFree for MarmotMessageDraftRevision {
    unsafe fn free_in_place(&mut self) {}
}
