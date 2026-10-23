//! Complete-selection C DTOs. Inputs are borrowed; returned roots own deep-freeable data.
//! Text fields use JSON string literals to retain embedded NULs; identifiers use C strings.
use super::account::MarmotSendSummary;
use super::chat_list::{MarmotChatConversationKind, MarmotChatListAttachmentKind};
use super::chat_window::MarmotChatListView;
use super::timeline::MarmotGroupSystemEventProvenance;
use crate::MarmotStatus;
use crate::macros::{c_enum, c_mirror};
use crate::memory::{self, CFree, c_bool, free_c_string, owned_c_string};
use marmot_uniffi::conversions::*;
use std::collections::HashMap;
use std::ffi::c_char;

c_enum! { MarmotChatSelectionField from ChatSelectionFieldFfi { Unread, Mentions, Muted, Pinned, Archived, Type, Accepted, Draft, PendingSend, Title, Participants, } }
impl MarmotChatSelectionField {
    fn to_ffi(self) -> ChatSelectionFieldFfi {
        match self {
            Self::Unread => ChatSelectionFieldFfi::Unread,
            Self::Mentions => ChatSelectionFieldFfi::Mentions,
            Self::Muted => ChatSelectionFieldFfi::Muted,
            Self::Pinned => ChatSelectionFieldFfi::Pinned,
            Self::Archived => ChatSelectionFieldFfi::Archived,
            Self::Type => ChatSelectionFieldFfi::Type,
            Self::Accepted => ChatSelectionFieldFfi::Accepted,
            Self::Draft => ChatSelectionFieldFfi::Draft,
            Self::PendingSend => ChatSelectionFieldFfi::PendingSend,
            Self::Title => ChatSelectionFieldFfi::Title,
            Self::Participants => ChatSelectionFieldFfi::Participants,
        }
    }
}
c_enum! { MarmotChatSelectionMode from ChatSelectionModeFfi { Present, None, Direct, Group, AnyOf, AllOf, Excludes, Contains, } }
impl MarmotChatSelectionMode {
    fn to_ffi(self) -> ChatSelectionModeFfi {
        match self {
            Self::Present => ChatSelectionModeFfi::Present,
            Self::None => ChatSelectionModeFfi::None,
            Self::Direct => ChatSelectionModeFfi::Direct,
            Self::Group => ChatSelectionModeFfi::Group,
            Self::AnyOf => ChatSelectionModeFfi::AnyOf,
            Self::AllOf => ChatSelectionModeFfi::AllOf,
            Self::Excludes => ChatSelectionModeFfi::Excludes,
            Self::Contains => ChatSelectionModeFfi::Contains,
        }
    }
}
c_enum! { MarmotChatSelectionSending from ChatSelectionSendingFfi { Sending, SuppressNative, } }
impl MarmotChatSelectionSending {
    fn to_ffi(self) -> ChatSelectionSendingFfi {
        match self {
            Self::Sending => ChatSelectionSendingFfi::Sending,
            Self::SuppressNative => ChatSelectionSendingFfi::SuppressNative,
        }
    }
}
c_enum! { MarmotChatSelectionLeafKind from ChatSelectionLeafKindFfi { TitleContains, LegacyKeyword, IsDirect, LegacyPeerEquals, ChatSearch, } }
c_enum! { #[derive(Default)] MarmotChatSelectionDepartureRefusal from ChatSelectionDepartureRefusalFfi { #[default] CatchingUp, CommitUndelivered, Other, } }

#[repr(C)]
pub enum MarmotChatSelectionText {
    Literal {
        /// JSON string literal; decode once to preserve embedded NULs. Not raw C text.
        text: *mut c_char,
    },
    UnnamedGroup {
        has_member_count: bool,
        member_count: u64,
    },
    UnavailableConversation,
}
impl From<PresentationTextFfi> for MarmotChatSelectionText {
    fn from(v: PresentationTextFfi) -> Self {
        match v {
            PresentationTextFfi::Literal { text } => Self::Literal {
                text: owned_c_string(serde_json::to_string(&text).expect("JSON text")),
            },
            PresentationTextFfi::UnnamedGroup { member_count } => Self::UnnamedGroup {
                has_member_count: member_count.is_some(),
                member_count: member_count.unwrap_or_default(),
            },
            PresentationTextFfi::UnavailableConversation => Self::UnavailableConversation,
        }
    }
}
impl CFree for MarmotChatSelectionText {
    unsafe fn free_in_place(&mut self) {
        if let Self::Literal { text } = self {
            unsafe { free_c_string(*text) };
        }
    }
}
c_mirror! { MarmotChatSelectionGroupSystem from GroupSystemEventFfi {
copy provenance: MarmotGroupSystemEventProvenance,
#[doc = "Nullable JSON string literal; NULL means absent. Decode JSON once; not raw C text."]
json_opt_str actor_display_name,
#[doc = "Nullable JSON string literal; NULL means absent. Decode JSON once; not raw C text."]
json_opt_str subject_display_name,
#[doc = "JSON string literal. Decode JSON once to preserve embedded NULs; not raw C text."]
json_str system_type,
#[doc = "JSON string literal. Decode JSON once to preserve embedded NULs; not raw C text."]
json_str text,
opt_str actor_account_id_hex, opt_str subject_account_id_hex,
#[doc = "Nullable JSON string literal; NULL means absent. Decode JSON once; not raw C text."]
json_opt_str name,
#[doc = "Nullable JSON string literal; NULL means absent. Decode JSON once; not raw C text."]
json_opt_str old_name,
opt_copy has_old_retention_seconds/old_retention_seconds: u64,
opt_copy has_new_retention_seconds/new_retention_seconds: u64,
} }
c_mirror! { MarmotChatSelectionSearchScope from ChatSelectionSearchScopeFfi {
#[doc = "JSON string literal. Decode JSON once to preserve embedded NULs; not raw C text."]
json_str raw_query,
#[doc = "Nullable JSON string literal; NULL means absent. Decode JSON once; not raw C text."]
json_opt_str sql_needle, copy message_only: bool,
} }
c_mirror! { MarmotChatSelectionSearchPreviewMessage from ChatSelectionSearchPreviewMessageFfi {
str message_id_hex,
#[doc = "Nullable JSON string literal; NULL means absent. Decode JSON once; not raw C text."]
json_opt_str resolved_media_preview_fallback,
#[doc = "JSON string literal. Decode JSON once to preserve embedded NULs; not raw C text."]
json_str plaintext, copy kind: u64,
copy deleted: bool, opt_copy has_attachment_kind/attachment_kind: MarmotChatListAttachmentKind,
copy attachment_count: u32, opt_rec group_system: MarmotChatSelectionGroupSystem,
} }
c_mirror! { MarmotChatSelectionSearchMessage from ChatSelectionSearchMessageFfi {
str message_id_hex, str sender,
#[doc = "JSON string literal. Decode JSON once to preserve embedded NULs; not raw C text."]
json_str plaintext, copy kind: u64, copy timeline_at: u64,
copy deleted: bool, opt_copy has_retention_seconds/retention_seconds: u64,
opt_copy has_retention_expires_at/retention_expires_at: u64, copy retention_expired: bool,
#[doc = "Array of JSON string literals; decode each element once, not as raw C text."]
json_str_vec media_types/media_types_len,
} }
c_mirror! { MarmotChatSelectionSearchPresentation from ChatSelectionSearchPresentationFfi {
rec scope: MarmotChatSelectionSearchScope, str nostr_group_id_hex,
opt_rec last_message: MarmotChatSelectionSearchPreviewMessage,
vec messages/messages_len: MarmotChatSelectionSearchMessage, copy capture_now_ms: i64,
} }
c_mirror! { MarmotChatSelectionLeaf from ChatSelectionLeafFfi {
copy slot: u32, copy kind: MarmotChatSelectionLeafKind,
#[doc = "JSON string literal. Decode JSON once to preserve embedded NULs; not raw C text."]
json_str needle,
} }
c_mirror! { MarmotChatSelectionOperand from ChatSelectionOperandFfi, free marmot_chat_selection_operand_free, list(MarmotChatSelectionOperandList, marmot_chat_selection_operand_list_free) {
copy candidate_slot: u64, str group_id_hex,
#[doc = "JSON string literal. Decode JSON once to preserve embedded NULs; not raw C text."]
json_str row_group_name,
#[doc = "JSON string literal. Decode JSON once to preserve embedded NULs; not raw C text."]
json_str fallback_group_name,
#[doc = "Nullable JSON string literal; NULL means absent. Decode JSON once; not raw C text."]
json_opt_str projected_title, opt_rec selected_title: MarmotChatSelectionText,
opt_str selected_peer_id_hex, opt_str roster_peer_id_hex, copy roster_peer_present: bool,
copy roster_member_count: i32, copy pending_confirmation: bool, opt_str welcomer_id_hex,
opt_copy has_conversation_kind/conversation_kind: MarmotChatConversationKind,
copy active_account_is_sole_member: bool,
#[doc = "Nullable JSON string literal; NULL means absent. Decode JSON once; not raw C text."]
json_opt_str description,
vec leaves/leaves_len: MarmotChatSelectionLeaf, opt_rec search: MarmotChatSelectionSearchPresentation,
} }
c_mirror! { MarmotChatSelectionStatus from ChatSelectionStatusFfi, free marmot_chat_selection_status_free {
copy revision: u64, opt_copy has_count/count: u64,
opt_copy has_all_archived/all_archived: bool, opt_copy has_all_direct/all_direct: bool,
opt_copy has_all_abandonable/all_abandonable: bool, copy presentation_operands: u64,
opt_copy has_operation_id/operation_id: u64, opt_copy has_last_attempt/last_attempt: u64, copy mutation_uncertain: bool,
} }
c_mirror! { MarmotChatSelectionSummary from ChatSelectionSummaryFfi, free marmot_chat_selection_summary_free {
copy revision: u64, copy count: u64,
} }
c_mirror! { MarmotChatSelectionPage from ChatSelectionPageFfi, free marmot_chat_selection_page_free {
copy revision: u64, str_vec group_ids/group_ids_len,
} }
c_mirror! { MarmotChatSelectionFolderPage from ChatSelectionFolderPageFfi, free marmot_chat_selection_folder_page_free {
copy revision: u64, str_vec group_ids/group_ids_len, opt_str next_after, copy done: bool,
} }
c_mirror! { MarmotChatSelectionMutationReport from ChatSelectionMutationReportFfi, free marmot_chat_selection_mutation_report_free {
copy mutation: MarmotChatSelectionMutation, copy operation_id: u64, copy attempt_id: u64,
copy revision: u64, str_vec applied_group_ids/applied_group_ids_len, opt_str failed_group_id,
copy uncertain: bool, copy remaining: u64,
} }
c_mirror! { MarmotChatSelectionDepartureReport from ChatSelectionDepartureReportFfi, free marmot_chat_selection_departure_report_free {
copy operation_id: u64, copy attempt_id: u64, copy revision: u64, str group_id_hex,
rec step: MarmotChatSelectionDepartureStep, opt_rec summary: MarmotSendSummary,
copy changed: bool, copy skipped: bool, opt_copy has_refusal/refusal: MarmotChatSelectionDepartureRefusal,
copy uncertain: bool,
} }

#[repr(C)]
pub enum MarmotChatSelectionMutation {
    Archive { archived: bool },
    DeleteLocal,
}
impl From<ChatSelectionMutationFfi> for MarmotChatSelectionMutation {
    fn from(v: ChatSelectionMutationFfi) -> Self {
        match v {
            ChatSelectionMutationFfi::Archive { archived } => Self::Archive { archived },
            ChatSelectionMutationFfi::DeleteLocal => Self::DeleteLocal,
        }
    }
}
impl CFree for MarmotChatSelectionMutation {
    unsafe fn free_in_place(&mut self) {}
}
#[repr(C)]
pub enum MarmotChatSelectionDepartureStep {
    Promote { member_ref: *mut c_char },
    SelfDemote,
    Leave,
    ForgetLocal,
    DeleteLocal,
}
impl From<ChatSelectionDepartureStepFfi> for MarmotChatSelectionDepartureStep {
    fn from(v: ChatSelectionDepartureStepFfi) -> Self {
        match v {
            ChatSelectionDepartureStepFfi::Promote { member_ref } => Self::Promote {
                member_ref: owned_c_string(member_ref),
            },
            ChatSelectionDepartureStepFfi::SelfDemote => Self::SelfDemote,
            ChatSelectionDepartureStepFfi::Leave => Self::Leave,
            ChatSelectionDepartureStepFfi::ForgetLocal => Self::ForgetLocal,
            ChatSelectionDepartureStepFfi::DeleteLocal => Self::DeleteLocal,
        }
    }
}
impl CFree for MarmotChatSelectionDepartureStep {
    unsafe fn free_in_place(&mut self) {
        if let Self::Promote { member_ref } = self {
            unsafe { free_c_string(*member_ref) };
        }
    }
}
#[repr(C)]
pub struct MarmotChatSelectionMembership {
    pub matches: *mut bool,
    pub matches_len: usize,
}
impl From<Vec<bool>> for MarmotChatSelectionMembership {
    fn from(v: Vec<bool>) -> Self {
        let (matches, matches_len) = memory::owned_vec(v);
        Self {
            matches,
            matches_len,
        }
    }
}
impl CFree for MarmotChatSelectionMembership {
    unsafe fn free_in_place(&mut self) {
        unsafe { memory::free_vec(self.matches, self.matches_len) };
    }
}
/// # Safety
/// The pointer is NULL or a live membership result returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_chat_selection_membership_free(
    ptr: *mut MarmotChatSelectionMembership,
) {
    memory::free_guard(|| unsafe { memory::free_boxed(ptr) });
}

fn invalid() -> MarmotStatus {
    crate::status::set_last_error("invalid chat selection input");
    MarmotStatus::InvalidArgument
}
// C callers own pointer validity/alignment/lifetime; these checks reject NULL/size inconsistencies.
unsafe fn array<'a, T>(ptr: *const T, len: usize) -> Result<&'a [T], MarmotStatus> {
    if len > isize::MAX as usize / std::mem::size_of::<T>().max(1) {
        return Err(invalid());
    }
    if ptr.is_null() {
        return if len == 0 {
            Ok(&[])
        } else {
            Err(MarmotStatus::NullPointer)
        };
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}
unsafe fn json_text(ptr: *const c_char) -> Result<String, MarmotStatus> {
    serde_json::from_str(&unsafe { memory::required_str(ptr) }?).map_err(|_| invalid())
}
unsafe fn opt_json_text(ptr: *const c_char) -> Result<Option<String>, MarmotStatus> {
    if ptr.is_null() {
        Ok(None)
    } else {
        unsafe { json_text(ptr) }.map(Some)
    }
}
unsafe fn texts(
    ptr: *const *const c_char,
    len: usize,
    json: bool,
) -> Result<Vec<String>, MarmotStatus> {
    let input = unsafe { array(ptr, len) }?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(input.len())
        .map_err(|_| MarmotStatus::ChatSelectionResourceExhausted)?;
    for value in input {
        result.push(if json {
            unsafe { json_text(*value) }?
        } else {
            unsafe { memory::required_str(*value) }?
        });
    }
    Ok(result)
}
unsafe fn optional<T, U>(
    ptr: *const T,
    convert: impl FnOnce(&T) -> Result<U, MarmotStatus>,
) -> Result<Option<U>, MarmotStatus> {
    if ptr.is_null() {
        Ok(None)
    } else {
        convert(unsafe { &*ptr }).map(Some)
    }
}

/// Borrowed tagged predicate: tag0=Group, tag1=Condition. Only active fields are read.
#[repr(C)]
pub struct MarmotChatSelectionPredicateInput {
    pub tag: u32,
    pub all: u8,
    pub negated: u8,
    pub children: *const MarmotChatSelectionPredicateInput,
    pub children_len: usize,
    pub field: u32,
    pub mode: u32,
    /// Array of JSON string literals, not raw C text; active for string-valued conditions.
    pub values: *const *const c_char,
    pub values_len: usize,
}
impl MarmotChatSelectionPredicateInput {
    // Match native smart_folder depth4/nodes64 before descending or allocating.
    // None is an invalid stored automatic rule: native preserves manual membership.
    unsafe fn decode(
        &self,
        depth: usize,
        nodes: &mut usize,
    ) -> Result<Option<ChatSelectionPredicateFfi>, MarmotStatus> {
        if depth > 4 || *nodes >= 64 {
            return Ok(None);
        }
        *nodes += 1;
        match self.tag {
            0 => {
                if self.children_len > 64 - *nodes {
                    return Ok(None);
                }
                let borrowed = unsafe { array(self.children, self.children_len) }?;
                let mut children = Vec::new();
                children
                    .try_reserve_exact(borrowed.len())
                    .map_err(|_| MarmotStatus::ChatSelectionResourceExhausted)?;
                for child in borrowed {
                    match unsafe { child.decode(depth + 1, nodes) }? {
                        Some(v) => children.push(v),
                        None => return Ok(None),
                    }
                }
                Ok(Some(ChatSelectionPredicateFfi::Group {
                    all: c_bool(self.all),
                    children,
                    not: c_bool(self.negated),
                }))
            }
            1 => {
                let field = MarmotChatSelectionField::from_c(self.field)?.to_ffi();
                let mode = MarmotChatSelectionMode::from_c(self.mode)?.to_ffi();
                // Native accepts64 participant values, exactly1 title value and no scalar values.
                let valid_count = match field {
                    ChatSelectionFieldFfi::Participants => {
                        self.values_len > 0 && self.values_len <= 64
                    }
                    ChatSelectionFieldFfi::Title => self.values_len == 1,
                    _ => self.values_len == 0,
                };
                if !valid_count {
                    return Ok(None);
                }
                Ok(Some(ChatSelectionPredicateFfi::Condition {
                    field,
                    mode,
                    values: unsafe {
                        texts(
                            self.values,
                            self.values_len,
                            matches!(field, ChatSelectionFieldFfi::Title),
                        )
                    }?,
                    not: c_bool(self.negated),
                }))
            }
            _ => Err(invalid()),
        }
    }
}
/// tag0=ManualOnly,1=Smart,2=Legacy. NULL active records are invalid arguments.
#[repr(C)]
pub struct MarmotChatSelectionAutomaticRuleInput {
    pub tag: u32,
    pub predicate: *const MarmotChatSelectionPredicateInput,
    pub legacy: *const MarmotChatSelectionLegacyRuleInput,
}
impl MarmotChatSelectionAutomaticRuleInput {
    pub(crate) unsafe fn to_ffi(&self) -> Result<ChatSelectionAutomaticRuleFfi, MarmotStatus> {
        match self.tag {
            0 => Ok(ChatSelectionAutomaticRuleFfi::ManualOnly),
            1 => {
                let p = unsafe { self.predicate.as_ref() }.ok_or(MarmotStatus::NullPointer)?;
                Ok(match unsafe { p.decode(0, &mut 0) }? {
                    Some(predicate) => ChatSelectionAutomaticRuleFfi::Smart { predicate },
                    None => ChatSelectionAutomaticRuleFfi::ManualOnly,
                })
            }
            2 => Ok(ChatSelectionAutomaticRuleFfi::Legacy {
                rule: unsafe {
                    self.legacy
                        .as_ref()
                        .ok_or(MarmotStatus::NullPointer)?
                        .to_ffi()
                }?,
            }),
            _ => Err(invalid()),
        }
    }
}

/// Borrowed input; all pointers remain caller-owned for the duration of the call.
#[repr(C)]
pub struct MarmotChatSelectionLegacyRuleInput {
    pub members: *const *const c_char,
    pub members_len: usize,
    /// Nullable JSON string literal; NULL means absent. Not raw C text.
    pub keyword: *const c_char,
    pub include_all: u8,
    pub unread_only: u8,
    pub unread_mentions_only: u8,
    pub pinned_only: u8,
    pub groups_only: u8,
    pub direct_only: u8,
    pub archived_only: u8,
    pub include_muted: u8,
}
impl MarmotChatSelectionLegacyRuleInput {
    /// # Safety
    /// Every active pointer must reference valid aligned values/UTF-8 C strings for its declared length.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ChatSelectionLegacyRuleFfi, MarmotStatus> {
        Ok(ChatSelectionLegacyRuleFfi {
            members: unsafe { texts(self.members, self.members_len, false) }?,
            keyword: unsafe { opt_json_text(self.keyword) }?,
            include_all: c_bool(self.include_all),
            unread_only: c_bool(self.unread_only),
            unread_mentions_only: c_bool(self.unread_mentions_only),
            pinned_only: c_bool(self.pinned_only),
            groups_only: c_bool(self.groups_only),
            direct_only: c_bool(self.direct_only),
            archived_only: c_bool(self.archived_only),
            include_muted: c_bool(self.include_muted),
        })
    }
}

/// Borrowed input; all pointers remain caller-owned for the duration of the call.
#[repr(C)]
pub struct MarmotChatSelectionFolderInput {
    pub manual: *const *const c_char,
    pub manual_len: usize,
    pub excluded: *const *const c_char,
    pub excluded_len: usize,
    pub automatic: MarmotChatSelectionAutomaticRuleInput,
}
impl MarmotChatSelectionFolderInput {
    /// # Safety
    /// Every active pointer must reference valid aligned values/UTF-8 C strings for its declared length.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ChatSelectionFolderFfi, MarmotStatus> {
        Ok(ChatSelectionFolderFfi {
            manual: unsafe { texts(self.manual, self.manual_len, false) }?,
            excluded: unsafe { texts(self.excluded, self.excluded_len, false) }?,
            automatic: unsafe { self.automatic.to_ffi() }?,
        })
    }
}

#[repr(C)]
pub struct MarmotChatSelectionBaseScopeInput {
    pub tag: u32,
    pub view: u32,
}
impl MarmotChatSelectionBaseScopeInput {
    pub(crate) fn to_ffi(&self) -> Result<ChatSelectionBaseScopeFfi, MarmotStatus> {
        match self.tag {
            0 => Ok(ChatSelectionBaseScopeFfi::View {
                view: MarmotChatListView::from_c(self.view)?.to_ffi(),
            }),
            1 => Ok(ChatSelectionBaseScopeFfi::ActiveAndArchived),
            _ => Err(invalid()),
        }
    }
}

/// Borrowed input; all pointers remain caller-owned for the duration of the call.
#[repr(C)]
pub struct MarmotChatSelectionSearchScopeInput {
    /// JSON string literal; decode once to preserve embedded NULs. Not raw C text.
    pub raw_query: *const c_char,
    /// Nullable JSON string literal; NULL means absent. Not raw C text.
    pub sql_needle: *const c_char,
    pub message_only: u8,
}
impl MarmotChatSelectionSearchScopeInput {
    /// # Safety
    /// Every active pointer must reference valid aligned values/UTF-8 C strings for its declared length.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ChatSelectionSearchScopeFfi, MarmotStatus> {
        Ok(ChatSelectionSearchScopeFfi {
            raw_query: unsafe { json_text(self.raw_query) }?,
            sql_needle: unsafe { opt_json_text(self.sql_needle) }?,
            message_only: c_bool(self.message_only),
        })
    }
}

#[repr(C)]
pub struct MarmotChatSelectionScopeInput {
    pub selected_folder: *const MarmotChatSelectionFolderInput,
    pub has_filter_folders: u8,
    pub filter_folders: *const MarmotChatSelectionFolderInput,
    pub filter_folders_len: usize,
    pub has_named_chats: u8,
    pub named_chats: *const *const c_char,
    pub named_chats_len: usize,
    pub direct: u8,
    pub groups: u8,
    pub search: *const MarmotChatSelectionSearchScopeInput,
}
impl MarmotChatSelectionScopeInput {
    /// # Safety
    /// Active arrays/records and their strings must be valid for their declared lengths.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ChatSelectionScopeFfi, MarmotStatus> {
        let filter_folders = if c_bool(self.has_filter_folders) {
            let borrowed = unsafe { array(self.filter_folders, self.filter_folders_len) }?;
            let mut folders = Vec::new();
            folders
                .try_reserve_exact(borrowed.len())
                .map_err(|_| MarmotStatus::ChatSelectionResourceExhausted)?;
            for value in borrowed {
                folders.push(unsafe { value.to_ffi() }?);
            }
            Some(folders)
        } else {
            None
        };
        let named_chats = if c_bool(self.has_named_chats) {
            Some(unsafe { texts(self.named_chats, self.named_chats_len, false) }?)
        } else {
            None
        };
        Ok(ChatSelectionScopeFfi {
            selected_folder: unsafe { optional(self.selected_folder, |v| v.to_ffi()) }?,
            filter_folders,
            named_chats,
            direct: c_bool(self.direct),
            groups: c_bool(self.groups),
            search: unsafe { optional(self.search, |v| v.to_ffi()) }?,
        })
    }
}

/// Borrowed input; all pointers remain caller-owned for the duration of the call.
#[repr(C)]
pub struct MarmotChatSelectionHostContextInput {
    pub account_id_hex: *const c_char,
    pub runtime_generation: i64,
    pub selection_generation: u64,
    pub presentation_context_id: u64,
}
impl MarmotChatSelectionHostContextInput {
    /// # Safety
    /// Every active pointer must reference valid aligned values/UTF-8 C strings for its declared length.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ChatSelectionHostContextFfi, MarmotStatus> {
        Ok(ChatSelectionHostContextFfi {
            account_id_hex: unsafe { memory::required_str(self.account_id_hex) }?,
            runtime_generation: self.runtime_generation,
            selection_generation: self.selection_generation,
            presentation_context_id: self.presentation_context_id,
        })
    }
}

/// Borrowed input; all pointers remain caller-owned for the duration of the call.
#[repr(C)]
pub struct MarmotChatSelectionGroupSystemInput {
    pub provenance: u32,
    /// Nullable JSON string literal; NULL means absent. Not raw C text.
    pub actor_display_name: *const c_char,
    /// Nullable JSON string literal; NULL means absent. Not raw C text.
    pub subject_display_name: *const c_char,
    /// JSON string literal; decode once to preserve embedded NULs. Not raw C text.
    pub system_type: *const c_char,
    /// JSON string literal; decode once to preserve embedded NULs. Not raw C text.
    pub text: *const c_char,
    pub actor_account_id_hex: *const c_char,
    pub subject_account_id_hex: *const c_char,
    /// Nullable JSON string literal; NULL means absent. Not raw C text.
    pub name: *const c_char,
    /// Nullable JSON string literal; NULL means absent. Not raw C text.
    pub old_name: *const c_char,
    pub has_old_retention_seconds: u8,
    pub old_retention_seconds: u64,
    pub has_new_retention_seconds: u8,
    pub new_retention_seconds: u64,
}
impl MarmotChatSelectionGroupSystemInput {
    /// # Safety
    /// Every active pointer must reference valid aligned values/UTF-8 C strings for its declared length.
    pub(crate) unsafe fn to_ffi(&self) -> Result<GroupSystemEventFfi, MarmotStatus> {
        Ok(GroupSystemEventFfi {
            provenance: match MarmotGroupSystemEventProvenance::from_c(self.provenance)? {
                MarmotGroupSystemEventProvenance::AuthenticatedGroupState => {
                    GroupSystemEventProvenanceFfi::AuthenticatedGroupState
                }
                MarmotGroupSystemEventProvenance::MemberAuthored => {
                    GroupSystemEventProvenanceFfi::MemberAuthored
                }
            },
            actor_display_name: unsafe { opt_json_text(self.actor_display_name) }?,
            subject_display_name: unsafe { opt_json_text(self.subject_display_name) }?,
            name: unsafe { opt_json_text(self.name) }?,
            old_name: unsafe { opt_json_text(self.old_name) }?,
            system_type: unsafe { json_text(self.system_type) }?,
            text: unsafe { json_text(self.text) }?,
            actor_account_id_hex: unsafe { memory::optional_str(self.actor_account_id_hex) }?,
            subject_account_id_hex: unsafe { memory::optional_str(self.subject_account_id_hex) }?,
            old_retention_seconds: c_bool(self.has_old_retention_seconds)
                .then_some(self.old_retention_seconds),
            new_retention_seconds: c_bool(self.has_new_retention_seconds)
                .then_some(self.new_retention_seconds),
        })
    }
}

/// Borrowed input; all pointers remain caller-owned for the duration of the call.
#[repr(C)]
pub struct MarmotChatSelectionSearchPreviewMessageInput {
    pub message_id_hex: *const c_char,
    /// Nullable JSON string literal; NULL means absent. Not raw C text.
    pub resolved_media_preview_fallback: *const c_char,
    /// JSON string literal; decode once to preserve embedded NULs. Not raw C text.
    pub plaintext: *const c_char,
    pub kind: u64,
    pub deleted: u8,
    pub has_attachment_kind: u8,
    pub attachment_kind: u32,
    pub attachment_count: u32,
    pub group_system: *const MarmotChatSelectionGroupSystemInput,
}
impl MarmotChatSelectionSearchPreviewMessageInput {
    /// # Safety
    /// Every active pointer must reference valid aligned values/UTF-8 C strings for its declared length.
    pub(crate) unsafe fn to_ffi(
        &self,
    ) -> Result<ChatSelectionSearchPreviewMessageFfi, MarmotStatus> {
        Ok(ChatSelectionSearchPreviewMessageFfi {
            message_id_hex: unsafe { memory::required_str(self.message_id_hex) }?,
            resolved_media_preview_fallback: unsafe {
                opt_json_text(self.resolved_media_preview_fallback)
            }?,
            plaintext: unsafe { json_text(self.plaintext) }?,
            kind: self.kind,
            deleted: c_bool(self.deleted),
            attachment_kind: if c_bool(self.has_attachment_kind) {
                Some(
                    match MarmotChatListAttachmentKind::from_c(self.attachment_kind)? {
                        MarmotChatListAttachmentKind::Photo => ChatListAttachmentKindFfi::Photo,
                        MarmotChatListAttachmentKind::Video => ChatListAttachmentKindFfi::Video,
                        MarmotChatListAttachmentKind::Audio => ChatListAttachmentKindFfi::Audio,
                        MarmotChatListAttachmentKind::File => ChatListAttachmentKindFfi::File,
                        MarmotChatListAttachmentKind::Mixed => ChatListAttachmentKindFfi::Mixed,
                    },
                )
            } else {
                None
            },
            attachment_count: self.attachment_count,
            group_system: unsafe { optional(self.group_system, |v| v.to_ffi()) }?,
        })
    }
}

/// Map entries are unique by key; a present preview entry with NULL value is explicit None.
#[repr(C)]
pub struct MarmotChatSelectionSendingEntryInput {
    pub group_id_hex: *const c_char,
    pub value: u32,
}
#[repr(C)]
pub struct MarmotChatSelectionMutedEntryInput {
    pub group_id_hex: *const c_char,
    pub value: u8,
}
#[repr(C)]
pub struct MarmotChatSelectionPreviewEntryInput {
    pub group_id_hex: *const c_char,
    pub value: *const MarmotChatSelectionSearchPreviewMessageInput,
}
#[repr(C)]
pub struct MarmotChatSelectionFallbackEntryInput {
    pub message_id_hex: *const c_char,
    /// JSON string literal; decode once to preserve embedded NULs. Not raw C text.
    pub text: *const c_char,
}
#[repr(C)]
pub struct MarmotChatSelectionHostOverlaysInput {
    pub sending: *const MarmotChatSelectionSendingEntryInput,
    pub sending_len: usize,
    pub muted: *const MarmotChatSelectionMutedEntryInput,
    pub muted_len: usize,
    pub removed: *const *const c_char,
    pub removed_len: usize,
    pub invite_conflicts: *const *const c_char,
    pub invite_conflicts_len: usize,
    pub preview_overrides: *const MarmotChatSelectionPreviewEntryInput,
    pub preview_overrides_len: usize,
    pub media_preview_fallbacks: *const MarmotChatSelectionFallbackEntryInput,
    pub media_preview_fallbacks_len: usize,
}
impl MarmotChatSelectionHostOverlaysInput {
    /// # Safety
    /// All non-NULL pointers and nested strings must be valid for the stated lengths.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ChatSelectionHostOverlaysFfi, MarmotStatus> {
        let sending_input = unsafe { array(self.sending, self.sending_len) }?;
        let mut sending = HashMap::new();
        sending
            .try_reserve(self.sending_len)
            .map_err(|_| MarmotStatus::ChatSelectionResourceExhausted)?;
        for v in sending_input {
            let key = unsafe { memory::required_str(v.group_id_hex) }?;
            let value = MarmotChatSelectionSending::from_c(v.value)?.to_ffi();
            if sending.insert(key, value).is_some() {
                return Err(invalid());
            }
        }
        let muted_input = unsafe { array(self.muted, self.muted_len) }?;
        let mut muted = HashMap::new();
        muted
            .try_reserve(self.muted_len)
            .map_err(|_| MarmotStatus::ChatSelectionResourceExhausted)?;
        for v in muted_input {
            let key = unsafe { memory::required_str(v.group_id_hex) }?;
            if muted.insert(key, c_bool(v.value)).is_some() {
                return Err(invalid());
            }
        }
        let preview_overrides_input =
            unsafe { array(self.preview_overrides, self.preview_overrides_len) }?;
        let mut preview_overrides = HashMap::new();
        preview_overrides
            .try_reserve(self.preview_overrides_len)
            .map_err(|_| MarmotStatus::ChatSelectionResourceExhausted)?;
        for v in preview_overrides_input {
            let key = unsafe { memory::required_str(v.group_id_hex) }?;
            let value = unsafe { optional(v.value, |v| v.to_ffi()) }?;
            if preview_overrides.insert(key, value).is_some() {
                return Err(invalid());
            }
        }
        let media_preview_fallbacks_input = unsafe {
            array(
                self.media_preview_fallbacks,
                self.media_preview_fallbacks_len,
            )
        }?;
        let mut media_preview_fallbacks = HashMap::new();
        media_preview_fallbacks
            .try_reserve(self.media_preview_fallbacks_len)
            .map_err(|_| MarmotStatus::ChatSelectionResourceExhausted)?;
        for v in media_preview_fallbacks_input {
            let key = unsafe { memory::required_str(v.message_id_hex) }?;
            let value = unsafe { json_text(v.text) }?;
            if media_preview_fallbacks.insert(key, value).is_some() {
                return Err(invalid());
            }
        }
        Ok(ChatSelectionHostOverlaysFfi {
            sending,
            muted,
            removed: unsafe { texts(self.removed, self.removed_len, false) }?,
            invite_conflicts: unsafe {
                texts(self.invite_conflicts, self.invite_conflicts_len, false)
            }?,
            preview_overrides,
            media_preview_fallbacks,
        })
    }
}

/// Borrowed input; all pointers remain caller-owned for the duration of the call.
#[repr(C)]
pub struct MarmotChatSelectionContextInput {
    pub host: MarmotChatSelectionHostContextInput,
    pub overlays: MarmotChatSelectionHostOverlaysInput,
    pub capture_now_ms: i64,
}
impl MarmotChatSelectionContextInput {
    /// # Safety
    /// Every active pointer must reference valid aligned values/UTF-8 C strings for its declared length.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ChatSelectionContextFfi, MarmotStatus> {
        Ok(ChatSelectionContextFfi {
            host: unsafe { self.host.to_ffi() }?,
            overlays: unsafe { self.overlays.to_ffi() }?,
            capture_now_ms: self.capture_now_ms,
        })
    }
}

/// Borrowed input; all pointers remain caller-owned for the duration of the call.
#[repr(C)]
pub struct MarmotChatSelectionOpenInput {
    pub scope: MarmotChatSelectionScopeInput,
    pub base: MarmotChatSelectionBaseScopeInput,
    pub context: MarmotChatSelectionContextInput,
}
impl MarmotChatSelectionOpenInput {
    /// # Safety
    /// Every active pointer must reference valid aligned values/UTF-8 C strings for its declared length.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ChatSelectionOpenFfi, MarmotStatus> {
        Ok(ChatSelectionOpenFfi {
            scope: unsafe { self.scope.to_ffi() }?,
            base: self.base.to_ffi()?,
            context: unsafe { self.context.to_ffi() }?,
        })
    }
}

/// Borrowed input; all pointers remain caller-owned for the duration of the call.
#[repr(C)]
pub struct MarmotChatSelectionAnswerInput {
    pub candidate_slot: u64,
    pub leaf_slot: u32,
    pub matches: u8,
}
impl MarmotChatSelectionAnswerInput {
    /// # Safety
    /// Every active pointer must reference valid aligned values/UTF-8 C strings for its declared length.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ChatSelectionAnswerFfi, MarmotStatus> {
        Ok(ChatSelectionAnswerFfi {
            candidate_slot: self.candidate_slot,
            leaf_slot: self.leaf_slot,
            matches: c_bool(self.matches),
        })
    }
}

/// Borrowed input; all pointers remain caller-owned for the duration of the call.
#[repr(C)]
pub struct MarmotChatSelectionActionInput {
    pub operation_id: u64,
    pub attempt_id: u64,
    pub revision: u64,
    pub group_id_hex: *const c_char,
    pub context: MarmotChatSelectionContextInput,
}
impl MarmotChatSelectionActionInput {
    /// # Safety
    /// Every active pointer must reference valid aligned values/UTF-8 C strings for its declared length.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ChatSelectionActionFfi, MarmotStatus> {
        Ok(ChatSelectionActionFfi {
            operation_id: self.operation_id,
            attempt_id: self.attempt_id,
            revision: self.revision,
            group_id_hex: unsafe { memory::required_str(self.group_id_hex) }?,
            context: unsafe { self.context.to_ffi() }?,
        })
    }
}

/// tag0=Archive,1=DeleteLocal. archived uses the shared nonzero boolean rule.
#[repr(C)]
pub struct MarmotChatSelectionMutationInput {
    pub tag: u32,
    pub archived: u8,
}
impl MarmotChatSelectionMutationInput {
    /// # Safety
    /// The input record must be valid for this call; no nested allocation is retained.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ChatSelectionMutationFfi, MarmotStatus> {
        match self.tag {
            0 => Ok(ChatSelectionMutationFfi::Archive {
                archived: c_bool(self.archived),
            }),
            1 => Ok(ChatSelectionMutationFfi::DeleteLocal),
            _ => Err(invalid()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    #[test]
    fn selection_text_retains_nul_and_optional_count_and_nonzero_boolean() {
        let _lock = memory::audit::test_lock();
        let mut text = MarmotChatSelectionText::from(PresentationTextFfi::Literal {
            text: "a\0b".into(),
        });
        match &text {
            MarmotChatSelectionText::Literal { text } => {
                assert_eq!(unsafe { json_text(*text) }.unwrap(), "a\0b")
            }
            _ => panic!("literal"),
        }
        unsafe { text.free_in_place() };
        let answer = MarmotChatSelectionAnswerInput {
            candidate_slot: 7,
            leaf_slot: 3,
            matches: 255,
        };
        assert!(unsafe { answer.to_ffi() }.unwrap().matches);
        let status = MarmotChatSelectionStatus::from(ChatSelectionStatusFfi {
            revision: 1,
            count: None,
            all_archived: None,
            all_direct: Some(false),
            all_abandonable: Some(true),
            presentation_operands: 2,
            operation_id: Some(0),
            last_attempt: None,
            mutation_uncertain: false,
        });
        assert!(
            !status.has_count
                && status.has_all_direct
                && !status.all_direct
                && status.has_all_abandonable
                && status.all_abandonable
                && status.has_operation_id
                && status.operation_id == 0
        );
    }

    #[test]
    fn oversized_automatic_tree_keeps_manual_membership_without_recursing_forever() {
        let manual = CString::new("opaque-original").unwrap();
        let ids = [manual.as_ptr()];
        let mut nodes = Vec::new();
        nodes.push(Box::new(MarmotChatSelectionPredicateInput {
            tag: 1,
            all: 0,
            negated: 0,
            children: std::ptr::null(),
            children_len: 0,
            field: 0,
            mode: 0,
            values: std::ptr::null(),
            values_len: 0,
        }));
        for _ in 0..5 {
            let child = &**nodes.last().unwrap() as *const MarmotChatSelectionPredicateInput;
            nodes.push(Box::new(MarmotChatSelectionPredicateInput {
                tag: 0,
                all: 1,
                negated: 0,
                children: child,
                children_len: 1,
                field: 0,
                mode: 0,
                values: std::ptr::null(),
                values_len: 0,
            }));
        }
        let folder = MarmotChatSelectionFolderInput {
            manual: ids.as_ptr(),
            manual_len: 1,
            excluded: std::ptr::null(),
            excluded_len: 0,
            automatic: MarmotChatSelectionAutomaticRuleInput {
                tag: 1,
                predicate: &**nodes.last().unwrap(),
                legacy: std::ptr::null(),
            },
        };
        let converted = unsafe { folder.to_ffi() }.unwrap();
        assert_eq!(converted.manual, vec!["opaque-original"]);
        assert!(matches!(
            converted.automatic,
            ChatSelectionAutomaticRuleFfi::ManualOnly
        ));
    }

    #[test]
    fn invalid_discriminant_and_json_are_refused_before_host_execution() {
        let predicate = MarmotChatSelectionPredicateInput {
            tag: 1,
            all: 0,
            negated: 0,
            children: std::ptr::null(),
            children_len: 0,
            field: u32::MAX,
            mode: 0,
            values: std::ptr::null(),
            values_len: 0,
        };
        assert!(matches!(
            unsafe { predicate.decode(0, &mut 0) },
            Err(MarmotStatus::InvalidArgument)
        ));
        let raw = CString::new("not-json").unwrap();
        assert!(unsafe { json_text(raw.as_ptr()) }.is_err());
        let json = CString::new("\"a\\u0000b\"").unwrap();
        assert_eq!(unsafe { json_text(json.as_ptr()) }.unwrap(), "a\0b");
        assert_eq!(
            unsafe { CStr::from_ptr(json.as_ptr()) }.to_bytes(),
            b"\"a\\u0000b\""
        );
    }
    #[cfg(feature = "alloc-audit")]
    fn nested_operand() -> ChatSelectionOperandFfi {
        let system = GroupSystemEventFfi {
            provenance: GroupSystemEventProvenanceFfi::AuthenticatedGroupState,
            actor_display_name: Some("actor\0name".into()),
            subject_display_name: Some("subject\0name".into()),
            system_type: "name\0change".into(),
            text: "fallback\0text".into(),
            actor_account_id_hex: Some("actor".into()),
            subject_account_id_hex: Some("subject".into()),
            name: Some("new\0name".into()),
            old_name: Some("old\0name".into()),
            old_retention_seconds: Some(0),
            new_retention_seconds: None,
        };
        let preview = ChatSelectionSearchPreviewMessageFfi {
            message_id_hex: "preview".into(),
            resolved_media_preview_fallback: Some("file\0name".into()),
            plaintext: "preview\0body".into(),
            kind: 9,
            deleted: false,
            attachment_kind: Some(ChatListAttachmentKindFfi::File),
            attachment_count: 1,
            group_system: Some(system),
        };
        ChatSelectionOperandFfi {
            candidate_slot: 7,
            group_id_hex: "opaque-group".into(),
            row_group_name: "row\0title".into(),
            fallback_group_name: "fallback\0title".into(),
            projected_title: Some("projected\0title".into()),
            selected_title: Some(PresentationTextFfi::Literal {
                text: "selected\0title".into(),
            }),
            selected_peer_id_hex: Some("selected-peer".into()),
            roster_peer_id_hex: Some("roster-peer".into()),
            roster_peer_present: true,
            roster_member_count: 2,
            pending_confirmation: false,
            welcomer_id_hex: Some("welcomer".into()),
            conversation_kind: Some(ChatConversationKindFfi::Group),
            active_account_is_sole_member: false,
            description: Some("description\0text".into()),
            leaves: vec![ChatSelectionLeafFfi {
                slot: 3,
                kind: ChatSelectionLeafKindFfi::TitleContains,
                needle: "needle\0text".into(),
            }],
            search: Some(ChatSelectionSearchPresentationFfi {
                scope: ChatSelectionSearchScopeFfi {
                    raw_query: "raw\0query".into(),
                    sql_needle: Some("sql\0needle".into()),
                    message_only: true,
                },
                nostr_group_id_hex: "route".into(),
                last_message: Some(preview),
                messages: vec![ChatSelectionSearchMessageFfi {
                    message_id_hex: "message".into(),
                    sender: "sender".into(),
                    plaintext: "body\0text".into(),
                    kind: 9,
                    timeline_at: 8,
                    deleted: false,
                    retention_seconds: Some(0),
                    retention_expires_at: None,
                    retention_expired: false,
                    media_types: vec!["text/plain".into(), "media\0type".into()],
                }],
                capture_now_ms: 9,
            }),
        }
    }

    #[cfg(feature = "alloc-audit")]
    #[test]
    fn selection_nested_roots_deep_free_restore_allocation_baseline() {
        let _lock = memory::audit::test_lock();
        let baseline = memory::audit::live_allocations();
        let full = nested_operand();
        let mut absent = nested_operand();
        absent.selected_title = Some(PresentationTextFfi::UnnamedGroup { member_count: None });
        absent.projected_title = None;
        absent.search = None;
        absent.description = None;
        absent.leaves.clear();
        let mut unavailable = absent.clone();
        unavailable.selected_title = Some(PresentationTextFfi::UnavailableConversation);
        unavailable.roster_peer_id_hex = None;
        unavailable.welcomer_id_hex = None;
        unavailable.conversation_kind = None;
        let roots = MarmotChatSelectionOperandList::from(vec![full.clone(), absent, unavailable]);
        let root = memory::boxed(roots);
        unsafe {
            marmot_chat_selection_operand_list_free(root);
        }
        let single = memory::boxed(MarmotChatSelectionOperand::from(full));
        unsafe {
            marmot_chat_selection_operand_free(single);
        }
        for ids in [vec!["one".into(), "two".into()], Vec::new()] {
            let page = memory::boxed(MarmotChatSelectionPage::from(ChatSelectionPageFfi {
                revision: 1,
                group_ids: ids.clone(),
            }));
            unsafe {
                marmot_chat_selection_page_free(page);
            }
            let folder = memory::boxed(MarmotChatSelectionFolderPage::from(
                ChatSelectionFolderPageFfi {
                    revision: 1,
                    group_ids: ids,
                    next_after: Some("cursor".into()),
                    done: false,
                },
            ));
            unsafe {
                marmot_chat_selection_folder_page_free(folder);
            }
        }
        let folder = memory::boxed(MarmotChatSelectionFolderPage::from(
            ChatSelectionFolderPageFfi {
                revision: 2,
                group_ids: vec![],
                next_after: None,
                done: true,
            },
        ));
        unsafe {
            marmot_chat_selection_folder_page_free(folder);
        }
        for step in [
            ChatSelectionDepartureStepFfi::Promote {
                member_ref: "member".into(),
            },
            ChatSelectionDepartureStepFfi::SelfDemote,
            ChatSelectionDepartureStepFfi::Leave,
            ChatSelectionDepartureStepFfi::ForgetLocal,
            ChatSelectionDepartureStepFfi::DeleteLocal,
        ] {
            for present in [true, false] {
                let report = memory::boxed(MarmotChatSelectionDepartureReport::from(
                    ChatSelectionDepartureReportFfi {
                        operation_id: 1,
                        attempt_id: 2,
                        revision: 3,
                        group_id_hex: "group".into(),
                        step: step.clone(),
                        summary: present.then(|| SendSummaryFfi {
                            published: 1,
                            message_ids: vec!["event".into()],
                            accept_disposition: SendAcceptDispositionFfi::Published,
                            maintenance_disposition: SendMaintenanceDispositionFfi::Ready,
                        }),
                        changed: true,
                        skipped: false,
                        refusal: present.then_some(ChatSelectionDepartureRefusalFfi::Other),
                        uncertain: false,
                    },
                ));
                unsafe {
                    marmot_chat_selection_departure_report_free(report);
                }
            }
        }
        for mutation in [
            ChatSelectionMutationFfi::Archive { archived: false },
            ChatSelectionMutationFfi::DeleteLocal,
        ] {
            let report = memory::boxed(MarmotChatSelectionMutationReport::from(
                ChatSelectionMutationReportFfi {
                    mutation,
                    operation_id: 1,
                    attempt_id: 2,
                    revision: 3,
                    applied_group_ids: vec!["applied".into()],
                    failed_group_id: Some("failed".into()),
                    uncertain: true,
                    remaining: 1,
                },
            ));
            unsafe {
                marmot_chat_selection_mutation_report_free(report);
            }
        }
        for values in [vec![true, false], Vec::new()] {
            let membership = memory::boxed(MarmotChatSelectionMembership::from(values));
            unsafe {
                marmot_chat_selection_membership_free(membership);
            }
        }
        let summary = memory::boxed(MarmotChatSelectionSummary::from(ChatSelectionSummaryFfi {
            revision: 1,
            count: 0,
        }));
        unsafe {
            marmot_chat_selection_summary_free(summary);
        }
        let status = memory::boxed(MarmotChatSelectionStatus::from(ChatSelectionStatusFfi {
            revision: 1,
            count: Some(0),
            all_archived: Some(false),
            all_direct: None,
            all_abandonable: None,
            presentation_operands: 0,
            operation_id: None,
            last_attempt: None,
            mutation_uncertain: false,
        }));
        unsafe {
            marmot_chat_selection_status_free(status);
        }
        unsafe {
            marmot_chat_selection_operand_list_free(std::ptr::null_mut());
            marmot_chat_selection_departure_report_free(std::ptr::null_mut());
        }
        assert_eq!(memory::audit::live_allocations(), baseline);
    }
}
