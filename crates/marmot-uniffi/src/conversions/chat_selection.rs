//! Mechanical complete-selection boundary. Host predicates remain outside SQL.
use super::*;
use crate::MarmotKitError;
use marmot_app as app;
use std::collections::HashMap;
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ChatSelectionFieldFfi {
    Unread,
    Mentions,
    Muted,
    Pinned,
    Archived,
    Type,
    Accepted,
    Draft,
    PendingSend,
    Title,
    Participants,
}
impl From<ChatSelectionFieldFfi> for app::ChatSelectionField {
    fn from(v: ChatSelectionFieldFfi) -> Self {
        match v {
            ChatSelectionFieldFfi::Unread => Self::Unread,
            ChatSelectionFieldFfi::Mentions => Self::Mentions,
            ChatSelectionFieldFfi::Muted => Self::Muted,
            ChatSelectionFieldFfi::Pinned => Self::Pinned,
            ChatSelectionFieldFfi::Archived => Self::Archived,
            ChatSelectionFieldFfi::Type => Self::Type,
            ChatSelectionFieldFfi::Accepted => Self::Accepted,
            ChatSelectionFieldFfi::Draft => Self::Draft,
            ChatSelectionFieldFfi::PendingSend => Self::PendingSend,
            ChatSelectionFieldFfi::Title => Self::Title,
            ChatSelectionFieldFfi::Participants => Self::Participants,
        }
    }
}
impl From<app::ChatSelectionField> for ChatSelectionFieldFfi {
    fn from(v: app::ChatSelectionField) -> Self {
        match v {
            app::ChatSelectionField::Unread => Self::Unread,
            app::ChatSelectionField::Mentions => Self::Mentions,
            app::ChatSelectionField::Muted => Self::Muted,
            app::ChatSelectionField::Pinned => Self::Pinned,
            app::ChatSelectionField::Archived => Self::Archived,
            app::ChatSelectionField::Type => Self::Type,
            app::ChatSelectionField::Accepted => Self::Accepted,
            app::ChatSelectionField::Draft => Self::Draft,
            app::ChatSelectionField::PendingSend => Self::PendingSend,
            app::ChatSelectionField::Title => Self::Title,
            app::ChatSelectionField::Participants => Self::Participants,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ChatSelectionModeFfi {
    Present,
    None,
    Direct,
    Group,
    AnyOf,
    AllOf,
    Excludes,
    Contains,
}
impl From<ChatSelectionModeFfi> for app::ChatSelectionMode {
    fn from(v: ChatSelectionModeFfi) -> Self {
        match v {
            ChatSelectionModeFfi::Present => Self::Present,
            ChatSelectionModeFfi::None => Self::None,
            ChatSelectionModeFfi::Direct => Self::Direct,
            ChatSelectionModeFfi::Group => Self::Group,
            ChatSelectionModeFfi::AnyOf => Self::AnyOf,
            ChatSelectionModeFfi::AllOf => Self::AllOf,
            ChatSelectionModeFfi::Excludes => Self::Excludes,
            ChatSelectionModeFfi::Contains => Self::Contains,
        }
    }
}
impl From<app::ChatSelectionMode> for ChatSelectionModeFfi {
    fn from(v: app::ChatSelectionMode) -> Self {
        match v {
            app::ChatSelectionMode::Present => Self::Present,
            app::ChatSelectionMode::None => Self::None,
            app::ChatSelectionMode::Direct => Self::Direct,
            app::ChatSelectionMode::Group => Self::Group,
            app::ChatSelectionMode::AnyOf => Self::AnyOf,
            app::ChatSelectionMode::AllOf => Self::AllOf,
            app::ChatSelectionMode::Excludes => Self::Excludes,
            app::ChatSelectionMode::Contains => Self::Contains,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ChatSelectionSendingFfi {
    Sending,
    SuppressNative,
}
impl From<ChatSelectionSendingFfi> for app::ChatSelectionSending {
    fn from(v: ChatSelectionSendingFfi) -> Self {
        match v {
            ChatSelectionSendingFfi::Sending => Self::Sending,
            ChatSelectionSendingFfi::SuppressNative => Self::SuppressNative,
        }
    }
}
impl From<app::ChatSelectionSending> for ChatSelectionSendingFfi {
    fn from(v: app::ChatSelectionSending) -> Self {
        match v {
            app::ChatSelectionSending::Sending => Self::Sending,
            app::ChatSelectionSending::SuppressNative => Self::SuppressNative,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ChatSelectionLeafKindFfi {
    TitleContains,
    LegacyKeyword,
    IsDirect,
    LegacyPeerEquals,
    ChatSearch,
}
impl From<ChatSelectionLeafKindFfi> for app::ChatSelectionLeafKind {
    fn from(v: ChatSelectionLeafKindFfi) -> Self {
        match v {
            ChatSelectionLeafKindFfi::TitleContains => Self::TitleContains,
            ChatSelectionLeafKindFfi::LegacyKeyword => Self::LegacyKeyword,
            ChatSelectionLeafKindFfi::IsDirect => Self::IsDirect,
            ChatSelectionLeafKindFfi::LegacyPeerEquals => Self::LegacyPeerEquals,
            ChatSelectionLeafKindFfi::ChatSearch => Self::ChatSearch,
        }
    }
}
impl From<app::ChatSelectionLeafKind> for ChatSelectionLeafKindFfi {
    fn from(v: app::ChatSelectionLeafKind) -> Self {
        match v {
            app::ChatSelectionLeafKind::TitleContains => Self::TitleContains,
            app::ChatSelectionLeafKind::LegacyKeyword => Self::LegacyKeyword,
            app::ChatSelectionLeafKind::IsDirect => Self::IsDirect,
            app::ChatSelectionLeafKind::LegacyPeerEquals => Self::LegacyPeerEquals,
            app::ChatSelectionLeafKind::ChatSearch => Self::ChatSearch,
        }
    }
}
#[derive(Clone, uniffi::Enum)]
pub enum ChatSelectionPredicateFfi {
    Group {
        all: bool,
        children: Vec<ChatSelectionPredicateFfi>,
        not: bool,
    },
    Condition {
        field: ChatSelectionFieldFfi,
        mode: ChatSelectionModeFfi,
        values: Vec<String>,
        not: bool,
    },
}
redact!(ChatSelectionPredicateFfi);
impl From<ChatSelectionPredicateFfi> for app::ChatSelectionPredicate {
    fn from(v: ChatSelectionPredicateFfi) -> Self {
        match v {
            ChatSelectionPredicateFfi::Group { all, children, not } => Self::Group {
                all,
                children: children.into_iter().map(Into::into).collect(),
                not,
            },
            ChatSelectionPredicateFfi::Condition {
                field,
                mode,
                values,
                not,
            } => Self::Condition {
                field: field.into(),
                mode: mode.into(),
                values,
                not,
            },
        }
    }
}
#[derive(Clone, uniffi::Enum)]
pub enum ChatSelectionAutomaticRuleFfi {
    ManualOnly,
    Smart {
        predicate: ChatSelectionPredicateFfi,
    },
    Legacy {
        rule: ChatSelectionLegacyRuleFfi,
    },
}
redact!(ChatSelectionAutomaticRuleFfi);
impl From<ChatSelectionAutomaticRuleFfi> for app::ChatSelectionAutomaticRule {
    fn from(v: ChatSelectionAutomaticRuleFfi) -> Self {
        match v {
            ChatSelectionAutomaticRuleFfi::ManualOnly => Self::ManualOnly,
            ChatSelectionAutomaticRuleFfi::Smart { predicate } => Self::Smart(predicate.into()),
            ChatSelectionAutomaticRuleFfi::Legacy { rule } => Self::Legacy(rule.into()),
        }
    }
}
#[derive(Clone, uniffi::Enum)]
pub enum ChatSelectionBaseScopeFfi {
    View { view: ChatListViewFfi },
    ActiveAndArchived,
}
impl From<ChatSelectionBaseScopeFfi> for app::ChatSelectionBaseScope {
    fn from(v: ChatSelectionBaseScopeFfi) -> Self {
        match v {
            ChatSelectionBaseScopeFfi::View { view } => Self::View(view.into()),
            ChatSelectionBaseScopeFfi::ActiveAndArchived => Self::ActiveAndArchived,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionLegacyRuleFfi {
    pub members: Vec<String>,
    pub keyword: Option<String>,
    pub include_all: bool,
    pub unread_only: bool,
    pub unread_mentions_only: bool,
    pub pinned_only: bool,
    pub groups_only: bool,
    pub direct_only: bool,
    pub archived_only: bool,
    pub include_muted: bool,
}
redact!(ChatSelectionLegacyRuleFfi);
impl From<ChatSelectionLegacyRuleFfi> for app::ChatSelectionLegacyRule {
    fn from(v: ChatSelectionLegacyRuleFfi) -> Self {
        Self {
            members: v.members,
            keyword: v.keyword,
            include_all: v.include_all,
            unread_only: v.unread_only,
            unread_mentions_only: v.unread_mentions_only,
            pinned_only: v.pinned_only,
            groups_only: v.groups_only,
            direct_only: v.direct_only,
            archived_only: v.archived_only,
            include_muted: v.include_muted,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionFolderFfi {
    pub manual: Vec<String>,
    pub excluded: Vec<String>,
    pub automatic: ChatSelectionAutomaticRuleFfi,
}
redact!(ChatSelectionFolderFfi);
impl From<ChatSelectionFolderFfi> for app::ChatSelectionFolder {
    fn from(v: ChatSelectionFolderFfi) -> Self {
        Self {
            manual: v.manual.into_iter().collect(),
            excluded: v.excluded.into_iter().collect(),
            automatic: v.automatic.into(),
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionSearchScopeFfi {
    pub raw_query: String,
    pub sql_needle: Option<String>,
    pub message_only: bool,
}
redact!(ChatSelectionSearchScopeFfi);
impl From<app::ChatSelectionSearchScope> for ChatSelectionSearchScopeFfi {
    fn from(v: app::ChatSelectionSearchScope) -> Self {
        Self {
            raw_query: v.raw_query,
            sql_needle: v.sql_needle,
            message_only: v.message_only,
        }
    }
}
impl From<ChatSelectionSearchScopeFfi> for app::ChatSelectionSearchScope {
    fn from(v: ChatSelectionSearchScopeFfi) -> Self {
        Self {
            raw_query: v.raw_query,
            sql_needle: v.sql_needle,
            message_only: v.message_only,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionScopeFfi {
    pub selected_folder: Option<ChatSelectionFolderFfi>,
    pub filter_folders: Option<Vec<ChatSelectionFolderFfi>>,
    pub named_chats: Option<Vec<String>>,
    pub direct: bool,
    pub groups: bool,
    pub search: Option<ChatSelectionSearchScopeFfi>,
}
redact!(ChatSelectionScopeFfi);
impl From<ChatSelectionScopeFfi> for app::ChatSelectionScope {
    fn from(v: ChatSelectionScopeFfi) -> Self {
        Self {
            selected_folder: v.selected_folder.map(Into::into),
            filter_folders: v
                .filter_folders
                .map(|v| v.into_iter().map(Into::into).collect()),
            named_chats: v.named_chats.map(|v| v.into_iter().collect()),
            direct: v.direct,
            groups: v.groups,
            search: v.search.map(Into::into),
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionHostContextFfi {
    pub account_id_hex: String,
    pub runtime_generation: i64,
    pub selection_generation: u64,
    pub presentation_context_id: u64,
}
redact!(ChatSelectionHostContextFfi);
impl From<app::ChatSelectionHostContext> for ChatSelectionHostContextFfi {
    fn from(v: app::ChatSelectionHostContext) -> Self {
        Self {
            account_id_hex: v.account_id_hex,
            runtime_generation: v.runtime_generation,
            selection_generation: v.selection_generation,
            presentation_context_id: v.presentation_context_id,
        }
    }
}
impl From<ChatSelectionHostContextFfi> for app::ChatSelectionHostContext {
    fn from(v: ChatSelectionHostContextFfi) -> Self {
        Self {
            account_id_hex: v.account_id_hex,
            runtime_generation: v.runtime_generation,
            selection_generation: v.selection_generation,
            presentation_context_id: v.presentation_context_id,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionSearchPreviewMessageFfi {
    pub message_id_hex: String,
    pub resolved_media_preview_fallback: Option<String>,
    pub plaintext: String,
    pub kind: u64,
    pub deleted: bool,
    pub attachment_kind: Option<ChatListAttachmentKindFfi>,
    pub attachment_count: u32,
    pub group_system: Option<GroupSystemEventFfi>,
}
redact!(ChatSelectionSearchPreviewMessageFfi);
impl From<app::ChatSelectionSearchPreviewMessage> for ChatSelectionSearchPreviewMessageFfi {
    fn from(v: app::ChatSelectionSearchPreviewMessage) -> Self {
        Self {
            message_id_hex: v.message_id_hex,
            resolved_media_preview_fallback: v.resolved_media_preview_fallback,
            plaintext: v.plaintext,
            kind: v.kind,
            deleted: v.deleted,
            attachment_kind: v.attachment_kind.map(Into::into),
            attachment_count: v.attachment_count,
            group_system: v.group_system.map(Into::into),
        }
    }
}
fn native_attachment(v: ChatListAttachmentKindFfi) -> app::ChatListAttachmentKind {
    match v {
        ChatListAttachmentKindFfi::Photo => app::ChatListAttachmentKind::Photo,
        ChatListAttachmentKindFfi::Video => app::ChatListAttachmentKind::Video,
        ChatListAttachmentKindFfi::Audio => app::ChatListAttachmentKind::Audio,
        ChatListAttachmentKindFfi::File => app::ChatListAttachmentKind::File,
        ChatListAttachmentKindFfi::Mixed => app::ChatListAttachmentKind::Mixed,
    }
}
fn native_system(v: GroupSystemEventFfi) -> app::AppGroupSystemEvent {
    app::AppGroupSystemEvent {
        provenance: match v.provenance {
            GroupSystemEventProvenanceFfi::AuthenticatedGroupState => {
                app::GroupSystemEventProvenance::AuthenticatedGroupState
            }
            GroupSystemEventProvenanceFfi::MemberAuthored => {
                app::GroupSystemEventProvenance::MemberAuthored
            }
        },
        actor_display_name: v.actor_display_name,
        subject_display_name: v.subject_display_name,
        system_type: v.system_type,
        text: v.text,
        actor_account_id_hex: v.actor_account_id_hex,
        subject_account_id_hex: v.subject_account_id_hex,
        name: v.name,
        old_name: v.old_name,
        old_retention_seconds: v.old_retention_seconds,
        new_retention_seconds: v.new_retention_seconds,
    }
}
impl From<ChatSelectionSearchPreviewMessageFfi> for app::ChatSelectionSearchPreviewMessage {
    fn from(v: ChatSelectionSearchPreviewMessageFfi) -> Self {
        Self {
            message_id_hex: v.message_id_hex,
            resolved_media_preview_fallback: v.resolved_media_preview_fallback,
            plaintext: v.plaintext,
            kind: v.kind,
            deleted: v.deleted,
            attachment_kind: v.attachment_kind.map(native_attachment),
            attachment_count: v.attachment_count,
            group_system: v.group_system.map(native_system),
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionHostOverlaysFfi {
    pub sending: HashMap<String, ChatSelectionSendingFfi>,
    pub muted: HashMap<String, bool>,
    pub removed: Vec<String>,
    pub invite_conflicts: Vec<String>,
    pub preview_overrides: HashMap<String, Option<ChatSelectionSearchPreviewMessageFfi>>,
    pub media_preview_fallbacks: HashMap<String, String>,
}
redact!(ChatSelectionHostOverlaysFfi);
impl From<ChatSelectionHostOverlaysFfi> for app::ChatSelectionHostOverlays {
    fn from(v: ChatSelectionHostOverlaysFfi) -> Self {
        Self {
            sending: v.sending.into_iter().map(|(k, v)| (k, v.into())).collect(),
            muted: v.muted,
            removed: v.removed.into_iter().collect(),
            invite_conflicts: v.invite_conflicts.into_iter().collect(),
            preview_overrides: v
                .preview_overrides
                .into_iter()
                .map(|(k, v)| (k, v.map(Into::into)))
                .collect(),
            media_preview_fallbacks: v.media_preview_fallbacks,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionContextFfi {
    pub host: ChatSelectionHostContextFfi,
    pub overlays: ChatSelectionHostOverlaysFfi,
    pub capture_now_ms: i64,
}
redact!(ChatSelectionContextFfi);
impl From<ChatSelectionContextFfi> for app::ChatSelectionContext {
    fn from(v: ChatSelectionContextFfi) -> Self {
        Self {
            host: v.host.into(),
            overlays: v.overlays.into(),
            capture_now_ms: v.capture_now_ms,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionOpenFfi {
    pub scope: ChatSelectionScopeFfi,
    pub base: ChatSelectionBaseScopeFfi,
    pub context: ChatSelectionContextFfi,
}
redact!(ChatSelectionOpenFfi);
impl From<ChatSelectionOpenFfi> for app::ChatSelectionOpen {
    fn from(v: ChatSelectionOpenFfi) -> Self {
        Self {
            scope: v.scope.into(),
            base: v.base.into(),
            context: v.context.into(),
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionSearchMessageFfi {
    pub message_id_hex: String,
    pub sender: String,
    pub plaintext: String,
    pub kind: u64,
    pub timeline_at: u64,
    pub deleted: bool,
    pub retention_seconds: Option<u64>,
    pub retention_expires_at: Option<u64>,
    pub retention_expired: bool,
    pub media_types: Vec<String>,
}
redact!(ChatSelectionSearchMessageFfi);
impl From<app::ChatSelectionSearchMessage> for ChatSelectionSearchMessageFfi {
    fn from(v: app::ChatSelectionSearchMessage) -> Self {
        Self {
            message_id_hex: v.message_id_hex,
            sender: v.sender,
            plaintext: v.plaintext,
            kind: v.kind,
            timeline_at: v.timeline_at,
            deleted: v.deleted,
            retention_seconds: v.retention_seconds,
            retention_expires_at: v.retention_expires_at,
            retention_expired: v.retention_expired,
            media_types: v.media_types,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionSearchPresentationFfi {
    pub scope: ChatSelectionSearchScopeFfi,
    pub nostr_group_id_hex: String,
    pub last_message: Option<ChatSelectionSearchPreviewMessageFfi>,
    pub messages: Vec<ChatSelectionSearchMessageFfi>,
    pub capture_now_ms: i64,
}
redact!(ChatSelectionSearchPresentationFfi);
impl From<app::ChatSelectionSearchPresentation> for ChatSelectionSearchPresentationFfi {
    fn from(v: app::ChatSelectionSearchPresentation) -> Self {
        Self {
            scope: v.scope.into(),
            nostr_group_id_hex: v.nostr_group_id_hex,
            last_message: v.last_message.map(Into::into),
            messages: v.messages.into_iter().map(Into::into).collect(),
            capture_now_ms: v.capture_now_ms,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionLeafFfi {
    pub slot: u32,
    pub kind: ChatSelectionLeafKindFfi,
    pub needle: String,
}
redact!(ChatSelectionLeafFfi);
impl From<app::ChatSelectionLeaf> for ChatSelectionLeafFfi {
    fn from(v: app::ChatSelectionLeaf) -> Self {
        Self {
            slot: v.slot,
            kind: v.kind.into(),
            needle: v.needle,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionOperandFfi {
    pub candidate_slot: u64,
    pub group_id_hex: String,
    pub row_group_name: String,
    pub fallback_group_name: String,
    pub projected_title: Option<String>,
    pub selected_title: Option<PresentationTextFfi>,
    pub selected_peer_id_hex: Option<String>,
    pub roster_peer_id_hex: Option<String>,
    pub roster_peer_present: bool,
    pub roster_member_count: i32,
    pub pending_confirmation: bool,
    pub welcomer_id_hex: Option<String>,
    pub conversation_kind: Option<ChatConversationKindFfi>,
    pub active_account_is_sole_member: bool,
    pub description: Option<String>,
    pub leaves: Vec<ChatSelectionLeafFfi>,
    pub search: Option<ChatSelectionSearchPresentationFfi>,
}
redact!(ChatSelectionOperandFfi);
impl From<app::ChatSelectionOperand> for ChatSelectionOperandFfi {
    fn from(v: app::ChatSelectionOperand) -> Self {
        Self {
            candidate_slot: v.candidate_slot,
            group_id_hex: v.group_id_hex,
            row_group_name: v.row_group_name,
            fallback_group_name: v.fallback_group_name,
            projected_title: v.projected_title,
            selected_title: v.selected_title.map(Into::into),
            selected_peer_id_hex: v.selected_peer_id_hex,
            roster_peer_id_hex: v.roster_peer_id_hex,
            roster_peer_present: v.roster_peer_present,
            roster_member_count: v.roster_member_count,
            pending_confirmation: v.pending_confirmation,
            welcomer_id_hex: v.welcomer_id_hex,
            conversation_kind: v.conversation_kind.map(Into::into),
            active_account_is_sole_member: v.active_account_is_sole_member,
            description: v.description,
            leaves: v.leaves.into_iter().map(Into::into).collect(),
            search: v.search.map(Into::into),
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionAnswerFfi {
    pub candidate_slot: u64,
    pub leaf_slot: u32,
    pub matches: bool,
}
redact!(ChatSelectionAnswerFfi);
impl From<ChatSelectionAnswerFfi> for app::ChatSelectionAnswer {
    fn from(v: ChatSelectionAnswerFfi) -> Self {
        Self {
            candidate_slot: v.candidate_slot,
            leaf_slot: v.leaf_slot,
            matches: v.matches,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionStatusFfi {
    pub revision: u64,
    pub count: Option<u64>,
    pub all_archived: Option<bool>,
    pub all_direct: Option<bool>,
    pub all_abandonable: Option<bool>,
    pub presentation_operands: u64,
    pub operation_id: Option<u64>,
    pub last_attempt: Option<u64>,
    pub mutation_uncertain: bool,
}
redact!(ChatSelectionStatusFfi);
impl TryFrom<app::ChatSelectionStatus> for ChatSelectionStatusFfi {
    type Error = MarmotKitError;
    fn try_from(v: app::ChatSelectionStatus) -> Result<Self, Self::Error> {
        Ok(Self {
            revision: v.revision,
            count: v
                .count
                .map(u64::try_from)
                .transpose()
                .map_err(|_| MarmotKitError::ChatSelectionResourceExhausted)?,
            all_archived: v.all_archived,
            all_direct: v.all_direct,
            all_abandonable: v.all_abandonable,
            presentation_operands: v
                .presentation_operands
                .try_into()
                .map_err(|_| MarmotKitError::ChatSelectionResourceExhausted)?,
            operation_id: v.operation_id,
            last_attempt: v.last_attempt,
            mutation_uncertain: v.mutation_uncertain,
        })
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionSummaryFfi {
    pub revision: u64,
    pub count: u64,
}
redact!(ChatSelectionSummaryFfi);
impl TryFrom<app::ChatListSelectionSummary> for ChatSelectionSummaryFfi {
    type Error = MarmotKitError;
    fn try_from(v: app::ChatListSelectionSummary) -> Result<Self, Self::Error> {
        Ok(Self {
            revision: v.revision,
            count: v
                .count
                .try_into()
                .map_err(|_| MarmotKitError::ChatSelectionResourceExhausted)?,
        })
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionPageFfi {
    pub revision: u64,
    pub group_ids: Vec<String>,
}
redact!(ChatSelectionPageFfi);
impl From<app::ChatListSelectionPage> for ChatSelectionPageFfi {
    fn from(v: app::ChatListSelectionPage) -> Self {
        Self {
            revision: v.revision,
            group_ids: v.group_ids,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ChatSelectionMutationFfi {
    Archive { archived: bool },
    DeleteLocal,
}
impl From<ChatSelectionMutationFfi> for app::ChatSelectionMutation {
    fn from(v: ChatSelectionMutationFfi) -> Self {
        match v {
            ChatSelectionMutationFfi::Archive { archived } => Self::Archive { archived },
            ChatSelectionMutationFfi::DeleteLocal => Self::DeleteLocal,
        }
    }
}
impl From<app::ChatSelectionMutation> for ChatSelectionMutationFfi {
    fn from(v: app::ChatSelectionMutation) -> Self {
        match v {
            app::ChatSelectionMutation::Archive { archived } => Self::Archive { archived },
            app::ChatSelectionMutation::DeleteLocal => Self::DeleteLocal,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionMutationReportFfi {
    pub mutation: ChatSelectionMutationFfi,
    pub operation_id: u64,
    pub attempt_id: u64,
    pub revision: u64,
    pub applied_group_ids: Vec<String>,
    pub failed_group_id: Option<String>,
    pub uncertain: bool,
    pub remaining: u64,
}
redact!(ChatSelectionMutationReportFfi);
impl TryFrom<app::ChatSelectionMutationReport> for ChatSelectionMutationReportFfi {
    type Error = MarmotKitError;
    fn try_from(v: app::ChatSelectionMutationReport) -> Result<Self, Self::Error> {
        Ok(Self {
            mutation: v.mutation.into(),
            operation_id: v.operation_id,
            attempt_id: v.attempt_id,
            revision: v.revision,
            applied_group_ids: v.applied_group_ids,
            failed_group_id: v.failed_group_id,
            uncertain: v.uncertain,
            remaining: v
                .remaining
                .try_into()
                .map_err(|_| MarmotKitError::ChatSelectionResourceExhausted)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chat_selection_boundary_preserves_unresolved_count_empty_union_and_opaque_manual_ids() {
        let status = app::ChatSelectionStatus {
            revision: 3,
            count: None,
            all_archived: None,
            all_direct: None,
            all_abandonable: None,
            presentation_operands: 1,
            operation_id: None,
            last_attempt: None,
            mutation_uncertain: false,
        };
        assert_eq!(
            ChatSelectionStatusFfi::try_from(status).unwrap().count,
            None
        );
        assert_eq!(
            ChatSelectionStatusFfi::try_from(app::ChatSelectionStatus {
                count: Some(0),
                ..status
            })
            .unwrap()
            .count,
            Some(0)
        );
        let native: app::ChatSelectionScope = ChatSelectionScopeFfi {
            selected_folder: Some(ChatSelectionFolderFfi {
                manual: vec!["aa".into(), "legacy-id".into()],
                excluded: vec!["old opaque".into()],
                automatic: ChatSelectionAutomaticRuleFfi::ManualOnly,
            }),
            filter_folders: Some(vec![]),
            named_chats: Some(vec![]),
            direct: false,
            groups: false,
            search: None,
        }
        .into();
        assert!(native.filter_folders.unwrap().is_empty());
        assert!(native.named_chats.unwrap().is_empty());
        let selected = native.selected_folder.unwrap();
        assert!(selected.manual.contains("legacy-id") && selected.manual.contains("aa"));
        assert!(selected.excluded.contains("old opaque"));
        let predicate: app::ChatSelectionPredicate = ChatSelectionPredicateFfi::Group {
            all: false,
            not: true,
            children: vec![ChatSelectionPredicateFfi::Condition {
                field: ChatSelectionFieldFfi::Participants,
                mode: ChatSelectionModeFfi::None,
                values: vec!["private-key-sentinel".into()],
                not: true,
            }],
        }
        .into();
        assert!(matches!(
            predicate,
            app::ChatSelectionPredicate::Group {
                all: false,
                not: true,
                ..
            }
        ));
        assert!(!format!("{predicate:?}").contains("sentinel"));
    }
    #[test]
    fn chat_selection_preview_boundary_preserves_message_binding_and_never_adds_body_media_authority()
     {
        let input = ChatSelectionSearchPreviewMessageFfi {
            message_id_hex: "message-sentinel".into(),
            resolved_media_preview_fallback: Some("document-sentinel".into()),
            plaintext: String::new(),
            kind: 9,
            deleted: false,
            attachment_kind: None,
            attachment_count: 0,
            group_system: None,
        };
        let native: app::ChatSelectionSearchPreviewMessage = input.clone().into();
        assert_eq!(native.message_id_hex, "message-sentinel");
        let output: ChatSelectionSearchPreviewMessageFfi = native.into();
        assert_eq!(
            output.resolved_media_preview_fallback,
            input.resolved_media_preview_fallback
        );
        assert!(!format!("{input:?} {output:?}").contains("sentinel"));
    }
}

/// One explicit invocation of the existing per-target departure/journal flow.
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionActionFfi {
    pub operation_id: u64,
    pub attempt_id: u64,
    pub revision: u64,
    pub group_id_hex: String,
    pub context: ChatSelectionContextFfi,
}
redact!(ChatSelectionActionFfi);
#[derive(Clone, uniffi::Enum)]
pub enum ChatSelectionDepartureStepFfi {
    Promote { member_ref: String },
    SelfDemote,
    Leave,
    ForgetLocal,
    DeleteLocal,
}
redact!(ChatSelectionDepartureStepFfi);
impl From<app::ChatSelectionDepartureStep> for ChatSelectionDepartureStepFfi {
    fn from(v: app::ChatSelectionDepartureStep) -> Self {
        match v {
            app::ChatSelectionDepartureStep::Promote { member_ref } => Self::Promote { member_ref },
            app::ChatSelectionDepartureStep::SelfDemote => Self::SelfDemote,
            app::ChatSelectionDepartureStep::Leave => Self::Leave,
            app::ChatSelectionDepartureStep::ForgetLocal => Self::ForgetLocal,
            app::ChatSelectionDepartureStep::DeleteLocal => Self::DeleteLocal,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ChatSelectionDepartureRefusalFfi {
    CatchingUp,
    CommitUndelivered,
    Other,
}
#[derive(Clone, uniffi::Record)]
pub struct ChatSelectionDepartureReportFfi {
    pub operation_id: u64,
    pub attempt_id: u64,
    pub revision: u64,
    pub group_id_hex: String,
    pub step: ChatSelectionDepartureStepFfi,
    pub summary: Option<SendSummaryFfi>,
    pub changed: bool,
    pub skipped: bool,
    pub refusal: Option<ChatSelectionDepartureRefusalFfi>,
    pub uncertain: bool,
}
redact!(ChatSelectionDepartureReportFfi);
impl From<app::ChatSelectionDepartureReport> for ChatSelectionDepartureReportFfi {
    fn from(v: app::ChatSelectionDepartureReport) -> Self {
        let refusal = v.refusal.as_deref().map(|e| match e {
            app::AppError::GroupCatchingUp(_) => ChatSelectionDepartureRefusalFfi::CatchingUp,
            app::AppError::GroupCommitUndelivered(_) => {
                ChatSelectionDepartureRefusalFfi::CommitUndelivered
            }
            _ => ChatSelectionDepartureRefusalFfi::Other,
        });
        Self {
            operation_id: v.operation_id,
            attempt_id: v.attempt_id,
            revision: v.revision,
            group_id_hex: v.group_id_hex,
            step: v.step.into(),
            summary: v.summary.map(Into::into),
            changed: v.changed,
            skipped: v.skipped,
            refusal,
            uncertain: v.uncertain,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ChatSelectionFolderPageFfi {
    pub revision: u64,
    pub group_ids: Vec<String>,
    pub next_after: Option<String>,
    pub done: bool,
}
redact!(ChatSelectionFolderPageFfi);
impl From<app::ChatSelectionFolderPage> for ChatSelectionFolderPageFfi {
    fn from(v: app::ChatSelectionFolderPage) -> Self {
        Self {
            revision: v.revision,
            group_ids: v.group_ids,
            next_after: v.next_after,
            done: v.done,
        }
    }
}
