//! Prepared conversation screen values. No profile/roster reads occur in this mapper.
use super::*;
use marmot_app as app;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum ConversationOpenModeFfi {
    Automatic,
    Latest,
    Message,
}
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum ConversationPageDirectionFfi {
    Older,
    Newer,
}
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum ConversationParticipationFfi {
    PendingInvitation,
    Active,
    Leaving,
    Left,
    Removed,
    Disbanded,
    Unavailable,
}
impl From<app::conversation_presentation::ConversationParticipation>
    for ConversationParticipationFfi
{
    fn from(v: app::conversation_presentation::ConversationParticipation) -> Self {
        match v {
            app::conversation_presentation::ConversationParticipation::PendingInvitation => {
                Self::PendingInvitation
            }
            app::conversation_presentation::ConversationParticipation::Active => Self::Active,
            app::conversation_presentation::ConversationParticipation::Leaving => Self::Leaving,
            app::conversation_presentation::ConversationParticipation::Left => Self::Left,
            app::conversation_presentation::ConversationParticipation::Removed => Self::Removed,
            app::conversation_presentation::ConversationParticipation::Disbanded => Self::Disbanded,
            app::conversation_presentation::ConversationParticipation::Unavailable => {
                Self::Unavailable
            }
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ConversationCapabilitiesFfi {
    pub participation: ConversationParticipationFfi,
    pub is_self_admin: bool,
    pub is_last_admin: bool,
    pub can_send: bool,
    pub can_invite: bool,
    pub can_edit_group: bool,
    pub can_leave: bool,
    pub requires_self_demote_before_leave: bool,
    pub can_enable_disbanding: bool,
    pub can_disband: bool,
}
impl From<app::conversation_presentation::ConversationCapabilities>
    for ConversationCapabilitiesFfi
{
    fn from(v: app::conversation_presentation::ConversationCapabilities) -> Self {
        Self {
            participation: v.participation.into(),
            is_self_admin: v.is_self_admin,
            is_last_admin: v.is_last_admin,
            can_send: v.can_send,
            can_invite: v.can_invite,
            can_edit_group: v.can_edit_group,
            can_leave: v.can_leave,
            requires_self_demote_before_leave: v.requires_self_demote_before_leave,
            can_enable_disbanding: v.can_enable_disbanding,
            can_disband: v.can_disband,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ConversationHeaderFfi {
    pub selected: ConversationPresentationFfi,
    pub member_count: Option<u64>,
    pub archived: bool,
    pub epoch: Option<u64>,
    pub lifecycle: GroupLifecycleStateFfi,
    pub disbanding: bool,
    pub unrecoverable: bool,
    pub capabilities: ConversationCapabilitiesFfi,
}
impl From<app::conversation_presentation::ConversationHeader> for ConversationHeaderFfi {
    fn from(v: app::conversation_presentation::ConversationHeader) -> Self {
        Self {
            selected: v.selected.into(),
            member_count: v.member_count,
            archived: v.archived,
            epoch: v.epoch,
            lifecycle: v.lifecycle.into(),
            disbanding: v.disbanding,
            unrecoverable: v.unrecoverable,
            capabilities: v.capabilities.into(),
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ConversationIdentityFfi {
    pub account_id_hex: String,
    pub display_name: String,
    pub avatar: SelectedAvatarFfi,
    pub has_cached_profile: bool,
}
impl From<app::conversation_presentation::ConversationIdentity> for ConversationIdentityFfi {
    fn from(v: app::conversation_presentation::ConversationIdentity) -> Self {
        Self {
            account_id_hex: v.account_id_hex,
            display_name: v.display_name,
            avatar: v.avatar.into(),
            has_cached_profile: v.has_cached_profile,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ConversationSystemReferencesFfi {
    pub system_type: String,
    pub actor: Option<String>,
    pub subject: Option<String>,
}
impl From<app::conversation_presentation::ConversationSystemReferences>
    for ConversationSystemReferencesFfi
{
    fn from(v: app::conversation_presentation::ConversationSystemReferences) -> Self {
        Self {
            system_type: v.system_type,
            actor: v.actor,
            subject: v.subject,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ConversationReactionFfi {
    pub emoji: String,
    pub count: u64,
    pub reactors: Vec<String>,
    /// Active reaction by the viewing account; independent of reactor previews.
    pub viewer_reacted: bool,
}
impl From<app::conversation_presentation::ConversationReaction> for ConversationReactionFfi {
    fn from(v: app::conversation_presentation::ConversationReaction) -> Self {
        Self {
            emoji: v.emoji,
            count: v.count as u64,
            reactors: v.reactors,
            viewer_reacted: v.viewer_reacted,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ConversationReactionsFfi {
    pub total_count: u64,
    pub total_kinds: u64,
    pub items: Vec<ConversationReactionFfi>,
    pub omitted_kinds: u64,
}
impl From<app::conversation_presentation::ConversationReactions> for ConversationReactionsFfi {
    fn from(v: app::conversation_presentation::ConversationReactions) -> Self {
        Self {
            total_count: v.total_count as u64,
            total_kinds: v.total_kinds as u64,
            items: v.items.into_iter().map(Into::into).collect(),
            omitted_kinds: v.omitted_kinds as u64,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ConversationMessageReferencesFfi {
    pub message_id_hex: String,
    pub sender: Option<String>,
    pub reply_author: Option<String>,
    pub mentions: Vec<String>,
    pub mentions_truncated: bool,
    pub reply_mentions: Vec<String>,
    pub reply_mentions_truncated: bool,
    pub system: Option<ConversationSystemReferencesFfi>,
    pub reactions: ConversationReactionsFfi,
}
impl From<app::conversation_presentation::ConversationMessageReferences>
    for ConversationMessageReferencesFfi
{
    fn from(v: app::conversation_presentation::ConversationMessageReferences) -> Self {
        Self {
            message_id_hex: v.message_id_hex,
            sender: v.sender,
            reply_author: v.reply_author,
            mentions: v.mentions,
            mentions_truncated: v.mentions_truncated,
            reply_mentions: v.reply_mentions,
            reply_mentions_truncated: v.reply_mentions_truncated,
            system: v.system.map(Into::into),
            reactions: v.reactions.into(),
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ConversationOpenReadStateFfi {
    pub initialized: bool,
    pub last_read_message_id_hex: Option<String>,
    pub last_read_timeline_at: Option<u64>,
    pub manually_marked_unread: bool,
    pub unread_count: u64,
    pub unread_mention_count: u64,
    pub first_unread_message_id_hex: Option<String>,
}
impl From<app::ConversationOpenReadState> for ConversationOpenReadStateFfi {
    fn from(v: app::ConversationOpenReadState) -> Self {
        Self {
            initialized: v.initialized,
            last_read_message_id_hex: v.last_read_message_id_hex,
            last_read_timeline_at: v.last_read_timeline_at,
            manually_marked_unread: v.manually_marked_unread,
            unread_count: v.unread_count,
            unread_mention_count: v.unread_mention_count,
            first_unread_message_id_hex: v.first_unread_message_id_hex,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct SelectedMessageDraftAttachmentFfi {
    pub id: String,
    pub file_name: String,
    pub media_type: String,
    pub plaintext_size: u64,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
    pub duration_seconds: Option<f64>,
    pub waveform_samples: Vec<f64>,
}
impl From<app::SelectedMessageDraftAttachment> for SelectedMessageDraftAttachmentFfi {
    fn from(v: app::SelectedMessageDraftAttachment) -> Self {
        Self {
            id: v.id,
            file_name: v.file_name,
            media_type: v.media_type,
            plaintext_size: v.plaintext_size,
            dim: v.dim,
            thumbhash: v.thumbhash,
            duration_seconds: v.duration_seconds,
            waveform_samples: v.waveform_samples,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct SelectedMessageDraftContentFfi {
    pub group_id_hex: String,
    pub content: String,
    pub reply_to_message_id_hex: Option<String>,
    pub media_attachments: Vec<SelectedMessageDraftAttachmentFfi>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}
impl From<app::SelectedMessageDraftContent> for SelectedMessageDraftContentFfi {
    fn from(v: app::SelectedMessageDraftContent) -> Self {
        Self {
            group_id_hex: v.group_id_hex,
            content: v.content,
            reply_to_message_id_hex: v.reply_to_message_id_hex,
            media_attachments: v.media_attachments.into_iter().map(Into::into).collect(),
            created_at_ms: v.created_at_ms,
            updated_at_ms: v.updated_at_ms,
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ConversationWindowRevisionFfi {
    pub generation: String,
    pub sequence: u64,
}
impl From<app::ConversationWindowRevision> for ConversationWindowRevisionFfi {
    fn from(v: app::ConversationWindowRevision) -> Self {
        Self {
            generation: v.generation,
            sequence: v.sequence,
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum ConversationAnchorKindFfi {
    Empty,
    Latest,
    FirstUnread,
    Message,
    Retained,
    RecoveredNext,
    RecoveredPrevious,
}
#[derive(Clone, uniffi::Record)]
pub struct ConversationAnchorOutcomeFfi {
    pub kind: ConversationAnchorKindFfi,
    pub index: Option<u32>,
}
impl From<app::ConversationOpenAnchorOutcome> for ConversationAnchorOutcomeFfi {
    fn from(v: app::ConversationOpenAnchorOutcome) -> Self {
        use app::ConversationOpenAnchorOutcome as A;
        let (kind, index) = match v {
            A::Empty => (ConversationAnchorKindFfi::Empty, None),
            A::Latest { index } => (ConversationAnchorKindFfi::Latest, Some(index as u32)),
            A::FirstUnread { index } => {
                (ConversationAnchorKindFfi::FirstUnread, Some(index as u32))
            }
            A::Message { index } => (ConversationAnchorKindFfi::Message, Some(index as u32)),
            A::Retained { index } => (ConversationAnchorKindFfi::Retained, Some(index as u32)),
            A::RecoveredNext { index } => {
                (ConversationAnchorKindFfi::RecoveredNext, Some(index as u32))
            }
            A::RecoveredPrevious { index } => (
                ConversationAnchorKindFfi::RecoveredPrevious,
                Some(index as u32),
            ),
        };
        Self { kind, index }
    }
}
/// Opaque store/group-scoped revision. Keep this object to perform conditional draft operations.
#[derive(uniffi::Object)]
pub struct MessageDraftRevisionFfi {
    pub(crate) inner: app::MessageDraftRevision,
}
#[derive(Clone, uniffi::Record)]
pub struct SelectedMessageDraftFfi {
    pub revision: Arc<MessageDraftRevisionFfi>,
    pub draft: Option<SelectedMessageDraftContentFfi>,
}
impl From<app::SelectedMessageDraft> for SelectedMessageDraftFfi {
    fn from(v: app::SelectedMessageDraft) -> Self {
        Self {
            revision: Arc::new(MessageDraftRevisionFfi { inner: v.revision }),
            draft: v.draft.map(Into::into),
        }
    }
}
/// Timeline content plus bounded display references. Use references.reactions for UI;
/// the compatibility timeline's raw tags/reactions are deliberately empty here.
#[derive(Clone, uniffi::Record)]
pub struct ConversationMessageFfi {
    pub timeline: TimelineMessageRecordFfi,
    pub references: ConversationMessageReferencesFfi,
}
#[derive(Clone, uniffi::Record)]
pub struct ConversationWindowSnapshotFfi {
    pub revision: ConversationWindowRevisionFfi,
    pub header: ConversationHeaderFfi,
    pub messages: Vec<ConversationMessageFfi>,
    /// One entry per identity required by the bounded display references, keyed by account_id_hex.
    pub identities: Vec<ConversationIdentityFfi>,
    pub read_state: ConversationOpenReadStateFfi,
    pub draft: SelectedMessageDraftFfi,
    pub pending_confirmation: bool,
    pub anchor: ConversationAnchorOutcomeFfi,
    pub has_more_before: bool,
    pub has_more_after: bool,
}
// Borrow raw rows so conversion never clones the full reactor/tag collections.
fn presented_timeline(row: &app::TimelineMessageRecord, trusted: bool) -> TimelineMessageRecordFfi {
    presented_timeline_with_tokens(
        row,
        trusted,
        super::common::markdown_content_tokens(row.kind, &row.plaintext),
    )
}

fn presented_timeline_with_tokens(
    row: &app::TimelineMessageRecord,
    trusted: bool,
    content_tokens: crate::markdown::MarkdownDocumentFfi,
) -> TimelineMessageRecordFfi {
    TimelineMessageRecordFfi {
        edit: row.edit.clone().map(Into::into),
        message_id_hex: row.message_id_hex.clone(),
        source_message_id_hex: row.source_message_id_hex.clone(),
        source_epoch: row.source_epoch,
        retention_seconds: row.retention_seconds,
        retention_expires_at: row.retention_expires_at,
        direction: row.direction.clone(),
        group_id_hex: row.group_id_hex.clone(),
        sender: row.sender.clone(),
        plaintext: row.plaintext.clone(),
        content_tokens,
        kind: row.kind,
        tags: vec![],
        timeline_at: row.timeline_at,
        received_at: row.received_at,
        reply_to_message_id_hex: row.reply_to_message_id_hex.clone(),
        reply_preview: row.reply_preview.clone().map(Into::into),
        media_json: None,
        media: super::media::timeline_media_outcomes_ffi(&row.media, row.source_epoch),
        agent_text_stream_json: row.agent_text_stream.as_ref().map(ToString::to_string),
        group_system: if trusted {
            row.group_system.clone().map(Into::into)
        } else {
            None
        },
        reactions: TimelineReactionSummaryFfi {
            by_emoji: vec![],
            user_reactions: vec![],
        },
        deleted: row.deleted,
        deleted_by_message_id_hex: row.deleted_by_message_id_hex.clone(),
        invalidation_status: row.invalidation_status.clone(),
    }
}
impl From<app::ConversationWindowSnapshot> for ConversationWindowSnapshotFfi {
    fn from(v: app::ConversationWindowSnapshot) -> Self {
        Self::from(&v)
    }
}
impl From<&app::ConversationWindowSnapshot> for ConversationWindowSnapshotFfi {
    fn from(v: &app::ConversationWindowSnapshot) -> Self {
        let page = v.page.page();
        let messages = page
            .messages
            .iter()
            .zip(&v.presentation.messages)
            .enumerate()
            .map(|(i, (row, references))| ConversationMessageFfi {
                timeline: presented_timeline(row, v.page.authenticated_system_content(i).is_some()),
                references: references.clone().into(),
            })
            .collect();
        Self::with_messages(v, messages)
    }
}
impl ConversationWindowSnapshotFfi {
    fn with_messages(
        v: &app::ConversationWindowSnapshot,
        messages: Vec<ConversationMessageFfi>,
    ) -> Self {
        let page = v.page.page();
        Self {
            revision: v.revision.clone().into(),
            header: v.presentation.header.clone().into(),
            messages,
            identities: v
                .presentation
                .identities
                .values()
                .cloned()
                .map(Into::into)
                .collect(),
            read_state: v.read_state.clone().into(),
            draft: v.draft.clone().into(),
            pending_confirmation: v.pending_confirmation,
            anchor: v.anchor.into(),
            has_more_before: page.has_more_before,
            has_more_after: page.has_more_after,
        }
    }
}
/// Subscription-local cache. Command replies and stream echoes share it; older
/// replies never replace the cache retained for a newer window.
#[derive(Default)]
pub(crate) struct ConversationConversionCache {
    sequence: Option<u64>,
    rows: std::collections::HashMap<String, CachedConversationRow>,
    closed: bool,
    #[cfg(test)]
    conversions: usize,
    #[cfg(test)]
    parses: usize,
}
struct CachedConversationRow {
    source: app::TimelineMessageRecord,
    converted: TimelineMessageRecordFfi,
}
impl ConversationConversionCache {
    pub(crate) fn close(&mut self) {
        self.rows.clear();
        self.closed = true;
    }
    pub(crate) fn convert(
        &mut self,
        v: &app::ConversationWindowSnapshot,
    ) -> ConversationWindowSnapshotFfi {
        if self.closed
            || self
                .sequence
                .is_some_and(|sequence| sequence > v.revision.sequence)
        {
            return v.into();
        }
        let messages = v
            .page
            .page()
            .messages
            .iter()
            .zip(&v.presentation.messages)
            .enumerate()
            .map(|(i, (row, references))| ConversationMessageFfi {
                timeline: self.row(row, v.page.authenticated_system_content(i).is_some()),
                references: references.clone().into(),
            })
            .collect();
        let retained: std::collections::HashSet<_> = v
            .page
            .page()
            .messages
            .iter()
            .map(|row| &row.message_id_hex)
            .collect();
        self.rows.retain(|id, _| retained.contains(id));
        self.sequence = Some(v.revision.sequence);
        ConversationWindowSnapshotFfi::with_messages(v, messages)
    }
    fn row(&mut self, row: &app::TimelineMessageRecord, trusted: bool) -> TimelineMessageRecordFfi {
        let cached = self.rows.get(&row.message_id_hex);
        if let Some(cached) = cached
            .filter(|cached| visible_row_key(&cached.source, true) == visible_row_key(row, trusted))
        {
            return cached.converted.clone();
        }
        let source = app::TimelineMessageRecord {
            message_id_hex: row.message_id_hex.clone(),
            source_message_id_hex: row.source_message_id_hex.clone(),
            source_epoch: row.source_epoch,
            retention_seconds: row.retention_seconds,
            retention_expires_at: row.retention_expires_at,
            direction: row.direction.clone(),
            group_id_hex: row.group_id_hex.clone(),
            sender: row.sender.clone(),
            plaintext: row.plaintext.clone(),
            kind: row.kind,
            tags: vec![],
            timeline_at: row.timeline_at,
            received_at: row.received_at,
            reply_to_message_id_hex: row.reply_to_message_id_hex.clone(),
            reply_preview: row.reply_preview.clone(),
            media: row.media.clone(),
            agent_text_stream: row.agent_text_stream.clone(),
            group_system: if trusted {
                row.group_system.clone()
            } else {
                None
            },
            reactions: Default::default(),
            edit: row.edit.clone(),
            deleted: row.deleted,
            deleted_by_message_id_hex: row.deleted_by_message_id_hex.clone(),
            invalidation_status: row.invalidation_status.clone(),
        };
        let tokens = match cached.filter(|cached| {
            cached.source.kind == row.kind && cached.source.plaintext == row.plaintext
        }) {
            Some(cached) => cached.converted.content_tokens.clone(),
            None => {
                #[cfg(test)]
                {
                    self.parses += 1;
                }
                super::common::markdown_content_tokens(row.kind, &row.plaintext)
            }
        };
        #[cfg(test)]
        {
            self.conversions += 1;
        }
        let converted = presented_timeline_with_tokens(&source, trusted, tokens);
        self.rows.insert(
            row.message_id_hex.clone(),
            CachedConversationRow {
                source,
                converted: converted.clone(),
            },
        );
        converted
    }
}

// Borrow the visible fields so cache hits do not allocate a second source row.
// Exhaustive destructuring makes additions to the source record a compile error
// until their effect on conversion reuse is explicitly considered.
fn visible_row_key(row: &app::TimelineMessageRecord, trusted: bool) -> impl PartialEq + '_ {
    let app::TimelineMessageRecord {
        message_id_hex,
        source_message_id_hex,
        source_epoch,
        retention_seconds,
        retention_expires_at,
        direction,
        group_id_hex,
        sender,
        plaintext,
        kind,
        tags: _,
        timeline_at,
        received_at,
        reply_to_message_id_hex,
        reply_preview,
        media,
        agent_text_stream,
        group_system,
        reactions: _,
        edit,
        deleted,
        deleted_by_message_id_hex,
        invalidation_status,
    } = row;
    (
        (
            message_id_hex,
            source_message_id_hex,
            source_epoch,
            retention_seconds,
            retention_expires_at,
            direction,
            group_id_hex,
            sender,
            plaintext,
            kind,
        ),
        (
            timeline_at,
            received_at,
            reply_to_message_id_hex,
            reply_preview,
            media,
            agent_text_stream,
            edit,
            deleted,
            deleted_by_message_id_hex,
            invalidation_status,
        ),
        if trusted { group_system.as_ref() } else { None },
    )
}

impl std::fmt::Debug for ConversationCapabilitiesFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationCapabilitiesFfi")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ConversationHeaderFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationHeaderFfi")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ConversationIdentityFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationIdentityFfi")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ConversationSystemReferencesFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationSystemReferencesFfi")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ConversationReactionFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationReactionFfi")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ConversationReactionsFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationReactionsFfi")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ConversationMessageReferencesFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationMessageReferencesFfi")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ConversationOpenReadStateFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationOpenReadStateFfi")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for SelectedMessageDraftAttachmentFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedMessageDraftAttachmentFfi")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for SelectedMessageDraftContentFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedMessageDraftContentFfi")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ConversationWindowRevisionFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationWindowRevisionFfi")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ConversationAnchorOutcomeFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationAnchorOutcomeFfi")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for SelectedMessageDraftFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedMessageDraftFfi")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ConversationMessageFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationMessageFfi")
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ConversationWindowSnapshotFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationWindowSnapshotFfi")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conversation_viewer_reaction_survives_native_conversion() {
        for viewer_reacted in [false, true] {
            let reaction = app::conversation_presentation::ConversationReaction {
                emoji: "👍".into(),
                count: 3,
                reactors: vec!["other-a".into(), "other-b".into()],
                viewer_reacted,
            };
            let native = ConversationReactionFfi::from(reaction);
            assert_eq!(native.viewer_reacted, viewer_reacted);
            assert_eq!(native.count, 3);
            assert_eq!(native.reactors, ["other-a", "other-b"]);
        }
    }

    #[test]
    fn conversation_native_timeline_requires_provenance_and_omits_unbounded_collections() {
        let content = cgka_traits::app_event::GroupSystemEvent::new(
            cgka_traits::app_event::GROUP_SYSTEM_TYPE_MEMBER_REMOVED,
            "Member removed",
            Some(serde_json::json!({
                cgka_traits::app_event::GROUP_SYSTEM_DATA_ACTOR: "aa".repeat(32),
                cgka_traits::app_event::GROUP_SYSTEM_DATA_SUBJECT: "bb".repeat(32),
                cgka_traits::app_event::GROUP_SYSTEM_DATA_OLD_NAME: "Team One",
                cgka_traits::app_event::GROUP_SYSTEM_DATA_NAME: "Team Two",
                cgka_traits::app_event::GROUP_SYSTEM_DATA_OLD_RETENTION_SECONDS: 60,
                cgka_traits::app_event::GROUP_SYSTEM_DATA_NEW_RETENTION_SECONDS: 0,
            })),
        )
        .to_content()
        .unwrap();
        let mut record = app::TimelineMessageRecord {
            group_system: Some({
                let mut event =
                    marmot_app::group_system_event_from_message(1210, &content).unwrap();
                event.provenance = marmot_app::GroupSystemEventProvenance::AuthenticatedGroupState;
                event
            }),
            edit: None,
            message_id_hex: "system-1".to_owned(),
            source_message_id_hex: None,
            source_epoch: Some(4),
            retention_seconds: None,
            retention_expires_at: None,
            direction: "system".to_owned(),
            group_id_hex: "11".repeat(32),
            sender: "aa".repeat(32),
            plaintext: content,
            kind: cgka_traits::app_event::MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
            tags: vec![vec!["system".to_owned(), "member_removed".to_owned()]],
            timeline_at: 10,
            received_at: 11,
            reply_to_message_id_hex: None,
            reply_preview: None,
            media: None,
            agent_text_stream: None,
            reactions: app::TimelineReactionSummary::default(),
            deleted: false,
            deleted_by_message_id_hex: None,
            invalidation_status: None,
        };

        record
            .reactions
            .by_emoji
            .insert("👍".into(), vec!["aa".repeat(32); 5000]);
        let untrusted = presented_timeline(&record, false);
        let trusted = presented_timeline(&record, true);
        assert!(untrusted.group_system.is_none());
        assert_eq!(trusted.group_system.unwrap().system_type, "member_removed");
        assert!(untrusted.tags.is_empty());
        assert!(untrusted.reactions.by_emoji.is_empty());
        assert!(untrusted.reactions.user_reactions.is_empty());
        assert_eq!(record.reactions.by_emoji["👍"].len(), 5000);
        assert_eq!(untrusted.plaintext, record.plaintext);
    }
}

#[cfg(test)]
mod edit_contract_tests {
    #[test]
    fn prepared_and_legacy_rows_share_effective_content_and_edit_metadata() {
        let row: marmot_app::TimelineMessageRecord = serde_json::from_value(serde_json::json!({
            "message_id_hex":"target","direction":"received","group_id_hex":"11","sender":"alice",
            "plaintext":"**replacement**","kind":9,"tags":[],"timeline_at":1,"received_at":1,
            "reactions":{"by_emoji":{},"user_reactions":[]},"deleted":false,
            "edit":{"edit_count":2,"latest_edit_message_id_hex":"edit","edited_at":5}
        }))
        .unwrap();
        let legacy = super::TimelineMessageRecordFfi::from(row.clone());
        let prepared = super::presented_timeline(&row, false);
        assert_eq!(legacy.plaintext, prepared.plaintext);
        assert_eq!(legacy.content_tokens, prepared.content_tokens);
        assert_eq!(prepared.edit.unwrap().latest_edit_message_id_hex, "edit");
        assert_eq!(legacy.edit.unwrap().edit_count, 2);
    }
}

#[cfg(test)]
#[path = "conversation_window/tests.rs"]
mod conversion_cache_tests;
