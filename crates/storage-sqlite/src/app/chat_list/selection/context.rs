//! Private compact source capture. No folder runtime/FFI admission is provided.
mod search;
use super::*;
use crate::app::account_projection::chat_mute_is_effective;
use crate::app::chat_presentation::row_contract::{
    NATIVE_TRIM_WHITESPACE, selected_draft_preview_tx,
};
pub use crate::app::chat_presentation::selection::SelectionPresentation;
use crate::{ChatConversationKind, ChatListMessageDeliveryState, SelfMembership};
use rusqlite::{OptionalExtension, params};
pub use search::SelectionSearchPreviewInput;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequiredContext {
    Participants,
    Title,
    Legacy,
    AccountSource,
    Presentation,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SelectionContextRequest {
    pub draft: bool,
    pub accepted_sources: bool,
    pub presentation_readiness: bool,
    pub title: bool,
    pub title_unknown_kind_only: bool,
    pub roster_for_native: bool,
    pub description: bool,
    pub search_routing_component: Option<u16>,
    pub text_budget: Option<usize>,
    pub unsupported: Option<RequiredContext>,
}

#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    #[error("required selection context is unsupported: {0:?}")]
    Unsupported(RequiredContext),
    #[error("required selection context is not ready: {0:?}")]
    NotReady(RequiredContext),
    #[error("selection capture exceeds its transient text budget")]
    ResourceExhausted,
    #[error(transparent)]
    Selection(#[from] ChatListSelectionError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProjectionFacts {
    pub archived: bool,
    pub pinned: bool,
    pub unread_count: u64,
    pub manually_marked_unread: bool,
    pub unread_mention_count: u64,
    pub muted: bool,
    pub conversation_kind: ChatConversationKind,
}

/// Raw native facts, not Android's cached invite-conflict or live authority state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedSourceFacts {
    pub row_pending_confirmation: bool,
    pub row_can_delete_local: bool,
    pub row_self_membership: SelfMembership,
    pub account_pending_confirmation: bool,
    pub account_self_membership: SelfMembership,
    pub leave_request_pending: bool,
    pub disbanding: bool,
    pub disbanded: bool,
}

pub struct SelectionSourceContext<'a> {
    pub group_id: &'a str,
    pub title_inputs: Option<&'a SelectionTitleInputs>,
    pub projection: ProjectionFacts,
    pub accepted_sources: Option<AcceptedSourceFacts>,
    pub selected_preview_has_draft: Option<bool>,
    /// Native baseline only. Host nonsending overrides can mask even this positive.
    pub native_sending: bool,
    pub selected_members: Option<&'a crate::ProjectedRosterEvidence>,
}
impl std::fmt::Debug for SelectionSourceContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectionSourceContext")
            .field("accepted_sources_present", &self.accepted_sources.is_some())
            .field(
                "draft_requested",
                &self.selected_preview_has_draft.is_some(),
            )
            .finish_non_exhaustive()
    }
}

/// Errors preserve the source-owned readiness failure without a storage-to-engine dependency.
#[derive(Debug, thiserror::Error)]
pub enum ContextCaptureError<R: std::fmt::Debug + std::fmt::Display> {
    #[error(transparent)]
    Native(#[from] ContextError),
    #[error("members source is not ready: {0}")]
    Readiness(R),
    #[error(transparent)]
    Roster(#[from] crate::RosterReadError),
}
impl<R: std::fmt::Debug + std::fmt::Display> From<StorageError> for ContextCaptureError<R> {
    fn from(error: StorageError) -> Self {
        Self::Native(ContextError::Storage(error))
    }
}
impl<R: std::fmt::Debug + std::fmt::Display> From<ChatListSelectionError>
    for ContextCaptureError<R>
{
    fn from(error: ChatListSelectionError) -> Self {
        Self::Native(ContextError::Selection(error))
    }
}

// Scalars only: deliberately not CHAT_LIST_ROW_SELECT_LIST, which includes text,
// media JSON and avatar secrets. Native trim uses the same Unicode set as Rust.
const CONTEXT_SQL: &str = "SELECT row.archived, pin.group_id_hex IS NOT NULL,
    row.unread_count, row.manually_marked_unread, row.unread_mention_count,
    mute.group_id_hex IS NOT NULL, mute.muted_until_ms,
    CASE WHEN length(CAST(trim(row.group_name, ?2) AS BLOB)) > 0 THEN 1
         WHEN typeof(ag.member_count) = 'integer' AND ag.member_count = 2 THEN 2
         WHEN typeof(ag.member_count) = 'integer' AND ag.member_count >= 0 THEN 1 ELSE 0 END,
    row.pending_confirmation, row.self_membership,
    ag.pending_confirmation, ag.self_membership,
    CASE WHEN row.last_message_sender IN (SELECT public_key FROM user_blocks)
         THEN NULL ELSE row.last_message_id_hex END,
    row.last_message_deleted, row.last_message_delivery_state,
    row.presentation_json IS NOT NULL,
    COALESCE(row.presentation_applied_source_revision = row.presentation_source_revision, 0)
    FROM chat_list_rows AS row
    LEFT JOIN account_groups AS ag ON ag.group_id_hex = row.group_id_hex
    LEFT JOIN chat_notification_settings AS mute ON mute.group_id_hex = row.group_id_hex
    LEFT JOIN chat_pin_positions AS pin ON pin.group_id_hex = row.group_id_hex
    WHERE row.group_id_hex = ?1";

/// Must run under the caller's one deferred read transaction. The native callback
/// is synchronous and pure: no storage reentry, external effects or escaped context.
/// Cancellation is cooperative between steps, not an interrupt of SQLite/lock waits.
#[cfg(test)]
fn context_filtered_ids(
    conn: &Connection,
    view: ChatListView,
    request: SelectionContextRequest,
    capture_now_ms: i64,
    cancelled: &impl Fn() -> bool,
    matches: &mut impl FnMut(&SelectionSourceContext<'_>) -> bool,
) -> Result<Vec<String>, ContextError> {
    match context_filtered_ids_with_members::<std::convert::Infallible>(
        conn,
        view,
        request,
        capture_now_ms,
        cancelled,
        None,
        &mut |_| Ok(()),
        matches,
    ) {
        Ok(ids) => Ok(ids),
        Err(ContextCaptureError::Native(error)) => Err(error),
        Err(ContextCaptureError::Readiness(never)) => match never {},
        Err(ContextCaptureError::Roster(_)) => unreachable!("no prepared members source"),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "The synchronous transaction boundary keeps source-owned scope, roster readiness and visitor callbacks explicit."
)]
pub(super) fn context_filtered_ids_with_members<R: std::fmt::Debug + std::fmt::Display>(
    conn: &Connection,
    view: ChatListView,
    request: SelectionContextRequest,
    capture_now_ms: i64,
    cancelled: &impl Fn() -> bool,
    members: Option<(&crate::SelectedMemberKeys, crate::PeerInputs<'_>)>,
    check_members: &mut impl FnMut(&cgka_traits::GroupId) -> Result<(), R>,
    matches: &mut impl FnMut(&SelectionSourceContext<'_>) -> bool,
) -> Result<Vec<String>, ContextCaptureError<R>> {
    visit_context_ids_with_members(
        conn,
        view,
        request,
        capture_now_ms,
        cancelled,
        members,
        check_members,
        &mut |context| Ok(matches(context)),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "The synchronous transaction boundary keeps source-owned scope, roster readiness and visitor callbacks explicit."
)]
pub(super) fn visit_context_ids_with_members<R: std::fmt::Debug + std::fmt::Display>(
    conn: &Connection,
    view: ChatListView,
    request: SelectionContextRequest,
    capture_now_ms: i64,
    cancelled: &impl Fn() -> bool,
    members: Option<(&crate::SelectedMemberKeys, crate::PeerInputs<'_>)>,
    check_members: &mut impl FnMut(&cgka_traits::GroupId) -> Result<(), R>,
    matches: &mut impl FnMut(&SelectionSourceContext<'_>) -> Result<bool, ContextError>,
) -> Result<Vec<String>, ContextCaptureError<R>> {
    visit_scope_context(
        conn,
        SelectionBaseScope::View(view),
        None,
        request,
        capture_now_ms,
        cancelled,
        members,
        check_members,
        matches,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "The synchronous transaction boundary keeps source-owned scope, roster readiness and visitor callbacks explicit."
)]
pub(super) fn visit_scope_context<R: std::fmt::Debug + std::fmt::Display>(
    conn: &Connection,
    scope: SelectionBaseScope,
    original_ids: Option<&[String]>,
    request: SelectionContextRequest,
    capture_now_ms: i64,
    cancelled: &impl Fn() -> bool,
    members: Option<(&crate::SelectedMemberKeys, crate::PeerInputs<'_>)>,
    check_members: &mut impl FnMut(&cgka_traits::GroupId) -> Result<(), R>,
    matches: &mut impl FnMut(&SelectionSourceContext<'_>) -> Result<bool, ContextError>,
) -> Result<Vec<String>, ContextCaptureError<R>> {
    check_cancelled(cancelled)?;
    if let Some(field) = request.unsupported {
        return Err(ContextError::Unsupported(field).into());
    }
    let missing_base: bool = conn
        .query_row_cached(
            "SELECT EXISTS(SELECT 1 FROM chat_presentation_row_work)",
            [],
            |r| r.get(0),
        )
        .storage()?;
    if missing_base {
        return Err(ChatListSelectionError::ProjectionNotReady.into());
    }
    let (index, predicate) = match scope {
        SelectionBaseScope::View(view) => (view.index(), view.predicate()),
        SelectionBaseScope::ActiveAndArchived => (
            "idx_chat_list_page",
            "list_scope IN (0,1) AND group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites)",
        ),
    };
    if let Some(ids) = original_ids {
        let mut unique = std::collections::HashSet::new();
        unique
            .try_reserve(ids.len())
            .map_err(|_| ContextError::ResourceExhausted)?;
        if ids.iter().any(|id| !unique.insert(id)) {
            return Err(
                StorageError::Serialization("invalid original selection intent".into()).into(),
            );
        }
    }
    let sql = format!(
        "SELECT group_id_hex FROM chat_list_rows INDEXED BY {index} WHERE {predicate} ORDER BY {}",
        pages::KEY_COLUMNS
    );
    let eligibility = format!(
        "SELECT EXISTS(SELECT 1 FROM chat_list_rows WHERE group_id_hex=?1 AND {predicate})"
    );
    let mut originals = original_ids.map(|ids| ids.iter());
    let mut candidates = conn.prepare_cached(&sql).storage()?;
    let mut rows = candidates.query([]).storage()?;
    let mut context_query = conn.prepare_cached(CONTEXT_SQL).storage()?;
    let mut ids = Vec::new();
    let mut text_remaining = request.text_budget.unwrap_or(0);
    'capture: loop {
        check_cancelled(cancelled)?;
        let id: String = if let Some(originals) = &mut originals {
            loop {
                check_cancelled(cancelled)?;
                let Some(id) = originals.next() else {
                    break 'capture;
                };
                let eligible: bool = conn
                    .query_row_cached(&eligibility, [id], |r| r.get(0))
                    .storage()?;
                if eligible {
                    break id.clone();
                }
            }
        } else {
            let Some(row) = rows.next().storage()? else {
                break;
            };
            row.get(0).storage()?
        };
        let (
            projection,
            pending,
            membership,
            account_pending,
            account_membership,
            native_sending,
            presentation_present,
            presentation_current,
        ) = context_query
            .query_row(params![id, NATIVE_TRIM_WHITESPACE], |r| {
                let count = |column| -> rusqlite::Result<u64> {
                    let raw: i64 = r.get(column)?;
                    raw.try_into()
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, raw))
                };
                let kind: i64 = r.get(7)?;
                let message: Option<String> = r.get(12)?;
                let deleted: Option<bool> = r.get(13)?;
                let delivery: Option<String> = r.get(14)?;
                Ok((
                    ProjectionFacts {
                        archived: r.get(0)?,
                        pinned: r.get(1)?,
                        unread_count: count(2)?,
                        manually_marked_unread: r.get(3)?,
                        unread_mention_count: count(4)?,
                        muted: chat_mute_is_effective(r.get(5)?, r.get(6)?, capture_now_ms),
                        conversation_kind: match kind {
                            1 => ChatConversationKind::Group,
                            2 => ChatConversationKind::Direct,
                            _ => ChatConversationKind::Unknown,
                        },
                    },
                    r.get::<_, bool>(8)?,
                    SelfMembership::from_storage(&r.get::<_, String>(9)?),
                    r.get::<_, Option<bool>>(10)?,
                    r.get::<_, Option<String>>(11)?,
                    message.is_some()
                        && !deleted.unwrap_or(false)
                        && delivery
                            .as_deref()
                            .map(ChatListMessageDeliveryState::from_storage)
                            == Some(ChatListMessageDeliveryState::Pending),
                    r.get::<_, bool>(15)?,
                    r.get::<_, bool>(16)?,
                ))
            })
            .storage()?;
        let title_required = request.search_routing_component.is_some()
            || (request.title
                && (!request.title_unknown_kind_only
                    || projection.conversation_kind == ChatConversationKind::Unknown));
        if (request.presentation_readiness
            || request.draft
            || title_required
            || request.description)
            && (!presentation_present || !presentation_current)
        {
            return Err(ContextError::NotReady(RequiredContext::Presentation).into());
        }
        let accepted_sources = if request.accepted_sources {
            let (Some(account_pending_confirmation), Some(account_membership)) =
                (account_pending, account_membership)
            else {
                return Err(ContextError::NotReady(RequiredContext::AccountSource).into());
            };
            let raw_id = hex::decode(&id).map_err(|_| {
                StorageError::Serialization("invalid selection group identity".into())
            })?;
            let gates = crate::cross::views::selection_group_gates_tx(conn, &raw_id)?;
            Some(AcceptedSourceFacts {
                row_pending_confirmation: pending,
                row_can_delete_local:
                    crate::app::chat_presentation::row_contract::can_delete_local_for_state(
                        membership,
                        gates.disbanded,
                        gates.leave_request_pending,
                        gates.disbanding,
                    ),
                row_self_membership: membership,
                account_pending_confirmation,
                account_self_membership: SelfMembership::from_storage(&account_membership),
                leave_request_pending: gates.leave_request_pending,
                disbanding: gates.disbanding,
                disbanded: gates.disbanded,
            })
        } else {
            None
        };
        let selected_preview_has_draft = if request.draft {
            let draft = selected_draft_preview_tx(conn, &id)?;
            Some(draft.is_some_and(|draft| {
                draft.text.chars().any(|c| !kotlin_whitespace(c))
                    || draft.attachment_count > 0
                    || draft.attachment_kind.is_some()
            }))
        } else {
            None
        };
        check_cancelled(cancelled)?;
        let selected_members = if let Some((keys, peer)) = members.filter(|(keys, _)| {
            request.roster_for_native || !keys.is_empty() || title_required || request.description
        }) {
            let raw = hex::decode(&id).map_err(|_| {
                StorageError::Serialization("invalid selection group identity".into())
            })?;
            let group_id = cgka_traits::GroupId::new(raw);
            check_members(&group_id).map_err(ContextCaptureError::Readiness)?;
            Some(
                crate::cross::selection_roster::projected_roster_selection_context_tx(
                    conn,
                    group_id.as_slice(),
                    keys,
                    peer,
                    (title_required || request.description).then_some(text_remaining),
                    cancelled,
                )?,
            )
        } else {
            None
        };
        if let Some(peer) = selected_members
            .as_ref()
            .and_then(|members| members.presentation.as_ref())
            .and_then(|presentation| presentation.peer_id_hex.as_ref())
        {
            text_remaining = text_remaining
                .checked_sub(peer.len())
                .ok_or(ContextError::ResourceExhausted)?;
        }
        let title_inputs = if title_required || request.description {
            Some(title_inputs_tx(
                conn,
                &id,
                request.description,
                request.search_routing_component,
                &mut text_remaining,
            )?)
        } else {
            None
        };
        let context = SelectionSourceContext {
            title_inputs: title_inputs.as_ref(),
            group_id: &id,
            projection,
            accepted_sources,
            selected_preview_has_draft,
            native_sending,
            selected_members: selected_members.as_ref(),
        };
        let matched = matches(&context)?;
        check_cancelled(cancelled)?;
        if matched {
            ids.push(id);
        }
    }
    check_cancelled(cancelled)?;
    Ok(ids)
}

/// Raw source-owned title inputs only. No rendered title, profile acquisition,
/// avatar-bearing object or message payload crosses this boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct SelectionTitleInputs {
    pub row_group_name: String,
    pub fallback_group_name: String,
    pub projected_title: String,
    pub selected: SelectionPresentation,
    pub description: Option<String>,
    pub pending_confirmation: bool,
    pub welcomer_id_hex: Option<String>,
    pub search: Option<SelectionSearchPreviewInput>,
}
impl std::fmt::Debug for SelectionTitleInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectionTitleInputs")
            .finish_non_exhaustive()
    }
}
fn title_inputs_tx(
    conn: &Connection,
    id: &str,
    description: bool,
    search_component: Option<u16>,
    remaining: &mut usize,
) -> Result<SelectionTitleInputs, ContextError> {
    // Byte lengths, including bytes after embedded NUL, precede text copying.
    let sizes: (i64, i64, i64, i64, i64, i64) = conn.query_row_cached(
        "SELECT length(CAST(row.group_name AS BLOB)), length(CAST(ag.profile_name AS BLOB)),
         length(CAST(row.title AS BLOB)), length(row.presentation_json),
         CASE WHEN ?2 THEN length(CAST(ag.profile_description AS BLOB)) ELSE 0 END,
         COALESCE(length(CAST(ag.welcomer_account_id_hex AS BLOB)),0)
         FROM chat_list_rows row JOIN account_groups ag ON ag.group_id_hex=row.group_id_hex WHERE row.group_id_hex=?1",
        params![id, description], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional().storage()?.ok_or(ContextError::NotReady(RequiredContext::AccountSource))?;
    crate::app::chat_presentation::validate_envelope_length(
        usize::try_from(sizes.3).map_err(|_| ContextError::ResourceExhausted)?,
    )?;
    let mut total = 0usize;
    for size in [sizes.0, sizes.1, sizes.2, sizes.4, sizes.5] {
        total = total
            .checked_add(usize::try_from(size).map_err(|_| ContextError::ResourceExhausted)?)
            .ok_or(ContextError::ResourceExhausted)?;
    }
    if total > *remaining {
        return Err(ContextError::ResourceExhausted);
    }
    let (row_group_name,fallback_group_name,projected_title,encoded,description,pending_confirmation,welcomer_id_hex) = conn.query_row_cached(
        "SELECT row.group_name, ag.profile_name, row.title, row.presentation_json,
         CASE WHEN ?2 THEN ag.profile_description ELSE NULL END,row.pending_confirmation,ag.welcomer_account_id_hex
         FROM chat_list_rows row JOIN account_groups ag ON ag.group_id_hex=row.group_id_hex WHERE row.group_id_hex=?1",
        params![id,description], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get::<_,Vec<u8>>(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).storage()?;
    let selected =
        crate::app::chat_presentation::selection::decode_selection_presentation(&encoded)?;
    // The bounded avatar-bearing envelope is transient. Charge only retained
    // selected title/peer text, never an account-sized sum of avatar metadata.
    let selected_text = match &selected.title {
        crate::PresentationText::Literal(text) => text.len(),
        _ => 0,
    };
    total = total
        .checked_add(selected_text)
        .and_then(|n| n.checked_add(selected.peer_id.as_ref().map_or(0, String::len)))
        .ok_or(ContextError::ResourceExhausted)?;
    if total > *remaining {
        return Err(ContextError::ResourceExhausted);
    }
    *remaining -= total;
    let search = search_component
        .map(|component| search::search_preview_tx(conn, id, component, remaining))
        .transpose()?;
    Ok(SelectionTitleInputs {
        row_group_name,
        fallback_group_name,
        projected_title,
        selected,
        description,
        pending_confirmation,
        welcomer_id_hex,
        search,
    })
}

// Kotlin Char.isWhitespace = Character.isWhitespace || Character.isSpaceChar.
// Apply to the exact already-selected native draft text, never raw composer text.
fn kotlin_whitespace(c: char) -> bool {
    matches!(c, '\u{0009}'..='\u{000d}' | '\u{001c}'..='\u{0020}' | '\u{00a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}')
}

#[cfg(test)]
mod tests;
