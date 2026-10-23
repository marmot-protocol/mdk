//! Snapshot-owned native facts and deferred host leaves. No callback invokes
//! host code; presentation pages become available only after SQL release.
mod search;
use super::presentation::{
    CaptureBudget, HostContextIdentity, PendingPresentation, PresentationAnswer, PresentationError,
    PresentationLeafKind, PresentationOperand,
};
use super::scope::{CompiledScope, NativeLeaf};
use crate::smart_folder::{
    FolderTruth, SmartFolderAccepted, SmartFolderContext, SmartFolderMode, SmartFolderProjection,
    evaluate_smart_folder_with_context,
};
use std::collections::{HashMap, HashSet};
use storage_sqlite::{
    ChatConversationKind, ContextError, RequiredContext, SelectionSourceContext, SelfMembership,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OptimisticSending {
    Sending,
    SuppressNative,
}
/// Frozen sparse facts exported by their existing host owners. No text maps or
/// loaded chat rows are accepted as candidate enumeration or completeness.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct HostOverlays {
    pub sending: HashMap<String, OptimisticSending>,
    pub muted: HashMap<String, bool>,
    pub removed: HashSet<String>,
    pub invite_conflicts: HashSet<String>,
    /// Actual sparse latest-preview replacement, including an explicit empty
    /// preview. Absence means native baseline; never OR with baseline text.
    pub preview_overrides: HashMap<String, Option<super::presentation::SearchPreviewMessage>>,
    /// Frozen existing media-preview cache, keyed by exact message ID.
    pub media_preview_fallbacks: HashMap<String, String>,
}
impl std::fmt::Debug for HostOverlays {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostOverlays").finish_non_exhaustive()
    }
}
struct Candidate {
    id: String,
    native: Vec<FolderTruth>,
    kind: ChatConversationKind,
    known: Option<bool>,
    archived: bool,
    abandonable: Option<bool>,
}
pub(crate) struct CaptureBuilder {
    pub scope: CompiledScope,
    host: HostContextIdentity,
    revision: u64,
    capture_now_ms: i64,
    overlays: HostOverlays,
    candidates: Vec<Candidate>,
    operands: Vec<PresentationOperand>,
    budget: CaptureBudget,
}
pub(crate) struct PreparedCapture {
    scope: CompiledScope,
    candidates: Vec<Candidate>,
    pub presentation: Option<PendingPresentation>,
}
impl std::fmt::Debug for PreparedCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedCapture")
            .field("candidate_count", &self.candidates.len())
            .field("needs_presentation", &self.presentation.is_some())
            .finish_non_exhaustive()
    }
}
fn resource(_: PresentationError) -> ContextError {
    ContextError::ResourceExhausted
}
impl CaptureBuilder {
    pub fn new(
        mut scope: CompiledScope,
        host: HostContextIdentity,
        revision: u64,
        capture_now_ms: i64,
        overlays: HostOverlays,
    ) -> Result<Self, ContextError> {
        let mut budget = std::mem::take(&mut scope.budget);
        for id in overlays
            .sending
            .keys()
            .chain(overlays.muted.keys())
            .chain(overlays.removed.iter())
            .chain(overlays.invite_conflicts.iter())
        {
            budget.charge(id.len(), 128).map_err(resource)?;
        }
        for (id, preview) in &overlays.preview_overrides {
            budget.charge(id.len(), 128).map_err(resource)?;
            if let Some(preview) = preview {
                // Group-system fields are source-bounded typed objects; charge
                // every retained string rather than only the plaintext.
                budget
                    .charge(
                        preview
                            .text_bytes()
                            .ok_or(ContextError::ResourceExhausted)?,
                        512,
                    )
                    .map_err(resource)?;
            }
        }
        for (message_id, text) in &overlays.media_preview_fallbacks {
            budget
                .charge(
                    message_id
                        .len()
                        .checked_add(text.len())
                        .ok_or(ContextError::ResourceExhausted)?,
                    128,
                )
                .map_err(resource)?;
        }
        let title = !scope.presentation.is_empty();
        scope.request.title = title;
        scope.request.title_unknown_kind_only = title
            && scope
                .presentation
                .iter()
                .all(|leaf| leaf.kind == PresentationLeafKind::IsDirect);
        scope.request.roster_for_native = scope.keys.is_some() || scope.needs_roster;
        scope.request.search_routing_component = scope
            .search
            .as_ref()
            .map(|_| cgka_traits::NOSTR_ROUTING_COMPONENT_ID);
        scope.request.description = scope.presentation.iter().any(|leaf| {
            matches!(
                leaf.kind,
                PresentationLeafKind::LegacyKeyword | PresentationLeafKind::ChatSearch
            )
        });
        scope.request.text_budget = title.then_some(budget.remaining_text());
        Ok(Self {
            scope,
            host,
            revision,
            capture_now_ms,
            overlays,
            candidates: Vec::new(),
            operands: Vec::new(),
            budget,
        })
    }
    pub fn needs_roster(&self) -> bool {
        self.scope.keys.is_some() || self.scope.needs_roster || self.scope.request.title
    }
    pub fn visit(&mut self, context: &SelectionSourceContext<'_>) -> Result<bool, ContextError> {
        let mut native = Vec::new();
        native
            .try_reserve_exact(self.scope.native.len())
            .map_err(|_| ContextError::ResourceExhausted)?;
        for leaf in &self.scope.native {
            native.push(native_truth(leaf, context, &self.overlays)?);
        }
        let kind = context.projection.conversation_kind;
        let leaves: Vec<_> = self
            .scope
            .presentation
            .iter()
            .filter(|leaf| {
                leaf.kind != PresentationLeafKind::IsDirect || kind == ChatConversationKind::Unknown
            })
            .cloned()
            .collect();
        let known = if leaves.is_empty() {
            Some(
                self.scope
                    .matches(context.group_id, &native, &HashMap::new(), kind, None),
            )
        } else {
            None
        };
        self.budget
            .charge(
                context
                    .group_id
                    .len()
                    .checked_mul(2)
                    .ok_or(ContextError::ResourceExhausted)?,
                std::mem::size_of::<String>()
                    + std::mem::size_of::<Candidate>()
                    + native.len() * std::mem::size_of::<FolderTruth>(),
            )
            .map_err(resource)?;
        self.candidates
            .try_reserve(1)
            .map_err(|_| ContextError::ResourceExhausted)?;
        if !leaves.is_empty() {
            let input = context
                .title_inputs
                .ok_or(ContextError::NotReady(RequiredContext::Title))?;
            let members = context
                .selected_members
                .ok_or(ContextError::NotReady(RequiredContext::Participants))?;
            let roster = members
                .presentation
                .as_ref()
                .ok_or(ContextError::NotReady(RequiredContext::Presentation))?;
            let search = self
                .scope
                .search
                .as_ref()
                .map(|scope| {
                    search::preview(
                        input
                            .search
                            .as_ref()
                            .ok_or(ContextError::NotReady(RequiredContext::Presentation))?,
                        scope,
                        self.capture_now_ms,
                        self.overlays.preview_overrides.get(context.group_id),
                        &self.overlays.media_preview_fallbacks,
                        &self.budget,
                    )
                })
                .transpose()?;
            let operand = PresentationOperand {
                candidate_slot: u64::try_from(self.candidates.len())
                    .map_err(|_| ContextError::ResourceExhausted)?,
                group_id_hex: context.group_id.into(),
                row_group_name: input.row_group_name.clone(),
                fallback_group_name: input.fallback_group_name.clone(),
                projected_title: Some(input.projected_title.clone()),
                selected_title: Some(input.selected.title.clone()),
                selected_peer_id_hex: input.selected.peer_id.clone(),
                roster_peer_id_hex: roster.peer_id_hex.clone(),
                roster_peer_present: members.peer_present(),
                roster_member_count: roster.member_count,
                pending_confirmation: input.pending_confirmation,
                welcomer_id_hex: input.welcomer_id_hex.clone(),
                conversation_kind: Some(kind),
                active_account_is_sole_member: roster.active_account_is_sole_member,
                description: input.description.clone(),
                leaves,
                search,
            };
            self.budget.charge_operand(&operand).map_err(resource)?;
            self.operands
                .try_reserve(1)
                .map_err(|_| ContextError::ResourceExhausted)?;
            self.operands.push(operand);
        }
        self.candidates.push(Candidate {
            id: context.group_id.into(),
            native: if known.is_none() { native } else { Vec::new() },
            kind,
            known,
            archived: context.projection.archived,
            abandonable: context.accepted_sources.map(|s| {
                !s.row_pending_confirmation
                    && !nonmember(s.account_self_membership)
                    && !s.disbanded
                    && !nonmember(s.row_self_membership)
                    && s.row_can_delete_local
            }),
        });
        // The builder owns compact IDs; do not duplicate them in storage's return.
        Ok(false)
    }
    pub fn finish(self) -> Result<PreparedCapture, PresentationError> {
        let presentation = if self.operands.is_empty() {
            None
        } else {
            // Global capture budget already charged each operand exactly once.
            // Constructor's separate subset accounting validates its issued-slot
            // map, without recharging the global capture attempt budget.
            Some(PendingPresentation::new(
                self.revision,
                self.host,
                self.operands,
                &mut CaptureBudget::default(),
            )?)
        };
        Ok(PreparedCapture {
            scope: self.scope,
            candidates: self.candidates,
            presentation,
        })
    }
}
impl PreparedCapture {
    /// Hints over the complete frozen selected set, never command authority.
    /// Missing optional facts do not prevent compact count/membership capture.
    pub fn affordances(
        &self,
        selected: &[String],
        proof: Option<&super::presentation::PresentationProof>,
    ) -> Option<(bool, Option<bool>, Option<bool>)> {
        if selected.is_empty() {
            return Some((false, Some(false), Some(false)));
        }
        let answers = self
            .presentation
            .as_ref()
            .map(PendingPresentation::answers)
            .transpose()
            .ok()?;
        let mut archived = true;
        let mut direct = Some(true);
        let mut abandonable = Some(true);
        let and = |left: Option<bool>, right: Option<bool>| match (left, right) {
            (Some(false), _) | (_, Some(false)) => Some(false),
            (Some(true), Some(true)) => Some(true),
            _ => None,
        };
        for (index, c) in self
            .candidates
            .iter()
            .enumerate()
            .filter(|(_, c)| selected.binary_search(&c.id).is_ok())
        {
            archived &= c.archived;
            abandonable = and(abandonable, c.abandonable);
            let value = match c.kind {
                ChatConversationKind::Direct => Some(true),
                ChatConversationKind::Group => Some(false),
                ChatConversationKind::Unknown => self.scope.direct_slot.and_then(|slot| {
                    answers
                        .and_then(|a| a.get(&(index as u64, slot)).copied().flatten())
                        .or_else(|| proof.and_then(|p| p.answer(index as u64, slot)))
                }),
            };
            direct = and(direct, value);
        }
        Some((archived, direct, abandonable))
    }
    pub fn submit(
        &mut self,
        revision: u64,
        host: &HostContextIdentity,
        answers: &[PresentationAnswer],
    ) -> Result<(), PresentationError> {
        self.presentation
            .as_mut()
            .ok_or(PresentationError::InvalidSlots)?
            .submit(revision, host, answers)
    }
    pub fn take_proof(
        &mut self,
    ) -> Result<Option<std::sync::Arc<super::presentation::PresentationProof>>, PresentationError>
    {
        if self
            .presentation
            .as_ref()
            .is_some_and(|pending| !pending.is_complete())
        {
            return Err(PresentationError::Incomplete);
        }
        self.presentation
            .take()
            .map(|pending| pending.into_proof().map(std::sync::Arc::new))
            .transpose()
    }
    #[cfg(test)]
    pub fn complete(self) -> Result<Vec<String>, PresentationError> {
        self.resolved_ids()
    }
    /// Retain exact operands/answers for a later fresh-worker admission check.
    /// No previous boolean alone is authority for a mutation.
    pub fn resolved_ids(&self) -> Result<Vec<String>, PresentationError> {
        let answers = self
            .presentation
            .as_ref()
            .map(PendingPresentation::answers)
            .transpose()?;
        let mut ids = Vec::new();
        ids.try_reserve(self.candidates.len())
            .map_err(|_| PresentationError::ResourceExhausted)?;
        for (slot, candidate) in self.candidates.iter().enumerate() {
            let matched = if let Some(known) = candidate.known {
                known
            } else {
                let mut leaves = HashMap::new();
                leaves
                    .try_reserve(self.scope.presentation.len())
                    .map_err(|_| PresentationError::ResourceExhausted)?;
                for leaf in &self.scope.presentation {
                    if let Some(Some(value)) =
                        answers.and_then(|answers| answers.get(&(slot as u64, leaf.slot)))
                    {
                        leaves.insert(leaf.slot, *value);
                    }
                }
                let direct = self
                    .scope
                    .direct_slot
                    .and_then(|slot| leaves.get(&slot).copied());
                self.scope.matches(
                    &candidate.id,
                    &candidate.native,
                    &leaves,
                    candidate.kind,
                    direct,
                )
            };
            if matched {
                ids.push(super::presentation::owned_text(&candidate.id)?);
            }
        }
        Ok(ids)
    }
}
fn native_truth(
    leaf: &NativeLeaf,
    c: &SelectionSourceContext<'_>,
    host: &HostOverlays,
) -> Result<FolderTruth, ContextError> {
    let p = c.projection;
    let projection = SmartFolderProjection {
        has_unread: p.unread_count > 0 || p.manually_marked_unread,
        manually_marked_unread: p.manually_marked_unread,
        unread_count: p.unread_count,
        has_unread_mention: p.unread_mention_count > 0,
        unread_mention_count: p.unread_mention_count,
        muted: p.muted,
        pinned: p.pinned,
        archived: p.archived,
        conversation_kind: p.conversation_kind,
    };
    let source = c.accepted_sources;
    if matches!(
        leaf,
        NativeLeaf::Smart(crate::smart_folder::SmartFolderPredicate::Condition {
            field: crate::smart_folder::SmartFolderField::Accepted,
            ..
        })
    ) && (source.is_none() || c.selected_members.is_none())
    {
        return Err(ContextError::NotReady(RequiredContext::AccountSource));
    }
    let removed = host.removed.contains(c.group_id);
    let sending = match host.sending.get(c.group_id) {
        Some(OptimisticSending::Sending) => Some(true),
        Some(OptimisticSending::SuppressNative) => None,
        None => c.native_sending.then_some(true),
    };
    let accepted = source.map(|s| SmartFolderAccepted {
        invite_confirmation_unresolved: host.invite_conflicts.contains(c.group_id)
            || (!nonmember(s.row_self_membership)
                && s.row_pending_confirmation != s.account_pending_confirmation),
        removed,
        pending_confirmation: s.account_pending_confirmation,
        self_is_member: s.account_self_membership == SelfMembership::Member,
        leave_request_pending: s.leave_request_pending,
        disbanding: s.disbanding,
        disbanded: s.disbanded,
        unrecoverable: c
            .selected_members
            .is_some_and(|members| members.unrecoverable),
    });
    Ok(match leaf {
        NativeLeaf::Smart(rule) => evaluate_smart_folder_with_context(
            rule,
            &SmartFolderContext {
                projection: Some(&projection),
                accepted,
                selected_preview_has_draft: c.selected_preview_has_draft,
                sending,
                participants: None,
            },
        )
        .map_err(|_| ContextError::NotReady(RequiredContext::AccountSource))?,
        NativeLeaf::Members { indices, mode, not } => {
            let members = c
                .selected_members
                .ok_or(ContextError::NotReady(RequiredContext::Participants))?;
            let found = indices
                .iter()
                .filter(|index| members.contains(**index))
                .count();
            let complete = members.roster_nonempty()
                && match p.conversation_kind {
                    ChatConversationKind::Group => true,
                    ChatConversationKind::Direct => members.peer_present(),
                    ChatConversationKind::Unknown => false,
                };
            let truth = match mode {
                SmartFolderMode::AnyOf if found > 0 => FolderTruth::True,
                SmartFolderMode::AllOf if found == indices.len() => FolderTruth::True,
                SmartFolderMode::Excludes if found > 0 => FolderTruth::False,
                SmartFolderMode::AnyOf | SmartFolderMode::AllOf if complete => FolderTruth::False,
                SmartFolderMode::Excludes if complete => FolderTruth::True,
                _ => FolderTruth::Unknown,
            };
            if *not { truth.inverted() } else { truth }
        }
        NativeLeaf::LegacyMembers(indices) => {
            let members = c
                .selected_members
                .ok_or(ContextError::NotReady(RequiredContext::Participants))?;
            FolderTruth::from_bool(indices.iter().any(|index| members.contains(*index)))
        }
        NativeLeaf::LegacyArchive(archived) => FolderTruth::from_bool(*archived == p.archived),
        NativeLeaf::LegacyUnmuted => {
            FolderTruth::from_bool(!host.muted.get(c.group_id).copied().unwrap_or(p.muted))
        }
        NativeLeaf::LegacyAttention {
            unread,
            mentions,
            pinned,
        } => {
            let effective_unread = if *unread || *mentions {
                let source =
                    source.ok_or(ContextError::NotReady(RequiredContext::AccountSource))?;
                let members = c
                    .selected_members
                    .ok_or(ContextError::NotReady(RequiredContext::Participants))?;
                let active = members
                    .active_account_is_member
                    .ok_or(ContextError::NotReady(RequiredContext::Participants))?;
                let nonmember = nonmember(source.row_self_membership)
                    || nonmember(source.account_self_membership)
                    || source.leave_request_pending
                    || source.disbanding
                    || source.disbanded
                    || removed
                    || (members.roster_nonempty() && !active);
                projection.has_unread && !nonmember
            } else {
                false
            };
            FolderTruth::from_bool(
                (!*unread || effective_unread)
                    && (!*mentions || (p.unread_mention_count > 0 && effective_unread))
                    && (!*pinned || p.pinned),
            )
        }
    })
}
fn nonmember(value: SelfMembership) -> bool {
    matches!(value, SelfMembership::Removed | SelfMembership::Left)
}

/// Private worker request. Source scope is complete before the SQL cursor; an
/// original-ID vector comes only from the existing native handle's frozen set.
#[derive(Clone)]
pub(crate) struct CaptureRequest {
    pub scope: super::scope::ScopeRequest,
    pub base: storage_sqlite::SelectionBaseScope,
    pub original_ids: Option<Vec<String>>,
    pub action_hints: bool,
    /// Source-owned explicit deselection payload retained outside this capture.
    pub excluded_cost: (usize, usize),
    pub host: HostContextIdentity,
    pub overlays: HostOverlays,
    pub revision: u64,
    pub capture_now_ms: i64,
    pub cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl std::fmt::Debug for CaptureRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureRequest")
            .field("base", &self.base)
            .field("original_count", &self.original_ids.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}
/// No source-owned error payload or identity is exposed to worker diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CaptureError {
    #[error("selection source is not ready")]
    NotReady,
    #[error("selection owner is closed")]
    Closed,
    #[error("selection capture was cancelled")]
    Cancelled,
    #[error("selection capture requires a multithread runtime")]
    UnsupportedRuntime,
    #[error("selection scope is invalid")]
    InvalidScope,
    #[error("selection capture exceeds its transient resource budget")]
    ResourceExhausted,
    #[error("selection capture response timed out")]
    TimedOut,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionMutation {
    Archive { archived: bool },
    DeleteLocal,
}
/// A retained per-handle result allows readback after an abandoned UI wait.
/// An uncertain result must never trigger an automatic retry.
#[derive(Clone, PartialEq, Eq)]
pub struct SelectionMutationReport {
    pub mutation: SelectionMutation,
    pub operation_id: u64,
    pub attempt_id: u64,
    pub revision: u64,
    pub applied_group_ids: Vec<String>,
    pub failed_group_id: Option<String>,
    pub uncertain: bool,
    pub remaining: usize,
}
impl std::fmt::Debug for SelectionMutationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectionMutationReport")
            .field("applied_count", &self.applied_group_ids.len())
            .field("has_failure", &self.failed_group_id.is_some())
            .field("uncertain", &self.uncertain)
            .field("remaining", &self.remaining)
            .finish()
    }
}
