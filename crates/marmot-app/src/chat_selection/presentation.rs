mod search;
pub use search::{SearchMessage, SearchPresentation, SearchPreviewMessage, SearchScope};
use std::collections::{HashMap, HashSet};
use std::fmt;
use storage_sqlite::{ChatConversationKind, PresentationText};

const TEXT_BUDGET: usize = 16 * 1024 * 1024;
const CAPTURE_BUDGET: usize = 64 * 1024 * 1024;
const PAGE_LIMIT: usize = 200;

/// Identity of a host-owned immutable snapshot, not an authorization token.
#[derive(Clone, PartialEq, Eq)]
pub struct HostContextIdentity {
    pub account_id_hex: String,
    pub runtime_generation: i64,
    pub selection_generation: u64,
    pub presentation_context_id: u64,
}
impl fmt::Debug for HostContextIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HostContextIdentity { redacted }")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresentationLeafKind {
    TitleContains,
    LegacyKeyword,
    IsDirect,
    LegacyPeerEquals,
    ChatSearch,
}
#[derive(Clone, PartialEq, Eq)]
pub struct PresentationLeaf {
    pub slot: u32,
    pub kind: PresentationLeafKind,
    pub needle: String,
}
impl fmt::Debug for PresentationLeaf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PresentationLeaf")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Raw inputs to the existing host renderer, never a purported rendered title.
/// Host chooses row_group_name.ifBlank { fallback_group_name }; native does not
/// reproduce Kotlin blankness, normalization, localization, or case folding.
#[derive(Clone, PartialEq, Eq)]
pub struct PresentationOperand {
    pub candidate_slot: u64,
    pub group_id_hex: String,
    pub row_group_name: String,
    pub fallback_group_name: String,
    pub projected_title: Option<String>,
    pub selected_title: Option<PresentationText>,
    pub selected_peer_id_hex: Option<String>,
    pub roster_peer_id_hex: Option<String>,
    pub roster_peer_present: bool,
    pub roster_member_count: i32,
    pub pending_confirmation: bool,
    pub welcomer_id_hex: Option<String>,
    pub conversation_kind: Option<ChatConversationKind>,
    pub active_account_is_sole_member: bool,
    pub description: Option<String>,
    pub leaves: Vec<PresentationLeaf>,
    pub search: Option<SearchPresentation>,
}
impl fmt::Debug for PresentationOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PresentationOperand")
            .field("leaf_count", &self.leaves.len())
            .finish_non_exhaustive()
    }
}
impl PresentationOperand {
    pub(super) fn text_bytes(&self) -> Option<usize> {
        let selected = match &self.selected_title {
            Some(PresentationText::Literal(text)) => text.len(),
            _ => 0,
        };
        let mut bytes = selected.checked_add(
            self.search
                .as_ref()
                .map_or(Some(0), SearchPresentation::text_bytes)?,
        )?;
        for text in [
            Some(self.group_id_hex.as_str()),
            Some(self.row_group_name.as_str()),
            Some(self.fallback_group_name.as_str()),
            self.projected_title.as_deref(),
            self.selected_peer_id_hex.as_deref(),
            self.roster_peer_id_hex.as_deref(),
            self.welcomer_id_hex.as_deref(),
            self.description.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            bytes = bytes.checked_add(text.len())?;
        }
        for leaf in &self.leaves {
            bytes = bytes.checked_add(leaf.needle.len())?;
        }
        Some(bytes)
    }
}

/// Fallible copy for unbounded legacy/raw presentation text after size preflight.
pub(crate) fn owned_text(text: &str) -> Result<String, PresentationError> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(text.len())
        .map_err(|_| PresentationError::ResourceExhausted)?;
    owned.push_str(text);
    Ok(owned)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PresentationAnswer {
    pub candidate_slot: u64,
    pub leaf_slot: u32,
    /// Uninverted result; native retains NONE/NOT/group semantics.
    pub matches: bool,
}
impl fmt::Debug for PresentationAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PresentationAnswer { redacted }")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PresentationError {
    #[error("selection capture exceeds its transient resource budget")]
    ResourceExhausted,
    #[error("selection presentation reply is stale")]
    Stale,
    #[error("selection presentation reply contains invalid or repeated slots")]
    InvalidSlots,
    #[error("selection presentation capture is incomplete")]
    Incomplete,
}

/// Aggregate accounting supplements SQL length preflight. Typed Group decoding
/// retains its inherited one-record allocation/work; this is not a decode cap.
#[derive(Default)]
pub(crate) struct CaptureBudget {
    text: usize,
    estimated: usize,
}
impl CaptureBudget {
    pub(super) fn remaining_total(&self) -> usize {
        CAPTURE_BUDGET - self.estimated
    }
    pub(super) fn remaining_text(&self) -> usize {
        TEXT_BUDGET - self.text
    }
    pub(super) fn charge_operand(
        &mut self,
        operand: &PresentationOperand,
    ) -> Result<(), PresentationError> {
        let other = operand
            .leaves
            .len()
            .checked_mul(std::mem::size_of::<PresentationLeaf>() + 128)
            .and_then(|n| n.checked_add(std::mem::size_of::<PresentationOperand>() + 128))
            .ok_or(PresentationError::ResourceExhausted)?;
        self.charge(
            operand
                .text_bytes()
                .ok_or(PresentationError::ResourceExhausted)?,
            other
                .checked_add(
                    operand
                        .search
                        .as_ref()
                        .map_or(Some(0), SearchPresentation::other_bytes)
                        .ok_or(PresentationError::ResourceExhausted)?,
                )
                .ok_or(PresentationError::ResourceExhausted)?,
        )
    }
    pub fn charge(&mut self, text: usize, other: usize) -> Result<(), PresentationError> {
        let next_text = self
            .text
            .checked_add(text)
            .ok_or(PresentationError::ResourceExhausted)?;
        let next_total = self
            .estimated
            .checked_add(text)
            .and_then(|n| n.checked_add(other))
            .ok_or(PresentationError::ResourceExhausted)?;
        if next_text > TEXT_BUDGET || next_total > CAPTURE_BUDGET {
            return Err(PresentationError::ResourceExhausted);
        }
        self.text = next_text;
        self.estimated = next_total;
        Ok(())
    }
}

/// Holds operands for one released native snapshot. Invalid batches never
/// partially consume slots. Completion cannot nominate or add candidate IDs.
/// The caller drops the per-attempt budget if construction fails; charges are
/// owned by the whole capture attempt, never reused for a retry.
/// A frozen completed host calculation. Payloads are never logged. Only a
/// fresh native capture with exactly equal required inputs may reuse it.
pub(crate) struct PresentationProof {
    host: HostContextIdentity,
    operands: Vec<PresentationOperand>,
    answers: HashMap<(u64, u32), Option<bool>>,
}
impl PresentationProof {
    pub fn answer(&self, candidate: u64, leaf: u32) -> Option<bool> {
        self.answers.get(&(candidate, leaf)).copied().flatten()
    }
}
impl fmt::Debug for PresentationProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PresentationProof")
            .field("operand_count", &self.operands.len())
            .finish_non_exhaustive()
    }
}
impl PresentationOperand {
    pub fn try_owned_copy(&self) -> Result<Self, PresentationError> {
        let optional = |value: &Option<String>| value.as_deref().map(owned_text).transpose();
        let mut leaves = Vec::new();
        leaves
            .try_reserve_exact(self.leaves.len())
            .map_err(|_| PresentationError::ResourceExhausted)?;
        for leaf in &self.leaves {
            leaves.push(PresentationLeaf {
                slot: leaf.slot,
                kind: leaf.kind,
                needle: owned_text(&leaf.needle)?,
            });
        }
        let selected_title = match &self.selected_title {
            Some(PresentationText::Literal(text)) => {
                Some(PresentationText::Literal(owned_text(text)?))
            }
            value => value.clone(),
        };
        Ok(Self {
            candidate_slot: self.candidate_slot,
            group_id_hex: owned_text(&self.group_id_hex)?,
            row_group_name: owned_text(&self.row_group_name)?,
            fallback_group_name: owned_text(&self.fallback_group_name)?,
            projected_title: optional(&self.projected_title)?,
            selected_title,
            selected_peer_id_hex: optional(&self.selected_peer_id_hex)?,
            roster_peer_id_hex: optional(&self.roster_peer_id_hex)?,
            roster_peer_present: self.roster_peer_present,
            roster_member_count: self.roster_member_count,
            pending_confirmation: self.pending_confirmation,
            welcomer_id_hex: optional(&self.welcomer_id_hex)?,
            conversation_kind: self.conversation_kind,
            active_account_is_sole_member: self.active_account_is_sole_member,
            description: optional(&self.description)?,
            leaves,
            search: self
                .search
                .as_ref()
                .map(SearchPresentation::try_owned_copy)
                .transpose()?,
        })
    }
    fn same_required_inputs(&self, old: &Self) -> bool {
        self.group_id_hex == old.group_id_hex
            && self.row_group_name == old.row_group_name
            && self.fallback_group_name == old.fallback_group_name
            && self.projected_title == old.projected_title
            && self.selected_title == old.selected_title
            && self.selected_peer_id_hex == old.selected_peer_id_hex
            && self.roster_peer_id_hex == old.roster_peer_id_hex
            && self.roster_peer_present == old.roster_peer_present
            && self.roster_member_count == old.roster_member_count
            && self.pending_confirmation == old.pending_confirmation
            && self.welcomer_id_hex == old.welcomer_id_hex
            && self.conversation_kind == old.conversation_kind
            && self.active_account_is_sole_member == old.active_account_is_sole_member
            && self.description == old.description
            && self.leaves == old.leaves
            && match (&self.search, &old.search) {
                (None, None) => true,
                (Some(current), Some(previous)) => current.same_required_inputs(previous),
                _ => false,
            }
    }
}
pub(crate) struct PendingPresentation {
    revision: u64,
    host: HostContextIdentity,
    operands: Vec<PresentationOperand>,
    answers: HashMap<(u64, u32), Option<bool>>,
    remaining: usize,
}
impl fmt::Debug for PendingPresentation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingPresentation")
            .field("operand_count", &self.operands.len())
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}
impl PendingPresentation {
    pub fn new(
        revision: u64,
        host: HostContextIdentity,
        operands: Vec<PresentationOperand>,
        budget: &mut CaptureBudget,
    ) -> Result<Self, PresentationError> {
        let mut answers = HashMap::new();
        let mut candidates = HashSet::new();
        candidates
            .try_reserve(operands.len())
            .map_err(|_| PresentationError::ResourceExhausted)?;
        for operand in &operands {
            if operand.leaves.is_empty() || !candidates.insert(operand.candidate_slot) {
                return Err(PresentationError::InvalidSlots);
            }
            let text = operand
                .text_bytes()
                .ok_or(PresentationError::ResourceExhausted)?;
            // Conservative map/set overhead plus owned DTO/leaf inline storage.
            let other = operand
                .leaves
                .len()
                .checked_mul(std::mem::size_of::<PresentationLeaf>() + 128)
                .and_then(|n| n.checked_add(std::mem::size_of::<PresentationOperand>() + 128))
                .ok_or(PresentationError::ResourceExhausted)?;
            budget.charge(text, other)?;
            answers
                .try_reserve(operand.leaves.len())
                .map_err(|_| PresentationError::ResourceExhausted)?;
            for leaf in &operand.leaves {
                if answers
                    .insert((operand.candidate_slot, leaf.slot), None)
                    .is_some()
                {
                    return Err(PresentationError::InvalidSlots);
                }
            }
        }
        let remaining = answers.len();
        Ok(Self {
            revision,
            host,
            operands,
            answers,
            remaining,
        })
    }
    pub fn page(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<&[PresentationOperand], PresentationError> {
        if limit == 0 || limit > PAGE_LIMIT || offset > self.operands.len() {
            return Err(PresentationError::InvalidSlots);
        }
        Ok(&self.operands[offset..offset.saturating_add(limit).min(self.operands.len())])
    }
    pub fn submit(
        &mut self,
        revision: u64,
        host: &HostContextIdentity,
        batch: &[PresentationAnswer],
    ) -> Result<(), PresentationError> {
        if revision != self.revision || host != &self.host {
            return Err(PresentationError::Stale);
        }
        if batch.len() > self.remaining {
            return Err(PresentationError::InvalidSlots);
        }
        let mut seen = HashSet::new();
        seen.try_reserve(batch.len())
            .map_err(|_| PresentationError::ResourceExhausted)?;
        for answer in batch {
            let key = (answer.candidate_slot, answer.leaf_slot);
            if !seen.insert(key) || !matches!(self.answers.get(&key), Some(None)) {
                return Err(PresentationError::InvalidSlots);
            }
        }
        for answer in batch {
            self.answers.insert(
                (answer.candidate_slot, answer.leaf_slot),
                Some(answer.matches),
            );
        }
        self.remaining -= batch.len();
        Ok(())
    }
    pub fn into_proof(self) -> Result<PresentationProof, PresentationError> {
        if self.remaining != 0 {
            return Err(PresentationError::Incomplete);
        }
        Ok(PresentationProof {
            host: self.host,
            operands: self.operands,
            answers: self.answers,
        })
    }
    /// Validate the whole fresh snapshot before consuming any copied answer.
    /// Candidate slots may compact after eligibility shrinks; group identity
    /// plus every required raw input and leaf must still match exactly.
    pub fn reuse_proof(&mut self, proof: &PresentationProof) -> Result<(), PresentationError> {
        if self.host != proof.host {
            return Err(PresentationError::Stale);
        }
        let mut old = HashMap::new();
        old.try_reserve(proof.operands.len())
            .map_err(|_| PresentationError::ResourceExhausted)?;
        for operand in &proof.operands {
            if old.insert(operand.group_id_hex.as_str(), operand).is_some() {
                return Err(PresentationError::InvalidSlots);
            }
        }
        let mut batch = Vec::new();
        batch
            .try_reserve_exact(self.remaining)
            .map_err(|_| PresentationError::ResourceExhausted)?;
        for operand in &self.operands {
            let previous = old
                .get(operand.group_id_hex.as_str())
                .ok_or(PresentationError::Stale)?;
            if !operand.same_required_inputs(previous) {
                return Err(PresentationError::Stale);
            }
            for leaf in &operand.leaves {
                let matches = proof
                    .answers
                    .get(&(previous.candidate_slot, leaf.slot))
                    .copied()
                    .flatten()
                    .ok_or(PresentationError::Stale)?;
                batch.push(PresentationAnswer {
                    candidate_slot: operand.candidate_slot,
                    leaf_slot: leaf.slot,
                    matches,
                });
            }
        }
        self.submit(self.revision, &self.host.clone(), &batch)
    }
    pub fn operand_count(&self) -> usize {
        self.operands.len()
    }
    pub fn is_complete(&self) -> bool {
        self.remaining == 0
    }
    pub fn answers(&self) -> Result<&HashMap<(u64, u32), Option<bool>>, PresentationError> {
        if self.remaining != 0 {
            return Err(PresentationError::Incomplete);
        }
        Ok(&self.answers)
    }
    #[cfg(test)]
    pub fn finish(self) -> Result<HashMap<(u64, u32), bool>, PresentationError> {
        if self.remaining != 0 {
            return Err(PresentationError::Incomplete);
        }
        Ok(self
            .answers
            .into_iter()
            .map(|(key, value)| (key, value.expect("all issued slots answered")))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn host() -> HostContextIdentity {
        HostContextIdentity {
            account_id_hex: "private-account-sentinel".into(),
            runtime_generation: 7,
            selection_generation: 8,
            presentation_context_id: 9,
        }
    }
    fn operand(slot: u64) -> PresentationOperand {
        PresentationOperand {
            candidate_slot: slot,
            group_id_hex: "private-group-sentinel".into(),
            row_group_name: "private-title-sentinel".into(),
            fallback_group_name: String::new(),
            projected_title: None,
            selected_title: Some(PresentationText::Literal(
                "private-selected-sentinel".into(),
            )),
            selected_peer_id_hex: Some("private-peer-sentinel".into()),
            roster_peer_id_hex: None,
            roster_peer_present: false,
            roster_member_count: 2,
            pending_confirmation: true,
            welcomer_id_hex: Some("private-inviter-sentinel".into()),
            conversation_kind: Some(ChatConversationKind::Direct),
            active_account_is_sole_member: false,
            description: Some("private-description-sentinel".into()),
            search: None,
            leaves: vec![
                PresentationLeaf {
                    slot: 70,
                    kind: PresentationLeafKind::TitleContains,
                    needle: "private-needle-sentinel".into(),
                },
                PresentationLeaf {
                    slot: 99,
                    kind: PresentationLeafKind::LegacyKeyword,
                    needle: "private-keyword-sentinel".into(),
                },
            ],
        }
    }
    fn answer(candidate_slot: u64, leaf_slot: u32) -> PresentationAnswer {
        PresentationAnswer {
            candidate_slot,
            leaf_slot,
            matches: true,
        }
    }
    #[test]
    fn replies_are_exact_atomic_and_revision_bound() {
        let identity = host();
        let mut pending = PendingPresentation::new(
            4,
            identity.clone(),
            vec![operand(500)],
            &mut CaptureBudget::default(),
        )
        .unwrap();
        assert_eq!(
            pending.submit(3, &identity, &[answer(500, 70)]),
            Err(PresentationError::Stale)
        );
        let mut changed = identity.clone();
        changed.presentation_context_id += 1;
        assert_eq!(
            pending.submit(4, &changed, &[answer(500, 70)]),
            Err(PresentationError::Stale)
        );
        assert_eq!(
            pending.submit(4, &identity, &[answer(500, 70), answer(500, 70)]),
            Err(PresentationError::InvalidSlots)
        );
        assert_eq!(
            pending.submit(4, &identity, &[answer(500, 70), answer(501, 99)]),
            Err(PresentationError::InvalidSlots)
        );
        // First slot in rejected batches was not consumed.
        pending.submit(4, &identity, &[answer(500, 70)]).unwrap();
        assert_eq!(pending.remaining, 1);
        assert_eq!(
            pending.submit(4, &identity, &[answer(500, 70)]),
            Err(PresentationError::InvalidSlots)
        );
        pending
            .submit(
                4,
                &identity,
                &[PresentationAnswer {
                    matches: false,
                    ..answer(500, 99)
                }],
            )
            .unwrap();
        let results = pending.finish().unwrap();
        assert_eq!(results.len(), 2);
        assert!(!results[&(500, 99)]);
    }
    #[test]
    fn incomplete_empty_and_duplicate_operands() {
        let pending =
            PendingPresentation::new(1, host(), vec![operand(3)], &mut CaptureBudget::default())
                .unwrap();
        assert_eq!(pending.finish(), Err(PresentationError::Incomplete));
        assert!(
            PendingPresentation::new(
                1,
                host(),
                vec![operand(3), operand(3)],
                &mut CaptureBudget::default()
            )
            .is_err()
        );
        let pending =
            PendingPresentation::new(1, host(), vec![], &mut CaptureBudget::default()).unwrap();
        assert!(pending.finish().unwrap().is_empty());
    }
    #[test]
    fn resource_refusal_is_checked_and_does_not_advance_budget() {
        let mut budget = CaptureBudget::default();
        budget.charge(TEXT_BUDGET, 0).unwrap();
        assert_eq!(
            budget.charge(1, 0),
            Err(PresentationError::ResourceExhausted)
        );
        assert_eq!(budget.text, TEXT_BUDGET);
        assert_eq!(
            budget.charge(usize::MAX, 1),
            Err(PresentationError::ResourceExhausted)
        );
        budget.charge(0, CAPTURE_BUDGET - TEXT_BUDGET).unwrap();
        assert_eq!(
            budget.charge(0, 1),
            Err(PresentationError::ResourceExhausted)
        );
    }
    #[test]
    fn pages_are_bounded_and_debug_redacts_every_payload() {
        let pending =
            PendingPresentation::new(1, host(), vec![operand(500)], &mut CaptureBudget::default())
                .unwrap();
        assert_eq!(pending.page(0, 200).unwrap().len(), 1);
        assert!(pending.page(0, 201).is_err());
        assert!(pending.page(2, 1).is_err());
        let debug = format!(
            "{:?}{:?}{:?}{:?}{:?}",
            host(),
            operand(500),
            operand(500).leaves,
            answer(500, 70),
            pending
        );
        assert!(!debug.contains("sentinel"));
        assert!(!debug.contains("500"));
    }
    #[test]
    fn completed_proof_maps_compacted_slots_and_rejects_changed_required_inputs_atomically() {
        let mut original =
            PendingPresentation::new(1, host(), vec![operand(77)], &mut CaptureBudget::default())
                .unwrap();
        original
            .submit(1, &host(), &[answer(77, 70), answer(77, 99)])
            .unwrap();
        let proof = original.into_proof().unwrap();
        let mut same =
            PendingPresentation::new(2, host(), vec![operand(0)], &mut CaptureBudget::default())
                .unwrap();
        same.reuse_proof(&proof).unwrap();
        assert!(same.is_complete());
        let mut changed = operand(0);
        changed.selected_title = Some(PresentationText::Literal(
            "changed after host answer".into(),
        ));
        let mut stale =
            PendingPresentation::new(2, host(), vec![changed], &mut CaptureBudget::default())
                .unwrap();
        assert_eq!(stale.reuse_proof(&proof), Err(PresentationError::Stale));
        assert_eq!(stale.remaining, 2);
        let mut identity = host();
        identity.presentation_context_id += 1;
        let mut changed_host =
            PendingPresentation::new(2, identity, vec![operand(0)], &mut CaptureBudget::default())
                .unwrap();
        assert_eq!(
            changed_host.reuse_proof(&proof),
            Err(PresentationError::Stale)
        );
        let mut new_peer = operand(0);
        new_peer.roster_peer_present = true;
        let mut changed_peer =
            PendingPresentation::new(2, host(), vec![new_peer], &mut CaptureBudget::default())
                .unwrap();
        assert_eq!(
            changed_peer.reuse_proof(&proof),
            Err(PresentationError::Stale)
        );
        let debug = format!("{proof:?}");
        assert!(!debug.contains("private-"));
    }
}
