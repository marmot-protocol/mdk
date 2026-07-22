//! A lenient, self-owned model of a Goggles `agent-state.json` export.
//!
//! Only the fields the classifier needs are modelled; every other field is
//! ignored, so the parser tolerates the export growing new fields. The model is
//! deliberately decoupled from `marmot-forensics`: it tracks the stable
//! `marmot-forensics-audit/v2` wire shape that Goggles serialises, not the
//! engine's internal `AuditEventKind` enum (which carries ~40 variants this
//! adapter has no reason to depend on).

use std::collections::BTreeMap;

use serde::Deserialize;

/// A parsed export, reduced to the classifier's inputs.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentStateExport {
    #[serde(default)]
    pub events: Vec<AuditEvent>,
    #[serde(default)]
    pub derived_projections: DerivedProjections,
}

/// Server-side projections. Only the pagination cursors are modelled: they carry
/// the authoritative truncation signal (`has_more`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DerivedProjections {
    #[serde(default)]
    pub pagination: BTreeMap<String, Pagination>,
}

/// One projection section's pagination cursor.
#[derive(Debug, Clone, Deserialize)]
pub struct Pagination {
    /// The section was capped and more rows exist server-side. A truncated
    /// export cannot be reproduced faithfully, so it is quarantined.
    #[serde(default)]
    pub has_more: bool,
}

/// One forensic audit event. The classifier reads `kind` plus the envelope's
/// `engine_id` and `wall_time_ms` (the liveness gates aggregate per-engine
/// activity from them).
#[derive(Debug, Clone, Deserialize)]
pub struct AuditEvent {
    #[serde(default)]
    pub account_ref: Option<String>,
    #[serde(default)]
    pub engine_id: Option<String>,
    #[serde(default)]
    pub wall_time_ms: Option<u64>,
    pub kind: EventKind,
}

/// The event kinds the classifier reasons about. Every other kind maps to
/// [`EventKind::Other`], so unknown or irrelevant events never fail the parse.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    /// `ForkRecoveryManager` resolved a same-epoch commit race. `source_epoch`
    /// is the epoch the branches forked *from*; the racers land at
    /// `source_epoch + 1`. `invalidated_msg_id` is the losing branch's commit.
    ForkResolution {
        winner: ForkWinner,
        #[serde(default)]
        source_epoch: Option<u64>,
        #[serde(default)]
        invalidated_msg_id: Option<String>,
    },
    /// `select_canonical_branch` evaluated a candidate set. Contested iff a
    /// branch actually lost (or more than one candidate was in play). Extraction
    /// (Phase 4) also reads which selector rule was decisive and the winning
    /// branch's witness quorum, to decide whether the decision is reproducible.
    ConvergenceDecision {
        #[serde(default)]
        selected_branch_id: Option<String>,
        #[serde(default)]
        candidates: Vec<ConvergenceCandidate>,
        #[serde(default)]
        rule_trace: Vec<ConvergenceRule>,
        #[serde(default)]
        losing_branch_ids: Vec<String>,
        /// The canonical tip the selector started from and the tip it adopted:
        /// both are epochs the engine has locally materialized, so they feed
        /// the epoch high-water mark. (Real case: an engine whose final acts
        /// before going dark were convergence selections would otherwise read
        /// older than it was.)
        #[serde(default)]
        current_tip_epoch: Option<u64>,
        #[serde(default)]
        selected_tip_epoch: Option<u64>,
    },
    /// A commit changed canonical group state (membership, admin set, profile).
    /// Extraction reads the actor and epoch to find the committers at the
    /// contested tip and the kind of commit they raced with.
    GroupStateChanged {
        #[serde(default)]
        epoch: Option<u64>,
        #[serde(default)]
        change_kind: Option<String>,
        #[serde(default)]
        actor_member_ref: Option<String>,
        /// Commit message that originated this canonical state change. This
        /// joins a fork invalidation to its actor without crossing identity
        /// namespaces.
        #[serde(default)]
        origin_commit_id: Option<String>,
    },
    /// A publish attempt/outcome carrying the `msg_id`.
    PublishOutcome {
        #[serde(default)]
        msg_id: Option<String>,
    },
    PublishAttempt {
        #[serde(default)]
        msg_id: Option<String>,
    },
    /// The engine handled a message while at `epoch`. The densest per-engine
    /// epoch signal in real exports; feeds the epoch high-water mark.
    MessageStateChanged {
        #[serde(default)]
        epoch: Option<u64>,
    },
    /// The engine's epoch machine moved (commit confirmed, group hydrated, …).
    EpochStateChanged {
        #[serde(default)]
        epoch: Option<u64>,
    },
    /// A snapshot of the group as the engine sees it; its epoch is the
    /// engine's own current epoch.
    GroupContext {
        #[serde(default)]
        context: GroupContextSnapshot,
    },
    /// A user-visible action; `epoch_changed` observations carry the epoch the
    /// engine advanced to.
    HumanAction {
        #[serde(default)]
        to_epoch: Option<u64>,
    },
    #[serde(other)]
    Other,
}

/// The group snapshot inside a `group_context` event. Only the epoch is
/// modelled: it is the engine's own view, so the liveness gate reads it. The
/// snapshot's member count is deliberately *not* a gate input — audit is
/// opt-in, so real groups routinely have more members than exporting engines
/// (a real six-member group exported from only two engines) and a coverage gate
/// would quarantine them all, permanently.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct GroupContextSnapshot {
    #[serde(default)]
    pub epoch: Option<u64>,
}

/// One branch the convergence selector evaluated. Only the fields extraction
/// reads are modelled; every other field the export carries is ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct ConvergenceCandidate {
    #[serde(default)]
    pub branch_id: String,
    #[serde(default)]
    pub score: Option<ConvergenceScore>,
}

/// The selector's score for a candidate. Extraction reads two fields: the
/// witness-quorum flag (which distinguishes the committer- and witness-decided
/// shapes) and the valid commit depth (the branch's `tip_epoch - fork_epoch`,
/// before any witness boost). The witness-decided shape reproduces only an
/// *equal-depth* race, so extraction compares the two branches' `valid_commit_depth`
/// to confirm the quorum boost — not raw depth — is what won.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConvergenceScore {
    #[serde(default)]
    pub witness_quorum_met: Option<bool>,
    #[serde(default)]
    pub valid_commit_depth: Option<u64>,
}

/// One selector-rule evaluation. Extraction reads which rule was decisive.
#[derive(Debug, Clone, Deserialize)]
pub struct ConvergenceRule {
    #[serde(default)]
    pub rule_name: String,
    #[serde(default)]
    pub decisive: Option<bool>,
}

/// The role that won a fork resolution. `MissingSnapshot` means the winner's
/// pre-commit snapshot was unavailable, so the incident is unreproducible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkWinner {
    Incumbent,
    Candidate,
    MissingSnapshot,
}

impl EventKind {
    /// A convergence decision that recorded a real contest: a branch lost, or
    /// more than one candidate was evaluated. Routine single-branch passes
    /// (the common case in healthy traffic) are not contests.
    pub fn is_contested_convergence(&self) -> bool {
        matches!(
            self,
            EventKind::ConvergenceDecision { candidates, losing_branch_ids, .. }
                if !losing_branch_ids.is_empty() || candidates.len() >= 2
        )
    }

    /// A fork resolution whose winning snapshot was missing — unreproducible.
    pub fn is_missing_snapshot_fork(&self) -> bool {
        matches!(
            self,
            EventKind::ForkResolution {
                winner: ForkWinner::MissingSnapshot,
                ..
            }
        )
    }

    /// Any fork resolution, regardless of winner.
    pub fn is_fork_resolution(&self) -> bool {
        matches!(self, EventKind::ForkResolution { .. })
    }

    /// The group epoch this event reports the engine itself to be at, if it
    /// reports one. The liveness gates fold these into a per-engine epoch
    /// high-water mark, so only kinds that reflect the engine's *own* state
    /// contribute — kinds describing another engine's traffic do not.
    pub fn observed_epoch(&self) -> Option<u64> {
        match self {
            EventKind::GroupStateChanged { epoch, .. }
            | EventKind::MessageStateChanged { epoch }
            | EventKind::EpochStateChanged { epoch } => *epoch,
            EventKind::GroupContext { context } => context.epoch,
            EventKind::HumanAction { to_epoch } => *to_epoch,
            EventKind::ConvergenceDecision {
                current_tip_epoch,
                selected_tip_epoch,
                ..
            } => (*current_tip_epoch).max(*selected_tip_epoch),
            _ => None,
        }
    }
}

/// Parse a Goggles `agent-state.json` export.
pub fn parse(json: &str) -> Result<AgentStateExport, ParseError> {
    Ok(serde_json::from_str(json)?)
}

/// Why an export could not be parsed.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("agent-state export does not match the expected schema: {0}")]
    Json(#[from] serde_json::Error),
}
