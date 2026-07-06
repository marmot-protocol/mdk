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

/// One forensic audit event. Only its `kind` matters to the classifier.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditEvent {
    pub kind: EventKind,
}

/// The event kinds the classifier reasons about. Every other kind maps to
/// [`EventKind::Other`], so unknown or irrelevant events never fail the parse.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    /// `ForkRecoveryManager` resolved a same-epoch commit race.
    ForkResolution { winner: ForkWinner },
    /// `select_canonical_branch` evaluated a candidate set. Contested iff a
    /// branch actually lost (or more than one candidate was in play).
    ConvergenceDecision {
        #[serde(default)]
        candidates: Vec<serde_json::Value>,
        #[serde(default)]
        losing_branch_ids: Vec<String>,
    },
    #[serde(other)]
    Other,
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
            EventKind::ConvergenceDecision { candidates, losing_branch_ids }
                if !losing_branch_ids.is_empty() || candidates.len() >= 2
        )
    }

    /// A fork resolution whose winning snapshot was missing — unreproducible.
    pub fn is_missing_snapshot_fork(&self) -> bool {
        matches!(
            self,
            EventKind::ForkResolution {
                winner: ForkWinner::MissingSnapshot
            }
        )
    }

    /// Any fork resolution, regardless of winner.
    pub fn is_fork_resolution(&self) -> bool {
        matches!(self, EventKind::ForkResolution { .. })
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
