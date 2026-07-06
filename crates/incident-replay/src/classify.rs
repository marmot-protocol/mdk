//! The classification gate.
//!
//! Everything downstream (extraction, fault synthesis, replay) is gated behind
//! this verdict, so a healthy export yields zero vectors and a clean exit rather
//! than a crash. Built incrementally, one rule per behaviour.

use crate::export::{AgentStateExport, EventKind};
use serde::Serialize;

/// How the pipeline should route an export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// No contested branch — the common case. Zero vectors, clean exit.
    Healthy,
    /// A same-epoch commit race resolved by the fork-recovery seam (Phase 3).
    ForkRecovery,
    /// A quiescence-window branch selection (Phase 4; needs the convergence
    /// assert surface).
    ConvergenceSelected,
    /// Unusable for faithful replay; never fabricate a vector from it.
    Quarantine { reason: QuarantineReason },
}

/// Why an export was quarantined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    /// A `derived_projections` section was capped server-side (`has_more`), so
    /// the export is incomplete.
    TruncatedProjections,
    /// A fork resolution's winning snapshot was missing — unreproducible.
    MissingSnapshot,
}

/// Classify an export into its routing verdict.
pub fn classify(export: &AgentStateExport) -> Verdict {
    // A truncated projection means the export is incomplete: reproduction could
    // miss witnesses or hidden state, so it is unusable regardless of what the
    // (uncapped) event log shows. Gate this first.
    if export
        .derived_projections
        .pagination
        .values()
        .any(|section| section.has_more)
    {
        return Verdict::Quarantine {
            reason: QuarantineReason::TruncatedProjections,
        };
    }
    let kinds = || export.events.iter().map(|event| &event.kind);
    // A contested convergence selection dominates: a real incident can carry
    // both a fork resolution and a convergence decision, and the convergence
    // route (Phase 4) is the one that reproduces it.
    if kinds().any(EventKind::is_contested_convergence) {
        return Verdict::ConvergenceSelected;
    }
    // Below here the export routes to fork recovery, where an unrecoverable
    // winner (missing snapshot) can't be replayed — quarantine instead of
    // fabricating a vector.
    if kinds().any(EventKind::is_missing_snapshot_fork) {
        return Verdict::Quarantine {
            reason: QuarantineReason::MissingSnapshot,
        };
    }
    if kinds().any(EventKind::is_fork_resolution) {
        return Verdict::ForkRecovery;
    }
    Verdict::Healthy
}
