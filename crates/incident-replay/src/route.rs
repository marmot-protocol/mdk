//! Route composition: classify, then drive the chosen incident route through
//! recover → accept, and gather the secondary advisories.
//!
//! This lives in the library rather than the CLI because it is pipeline policy,
//! not presentation: which route an export takes, what happens when that route
//! fails closed, and which co-occurring incidents must still be reported. The
//! CLI is left with I/O and formatting.
//!
//! ## Attested history first
//!
//! Every incident route begins with the producer's own attested normalized
//! history ([`import_attested_history`]): it is the export's account of what
//! actually happened, so no derived archetype can improve on it. The gate reads
//! the export, not the verdict — both incident routes ask it the same question —
//! so it runs once, ahead of route dispatch, and only for the incident verdicts.
//! A legacy export carries no such history, and the archetype routes below take
//! over.
//!
//! ## Fall-through
//!
//! [`classify`] returns a single verdict and the incident routes are ordered
//! (contested convergence outranks fork recovery), so an export carrying both
//! used to lose the lower one entirely: on a real export the convergence
//! recovery fail-closed while the *same* export held a cleanly reproducible
//! membership fork, and the fork was silently discarded.
//!
//! Recovery failing closed is not evidence that the rest of the export is
//! unusable, so a failed route falls through to the remaining lower-precedence
//! ones. Classification precedence is untouched — the fall-through happens only
//! *after* the higher route has already failed — and one rule keeps the outcome
//! honest: **a lower route may override a higher route's quarantine only by
//! producing an accepted vector.** A second quarantine never displaces the
//! higher-precedence one; it is reported as an advisory instead.

use std::fmt;

use cgka_conformance_simulator::VectorFixture;

use crate::artifact::{
    IncidentScenarioArtifactV1, IncidentSourceFormatV1, NormalizedHistoryImportError,
    accept_attested_history, archetype_artifact, import_attested_history,
};
use crate::classify::{QuarantineReason, Verdict, classify, halt_advisory, liveness_advisory};
use crate::export::AgentStateExport;
use crate::fork::ForkCommitKind;
use crate::{accept, accept_convergence, recover_convergence, recover_fork};

/// Vector name for a group-metadata fork-recovery incident.
pub const INCIDENT_NAME: &str = "fork-recovery-incident/v1";
/// Vector name for a membership/admin fork-recovery incident (a distinct shape,
/// so a distinct name and file — it must not overwrite the group-data vector).
pub const MEMBERSHIP_INCIDENT_NAME: &str = "membership-fork-recovery-incident/v1";
/// Vector name for a convergence incident.
pub const CONVERGENCE_NAME: &str = "convergence-incident/v1";

/// A higher-precedence route quarantined, but a lower one reproduced an incident
/// from the same export.
const SUPERSEDED_ROUTE: &str = "superseded route";
/// A higher-precedence route quarantined and the fall-through could not rescue
/// it either.
const FALLBACK_ROUTE: &str = "fallback route";
/// A co-occurring unrecoverable halt (rule 5).
const HALT: &str = "halt";
/// A co-occurring liveness incident (rule 6).
const LIVENESS: &str = "liveness";

/// What the pipeline produced for an export: exactly one primary outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// No incident and no liveness problem. Zero vectors.
    Healthy,
    /// A vector the simulator reproduced, inside its evidence envelope.
    Accepted(Box<IncidentScenarioArtifactV1>),
    /// Fail-closed: a real or unusable incident that yields no vector.
    Quarantine { reason: String },
    /// The simulator machinery itself failed, so the export reached no verdict.
    /// Distinct from [`Outcome::Quarantine`], which *is* a verdict: retrying the
    /// same export on working infrastructure may still classify it.
    InfrastructureFailure { reason: String },
}

/// One secondary line reported alongside the primary [`Outcome`].
///
/// Advisories exist because an export can carry several incidents while
/// [`classify`] returns one verdict. Keeping them separate from the outcome
/// preserves the one-primary-line contract: the outcome says what the pipeline
/// produced, and each advisory names something that outcome does not cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    /// Short category, rendered as `advisory (<label>): <detail>`.
    pub label: &'static str,
    /// The human-readable finding.
    pub detail: String,
}

/// A routed export: one primary outcome plus every co-occurring finding it does
/// not itself report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routing {
    pub outcome: Outcome,
    pub advisories: Vec<Advisory>,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::Healthy => f.write_str("healthy: 0 vectors"),
            Outcome::Accepted(artifact) => {
                write!(f, "accepted: {}", artifact.vector.scenario_name)
            }
            Outcome::Quarantine { reason } => write!(f, "quarantine: {reason}"),
            Outcome::InfrastructureFailure { reason } => write!(f, "error: {reason}"),
        }
    }
}

impl fmt::Display for Advisory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "advisory ({}): {}", self.label, self.detail)
    }
}

/// Classify `export` and run the route its verdict selects, falling through to
/// lower-precedence routes if that one fails closed.
pub fn route(export: &AgentStateExport, source_format: IncidentSourceFormatV1) -> Routing {
    let verdict = classify(export);
    let mut advisories = Vec::new();
    let outcome = routed_outcome(export, source_format, &verdict, &mut advisories);

    advisories.extend(co_occurring_advisories(export, &verdict));
    Routing {
        outcome,
        advisories,
    }
}

/// The primary outcome for `verdict`, appending any fall-through advisory it
/// produced along the way.
fn routed_outcome(
    export: &AgentStateExport,
    source_format: IncidentSourceFormatV1,
    verdict: &Verdict,
    advisories: &mut Vec<Advisory>,
) -> Outcome {
    if matches!(verdict, Verdict::ForkRecovery | Verdict::ConvergenceSelected)
        && let Some(outcome) = attested_outcome(export, source_format)
    {
        return outcome;
    }
    match verdict {
        Verdict::Healthy => Outcome::Healthy,
        Verdict::ForkRecovery => accepted_or_quarantine(fork_route(export, source_format)),
        // The only route with somewhere to fall through to: fork recovery sits
        // below it (rules 3 and 4), and `fork_route` applies both.
        Verdict::ConvergenceSelected => match convergence_route(export, source_format) {
            Ok(artifact) => Outcome::Accepted(artifact),
            Err(superseded) => fall_through_to_fork(export, source_format, superseded, advisories),
        },
        // Not an incident route: nothing to recover, so nothing to fall through
        // to. The quarantine is the outcome.
        Verdict::Quarantine { reason } => Outcome::Quarantine {
            reason: reason.to_string(),
        },
    }
}

/// Run the producer-attested normalized history, if the export carries one.
///
/// `None` is the ordinary legacy-export case: no attested history, so the
/// archetype routes decide the outcome. Anything else is already the answer —
/// attested history is the highest fidelity available, so it neither falls
/// through nor defers to an archetype of the same incident.
fn attested_outcome(
    export: &AgentStateExport,
    source_format: IncidentSourceFormatV1,
) -> Option<Outcome> {
    match import_attested_history(export, source_format) {
        Ok(None) => None,
        Ok(Some(artifact)) => Some(match accept_attested_history(artifact) {
            Ok(artifact) => Outcome::Accepted(Box::new(artifact)),
            Err(error) => attested_failure(&error),
        }),
        Err(error) => Some(attested_failure(&error)),
    }
}

/// A rejected attested history is fail-closed like any other route, *except*
/// when the simulator could not be run at all: that decided nothing about the
/// incident, so reporting a quarantine would state a verdict nobody reached.
fn attested_failure(error: &NormalizedHistoryImportError) -> Outcome {
    let reason = error.to_string();
    match error {
        NormalizedHistoryImportError::Run(_) | NormalizedHistoryImportError::RunTimedOut => {
            Outcome::InfrastructureFailure { reason }
        }
        _ => Outcome::Quarantine { reason },
    }
}

/// Rules 3 and 4: recover the fork, run it against the simulator, and wrap the
/// accepted vector in its archetype evidence envelope. `recover_fork` reports
/// the rule-3 missing snapshot as its own fail-closed error, so this one
/// function is the whole fork route.
fn fork_route(
    export: &AgentStateExport,
    source_format: IncidentSourceFormatV1,
) -> Result<Box<IncidentScenarioArtifactV1>, String> {
    let fork = recover_fork(export).map_err(|err| err.to_string())?;
    let name = match fork.commit {
        ForkCommitKind::GroupData => INCIDENT_NAME,
        ForkCommitKind::Membership => MEMBERSHIP_INCIDENT_NAME,
    };
    let vector = accept(&fork, name).map_err(|err| err.to_string())?;
    archetype(export, source_format, vector)
}

/// Rule 2: recover the contested convergence decision and run it.
fn convergence_route(
    export: &AgentStateExport,
    source_format: IncidentSourceFormatV1,
) -> Result<Box<IncidentScenarioArtifactV1>, String> {
    let conv = recover_convergence(export).map_err(|err| err.to_string())?;
    let vector = accept_convergence(&conv, CONVERGENCE_NAME).map_err(|err| err.to_string())?;
    archetype(export, source_format, vector)
}

/// Envelope an accepted archetype vector. Failing to evidence the incident the
/// vector stands for is fail-closed like any other route failure: an artifact
/// that cannot point at its own source rows is not publishable evidence.
fn archetype(
    export: &AgentStateExport,
    source_format: IncidentSourceFormatV1,
    vector: VectorFixture,
) -> Result<Box<IncidentScenarioArtifactV1>, String> {
    archetype_artifact(export, source_format, vector)
        .map(Box::new)
        .map_err(|err| err.to_string())
}

/// Try the fork route after the convergence route fail-closed with `superseded`.
///
/// The fall-through may only *upgrade* the outcome. If the fork route also
/// yields nothing, the convergence quarantine stays the primary — it is the
/// higher-precedence incident, and demoting it would misreport which one the
/// export is really about.
fn fall_through_to_fork(
    export: &AgentStateExport,
    source_format: IncidentSourceFormatV1,
    superseded: String,
    advisories: &mut Vec<Advisory>,
) -> Outcome {
    // Without a fork resolution there is no lower route to enter, and saying so
    // would be noise rather than a finding.
    if !export
        .events
        .iter()
        .any(|event| event.kind.is_fork_resolution())
    {
        return Outcome::Quarantine { reason: superseded };
    }
    match fork_route(export, source_format) {
        Ok(artifact) => {
            advisories.push(Advisory {
                label: SUPERSEDED_ROUTE,
                detail: format!("contested convergence could not be replayed: {superseded}"),
            });
            Outcome::Accepted(artifact)
        }
        Err(fallback) => {
            advisories.push(Advisory {
                label: FALLBACK_ROUTE,
                detail: format!("fork recovery could not be replayed either: {fallback}"),
            });
            Outcome::Quarantine { reason: superseded }
        }
    }
}

/// The rule-5 and rule-6 incidents the primary outcome does not already report.
///
/// Both gates are verdict-independent, so an export routed to an incident (or
/// quarantined for a different reason) still discloses a halted or stranded
/// engine. Each is suppressed only when the verdict already *is* that finding,
/// which would otherwise print it twice.
fn co_occurring_advisories(export: &AgentStateExport, verdict: &Verdict) -> Vec<Advisory> {
    [
        (HALT, halt_advisory(export)),
        (LIVENESS, liveness_advisory(export)),
    ]
    .into_iter()
    .filter_map(|(label, finding)| {
        let finding = finding?;
        (!is_primary(verdict, &finding)).then(|| Advisory {
            label,
            detail: finding.to_string(),
        })
    })
    .collect()
}

/// Whether `verdict` already reports `finding` as the primary outcome. Compared
/// by variant, not value: the gate that produced the verdict and the gate that
/// produced the advisory are the same computation, so matching variants means
/// matching findings.
fn is_primary(verdict: &Verdict, finding: &QuarantineReason) -> bool {
    matches!(
        verdict,
        Verdict::Quarantine { reason }
            if std::mem::discriminant(reason) == std::mem::discriminant(finding)
    )
}

fn accepted_or_quarantine(result: Result<Box<IncidentScenarioArtifactV1>, String>) -> Outcome {
    match result {
        Ok(artifact) => Outcome::Accepted(artifact),
        Err(reason) => Outcome::Quarantine { reason },
    }
}
