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

/// The epoch-machine state an engine enters when its group is blocked pending a
/// verified repair. Goggles derives its error-severity `epoch_state_transition`
/// projection row from exactly this state, so the classifier reads the primary
/// audit event rather than that derived label: the event is present in both wire
/// formats and does not depend on Goggles' severity derivation.
const UNRECOVERABLE_STATE: &str = "unrecoverable";

/// The healthy epoch-machine state. A halt clears only through a transition into
/// it, but this state alone is *not* the clearing signal — it is by far the
/// engine's most ordinary state, entered from `publish_confirmed`,
/// `publish_failed`, `join_welcome`, `founding_create`,
/// `auto_commit_stage_failed`, and `update_group_data_stage_failed`, none of
/// which repairs anything. `publish_confirmed` alone is one of the commonest rows
/// in a healthy export, so matching the bare state would clear every halt on the
/// engine's next successful publish. Hence the pairing with
/// [`VERIFIED_REPAIR_REASON`]: the reason is what identifies the repair.
const STABLE_STATE: &str = "stable";

/// The `reason` the engine stamps on the one legal exit from
/// [`UNRECOVERABLE_STATE`]. `Engine::join_welcome` routes a halted group's
/// re-join through `EpochManager::repair_to_stable` — the only caller, and the
/// only transition the state machine accepts out of `Unrecoverable` — then emits
/// this `epoch_state_changed { new_state: "stable" }` row unconditionally right
/// after it succeeds (`cgka-engine/src/group_lifecycle.rs`). So the row is
/// present exactly when a verified repair completed: an authenticated Welcome
/// rebuilt the group's state and the durable `unrecoverable` marker is gone.
const VERIFIED_REPAIR_REASON: &str = "join_welcome_repair";

/// Stand-in reason for a halt whose row carried none. Every emitting surface
/// populates a reason today; this keeps the lenient model from dropping a halt
/// on the floor should one ever not.
const UNSPECIFIED_HALT_REASON: &str = "unspecified";

/// Halt reasons that re-assert an existing halt instead of naming its cause.
///
/// `already_unrecoverable` is emitted on every convergence attempt against an
/// already-halted group (`cgka-engine/src/distributed_convergence.rs`) and
/// `hydrate_unrecoverable_group` on every session open over one
/// (`cgka-engine/src/engine.rs`). Both are the halt restating itself — the
/// property rule 5's newest-wins clearing relies on — so they arm the gate like
/// any other halt reason. Neither says why the engine stopped. See
/// [`is_halt_re_assertion`] for what that means for reporting.
const HALT_RE_ASSERTION_REASONS: [&str; 2] =
    ["already_unrecoverable", "hydrate_unrecoverable_group"];

/// Whether `reason` only re-asserts a halt rather than naming its cause.
///
/// Purely a reporting distinction: rule 5 arms on any halt reason, and a window
/// carrying nothing but re-assertions is still a live halt. It exists because
/// `reasons` is the first thing an operator reads, and once a cause is known a
/// re-assertion adds nothing — that the halt is durable and still being retried
/// is what rule 5 *means*, not a separate finding.
pub(crate) fn is_halt_re_assertion(reason: &str) -> bool {
    HALT_RE_ASSERTION_REASONS.contains(&reason)
}

/// A parsed export, reduced to the classifier's inputs.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentStateExport {
    #[serde(default)]
    pub events: Vec<AuditEvent>,
    #[serde(default)]
    pub derived_projections: DerivedProjections,
    /// Optional complete, normalized Scenario IR history. Existing Goggles
    /// exports omit it and remain eligible only for archetype synthesis.
    #[serde(default)]
    pub normalized_scenario_history: Option<crate::artifact::NormalizedScenarioHistoryV1>,
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
/// `engine_id`, `group_ref`, and `wall_time_ms` (the liveness gates aggregate
/// per-engine activity from them).
#[derive(Debug, Clone, Deserialize)]
pub struct AuditEvent {
    #[serde(default)]
    pub account_ref: Option<String>,
    #[serde(default)]
    pub engine_id: Option<String>,
    /// The group this row belongs to, when it is group-scoped. The halt
    /// lifecycle keys on it: `Unrecoverable` is per-group state, so a repair in
    /// one group says nothing about a halt in another. `None` is therefore its
    /// own bucket and never a wildcard — an unattributed repair must not clear an
    /// attributed halt (nor the reverse), which keeps a partially-attributed
    /// export failing closed the way an untimed one does.
    #[serde(default)]
    pub group_ref: Option<String>,
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
    /// `new_state` is the state it moved *into*; the classifier reads it for the
    /// terminal [`UNRECOVERABLE_STATE`] halt, with `reason` naming the trigger
    /// (e.g. `hydrate_unrecoverable_group`).
    EpochStateChanged {
        #[serde(default)]
        epoch: Option<u64>,
        #[serde(default)]
        new_state: Option<String>,
        #[serde(default)]
        reason: Option<String>,
    },
    /// A distributed-convergence run changed lifecycle phase. The classifier
    /// reads only the terminal [`ConvergencePhase::Unrecoverable`] halt (mdk
    /// #1110): the pass stopped and the group stays blocked until a verified
    /// repair clears the marker. `reason` names the halt (e.g.
    /// `frozen_pass_integrity_failure`) and `error_kind` its underlying cause
    /// (e.g. `frozen_member_integrity`). The `missing_retained_anchor` halt
    /// carries only `error_kind`, hence the fallback in
    /// [`EventKind::unrecoverable_halt_reason`].
    ///
    /// No reason is whitelisted, so a retired one still arms the gate on a
    /// historical export — mdk#1182 retired `convergence_pass_base_changed` /
    /// `base_epoch_mismatch`, which is now the non-terminal
    /// [`EventKind::ConvergencePassDiscarded`] repair instead of a halt.
    ConvergenceRunState {
        #[serde(default)]
        phase: Option<ConvergencePhase>,
        #[serde(default)]
        reason: Option<String>,
        #[serde(default)]
        error_kind: Option<String>,
        /// The tip the run started from — an epoch the engine has locally
        /// materialized, so it feeds the epoch high-water mark exactly as
        /// `convergence_decision.current_tip_epoch` does.
        #[serde(default)]
        current_tip_epoch: Option<u64>,
    },
    /// A durable convergence pass whose base epoch disagreed with the device's
    /// tip was discarded so convergence could reopen at the tip (mdk #1182,
    /// which replaced the `base_epoch_mismatch` halt this repairs). Non-terminal
    /// by construction, so it arms no gate — but `current_tip_epoch` is read from
    /// `convergence_tip_epoch()` at every emitting call site, making it the
    /// engine's own materialized tip and therefore epoch evidence of the same
    /// class as `convergence_run_state.current_tip_epoch`.
    ///
    /// `stale_base_epoch` is deliberately not modelled. It is inherited
    /// scheduling state that can sit either behind *or ahead of* the tip, so it
    /// is not an epoch any engine reached; folding it into the high-water mark
    /// could invent a group tip nobody materialized and report every engine
    /// behind it.
    ConvergencePassDiscarded {
        #[serde(default)]
        current_tip_epoch: Option<u64>,
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

/// The lifecycle phase of a convergence run. Only the terminal halt is
/// modelled — every other phase (`started`, `applied`, `waiting`, …) is routine
/// and carries no verdict signal, so it maps to [`ConvergencePhase::Other`]
/// exactly as unknown [`EventKind`]s map to [`EventKind::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConvergencePhase {
    /// The run halted and cannot continue: convergence and ingest stay blocked
    /// for this group until a verified repair path clears the marker.
    Unrecoverable,
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

    /// Why the engine recorded halting unrecoverably, or `None` when this event
    /// is not such a halt.
    ///
    /// A halt is the engine's own statement that it stopped and will stay
    /// stopped until repaired, so — unlike the inferential liveness gate — it
    /// needs no corroborating timestamps to be believed.
    pub fn unrecoverable_halt_reason(&self) -> Option<&str> {
        match self {
            EventKind::ConvergenceRunState {
                phase: Some(ConvergencePhase::Unrecoverable),
                reason,
                error_kind,
                ..
            } => Some(
                reason
                    .as_deref()
                    .or(error_kind.as_deref())
                    .unwrap_or(UNSPECIFIED_HALT_REASON),
            ),
            EventKind::EpochStateChanged {
                new_state: Some(new_state),
                reason,
                ..
            } if new_state == UNRECOVERABLE_STATE => {
                Some(reason.as_deref().unwrap_or(UNSPECIFIED_HALT_REASON))
            }
            _ => None,
        }
    }

    /// The engine recorded completing the verified repair that exits
    /// [`UNRECOVERABLE_STATE`] — the counterpart to
    /// [`EventKind::unrecoverable_halt_reason`], and the only thing that clears a
    /// halt.
    ///
    /// Both halves of the match are load-bearing: [`STABLE_STATE`] alone is the
    /// ordinary healthy state and [`VERIFIED_REPAIR_REASON`] is what marks this
    /// particular transition as the repair.
    pub fn is_verified_repair(&self) -> bool {
        matches!(
            self,
            EventKind::EpochStateChanged {
                new_state: Some(new_state),
                reason: Some(reason),
                ..
            } if new_state == STABLE_STATE && reason == VERIFIED_REPAIR_REASON
        )
    }

    /// The group epoch this event reports the engine itself to be at, if it
    /// reports one. The liveness gates fold these into a per-engine epoch
    /// high-water mark, so only kinds that reflect the engine's *own* state
    /// contribute — kinds describing another engine's traffic do not.
    pub fn observed_epoch(&self) -> Option<u64> {
        match self {
            EventKind::GroupStateChanged { epoch, .. }
            | EventKind::MessageStateChanged { epoch }
            | EventKind::EpochStateChanged { epoch, .. } => *epoch,
            EventKind::GroupContext { context } => context.epoch,
            EventKind::HumanAction { to_epoch } => *to_epoch,
            EventKind::ConvergenceDecision {
                current_tip_epoch,
                selected_tip_epoch,
                ..
            } => (*current_tip_epoch).max(*selected_tip_epoch),
            EventKind::ConvergenceRunState {
                current_tip_epoch, ..
            }
            | EventKind::ConvergencePassDiscarded { current_tip_epoch } => *current_tip_epoch,
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
