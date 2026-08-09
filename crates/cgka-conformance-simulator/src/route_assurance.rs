//! Machine-readable ownership and claim lifecycle for convergence decision routes.
//!
//! This module records assurance evidence; it does not choose a convergence
//! result and is never called by production engine code.

use serde::{Deserialize, Serialize};

pub const ROUTE_ASSURANCE_SCHEMA_VERSION: &str = "1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionRouteId {
    OrdinaryIngest,
    PairwiseForkRecovery,
    StoredConvergence,
    CandidateMaterialization,
    RetainedHistoryReplay,
    CrashRestartRecovery,
    ApplicationDisposition,
}

const DECISION_ROUTE_VARIANT_COUNT: usize = 7;

impl DecisionRouteId {
    pub const ALL: [Self; DECISION_ROUTE_VARIANT_COUNT] = [
        Self::OrdinaryIngest,
        Self::PairwiseForkRecovery,
        Self::StoredConvergence,
        Self::CandidateMaterialization,
        Self::RetainedHistoryReplay,
        Self::CrashRestartRecovery,
        Self::ApplicationDisposition,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OrdinaryIngest => "ordinary_ingest",
            Self::PairwiseForkRecovery => "pairwise_fork_recovery",
            Self::StoredConvergence => "stored_convergence",
            Self::CandidateMaterialization => "candidate_materialization",
            Self::RetainedHistoryReplay => "retained_history_replay",
            Self::CrashRestartRecovery => "crash_restart_recovery",
            Self::ApplicationDisposition => "application_disposition",
        }
    }
}

const _: [(); DECISION_ROUTE_VARIANT_COUNT] = [(); DecisionRouteId::ALL.len()];

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RouteBranchV1 {
    pub id: u8,
    pub effective_depth: u8,
    /// Lower values win after depth. The value represents an already-derived
    /// deterministic ordering key, not raw unauthenticated input.
    pub ordering_key: u8,
}

/// Bounded abstract lifecycle for a closed durable branch set. Candidate
/// branches are durable; the route and any provisional winner are volatile.
///
/// This is a deterministic bookkeeping model and mutation witness, not an
/// exhaustively explored transition system or a production route-equivalence
/// proof.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RouteLifecycleStateV1 {
    pub durable_branches: Vec<RouteBranchV1>,
    pub volatile_route: Option<DecisionRouteId>,
    pub volatile_provisional_winner: Option<u8>,
    pub canonical_winner: Option<u8>,
    pub crashed: bool,
}

impl RouteLifecycleStateV1 {
    pub fn new(mut durable_branches: Vec<RouteBranchV1>) -> Self {
        durable_branches.sort_by_key(|branch| branch.id);
        Self {
            durable_branches,
            volatile_route: None,
            volatile_provisional_winner: None,
            canonical_winner: None,
            crashed: false,
        }
    }

    pub fn observe_route(mut self, route: DecisionRouteId, provisional_winner: Option<u8>) -> Self {
        self.volatile_route = Some(route);
        self.volatile_provisional_winner = provisional_winner;
        self
    }

    pub fn crash(mut self) -> Self {
        self.crashed = true;
        self.volatile_route = None;
        self.volatile_provisional_winner = None;
        self
    }

    pub fn restart(mut self) -> Self {
        self.crashed = false;
        self
    }

    pub fn settle(mut self) -> Self {
        if self.crashed {
            return self;
        }
        self.canonical_winner = self
            .durable_branches
            .iter()
            .max_by(|left, right| {
                left.effective_depth
                    .cmp(&right.effective_depth)
                    .then_with(|| right.ordering_key.cmp(&left.ordering_key))
                    .then_with(|| right.id.cmp(&left.id))
            })
            .map(|branch| branch.id);
        self
    }

    /// Deliberately inconsistent route used only by mutation adequacy. It
    /// terminalizes the pairwise provisional result rather than reconsidering
    /// the complete durable branch set.
    pub(crate) fn settle_with_terminal_pairwise_loser(mut self) -> Self {
        if self.volatile_route == Some(DecisionRouteId::PairwiseForkRecovery) {
            self.canonical_winner = self.volatile_provisional_winner;
            return self;
        }
        self.settle()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ProductionDecisionSiteV1 {
    pub path: &'static str,
    pub marker: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceOwnershipStatus {
    Covered,
    Partial,
    Gap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AssuranceOwnerV1 {
    pub status: AssuranceOwnershipStatus,
    pub owner: &'static str,
    pub limitation: &'static str,
}

impl AssuranceOwnerV1 {
    const fn covered(owner: &'static str) -> Self {
        Self {
            status: AssuranceOwnershipStatus::Covered,
            owner,
            limitation: "",
        }
    }

    const fn partial(owner: &'static str, limitation: &'static str) -> Self {
        Self {
            status: AssuranceOwnershipStatus::Partial,
            owner,
            limitation,
        }
    }

    pub const fn gap(owner: &'static str, limitation: &'static str) -> Self {
        Self {
            status: AssuranceOwnershipStatus::Gap,
            owner,
            limitation,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DecisionRouteInventoryEntryV1 {
    pub route: DecisionRouteId,
    pub production_sites: &'static [ProductionDecisionSiteV1],
    pub adopted_rule: &'static str,
    pub reference_model: AssuranceOwnerV1,
    pub mutation_sentinel: AssuranceOwnerV1,
    pub campaign: AssuranceOwnerV1,
}

const ORDINARY_INGEST_SITES: &[ProductionDecisionSiteV1] = &[ProductionDecisionSiteV1 {
    path: "crates/cgka-engine/src/message_processor/ingest.rs",
    marker: "let commit_should_enter_convergence =",
}];
const PAIRWISE_FORK_RECOVERY_SITES: &[ProductionDecisionSiteV1] = &[
    ProductionDecisionSiteV1 {
        path: "crates/cgka-engine/src/message_processor/ingest.rs",
        marker: ".resolve_fork_candidate(",
    },
    ProductionDecisionSiteV1 {
        path: "crates/cgka-engine/src/fork_recovery.rs",
        marker: "struct ForkRecoveryManager",
    },
];
const STORED_CONVERGENCE_SITES: &[ProductionDecisionSiteV1] = &[ProductionDecisionSiteV1 {
    path: "crates/cgka-engine/src/distributed_convergence.rs",
    marker: "fn converge_stored_openmls_messages_with_time(",
}];
const CANDIDATE_MATERIALIZATION_SITES: &[ProductionDecisionSiteV1] = &[ProductionDecisionSiteV1 {
    path: "crates/cgka-engine/src/openmls_projection.rs",
    marker: "fn canonicalize_stored_openmls_messages_with_profile_policy<",
}];
const RETAINED_HISTORY_REPLAY_SITES: &[ProductionDecisionSiteV1] = &[
    ProductionDecisionSiteV1 {
        path: "crates/cgka-engine/src/message_processor/ingest.rs",
        marker: "fn convergence_ingest_outcome(",
    },
    ProductionDecisionSiteV1 {
        path: "crates/cgka-engine/src/openmls_projection.rs",
        marker: "CanonicalizationError::MissingRetainedAnchor",
    },
];
const CRASH_RESTART_RECOVERY_SITES: &[ProductionDecisionSiteV1] = &[
    ProductionDecisionSiteV1 {
        path: "crates/cgka-engine/src/engine.rs",
        marker: "fn hydrate_one_stored_group(",
    },
    ProductionDecisionSiteV1 {
        path: "crates/cgka-engine/src/distributed_convergence.rs",
        marker: "fn discard_stale_convergence_pass(",
    },
];
const APPLICATION_DISPOSITION_SITES: &[ProductionDecisionSiteV1] = &[
    ProductionDecisionSiteV1 {
        path: "crates/cgka-engine/src/message_processor/ingest.rs",
        marker: "fn convergence_ingest_outcome(",
    },
    ProductionDecisionSiteV1 {
        path: "crates/cgka-engine/src/openmls_projection.rs",
        marker: "fn persist_openmls_canonicalization_dispositions<",
    },
];

/// Current production decision-route inventory. Partial and gap entries are
/// deliberate: an inventory must not turn the existence of adjacent evidence
/// into a stronger route-equivalence claim than that evidence supports.
pub const DECISION_ROUTE_INVENTORY: &[DecisionRouteInventoryEntryV1] = &[
    DecisionRouteInventoryEntryV1 {
        route: DecisionRouteId::OrdinaryIngest,
        production_sites: ORDINARY_INGEST_SITES,
        adopted_rule: "Authenticated eligible competing commits enter the durable convergence input set; only a named terminal disposition removes eligibility.",
        reference_model: AssuranceOwnerV1::partial(
            "reference_convergence::evaluate",
            "Models canonical selection and dispositions but not the production route that admitted the input.",
        ),
        mutation_sentinel: AssuranceOwnerV1::covered(
            "cutoff_boundary_admission and output_invalidation",
        ),
        campaign: AssuranceOwnerV1::partial(
            "convergence-committer-selected/v1 and convergence-witness-selected/v1",
            "The fixed vectors cover observer ingest but not equivalence with every other decision route.",
        ),
    },
    DecisionRouteInventoryEntryV1 {
        route: DecisionRouteId::PairwiseForkRecovery,
        production_sites: PAIRWISE_FORK_RECOVERY_SITES,
        adopted_rule: "A pairwise winner is provisional and every authenticated eligible loser remains reconsiderable by the shared closed-input selector.",
        reference_model: AssuranceOwnerV1::partial(
            "route_assurance::RouteLifecycleStateV1",
            "Models closed-input route volatility abstractly; it is not exhaustively explored or compared against production routing.",
        ),
        mutation_sentinel: AssuranceOwnerV1::partial(
            "pairwise_losing_branch_terminalization",
            "The sibling-model mutant proves the witness distinguishes two abstract rules, not that production takes the adopted transition.",
        ),
        campaign: AssuranceOwnerV1::partial(
            "pairwise_incumbent_defers_to_deeper_convergence_branch and pairwise_candidate_win_leaves_old_incumbent_reconsiderable",
            "Engine regressions cover reconsideration, but the cross-adapter #1236 topology remains open.",
        ),
    },
    DecisionRouteInventoryEntryV1 {
        route: DecisionRouteId::StoredConvergence,
        production_sites: STORED_CONVERGENCE_SITES,
        adopted_rule: "Freeze one dependency-closed durable input set, select with the adopted comparator, and apply state plus dispositions atomically.",
        reference_model: AssuranceOwnerV1::partial(
            "reference_convergence::evaluate and lifecycle_model",
            "Selection and frozen-pass lifecycle are modeled separately; route equivalence is not yet a modeled transition.",
        ),
        mutation_sentinel: AssuranceOwnerV1::covered(
            "selector_comparison_order and frozen_member_persistence",
        ),
        campaign: AssuranceOwnerV1::partial(
            "stored convergence restart properties and convergence-chaos/v1",
            "The route is exercised without the complete committer-versus-observer cross-route matrix.",
        ),
    },
    DecisionRouteInventoryEntryV1 {
        route: DecisionRouteId::CandidateMaterialization,
        production_sites: CANDIDATE_MATERIALIZATION_SITES,
        adopted_rule: "Materialization may fail only with a named deferred, resource, or fail-closed outcome; it cannot silently discard an authenticated eligible branch.",
        reference_model: AssuranceOwnerV1::partial(
            "reference_convergence dependency closure and dispositions",
            "The symbolic model does not execute OpenMLS checkpoint or retained-anchor replay.",
        ),
        mutation_sentinel: AssuranceOwnerV1::covered(
            "retained_history_expiration_boundary and frozen_member_persistence",
        ),
        campaign: AssuranceOwnerV1::partial(
            "openmls_replay_probe and replay-budget repair tests",
            "Byte replay is covered, but equality with live pairwise routing remains open.",
        ),
    },
    DecisionRouteInventoryEntryV1 {
        route: DecisionRouteId::RetainedHistoryReplay,
        production_sites: RETAINED_HISTORY_REPLAY_SITES,
        adopted_rule: "Duplicate and delivery order do not change the closed-input result; missing history or retention boundaries produce named incomplete or refusal evidence.",
        reference_model: AssuranceOwnerV1::partial(
            "lifecycle_model unequal-history transitions",
            "The model represents unequal input sets but not the production retained-relay query and replay route.",
        ),
        mutation_sentinel: AssuranceOwnerV1::covered(
            "retained_history_expiration_boundary and witness_sender_epoch_deduplication",
        ),
        campaign: AssuranceOwnerV1::partial(
            "retained-relay history equality and chat-journey/v1 offline profile",
            "History recovery is exercised without the complete #1236 cross-route topology.",
        ),
    },
    DecisionRouteInventoryEntryV1 {
        route: DecisionRouteId::CrashRestartRecovery,
        production_sites: CRASH_RESTART_RECOVERY_SITES,
        adopted_rule: "Durable candidate membership and frozen revision survive restart while volatile route hints and staged replay state do not define the result.",
        reference_model: AssuranceOwnerV1::covered("lifecycle_model crash and restart transitions"),
        mutation_sentinel: AssuranceOwnerV1::covered(
            "frozen_member_persistence and scheduler_deadline_rearm",
        ),
        campaign: AssuranceOwnerV1::partial(
            "durable-phase kill matrix and stored convergence restart properties",
            "Restart coverage has not yet been crossed with every #1236 route transition.",
        ),
    },
    DecisionRouteInventoryEntryV1 {
        route: DecisionRouteId::ApplicationDisposition,
        production_sites: APPLICATION_DISPOSITION_SITES,
        adopted_rule: "Every application input ends canonical, explicitly invalidated, retryable or deferred, resource-refused, rejected, or durably fail-closed; no input disappears from accounting.",
        reference_model: AssuranceOwnerV1::covered(
            "reference_convergence application dispositions",
        ),
        mutation_sentinel: AssuranceOwnerV1::covered("output_invalidation"),
        campaign: AssuranceOwnerV1::partial(
            "scenario-input ledgers and bidirectional decryptability probes",
            "Complete sender-visible disposition coverage across branch replacement remains open.",
        ),
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceClaimId {
    RouteEquivalence,
    ReconsiderableLoser,
    RestartInvariance,
    ExactCryptographicAgreement,
    ActiveBidirectionalDecryptability,
    CompleteApplicationDisposition,
}

impl AssuranceClaimId {
    pub const ALL: [Self; 6] = [
        Self::RouteEquivalence,
        Self::ReconsiderableLoser,
        Self::RestartInvariance,
        Self::ExactCryptographicAgreement,
        Self::ActiveBidirectionalDecryptability,
        Self::CompleteApplicationDisposition,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RouteEquivalence => "route_equivalence",
            Self::ReconsiderableLoser => "reconsiderable_loser",
            Self::RestartInvariance => "restart_invariance",
            Self::ExactCryptographicAgreement => "exact_cryptographic_agreement",
            Self::ActiveBidirectionalDecryptability => "active_bidirectional_decryptability",
            Self::CompleteApplicationDisposition => "complete_application_disposition",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceClaimStatus {
    Open,
    Covered,
    Reopened,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssuranceFalsificationV1 {
    pub evidence_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssuranceClaimRecordV1 {
    pub schema_version: String,
    pub claim_id: AssuranceClaimId,
    pub status: AssuranceClaimStatus,
    pub passing_evidence: Vec<String>,
    pub falsifications: Vec<AssuranceFalsificationV1>,
}

impl AssuranceClaimRecordV1 {
    pub fn open(claim_id: AssuranceClaimId) -> Self {
        Self {
            schema_version: ROUTE_ASSURANCE_SCHEMA_VERSION.into(),
            claim_id,
            status: AssuranceClaimStatus::Open,
            passing_evidence: Vec::new(),
            falsifications: Vec::new(),
        }
    }

    /// Record a green campaign without allowing it to silently close an
    /// already-known counterexample.
    pub fn record_passing_evidence(&mut self, evidence_id: impl Into<String>) {
        insert_sorted_unique(&mut self.passing_evidence, evidence_id.into());
        if self.status == AssuranceClaimStatus::Open {
            self.status = AssuranceClaimStatus::Covered;
        }
    }

    pub fn reopen(&mut self, evidence_id: impl Into<String>) {
        let evidence_id = evidence_id.into();
        if let Some(existing) = self
            .falsifications
            .iter_mut()
            .find(|existing| existing.evidence_id == evidence_id)
        {
            existing.resolved_by = None;
        } else {
            self.falsifications.push(AssuranceFalsificationV1 {
                evidence_id,
                resolved_by: None,
            });
            self.falsifications
                .sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
        }
        self.status = AssuranceClaimStatus::Reopened;
    }

    /// Resolve one named counterexample with reviewed passing evidence. The
    /// claim remains reopened while any other counterexample is unresolved.
    pub fn resolve_falsification(
        &mut self,
        falsification_id: &str,
        passing_evidence_id: impl Into<String>,
    ) -> bool {
        let passing_evidence_id = passing_evidence_id.into();
        let Some(falsification) = self
            .falsifications
            .iter_mut()
            .find(|entry| entry.evidence_id == falsification_id && entry.resolved_by.is_none())
        else {
            return false;
        };
        falsification.resolved_by = Some(passing_evidence_id.clone());
        insert_sorted_unique(&mut self.passing_evidence, passing_evidence_id);
        self.status = if self
            .falsifications
            .iter()
            .any(|entry| entry.resolved_by.is_none())
        {
            AssuranceClaimStatus::Reopened
        } else {
            AssuranceClaimStatus::Covered
        };
        true
    }
}

pub fn open_route_assurance_claims() -> Vec<AssuranceClaimRecordV1> {
    AssuranceClaimId::ALL
        .into_iter()
        .map(AssuranceClaimRecordV1::open)
        .collect()
}

fn insert_sorted_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
        values.sort();
    }
}
