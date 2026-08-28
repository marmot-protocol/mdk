//! Machine-readable convergence-policy classification.
//!
//! This is conformance metadata, not a wire format. Marmot convergence v1 is
//! the implicit mandatory baseline. A future behavior-changing policy requires
//! a new required app component; operational constants remain local only while
//! they preserve fail-closed and closed-input fixed-point invariants.

use serde::{Deserialize, Serialize};

pub const ADOPTED_MARMOT_CONVERGENCE_COMMIT: &str = "4ad4ae21479c3f3fa9950c6fc4556a76941a62e1";
pub const ACTIVE_CONVERGENCE_POLICY_ID: &str = "marmot-convergence-v1-implicit";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstantInfluence {
    SelectedStateSemantic,
    BatchLifecycleSemantic,
    SecurityRetentionAlignment,
    OperationalResource,
    OperationalScheduler,
    InputAcquisition,
    Sentinel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersioningRule {
    /// Mandatory implicit policy in every v1 implementation; no group field.
    ImplicitV1,
    /// Must remain identical to the owning implicit-v1 semantic constant.
    CoupledToImplicitV1,
    /// Local-only while it cannot change a settled closed-input result.
    OperationalNonInterference,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstantDecision {
    pub id: &'static str,
    pub influence: ConstantInfluence,
    pub versioning: VersioningRule,
}

pub const CONSTANT_DECISIONS: [ConstantDecision; 32] = [
    decision(
        "P1",
        ConstantInfluence::SelectedStateSemantic,
        VersioningRule::ImplicitV1,
    ),
    decision(
        "P2",
        ConstantInfluence::SelectedStateSemantic,
        VersioningRule::ImplicitV1,
    ),
    decision(
        "P3",
        ConstantInfluence::SecurityRetentionAlignment,
        VersioningRule::CoupledToImplicitV1,
    ),
    decision(
        "P4",
        ConstantInfluence::BatchLifecycleSemantic,
        VersioningRule::ImplicitV1,
    ),
    decision(
        "P5",
        ConstantInfluence::BatchLifecycleSemantic,
        VersioningRule::ImplicitV1,
    ),
    decision(
        "P6",
        ConstantInfluence::SelectedStateSemantic,
        VersioningRule::ImplicitV1,
    ),
    decision(
        "P7",
        ConstantInfluence::SelectedStateSemantic,
        VersioningRule::ImplicitV1,
    ),
    decision(
        "P8",
        ConstantInfluence::SelectedStateSemantic,
        VersioningRule::ImplicitV1,
    ),
    decision(
        "P9",
        ConstantInfluence::SelectedStateSemantic,
        VersioningRule::ImplicitV1,
    ),
    decision(
        "P10",
        ConstantInfluence::SelectedStateSemantic,
        VersioningRule::ImplicitV1,
    ),
    decision(
        "E1",
        ConstantInfluence::OperationalResource,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "E2",
        ConstantInfluence::OperationalResource,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "E3",
        ConstantInfluence::OperationalResource,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "E4",
        ConstantInfluence::OperationalScheduler,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "E5",
        ConstantInfluence::OperationalResource,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "E6",
        ConstantInfluence::OperationalResource,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "E7",
        ConstantInfluence::OperationalScheduler,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "E8",
        ConstantInfluence::OperationalResource,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "E9",
        ConstantInfluence::OperationalResource,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "E10",
        ConstantInfluence::OperationalResource,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "E11",
        ConstantInfluence::OperationalScheduler,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "E12",
        ConstantInfluence::OperationalScheduler,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "A1",
        ConstantInfluence::OperationalScheduler,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "A2",
        ConstantInfluence::OperationalScheduler,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "A3",
        ConstantInfluence::OperationalScheduler,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "A4",
        ConstantInfluence::OperationalScheduler,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "A5",
        ConstantInfluence::Sentinel,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "A6",
        ConstantInfluence::InputAcquisition,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "A7",
        ConstantInfluence::InputAcquisition,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "A8",
        ConstantInfluence::InputAcquisition,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "A9",
        ConstantInfluence::InputAcquisition,
        VersioningRule::OperationalNonInterference,
    ),
    decision(
        "A10",
        ConstantInfluence::InputAcquisition,
        VersioningRule::OperationalNonInterference,
    ),
];

const fn decision(
    id: &'static str,
    influence: ConstantInfluence,
    versioning: VersioningRule,
) -> ConstantDecision {
    ConstantDecision {
        id,
        influence,
        versioning,
    }
}

pub fn future_policy_change_requires_new_required_app_component(changed_ids: &[&str]) -> bool {
    changed_ids.iter().any(|changed| {
        match CONSTANT_DECISIONS
            .iter()
            .find(|decision| decision.id == *changed)
        {
            Some(decision) => matches!(
                decision.versioning,
                VersioningRule::ImplicitV1 | VersioningRule::CoupledToImplicitV1
            ),
            // Unknown constants have no proof of operational non-interference.
            None => true,
        }
    })
}
