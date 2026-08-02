//! Explicit test-policy sweeps over one fixed canonicalization input set.

use cgka_engine::canonicalization::{
    CanonicalizationInput, CanonicalizationPolicy, ConvergenceStatus, canonicalize,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySweepConstantV1 {
    MaxRewindCommits,
    AppMessagePastEpochLimit,
    SettlementQuiescenceMs,
    MaxConvergencePassMs,
    WitnessQuorumSendersPerEpoch,
    WitnessQuorumEpochs,
    MaxWitnessOverrideDepth,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySweepCurveV1 {
    pub schema_version: String,
    pub constant: PolicySweepConstantV1,
    pub retained_input_count: usize,
    pub current_tip_epoch: u64,
    pub retained_anchor_epoch: u64,
    pub points: Vec<PolicySweepPointV1>,
    pub production_auto_tuning_permitted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySweepPointV1 {
    pub value: u64,
    pub selected_branch_id: Option<String>,
    pub selected_tip: Option<u64>,
    pub candidate_count: usize,
    pub eligible_count: usize,
    pub accepted_commits: usize,
    pub deferred_messages: usize,
    pub dropped_messages: usize,
    pub convergence_status: String,
    pub boundary_failure: Option<String>,
}

/// Sweep one constant while preserving the exact pending input set, current
/// tip, retained anchor, time, and every non-selected policy field.
pub fn sweep_canonicalization_policy(
    input: &CanonicalizationInput,
    constant: PolicySweepConstantV1,
    values: impl IntoIterator<Item = u64>,
) -> PolicySweepCurveV1 {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    let points = values
        .into_iter()
        .map(|value| {
            let mut candidate = input.clone();
            let boundary_failure = apply_value(&mut candidate.policy, constant, value).err();
            if let Some(boundary_failure) = boundary_failure {
                return PolicySweepPointV1 {
                    value,
                    selected_branch_id: None,
                    selected_tip: None,
                    candidate_count: 0,
                    eligible_count: 0,
                    accepted_commits: 0,
                    deferred_messages: 0,
                    dropped_messages: 0,
                    convergence_status: "policy_rejected".into(),
                    boundary_failure: Some(boundary_failure),
                };
            }
            let result = canonicalize(candidate);
            PolicySweepPointV1 {
                value,
                selected_branch_id: result.selected_branch_id,
                selected_tip: result.selected_tip,
                candidate_count: result.candidate_count,
                eligible_count: result.eligible_count,
                accepted_commits: result.accepted_commits.len(),
                deferred_messages: result.deferred_messages.len(),
                dropped_messages: result.dropped_messages.len(),
                convergence_status: status_label(result.convergence_status).into(),
                boundary_failure: None,
            }
        })
        .collect();
    PolicySweepCurveV1 {
        schema_version: "1".into(),
        constant,
        retained_input_count: input.pending_messages.len(),
        current_tip_epoch: input.state.current_tip_epoch,
        retained_anchor_epoch: input.state.retained_anchor_epoch,
        points,
        production_auto_tuning_permitted: false,
    }
}

fn apply_value(
    policy: &mut CanonicalizationPolicy,
    constant: PolicySweepConstantV1,
    value: u64,
) -> Result<(), String> {
    match constant {
        PolicySweepConstantV1::MaxRewindCommits => policy.convergence.max_rewind_commits = value,
        PolicySweepConstantV1::AppMessagePastEpochLimit => {
            policy.app_message_past_epoch_limit = value
        }
        PolicySweepConstantV1::SettlementQuiescenceMs => policy.settlement_quiescence_ms = value,
        PolicySweepConstantV1::MaxConvergencePassMs => policy.max_convergence_pass_ms = value,
        PolicySweepConstantV1::WitnessQuorumSendersPerEpoch => {
            policy.convergence.witness_quorum_senders_per_epoch = usize::try_from(value)
                .map_err(|_| "value does not fit witness sender count".to_owned())?
        }
        PolicySweepConstantV1::WitnessQuorumEpochs => {
            policy.convergence.witness_quorum_epochs = usize::try_from(value)
                .map_err(|_| "value does not fit witness epoch count".to_owned())?
        }
        PolicySweepConstantV1::MaxWitnessOverrideDepth => {
            policy.convergence.max_witness_override_depth = value
        }
    }
    policy.validate().map_err(|error| error.to_string())
}

fn status_label(status: ConvergenceStatus) -> &'static str {
    match status {
        ConvergenceStatus::Syncing => "syncing",
        ConvergenceStatus::Resolving => "resolving",
        ConvergenceStatus::Settled => "settled",
        ConvergenceStatus::Blocked => "blocked",
    }
}
