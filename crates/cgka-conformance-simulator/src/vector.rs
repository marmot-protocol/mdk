//! Scenario traces for early cross-implementation test vectors.
//!
//! These records intentionally avoid implementation-local MLS bytes and group
//! ids. They capture the deterministic observable outcome a conforming engine
//! should produce after running the same scripted scenario.

use crate::{HarnessClient, ScenarioSpec};
use cgka_traits::engine::{
    AppMessageInvalidationReason, CommitOrderingKey, CommitOrderingPriority, GroupEvent,
    GroupStateChange,
};
use marmot_forensics::AuditEventKind;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorFixture {
    pub scenario_name: String,
    pub vector_version: String,
    pub conformance_version: String,
    pub seed: Option<u64>,
    pub scenario: ScenarioSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_trace: Option<ScenarioTrace>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_outcomes: Vec<TraceExpectation>,
}

impl VectorFixture {
    pub fn compare_observed_trace(&self, observed: &ScenarioTrace) -> Vec<ExpectationFailure> {
        compare_trace_expectations(
            self.expected_trace.as_ref(),
            &self.expected_outcomes,
            observed,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectationFailure {
    pub kind: String,
    pub message: String,
    pub expected: Value,
    pub actual: Value,
}

pub type VectorMismatch = ExpectationFailure;

pub fn compare_trace_expectations(
    expected_trace: Option<&ScenarioTrace>,
    expected_outcomes: &[TraceExpectation],
    observed: &ScenarioTrace,
) -> Vec<ExpectationFailure> {
    let mut failures = Vec::new();
    if let Some(expected) = expected_trace
        && expected != observed
    {
        failures.push(ExpectationFailure {
            kind: "trace_mismatch".into(),
            message: format!(
                "expected exact trace for {} did not match observed trace",
                observed.name
            ),
            expected: json!(expected),
            actual: json!(observed),
        });
    }
    for expectation in expected_outcomes {
        expectation.compare(observed, &mut failures);
    }
    failures
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TraceExpectation {
    PendingResolution {
        step_index: usize,
        client: String,
        pending: String,
        resolution: String,
    },
    ExpectedError {
        step_index: usize,
        client: String,
        operation: String,
        error: String,
    },
    AdminPolicy {
        client: String,
        admins: Vec<String>,
    },
    ClientState {
        client: String,
        epoch: u64,
        member_count: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        received_payloads: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        added_members: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        removed_members: Option<Vec<String>>,
    },
    ClientsConverged {
        clients: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        epoch: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        member_count: Option<usize>,
    },
    ClientEpochChanges {
        client: String,
        changes: Vec<EpochChangeObservation>,
    },
    ClientRecoveries {
        client: String,
        count: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_epoch: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovered_epoch: Option<u64>,
        #[serde(default)]
        winner_differs_from_invalidated: bool,
    },
    RecoverySummary {
        count: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_epoch: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovered_epoch: Option<u64>,
        #[serde(default)]
        winner_differs_from_invalidated: bool,
    },
    /// Assert against the client's **settled** convergence decision: the last
    /// convergence pass that actually evaluated a candidate set. Not count-based
    /// like [`Self::RecoverySummary`], and deliberately not any-match — the
    /// engine emits one decision per settle pass, and an earlier pass can select
    /// a branch a later pass supersedes, so any-match would let a vector bind to
    /// a superseded intermediate (or a trailing no-candidate pass). A field left
    /// `None` is not checked; `min_app_witness_score` asserts the winning branch
    /// scored at least that many app witnesses. With `client` set, the scope is
    /// that client's settled decision; with `client` `None`, any observed
    /// client's settled decision.
    ConvergenceDecision {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selected_branch_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selected_tip_epoch: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decisive_rule: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        witness_quorum_met: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min_app_witness_score: Option<u64>,
    },
}

impl TraceExpectation {
    fn compare(&self, observed: &ScenarioTrace, mismatches: &mut Vec<ExpectationFailure>) {
        match self {
            TraceExpectation::PendingResolution {
                step_index,
                client,
                pending,
                resolution,
            } => {
                let expected = PendingResolutionObservation {
                    step_index: *step_index,
                    client: client.clone(),
                    pending: pending.clone(),
                    resolution: resolution.clone(),
                };
                if !observed.pending_resolutions.contains(&expected) {
                    mismatches.push(ExpectationFailure {
                        kind: "missing_pending_resolution".into(),
                        message: format!(
                            "missing pending resolution {pending}={resolution} for {client}"
                        ),
                        expected: json!(expected),
                        actual: json!(observed.pending_resolutions),
                    });
                }
            }
            TraceExpectation::ExpectedError {
                step_index,
                client,
                operation,
                error,
            } => {
                let expected = ScenarioErrorObservation {
                    step_index: *step_index,
                    client: client.clone(),
                    operation: operation.clone(),
                    error: error.clone(),
                };
                if !observed.errors.contains(&expected) {
                    mismatches.push(ExpectationFailure {
                        kind: "missing_expected_error".into(),
                        message: format!(
                            "missing expected {operation} error {error} for {client}"
                        ),
                        expected: json!(expected),
                        actual: json!(observed.errors),
                    });
                }
            }
            TraceExpectation::AdminPolicy { client, admins } => {
                match observed
                    .admin_policies
                    .iter()
                    .rev()
                    .find(|policy| policy.client == *client)
                {
                    Some(policy) if &policy.admins == admins => {}
                    Some(policy) => mismatches.push(ExpectationFailure {
                        kind: "admin_policy_mismatch".into(),
                        message: format!(
                            "client {client} admin policy was {:?}",
                            policy.admins
                        ),
                        expected: json!({"client": client, "admins": admins}),
                        actual: json!(policy),
                    }),
                    None => mismatches.push(ExpectationFailure {
                        kind: "missing_admin_policy_observation".into(),
                        message: format!("missing admin policy observation for {client}"),
                        expected: json!(self),
                        actual: json!(observed.admin_policies),
                    }),
                }
            }
            TraceExpectation::ClientState {
                client,
                epoch,
                member_count,
                received_payloads,
                added_members,
                removed_members,
            } => match client_observation(observed, client) {
                Some(observation)
                    if observation.epoch == *epoch
                        && observation.member_count == *member_count
                        && received_payloads
                            .as_ref()
                            .is_none_or(|payloads| &observation.received_payloads == payloads)
                        && added_members
                            .as_ref()
                            .is_none_or(|members| &observation.added_members == members)
                        && removed_members
                            .as_ref()
                            .is_none_or(|members| &observation.removed_members == members) => {}
                Some(observation) => mismatches.push(ExpectationFailure {
                    kind: "client_state_mismatch".into(),
                    message: format!(
                        "client {client} state was epoch {}, members {}, payloads {:?}, added {:?}, removed {:?}",
                        observation.epoch,
                        observation.member_count,
                        observation.received_payloads,
                        observation.added_members,
                        observation.removed_members
                    ),
                    expected: json!({
                        "client": client,
                        "epoch": epoch,
                        "member_count": member_count,
                        "received_payloads": received_payloads,
                        "added_members": added_members,
                        "removed_members": removed_members,
                    }),
                    actual: json!(observation),
                }),
                None => missing_client(client, self, mismatches),
            },
            TraceExpectation::ClientsConverged {
                clients,
                epoch,
                member_count,
            } => {
                let mut observations = Vec::with_capacity(clients.len());
                for client in clients {
                    match client_observation(observed, client) {
                        Some(observation) => observations.push(observation),
                        None => {
                            missing_client(client, self, mismatches);
                            return;
                        }
                    }
                }
                if observations.is_empty() {
                    mismatches.push(ExpectationFailure {
                        kind: "empty_convergence_expectation".into(),
                        message: "clients_converged expectation did not name any clients".into(),
                        expected: json!(self),
                        actual: json!(observed.observations),
                    });
                    return;
                }

                let first_epoch = observations[0].epoch;
                let first_member_count = observations[0].member_count;
                let first_group_name = &observations[0].group_name;
                let converged = observations.iter().all(|observation| {
                    observation.epoch == first_epoch
                        && observation.member_count == first_member_count
                        && &observation.group_name == first_group_name
                });
                let epoch_matches = epoch.is_none_or(|expected| expected == first_epoch);
                let member_count_matches =
                    member_count.is_none_or(|expected| expected == first_member_count);
                if !(converged && epoch_matches && member_count_matches) {
                    mismatches.push(ExpectationFailure {
                        kind: "clients_not_converged".into(),
                        message: format!(
                            "clients {:?} did not converge to epoch {:?}, member_count {:?} \
                             (group names: {:?})",
                            clients,
                            epoch,
                            member_count,
                            observations
                                .iter()
                                .map(|observation| observation.group_name.as_str())
                                .collect::<Vec<_>>()
                        ),
                        expected: json!({
                            "clients": clients,
                            "epoch": epoch,
                            "member_count": member_count,
                        }),
                        actual: json!(observations),
                    });
                }
            }
            TraceExpectation::ClientEpochChanges { client, changes } => {
                match client_observation(observed, client) {
                    Some(observation) if &observation.epoch_changes == changes => {}
                    Some(observation) => mismatches.push(ExpectationFailure {
                        kind: "client_epoch_changes_mismatch".into(),
                        message: format!(
                            "client {client} epoch changes were {:?}",
                            observation.epoch_changes
                        ),
                        expected: json!(changes),
                        actual: json!(observation.epoch_changes),
                    }),
                    None => missing_client(client, self, mismatches),
                }
            }
            TraceExpectation::ClientRecoveries {
                client,
                count,
                source_epoch,
                recovered_epoch,
                winner_differs_from_invalidated,
            } => match client_observation(observed, client) {
                Some(observation) => {
                    compare_recoveries(
                        RecoveryExpectation {
                            scope: "client",
                            label: client,
                            recoveries: &observation.recoveries,
                            count: *count,
                            source_epoch: *source_epoch,
                            recovered_epoch: *recovered_epoch,
                            winner_differs_from_invalidated: *winner_differs_from_invalidated,
                        },
                        mismatches,
                    );
                }
                None => missing_client(client, self, mismatches),
            },
            TraceExpectation::RecoverySummary {
                count,
                source_epoch,
                recovered_epoch,
                winner_differs_from_invalidated,
            } => {
                let recoveries = observed
                    .observations
                    .iter()
                    .flat_map(|observation| observation.recoveries.iter().cloned())
                    .collect::<Vec<_>>();
                compare_recoveries(
                    RecoveryExpectation {
                        scope: "trace",
                        label: &observed.name,
                        recoveries: &recoveries,
                        count: *count,
                        source_epoch: *source_epoch,
                        recovered_epoch: *recovered_epoch,
                        winner_differs_from_invalidated: *winner_differs_from_invalidated,
                    },
                    mismatches,
                );
            }
            TraceExpectation::ConvergenceDecision {
                client,
                selected_branch_id,
                selected_tip_epoch,
                decisive_rule,
                witness_quorum_met,
                min_app_witness_score,
            } => {
                compare_convergence_decision(
                    ConvergenceDecisionExpectation {
                        client: client.as_deref(),
                        selected_branch_id: selected_branch_id.as_deref(),
                        selected_tip_epoch: *selected_tip_epoch,
                        decisive_rule: decisive_rule.as_deref(),
                        witness_quorum_met: *witness_quorum_met,
                        min_app_witness_score: *min_app_witness_score,
                    },
                    observed,
                    mismatches,
                );
            }
        }
    }
}

struct RecoveryExpectation<'a> {
    scope: &'static str,
    label: &'a str,
    recoveries: &'a [ForkRecoveryObservation],
    count: usize,
    source_epoch: Option<u64>,
    recovered_epoch: Option<u64>,
    winner_differs_from_invalidated: bool,
}

fn compare_recoveries(
    expected_recovery: RecoveryExpectation<'_>,
    mismatches: &mut Vec<ExpectationFailure>,
) {
    let RecoveryExpectation {
        scope,
        label,
        recoveries,
        count,
        source_epoch,
        recovered_epoch,
        winner_differs_from_invalidated,
    } = expected_recovery;

    if recoveries.len() != count {
        mismatches.push(ExpectationFailure {
            kind: format!("{scope}_recovery_count_mismatch"),
            message: format!(
                "{scope} {label} recorded {} recoveries, expected {count}",
                recoveries.len()
            ),
            expected: json!({
                "count": count,
                "source_epoch": source_epoch,
                "recovered_epoch": recovered_epoch,
                "winner_differs_from_invalidated": winner_differs_from_invalidated,
            }),
            actual: json!(recoveries),
        });
        return;
    }
    for recovery in recoveries {
        if source_epoch.is_some_and(|expected| recovery.source_epoch != expected) {
            mismatches.push(ExpectationFailure {
                kind: format!("{scope}_recovery_source_epoch_mismatch"),
                message: format!(
                    "{scope} {label} recovery source epoch was {}",
                    recovery.source_epoch
                ),
                expected: json!(source_epoch),
                actual: json!(recovery),
            });
        }
        if recovered_epoch.is_some_and(|expected| recovery.recovered_epoch != expected) {
            mismatches.push(ExpectationFailure {
                kind: format!("{scope}_recovery_epoch_mismatch"),
                message: format!(
                    "{scope} {label} recovered to epoch {}",
                    recovery.recovered_epoch
                ),
                expected: json!(recovered_epoch),
                actual: json!(recovery),
            });
        }
        if winner_differs_from_invalidated && recovery.winner == recovery.invalidated {
            mismatches.push(ExpectationFailure {
                kind: format!("{scope}_recovery_ordering_mismatch"),
                message: format!(
                    "{scope} {label} recovery used the same winner and invalidated key"
                ),
                expected: json!({"winner_differs_from_invalidated": true}),
                actual: json!(recovery),
            });
        }
    }
}

struct ConvergenceDecisionExpectation<'a> {
    client: Option<&'a str>,
    selected_branch_id: Option<&'a str>,
    selected_tip_epoch: Option<u64>,
    decisive_rule: Option<&'a str>,
    witness_quorum_met: Option<bool>,
    min_app_witness_score: Option<u64>,
}

impl ConvergenceDecisionExpectation<'_> {
    fn matches(&self, decision: &ConvergenceDecisionObservation) -> bool {
        self.selected_branch_id
            .is_none_or(|id| decision.selected_branch_id.as_deref() == Some(id))
            && self
                .selected_tip_epoch
                .is_none_or(|epoch| decision.selected_tip_epoch == Some(epoch))
            && self
                .decisive_rule
                .is_none_or(|rule| decision.decisive_rule.as_deref() == Some(rule))
            && self
                .witness_quorum_met
                .is_none_or(|met| decision.witness_quorum_met == met)
            && self.min_app_witness_score.is_none_or(|min| {
                decision
                    .selected_app_witness_score
                    .is_some_and(|score| score >= min)
            })
    }

    fn expected_json(&self) -> Value {
        json!({
            "client": self.client,
            "selected_branch_id": self.selected_branch_id,
            "selected_tip_epoch": self.selected_tip_epoch,
            "decisive_rule": self.decisive_rule,
            "witness_quorum_met": self.witness_quorum_met,
            "min_app_witness_score": self.min_app_witness_score,
        })
    }
}

/// The client's settled convergence decision: the last pass that actually
/// evaluated a candidate set. The engine emits one decision per settle pass, so
/// this skips both superseded intermediates and trailing no-candidate passes.
fn settled_decision(
    decisions: &[ConvergenceDecisionObservation],
) -> Option<&ConvergenceDecisionObservation> {
    decisions
        .iter()
        .rev()
        .find(|decision| decision.candidate_count > 0)
}

fn compare_convergence_decision(
    expectation: ConvergenceDecisionExpectation<'_>,
    observed: &ScenarioTrace,
    mismatches: &mut Vec<ExpectationFailure>,
) {
    let settled: Vec<&ConvergenceDecisionObservation> = match expectation.client {
        Some(client) => match client_observation(observed, client) {
            Some(observation) => settled_decision(&observation.convergence_decisions)
                .into_iter()
                .collect(),
            None => {
                mismatches.push(ExpectationFailure {
                    kind: "missing_client_observation".into(),
                    message: format!("missing observation for client {client}"),
                    expected: expectation.expected_json(),
                    actual: Value::Null,
                });
                return;
            }
        },
        None => observed
            .observations
            .iter()
            .filter_map(|observation| settled_decision(&observation.convergence_decisions))
            .collect(),
    };
    if settled.iter().any(|decision| expectation.matches(decision)) {
        return;
    }
    mismatches.push(ExpectationFailure {
        kind: "missing_convergence_decision".into(),
        message: "no settled convergence decision matched the expectation".into(),
        expected: expectation.expected_json(),
        actual: json!(settled),
    });
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioTrace {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_resolutions: Vec<PendingResolutionObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<ScenarioErrorObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub admin_policies: Vec<ScenarioAdminPolicyObservation>,
    pub observations: Vec<ClientObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingResolutionObservation {
    pub step_index: usize,
    pub client: String,
    pub pending: String,
    pub resolution: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioErrorObservation {
    pub step_index: usize,
    pub client: String,
    pub operation: String,
    pub error: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioAdminPolicyObservation {
    pub client: String,
    pub admins: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientObservation {
    pub client: String,
    pub epoch: u64,
    pub member_count: usize,
    /// Branch-sensitive group name mirrored from signed group-profile state.
    ///
    /// `UpdateGroupData` commits change only the group name/description, which
    /// the epoch/member_count facts cannot distinguish. Recording the observed
    /// name lets `ClientsConverged` reject a permanent group-data fork where the
    /// committers share an epoch and member count but settled on different
    /// branches. Defaulted for backward compatibility with serialized traces
    /// that predate the field.
    #[serde(default)]
    pub group_name: String,
    #[serde(default)]
    pub event_counts: ClientEventCounts,
    pub received_payloads: Vec<String>,
    #[serde(default)]
    pub added_members: Vec<String>,
    pub removed_members: Vec<String>,
    #[serde(default)]
    pub epoch_changes: Vec<EpochChangeObservation>,
    #[serde(default)]
    pub app_invalidations: Vec<AppInvalidationObservation>,
    pub recoveries: Vec<ForkRecoveryObservation>,
    /// Convergence decisions the engine emitted, captured via the forensic
    /// recorder (no `GroupEvent` carries them). Defaulted for backward
    /// compatibility with serialized traces that predate the field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub convergence_decisions: Vec<ConvergenceDecisionObservation>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientEventCounts {
    pub message_received: usize,
    pub member_added: usize,
    pub member_removed: usize,
    pub epoch_changed: usize,
    pub app_invalidated: usize,
    pub fork_recovered: usize,
}

fn client_observation<'a>(
    observed: &'a ScenarioTrace,
    client: &str,
) -> Option<&'a ClientObservation> {
    observed
        .observations
        .iter()
        .rev()
        .find(|observation| observation.client == client)
}

fn missing_client(
    client: &str,
    expectation: &TraceExpectation,
    mismatches: &mut Vec<ExpectationFailure>,
) {
    mismatches.push(ExpectationFailure {
        kind: "missing_client_observation".into(),
        message: format!("missing observation for client {client}"),
        expected: json!(expectation),
        actual: Value::Null,
    });
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochChangeObservation {
    pub from: u64,
    pub to: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppInvalidationObservation {
    pub epoch: u64,
    pub reason: String,
    pub payload_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkRecoveryObservation {
    pub source_epoch: u64,
    pub recovered_epoch: u64,
    pub winner: RecoveryOrderingKeyObservation,
    pub invalidated: RecoveryOrderingKeyObservation,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RecoveryOrderingKeyObservation {
    pub source_epoch: u64,
    pub priority: CommitOrderingPriority,
    pub committer: String,
    pub commit_digest: String,
}

/// A convergence decision projected from an
/// [`AuditEventKind::ConvergenceDecision`] down to the scalar facts a vector can
/// assert on. The raw audit event carries free-form `serde_json::Value` rule
/// traces that are not `Eq`; this projection stays comparable and
/// implementation-neutral.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceDecisionObservation {
    pub current_tip_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_branch_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_tip_epoch: Option<u64>,
    /// `rule_name` of the selector rule the engine marked decisive, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decisive_rule: Option<String>,
    /// Whether the winning branch met the app-witness quorum.
    #[serde(default)]
    pub witness_quorum_met: bool,
    /// App-witness score of the winning branch, when the selector scored one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_app_witness_score: Option<u64>,
    pub candidate_count: usize,
}

fn observe_convergence_decision(kind: &AuditEventKind) -> Option<ConvergenceDecisionObservation> {
    let AuditEventKind::ConvergenceDecision {
        current_tip_epoch,
        candidates,
        rule_trace,
        selected_branch_id,
        selected_tip_epoch,
        ..
    } = kind
    else {
        return None;
    };
    let selected_score = selected_branch_id
        .as_ref()
        .and_then(|id| {
            candidates
                .iter()
                .find(|candidate| &candidate.branch_id == id)
        })
        .and_then(|candidate| candidate.score.as_ref());
    Some(ConvergenceDecisionObservation {
        current_tip_epoch: *current_tip_epoch,
        selected_branch_id: selected_branch_id.clone(),
        selected_tip_epoch: *selected_tip_epoch,
        decisive_rule: rule_trace
            .iter()
            .find(|rule| rule.decisive == Some(true))
            .map(|rule| rule.rule_name.clone()),
        witness_quorum_met: selected_score
            .and_then(|score| score.witness_quorum_met)
            .unwrap_or(false),
        selected_app_witness_score: selected_score.and_then(|score| score.app_witness_score),
        candidate_count: candidates.len(),
    })
}

pub fn observe_client(label: impl Into<String>, client: &mut HarnessClient) -> ClientObservation {
    let events = client.drain_events();
    let captured_decisions = client.drain_convergence_decisions();
    let event_counts = ClientEventCounts {
        message_received: events
            .iter()
            .filter(|event| matches!(event, GroupEvent::MessageReceived { .. }))
            .count(),
        member_added: events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    GroupEvent::GroupStateChanged {
                        change: GroupStateChange::MemberAdded { .. },
                        ..
                    }
                )
            })
            .count(),
        member_removed: events
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    GroupEvent::GroupStateChanged {
                        change: GroupStateChange::MemberRemoved { .. }
                            | GroupStateChange::MemberLeft { .. },
                        ..
                    }
                )
            })
            .count(),
        epoch_changed: events
            .iter()
            .filter(|event| matches!(event, GroupEvent::EpochChanged { .. }))
            .count(),
        app_invalidated: events
            .iter()
            .filter(|event| matches!(event, GroupEvent::AppMessageInvalidated { .. }))
            .count(),
        fork_recovered: events
            .iter()
            .filter(|event| matches!(event, GroupEvent::ForkRecovered { .. }))
            .count(),
    };
    ClientObservation {
        client: label.into(),
        epoch: client.epoch().0,
        member_count: client.members().len(),
        group_name: client.group_name(),
        event_counts,
        received_payloads: events
            .iter()
            .filter_map(|e| match e {
                GroupEvent::MessageReceived { payload, .. } => {
                    let content = crate::client::decode_harness_app_payload(payload);
                    Some(String::from_utf8_lossy(&content).into_owned())
                }
                _ => None,
            })
            .collect(),
        removed_members: events
            .iter()
            .filter_map(|e| match e {
                GroupEvent::GroupStateChanged {
                    change:
                        GroupStateChange::MemberRemoved { member }
                        | GroupStateChange::MemberLeft { member },
                    ..
                } => Some(observe_member_id(member.as_slice())),
                _ => None,
            })
            .collect(),
        added_members: events
            .iter()
            .filter_map(|e| match e {
                GroupEvent::GroupStateChanged {
                    change: GroupStateChange::MemberAdded { member },
                    ..
                } => Some(observe_member_id(member.as_slice())),
                _ => None,
            })
            .collect(),
        epoch_changes: events
            .iter()
            .filter_map(|e| match e {
                GroupEvent::EpochChanged { from, to, .. } => Some(EpochChangeObservation {
                    from: from.0,
                    to: to.0,
                }),
                _ => None,
            })
            .collect(),
        app_invalidations: events
            .iter()
            .filter_map(|e| match e {
                GroupEvent::AppMessageInvalidated {
                    epoch,
                    reason,
                    decrypted_payload_ref,
                    ..
                } => Some(AppInvalidationObservation {
                    epoch: epoch.0,
                    reason: observe_app_invalidation_reason(*reason),
                    payload_ref: decrypted_payload_ref.clone(),
                }),
                _ => None,
            })
            .collect(),
        recoveries: events
            .iter()
            .filter_map(|e| match e {
                GroupEvent::ForkRecovered {
                    source_epoch,
                    recovered_epoch,
                    winner,
                    invalidated,
                    ..
                } => Some(ForkRecoveryObservation {
                    source_epoch: source_epoch.0,
                    recovered_epoch: recovered_epoch.0,
                    winner: observe_key(winner),
                    invalidated: observe_key(invalidated),
                }),
                _ => None,
            })
            .collect(),
        convergence_decisions: captured_decisions
            .iter()
            .filter_map(observe_convergence_decision)
            .collect(),
    }
}

fn observe_member_id(bytes: &[u8]) -> String {
    if let Some(label) = crate::client::logical_label_for_member_id(bytes) {
        return label;
    }
    let end = bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |i| i + 1);
    if end > 0
        && let Ok(label) = std::str::from_utf8(&bytes[..end])
        && !label.is_empty()
    {
        return label.into();
    }
    hex::encode(bytes)
}

fn observe_app_invalidation_reason(reason: AppMessageInvalidationReason) -> String {
    match reason {
        AppMessageInvalidationReason::LosingBranch => "losing_branch",
        AppMessageInvalidationReason::BeyondAnchor => "beyond_anchor",
        AppMessageInvalidationReason::BeyondAppRetention => "beyond_app_retention",
        AppMessageInvalidationReason::UndecryptableInCanonicalState => {
            "undecryptable_in_canonical_state"
        }
    }
    .into()
}

fn observe_key(key: &CommitOrderingKey) -> RecoveryOrderingKeyObservation {
    RecoveryOrderingKeyObservation {
        source_epoch: key.source_epoch.0,
        priority: key.priority,
        committer: hex::encode(key.committer.as_slice()),
        commit_digest: hex::encode(key.commit_digest),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(client: &str, epoch: u64, member_count: usize) -> ClientObservation {
        ClientObservation {
            client: client.into(),
            epoch,
            member_count,
            group_name: String::new(),
            event_counts: ClientEventCounts::default(),
            received_payloads: Vec::new(),
            added_members: Vec::new(),
            removed_members: Vec::new(),
            epoch_changes: Vec::new(),
            app_invalidations: Vec::new(),
            recoveries: Vec::new(),
            convergence_decisions: Vec::new(),
        }
    }

    fn trace(observations: Vec<ClientObservation>) -> ScenarioTrace {
        ScenarioTrace {
            name: "duplicate-observations".into(),
            pending_resolutions: Vec::new(),
            errors: Vec::new(),
            admin_policies: Vec::new(),
            observations,
        }
    }

    fn convergence_decision(
        selected_branch_id: &str,
        selected_tip_epoch: u64,
        decisive_rule: &str,
        witness_quorum_met: bool,
        selected_app_witness_score: u64,
    ) -> ConvergenceDecisionObservation {
        ConvergenceDecisionObservation {
            current_tip_epoch: selected_tip_epoch.saturating_sub(1),
            selected_branch_id: Some(selected_branch_id.into()),
            selected_tip_epoch: Some(selected_tip_epoch),
            decisive_rule: Some(decisive_rule.into()),
            witness_quorum_met,
            selected_app_witness_score: Some(selected_app_witness_score),
            candidate_count: 2,
        }
    }

    #[test]
    fn client_state_expectation_uses_latest_observation() {
        let mut latest = observation("alice", 2, 3);
        latest.received_payloads = vec!["after-fork".into()];

        let observed = trace(vec![observation("alice", 1, 2), latest]);
        let failures = compare_trace_expectations(
            None,
            &[TraceExpectation::ClientState {
                client: "alice".into(),
                epoch: 2,
                member_count: 3,
                received_payloads: Some(vec!["after-fork".into()]),
                added_members: None,
                removed_members: None,
            }],
            &observed,
        );

        assert!(failures.is_empty(), "unexpected failures: {failures:#?}");
    }

    #[test]
    fn clients_converged_expectation_rejects_stale_pre_fork_observations() {
        let observed = trace(vec![
            observation("alice", 1, 2),
            observation("bob", 1, 2),
            observation("alice", 2, 3),
            observation("bob", 2, 4),
        ]);
        let failures = compare_trace_expectations(
            None,
            &[TraceExpectation::ClientsConverged {
                clients: vec!["alice".into(), "bob".into()],
                epoch: None,
                member_count: None,
            }],
            &observed,
        );

        assert_eq!(failures.len(), 1, "expected one failure: {failures:#?}");
        assert_eq!(failures[0].kind, "clients_not_converged");
    }

    #[test]
    fn clients_converged_expectation_rejects_group_data_branch_fork() {
        // Regression for mdk#162: a multi-committer group-data storm fork
        // leaves the committers on competing branches that share an epoch and
        // member count (group-data commits change only the group name). The
        // epoch/member_count facts alone cannot tell the branches apart, so the
        // branch-sensitive group name must make the oracle fail.
        let mut alice = observation("alice", 2, 21);
        alice.group_name = "alice branch".into();
        let mut bob = observation("bob", 2, 21);
        bob.group_name = "bob branch".into();
        let observed = trace(vec![alice, bob]);
        let failures = compare_trace_expectations(
            None,
            &[TraceExpectation::ClientsConverged {
                clients: vec!["alice".into(), "bob".into()],
                epoch: Some(2),
                member_count: Some(21),
            }],
            &observed,
        );

        assert_eq!(failures.len(), 1, "expected one failure: {failures:#?}");
        assert_eq!(failures[0].kind, "clients_not_converged");
    }

    #[test]
    fn clients_converged_expectation_accepts_shared_group_name() {
        // The converged case: same epoch, member count, and group name (every
        // client settled on the winning branch) must still pass.
        let mut alice = observation("alice", 2, 21);
        alice.group_name = "winner branch".into();
        let mut bob = observation("bob", 2, 21);
        bob.group_name = "winner branch".into();
        let observed = trace(vec![alice, bob]);
        let failures = compare_trace_expectations(
            None,
            &[TraceExpectation::ClientsConverged {
                clients: vec!["alice".into(), "bob".into()],
                epoch: Some(2),
                member_count: Some(21),
            }],
            &observed,
        );

        assert!(failures.is_empty(), "unexpected failures: {failures:#?}");
    }

    #[test]
    fn client_epoch_changes_expectation_uses_latest_observation() {
        let mut latest = observation("alice", 3, 3);
        latest.epoch_changes = vec![EpochChangeObservation { from: 2, to: 3 }];

        let observed = trace(vec![observation("alice", 1, 2), latest]);
        let failures = compare_trace_expectations(
            None,
            &[TraceExpectation::ClientEpochChanges {
                client: "alice".into(),
                changes: vec![EpochChangeObservation { from: 2, to: 3 }],
            }],
            &observed,
        );

        assert!(failures.is_empty(), "unexpected failures: {failures:#?}");
    }

    #[test]
    fn observe_convergence_decision_projects_selected_branch_scalars() {
        use marmot_forensics::{ConvergenceCandidate, ConvergenceRuleEvaluation, ConvergenceScore};

        let scored = |branch: &str, quorum: bool, app_witnesses: u64| ConvergenceCandidate {
            branch_id: branch.into(),
            tip_epoch: 2,
            score: Some(ConvergenceScore {
                witness_quorum_met: Some(quorum),
                app_witness_score: Some(app_witnesses),
                ..ConvergenceScore::default()
            }),
            ..ConvergenceCandidate::default()
        };
        let kind = AuditEventKind::ConvergenceDecision {
            current_tip_epoch: 1,
            max_rewind_commits: 5,
            candidates: vec![scored("winner", true, 2), scored("loser", false, 0)],
            rule_trace: vec![ConvergenceRuleEvaluation {
                rule_name: "witness_quorum_met".into(),
                scope: None,
                candidate_branch_id: None,
                other_candidate_branch_id: None,
                inputs: None,
                result: Value::Null,
                decisive: Some(true),
                selected_branch_id: None,
                rejected_branch_id: None,
            }],
            selected_branch_id: Some("winner".into()),
            selected_fork_epoch: Some(1),
            selected_tip_epoch: Some(2),
            losing_branch_ids: vec!["loser".into()],
            error_kinds: Vec::new(),
        };

        let projected = observe_convergence_decision(&kind).expect("projects a decision");
        assert_eq!(projected.selected_branch_id.as_deref(), Some("winner"));
        assert_eq!(projected.selected_tip_epoch, Some(2));
        assert_eq!(
            projected.decisive_rule.as_deref(),
            Some("witness_quorum_met")
        );
        assert!(
            projected.witness_quorum_met,
            "winner met the app-witness quorum"
        );
        assert_eq!(projected.selected_app_witness_score, Some(2));
        assert_eq!(projected.candidate_count, 2);
    }

    #[test]
    fn observe_convergence_decision_ignores_unrelated_kind() {
        let kind = AuditEventKind::RecorderStarted {
            recorder: "test".into(),
        };
        assert!(observe_convergence_decision(&kind).is_none());
    }

    #[test]
    fn convergence_decision_expectation_distinguishes_witness_win_from_tiebreak() {
        let mut carol = observation("carol", 2, 4);
        carol.convergence_decisions = vec![convergence_decision(
            "witnessed",
            2,
            "witness_quorum_met",
            true,
            2,
        )];
        let observed = trace(vec![carol]);

        // The witness-decided winner is asserted through the new expectation.
        let matched = compare_trace_expectations(
            None,
            &[TraceExpectation::ConvergenceDecision {
                client: Some("carol".into()),
                selected_branch_id: Some("witnessed".into()),
                selected_tip_epoch: Some(2),
                decisive_rule: Some("witness_quorum_met".into()),
                witness_quorum_met: Some(true),
                min_app_witness_score: Some(2),
            }],
            &observed,
        );
        assert!(matched.is_empty(), "witness win should match: {matched:#?}");

        // The same decision must NOT satisfy a digest-tiebreak expectation — the
        // decisive rule and quorum flag are what tell the two apart.
        let mismatch = compare_trace_expectations(
            None,
            &[TraceExpectation::ConvergenceDecision {
                client: Some("carol".into()),
                selected_branch_id: None,
                selected_tip_epoch: None,
                decisive_rule: Some("tip_digest".into()),
                witness_quorum_met: Some(false),
                min_app_witness_score: None,
            }],
            &observed,
        );
        assert_eq!(
            mismatch.len(),
            1,
            "digest expectation must not match: {mismatch:#?}"
        );
        assert_eq!(mismatch[0].kind, "missing_convergence_decision");
    }

    #[test]
    fn convergence_decision_min_app_witness_score_is_a_threshold() {
        let mut carol = observation("carol", 2, 4);
        carol.convergence_decisions = vec![convergence_decision(
            "winner",
            2,
            "app_witness_score",
            true,
            3,
        )];
        let observed = trace(vec![carol]);

        let at_threshold = compare_trace_expectations(
            None,
            &[TraceExpectation::ConvergenceDecision {
                client: None,
                selected_branch_id: None,
                selected_tip_epoch: None,
                decisive_rule: None,
                witness_quorum_met: None,
                min_app_witness_score: Some(3),
            }],
            &observed,
        );
        assert!(
            at_threshold.is_empty(),
            "score 3 meets min 3: {at_threshold:#?}"
        );

        let above_threshold = compare_trace_expectations(
            None,
            &[TraceExpectation::ConvergenceDecision {
                client: None,
                selected_branch_id: None,
                selected_tip_epoch: None,
                decisive_rule: None,
                witness_quorum_met: None,
                min_app_witness_score: Some(4),
            }],
            &observed,
        );
        assert_eq!(above_threshold.len(), 1, "score 3 is below min 4");
    }

    #[test]
    fn convergence_decision_expectation_reports_missing_client() {
        let mut carol = observation("carol", 2, 4);
        carol.convergence_decisions =
            vec![convergence_decision("winner", 2, "tip_committer", false, 0)];
        let observed = trace(vec![carol]);

        let failures = compare_trace_expectations(
            None,
            &[TraceExpectation::ConvergenceDecision {
                client: Some("dave".into()),
                selected_branch_id: None,
                selected_tip_epoch: None,
                decisive_rule: None,
                witness_quorum_met: None,
                min_app_witness_score: None,
            }],
            &observed,
        );
        assert_eq!(failures.len(), 1, "missing client must fail: {failures:#?}");
        assert_eq!(failures[0].kind, "missing_client_observation");
    }

    #[test]
    fn convergence_decision_expectation_matches_settled_not_superseded() {
        // The engine emits a decision per settle pass. An early pass selected a
        // single-candidate branch; a later pass, once the competing commit
        // arrived, superseded it (committer-decided among two). The expectation
        // must bind to the settled decision, never the superseded intermediate.
        let superseded = ConvergenceDecisionObservation {
            current_tip_epoch: 1,
            selected_branch_id: Some("superseded".into()),
            selected_tip_epoch: Some(2),
            decisive_rule: None,
            witness_quorum_met: false,
            selected_app_witness_score: Some(0),
            candidate_count: 1,
        };
        let settled = convergence_decision("settled", 2, "tip_committer", false, 0);
        let mut carol = observation("carol", 2, 4);
        carol.convergence_decisions = vec![superseded, settled];
        let observed = trace(vec![carol]);

        let matched = compare_trace_expectations(
            None,
            &[TraceExpectation::ConvergenceDecision {
                client: Some("carol".into()),
                selected_branch_id: Some("settled".into()),
                selected_tip_epoch: Some(2),
                decisive_rule: Some("tip_committer".into()),
                witness_quorum_met: Some(false),
                min_app_witness_score: None,
            }],
            &observed,
        );
        assert!(
            matched.is_empty(),
            "settled decision should match: {matched:#?}"
        );

        let superseded_match = compare_trace_expectations(
            None,
            &[TraceExpectation::ConvergenceDecision {
                client: Some("carol".into()),
                selected_branch_id: Some("superseded".into()),
                selected_tip_epoch: None,
                decisive_rule: None,
                witness_quorum_met: None,
                min_app_witness_score: None,
            }],
            &observed,
        );
        assert_eq!(
            superseded_match.len(),
            1,
            "a superseded intermediate must not match: {superseded_match:#?}"
        );
        assert_eq!(superseded_match[0].kind, "missing_convergence_decision");
    }

    #[test]
    fn convergence_decision_expectation_skips_trailing_empty_pass() {
        // A settled selection followed by a no-candidate convergence pass: the
        // settled decision is the one that evaluated candidates, not the trailer.
        let settled = convergence_decision("settled", 2, "tip_committer", false, 0);
        let trailing_empty = ConvergenceDecisionObservation {
            current_tip_epoch: 2,
            selected_branch_id: None,
            selected_tip_epoch: None,
            decisive_rule: None,
            witness_quorum_met: false,
            selected_app_witness_score: None,
            candidate_count: 0,
        };
        let mut carol = observation("carol", 2, 4);
        carol.convergence_decisions = vec![settled, trailing_empty];
        let observed = trace(vec![carol]);

        let matched = compare_trace_expectations(
            None,
            &[TraceExpectation::ConvergenceDecision {
                client: Some("carol".into()),
                selected_branch_id: None,
                selected_tip_epoch: None,
                decisive_rule: Some("tip_committer".into()),
                witness_quorum_met: None,
                min_app_witness_score: None,
            }],
            &observed,
        );
        assert!(
            matched.is_empty(),
            "must skip the empty trailing pass and match the settled decision: {matched:#?}"
        );
    }
}
