//! Scenario traces for early cross-implementation test vectors.
//!
//! These records intentionally avoid implementation-local MLS bytes and group
//! ids. They capture the deterministic observable outcome a conforming engine
//! should produce after running the same scripted scenario.

use crate::{HarnessClient, ScenarioSpec};
use cgka_traits::engine::{AppMessageInvalidationReason, CommitOrderingKey, GroupEvent};
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
                let converged = observations.iter().all(|observation| {
                    observation.epoch == first_epoch
                        && observation.member_count == first_member_count
                });
                let epoch_matches = epoch.is_none_or(|expected| expected == first_epoch);
                let member_count_matches =
                    member_count.is_none_or(|expected| expected == first_member_count);
                if !(converged && epoch_matches && member_count_matches) {
                    mismatches.push(ExpectationFailure {
                        kind: "clients_not_converged".into(),
                        message: format!(
                            "clients {:?} did not converge to epoch {:?}, member_count {:?}",
                            clients, epoch, member_count
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioTrace {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_resolutions: Vec<PendingResolutionObservation>,
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
pub struct ClientObservation {
    pub client: String,
    pub epoch: u64,
    pub member_count: usize,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryOrderingKeyObservation {
    pub source_epoch: u64,
    pub commit_digest: String,
}

pub fn observe_client(label: impl Into<String>, client: &mut HarnessClient) -> ClientObservation {
    let events = client.drain_events();
    let event_counts = ClientEventCounts {
        message_received: events
            .iter()
            .filter(|event| matches!(event, GroupEvent::MessageReceived { .. }))
            .count(),
        member_added: events
            .iter()
            .filter(|event| matches!(event, GroupEvent::MemberAdded { .. }))
            .count(),
        member_removed: events
            .iter()
            .filter(|event| matches!(event, GroupEvent::MemberRemoved { .. }))
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
        event_counts,
        received_payloads: events
            .iter()
            .filter_map(|e| match e {
                GroupEvent::MessageReceived { payload, .. } => {
                    Some(String::from_utf8_lossy(payload).into_owned())
                }
                _ => None,
            })
            .collect(),
        removed_members: events
            .iter()
            .filter_map(|e| match e {
                GroupEvent::MemberRemoved { member, .. } => {
                    Some(observe_member_id(member.as_slice()))
                }
                _ => None,
            })
            .collect(),
        added_members: events
            .iter()
            .filter_map(|e| match e {
                GroupEvent::MemberAdded { member, .. } => {
                    Some(observe_member_id(member.id.as_slice()))
                }
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
        commit_digest: hex::encode(key.commit_digest),
    }
}
