//! Scenario traces for early cross-implementation test vectors.
//!
//! These records intentionally avoid implementation-local MLS bytes and group
//! ids. They capture the deterministic observable outcome a conforming engine
//! should produce after running the same scripted scenario.

use crate::{HarnessClient, ScenarioSpec};
use cgka_traits::engine::{AppMessageInvalidationReason, CommitOrderingKey, GroupEvent};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorFixture {
    pub scenario_name: String,
    pub vector_version: String,
    pub conformance_version: String,
    pub seed: Option<u64>,
    pub scenario: ScenarioSpec,
    pub expected_trace: ScenarioTrace,
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
    ClientObservation {
        client: label.into(),
        epoch: client.epoch().0,
        member_count: client.members().len(),
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
