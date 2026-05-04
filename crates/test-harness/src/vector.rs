//! Scenario traces for early cross-implementation test vectors.
//!
//! These records intentionally avoid implementation-local MLS bytes and group
//! ids. They capture the deterministic observable outcome a conforming engine
//! should produce after running the same scripted scenario.

use crate::{HarnessClient, ScenarioSpec};
use cgka_traits::engine::{CommitOrderingKey, GroupEvent};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorFixture {
    pub scenario_name: String,
    pub vector_version: String,
    pub harness_version: String,
    pub seed: Option<u64>,
    pub scenario: ScenarioSpec,
    pub expected_trace: ScenarioTrace,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioTrace {
    pub name: String,
    pub observations: Vec<ClientObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientObservation {
    pub client: String,
    pub epoch: u64,
    pub member_count: usize,
    pub received_payloads: Vec<String>,
    pub removed_members: Vec<String>,
    pub recoveries: Vec<ForkRecoveryObservation>,
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
    pub timestamp: u64,
    pub message_id: String,
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
                    Some(String::from_utf8_lossy(member.as_slice()).into_owned())
                }
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

fn observe_key(key: &CommitOrderingKey) -> RecoveryOrderingKeyObservation {
    RecoveryOrderingKeyObservation {
        timestamp: key.timestamp.0,
        message_id: hex::encode(key.message_id.as_slice()),
    }
}
