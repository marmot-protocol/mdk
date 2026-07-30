//! Active application-message probes for cryptographic reachability.
//!
//! Exact group snapshots can establish that two clients expose the same
//! canonical state, but they do not exercise the normal send, transport peel,
//! MLS decrypt, and application delivery path. These observations record that
//! end-to-end evidence for every directed pair in a selected client set.

use crate::ScenarioInputLedgerEntry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DecryptabilityProbeSendStatus {
    Published,
    Queued,
    Failed { error: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectionalDecryptabilityProbe {
    pub sender: String,
    pub recipient: String,
    pub payload: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_id: Option<String>,
    pub send_status: DecryptabilityProbeSendStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_ledger: Option<ScenarioInputLedgerEntry>,
}

impl DirectionalDecryptabilityProbe {
    pub fn succeeded(&self) -> bool {
        matches!(self.send_status, DecryptabilityProbeSendStatus::Published)
            && self.recipient_ledger.as_ref().is_some_and(|entry| {
                self.logical_id.as_ref() == entry.logical_id.as_ref()
                    && entry.sender == self.sender
                    && entry.payload == self.payload
                    && entry.delivered > 0
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BidirectionalDecryptabilityObservation {
    pub step_index: usize,
    pub clients: Vec<String>,
    pub probes: Vec<DirectionalDecryptabilityProbe>,
}

impl BidirectionalDecryptabilityObservation {
    pub fn succeeded(&self) -> bool {
        let unique_clients = self.clients.iter().collect::<BTreeSet<_>>();
        let expected_edges = self
            .clients
            .iter()
            .flat_map(|sender| {
                self.clients
                    .iter()
                    .filter(move |recipient| *recipient != sender)
                    .map(move |recipient| (sender, recipient))
            })
            .collect::<BTreeSet<_>>();
        let observed_edges = self
            .probes
            .iter()
            .map(|probe| (&probe.sender, &probe.recipient))
            .collect::<BTreeSet<_>>();
        self.clients.len() >= 2
            && unique_clients.len() == self.clients.len()
            && observed_edges == expected_edges
            && self.probes.len() == expected_edges.len()
            && self
                .probes
                .iter()
                .all(DirectionalDecryptabilityProbe::succeeded)
    }

    pub fn failed_edges(&self) -> Vec<&DirectionalDecryptabilityProbe> {
        self.probes
            .iter()
            .filter(|probe| !probe.succeeded())
            .collect()
    }

    pub(crate) fn matches_clients(&self, clients: &[String]) -> bool {
        let mut observed = self.clients.clone();
        observed.sort();
        let mut expected = clients.to_vec();
        expected.sort();
        observed == expected
    }
}
