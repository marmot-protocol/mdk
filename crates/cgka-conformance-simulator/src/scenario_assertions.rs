//! Executable adapter-neutral scenario assertions.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScenarioPredicateV2 {
    ClientState {
        client: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        epoch: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        member_count: Option<usize>,
    },
    PayloadCount {
        client: String,
        payload: String,
        count: usize,
    },
    ClientsExactlyEquivalent {
        clients: Vec<String>,
    },
    NoPendingWork {
        clients: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioResourceMetric {
    RunnableWork,
    DeferredRetryWork,
    OutboundAwaitingAcknowledgement,
    TransportQueuedMessages,
    TransportDelayedMessages,
    TransportMailboxMessages,
    ScenarioInputsPending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioComparison {
    Equal,
    LessThanOrEqual,
    GreaterThanOrEqual,
}

impl ScenarioComparison {
    pub fn matches(self, actual: usize, expected: usize) -> bool {
        match self {
            Self::Equal => actual == expected,
            Self::LessThanOrEqual => actual <= expected,
            Self::GreaterThanOrEqual => actual >= expected,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ScenarioAssertionV2 {
    /// Predicate must hold at this exact action boundary.
    Exactly { predicate: ScenarioPredicateV2 },
    /// Predicate must hold within a bounded number of deterministic tick rounds.
    Eventually {
        predicate: ScenarioPredicateV2,
        max_iterations: usize,
    },
    /// Predicate must hold by a virtual-time deadline.
    Within {
        predicate: ScenarioPredicateV2,
        timeout_ms: u64,
        poll_interval_ms: u64,
    },
    /// Predicate must remain false at every sample through a virtual-time window.
    Never {
        predicate: ScenarioPredicateV2,
        duration_ms: u64,
        poll_interval_ms: u64,
    },
    Resource {
        metric: ScenarioResourceMetric,
        comparison: ScenarioComparison,
        value: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioPredicateObservationV2 {
    pub matched: bool,
    pub actual: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioAssertionObservationV2 {
    pub step_index: usize,
    pub assertion: ScenarioAssertionV2,
    pub passed: bool,
    pub samples: usize,
    pub elapsed_virtual_ms: u64,
    pub final_actual: Value,
}

pub fn resource_value(
    snapshot: &crate::SubjectProgressSnapshot,
    metric: ScenarioResourceMetric,
) -> usize {
    match metric {
        ScenarioResourceMetric::RunnableWork => snapshot.runnable_work,
        ScenarioResourceMetric::DeferredRetryWork => snapshot.deferred_retry_work,
        ScenarioResourceMetric::OutboundAwaitingAcknowledgement => {
            snapshot.outbound_awaiting_acknowledgement
        }
        ScenarioResourceMetric::TransportQueuedMessages => snapshot.transport_queued_messages,
        ScenarioResourceMetric::TransportDelayedMessages => snapshot.transport_delayed_messages,
        ScenarioResourceMetric::TransportMailboxMessages => snapshot.transport_mailbox_messages,
        ScenarioResourceMetric::ScenarioInputsPending => snapshot.scenario_inputs_pending,
    }
}
