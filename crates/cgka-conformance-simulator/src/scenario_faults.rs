//! Adapter-neutral semantic transport fault selectors.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioTransportClass {
    Commit,
    Proposal,
    Application,
    Welcome,
    GroupMessage,
}

/// Select one queued transport object by stable scenario meaning rather than
/// mutable queue position. All populated fields are conjunctive; `occurrence`
/// chooses the zero-based match in deterministic queue order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioMessageSelectorV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<ScenarioTransportClass>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub occurrence: usize,
}

impl ScenarioMessageSelectorV2 {
    pub fn is_semantic(&self) -> bool {
        self.action_id.is_some()
            || self.publication.is_some()
            || self.sender.is_some()
            || self.class.is_some()
    }
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioStorageFaultKind {
    Busy,
    ReadFailure,
    WriteFailure,
    CapacityExceeded,
    TornWrite,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioStorageFaultV2 {
    /// Device or process label interpreted by the selected adapter.
    pub target: String,
    pub kind: ScenarioStorageFaultKind,
    /// Number of matching storage operations to fail before auto-clearing.
    pub operations: u32,
}
