//! Explicit scenario deployment topology.
//!
//! This is descriptive input shared by every adapter. It does not prescribe
//! how a process or relay is launched; later adapters map these stable labels
//! to in-process objects, OS processes, containers, or VMs.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{ScenarioRunError, SubjectFailureCategory};

const UNSPECIFIED_VERSION: &str = "unspecified";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioTopologyV2 {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<ScenarioAccountV2>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<ScenarioDeviceV2>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub processes: Vec<ScenarioProcessV2>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<ScenarioGroupV2>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<ScenarioRelayV2>,
}

impl ScenarioTopologyV2 {
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
            && self.devices.is_empty()
            && self.processes.is_empty()
            && self.groups.is_empty()
            && self.relays.is_empty()
    }

    /// Resolve legacy client-only documents to one account/device/process per
    /// client. The values are intentionally explicit in compiled reports, but
    /// `unspecified` makes clear that an old vector did not pin a binary.
    pub fn resolve_for_clients(&self, clients: &[String]) -> Result<Self, ScenarioRunError> {
        let resolved = if self.is_empty() {
            Self {
                accounts: clients
                    .iter()
                    .map(|client| ScenarioAccountV2 {
                        id: format!("account:{client}"),
                        roles: vec!["member".into()],
                    })
                    .collect(),
                devices: clients
                    .iter()
                    .map(|client| ScenarioDeviceV2 {
                        id: format!("device:{client}"),
                        account: format!("account:{client}"),
                        process: format!("process:{client}"),
                        client: client.clone(),
                    })
                    .collect(),
                processes: clients
                    .iter()
                    .map(|client| ScenarioProcessV2 {
                        id: format!("process:{client}"),
                        binary_version: UNSPECIFIED_VERSION.into(),
                        policy_version: UNSPECIFIED_VERSION.into(),
                        relays: Vec::new(),
                    })
                    .collect(),
                groups: Vec::new(),
                relays: Vec::new(),
            }
        } else {
            self.clone()
        };
        resolved.validate(clients)?;
        Ok(resolved)
    }

    pub fn validate(&self, clients: &[String]) -> Result<(), ScenarioRunError> {
        let client_set = clients.iter().collect::<BTreeSet<_>>();
        let accounts = unique_by_id("account", self.accounts.iter().map(|item| &item.id))?;
        let processes = unique_by_id("process", self.processes.iter().map(|item| &item.id))?;
        let relays = unique_by_id("relay", self.relays.iter().map(|item| &item.id))?;
        unique_by_id("device", self.devices.iter().map(|item| &item.id))?;
        unique_by_id("group", self.groups.iter().map(|item| &item.id))?;

        let mut devices_by_client = BTreeMap::new();
        for device in &self.devices {
            require_label("device id", &device.id)?;
            require_label("device account", &device.account)?;
            require_label("device process", &device.process)?;
            require_label("device client", &device.client)?;
            if !client_set.contains(&device.client) {
                return Err(topology_error(format!(
                    "device {} references unknown client {}",
                    device.id, device.client
                )));
            }
            if !accounts.contains(device.account.as_str()) {
                return Err(topology_error(format!(
                    "device {} references unknown account {}",
                    device.id, device.account
                )));
            }
            if !processes.contains(device.process.as_str()) {
                return Err(topology_error(format!(
                    "device {} references unknown process {}",
                    device.id, device.process
                )));
            }
            if devices_by_client
                .insert(device.client.as_str(), device.id.as_str())
                .is_some()
            {
                return Err(topology_error(format!(
                    "client {} is mapped by more than one device",
                    device.client
                )));
            }
        }
        for client in clients {
            if !devices_by_client.contains_key(client.as_str()) {
                return Err(topology_error(format!(
                    "client {client} has no device mapping"
                )));
            }
        }

        for account in &self.accounts {
            require_label("account id", &account.id)?;
            for role in &account.roles {
                require_label("account role", role)?;
            }
        }
        for process in &self.processes {
            require_label("process id", &process.id)?;
            require_label("binary version", &process.binary_version)?;
            require_label("policy version", &process.policy_version)?;
            let mut process_relays = BTreeSet::new();
            for relay in &process.relays {
                if !relays.contains(relay.as_str()) {
                    return Err(topology_error(format!(
                        "process {} references unknown relay {relay}",
                        process.id
                    )));
                }
                if !process_relays.insert(relay) {
                    return Err(topology_error(format!(
                        "process {} repeats relay {relay}",
                        process.id
                    )));
                }
            }
        }
        let explicit_policy_versions = self
            .processes
            .iter()
            .map(|process| process.policy_version.as_str())
            .filter(|version| *version != UNSPECIFIED_VERSION)
            .collect::<BTreeSet<_>>();
        if explicit_policy_versions.len() > 1 {
            return Err(topology_error_with_kind(
                "incompatible_convergence_policy",
                format!(
                    "incompatible convergence policies in one scenario: {}",
                    explicit_policy_versions
                        .into_iter()
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
        for relay in &self.relays {
            require_label("relay id", &relay.id)?;
            require_label(
                "relay implementation version",
                &relay.implementation_version,
            )?;
            require_label("relay policy version", &relay.policy_version)?;
        }
        for group in &self.groups {
            require_label("group id", &group.id)?;
            let members = group.members.iter().collect::<BTreeSet<_>>();
            if members.len() != group.members.len() {
                return Err(topology_error(format!(
                    "group {} contains duplicate members",
                    group.id
                )));
            }
            for member in &group.members {
                if !client_set.contains(member) {
                    return Err(topology_error(format!(
                        "group {} references unknown member {member}",
                        group.id
                    )));
                }
            }
            for admin in &group.admins {
                if !members.contains(admin) {
                    return Err(topology_error(format!(
                        "group {} admin {admin} is not an initial member",
                        group.id
                    )));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioAccountV2 {
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioDeviceV2 {
    pub id: String,
    pub account: String,
    pub process: String,
    /// Scenario participant label used by actions and observations.
    pub client: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioProcessV2 {
    pub id: String,
    pub binary_version: String,
    pub policy_version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioGroupV2 {
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub admins: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioRelayV2 {
    pub id: String,
    pub implementation_version: String,
    pub policy_version: String,
}

fn unique_by_id<'a>(
    kind: &str,
    ids: impl Iterator<Item = &'a String>,
) -> Result<BTreeSet<&'a str>, ScenarioRunError> {
    let mut unique = BTreeSet::new();
    for id in ids {
        require_label(&format!("{kind} id"), id)?;
        if !unique.insert(id.as_str()) {
            return Err(topology_error(format!("duplicate {kind} id {id}")));
        }
    }
    Ok(unique)
}

fn require_label(field: &str, value: &str) -> Result<(), ScenarioRunError> {
    if value.trim().is_empty() {
        Err(topology_error(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}

fn topology_error(message: impl Into<String>) -> ScenarioRunError {
    topology_error_with_kind("scenario_topology_error", message)
}

fn topology_error_with_kind(
    kind: impl Into<String>,
    message: impl Into<String>,
) -> ScenarioRunError {
    ScenarioRunError {
        step_index: None,
        kind: kind.into(),
        category: SubjectFailureCategory::Environment,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implicit_topology_is_complete_and_deterministic() {
        let clients = vec!["alice".into(), "bob".into()];
        let first = ScenarioTopologyV2::default()
            .resolve_for_clients(&clients)
            .expect("resolve topology");
        let second = ScenarioTopologyV2::default()
            .resolve_for_clients(&clients)
            .expect("resolve topology");
        assert_eq!(first, second);
        assert_eq!(first.accounts.len(), 2);
        assert_eq!(first.devices.len(), 2);
        assert_eq!(first.processes.len(), 2);
    }

    #[test]
    fn explicit_topology_rejects_missing_device_mapping() {
        let topology = ScenarioTopologyV2 {
            accounts: vec![ScenarioAccountV2 {
                id: "account:alice".into(),
                roles: vec![],
            }],
            processes: vec![ScenarioProcessV2 {
                id: "process:alice".into(),
                binary_version: "v1".into(),
                policy_version: "v1".into(),
                relays: vec![],
            }],
            ..Default::default()
        };
        let error = topology
            .resolve_for_clients(&["alice".into()])
            .expect_err("missing device must fail");
        assert!(error.message.contains("no device mapping"));
    }
}
