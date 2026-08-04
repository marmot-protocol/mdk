use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::RunnerError;

pub const DISTRIBUTED_CAMPAIGN_MANIFEST_VERSION: &str = "1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributedCampaignManifestV1 {
    pub schema_version: String,
    pub campaign_id: String,
    pub scenario: ScenarioArtifactV1,
    pub participants: Vec<DistributedParticipantV1>,
    pub backend: DistributedBackendV1,
    #[serde(default)]
    pub faults: Vec<ScheduledFaultV1>,
    pub output_dir: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioArtifactV1 {
    pub path: PathBuf,
    /// Lowercase SHA-256 of the exact scenario bytes.
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributedParticipantV1 {
    pub id: String,
    /// Stable build or source-revision label recorded in evidence.
    pub build_id: String,
    /// Overrides the container backend default image for mixed-build runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_image: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DistributedBackendV1 {
    Container(ContainerBackendV1),
    VirtualMachine(VirtualMachineBackendV1),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerBackendV1 {
    pub runtime: OciRuntimeV1,
    /// Safe, operator-selected namespace for the runtime network and relay.
    pub namespace: String,
    pub default_participant_image: String,
    pub relay_image: String,
    #[serde(default = "default_relay_command")]
    pub relay_command: Vec<String>,
    #[serde(default = "default_node_command")]
    pub node_command: Vec<String>,
}

fn default_relay_command() -> Vec<String> {
    vec![
        "cgka-conformance-relay".into(),
        "--bind".into(),
        "0.0.0.0:8080".into(),
    ]
}

fn default_node_command() -> Vec<String> {
    vec!["cgka-conformance-node".into()]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OciRuntimeV1 {
    Docker,
    Podman,
}

impl OciRuntimeV1 {
    pub fn executable(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualMachineBackendV1 {
    /// External VM harness. The MDK runner owns the manifest/evidence contract;
    /// provisioning remains in the dedicated multi-VM repository.
    pub driver: PathBuf,
    #[serde(default)]
    pub driver_args: Vec<String>,
    pub capabilities: BTreeSet<VirtualMachineCapabilityV1>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VirtualMachineCapabilityV1 {
    KernelNetworkIsolation,
    BlockDeviceLatency,
    FilesystemFaults,
    HostIsolation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledFaultV1 {
    /// Faults are applied before the named canonical Scenario IR barrier.
    pub at_barrier: String,
    pub action: DistributedFaultV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DistributedFaultV1 {
    NetworkPartition {
        participant: String,
        peer: FaultPeerV1,
    },
    NetworkHeal {
        participant: String,
        peer: FaultPeerV1,
    },
    NetworkShape {
        participant: String,
        latency_ms: u32,
        jitter_ms: u32,
        loss_basis_points: u16,
        bandwidth_kbit: u32,
    },
    NetworkReset {
        participant: String,
    },
    RestartRelay,
    CrashParticipantHost {
        participant: String,
    },
    FillDisk {
        participant: String,
        bytes: u64,
    },
    ReleaseDisk {
        participant: String,
    },
    DatabaseContention {
        participant: String,
        workers: u8,
        bytes_per_worker: u64,
        duration_ms: u64,
    },
    StopDatabaseContention {
        participant: String,
    },
    SlowBlockDevice {
        participant: String,
        latency_ms: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultPeerV1 {
    Relay,
    Participant(String),
}

impl DistributedCampaignManifestV1 {
    pub fn validate(&self) -> Result<(), RunnerError> {
        if self.schema_version != DISTRIBUTED_CAMPAIGN_MANIFEST_VERSION {
            return Err(RunnerError::validation(
                "unsupported_manifest_version",
                "distributed campaign manifest version is unsupported",
            ));
        }
        validate_identifier("campaign_id", &self.campaign_id)?;
        if self.participants.len() < 2 {
            return Err(RunnerError::validation(
                "participant_count",
                "distributed campaigns require at least two participants",
            ));
        }
        if self.scenario.sha256.len() != 64
            || !self
                .scenario
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(RunnerError::validation(
                "scenario_digest",
                "scenario sha256 must be 64 lowercase hexadecimal characters",
            ));
        }
        let mut participants = BTreeSet::new();
        for participant in &self.participants {
            validate_identifier("participant", &participant.id)?;
            validate_identifier("build_id", &participant.build_id)?;
            if !participants.insert(participant.id.as_str()) {
                return Err(RunnerError::validation(
                    "duplicate_participant",
                    "participant ids must be unique",
                ));
            }
        }
        for fault in &self.faults {
            validate_identifier("barrier", &fault.at_barrier)?;
            for participant in fault.action.participants() {
                if !participants.contains(participant) {
                    return Err(RunnerError::validation(
                        "unknown_fault_participant",
                        "fault references a participant outside the manifest",
                    ));
                }
            }
            fault.action.validate_values()?;
        }
        match &self.backend {
            DistributedBackendV1::Container(container) => {
                validate_identifier("container_namespace", &container.namespace)?;
                if container.default_participant_image.is_empty()
                    || container.relay_image.is_empty()
                    || container.relay_command.is_empty()
                    || container.node_command.is_empty()
                {
                    return Err(RunnerError::validation(
                        "container_image_or_command",
                        "container images and argv commands must be non-empty",
                    ));
                }
                if self
                    .faults
                    .iter()
                    .any(|fault| matches!(fault.action, DistributedFaultV1::SlowBlockDevice { .. }))
                {
                    return Err(RunnerError::validation(
                        "vm_required_for_block_latency",
                        "slow block-device latency requires the virtual-machine backend",
                    ));
                }
            }
            DistributedBackendV1::VirtualMachine(vm) => {
                if vm.driver.as_os_str().is_empty() {
                    return Err(RunnerError::validation(
                        "vm_driver",
                        "virtual-machine backend requires an external driver",
                    ));
                }
                let required = self.required_vm_capabilities();
                if required.is_empty() {
                    return Err(RunnerError::validation(
                        "unnecessary_vm_backend",
                        "use the container backend when no VM-only capability is required",
                    ));
                }
                if !required.is_subset(&vm.capabilities) {
                    return Err(RunnerError::validation(
                        "missing_vm_capability",
                        "VM driver does not declare every capability required by the faults",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn required_vm_capabilities(&self) -> BTreeSet<VirtualMachineCapabilityV1> {
        self.faults
            .iter()
            .filter_map(|fault| match fault.action {
                DistributedFaultV1::SlowBlockDevice { .. } => {
                    Some(VirtualMachineCapabilityV1::BlockDeviceLatency)
                }
                _ => None,
            })
            .collect()
    }
}

impl DistributedFaultV1 {
    fn participants(&self) -> Vec<&str> {
        match self {
            Self::NetworkPartition { participant, peer }
            | Self::NetworkHeal { participant, peer } => {
                let mut participants = vec![participant.as_str()];
                if let FaultPeerV1::Participant(peer) = peer {
                    participants.push(peer);
                }
                participants
            }
            Self::NetworkShape { participant, .. }
            | Self::NetworkReset { participant }
            | Self::CrashParticipantHost { participant }
            | Self::FillDisk { participant, .. }
            | Self::ReleaseDisk { participant }
            | Self::DatabaseContention { participant, .. }
            | Self::StopDatabaseContention { participant }
            | Self::SlowBlockDevice { participant, .. } => vec![participant],
            Self::RestartRelay => Vec::new(),
        }
    }

    fn validate_values(&self) -> Result<(), RunnerError> {
        match self {
            Self::NetworkShape {
                loss_basis_points,
                bandwidth_kbit,
                ..
            } if *loss_basis_points > 10_000 || *bandwidth_kbit == 0 => {
                Err(RunnerError::validation(
                    "network_shape",
                    "loss must be at most 10000 basis points and bandwidth must be nonzero",
                ))
            }
            Self::FillDisk { bytes: 0, .. }
            | Self::DatabaseContention {
                workers: 0,
                bytes_per_worker: _,
                ..
            }
            | Self::DatabaseContention {
                workers: _,
                bytes_per_worker: 0,
                ..
            }
            | Self::DatabaseContention { duration_ms: 0, .. }
            | Self::SlowBlockDevice { latency_ms: 0, .. } => Err(RunnerError::validation(
                "fault_magnitude",
                "disk fault magnitudes and contention workers must be nonzero",
            )),
            _ => Ok(()),
        }
    }
}

fn validate_identifier(field: &str, value: &str) -> Result<(), RunnerError> {
    if value.is_empty()
        || value.len() > 96
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(RunnerError::validation(
            "unsafe_identifier",
            format!("{field} must use 1-96 safe identifier characters"),
        ));
    }
    Ok(())
}
