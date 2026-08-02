//! Adapter boundary between scenario semantics and a convergence implementation.
//!
//! The scenario runner owns step ordering, stable action ids, and report
//! construction. A [`ConvergenceSubject`] implements semantic operations using
//! only the public behavior available at its layer. Harness-only transport
//! mutation is exposed separately through [`ConvergenceFaultSubject`].

use crate::client::HarnessPublicationError;
use crate::{
    BidirectionalDecryptabilityObservation, CapturedTransportArtifactV1, CapturedTransportWindowV1,
    ClientBuilder, ClientObservation, DecryptabilityProbeSendStatus,
    DirectionalDecryptabilityProbe, EngineByteReplayV1, HarnessClient, HarnessStorageMode,
    ScenarioAdminPolicyObservation, ScenarioStep, SubjectProgressSnapshot, SubjectTerminalBlocker,
    TransportBus, observe_client, observe_client_exact,
};
use async_trait::async_trait;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::{ConvergenceClock, ManualConvergenceClock};
use cgka_traits::EngineError;
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::KeyPackage;
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::{GroupId, MemberId, MessageId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

/// A semantic or explicitly white-box operation an adapter can execute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectCapability {
    GroupMutation,
    ApplicationMessaging,
    TransportDelivery,
    EventObservation,
    ExactConformanceObservation,
    ActiveDecryptabilityProbe,
    AdminPolicyObservation,
    CrashReopen,
    VirtualTime,
    OutboundPublication,
    StructuralProgress,
    WhiteBoxTransportPartition,
    WhiteBoxStorageFaults,
    SemanticTransportFaults,
    ParticipantConnectivity,
    ProcessLifecycle,
    StorageFaultInjection,
    AssertionEvaluation,
    RetainedRelayHistory,
    RetainedRelayControl,
}

impl SubjectCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GroupMutation => "group_mutation",
            Self::ApplicationMessaging => "application_messaging",
            Self::TransportDelivery => "transport_delivery",
            Self::EventObservation => "event_observation",
            Self::ExactConformanceObservation => "exact_conformance_observation",
            Self::ActiveDecryptabilityProbe => "active_decryptability_probe",
            Self::AdminPolicyObservation => "admin_policy_observation",
            Self::CrashReopen => "crash_reopen",
            Self::VirtualTime => "virtual_time",
            Self::OutboundPublication => "outbound_publication",
            Self::StructuralProgress => "structural_progress",
            Self::WhiteBoxTransportPartition => "white_box_transport_partition",
            Self::WhiteBoxStorageFaults => "white_box_storage_faults",
            Self::SemanticTransportFaults => "semantic_transport_faults",
            Self::ParticipantConnectivity => "participant_connectivity",
            Self::ProcessLifecycle => "process_lifecycle",
            Self::StorageFaultInjection => "storage_fault_injection",
            Self::AssertionEvaluation => "assertion_evaluation",
            Self::RetainedRelayHistory => "retained_relay_history",
            Self::RetainedRelayControl => "retained_relay_control",
        }
    }

    pub const fn is_white_box(self) -> bool {
        matches!(
            self,
            Self::WhiteBoxTransportPartition | Self::WhiteBoxStorageFaults
        )
    }
}

impl fmt::Display for SubjectCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable adapter identity and its declared executable surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectDescriptor {
    pub adapter: String,
    pub adapter_version: String,
    pub storage_backend: String,
    pub capabilities: BTreeSet<SubjectCapability>,
}

impl SubjectDescriptor {
    pub fn supports(&self, capability: SubjectCapability) -> bool {
        self.capabilities.contains(&capability)
    }
}

/// Adapter-level failure with a normalized code suitable for expectations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectFailureCategory {
    ExpectedRefusal,
    Protocol,
    Resource,
    #[default]
    Environment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectError {
    pub code: String,
    pub message: String,
    pub category: SubjectFailureCategory,
}

impl SubjectError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            category: SubjectFailureCategory::Environment,
        }
    }

    pub fn classified(
        category: SubjectFailureCategory,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            category,
        }
    }

    fn unsupported(capability: SubjectCapability) -> Self {
        Self::new(
            "unsupported_capability",
            format!("subject does not support {capability}"),
        )
    }
}

impl fmt::Display for SubjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for SubjectError {}

pub struct SubjectCreateGroup<'a> {
    pub creator: &'a str,
    pub name: &'a str,
    pub invitees: &'a [String],
    pub required_features: &'a [String],
    pub initial_admins: &'a [String],
    pub pending: &'a str,
}

pub struct SubjectInviteMembers<'a> {
    pub action_id: &'a str,
    pub inviter: &'a str,
    pub invitees: &'a [String],
    pub pending: &'a str,
}

pub struct SubjectRemoveMembers<'a> {
    pub action_id: &'a str,
    pub remover: &'a str,
    pub members: &'a [String],
    pub pending: &'a str,
}

pub struct SubjectSelfUpdate<'a> {
    pub action_id: &'a str,
    pub client: &'a str,
    pub pending: &'a str,
}

pub struct SubjectUpdateGroupData<'a> {
    pub action_id: &'a str,
    pub client: &'a str,
    pub name: &'a str,
    pub pending: &'a str,
}

pub struct SubjectUpdateAdminPolicy<'a> {
    /// Stable input id for operations expected to produce protocol input.
    /// Expected validation failures leave this unset because no input should
    /// be produced or entered into the scenario-input ledger.
    pub action_id: Option<&'a str>,
    pub client: &'a str,
    pub admins: &'a [String],
    pub pending: Option<&'a str>,
}

pub struct SubjectSendApplication<'a> {
    pub action_id: &'a str,
    pub sender: &'a str,
    pub payload: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectOutboundKind {
    GroupMessage,
    Welcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectOutboundOutcome {
    Accepted,
    ReachedNoEndpoint,
}

/// One transport-ready artifact emitted by a subject participant.
///
/// `outbound_id` is an adapter-owned opaque acknowledgement handle. The
/// transport message is intentionally preserved as a cross-boundary value so
/// retained-relay and process adapters can publish the exact bytes without
/// gaining access to engine or harness storage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectOutboundArtifact {
    pub outbound_id: String,
    pub client: String,
    /// Stable scenario publication label, when the emission belongs to a
    /// scenario-requested staged state transition. Engine-generated outbound
    /// work intentionally leaves this unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication: Option<String>,
    pub kind: SubjectOutboundKind,
    pub message: TransportMessage,
    pub state_confirmation_required: bool,
    pub regenerated_queued_intent: bool,
}

/// Normal convergence operations available to a scenario executor.
///
/// Default methods fail closed. A partial adapter can therefore declare only
/// the capabilities it truly supports; preflight rejects the scenario before
/// any method is invoked.
#[async_trait]
pub trait ConvergenceSubject: Send {
    fn descriptor(&self) -> SubjectDescriptor;

    async fn create_group(&mut self, _action: SubjectCreateGroup<'_>) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(SubjectCapability::GroupMutation))
    }

    async fn invite_members(
        &mut self,
        _action: SubjectInviteMembers<'_>,
    ) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(SubjectCapability::GroupMutation))
    }

    async fn update_group_data(
        &mut self,
        _action: SubjectUpdateGroupData<'_>,
    ) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(SubjectCapability::GroupMutation))
    }

    async fn remove_members(
        &mut self,
        _action: SubjectRemoveMembers<'_>,
    ) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(SubjectCapability::GroupMutation))
    }

    async fn self_update(&mut self, _action: SubjectSelfUpdate<'_>) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(SubjectCapability::GroupMutation))
    }

    async fn update_admin_policy(
        &mut self,
        _action: SubjectUpdateAdminPolicy<'_>,
    ) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(SubjectCapability::GroupMutation))
    }

    async fn send_application(
        &mut self,
        _action: SubjectSendApplication<'_>,
    ) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::ApplicationMessaging,
        ))
    }

    async fn leave(&mut self, _action_id: &str, _client: &str) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(SubjectCapability::GroupMutation))
    }

    fn deliver_all(&mut self) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::TransportDelivery,
        ))
    }

    async fn tick(&mut self, _clients: &[String]) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::TransportDelivery,
        ))
    }

    /// Select controlled virtual-time behavior without advancing either clock
    /// domain. This makes the clock-mode transition explicit for adapters.
    fn activate_virtual_time(&mut self) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(SubjectCapability::VirtualTime))
    }

    /// Advance the subject's paired convergence clock without waking a
    /// participant runtime. A later `tick` selects which participants observe
    /// the elapsed deadline.
    async fn advance_time(&mut self, _delta_ms: u64) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(SubjectCapability::VirtualTime))
    }

    fn poll_outbound(
        &mut self,
        _client: &str,
    ) -> Result<Vec<SubjectOutboundArtifact>, SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::OutboundPublication,
        ))
    }

    async fn acknowledge_outbound(
        &mut self,
        _client: &str,
        _outbound_id: &str,
        _outcome: SubjectOutboundOutcome,
    ) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::OutboundPublication,
        ))
    }

    fn structural_progress(&mut self) -> Result<SubjectProgressSnapshot, SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::StructuralProgress,
        ))
    }

    fn observe(&mut self, _clients: &[String]) -> Result<Vec<ClientObservation>, SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::EventObservation,
        ))
    }

    fn observe_exact(
        &mut self,
        _clients: &[String],
    ) -> Result<Vec<ClientObservation>, SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::ExactConformanceObservation,
        ))
    }

    async fn probe_bidirectional_decryptability(
        &mut self,
        _clients: &[String],
        _step_index: usize,
    ) -> Result<BidirectionalDecryptabilityObservation, SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::ActiveDecryptabilityProbe,
        ))
    }

    fn observe_admin_policy(
        &self,
        _clients: &[String],
    ) -> Result<Vec<ScenarioAdminPolicyObservation>, SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::AdminPolicyObservation,
        ))
    }

    fn evaluate_predicate(
        &mut self,
        _predicate: &crate::ScenarioPredicateV2,
    ) -> Result<crate::ScenarioPredicateObservationV2, SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::AssertionEvaluation,
        ))
    }

    fn sync_relay_history(
        &mut self,
        _clients: &[String],
        _mode: &crate::ScenarioRelaySyncModeV2,
    ) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::RetainedRelayHistory,
        ))
    }

    fn configure_relay(
        &mut self,
        _relay: &str,
        _order: crate::ScenarioRelayOrderV2,
        _duplicate_copies: usize,
    ) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::RetainedRelayControl,
        ))
    }

    fn set_relay_event_visibility(
        &mut self,
        _relay: &str,
        _selector: &crate::ScenarioMessageSelectorV2,
        _clients: &[String],
        _visible: bool,
    ) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::RetainedRelayControl,
        ))
    }

    fn reconcile_relay_histories(&mut self, _relays: &[String]) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::RetainedRelayControl,
        ))
    }

    fn relay_sync_observations(&self) -> Vec<crate::RelaySyncObservationV2> {
        Vec::new()
    }

    fn clear_events(&mut self, _clients: &[String]) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::EventObservation,
        ))
    }

    fn restart(&mut self, _client: &str) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(SubjectCapability::CrashReopen))
    }

    fn set_client_online(&mut self, _client: &str, _online: bool) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::ParticipantConnectivity,
        ))
    }

    fn crash_process(&mut self, _process: &str) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::ProcessLifecycle,
        ))
    }

    fn restart_process(&mut self, _process: &str) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::ProcessLifecycle,
        ))
    }

    fn inject_storage_fault(
        &mut self,
        _fault: &crate::ScenarioStorageFaultV2,
    ) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::StorageFaultInjection,
        ))
    }

    fn clear_storage_fault(&mut self, _target: &str) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::StorageFaultInjection,
        ))
    }

    fn fault_injection(&mut self) -> Option<&mut dyn ConvergenceFaultSubject> {
        None
    }
}

/// Explicit harness-only transport mutation. Normal subjects need not expose it.
pub trait ConvergenceFaultSubject {
    fn set_partition(&mut self, allow: &[String]) -> Result<(), SubjectError>;
    fn clear_partition(&mut self) -> Result<(), SubjectError>;
    fn omit_message(
        &mut self,
        selector: &crate::ScenarioMessageSelectorV2,
    ) -> Result<(), SubjectError>;
    fn duplicate_message(
        &mut self,
        selector: &crate::ScenarioMessageSelectorV2,
    ) -> Result<(), SubjectError>;
    fn withhold_message(
        &mut self,
        selector: &crate::ScenarioMessageSelectorV2,
        label: &str,
    ) -> Result<(), SubjectError>;
    fn release_withheld(&mut self, label: &str) -> Result<(), SubjectError>;
    fn reorder_messages(
        &mut self,
        order: &[crate::ScenarioMessageSelectorV2],
    ) -> Result<(), SubjectError>;
}

/// Complete capability set used by a scenario step. Most operations need one
/// capability; fixed-point settling composes progress, time, delivery, and
/// optionally outbound acknowledgement without moving policy into the subject.
pub fn required_capabilities(step: &ScenarioStep) -> Vec<SubjectCapability> {
    if matches!(step, ScenarioStep::Barrier { .. }) {
        return Vec::new();
    }
    if let ScenarioStep::Assert { assertion } = step {
        let predicate = match assertion {
            crate::ScenarioAssertionV2::Exactly { predicate }
            | crate::ScenarioAssertionV2::Eventually { predicate, .. }
            | crate::ScenarioAssertionV2::Within { predicate, .. }
            | crate::ScenarioAssertionV2::Never { predicate, .. } => Some(predicate),
            crate::ScenarioAssertionV2::Resource { .. } => None,
        };
        let mut capabilities = match assertion {
            crate::ScenarioAssertionV2::Exactly { .. } => {
                vec![SubjectCapability::AssertionEvaluation]
            }
            crate::ScenarioAssertionV2::Eventually { .. } => vec![
                SubjectCapability::AssertionEvaluation,
                SubjectCapability::TransportDelivery,
            ],
            crate::ScenarioAssertionV2::Within { .. }
            | crate::ScenarioAssertionV2::Never { .. } => vec![
                SubjectCapability::AssertionEvaluation,
                SubjectCapability::TransportDelivery,
                SubjectCapability::VirtualTime,
            ],
            crate::ScenarioAssertionV2::Resource { .. } => {
                vec![SubjectCapability::StructuralProgress]
            }
        };
        if matches!(
            predicate,
            Some(
                crate::ScenarioPredicateV2::ClientsExactlyEquivalent { .. }
                    | crate::ScenarioPredicateV2::NoPendingWork { .. }
            )
        ) {
            capabilities.push(SubjectCapability::ExactConformanceObservation);
        }
        return capabilities;
    }
    if let ScenarioStep::AwaitQuiescence { policy } = step {
        let mut capabilities = vec![
            SubjectCapability::StructuralProgress,
            SubjectCapability::VirtualTime,
            SubjectCapability::TransportDelivery,
        ];
        if policy.outbound == crate::QuiescenceOutboundPolicy::AcceptAll {
            capabilities.push(SubjectCapability::OutboundPublication);
        }
        capabilities
    } else {
        vec![match step {
            ScenarioStep::CreateGroup { .. }
            | ScenarioStep::InviteMembers { .. }
            | ScenarioStep::RemoveMembers { .. }
            | ScenarioStep::SelfUpdate { .. }
            | ScenarioStep::UpdateGroupData { .. }
            | ScenarioStep::UpdateAdminPolicy { .. }
            | ScenarioStep::ExpectUpdateAdminPolicyError { .. }
            | ScenarioStep::Leave { .. } => SubjectCapability::GroupMutation,
            ScenarioStep::AcknowledgeOutbound { .. } => SubjectCapability::OutboundPublication,
            ScenarioStep::SendAppMessage { .. } => SubjectCapability::ApplicationMessaging,
            ScenarioStep::DeliverAll | ScenarioStep::Tick { .. } => {
                SubjectCapability::TransportDelivery
            }
            ScenarioStep::AdvanceTime { .. } => SubjectCapability::VirtualTime,
            ScenarioStep::Observe { .. } | ScenarioStep::ClearEvents { .. } => {
                SubjectCapability::EventObservation
            }
            ScenarioStep::ObserveExact { .. } => SubjectCapability::ExactConformanceObservation,
            ScenarioStep::ProbeBidirectionalDecryptability { .. } => {
                SubjectCapability::ActiveDecryptabilityProbe
            }
            ScenarioStep::ObserveAdminPolicy { .. } => SubjectCapability::AdminPolicyObservation,
            ScenarioStep::RestartClient { .. } => SubjectCapability::CrashReopen,
            ScenarioStep::SetClientOffline { .. } | ScenarioStep::ReconnectClient { .. } => {
                SubjectCapability::ParticipantConnectivity
            }
            ScenarioStep::SyncRelayHistory { .. } => SubjectCapability::RetainedRelayHistory,
            ScenarioStep::ConfigureRelay { .. }
            | ScenarioStep::SetRelayEventVisibility { .. }
            | ScenarioStep::ReconcileRelayHistories { .. } => {
                SubjectCapability::RetainedRelayControl
            }
            ScenarioStep::CrashProcess { .. } | ScenarioStep::RestartProcess { .. } => {
                SubjectCapability::ProcessLifecycle
            }
            ScenarioStep::InjectStorageFault { .. } | ScenarioStep::ClearStorageFault { .. } => {
                SubjectCapability::StorageFaultInjection
            }
            ScenarioStep::SetPartition { .. } | ScenarioStep::ClearPartition => {
                SubjectCapability::WhiteBoxTransportPartition
            }
            ScenarioStep::OmitMessage { .. }
            | ScenarioStep::DuplicateMessage { .. }
            | ScenarioStep::WithholdMessage { .. }
            | ScenarioStep::ReleaseWithheld { .. }
            | ScenarioStep::ReorderMessages { .. } => SubjectCapability::SemanticTransportFaults,
            ScenarioStep::Barrier { .. } => unreachable!("handled above"),
            ScenarioStep::Assert { .. } => unreachable!("handled above"),
            ScenarioStep::AwaitQuiescence { .. } => unreachable!("handled above"),
        }]
    }
}

/// Current in-process OpenMLS/SQLite/Nostr-peeler subject.
pub struct EngineHarnessSubject {
    descriptor: SubjectDescriptor,
    bus: TransportBus,
    clients: BTreeMap<String, HarnessClient>,
    pending_refs: HashMap<String, EngineSubjectPendingRef>,
    convergence_clock: ManualConvergenceClock,
    outbound_cursors: HashMap<String, u64>,
    outbound_records: BTreeMap<u64, EngineSubjectOutboundRecord>,
    replay_capture_target_tick: Option<usize>,
    observed_recipient_ticks: usize,
    last_byte_replay: Option<EngineByteReplayV1>,
}

#[derive(Clone)]
struct EngineSubjectPendingRef {
    client: String,
    pending: PendingStateRef,
}

#[derive(Clone)]
struct EngineSubjectOutboundRecord {
    artifact: SubjectOutboundArtifact,
    pending: Option<PendingStateRef>,
    queued_intent: Option<(GroupId, MessageId)>,
    resolution: Option<SubjectOutboundOutcome>,
}

struct PendingByteReplay {
    client_label: String,
    identity_seed: Vec<u8>,
    protocol_profile: ProtocolProfile,
    group_id: Vec<u8>,
    sensitive_checkpoint: Vec<u8>,
    captured_deliveries: Vec<TransportMessage>,
    checkpoint_monotonic_ms: u64,
    checkpoint_wall_ms: u64,
    virtual_time_tick_enabled: bool,
}

impl EngineHarnessSubject {
    pub fn new(
        clients: &[String],
        protocol_profile: ProtocolProfile,
        storage_mode: HarnessStorageMode,
    ) -> Result<Self, SubjectError> {
        let bus = TransportBus::ordered();
        let convergence_clock = ManualConvergenceClock::new(0, 0);
        let mut attached = BTreeMap::new();
        for label in clients {
            if attached.contains_key(label) {
                return Err(SubjectError::new(
                    "duplicate_client",
                    format!("duplicate client label {label}"),
                ));
            }
            let builder = ClientBuilder::new(pad32(label.as_bytes()))
                .registry(engine_harness_feature_registry())
                .protocol_profile(protocol_profile)
                .storage_mode(storage_mode)
                .convergence_clock(Arc::new(convergence_clock.clone()));
            let client = builder.attach(&bus);
            attached.insert(label.clone(), client);
        }
        let capabilities = BTreeSet::from([
            SubjectCapability::GroupMutation,
            SubjectCapability::ApplicationMessaging,
            SubjectCapability::TransportDelivery,
            SubjectCapability::EventObservation,
            SubjectCapability::ExactConformanceObservation,
            SubjectCapability::ActiveDecryptabilityProbe,
            SubjectCapability::AdminPolicyObservation,
            SubjectCapability::CrashReopen,
            SubjectCapability::VirtualTime,
            SubjectCapability::OutboundPublication,
            SubjectCapability::StructuralProgress,
            SubjectCapability::WhiteBoxTransportPartition,
            SubjectCapability::SemanticTransportFaults,
            SubjectCapability::AssertionEvaluation,
        ]);
        Ok(Self {
            descriptor: SubjectDescriptor {
                adapter: "mdk-engine-harness".into(),
                adapter_version: env!("CARGO_PKG_VERSION").into(),
                storage_backend: storage_mode.report_label().into(),
                capabilities,
            },
            bus,
            clients: attached,
            pending_refs: HashMap::new(),
            convergence_clock,
            outbound_cursors: HashMap::new(),
            outbound_records: BTreeMap::new(),
            replay_capture_target_tick: None,
            observed_recipient_ticks: 0,
            last_byte_replay: None,
        })
    }

    fn client(&self, label: &str) -> Result<&HarnessClient, SubjectError> {
        self.clients
            .get(label)
            .ok_or_else(|| SubjectError::new("unknown_client", format!("unknown client {label}")))
    }

    /// Bounded tail of exact transport artifacts emitted during this subject
    /// run, plus totals that make truncation explicit.
    pub fn captured_transport_window(&self) -> CapturedTransportWindowV1 {
        let capture = self.bus.captured_outbound_window();
        let labels_by_bus_id = self
            .clients
            .iter()
            .map(|(label, client)| (client.bus_id, label))
            .collect::<HashMap<_, _>>();
        let artifacts = capture
            .emissions
            .into_iter()
            .filter_map(|(sender, emission)| {
                Some(CapturedTransportArtifactV1 {
                    sequence: emission.sequence,
                    sender: labels_by_bus_id.get(&sender)?.to_string(),
                    message: emission.msg,
                })
            })
            .collect();
        CapturedTransportWindowV1 {
            artifacts,
            observed_objects: capture.observed_objects,
            observed_json_bytes: capture.observed_json_bytes,
        }
    }

    pub fn captured_transport_artifacts(&self) -> Vec<CapturedTransportArtifactV1> {
        self.captured_transport_window().artifacts
    }

    pub fn byte_replay_capture(&self) -> Option<EngineByteReplayV1> {
        self.last_byte_replay.clone()
    }

    pub(crate) fn discard_packet_bus_artifact(&self, message_id: MessageId) -> usize {
        self.bus.discard_queued_messages(&[message_id])
    }

    pub(crate) fn inject_transport_for_client(
        &self,
        client: &str,
        message: TransportMessage,
    ) -> Result<(), SubjectError> {
        self.bus.inject(self.client(client)?.bus_id, message);
        Ok(())
    }

    /// Capture one explicitly selected recipient tick. Campaign callers choose
    /// the final planned tick so checkpoint export is paid at most once rather
    /// than once per client on every tick step.
    pub fn capture_failure_replay_at_tick(&mut self, recipient_tick: usize) {
        self.replay_capture_target_tick = Some(recipient_tick);
    }

    fn prepare_byte_replay(&self, label: &str) -> Option<PendingByteReplay> {
        let client = self.clients.get(label)?;
        let group_id = client.replay_group_id()?.clone();
        let sensitive_checkpoint = client
            .export_conformance_replay_checkpoint(&group_id)
            .ok()?;
        if sensitive_checkpoint.len() > crate::MAX_CAPTURED_REPLAY_CHECKPOINT_BYTES {
            return None;
        }
        let captured_deliveries = self.bus.mailbox_snapshot(client.bus_id);
        let captured_delivery_bytes = captured_deliveries
            .iter()
            .map(|message| serde_json::to_vec(message).map_or(0, |bytes| bytes.len() as u64))
            .sum::<u64>();
        if captured_deliveries.len() > crate::MAX_CAPTURED_TRANSPORT_OBJECTS
            || captured_delivery_bytes > crate::MAX_CAPTURED_TRANSPORT_JSON_BYTES
        {
            return None;
        }
        let now = self.convergence_clock.now();
        Some(PendingByteReplay {
            client_label: label.to_owned(),
            identity_seed: pad32(label.as_bytes()),
            protocol_profile: client.replay_protocol_profile(),
            group_id: group_id.as_slice().to_vec(),
            sensitive_checkpoint,
            captured_deliveries,
            checkpoint_monotonic_ms: now.monotonic_ms,
            checkpoint_wall_ms: now.wall_ms,
            virtual_time_tick_enabled: client.replay_uses_virtual_time(),
        })
    }

    fn complete_byte_replay(
        &self,
        pending: PendingByteReplay,
        outcomes: &[Result<cgka_traits::ingest::IngestOutcome, EngineError>],
    ) -> Option<EngineByteReplayV1> {
        let client = self.clients.get(&pending.client_label)?;
        let canonical_state = client.try_canonical_state_snapshot().ok()?;
        let normalized_state_digest = crate::digest_json(&canonical_state).ok()?;
        let (classification, failure_kind) = outcomes
            .iter()
            .find_map(|outcome| outcome.as_ref().err())
            .map_or(
                (
                    crate::TerminalOutcomeClassification::Converged,
                    "campaign_tick_replay".to_string(),
                ),
                |error| {
                    let (category, code) = classify_engine_error(error);
                    (
                        crate::failure_capsule::terminal_classification(category),
                        format!("scenario_step_failed:{code}"),
                    )
                },
            );
        let expected_fingerprint = crate::build_fingerprint(
            classification,
            Some("campaign_tick".into()),
            failure_kind,
            normalized_state_digest,
        );
        Some(EngineByteReplayV1 {
            client_label: pending.client_label,
            identity_seed: pending.identity_seed,
            protocol_profile: pending.protocol_profile,
            group_id: pending.group_id,
            sensitive_checkpoint: pending.sensitive_checkpoint,
            captured_deliveries: pending.captured_deliveries,
            checkpoint_monotonic_ms: pending.checkpoint_monotonic_ms,
            checkpoint_wall_ms: pending.checkpoint_wall_ms,
            virtual_time_tick_enabled: pending.virtual_time_tick_enabled,
            expected_fingerprint,
        })
    }

    fn client_mut(&mut self, label: &str) -> Result<&mut HarnessClient, SubjectError> {
        self.clients
            .get_mut(label)
            .ok_or_else(|| SubjectError::new("unknown_client", format!("unknown client {label}")))
    }

    fn semantic_queue_index(
        &mut self,
        selector: &crate::ScenarioMessageSelectorV2,
    ) -> Result<usize, SubjectError> {
        if !selector.is_semantic() {
            return Err(SubjectError::new(
                "empty_message_selector",
                "message selector must constrain action, publication, sender, or class",
            ));
        }
        if selector.publication.is_some() {
            let clients = self.clients.keys().cloned().collect::<Vec<_>>();
            for client in clients {
                self.sync_client_outbound(&client)?;
            }
        }
        let sender = selector
            .sender
            .as_deref()
            .map(|sender| self.client(sender).map(|client| client.bus_id))
            .transpose()?;
        let publication_ids = selector.publication.as_ref().map(|publication| {
            self.outbound_records
                .values()
                .filter(|record| record.artifact.publication.as_ref() == Some(publication))
                .map(|record| record.artifact.message.id.clone())
                .collect::<HashSet<_>>()
        });
        if selector.publication.is_some() && publication_ids.as_ref().is_some_and(HashSet::is_empty)
        {
            return Err(SubjectError::new(
                "unknown_publication_selector",
                format!(
                    "no emitted transport artifacts match publication {:?}",
                    selector.publication
                ),
            ));
        }
        self.bus
            .semantic_queue_index(selector, sender, publication_ids.as_ref())
            .ok_or_else(|| {
                SubjectError::new(
                    "message_selector_no_match",
                    format!("no queued transport object matches {selector:?}"),
                )
            })
    }

    async fn fresh_key_packages(
        &mut self,
        labels: &[String],
    ) -> Result<Vec<KeyPackage>, SubjectError> {
        let mut key_packages = Vec::with_capacity(labels.len());
        for label in labels {
            key_packages.push(self.client_mut(label)?.fresh_key_package().await);
        }
        Ok(key_packages)
    }

    fn member_ids(&self, labels: &[String]) -> Result<Vec<MemberId>, SubjectError> {
        labels
            .iter()
            .map(|label| self.client(label).map(HarnessClient::member_id))
            .collect()
    }

    fn insert_pending(
        &mut self,
        label: &str,
        client: &str,
        pending_ref: PendingStateRef,
    ) -> Result<(), SubjectError> {
        if self
            .pending_refs
            .insert(
                label.to_string(),
                EngineSubjectPendingRef {
                    client: client.to_owned(),
                    pending: pending_ref,
                },
            )
            .is_some()
        {
            return Err(SubjectError::new(
                "duplicate_pending",
                format!("duplicate pending label {label}"),
            ));
        }
        Ok(())
    }

    fn publication_for_pending(&self, client: &str, pending: PendingStateRef) -> Option<String> {
        self.pending_refs.iter().find_map(|(label, candidate)| {
            (candidate.client == client && candidate.pending == pending).then(|| label.clone())
        })
    }

    fn sync_client_outbound(&mut self, label: &str) -> Result<(), SubjectError> {
        let client = self.client(label)?;
        let bus_id = client.bus_id;
        let after_sequence = self.outbound_cursors.get(label).copied();
        let emissions = self.bus.outbound_since(bus_id, after_sequence);
        if emissions.is_empty() {
            return Ok(());
        }

        for emission in emissions {
            let pending = self
                .client(label)?
                .pending_publication_for_message(&emission.msg.id);
            let publication =
                pending.and_then(|pending| self.publication_for_pending(label, pending));
            let queued_intent = self
                .client(label)?
                .regenerated_queued_intent_for_message(&emission.msg.id);
            let state_confirmation_required = pending.is_some_and(|pending| {
                self.client(label)
                    .expect("validated client remains present")
                    .message_confirms_pending(pending, &emission.msg.id)
            });
            let kind = match &emission.msg.envelope {
                TransportEnvelope::GroupMessage { .. } => SubjectOutboundKind::GroupMessage,
                TransportEnvelope::Welcome { .. } => SubjectOutboundKind::Welcome,
            };
            let outbound_id = format!("outbound/{}", emission.sequence);
            self.outbound_records
                .entry(emission.sequence)
                .or_insert_with(|| EngineSubjectOutboundRecord {
                    artifact: SubjectOutboundArtifact {
                        outbound_id,
                        client: label.to_owned(),
                        publication,
                        kind,
                        message: emission.msg,
                        state_confirmation_required,
                        regenerated_queued_intent: queued_intent.is_some(),
                    },
                    pending,
                    queued_intent,
                    resolution: None,
                });
            self.outbound_cursors
                .insert(label.to_owned(), emission.sequence);
        }
        Ok(())
    }

    fn mark_pending_outbound(
        &mut self,
        client: &str,
        pending: PendingStateRef,
        outcome: SubjectOutboundOutcome,
    ) {
        for record in self.outbound_records.values_mut() {
            if record.artifact.client == client
                && record.pending == Some(pending)
                && record.resolution.is_none()
            {
                record.resolution = Some(outcome);
            }
        }
    }

    fn pending_confirmation_accepted(&self, client: &str, pending: PendingStateRef) -> bool {
        self.outbound_records.values().any(|candidate| {
            candidate.artifact.client == client
                && candidate.pending == Some(pending)
                && candidate.artifact.state_confirmation_required
                && candidate.resolution == Some(SubjectOutboundOutcome::Accepted)
        })
    }

    fn pending_non_confirmation_accepted(&self, client: &str, pending: PendingStateRef) -> bool {
        self.outbound_records.values().any(|candidate| {
            candidate.artifact.client == client
                && candidate.pending == Some(pending)
                && !candidate.artifact.state_confirmation_required
                && candidate.resolution == Some(SubjectOutboundOutcome::Accepted)
        })
    }
}

#[async_trait]
impl ConvergenceSubject for EngineHarnessSubject {
    fn descriptor(&self) -> SubjectDescriptor {
        self.descriptor.clone()
    }

    async fn create_group(&mut self, action: SubjectCreateGroup<'_>) -> Result<(), SubjectError> {
        let initial_admins = self.member_ids(action.initial_admins)?;
        let key_packages = self.fresh_key_packages(action.invitees).await?;
        let required_features = required_features_from_names(action.required_features)?;
        let creator = self.client_mut(action.creator)?;
        let (_, pending_ref) = creator
            .create_group_with_admins_maybe_pending(
                action.name,
                key_packages,
                required_features,
                initial_admins,
            )
            .await;
        if let Some(pending_ref) = pending_ref {
            self.insert_pending(action.pending, action.creator, pending_ref)?;
            self.sync_client_outbound(action.creator)?;
            if self
                .client_mut(action.creator)?
                .confirm_empty_publication(pending_ref)
                .await
                .map_err(subject_engine_error)?
            {
                self.pending_refs.remove(action.pending);
            }
        }
        Ok(())
    }

    async fn invite_members(
        &mut self,
        action: SubjectInviteMembers<'_>,
    ) -> Result<(), SubjectError> {
        let key_packages = self.fresh_key_packages(action.invitees).await?;
        let inviter = self.client_mut(action.inviter)?;
        inviter.name_next_scenario_input(action.action_id);
        let pending_ref = inviter.invite(key_packages).await;
        self.insert_pending(action.pending, action.inviter, pending_ref)
    }

    async fn update_group_data(
        &mut self,
        action: SubjectUpdateGroupData<'_>,
    ) -> Result<(), SubjectError> {
        let client = self.client_mut(action.client)?;
        client.name_next_scenario_input(action.action_id);
        let pending_ref = client.update_group_data(action.name.to_owned()).await;
        self.insert_pending(action.pending, action.client, pending_ref)
    }

    async fn remove_members(
        &mut self,
        action: SubjectRemoveMembers<'_>,
    ) -> Result<(), SubjectError> {
        let member_ids = self.member_ids(action.members)?;
        let remover = self.client_mut(action.remover)?;
        remover.name_next_scenario_input(action.action_id);
        let pending_ref = remover.remove_members(member_ids).await;
        self.insert_pending(action.pending, action.remover, pending_ref)
    }

    async fn self_update(&mut self, action: SubjectSelfUpdate<'_>) -> Result<(), SubjectError> {
        let client = self.client_mut(action.client)?;
        client.name_next_scenario_input(action.action_id);
        let pending_ref = client.self_update().await;
        self.insert_pending(action.pending, action.client, pending_ref)
    }

    async fn update_admin_policy(
        &mut self,
        action: SubjectUpdateAdminPolicy<'_>,
    ) -> Result<(), SubjectError> {
        let admin_ids = self.member_ids(action.admins)?;
        let client = self.client_mut(action.client)?;
        if let Some(action_id) = action.action_id {
            client.name_next_scenario_input(action_id);
        }
        let pending_ref = client
            .update_admin_policy(admin_ids)
            .await
            .map_err(subject_engine_error)?;
        if let Some(pending) = action.pending {
            self.insert_pending(pending, action.client, pending_ref)?;
        }
        Ok(())
    }

    async fn send_application(
        &mut self,
        action: SubjectSendApplication<'_>,
    ) -> Result<(), SubjectError> {
        let sender = self.client_mut(action.sender)?;
        sender.name_next_scenario_input(action.action_id);
        sender.send_app(action.payload.as_bytes().to_vec()).await;
        Ok(())
    }

    async fn leave(&mut self, action_id: &str, client: &str) -> Result<(), SubjectError> {
        let client = self.client_mut(client)?;
        client.name_next_scenario_input(action_id);
        client.leave().await;
        Ok(())
    }

    fn deliver_all(&mut self) -> Result<(), SubjectError> {
        self.bus.deliver_all();
        Ok(())
    }

    async fn tick(&mut self, clients: &[String]) -> Result<(), SubjectError> {
        for label in clients {
            let recipient_tick = self.observed_recipient_ticks;
            self.observed_recipient_ticks = self.observed_recipient_ticks.saturating_add(1);
            let pending_replay = (self.replay_capture_target_tick == Some(recipient_tick))
                .then(|| self.prepare_byte_replay(label))
                .flatten();
            let outcomes = self.client_mut(label)?.tick().await;
            if let Some(pending_replay) = pending_replay
                && let Some(replay) = self.complete_byte_replay(pending_replay, &outcomes)
            {
                self.last_byte_replay = Some(replay);
            }
            ensure_tick_succeeded(outcomes)?;
        }
        Ok(())
    }

    fn activate_virtual_time(&mut self) -> Result<(), SubjectError> {
        for client in self.clients.values_mut() {
            client.enable_virtual_time_tick();
        }
        Ok(())
    }

    async fn advance_time(&mut self, delta_ms: u64) -> Result<(), SubjectError> {
        self.convergence_clock.advance_ms(delta_ms);
        self.activate_virtual_time()
    }

    fn poll_outbound(
        &mut self,
        client: &str,
    ) -> Result<Vec<SubjectOutboundArtifact>, SubjectError> {
        self.sync_client_outbound(client)?;
        Ok(self
            .outbound_records
            .values()
            .filter(|record| record.artifact.client == client && record.resolution.is_none())
            .map(|record| record.artifact.clone())
            .collect())
    }

    async fn acknowledge_outbound(
        &mut self,
        client: &str,
        outbound_id: &str,
        outcome: SubjectOutboundOutcome,
    ) -> Result<(), SubjectError> {
        self.sync_client_outbound(client)?;
        let outbound_sequence = outbound_sequence(outbound_id)?;
        let record = self
            .outbound_records
            .get(&outbound_sequence)
            .filter(|record| record.artifact.outbound_id == outbound_id)
            .cloned()
            .ok_or_else(|| {
                SubjectError::new(
                    "unknown_outbound",
                    format!("unknown outbound artifact {outbound_id}"),
                )
            })?;
        if record.artifact.client != client {
            return Err(SubjectError::new(
                "outbound_client_mismatch",
                format!("outbound artifact {outbound_id} does not belong to {client}"),
            ));
        }
        if let Some(previous) = record.resolution {
            return if previous == outcome {
                Ok(())
            } else {
                Err(SubjectError::new(
                    "outbound_already_resolved",
                    format!("outbound artifact {outbound_id} was already resolved as {previous:?}"),
                ))
            };
        }

        let pending_already_confirmed = record
            .pending
            .is_some_and(|pending| self.pending_confirmation_accepted(client, pending));

        match outcome {
            SubjectOutboundOutcome::Accepted => {
                if record.artifact.state_confirmation_required
                    && !pending_already_confirmed
                    && let Some(pending) = record.pending
                {
                    self.client_mut(client)?
                        .try_confirm(pending)
                        .await
                        .map_err(subject_engine_error)?;
                    self.pending_refs
                        .retain(|_, value| value.client != client || value.pending != pending);
                }
                if let Some((_, intent_id)) = &record.queued_intent {
                    self.client_mut(client)?
                        .confirm_regenerated_queued_intent(intent_id)
                        .map_err(subject_engine_error)?;
                    self.client_mut(client)?
                        .forget_regenerated_queued_intent(&record.artifact.message.id);
                }
                self.outbound_records
                    .get_mut(&outbound_sequence)
                    .expect("validated outbound record remains present")
                    .resolution = Some(outcome);
            }
            SubjectOutboundOutcome::ReachedNoEndpoint => {
                if record
                    .pending
                    .filter(|_| record.artifact.state_confirmation_required)
                    .is_some_and(|pending| {
                        !self.pending_confirmation_accepted(client, pending)
                            && self.pending_non_confirmation_accepted(client, pending)
                    })
                {
                    return Err(SubjectError::new(
                        "outbound_already_exposed",
                        format!(
                            "cannot report no-endpoint publication for {outbound_id} after a sibling artifact was accepted"
                        ),
                    ));
                }
                let should_roll_back_pending = record
                    .pending
                    .filter(|_| record.artifact.state_confirmation_required)
                    .is_some_and(|pending| {
                        let another_confirmation_is_unresolved =
                            self.outbound_records
                                .iter()
                                .any(|(candidate_sequence, candidate)| {
                                    *candidate_sequence != outbound_sequence
                                        && candidate.artifact.client == client
                                        && candidate.pending == Some(pending)
                                        && candidate.artifact.state_confirmation_required
                                        && candidate.resolution.is_none()
                                });
                        let confirmation_was_accepted =
                            self.pending_confirmation_accepted(client, pending);
                        !another_confirmation_is_unresolved && !confirmation_was_accepted
                    });

                if should_roll_back_pending {
                    let pending = record
                        .pending
                        .expect("rollback decision requires pending state");
                    // `try_fail` validates the complete commit/Welcome
                    // exposure set before retracting any artifact. Do not
                    // retract this one first: an exposed sibling must leave
                    // both the bus and pending state untouched.
                    self.client_mut(client)?
                        .try_fail_publication(pending)
                        .await
                        .map_err(subject_publication_error)?;
                    self.pending_refs
                        .retain(|_, value| value.client != client || value.pending != pending);
                    self.mark_pending_outbound(client, pending, outcome);
                } else {
                    self.bus
                        .retract_undelivered_publication(
                            self.client(client)?.bus_id,
                            std::slice::from_ref(&record.artifact.message.id),
                        )
                        .map_err(|delivered| {
                            SubjectError::new(
                                "outbound_already_exposed",
                                format!(
                                    "cannot report no-endpoint publication after {delivered} recipient exposure(s)"
                                ),
                            )
                    })?;
                    self.outbound_records
                        .get_mut(&outbound_sequence)
                        .expect("validated outbound record remains present")
                        .resolution = Some(outcome);
                }

                if let Some((group_id, _)) = &record.queued_intent {
                    self.client_mut(client)?
                        .retry_regenerated_queued_intent(group_id);
                    self.client_mut(client)?
                        .forget_regenerated_queued_intent(&record.artifact.message.id);
                }
            }
        }
        Ok(())
    }

    fn structural_progress(&mut self) -> Result<SubjectProgressSnapshot, SubjectError> {
        let labels = self.clients.keys().cloned().collect::<Vec<_>>();
        for label in &labels {
            self.sync_client_outbound(label)?;
            // Refresh durable message dispositions before counting scenario
            // inputs that still lack a current or terminal outcome.
            let _ = self.client_mut(label)?.scenario_input_ledger();
        }

        let clients = labels
            .iter()
            .map(|label| {
                self.client(label)?
                    .structural_progress_observation(label.clone())
                    .map_err(|error| {
                        SubjectError::new("progress_snapshot_failed", observe_engine_error(&error))
                    })
            })
            .collect::<Result<Vec<_>, SubjectError>>()?;
        let bus = self.bus.structural_progress_snapshot();
        let current_monotonic_ms = self.convergence_clock.now().monotonic_ms;
        let outbound_awaiting_acknowledgement = self
            .outbound_records
            .values()
            .filter(|record| record.resolution.is_none())
            .count();
        let runnable_engine_work = clients
            .iter()
            .filter_map(|client| client.engine.as_ref())
            .map(|engine| engine.runnable_work)
            .sum::<usize>();
        let earliest_next_wake_monotonic_ms = clients
            .iter()
            .filter_map(|client| {
                client
                    .engine
                    .as_ref()
                    .and_then(|engine| engine.earliest_next_wake_monotonic_ms)
            })
            .min();
        let deferred_retry_work = clients
            .iter()
            .filter_map(|client| client.engine.as_ref())
            .map(|engine| {
                engine
                    .pending_work
                    .stored_retryable_messages
                    .saturating_add(engine.pending_work.stored_transport_deferred_messages)
            })
            .sum();
        let scenario_inputs_pending = clients
            .iter()
            .map(|client| client.scenario_inputs_pending)
            .sum();
        let terminal_blockers = clients
            .iter()
            .filter(|client| {
                client
                    .engine
                    .as_ref()
                    .is_some_and(|engine| engine.terminal_unrecoverable)
            })
            .map(|client| SubjectTerminalBlocker::EngineUnrecoverable {
                client: client.client.clone(),
            })
            .collect();

        let mut snapshot = SubjectProgressSnapshot {
            schema_version: "1".into(),
            structural_token: String::new(),
            current_monotonic_ms,
            runnable_engine_work,
            runnable_work: runnable_engine_work
                .saturating_add(bus.queued_messages)
                .saturating_add(bus.mailbox_messages),
            earliest_next_wake_monotonic_ms,
            deferred_retry_work,
            outbound_awaiting_acknowledgement,
            transport_queued_messages: bus.queued_messages,
            transport_delayed_messages: bus.delayed_messages,
            transport_mailbox_messages: bus.mailbox_messages,
            scenario_inputs_pending,
            terminal_blockers,
            clients,
        };
        let encoded = serde_json::to_vec(&snapshot).map_err(|error| {
            SubjectError::new(
                "progress_serialization_failed",
                format!("serialize structural progress: {error}"),
            )
        })?;
        snapshot.structural_token = hex::encode(Sha256::digest(encoded));
        Ok(snapshot)
    }

    fn observe(&mut self, clients: &[String]) -> Result<Vec<ClientObservation>, SubjectError> {
        clients
            .iter()
            .map(|label| {
                let client = self.client_mut(label)?;
                Ok(observe_client(label.clone(), client))
            })
            .collect()
    }

    fn observe_exact(
        &mut self,
        clients: &[String],
    ) -> Result<Vec<ClientObservation>, SubjectError> {
        clients
            .iter()
            .map(|label| {
                let client = self.client_mut(label)?;
                Ok(observe_client_exact(label.clone(), client))
            })
            .collect()
    }

    async fn probe_bidirectional_decryptability(
        &mut self,
        labels: &[String],
        step_index: usize,
    ) -> Result<BidirectionalDecryptabilityObservation, SubjectError> {
        let mut unique_labels = labels.to_vec();
        unique_labels.sort();
        unique_labels.dedup();
        if labels.len() < 2 || unique_labels.len() != labels.len() {
            return Err(SubjectError::new(
                "invalid_probe_clients",
                "bidirectional decryptability probe requires at least two unique clients",
            ));
        }
        for label in labels {
            self.client(label)?;
        }

        let mut sends = BTreeMap::new();
        for sender in labels {
            let payload = format!("cgka-decryptability-probe/v1/{step_index}/{sender}");
            let status = match self
                .client_mut(sender)?
                .try_send_app(payload.clone().into_bytes())
                .await
            {
                Ok((status, logical_id)) => (status, Some(logical_id)),
                Err(error) => (
                    DecryptabilityProbeSendStatus::Failed {
                        error: observe_engine_error(&error),
                    },
                    None,
                ),
            };
            sends.insert(sender.clone(), (payload, status));
        }

        self.bus.deliver_all();
        let all_clients = self.clients.keys().cloned().collect::<Vec<_>>();
        self.tick(&all_clients).await?;

        let mut recipient_ledgers = BTreeMap::new();
        for recipient in labels {
            recipient_ledgers.insert(
                recipient.clone(),
                self.client_mut(recipient)?.scenario_input_ledger(),
            );
        }

        let mut probes = Vec::with_capacity(labels.len() * (labels.len() - 1));
        for sender in labels {
            let (payload, (send_status, logical_id)) = sends
                .get(sender)
                .expect("probe send result exists for every validated sender");
            for recipient in labels {
                if recipient == sender {
                    continue;
                }
                let recipient_ledger = recipient_ledgers[recipient]
                    .iter()
                    .find(|entry| entry.logical_id.as_ref() == logical_id.as_ref())
                    .cloned();
                probes.push(DirectionalDecryptabilityProbe {
                    sender: sender.clone(),
                    recipient: recipient.clone(),
                    payload: payload.clone(),
                    logical_id: logical_id.clone(),
                    send_status: send_status.clone(),
                    recipient_ledger,
                });
            }
        }

        Ok(BidirectionalDecryptabilityObservation {
            step_index,
            clients: labels.to_vec(),
            probes,
        })
    }

    fn observe_admin_policy(
        &self,
        clients: &[String],
    ) -> Result<Vec<ScenarioAdminPolicyObservation>, SubjectError> {
        clients
            .iter()
            .map(|label| {
                Ok(ScenarioAdminPolicyObservation {
                    client: label.clone(),
                    admins: self.client(label)?.admin_labels(),
                })
            })
            .collect()
    }

    fn evaluate_predicate(
        &mut self,
        predicate: &crate::ScenarioPredicateV2,
    ) -> Result<crate::ScenarioPredicateObservationV2, SubjectError> {
        use crate::ScenarioPredicateV2;
        let (matched, actual) = match predicate {
            ScenarioPredicateV2::ClientState {
                client,
                epoch,
                member_count,
            } => {
                let client_state = self.client(client)?;
                let actual_epoch = client_state.epoch().0;
                let actual_member_count = client_state.members().len();
                (
                    epoch.is_none_or(|epoch| actual_epoch == epoch)
                        && member_count.is_none_or(|count| actual_member_count == count),
                    serde_json::json!({
                        "client": client,
                        "epoch": actual_epoch,
                        "member_count": actual_member_count,
                    }),
                )
            }
            ScenarioPredicateV2::PayloadCount {
                client,
                payload,
                count,
            } => {
                let actual_count = self.client_mut(client)?.pending_payload_count(payload);
                (
                    actual_count == *count,
                    serde_json::json!({"count": actual_count}),
                )
            }
            ScenarioPredicateV2::ClientsExactlyEquivalent { clients } => {
                let states = clients
                    .iter()
                    .map(|client| {
                        self.client(client)?
                            .try_canonical_state_snapshot()
                            .map_err(|error| {
                                SubjectError::new(
                                    "exact_observation_failed",
                                    observe_engine_error(&error),
                                )
                            })
                    })
                    .collect::<Result<Vec<_>, SubjectError>>()?;
                let matched = states
                    .first()
                    .is_some_and(|first| states.iter().all(|state| state == first));
                (matched, serde_json::json!(states))
            }
            ScenarioPredicateV2::NoPendingWork { clients } => {
                let observations = clients
                    .iter()
                    .map(|client| {
                        Ok((
                            client.clone(),
                            self.client(client)?.pending_work_observation(),
                        ))
                    })
                    .collect::<Result<BTreeMap<_, _>, SubjectError>>()?;
                let matched = observations
                    .values()
                    .all(crate::PendingWorkObservation::is_empty);
                (matched, serde_json::json!(observations))
            }
        };
        Ok(crate::ScenarioPredicateObservationV2 { matched, actual })
    }

    fn clear_events(&mut self, clients: &[String]) -> Result<(), SubjectError> {
        for label in clients {
            let client = self.client_mut(label)?;
            client.drain_events();
            client.clear_audit_capture();
        }
        Ok(())
    }

    fn restart(&mut self, client: &str) -> Result<(), SubjectError> {
        self.client_mut(client)?.restart();
        Ok(())
    }

    fn fault_injection(&mut self) -> Option<&mut dyn ConvergenceFaultSubject> {
        Some(self)
    }
}

impl ConvergenceFaultSubject for EngineHarnessSubject {
    fn set_partition(&mut self, allow: &[String]) -> Result<(), SubjectError> {
        let allowed = allow
            .iter()
            .map(|label| self.client(label).map(|client| client.bus_id))
            .collect::<Result<Vec<_>, _>>()?;
        self.bus.set_partition(Some(allowed));
        Ok(())
    }

    fn clear_partition(&mut self) -> Result<(), SubjectError> {
        self.bus.set_partition(None);
        Ok(())
    }

    fn omit_message(
        &mut self,
        selector: &crate::ScenarioMessageSelectorV2,
    ) -> Result<(), SubjectError> {
        let index = self.semantic_queue_index(selector)?;
        if self.bus.drop_queued(index) {
            Ok(())
        } else {
            Err(SubjectError::new(
                "selected_message_disappeared",
                "selected message disappeared before omission",
            ))
        }
    }

    fn duplicate_message(
        &mut self,
        selector: &crate::ScenarioMessageSelectorV2,
    ) -> Result<(), SubjectError> {
        let index = self.semantic_queue_index(selector)?;
        if self.bus.duplicate_queued(index) {
            Ok(())
        } else {
            Err(SubjectError::new(
                "selected_message_disappeared",
                "selected message disappeared before duplication",
            ))
        }
    }

    fn withhold_message(
        &mut self,
        selector: &crate::ScenarioMessageSelectorV2,
        label: &str,
    ) -> Result<(), SubjectError> {
        let index = self.semantic_queue_index(selector)?;
        if self.bus.delay_queued(index, label.to_owned()) {
            Ok(())
        } else {
            Err(SubjectError::new(
                "selected_message_disappeared",
                "selected message disappeared before withholding",
            ))
        }
    }

    fn release_withheld(&mut self, label: &str) -> Result<(), SubjectError> {
        if self.bus.release_delayed(label) {
            Ok(())
        } else {
            Err(SubjectError::new(
                "unknown_withheld_messages",
                format!("withheld-message label {label} does not exist"),
            ))
        }
    }

    fn reorder_messages(
        &mut self,
        order: &[crate::ScenarioMessageSelectorV2],
    ) -> Result<(), SubjectError> {
        let indices = order
            .iter()
            .map(|selector| self.semantic_queue_index(selector))
            .collect::<Result<Vec<_>, _>>()?;
        if self.bus.reorder_queued(&indices) {
            Ok(())
        } else {
            Err(SubjectError::new(
                "invalid_semantic_queue_order",
                "semantic reorder must select every queued message exactly once",
            ))
        }
    }
}

fn required_features_from_names(names: &[String]) -> Result<Vec<Feature>, SubjectError> {
    names
        .iter()
        .map(|name| match name.as_str() {
            "self-remove" => Ok(Feature("self-remove")),
            _ => Err(SubjectError::new(
                "unknown_required_feature",
                format!("unknown required feature {name}"),
            )),
        })
        .collect()
}

/// Returns the feature registry used by the production-shaped engine harness.
///
/// Exact replay tests use this helper so their client capabilities cannot drift
/// from the clients constructed by [`EngineHarnessSubject`].
pub fn engine_harness_feature_registry() -> FeatureRegistry {
    let mut registry = FeatureRegistry::new();
    registry.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    registry
}

fn pad32(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let n = name.len().min(32);
    out[..n].copy_from_slice(&name[..n]);
    out
}

fn outbound_sequence(outbound_id: &str) -> Result<u64, SubjectError> {
    outbound_id
        .strip_prefix("outbound/")
        .and_then(|sequence| sequence.parse().ok())
        .ok_or_else(|| {
            SubjectError::new(
                "unknown_outbound",
                format!("unknown outbound artifact {outbound_id}"),
            )
        })
}

pub(crate) fn classify_engine_error(error: &EngineError) -> (SubjectFailureCategory, String) {
    let category = match error {
        EngineError::Backend(_) | EngineError::Storage(_) => SubjectFailureCategory::Resource,
        EngineError::InvalidTransition(_)
        | EngineError::Other(_)
        | EngineError::Peeler(_)
        | EngineError::ForkedEpoch { .. }
        | EngineError::UnknownPending
        | EngineError::Serialize(_) => SubjectFailureCategory::Protocol,
        EngineError::NotGroupAdmin { .. }
        | EngineError::AdminCannotSelfRemove { .. }
        | EngineError::AdminDepletion { .. }
        | EngineError::LeaveAlreadyRequested { .. }
        | EngineError::InvalidWelcome
        | EngineError::WelcomeAlreadyProcessed
        | EngineError::UnknownGroup(_)
        | EngineError::UnknownMember { .. }
        | EngineError::NotAMember { .. }
        | EngineError::MissingRequiredCapabilities { .. }
        | EngineError::DisbandingUnsupportedMembers { .. }
        | EngineError::DisbandingNotEnabled { .. }
        | EngineError::InvalidCredentialIdentity(_)
        | EngineError::InvalidAccountIdentityProof(_)
        | EngineError::InvalidKeyPackageLifetime { .. }
        | EngineError::UnsupportedCiphersuite { .. }
        | EngineError::InvalidAppMessagePayload(_) => SubjectFailureCategory::ExpectedRefusal,
    };
    (category, observe_engine_error(error))
}

fn subject_engine_error(error: EngineError) -> SubjectError {
    let (category, code) = classify_engine_error(&error);
    SubjectError::classified(category, code, error.to_string())
}

fn ensure_tick_succeeded(
    outcomes: Vec<Result<cgka_traits::ingest::IngestOutcome, EngineError>>,
) -> Result<(), SubjectError> {
    match outcomes.into_iter().find_map(Result::err) {
        Some(error) => Err(subject_engine_error(error)),
        None => Ok(()),
    }
}

fn subject_publication_error(error: HarnessPublicationError) -> SubjectError {
    match error {
        HarnessPublicationError::AlreadyExposed {
            recipient_exposures,
        } => SubjectError::new(
            "outbound_already_exposed",
            format!(
                "cannot report definite publication failure after {recipient_exposures} matching artifact(s) reached a recipient mailbox"
            ),
        ),
        HarnessPublicationError::Engine(error) => subject_engine_error(error),
    }
}

fn observe_engine_error(error: &EngineError) -> String {
    match error {
        EngineError::NotGroupAdmin { .. } => "not_group_admin",
        EngineError::AdminCannotSelfRemove { .. } | EngineError::AdminDepletion { .. } => {
            "admin_policy"
        }
        EngineError::LeaveAlreadyRequested { .. } => "leave_already_requested",
        EngineError::Serialize(_) => "invalid_admin_policy",
        EngineError::InvalidWelcome => "invalid_welcome",
        EngineError::WelcomeAlreadyProcessed => "welcome_already_processed",
        EngineError::InvalidTransition(_) => "invalid_transition",
        EngineError::UnknownGroup(_) => "unknown_group",
        EngineError::UnknownMember { .. } => "unknown_member",
        EngineError::NotAMember { .. } => "not_a_member",
        EngineError::Other(_) => "other",
        EngineError::Backend(_) => "backend",
        EngineError::Storage(_) => "storage",
        EngineError::Peeler(_) => "peeler",
        EngineError::ForkedEpoch { .. } => "forked_epoch",
        EngineError::MissingRequiredCapabilities { .. } => "missing_required_capabilities",
        EngineError::DisbandingUnsupportedMembers { .. } => "disbanding_unsupported_members",
        EngineError::DisbandingNotEnabled { .. } => "disbanding_not_enabled",
        EngineError::InvalidCredentialIdentity(_) => "invalid_credential_identity",
        EngineError::InvalidAccountIdentityProof(_) => "invalid_account_identity_proof",
        EngineError::InvalidKeyPackageLifetime { .. } => "invalid_key_package_lifetime",
        EngineError::UnsupportedCiphersuite { .. } => "unsupported_ciphersuite",
        EngineError::InvalidAppMessagePayload(_) => "invalid_app_message_payload",
        EngineError::UnknownPending => "unknown_pending",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ConformanceCanonicalStateSnapshot, QuiescenceOutboundPolicy, QuiescencePolicy,
        QuiescenceStatus, drive_subject_to_quiescence,
    };

    async fn create_current_group_and_join(
        subject: &mut EngineHarnessSubject,
        creator: &str,
        invitees: &[String],
    ) {
        subject
            .create_group(SubjectCreateGroup {
                creator,
                name: "outbound-contract",
                invitees,
                required_features: &[],
                initial_admins: &[],
                pending: "unused-current-create",
            })
            .await
            .expect("current founding group is created");
        let welcomes = subject
            .poll_outbound(creator)
            .expect("founding welcomes are pollable");
        assert_eq!(welcomes.len(), invitees.len());
        for welcome in welcomes {
            assert_eq!(welcome.kind, SubjectOutboundKind::Welcome);
            assert!(!welcome.state_confirmation_required);
            subject
                .acknowledge_outbound(
                    creator,
                    &welcome.outbound_id,
                    SubjectOutboundOutcome::Accepted,
                )
                .await
                .expect("founding welcome publication is accepted");
        }
        subject.deliver_all().expect("deliver founding welcomes");
        subject
            .tick(invitees)
            .await
            .expect("invitees ingest founding welcomes");
    }

    #[test]
    fn engine_subject_tick_surfaces_engine_failures() {
        let error = ensure_tick_succeeded(vec![Err(EngineError::Backend(
            "converge buffered group: injected failure".into(),
        ))])
        .expect_err("tick must not discard the engine failure");
        assert_eq!(error.code, "backend");
        assert_eq!(error.category, SubjectFailureCategory::Resource);
        assert!(error.message.contains("converge buffered group"));
    }

    #[test]
    fn serialization_failures_are_not_classified_as_expected_refusals() {
        let (category, code) =
            classify_engine_error(&EngineError::Serialize("malformed internal state".into()));
        assert_eq!(category, SubjectFailureCategory::Protocol);
        assert_eq!(code, "invalid_admin_policy");
    }

    #[tokio::test]
    async fn outbound_poll_is_non_destructive_and_acknowledgement_is_idempotent() {
        let labels = vec!["alice".to_owned(), "bob".to_owned()];
        let mut subject = EngineHarnessSubject::new(
            &labels,
            ProtocolProfile::Current,
            HarnessStorageMode::InMemorySqlite,
        )
        .expect("engine subject constructs");
        assert!(
            subject
                .descriptor()
                .supports(SubjectCapability::OutboundPublication)
        );
        create_current_group_and_join(&mut subject, "alice", &labels[1..]).await;

        subject
            .send_application(SubjectSendApplication {
                action_id: "app-1",
                sender: "alice",
                payload: "hello",
            })
            .await
            .expect("application send succeeds");
        let first = subject
            .poll_outbound("alice")
            .expect("application publication is pollable");
        let second = subject
            .poll_outbound("alice")
            .expect("polling is non-destructive");
        assert_eq!(first, second);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].kind, SubjectOutboundKind::GroupMessage);
        assert!(!first[0].state_confirmation_required);

        subject
            .acknowledge_outbound(
                "alice",
                &first[0].outbound_id,
                SubjectOutboundOutcome::Accepted,
            )
            .await
            .expect("application publication is accepted");
        subject
            .acknowledge_outbound(
                "alice",
                &first[0].outbound_id,
                SubjectOutboundOutcome::Accepted,
            )
            .await
            .expect("same acknowledgement is idempotent");
        let contradiction = subject
            .acknowledge_outbound(
                "alice",
                &first[0].outbound_id,
                SubjectOutboundOutcome::ReachedNoEndpoint,
            )
            .await
            .expect_err("contradictory acknowledgement is rejected");
        assert_eq!(contradiction.code, "outbound_already_resolved");
        assert!(
            subject
                .poll_outbound("alice")
                .expect("resolved publication is absent")
                .is_empty()
        );

        subject.deliver_all().expect("deliver application message");
        subject
            .tick(&["bob".to_owned()])
            .await
            .expect("bob ingests application message");
        assert_eq!(
            subject
                .client_mut("bob")
                .expect("bob exists")
                .received_app_payloads(),
            vec![b"hello".to_vec()]
        );
    }

    #[tokio::test]
    async fn outbound_poll_preserves_emission_order_past_single_digit_handles() {
        let labels = vec!["alice".to_owned(), "bob".to_owned()];
        let mut subject = EngineHarnessSubject::new(
            &labels,
            ProtocolProfile::Current,
            HarnessStorageMode::InMemorySqlite,
        )
        .expect("engine subject constructs");
        create_current_group_and_join(&mut subject, "alice", &labels[1..]).await;

        for index in 0..12 {
            subject
                .send_application(SubjectSendApplication {
                    action_id: &format!("app-{index}"),
                    sender: "alice",
                    payload: &format!("payload-{index}"),
                })
                .await
                .expect("application send succeeds");
        }

        let outbound = subject
            .poll_outbound("alice")
            .expect("application publications are pollable");
        let sequences = outbound
            .iter()
            .map(|artifact| {
                outbound_sequence(&artifact.outbound_id)
                    .expect("polled artifact has a numeric adapter handle")
            })
            .collect::<Vec<_>>();
        assert_eq!(sequences, (1..=12).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn pending_publication_identity_is_scoped_by_client() {
        let labels = vec!["alice".to_owned(), "bob".to_owned()];
        let mut subject = EngineHarnessSubject::new(
            &labels,
            ProtocolProfile::Legacy,
            HarnessStorageMode::InMemorySqlite,
        )
        .expect("engine subject constructs");
        for label in &labels {
            subject
                .create_group(SubjectCreateGroup {
                    creator: label,
                    name: "independent-group",
                    invitees: &[],
                    required_features: &[],
                    initial_admins: &[],
                    pending: "unused-empty-create",
                })
                .await
                .expect("independent legacy group is created");
        }

        for (client, pending, name) in [
            ("alice", "alice-first", "alice-first-name"),
            ("bob", "bob-first", "bob-first-name"),
        ] {
            subject
                .update_group_data(SubjectUpdateGroupData {
                    action_id: pending,
                    client,
                    name,
                    pending,
                })
                .await
                .expect("group-data update produces pending publication");
        }
        assert_eq!(
            subject.pending_refs["alice-first"].pending, subject.pending_refs["bob-first"].pending,
            "the regression requires equal per-engine pending counters"
        );
        let alice_first = subject
            .poll_outbound("alice")
            .expect("alice publication is pollable")
            .pop()
            .expect("alice commit exists");
        let bob_first = subject
            .poll_outbound("bob")
            .expect("bob publication is pollable")
            .pop()
            .expect("bob commit exists");
        subject
            .acknowledge_outbound(
                "bob",
                &bob_first.outbound_id,
                SubjectOutboundOutcome::Accepted,
            )
            .await
            .expect("bob confirms only bob's staged state");
        subject
            .acknowledge_outbound(
                "alice",
                &alice_first.outbound_id,
                SubjectOutboundOutcome::Accepted,
            )
            .await
            .expect("bob's equal pending counter cannot suppress alice confirmation");
        assert_eq!(
            subject.client("alice").expect("alice exists").group_name(),
            "alice-first-name"
        );
        assert_eq!(
            subject.client("bob").expect("bob exists").group_name(),
            "bob-first-name"
        );

        for (client, pending, name) in [
            ("alice", "alice-second", "alice-rolled-back-name"),
            ("bob", "bob-second", "bob-second-name"),
        ] {
            subject
                .update_group_data(SubjectUpdateGroupData {
                    action_id: pending,
                    client,
                    name,
                    pending,
                })
                .await
                .expect("second group-data update produces pending publication");
        }
        assert_eq!(
            subject.pending_refs["alice-second"].pending,
            subject.pending_refs["bob-second"].pending,
            "the rollback regression also requires colliding pending counters"
        );
        let alice_second = subject
            .poll_outbound("alice")
            .expect("alice second publication is pollable")
            .pop()
            .expect("alice second commit exists");
        let bob_second = subject
            .poll_outbound("bob")
            .expect("bob second publication is pollable")
            .pop()
            .expect("bob second commit exists");
        subject
            .acknowledge_outbound(
                "alice",
                &alice_second.outbound_id,
                SubjectOutboundOutcome::ReachedNoEndpoint,
            )
            .await
            .expect("alice rolls back only alice's staged state");
        assert_eq!(
            subject
                .poll_outbound("bob")
                .expect("bob publication remains unresolved"),
            vec![bob_second.clone()]
        );
        subject
            .acknowledge_outbound(
                "bob",
                &bob_second.outbound_id,
                SubjectOutboundOutcome::Accepted,
            )
            .await
            .expect("bob publication remains acknowledgeable");
        assert_eq!(
            subject.client("alice").expect("alice exists").group_name(),
            "alice-first-name"
        );
        assert_eq!(
            subject.client("bob").expect("bob exists").group_name(),
            "bob-second-name"
        );
        assert!(subject.pending_refs.is_empty());
    }

    #[tokio::test]
    async fn evolution_commit_acknowledgement_and_welcome_outcome_are_independent() {
        let labels = vec!["alice".to_owned(), "bob".to_owned(), "carol".to_owned()];
        let mut subject = EngineHarnessSubject::new(
            &labels,
            ProtocolProfile::Current,
            HarnessStorageMode::InMemorySqlite,
        )
        .expect("engine subject constructs");
        create_current_group_and_join(&mut subject, "alice", &labels[1..2]).await;
        let prior_epoch = subject.client("alice").expect("alice exists").epoch().0;

        subject
            .invite_members(SubjectInviteMembers {
                action_id: "invite-carol",
                inviter: "alice",
                invitees: &labels[2..],
                pending: "invite-carol-pending",
            })
            .await
            .expect("invite produces outbound work");
        let outbound = subject
            .poll_outbound("alice")
            .expect("invite artifacts are pollable");
        assert_eq!(outbound.len(), 2);
        let commit = outbound
            .iter()
            .find(|artifact| artifact.state_confirmation_required)
            .expect("commit requires state confirmation");
        let welcome = outbound
            .iter()
            .find(|artifact| artifact.kind == SubjectOutboundKind::Welcome)
            .expect("welcome is an independent obligation");
        assert!(!welcome.state_confirmation_required);

        subject
            .acknowledge_outbound(
                "alice",
                &commit.outbound_id,
                SubjectOutboundOutcome::Accepted,
            )
            .await
            .expect("accepted commit confirms local state");
        assert_eq!(
            subject.client("alice").expect("alice exists").epoch().0,
            prior_epoch + 1
        );
        assert_eq!(
            subject
                .poll_outbound("alice")
                .expect("welcome remains independently pending"),
            vec![welcome.clone()]
        );

        subject
            .acknowledge_outbound(
                "alice",
                &welcome.outbound_id,
                SubjectOutboundOutcome::ReachedNoEndpoint,
            )
            .await
            .expect("failed welcome does not roll back an accepted commit");
        assert_eq!(
            subject.client("alice").expect("alice exists").epoch().0,
            prior_epoch + 1
        );
        assert!(
            subject
                .poll_outbound("alice")
                .expect("both obligations are resolved")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn accepted_welcome_blocks_later_definite_commit_failure() {
        let labels = vec!["alice".to_owned(), "bob".to_owned(), "carol".to_owned()];
        let mut subject = EngineHarnessSubject::new(
            &labels,
            ProtocolProfile::Current,
            HarnessStorageMode::InMemorySqlite,
        )
        .expect("engine subject constructs");
        create_current_group_and_join(&mut subject, "alice", &labels[1..2]).await;

        subject
            .invite_members(SubjectInviteMembers {
                action_id: "invite-carol",
                inviter: "alice",
                invitees: &labels[2..],
                pending: "invite-carol-pending",
            })
            .await
            .expect("invite produces outbound work");
        let outbound = subject
            .poll_outbound("alice")
            .expect("invite artifacts are pollable");
        let commit = outbound
            .iter()
            .find(|artifact| artifact.state_confirmation_required)
            .expect("commit requires state confirmation")
            .clone();
        let welcome = outbound
            .iter()
            .find(|artifact| artifact.kind == SubjectOutboundKind::Welcome)
            .expect("invite produces a Welcome")
            .clone();
        let pending_snapshot = subject
            .client("alice")
            .expect("alice exists")
            .canonical_state_snapshot();

        subject
            .acknowledge_outbound(
                "alice",
                &welcome.outbound_id,
                SubjectOutboundOutcome::Accepted,
            )
            .await
            .expect("Welcome publication is accepted independently");
        let failure = subject
            .acknowledge_outbound(
                "alice",
                &commit.outbound_id,
                SubjectOutboundOutcome::ReachedNoEndpoint,
            )
            .await
            .expect_err("accepted sibling prevents definite publication rollback");
        assert_eq!(failure.code, "outbound_already_exposed");
        assert_eq!(
            subject
                .poll_outbound("alice")
                .expect("commit remains unresolved"),
            vec![commit.clone()]
        );
        assert_eq!(
            subject
                .client("alice")
                .expect("alice exists")
                .canonical_state_snapshot(),
            pending_snapshot
        );
        subject
            .acknowledge_outbound(
                "alice",
                &commit.outbound_id,
                SubjectOutboundOutcome::Accepted,
            )
            .await
            .expect("commit remains acceptably acknowledgeable");
        subject
            .acknowledge_outbound(
                "alice",
                &welcome.outbound_id,
                SubjectOutboundOutcome::Accepted,
            )
            .await
            .expect("the accepted Welcome outcome remains idempotent");
    }

    #[tokio::test]
    async fn no_endpoint_commit_outcome_rolls_back_the_complete_unexposed_publication() {
        let labels = vec!["alice".to_owned(), "bob".to_owned(), "carol".to_owned()];
        let mut subject = EngineHarnessSubject::new(
            &labels,
            ProtocolProfile::Current,
            HarnessStorageMode::InMemorySqlite,
        )
        .expect("engine subject constructs");
        create_current_group_and_join(&mut subject, "alice", &labels[1..2]).await;
        let prior_epoch = subject.client("alice").expect("alice exists").epoch().0;

        subject
            .invite_members(SubjectInviteMembers {
                action_id: "invite-carol",
                inviter: "alice",
                invitees: &labels[2..],
                pending: "invite-carol-pending",
            })
            .await
            .expect("invite produces outbound work");
        let outbound = subject
            .poll_outbound("alice")
            .expect("invite artifacts are pollable");
        let commit = outbound
            .iter()
            .find(|artifact| artifact.state_confirmation_required)
            .expect("commit requires state confirmation");

        subject
            .acknowledge_outbound(
                "alice",
                &commit.outbound_id,
                SubjectOutboundOutcome::ReachedNoEndpoint,
            )
            .await
            .expect("unexposed commit failure rolls back");
        assert_eq!(
            subject.client("alice").expect("alice exists").epoch().0,
            prior_epoch
        );
        assert!(
            subject
                .poll_outbound("alice")
                .expect("rollback resolves the complete publication")
                .is_empty()
        );

        subject
            .deliver_all()
            .expect("rolled-back artifacts are absent from the bus");
        subject
            .tick(&["bob".to_owned(), "carol".to_owned()])
            .await
            .expect("no rolled-back artifact is ingested");
    }

    #[tokio::test]
    async fn exposed_welcome_prevents_partial_commit_retraction_and_rollback() {
        let labels = vec!["alice".to_owned(), "bob".to_owned(), "carol".to_owned()];
        let mut subject = EngineHarnessSubject::new(
            &labels,
            ProtocolProfile::Current,
            HarnessStorageMode::InMemorySqlite,
        )
        .expect("engine subject constructs");
        create_current_group_and_join(&mut subject, "alice", &labels[1..2]).await;
        subject
            .invite_members(SubjectInviteMembers {
                action_id: "invite-carol",
                inviter: "alice",
                invitees: &labels[2..],
                pending: "invite-carol-pending",
            })
            .await
            .expect("invite produces outbound work");
        let outbound = subject
            .poll_outbound("alice")
            .expect("invite artifacts are pollable");
        let commit = outbound
            .iter()
            .find(|artifact| artifact.state_confirmation_required)
            .expect("commit requires state confirmation");
        let pending_snapshot = subject
            .client("alice")
            .expect("alice exists")
            .canonical_state_snapshot();
        subject
            .deliver_all()
            .expect("commit and welcome reach recipient mailboxes");

        let error = subject
            .acknowledge_outbound(
                "alice",
                &commit.outbound_id,
                SubjectOutboundOutcome::ReachedNoEndpoint,
            )
            .await
            .expect_err("exposed sibling prevents definite rollback");
        assert_eq!(error.code, "outbound_already_exposed");
        assert_eq!(
            subject
                .poll_outbound("alice")
                .expect("failed rollback leaves every obligation pending"),
            outbound
        );
        assert_eq!(
            subject
                .client("alice")
                .expect("alice exists")
                .canonical_state_snapshot(),
            pending_snapshot
        );
    }

    #[tokio::test]
    async fn no_endpoint_outcome_is_rejected_after_recipient_exposure() {
        let labels = vec!["alice".to_owned(), "bob".to_owned()];
        let mut subject = EngineHarnessSubject::new(
            &labels,
            ProtocolProfile::Current,
            HarnessStorageMode::InMemorySqlite,
        )
        .expect("engine subject constructs");
        subject
            .create_group(SubjectCreateGroup {
                creator: "alice",
                name: "exposed-welcome",
                invitees: &labels[1..],
                required_features: &[],
                initial_admins: &[],
                pending: "unused-current-create",
            })
            .await
            .expect("current founding group is created");
        let welcome = subject
            .poll_outbound("alice")
            .expect("welcome is pollable")
            .pop()
            .expect("welcome exists");
        subject.deliver_all().expect("expose welcome to bob");
        let error = subject
            .acknowledge_outbound(
                "alice",
                &welcome.outbound_id,
                SubjectOutboundOutcome::ReachedNoEndpoint,
            )
            .await
            .expect_err("exposed artifact cannot be declared unpublished");
        assert_eq!(error.code, "outbound_already_exposed");
        assert_eq!(
            subject
                .poll_outbound("alice")
                .expect("failed acknowledgement leaves work pending"),
            vec![welcome]
        );
    }

    #[tokio::test]
    async fn empty_creation_confirms_without_synthetic_outbound_work() {
        let labels = vec!["alice".to_owned()];
        let mut subject = EngineHarnessSubject::new(
            &labels,
            ProtocolProfile::Legacy,
            HarnessStorageMode::InMemorySqlite,
        )
        .expect("engine subject constructs");

        subject
            .create_group(SubjectCreateGroup {
                creator: "alice",
                name: "empty-group",
                invitees: &[],
                required_features: &[],
                initial_admins: &[],
                pending: "no-publication-needed",
            })
            .await
            .expect("empty legacy group is created");

        assert!(
            subject
                .poll_outbound("alice")
                .expect("no synthetic artifact is invented")
                .is_empty()
        );
        assert!(
            subject
                .client("alice")
                .expect("alice exists")
                .pending_work_observation()
                .engine
                .is_empty(),
            "a no-op publication must not strand pending MLS state"
        );
    }

    #[tokio::test]
    async fn create_confirms_on_first_welcome_acceptance_and_keeps_other_welcomes_independent() {
        let labels = vec!["alice".to_owned(), "bob".to_owned(), "carol".to_owned()];
        let mut subject = EngineHarnessSubject::new(
            &labels,
            ProtocolProfile::Legacy,
            HarnessStorageMode::InMemorySqlite,
        )
        .expect("engine subject constructs");
        subject
            .create_group(SubjectCreateGroup {
                creator: "alice",
                name: "explicit-create",
                invitees: &labels[1..],
                required_features: &[],
                initial_admins: &[],
                pending: "create-pending",
            })
            .await
            .expect("create produces welcomes");
        let outbound = subject
            .poll_outbound("alice")
            .expect("welcomes are pollable");
        assert_eq!(outbound.len(), 2);
        assert!(
            outbound
                .iter()
                .all(|artifact| artifact.state_confirmation_required)
        );

        subject
            .acknowledge_outbound(
                "alice",
                &outbound[0].outbound_id,
                SubjectOutboundOutcome::Accepted,
            )
            .await
            .expect("first exposed legacy welcome confirms creation");
        assert_eq!(
            subject
                .poll_outbound("alice")
                .expect("second welcome remains pending"),
            vec![outbound[1].clone()]
        );
        subject
            .acknowledge_outbound(
                "alice",
                &outbound[1].outbound_id,
                SubjectOutboundOutcome::ReachedNoEndpoint,
            )
            .await
            .expect("later welcome failure cannot roll back confirmed creation");
        assert!(
            subject
                .poll_outbound("alice")
                .expect("legacy obligations are resolved")
                .is_empty()
        );
        assert_eq!(subject.client("alice").expect("alice exists").epoch().0, 1);
    }

    #[tokio::test]
    async fn scheduled_group_evolution_waits_for_public_outbound_acknowledgement() {
        let labels = vec!["alice".to_owned()];
        let mut subject = EngineHarnessSubject::new(
            &labels,
            ProtocolProfile::Current,
            HarnessStorageMode::InMemorySqlite,
        )
        .expect("engine subject constructs");
        create_current_group_and_join(&mut subject, "alice", &[]).await;
        let prior_epoch = subject.client("alice").expect("alice exists").epoch().0;

        let alice = subject.client_mut("alice").expect("alice exists");
        alice.request_disband().await.expect("request disband");
        alice
            .advance_convergence()
            .await
            .expect("scheduled convergence emits terminal commit");
        assert!(matches!(
            subject
                .client("alice")
                .expect("alice exists")
                .canonical_state_snapshot(),
            ConformanceCanonicalStateSnapshot::Live(_)
        ));

        let outbound = subject
            .poll_outbound("alice")
            .expect("scheduled commit is pollable");
        assert_eq!(outbound.len(), 1);
        assert!(outbound[0].state_confirmation_required);
        subject
            .acknowledge_outbound(
                "alice",
                &outbound[0].outbound_id,
                SubjectOutboundOutcome::Accepted,
            )
            .await
            .expect("scheduled commit acknowledgement applies the evolution");
        assert_eq!(
            subject.client("alice").expect("alice exists").epoch().0,
            prior_epoch + 1
        );
    }

    #[tokio::test]
    async fn regenerated_queued_intent_retries_then_retires_through_outbound_acknowledgement() {
        let labels = vec![
            "alice".to_owned(),
            "bob".to_owned(),
            "carol".to_owned(),
            "david".to_owned(),
        ];
        let mut subject = EngineHarnessSubject::new(
            &labels,
            ProtocolProfile::Current,
            HarnessStorageMode::InMemorySqlite,
        )
        .expect("engine subject constructs");
        create_current_group_and_join(&mut subject, "alice", &labels[1..3]).await;

        subject
            .invite_members(SubjectInviteMembers {
                action_id: "invite-david",
                inviter: "alice",
                invitees: &labels[3..],
                pending: "invite-david-pending",
            })
            .await
            .expect("invite produces outbound work");
        let invite_commit = subject
            .poll_outbound("alice")
            .expect("invite publication is pollable")
            .into_iter()
            .find(|artifact| artifact.state_confirmation_required)
            .expect("invite commit requires confirmation");
        subject
            .acknowledge_outbound(
                "alice",
                &invite_commit.outbound_id,
                SubjectOutboundOutcome::Accepted,
            )
            .await
            .expect("invite commit publication is accepted");
        subject.deliver_all().expect("deliver invite artifacts");
        let ingest = subject
            .client_mut("carol")
            .expect("carol exists")
            .tick_ingest_only()
            .await;
        assert!(
            ingest.iter().any(|outcome| matches!(
                outcome,
                Ok(cgka_traits::ingest::IngestOutcome::Buffered { .. })
            )),
            "carol must buffer the invite commit before attempting an app send: {ingest:?}"
        );
        subject
            .send_application(SubjectSendApplication {
                action_id: "queued-app",
                sender: "carol",
                payload: "queued while convergence is live",
            })
            .await
            .expect("application intent is queued");
        assert!(
            subject
                .poll_outbound("carol")
                .expect("queued application has not emitted yet")
                .is_empty()
        );
        subject
            .advance_time(1_000)
            .await
            .expect("advance through the pinned settlement window");

        subject
            .client_mut("carol")
            .expect("carol exists")
            .advance_convergence()
            .await
            .expect("carol settles and regenerates queued application");
        let first = subject
            .poll_outbound("carol")
            .expect("regenerated application is pollable");
        assert_eq!(first.len(), 1);
        assert!(first[0].regenerated_queued_intent);
        subject
            .acknowledge_outbound(
                "carol",
                &first[0].outbound_id,
                SubjectOutboundOutcome::ReachedNoEndpoint,
            )
            .await
            .expect("definite failure re-arms the queued intent");

        subject
            .client_mut("carol")
            .expect("carol exists")
            .advance_convergence()
            .await
            .expect("carol retries the queued application");
        let retry = subject
            .poll_outbound("carol")
            .expect("retried application is pollable");
        assert_eq!(retry.len(), 1);
        assert!(retry[0].regenerated_queued_intent);
        assert_ne!(retry[0].outbound_id, first[0].outbound_id);
        subject
            .acknowledge_outbound(
                "carol",
                &retry[0].outbound_id,
                SubjectOutboundOutcome::Accepted,
            )
            .await
            .expect("accepted retry retires the queued intent");
        subject
            .client_mut("carol")
            .expect("carol exists")
            .advance_convergence()
            .await
            .expect("no queued retry remains");
        assert!(
            subject
                .poll_outbound("carol")
                .expect("retired queued intent stays absent")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn engine_subject_virtual_time_is_shared_while_participant_wakes_are_selected() {
        let labels = vec!["alice".to_owned(), "bob".to_owned()];
        let mut subject = EngineHarnessSubject::new(
            &labels,
            ProtocolProfile::Current,
            HarnessStorageMode::InMemorySqlite,
        )
        .expect("engine subject constructs");
        assert!(
            subject
                .descriptor()
                .supports(SubjectCapability::VirtualTime)
        );

        for label in &labels {
            subject
                .create_group(SubjectCreateGroup {
                    creator: label,
                    name: "virtual-time",
                    invitees: &[],
                    required_features: &[],
                    initial_admins: &[],
                    pending: "unused",
                })
                .await
                .expect("founding group is created");
            let client = subject.client_mut(label).expect("client exists");
            client.request_disband().await.expect("request disband");
            client
                .advance_convergence()
                .await
                .expect("prepare disband commit");
            let outbound = subject
                .poll_outbound(label)
                .expect("disband commit is pollable");
            assert!(!outbound.is_empty(), "disband emits outbound work");
            for artifact in outbound {
                subject
                    .acknowledge_outbound(
                        label,
                        &artifact.outbound_id,
                        SubjectOutboundOutcome::Accepted,
                    )
                    .await
                    .expect("accept disband publication");
            }
            subject
                .client_mut(label)
                .expect("client exists")
                .advance_convergence()
                .await
                .expect("open collecting pass");
        }

        subject
            .advance_time(999)
            .await
            .expect("advance before cutoff");
        subject
            .tick(&["alice".to_owned()])
            .await
            .expect("wake alice before cutoff");
        for label in &labels {
            assert!(matches!(
                subject
                    .client(label)
                    .expect("client exists")
                    .canonical_state_snapshot(),
                ConformanceCanonicalStateSnapshot::Live(_)
            ));
        }

        subject.advance_time(1).await.expect("advance to cutoff");
        subject
            .tick(&["alice".to_owned()])
            .await
            .expect("wake alice at cutoff");
        assert!(matches!(
            subject
                .client("alice")
                .expect("alice exists")
                .canonical_state_snapshot(),
            ConformanceCanonicalStateSnapshot::Disbanded(_)
        ));
        assert!(matches!(
            subject
                .client("bob")
                .expect("bob exists")
                .canonical_state_snapshot(),
            ConformanceCanonicalStateSnapshot::Live(_)
        ));

        subject
            .tick(&["bob".to_owned()])
            .await
            .expect("wake bob without advancing time again");
        assert!(matches!(
            subject
                .client("bob")
                .expect("bob exists")
                .canonical_state_snapshot(),
            ConformanceCanonicalStateSnapshot::Disbanded(_)
        ));
    }

    #[tokio::test]
    async fn structural_progress_is_stable_sanitized_and_names_publication_work() {
        let labels = vec!["alice".to_owned(), "bob".to_owned()];
        let mut subject = EngineHarnessSubject::new(
            &labels,
            ProtocolProfile::Current,
            HarnessStorageMode::InMemorySqlite,
        )
        .expect("engine subject constructs");
        create_current_group_and_join(&mut subject, "alice", &labels[1..]).await;

        let settled = subject.structural_progress().expect("progress snapshot");
        assert!(settled.is_quiescent(), "settled snapshot: {settled:#?}");
        assert_eq!(
            settled.structural_token,
            subject
                .structural_progress()
                .expect("repeat progress snapshot")
                .structural_token,
            "unchanged structure must have a stable token"
        );

        subject
            .send_application(SubjectSendApplication {
                action_id: "structural-app",
                sender: "alice",
                payload: "pending publication",
            })
            .await
            .expect("application emits outbound work");
        let pending = subject.structural_progress().expect("pending progress");
        assert_ne!(pending.structural_token, settled.structural_token);
        assert_eq!(pending.outbound_awaiting_acknowledgement, 1);
        assert_eq!(pending.transport_queued_messages, 1);

        let encoded = serde_json::to_string(&pending).expect("progress serializes");
        for forbidden in [
            "group_id",
            "message_id",
            "account_id",
            "payload",
            "ciphertext",
            "pubkey",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "progress leaked forbidden field name {forbidden}: {encoded}"
            );
        }
    }

    #[tokio::test]
    async fn fixed_point_reports_manual_ack_blocker_then_settles() {
        let labels = vec!["alice".to_owned(), "bob".to_owned()];
        let mut subject = EngineHarnessSubject::new(
            &labels,
            ProtocolProfile::Current,
            HarnessStorageMode::InMemorySqlite,
        )
        .expect("engine subject constructs");
        create_current_group_and_join(&mut subject, "alice", &labels[1..]).await;
        subject
            .send_application(SubjectSendApplication {
                action_id: "manual-ack-app",
                sender: "alice",
                payload: "manual ack",
            })
            .await
            .expect("application emits outbound work");

        let blocked = drive_subject_to_quiescence(
            &mut subject,
            &labels,
            &QuiescencePolicy {
                outbound: QuiescenceOutboundPolicy::Manual,
                ..QuiescencePolicy::default()
            },
            7,
        )
        .await
        .expect("manual fixed point reports a terminal observation");
        assert!(matches!(blocked.status, QuiescenceStatus::Blocked { .. }));
        assert!(
            blocked
                .final_progress
                .blocking_subsystems()
                .contains(&"outbound_acknowledgement")
        );

        let settled =
            drive_subject_to_quiescence(&mut subject, &labels, &QuiescencePolicy::default(), 8)
                .await
                .expect("automatic publication and delivery settle");
        assert_eq!(settled.status, QuiescenceStatus::Quiescent);
        assert!(settled.final_progress.is_quiescent());
    }

    #[tokio::test]
    async fn fixed_point_advances_exactly_to_engine_wake() {
        let labels = vec!["alice".to_owned()];
        let mut subject = EngineHarnessSubject::new(
            &labels,
            ProtocolProfile::Current,
            HarnessStorageMode::InMemorySqlite,
        )
        .expect("engine subject constructs");
        create_current_group_and_join(&mut subject, "alice", &[]).await;
        let alice = subject.client_mut("alice").expect("alice exists");
        alice.request_disband().await.expect("request disband");
        alice
            .advance_convergence()
            .await
            .expect("prepare disband commit");
        for artifact in subject
            .poll_outbound("alice")
            .expect("disband publication is pollable")
        {
            subject
                .acknowledge_outbound(
                    "alice",
                    &artifact.outbound_id,
                    SubjectOutboundOutcome::Accepted,
                )
                .await
                .expect("accept disband publication");
        }
        subject
            .client_mut("alice")
            .expect("alice exists")
            .advance_convergence()
            .await
            .expect("open collecting pass");

        let before = subject.structural_progress().expect("scheduled progress");
        assert_eq!(before.earliest_next_wake_monotonic_ms, Some(1_000));
        let settled =
            drive_subject_to_quiescence(&mut subject, &labels, &QuiescencePolicy::default(), 9)
                .await
                .expect("fixed point settles disband");
        assert_eq!(settled.status, QuiescenceStatus::Quiescent);
        assert_eq!(
            settled.virtual_time_advanced_ms, 1_000,
            "before={before:#?}; settled={settled:#?}"
        );
        assert!(matches!(
            subject
                .client("alice")
                .expect("alice exists")
                .canonical_state_snapshot(),
            ConformanceCanonicalStateSnapshot::Disbanded(_)
        ));
    }

    #[tokio::test]
    async fn structural_wake_rebases_across_restart_without_granting_fresh_time() {
        let labels = vec!["alice".to_owned()];
        let mut subject = EngineHarnessSubject::new(
            &labels,
            ProtocolProfile::Current,
            HarnessStorageMode::TempFileBackedSqlite,
        )
        .expect("file-backed engine subject constructs");
        create_current_group_and_join(&mut subject, "alice", &[]).await;
        let alice = subject.client_mut("alice").expect("alice exists");
        alice.request_disband().await.expect("request disband");
        alice
            .advance_convergence()
            .await
            .expect("prepare disband commit");
        for artifact in subject
            .poll_outbound("alice")
            .expect("disband publication is pollable")
        {
            subject
                .acknowledge_outbound(
                    "alice",
                    &artifact.outbound_id,
                    SubjectOutboundOutcome::Accepted,
                )
                .await
                .expect("accept disband publication");
        }
        subject
            .client_mut("alice")
            .expect("alice exists")
            .advance_convergence()
            .await
            .expect("open collecting pass");
        subject
            .advance_time(400)
            .await
            .expect("advance partway to cutoff");
        subject
            .restart("alice")
            .expect("restart file-backed client");

        let restarted = subject.structural_progress().expect("restarted progress");
        assert_eq!(restarted.current_monotonic_ms, 400);
        assert_eq!(restarted.earliest_next_wake_monotonic_ms, Some(1_000));
        let settled =
            drive_subject_to_quiescence(&mut subject, &labels, &QuiescencePolicy::default(), 10)
                .await
                .expect("restarted fixed point settles");
        assert_eq!(settled.status, QuiescenceStatus::Quiescent);
        assert_eq!(settled.virtual_time_advanced_ms, 600);
    }

    #[tokio::test]
    async fn fixed_point_names_withheld_transport_without_spinning() {
        let labels = vec!["alice".to_owned(), "bob".to_owned()];
        let mut subject = EngineHarnessSubject::new(
            &labels,
            ProtocolProfile::Current,
            HarnessStorageMode::InMemorySqlite,
        )
        .expect("engine subject constructs");
        create_current_group_and_join(&mut subject, "alice", &labels[1..]).await;
        subject
            .send_application(SubjectSendApplication {
                action_id: "withheld-app",
                sender: "alice",
                payload: "withheld",
            })
            .await
            .expect("application emits outbound work");
        for artifact in subject
            .poll_outbound("alice")
            .expect("application is pollable")
        {
            subject
                .acknowledge_outbound(
                    "alice",
                    &artifact.outbound_id,
                    SubjectOutboundOutcome::Accepted,
                )
                .await
                .expect("transport accepted the application");
        }
        subject
            .withhold_message(
                &crate::ScenarioMessageSelectorV2 {
                    action_id: Some("withheld-app".into()),
                    class: Some(crate::ScenarioTransportClass::Application),
                    ..Default::default()
                },
                "withheld",
            )
            .expect("withhold application");

        let blocked =
            drive_subject_to_quiescence(&mut subject, &labels, &QuiescencePolicy::default(), 10)
                .await
                .expect("withheld transport produces an observation");
        assert_eq!(blocked.iterations, 0);
        assert!(matches!(blocked.status, QuiescenceStatus::Blocked { .. }));
        assert!(
            blocked
                .final_progress
                .blocking_subsystems()
                .contains(&"transport_delayed")
        );
    }
}
