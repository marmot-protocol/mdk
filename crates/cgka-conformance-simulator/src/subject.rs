//! Adapter boundary between scenario semantics and a convergence implementation.
//!
//! The scenario runner owns step ordering, stable action ids, and report
//! construction. A [`ConvergenceSubject`] implements semantic operations using
//! only the public behavior available at its layer. Harness-only transport
//! mutation is exposed separately through [`ConvergenceFaultSubject`].

use crate::{
    BidirectionalDecryptabilityObservation, ClientBuilder, ClientObservation,
    DecryptabilityProbeSendStatus, DirectionalDecryptabilityProbe, HarnessClient,
    HarnessStorageMode, ScenarioAdminPolicyObservation, ScenarioStep, TransportBus, observe_client,
    observe_client_exact,
};
use async_trait::async_trait;
use cgka_engine::ManualConvergenceClock;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::EngineError;
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::KeyPackage;
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::types::MemberId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::Arc;

/// A semantic or explicitly white-box operation an adapter can execute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectCapability {
    GroupMutation,
    PublicationLifecycle,
    ApplicationMessaging,
    TransportDelivery,
    EventObservation,
    ExactConformanceObservation,
    ActiveDecryptabilityProbe,
    AdminPolicyObservation,
    CrashReopen,
    VirtualTime,
    WhiteBoxTransportQueueFaults,
    WhiteBoxTransportPartition,
    WhiteBoxStorageFaults,
}

impl SubjectCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GroupMutation => "group_mutation",
            Self::PublicationLifecycle => "publication_lifecycle",
            Self::ApplicationMessaging => "application_messaging",
            Self::TransportDelivery => "transport_delivery",
            Self::EventObservation => "event_observation",
            Self::ExactConformanceObservation => "exact_conformance_observation",
            Self::ActiveDecryptabilityProbe => "active_decryptability_probe",
            Self::AdminPolicyObservation => "admin_policy_observation",
            Self::CrashReopen => "crash_reopen",
            Self::VirtualTime => "virtual_time",
            Self::WhiteBoxTransportQueueFaults => "white_box_transport_queue_faults",
            Self::WhiteBoxTransportPartition => "white_box_transport_partition",
            Self::WhiteBoxStorageFaults => "white_box_storage_faults",
        }
    }

    pub const fn is_white_box(self) -> bool {
        matches!(
            self,
            Self::WhiteBoxTransportQueueFaults
                | Self::WhiteBoxTransportPartition
                | Self::WhiteBoxStorageFaults
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectError {
    pub code: String,
    pub message: String,
}

impl SubjectError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
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

    async fn update_admin_policy(
        &mut self,
        _action: SubjectUpdateAdminPolicy<'_>,
    ) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(SubjectCapability::GroupMutation))
    }

    async fn confirm_pending(&mut self, _client: &str, _pending: &str) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::PublicationLifecycle,
        ))
    }

    async fn fail_pending(&mut self, _client: &str, _pending: &str) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::PublicationLifecycle,
        ))
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

    /// Advance the subject's paired convergence clock without waking a
    /// participant runtime. A later `tick` selects which participants observe
    /// the elapsed deadline.
    async fn advance_time(&mut self, _delta_ms: u64) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(SubjectCapability::VirtualTime))
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

    fn clear_events(&mut self, _clients: &[String]) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(
            SubjectCapability::EventObservation,
        ))
    }

    fn restart(&mut self, _client: &str) -> Result<(), SubjectError> {
        Err(SubjectError::unsupported(SubjectCapability::CrashReopen))
    }

    fn fault_injection(&mut self) -> Option<&mut dyn ConvergenceFaultSubject> {
        None
    }
}

/// Explicit harness-only transport mutation. Normal subjects need not expose it.
pub trait ConvergenceFaultSubject {
    fn drop_queued(&mut self, index: usize) -> Result<(), SubjectError>;
    fn duplicate_queued(&mut self, index: usize) -> Result<(), SubjectError>;
    fn delay_queued(&mut self, index: usize, delayed: &str) -> Result<(), SubjectError>;
    fn release_delayed(&mut self, delayed: &str) -> Result<(), SubjectError>;
    fn reorder_queued(&mut self, order: &[usize]) -> Result<(), SubjectError>;
    fn set_partition(&mut self, allow: &[String]) -> Result<(), SubjectError>;
    fn clear_partition(&mut self) -> Result<(), SubjectError>;
}

/// Capability required for one ScenarioSpec v1 step.
pub fn required_capability(step: &ScenarioStep) -> SubjectCapability {
    match step {
        ScenarioStep::CreateGroup { .. }
        | ScenarioStep::InviteMembers { .. }
        | ScenarioStep::UpdateGroupData { .. }
        | ScenarioStep::UpdateAdminPolicy { .. }
        | ScenarioStep::ExpectUpdateAdminPolicyError { .. }
        | ScenarioStep::Leave { .. } => SubjectCapability::GroupMutation,
        ScenarioStep::ConfirmPending { .. } | ScenarioStep::FailPending { .. } => {
            SubjectCapability::PublicationLifecycle
        }
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
        ScenarioStep::DropQueued { .. }
        | ScenarioStep::DuplicateQueued { .. }
        | ScenarioStep::DelayQueued { .. }
        | ScenarioStep::ReleaseDelayed { .. }
        | ScenarioStep::ReorderQueued { .. } => SubjectCapability::WhiteBoxTransportQueueFaults,
        ScenarioStep::SetPartition { .. } | ScenarioStep::ClearPartition => {
            SubjectCapability::WhiteBoxTransportPartition
        }
    }
}

/// Current in-process OpenMLS/SQLite/Nostr-peeler subject.
pub struct EngineHarnessSubject {
    descriptor: SubjectDescriptor,
    bus: TransportBus,
    clients: BTreeMap<String, HarnessClient>,
    pending_refs: HashMap<String, PendingStateRef>,
    convergence_clock: ManualConvergenceClock,
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
            let client = ClientBuilder::new(pad32(label.as_bytes()))
                .registry(scenario_registry())
                .protocol_profile(protocol_profile)
                .storage_mode(storage_mode)
                .convergence_clock(Arc::new(convergence_clock.clone()))
                .attach(&bus);
            attached.insert(label.clone(), client);
        }
        let capabilities = [
            SubjectCapability::GroupMutation,
            SubjectCapability::PublicationLifecycle,
            SubjectCapability::ApplicationMessaging,
            SubjectCapability::TransportDelivery,
            SubjectCapability::EventObservation,
            SubjectCapability::ExactConformanceObservation,
            SubjectCapability::ActiveDecryptabilityProbe,
            SubjectCapability::AdminPolicyObservation,
            SubjectCapability::CrashReopen,
            SubjectCapability::VirtualTime,
            SubjectCapability::WhiteBoxTransportQueueFaults,
            SubjectCapability::WhiteBoxTransportPartition,
        ]
        .into_iter()
        .collect();
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
        })
    }

    fn client(&self, label: &str) -> Result<&HarnessClient, SubjectError> {
        self.clients
            .get(label)
            .ok_or_else(|| SubjectError::new("unknown_client", format!("unknown client {label}")))
    }

    fn client_mut(&mut self, label: &str) -> Result<&mut HarnessClient, SubjectError> {
        self.clients
            .get_mut(label)
            .ok_or_else(|| SubjectError::new("unknown_client", format!("unknown client {label}")))
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
        pending_ref: PendingStateRef,
    ) -> Result<(), SubjectError> {
        if self
            .pending_refs
            .insert(label.to_string(), pending_ref)
            .is_some()
        {
            return Err(SubjectError::new(
                "duplicate_pending",
                format!("duplicate pending label {label}"),
            ));
        }
        Ok(())
    }

    fn take_pending(&mut self, label: &str) -> Result<PendingStateRef, SubjectError> {
        self.pending_refs.remove(label).ok_or_else(|| {
            SubjectError::new("unknown_pending", format!("unknown pending label {label}"))
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
            self.insert_pending(action.pending, pending_ref)?;
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
        self.insert_pending(action.pending, pending_ref)
    }

    async fn update_group_data(
        &mut self,
        action: SubjectUpdateGroupData<'_>,
    ) -> Result<(), SubjectError> {
        let client = self.client_mut(action.client)?;
        client.name_next_scenario_input(action.action_id);
        let pending_ref = client.update_group_data(action.name.to_owned()).await;
        self.insert_pending(action.pending, pending_ref)
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
            self.insert_pending(pending, pending_ref)?;
        }
        Ok(())
    }

    async fn confirm_pending(&mut self, client: &str, pending: &str) -> Result<(), SubjectError> {
        let pending_ref = self.take_pending(pending)?;
        self.client_mut(client)?.confirm(pending_ref).await;
        Ok(())
    }

    async fn fail_pending(&mut self, client: &str, pending: &str) -> Result<(), SubjectError> {
        let pending_ref = self.pending_refs.get(pending).cloned().ok_or_else(|| {
            SubjectError::new(
                "unknown_pending",
                format!("unknown pending label {pending}"),
            )
        })?;
        self.client_mut(client)?
            .try_fail(pending_ref)
            .await
            .map_err(subject_engine_error)?;
        self.pending_refs.remove(pending);
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
            self.client_mut(label)?.tick().await;
        }
        Ok(())
    }

    async fn advance_time(&mut self, delta_ms: u64) -> Result<(), SubjectError> {
        self.convergence_clock.advance_ms(delta_ms);
        for client in self.clients.values_mut() {
            client.enable_virtual_time_tick();
        }
        Ok(())
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
    fn drop_queued(&mut self, index: usize) -> Result<(), SubjectError> {
        if self.bus.drop_queued(index) {
            Ok(())
        } else {
            Err(SubjectError::new(
                "unknown_queued_message",
                format!("queued message index {index} does not exist"),
            ))
        }
    }

    fn duplicate_queued(&mut self, index: usize) -> Result<(), SubjectError> {
        if self.bus.duplicate_queued(index) {
            Ok(())
        } else {
            Err(SubjectError::new(
                "unknown_queued_message",
                format!("queued message index {index} does not exist"),
            ))
        }
    }

    fn delay_queued(&mut self, index: usize, delayed: &str) -> Result<(), SubjectError> {
        if self.bus.delay_queued(index, delayed.to_owned()) {
            Ok(())
        } else {
            Err(SubjectError::new(
                "unknown_queued_message",
                format!("queued message index {index} does not exist"),
            ))
        }
    }

    fn release_delayed(&mut self, delayed: &str) -> Result<(), SubjectError> {
        if self.bus.release_delayed(delayed) {
            Ok(())
        } else {
            Err(SubjectError::new(
                "unknown_delayed_queue",
                format!("delayed queue label {delayed} does not exist"),
            ))
        }
    }

    fn reorder_queued(&mut self, order: &[usize]) -> Result<(), SubjectError> {
        if self.bus.reorder_queued(order) {
            Ok(())
        } else {
            Err(SubjectError::new(
                "invalid_queue_order",
                format!("invalid queue reorder permutation {order:?}"),
            ))
        }
    }

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

fn scenario_registry() -> FeatureRegistry {
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

fn subject_engine_error(error: EngineError) -> SubjectError {
    SubjectError::new(observe_engine_error(&error), error.to_string())
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
    use crate::ConformanceCanonicalStateSnapshot;

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
                .expect("prepare and confirm disband commit");
            client
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
}
