//! Production-shaped account-device session wrapper.
//!
//! This crate wires an OpenMLS-backed engine to SQLCipher storage for one
//! Marmot account-device identity. Transport remains injected through
//! `TransportPeeler`; actual network publish and relay sync stay above this
//! crate.

use std::{path::PathBuf, sync::Arc};

use cgka_engine::account_identity_proof::AccountIdentityProofSigner;
use cgka_engine::canonicalization::CanonicalizationPolicy;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::app_components::{AppComponentId, AppComponentSet, default_group_components};
use cgka_traits::engine::{
    CgkaEngine, CreateGroupRequest, GroupEvent, KeyPackage, SendIntent, SendResult,
};
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::error::EngineError;
use cgka_traits::group::{Group, Member};
use cgka_traits::ingest::IngestOutcome;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::StorageError;
use cgka_traits::transport::TransportMessage;
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use cgka_traits::{
    SecretBytes, TransportDelivery, TransportDeliveryPlane, TransportDeliverySource,
};
use marmot_forensics::{
    AuditEventContext, AuditEventKind, AuditTransportContext, ForensicRecorder,
};
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage, SqliteStorageOptions};

const TRACE_TARGET: &str = "cgka_session::session";

pub type SessionResult<T> = Result<T, SessionError>;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Engine(#[from] EngineError),
}

pub struct SessionConfig {
    database_path: PathBuf,
    database_key: SqlCipherKey,
    identity: Vec<u8>,
    peeler: Box<dyn TransportPeeler>,
    account_identity_proof_signer: Option<Arc<dyn AccountIdentityProofSigner>>,
    feature_registry: FeatureRegistry,
    supported_app_components: AppComponentSet,
    storage_options: SqliteStorageOptions,
    convergence_policy: CanonicalizationPolicy,
    recorder: Option<Box<dyn ForensicRecorder>>,
}

impl SessionConfig {
    pub fn new(
        database_path: impl Into<PathBuf>,
        database_key: SqlCipherKey,
        identity: Vec<u8>,
        peeler: Box<dyn TransportPeeler>,
    ) -> Self {
        Self {
            database_path: database_path.into(),
            database_key,
            identity,
            peeler,
            account_identity_proof_signer: None,
            feature_registry: FeatureRegistry::new(),
            supported_app_components: AppComponentSet::new(default_group_components()),
            storage_options: SqliteStorageOptions::default(),
            convergence_policy: CanonicalizationPolicy::default(),
            recorder: None,
        }
    }

    /// Install a forensic audit-log recorder. Without this call the engine
    /// uses the no-op recorder.
    pub fn recorder(mut self, recorder: Box<dyn ForensicRecorder>) -> Self {
        self.recorder = Some(recorder);
        self
    }

    pub fn feature_registry(mut self, registry: FeatureRegistry) -> Self {
        self.feature_registry = registry;
        self
    }

    pub fn account_identity_proof_signer(
        mut self,
        signer: Arc<dyn AccountIdentityProofSigner>,
    ) -> Self {
        self.account_identity_proof_signer = Some(signer);
        self
    }

    pub fn supported_app_components(
        mut self,
        components: impl IntoIterator<Item = AppComponentId>,
    ) -> Self {
        self.supported_app_components = AppComponentSet::new(components);
        self
    }

    pub fn storage_options(mut self, options: SqliteStorageOptions) -> Self {
        self.storage_options = options;
        self
    }

    pub fn convergence_policy(mut self, policy: CanonicalizationPolicy) -> Self {
        self.convergence_policy = policy;
        self
    }
}

pub struct AccountDeviceSession {
    engine: Engine<SqliteAccountStorage>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionEffects {
    pub events: Vec<GroupEvent>,
    pub publish: Vec<PublishWork>,
    pub queued: Vec<QueuedIntentRef>,
}

impl SessionEffects {
    pub fn is_empty(&self) -> bool {
        self.events.is_empty() && self.publish.is_empty() && self.queued.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublishWork {
    ApplicationMessage {
        msg: TransportMessage,
    },
    Proposal {
        msg: TransportMessage,
    },
    GroupEvolution {
        msg: TransportMessage,
        welcomes: Vec<TransportMessage>,
        pending: PendingStateRef,
    },
    GroupCreated {
        welcomes: Vec<TransportMessage>,
        pending: PendingStateRef,
    },
    AutoPublish {
        msg: TransportMessage,
        pending: PendingStateRef,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedIntentRef {
    pub group_id: GroupId,
    pub intent_id: MessageId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateGroupEffects {
    pub group_id: GroupId,
    pub effects: SessionEffects,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngestEffects {
    pub outcome: IngestOutcome,
    pub effects: SessionEffects,
}

impl AccountDeviceSession {
    pub fn open(config: SessionConfig) -> SessionResult<Self> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "open",
            "opening account device session"
        );
        let storage = SqliteAccountStorage::open_encrypted_with_options(
            config.database_path,
            &config.database_key,
            config.storage_options,
        )?;
        let mut builder = EngineBuilder::new(storage)
            .identity(config.identity)
            .account_identity_proof_signer(config.account_identity_proof_signer.ok_or_else(
                || EngineError::Other("account identity proof signer is required".into()),
            )?)
            .feature_registry(config.feature_registry)
            .supported_app_components(config.supported_app_components.ids)
            .peeler(config.peeler);
        if let Some(recorder) = config.recorder {
            builder = builder.recorder(recorder);
        }
        let mut engine = builder.build()?;
        engine.hydrate_stable_groups_from_storage()?;
        engine.set_convergence_policy(config.convergence_policy);
        engine.audit_recorder_health();
        tracing::debug!(
            target: TRACE_TARGET,
            method = "open",
            "account device session opened"
        );
        Ok(Self { engine })
    }

    pub async fn fresh_key_package(&mut self) -> Result<KeyPackage, EngineError> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "fresh_key_package",
            "creating fresh key package"
        );
        let key_package = self.engine.fresh_key_package().await?;
        tracing::debug!(
            target: TRACE_TARGET,
            method = "fresh_key_package",
            "fresh key package created"
        );
        Ok(key_package)
    }

    pub fn group_record(&self, group_id: &GroupId) -> SessionResult<Group> {
        Ok(self.engine.group_record(group_id)?)
    }

    pub fn admin_pubkeys(&self, group_id: &GroupId) -> SessionResult<Vec<[u8; 32]>> {
        Ok(self.engine.admin_pubkeys(group_id)?)
    }

    pub fn app_component(
        &self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> SessionResult<Option<Vec<u8>>> {
        Ok(self.engine.app_component(group_id, component_id)?)
    }

    pub fn safe_export_secret(
        &mut self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> Result<SecretBytes, EngineError> {
        self.engine.safe_export_secret(group_id, component_id)
    }

    pub fn exporter_secret(
        &self,
        group_id: &GroupId,
        label: &str,
        length: usize,
    ) -> Result<SecretBytes, EngineError> {
        let context = self.engine.group_context(group_id)?;
        context
            .exporter_secret(label, length)
            .ok_or_else(|| EngineError::Other(format!("missing exporter secret for label {label}")))
    }

    pub fn exporter_secret_with_epoch(
        &self,
        group_id: &GroupId,
        label: &str,
        length: usize,
    ) -> Result<(EpochId, SecretBytes), EngineError> {
        let context = self.engine.group_context(group_id)?;
        let epoch = context.epoch();
        let secret = context.exporter_secret(label, length).ok_or_else(|| {
            EngineError::Other(format!("missing exporter secret for label {label}"))
        })?;
        Ok((epoch, secret))
    }

    pub fn safe_export_secret_with_epoch(
        &mut self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> Result<(EpochId, SecretBytes), EngineError> {
        self.engine
            .safe_export_secret_with_epoch(group_id, component_id)
    }

    pub fn current_safe_export_epoch(
        &self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> Result<EpochId, EngineError> {
        self.engine
            .current_safe_export_epoch(group_id, component_id)
    }

    pub async fn create_group(
        &mut self,
        req: CreateGroupRequest,
    ) -> SessionResult<CreateGroupEffects> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "create_group",
            invitee_count = req.members.len(),
            required_feature_count = req.required_features.len(),
            initial_admin_count = req.initial_admins.len(),
            "creating group"
        );
        let (group_id, result) = self.engine.create_group(req).await?;
        let effects = self.collect_effects(vec![result]);
        tracing::debug!(
            target: TRACE_TARGET,
            method = "create_group",
            "group created"
        );
        Ok(CreateGroupEffects { group_id, effects })
    }

    pub async fn create_group_with_audit_context(
        &mut self,
        req: CreateGroupRequest,
        context: AuditEventContext,
    ) -> SessionResult<CreateGroupEffects> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "create_group_with_audit_context",
            invitee_count = req.members.len(),
            required_feature_count = req.required_features.len(),
            initial_admin_count = req.initial_admins.len(),
            "creating group"
        );
        let (group_id, result) = self
            .engine
            .create_group_with_audit_context(req, Some(context))
            .await?;
        tracing::debug!(
            target: TRACE_TARGET,
            method = "create_group_with_audit_context",
            "group created"
        );
        let effects = self.collect_effects(vec![result]);
        Ok(CreateGroupEffects { group_id, effects })
    }

    pub async fn send(&mut self, intent: SendIntent) -> SessionResult<SessionEffects> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "send",
            intent_kind = send_intent_kind(&intent),
            "sending local intent"
        );
        let result = self.engine.send(intent).await?;
        tracing::debug!(
            target: TRACE_TARGET,
            method = "send",
            result_kind = send_result_kind(&result),
            "local intent accepted"
        );
        Ok(self.collect_effects(vec![result]))
    }

    pub async fn send_with_audit_context(
        &mut self,
        intent: SendIntent,
        context: AuditEventContext,
    ) -> SessionResult<SessionEffects> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "send_with_audit_context",
            intent_kind = send_intent_kind(&intent),
            "sending local intent"
        );
        let result = self
            .engine
            .send_with_audit_context(intent, Some(context))
            .await?;
        tracing::debug!(
            target: TRACE_TARGET,
            method = "send_with_audit_context",
            result_kind = send_result_kind(&result),
            "local intent accepted"
        );
        Ok(self.collect_effects(vec![result]))
    }

    pub async fn ingest(&mut self, msg: TransportMessage) -> SessionResult<IngestEffects> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "ingest",
            "ingesting transport message"
        );
        let outcome = self.engine.ingest(msg).await?;
        tracing::debug!(
            target: TRACE_TARGET,
            method = "ingest",
            outcome_kind = ingest_outcome_kind(&outcome),
            "transport message ingested"
        );
        let effects = self.collect_effects(vec![]);
        Ok(IngestEffects { outcome, effects })
    }

    pub async fn ingest_delivery(
        &mut self,
        delivery: TransportDelivery,
    ) -> SessionResult<IngestEffects> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "ingest_delivery",
            "ingesting transport delivery"
        );
        let transport_context = audit_transport_context(delivery.source);
        let outcome = self
            .engine
            .ingest_with_audit_context(delivery.message, Some(transport_context))
            .await?;
        tracing::debug!(
            target: TRACE_TARGET,
            method = "ingest_delivery",
            outcome_kind = ingest_outcome_kind(&outcome),
            "transport delivery ingested"
        );
        let effects = self.collect_effects(vec![]);
        Ok(IngestEffects { outcome, effects })
    }

    pub async fn advance_convergence(
        &mut self,
        group_id: &GroupId,
    ) -> SessionResult<SessionEffects> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "advance_convergence",
            "advancing convergence"
        );
        let results = self.engine.advance_convergence(group_id).await?;
        tracing::debug!(
            target: TRACE_TARGET,
            method = "advance_convergence",
            result_count = results.len(),
            "convergence advanced"
        );
        Ok(self.collect_effects(results))
    }

    pub async fn confirm_published(
        &mut self,
        pending: PendingStateRef,
    ) -> SessionResult<SessionEffects> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "confirm_published",
            "confirming published state"
        );
        let event = self.engine.confirm_published(pending).await?;
        let mut effects = self.collect_effects(vec![]);
        if !effects.events.contains(&event) {
            effects.events.insert(0, event);
        }
        tracing::debug!(
            target: TRACE_TARGET,
            method = "confirm_published",
            "published state confirmed"
        );
        Ok(effects)
    }

    pub async fn publish_failed(
        &mut self,
        pending: PendingStateRef,
    ) -> SessionResult<SessionEffects> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "publish_failed",
            "recording publish failure"
        );
        self.engine.publish_failed(pending).await?;
        tracing::debug!(
            target: TRACE_TARGET,
            method = "publish_failed",
            "publish failure recorded"
        );
        Ok(self.collect_effects(vec![]))
    }

    pub fn drain(&mut self) -> SessionEffects {
        tracing::trace!(
            target: TRACE_TARGET,
            method = "drain",
            "draining session effects"
        );
        self.collect_effects(vec![])
    }

    pub fn epoch(&self, group_id: &GroupId) -> Result<EpochId, EngineError> {
        self.engine.epoch(group_id)
    }

    pub fn members(&self, group_id: &GroupId) -> Result<Vec<Member>, EngineError> {
        self.engine.members(group_id)
    }

    pub fn self_id(&self) -> MemberId {
        self.engine.self_id()
    }

    pub fn set_convergence_policy(&mut self, policy: CanonicalizationPolicy) {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "set_convergence_policy",
            "updating convergence policy"
        );
        self.engine.set_convergence_policy(policy);
    }

    pub fn record_audit_event(
        &self,
        group_id: Option<&GroupId>,
        context: Option<AuditEventContext>,
        kind: AuditEventKind,
    ) {
        self.engine.audit_external(group_id, context, kind);
    }

    pub fn record_audit_health(&self) {
        self.engine.audit_recorder_health();
    }

    fn collect_effects(&mut self, results: Vec<SendResult>) -> SessionEffects {
        let mut effects = SessionEffects {
            events: self.engine.drain_events(),
            publish: Vec::new(),
            queued: Vec::new(),
        };
        for result in results {
            match result {
                SendResult::ApplicationMessage { msg } => effects
                    .publish
                    .push(PublishWork::ApplicationMessage { msg }),
                SendResult::Proposal { msg } => effects.publish.push(PublishWork::Proposal { msg }),
                SendResult::GroupEvolution {
                    msg,
                    welcomes,
                    pending,
                } => effects.publish.push(PublishWork::GroupEvolution {
                    msg,
                    welcomes,
                    pending,
                }),
                SendResult::GroupCreated { welcomes, pending } => effects
                    .publish
                    .push(PublishWork::GroupCreated { welcomes, pending }),
                SendResult::Queued {
                    group_id,
                    intent_id,
                } => effects.queued.push(QueuedIntentRef {
                    group_id,
                    intent_id,
                }),
            }
        }
        for auto in self.engine.drain_auto_publish() {
            effects.publish.push(PublishWork::AutoPublish {
                msg: auto.msg,
                pending: auto.pending,
            });
        }
        effects.events.extend(self.engine.drain_events());
        tracing::trace!(
            target: TRACE_TARGET,
            method = "collect_effects",
            event_count = effects.events.len(),
            publish_count = effects.publish.len(),
            queued_count = effects.queued.len(),
            "session effects collected"
        );
        effects
    }
}

fn send_intent_kind(intent: &SendIntent) -> &'static str {
    match intent {
        SendIntent::AppMessage { .. } => "app_message",
        SendIntent::Invite { .. } => "invite",
        SendIntent::RemoveMembers { .. } => "remove_members",
        SendIntent::Leave { .. } => "leave",
        SendIntent::UpdateAppComponents { .. } => "update_app_components",
        SendIntent::UpdateGroupData { .. } => "update_group_data",
    }
}

fn send_result_kind(result: &SendResult) -> &'static str {
    match result {
        SendResult::ApplicationMessage { .. } => "application_message",
        SendResult::Queued { .. } => "queued",
        SendResult::Proposal { .. } => "proposal",
        SendResult::GroupEvolution { .. } => "group_evolution",
        SendResult::GroupCreated { .. } => "group_created",
    }
}

fn ingest_outcome_kind(outcome: &IngestOutcome) -> &'static str {
    match outcome {
        IngestOutcome::Processed => "processed",
        IngestOutcome::Buffered { .. } => "buffered",
        IngestOutcome::Stale { .. } => "stale",
    }
}

fn audit_transport_context(source: TransportDeliverySource) -> AuditTransportContext {
    AuditTransportContext {
        transport_source: source.transport.0,
        delivery_plane: Some(delivery_plane_label(source.plane).to_string()),
        relay_url: source.endpoint.map(|endpoint| endpoint.0),
        subscription_id: source.subscription_id,
    }
}

fn delivery_plane_label(plane: TransportDeliveryPlane) -> &'static str {
    match plane {
        TransportDeliveryPlane::Discovery => "discovery",
        TransportDeliveryPlane::AccountInbox => "account_inbox",
        TransportDeliveryPlane::Group => "group",
        TransportDeliveryPlane::Ephemeral => "ephemeral",
    }
}
