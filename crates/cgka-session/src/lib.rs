//! Production-shaped account-device session wrapper.
//!
//! This crate wires an OpenMLS-backed engine to SQLCipher storage for one
//! Marmot account-device identity. Transport remains injected through
//! `TransportPeeler`; actual network publish and relay sync stay above this
//! crate.

use std::path::PathBuf;

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
use storage_sqlite::{SqlCipherKey, SqliteStorage, SqliteStorageOptions};

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
    feature_registry: FeatureRegistry,
    supported_app_components: AppComponentSet,
    storage_options: SqliteStorageOptions,
    convergence_policy: CanonicalizationPolicy,
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
            feature_registry: FeatureRegistry::new(),
            supported_app_components: AppComponentSet::new(default_group_components()),
            storage_options: SqliteStorageOptions::default(),
            convergence_policy: CanonicalizationPolicy::default(),
        }
    }

    pub fn feature_registry(mut self, registry: FeatureRegistry) -> Self {
        self.feature_registry = registry;
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
    engine: Engine<SqliteStorage>,
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
        let storage = SqliteStorage::open_encrypted_with_options(
            config.database_path,
            &config.database_key,
            config.storage_options,
        )?;
        let mut engine = EngineBuilder::new(storage)
            .identity(config.identity)
            .feature_registry(config.feature_registry)
            .supported_app_components(config.supported_app_components.ids)
            .peeler(config.peeler)
            .build()?;
        engine.hydrate_stable_groups_from_storage()?;
        engine.set_convergence_policy(config.convergence_policy);
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
