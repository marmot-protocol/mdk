//! [`Engine<S>`] is the OpenMLS-backed [`CgkaEngine`] implementation.
//!
//! Generic over `S: cgka_traits::StorageProvider`. Holds OpenMLS RustCrypto
//! for the crypto + rand half of OpenMLS's provider surface, materializing an
//! `EngineOpenMlsProvider` on demand per MLS call.
//!
//! This file owns construction, trait dispatch, event drains, and small
//! read-only helpers. Group creation, ingest/send, publish lifecycle,
//! convergence, and capability logic live in focused sibling modules.

use crate::feature_registry::FeatureRegistry;
use crate::identity::Identity;
use async_trait::async_trait;
use cgka_traits::capabilities::{Feature, FeatureStatus, GroupCapabilities};
use cgka_traits::engine::{
    AutoPublish, CgkaEngine, CreateGroupRequest, GroupEvent, KeyPackage, SendIntent, SendResult,
};
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::error::EngineError;
use cgka_traits::group::{Group, Member};
use cgka_traits::group_context::GroupContext;
use cgka_traits::ingest::IngestOutcome;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::StorageProvider;
use cgka_traits::transport::TransportMessage;
use cgka_traits::types::MessageId;
use cgka_traits::types::{EpochId, GroupId, MemberId};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::types::Ciphersuite;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

/// Default ciphersuite. MLS-1.0 mandatory-to-implement; TLS-ish naming.
pub const DEFAULT_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// OpenMLS-backed CGKA engine. Construct via [`EngineBuilder`].
pub struct Engine<S: StorageProvider> {
    pub(crate) storage: S,
    pub(crate) crypto: RustCrypto,
    pub(crate) identity: Identity,
    pub(crate) registry: FeatureRegistry,
    pub(crate) peeler: Box<dyn TransportPeeler>,
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) max_past_epochs: usize,

    /// Per-group state-machine owner. Every transition, pending-ref
    /// allocation, and fork-detection marker flows through this struct.
    pub(crate) epoch_manager: crate::epoch_manager::EpochManager,

    /// Snapshot + ordering metadata for same-epoch competing commits.
    pub(crate) fork_recovery: crate::fork_recovery::ForkRecoveryManager,

    pub(crate) events_buf: VecDeque<GroupEvent>,
    pub(crate) auto_publish_buf: VecDeque<AutoPublish>,
    /// Members removed by a locally staged commit. The event is emitted after
    /// publish confirmation, when the OpenMLS pending commit is actually
    /// merged.
    pub(crate) pending_auto_removed: HashMap<PendingStateRef, Vec<MemberId>>,

    /// MessageIds the engine has ingested. Backs `StaleReason::AlreadySeen`.
    pub(crate) seen_message_ids: HashSet<MessageId>,

    /// MessageIds this engine has produced via `send` or `create_group` /
    /// `invite`. Backs `StaleReason::OwnEcho` when a message we produced
    /// bounces back via ingest before we filter it client-side.
    pub(crate) sent_message_ids: HashSet<MessageId>,

    pub(crate) convergence_policy: crate::canonicalization::CanonicalizationPolicy,
    pub(crate) last_convergence_relevant_input_ms: HashMap<GroupId, u64>,
    pub(crate) convergence_clock_started_at: Instant,
}

// ── Builder ─────────────────────────────────────────────────────────────────

/// Construction-time wiring for [`Engine`].
pub struct EngineBuilder<S: StorageProvider> {
    storage: S,
    identity_bytes: Option<Vec<u8>>,
    registry: FeatureRegistry,
    peeler: Option<Box<dyn TransportPeeler>>,
    ciphersuite: Ciphersuite,
    max_past_epochs: usize,
}

impl<S: StorageProvider> EngineBuilder<S> {
    pub fn new(storage: S) -> Self {
        Self {
            storage,
            identity_bytes: None,
            registry: FeatureRegistry::new(),
            peeler: None,
            ciphersuite: DEFAULT_CIPHERSUITE,
            max_past_epochs: crate::wire_format::DEFAULT_MAX_PAST_EPOCHS,
        }
    }

    pub fn identity(mut self, bytes: Vec<u8>) -> Self {
        self.identity_bytes = Some(bytes);
        self
    }

    pub fn feature_registry(mut self, registry: FeatureRegistry) -> Self {
        self.registry = registry;
        self
    }

    pub fn peeler(mut self, peeler: Box<dyn TransportPeeler>) -> Self {
        self.peeler = Some(peeler);
        self
    }

    pub fn ciphersuite(mut self, cs: Ciphersuite) -> Self {
        self.ciphersuite = cs;
        self
    }

    pub fn max_past_epochs(mut self, max_past_epochs: usize) -> Self {
        self.max_past_epochs = max_past_epochs;
        self
    }

    pub fn build(self) -> Result<Engine<S>, EngineError> {
        let identity_bytes = self
            .identity_bytes
            .ok_or_else(|| EngineError::Other("identity bytes are required".into()))?;
        let peeler = self
            .peeler
            .ok_or_else(|| EngineError::Other("TransportPeeler is required".into()))?;
        let crypto = RustCrypto::default();
        let identity = Identity::load_or_generate(self.ciphersuite, identity_bytes, &self.storage)
            .map_err(EngineError::Other)?;

        Ok(Engine {
            storage: self.storage,
            crypto,
            identity,
            registry: self.registry,
            peeler,
            ciphersuite: self.ciphersuite,
            max_past_epochs: self.max_past_epochs,
            epoch_manager: crate::epoch_manager::EpochManager::new(),
            fork_recovery: crate::fork_recovery::ForkRecoveryManager::default(),
            events_buf: VecDeque::new(),
            auto_publish_buf: VecDeque::new(),
            pending_auto_removed: HashMap::new(),
            seen_message_ids: HashSet::new(),
            sent_message_ids: HashSet::new(),
            convergence_policy: crate::canonicalization::CanonicalizationPolicy::default(),
            last_convergence_relevant_input_ms: HashMap::new(),
            convergence_clock_started_at: Instant::now(),
        })
    }
}

impl<S: StorageProvider> Engine<S> {
    /// Restore stable epoch state for groups already present in storage.
    ///
    /// This is used by production session startup after opening durable
    /// storage. Pending publish state is deliberately not reconstructed here:
    /// v1 sessions require the application to resolve publish success/failure
    /// before shutdown, and future resumable-pending support should persist a
    /// dedicated pending-publish record instead of inferring one from group
    /// rows.
    pub fn hydrate_stable_groups_from_storage(&mut self) -> Result<(), EngineError> {
        for group_id in self.storage.list_groups()? {
            let group = self.storage.get_group(&group_id)?;
            self.epoch_manager.set_stable(group_id, group.epoch);
        }
        Ok(())
    }

    pub(crate) fn convergence_now_ms(&self) -> u64 {
        self.convergence_clock_started_at
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    /// Return the Marmot group metadata mirrored from signed MLS group state.
    ///
    /// App surfaces use this for projections such as group profile components
    /// without reaching into OpenMLS internals.
    pub fn group_record(&self, group_id: &GroupId) -> Result<Group, EngineError> {
        Ok(self.storage.get_group(group_id)?)
    }
}

// ── CgkaEngine impl ─────────────────────────────────────────────────────────
//
// Trait methods stay thin: validate the trait boundary, then delegate to
// the module that owns the behavior.

#[async_trait]
impl<S: StorageProvider + 'static> CgkaEngine for Engine<S> {
    async fn ingest(&mut self, msg: TransportMessage) -> Result<IngestOutcome, EngineError> {
        self.do_ingest(msg).await
    }

    fn drain_events(&mut self) -> Vec<GroupEvent> {
        self.events_buf.drain(..).collect()
    }

    fn drain_auto_publish(&mut self) -> Vec<AutoPublish> {
        self.auto_publish_buf.drain(..).collect()
    }

    async fn send(&mut self, intent: SendIntent) -> Result<SendResult, EngineError> {
        self.do_send(intent).await
    }

    async fn advance_convergence(
        &mut self,
        group_id: &GroupId,
    ) -> Result<Vec<SendResult>, EngineError> {
        let now_ms = self.convergence_now_ms();
        self.converge_and_drain_queued_outbound_intents(group_id, now_ms)
            .await
    }

    async fn confirm_published(
        &mut self,
        pending: PendingStateRef,
    ) -> Result<GroupEvent, EngineError> {
        self.do_confirm_published(pending).await
    }

    async fn publish_failed(&mut self, pending: PendingStateRef) -> Result<(), EngineError> {
        self.do_publish_failed(pending).await
    }

    async fn create_group(
        &mut self,
        req: CreateGroupRequest,
    ) -> Result<(GroupId, SendResult), EngineError> {
        self.do_create_group(req).await
    }

    async fn join_welcome(
        &mut self,
        welcome_msg: TransportMessage,
    ) -> Result<GroupId, EngineError> {
        self.do_join_welcome(welcome_msg).await
    }

    fn feature_status(
        &self,
        group_id: &GroupId,
        feature: &Feature,
    ) -> Result<FeatureStatus, EngineError> {
        self.do_feature_status(group_id, feature)
    }

    fn constructable_capabilities(
        &self,
        key_packages: &[KeyPackage],
    ) -> Result<GroupCapabilities, EngineError> {
        self.do_constructable_capabilities(key_packages)
    }

    fn upgradeable_capabilities(
        &self,
        group_id: &GroupId,
    ) -> Result<GroupCapabilities, EngineError> {
        self.do_upgradeable_capabilities(group_id)
    }

    async fn upgrade_group_capabilities(
        &mut self,
        group_id: &GroupId,
    ) -> Result<SendResult, EngineError> {
        self.do_upgrade_group_capabilities(group_id).await
    }

    fn group_context(&self, group_id: &GroupId) -> Result<Box<dyn GroupContext + '_>, EngineError> {
        use crate::provider::EngineOpenMlsProvider;
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = openmls::group::MlsGroup::load(
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        // When the group is in `PendingPublish`, the MLS group is at the
        // pre-stage epoch but the staged commit carries the projected
        // future state. Project so callers see the same epoch the rest of
        // the engine reports via `epoch()` / `EpochState`.
        let crypto =
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::crypto(&provider);
        let (epoch, secret) = if let Some(staged) = mls_group.pending_commit() {
            let s = staged
                .export_secret(crypto, crate::group_lifecycle::EXPORTER_LABEL, &[], 32)
                .map_err(|e| EngineError::Backend(format!("staged export_secret: {e:?}")))?;
            (staged.group_context().epoch().as_u64(), s)
        } else {
            let s = mls_group
                .export_secret(crypto, crate::group_lifecycle::EXPORTER_LABEL, &[], 32)
                .map_err(|e| EngineError::Backend(format!("export_secret: {e:?}")))?;
            (mls_group.epoch().as_u64(), s)
        };
        let mut map = std::collections::HashMap::new();
        map.insert(crate::group_lifecycle::EXPORTER_LABEL.to_string(), secret);
        Ok(Box::new(crate::group_context_view::GroupContextView::new(
            EpochId(epoch),
            map,
            Some(group_id.as_slice().to_vec()),
        )))
    }

    fn members(&self, group_id: &GroupId) -> Result<Vec<Member>, EngineError> {
        self.do_members(group_id)
    }

    fn epoch(&self, group_id: &GroupId) -> Result<EpochId, EngineError> {
        self.epoch_manager
            .epoch(group_id)
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))
    }

    fn self_id(&self) -> MemberId {
        self.identity.self_id().clone()
    }

    async fn fresh_key_package(&mut self) -> Result<KeyPackage, EngineError> {
        self.do_fresh_key_package()
    }
}
