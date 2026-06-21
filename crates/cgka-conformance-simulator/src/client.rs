//! `HarnessClient` — wraps an `Engine<SqliteAccountStorage>` + Nostr peeler + bus
//! attachment. Provides scenario-level affordances: `send`, `tick`,
//! `confirm_all_pending`, `assert_at_epoch`.

use crate::bus::{ClientId, TransportBus};
use cgka_engine::account_identity_proof::{
    AccountIdentityProofRequest, AccountIdentityProofSigner,
};
use cgka_engine::canonicalization::CanonicalizationPolicy;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::app_components::{
    AppComponentData, GROUP_ADMIN_POLICY_COMPONENT_ID, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1,
    default_group_components, encode_nostr_routing_v1,
};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::engine::{
    CgkaEngine, CreateGroupRequest, GroupEvent, KeyPackage, SendIntent, SendResult,
};
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::error::EngineError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, PeeledContent};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage};
use transport_nostr_peeler::NostrMlsPeeler;

const STORAGE_MODE_ENV: &str = "DARKMATTER_CONFORMANCE_SQLITE_STORAGE";
const TEMP_FILE_KEY: &str = "marmot-conformance-sqlite-temp-key";

pub struct HarnessClient {
    pub engine: Engine<SqliteAccountStorage>,
    pub bus_id: ClientId,
    bus: TransportBus,
    storage: SqliteAccountStorage,
    _storage_dir: Option<tempfile::TempDir>,
    identity: Vec<u8>,
    signer: nostr::Keys,
    registry: FeatureRegistry,
    pending_events: Vec<GroupEvent>,
    /// Default MLS group id used by single-group scenarios. Set
    /// automatically after the first create/join.
    default_group: Option<GroupId>,
    app_event_counter: u64,
}

pub struct ClientBuilder {
    identity: Vec<u8>,
    signer: nostr::Keys,
    registry: FeatureRegistry,
    storage_mode: HarnessStorageMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HarnessStorageMode {
    InMemorySqlite,
    TempFileBackedSqlite,
}

impl HarnessStorageMode {
    fn from_env() -> Self {
        match std::env::var(STORAGE_MODE_ENV) {
            Ok(value) if matches!(value.as_str(), "file" | "file-backed" | "tempfile") => {
                Self::TempFileBackedSqlite
            }
            Ok(value) if matches!(value.as_str(), "memory" | "in-memory" | "sqlite-memory") => {
                Self::InMemorySqlite
            }
            Ok(value) => panic!(
                "{STORAGE_MODE_ENV} must be one of memory, in-memory, sqlite-memory, file, file-backed, or tempfile; got {value:?}"
            ),
            Err(_) => Self::InMemorySqlite,
        }
    }

    fn open(self) -> Result<(SqliteAccountStorage, Option<tempfile::TempDir>), String> {
        match self {
            Self::InMemorySqlite => SqliteAccountStorage::in_memory()
                .map(|storage| (storage, None))
                .map_err(|err| err.to_string()),
            Self::TempFileBackedSqlite => {
                let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
                let key = SqlCipherKey::new(TEMP_FILE_KEY).map_err(|err| err.to_string())?;
                let storage =
                    SqliteAccountStorage::open_encrypted(dir.path().join("client.sqlite3"), &key)
                        .map_err(|err| err.to_string())?;
                Ok((storage, Some(dir)))
            }
        }
    }
}

impl ClientBuilder {
    pub fn new(identity: impl Into<Vec<u8>>) -> Self {
        let seed = identity.into();
        let signer = deterministic_nostr_keys(&seed);
        let identity = signer.public_key().to_bytes().to_vec();
        register_logical_identity(&seed, &identity);
        Self {
            identity,
            signer,
            registry: FeatureRegistry::new(),
            storage_mode: HarnessStorageMode::from_env(),
        }
    }

    pub fn registry(mut self, r: FeatureRegistry) -> Self {
        self.registry = r;
        self
    }

    pub fn storage_mode(mut self, mode: HarnessStorageMode) -> Self {
        self.storage_mode = mode;
        self
    }

    pub fn attach(self, bus: &TransportBus) -> HarnessClient {
        let (storage, storage_dir) = self.storage_mode.open().expect("storage opens");
        let peeler = NostrMlsPeeler::new().with_welcome_signer(self.signer.clone());
        let engine = EngineBuilder::new(storage.clone())
            .identity(self.identity.clone())
            .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner {
                keys: self.signer.clone(),
            }))
            .feature_registry(self.registry.clone())
            .supported_app_components(harness_supported_app_components())
            .peeler(Box::new(peeler))
            .build()
            .expect("engine builds");
        let bus_id = bus.attach(MemberId::new(self.identity.clone()));
        HarnessClient {
            engine,
            bus_id,
            bus: bus.clone(),
            storage,
            _storage_dir: storage_dir,
            identity: self.identity,
            signer: self.signer,
            registry: self.registry,
            pending_events: Vec::new(),
            default_group: None,
            app_event_counter: 0,
        }
    }
}

fn deterministic_nostr_keys(seed: &[u8]) -> nostr::Keys {
    let mut counter = 0_u64;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(b"marmot-cgka-conformance-nostr-key-v1");
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        let secret = hasher.finalize();
        if let Ok(keys) = nostr::Keys::parse(&hex::encode(secret)) {
            return keys;
        }
        counter = counter
            .checked_add(1)
            .expect("deterministic Nostr key search exhausted");
    }
}

fn harness_supported_app_components() -> Vec<u16> {
    let mut components = default_group_components();
    components.insert(NOSTR_ROUTING_COMPONENT_ID);
    components.into_iter().collect()
}

fn harness_nostr_routing_component(creator_identity: &[u8], name: &str) -> AppComponentData {
    let routing = NostrRoutingV1::new(
        deterministic_nostr_group_id(creator_identity, name),
        vec!["wss://group.example".to_owned()],
    )
    .expect("harness Nostr routing is valid");
    AppComponentData {
        component_id: NOSTR_ROUTING_COMPONENT_ID,
        data: encode_nostr_routing_v1(&routing).expect("harness Nostr routing encodes"),
    }
}

fn deterministic_nostr_group_id(creator_identity: &[u8], name: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"marmot-cgka-conformance-nostr-group-id-v1");
    hasher.update(creator_identity);
    hasher.update(name.as_bytes());
    hasher.finalize().into()
}

fn key_package_with_harness_source(key_package: KeyPackage) -> KeyPackage {
    let mut hasher = Sha256::new();
    hasher.update(b"marmot-cgka-conformance-key-package-event-id-v1");
    hasher.update(key_package.bytes());
    KeyPackage::with_source_event_id(
        key_package.bytes().to_vec(),
        MessageId::new(hasher.finalize().to_vec()),
    )
}

#[derive(Clone)]
struct NostrAccountIdentityProofSigner {
    keys: nostr::Keys,
}

impl AccountIdentityProofSigner for NostrAccountIdentityProofSigner {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if self.keys.public_key().to_bytes().as_slice() != request.account_identity.as_slice() {
            return Err("request account identity does not match harness Nostr key".into());
        }
        let message = nostr::secp256k1::Message::from_digest(request.signing_digest());
        Ok(self.keys.sign_schnorr(&message).serialize())
    }
}

pub(crate) fn logical_label_for_member_id(bytes: &[u8]) -> Option<String> {
    logical_identity_labels()
        .lock()
        .expect("logical identity label registry lock")
        .get(bytes)
        .cloned()
}

fn register_logical_identity(seed: &[u8], identity: &[u8]) {
    let Some(label) = logical_label_from_seed(seed) else {
        return;
    };
    logical_identity_labels()
        .lock()
        .expect("logical identity label registry lock")
        .insert(identity.to_vec(), label);
}

fn logical_identity_labels() -> &'static Mutex<HashMap<Vec<u8>, String>> {
    static LABELS: OnceLock<Mutex<HashMap<Vec<u8>, String>>> = OnceLock::new();
    LABELS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn logical_label_from_seed(seed: &[u8]) -> Option<String> {
    let end = seed
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |i| i + 1);
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&seed[..end])
        .ok()
        .filter(|label| !label.is_empty())
        .map(str::to_owned)
}

impl HarnessClient {
    pub fn storage(&self) -> &SqliteAccountStorage {
        &self.storage
    }

    pub fn restart(&mut self) {
        let peeler = NostrMlsPeeler::new().with_welcome_signer(self.signer.clone());
        let mut engine = EngineBuilder::new(self.storage.clone())
            .identity(self.identity.clone())
            .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner {
                keys: self.signer.clone(),
            }))
            .feature_registry(self.registry.clone())
            .supported_app_components(harness_supported_app_components())
            .peeler(Box::new(peeler))
            .build()
            .expect("engine rebuilds");
        engine
            .hydrate_stable_groups_from_storage()
            .expect("engine hydrates from storage");
        self.engine = engine;
        self.pending_events.clear();
    }

    pub fn member_id(&self) -> MemberId {
        self.engine.self_id()
    }

    pub async fn fresh_key_package(&mut self) -> KeyPackage {
        let key_package = self.engine.fresh_key_package().await.expect("kp");
        key_package_with_harness_source(key_package)
    }

    /// Create a new group with the given members + features.
    pub async fn create_group(
        &mut self,
        name: &str,
        invitees: Vec<KeyPackage>,
        required_features: Vec<cgka_traits::capabilities::Feature>,
    ) -> (GroupId, PendingStateRef) {
        self.create_group_with_admins(name, invitees, required_features, vec![])
            .await
    }

    /// Variant of `create_group` that lets the test bootstrap a multi-admin
    /// group. The creator is always implicitly an admin; pass additional
    /// member ids in `initial_admins`.
    pub async fn create_group_with_admins(
        &mut self,
        name: &str,
        invitees: Vec<KeyPackage>,
        required_features: Vec<cgka_traits::capabilities::Feature>,
        initial_admins: Vec<MemberId>,
    ) -> (GroupId, PendingStateRef) {
        self.try_create_group_with_admins(name, invitees, required_features, initial_admins)
            .await
            .expect("create_group")
    }

    pub async fn try_create_group_with_admins(
        &mut self,
        name: &str,
        invitees: Vec<KeyPackage>,
        required_features: Vec<cgka_traits::capabilities::Feature>,
        initial_admins: Vec<MemberId>,
    ) -> Result<(GroupId, PendingStateRef), EngineError> {
        let res = self
            .engine
            .create_group(CreateGroupRequest {
                name: name.into(),
                description: "".into(),
                members: invitees,
                required_features,
                app_components: vec![harness_nostr_routing_component(&self.identity, name)],
                initial_admins,
            })
            .await?;
        let (gid, pending, welcomes) = match res {
            (gid, SendResult::GroupCreated { pending, welcomes }) => (gid, pending, welcomes),
            (_, other) => {
                return Err(EngineError::Other(format!(
                    "expected GroupCreated, got {other:?}"
                )));
            }
        };
        for w in welcomes {
            self.bus.send(self.bus_id, w);
        }
        self.default_group = Some(gid.clone());
        Ok((gid, pending))
    }

    /// Confirm a pending publish. Required after every commit-producing
    /// action (create, invite, upgrade) when the simulated transport
    /// "succeeds."
    pub async fn confirm(&mut self, pending: PendingStateRef) {
        self.engine
            .confirm_published(pending)
            .await
            .expect("confirm_published");
    }

    /// Report a publish failure for a pending operation. The engine
    /// discards the staged commit and rewinds to `Stable` at the prior
    /// epoch. Used by the rollback proptest property.
    pub async fn fail(&mut self, pending: PendingStateRef) {
        self.engine
            .publish_failed(pending)
            .await
            .expect("publish_failed");
    }

    /// Issue a `SendIntent::UpgradeCapabilities` for the default group
    /// and bus-broadcast the resulting commit. Returns the
    /// `PendingStateRef` so the test can confirm or fail it.
    pub async fn upgrade(&mut self) -> PendingStateRef {
        let gid = self.default_group.clone().expect("group");
        let res = self
            .engine
            .upgrade_group_capabilities(&gid)
            .await
            .expect("upgrade");
        match res {
            SendResult::GroupEvolution {
                msg,
                welcomes,
                pending,
            } => {
                for w in welcomes {
                    self.bus.send(self.bus_id, w);
                }
                self.bus.send(self.bus_id, route(msg, &gid));
                pending
            }
            other => panic!("expected GroupEvolution from upgrade, got {other:?}"),
        }
    }

    pub async fn update_group_data(&mut self, name: impl Into<String>) -> PendingStateRef {
        let gid = self.default_group.clone().expect("group");
        let res = self
            .engine
            .send(SendIntent::UpdateGroupData {
                group_id: gid.clone(),
                name: Some(name.into()),
                description: None,
            })
            .await
            .expect("update group data");
        match res {
            SendResult::GroupEvolution {
                msg,
                welcomes,
                pending,
            } => {
                assert!(
                    welcomes.is_empty(),
                    "group-data update should not create welcomes"
                );
                self.bus.send(self.bus_id, route(msg, &gid));
                pending
            }
            other => panic!("expected GroupEvolution from update_group_data, got {other:?}"),
        }
    }

    pub async fn update_admin_policy(
        &mut self,
        admins: Vec<MemberId>,
    ) -> Result<PendingStateRef, EngineError> {
        let gid = self.default_group.clone().expect("group");
        let data = encode_admin_policy(admins)?;
        let res = self
            .engine
            .send(SendIntent::UpdateAppComponents {
                group_id: gid.clone(),
                updates: vec![AppComponentData {
                    component_id: GROUP_ADMIN_POLICY_COMPONENT_ID,
                    data,
                }],
            })
            .await?;
        match res {
            SendResult::GroupEvolution {
                msg,
                welcomes,
                pending,
            } => {
                assert!(
                    welcomes.is_empty(),
                    "admin policy update should not create welcomes"
                );
                self.bus.send(self.bus_id, route(msg, &gid));
                Ok(pending)
            }
            other => Err(EngineError::Backend(format!(
                "expected GroupEvolution from update_admin_policy, got {other:?}"
            ))),
        }
    }

    pub fn admin_labels(&self) -> Vec<String> {
        let gid = self.default_group.clone().expect("group");
        self.engine
            .admin_pubkeys(&gid)
            .expect("admin pubkeys")
            .into_iter()
            .map(|admin| logical_label_for_member_id(&admin).unwrap_or_else(|| hex::encode(admin)))
            .collect()
    }

    /// Send an application message and return the wrapped TransportMessage
    /// that was put on the bus. Useful for the same-id-replay proptest
    /// property which needs to re-inject that exact message.
    pub async fn send_app_capture(&mut self, payload: impl Into<Vec<u8>>) -> TransportMessage {
        let gid = self
            .default_group
            .clone()
            .expect("must create or join a group first");
        let payload = self.next_app_payload(payload.into());
        let res = self
            .engine
            .send(SendIntent::AppMessage {
                group_id: gid.clone(),
                payload,
            })
            .await
            .expect("send app");
        match res {
            SendResult::ApplicationMessage { msg } => {
                let routed = route(msg, &gid);
                self.bus.send(self.bus_id, routed.clone());
                routed
            }
            _ => panic!("expected ApplicationMessage"),
        }
    }

    /// Send an application message to the default group.
    pub async fn send_app(&mut self, payload: impl Into<Vec<u8>>) {
        let gid = self
            .default_group
            .clone()
            .expect("must create or join a group first");
        let payload = self.next_app_payload(payload.into());
        let res = self
            .engine
            .send(SendIntent::AppMessage {
                group_id: gid.clone(),
                payload,
            })
            .await
            .expect("send app");
        if let SendResult::ApplicationMessage { msg } = res {
            self.bus.send(self.bus_id, route(msg, &gid));
        } else {
            panic!("expected ApplicationMessage");
        }
    }

    /// Invite new members to the default group.
    pub async fn invite(&mut self, kps: Vec<KeyPackage>) -> PendingStateRef {
        let gid = self.default_group.clone().expect("group");
        let res = self
            .engine
            .send(SendIntent::Invite {
                group_id: gid.clone(),
                key_packages: kps,
            })
            .await
            .expect("send invite");
        match res {
            SendResult::GroupEvolution {
                msg,
                welcomes,
                pending,
            } => {
                // Send welcomes before the commit so new members join via
                // welcome and only then classify the commit echo as
                // AlreadyAtEpoch.
                for w in welcomes {
                    self.bus.send(self.bus_id, w);
                }
                self.bus.send(self.bus_id, route(msg, &gid));
                pending
            }
            other => panic!("expected GroupEvolution, got {other:?}"),
        }
    }

    /// Send a SelfRemove proposal (Leave intent).
    pub async fn leave(&mut self) {
        self.leave_capture().await;
    }

    /// Send a SelfRemove proposal and return the wrapped transport message.
    pub async fn leave_capture(&mut self) -> TransportMessage {
        let gid = self.default_group.clone().expect("group");
        let res = self
            .engine
            .send(SendIntent::Leave {
                group_id: gid.clone(),
            })
            .await
            .expect("send leave");
        if let SendResult::Proposal { msg } = res {
            let routed = route(msg, &gid);
            self.bus.send(self.bus_id, routed.clone());
            routed
        } else {
            panic!("expected Proposal");
        }
    }

    /// Drain the bus mailbox into the engine. Returns ingest outcomes for
    /// each message in order.
    pub async fn tick(&mut self) -> Vec<Result<IngestOutcome, EngineError>> {
        let mut outcomes = self.tick_ingest_only().await;
        if let Some(gid) = self.default_group.clone() {
            match self
                .engine
                .advance_convergence_inputs_until_settled(&gid, 1_000_000)
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    outcomes.push(Err(EngineError::Backend(format!(
                        "converge buffered group: {e}"
                    ))));
                    return outcomes;
                }
            }
            self.capture_engine_events();
        }
        outcomes.extend(self.drain_auto_publish_confirm().await);
        outcomes
    }

    /// Ingest every message in the mailbox without running convergence.
    ///
    /// Production clients defer commit application to a scheduled convergence
    /// pass; this helper models that ingest-only boundary.
    pub async fn tick_ingest_only(&mut self) -> Vec<Result<IngestOutcome, EngineError>> {
        let inbound = self.bus.mailbox(self.bus_id);
        let mut outcomes = Vec::with_capacity(inbound.len());
        for msg in inbound {
            let result = self.engine.ingest(msg).await;
            if result.is_ok() {
                self.capture_engine_events();
            }
            outcomes.push(result);
        }
        outcomes
    }

    /// Override the engine-wide convergence policy (quiescence window, etc.).
    pub fn set_convergence_policy(&mut self, policy: CanonicalizationPolicy) {
        self.engine.set_convergence_policy(policy);
    }

    /// Run the same convergence entry point the app uses after a scheduled
    /// timer (`CgkaEngine::advance_convergence`), then capture emitted events.
    pub async fn advance_convergence(&mut self) -> Result<(), EngineError> {
        let gid = self.default_group.clone().expect("group");
        self.engine.advance_convergence(&gid).await?;
        self.capture_engine_events();
        for result in self.drain_auto_publish_confirm().await {
            result?;
        }
        Ok(())
    }

    /// Model the fixed marmot-app account worker: if a scheduled pass did not
    /// settle stored convergence inputs, wait for the quiescence window (+ the
    /// same schedule margin production uses) and run one retry pass.
    ///
    /// Production re-arms repeatedly until inputs settle; this helper models only
    /// the first re-arm after a premature tick.
    pub async fn advance_convergence_with_app_retry(
        &mut self,
        quiescence_ms: u64,
    ) -> Result<(), EngineError> {
        const SCHEDULE_MARGIN_MS: u64 = 100;
        self.advance_convergence().await?;
        if !self.has_pending_convergence_inputs() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(
            quiescence_ms.saturating_add(SCHEDULE_MARGIN_MS),
        ))
        .await;
        self.advance_convergence().await
    }

    pub fn has_pending_convergence_inputs(&self) -> bool {
        let gid = self.default_group.clone().expect("group");
        self.engine
            .has_pending_convergence_inputs(&gid)
            .expect("pending convergence probe")
    }

    pub fn received_app_payloads(&mut self) -> Vec<Vec<u8>> {
        self.capture_engine_events();
        self.pending_events
            .iter()
            .filter_map(|event| match event {
                GroupEvent::MessageReceived { payload, .. } => {
                    Some(decode_harness_app_payload(payload))
                }
                _ => None,
            })
            .collect()
    }

    async fn drain_auto_publish_confirm(&mut self) -> Vec<Result<IngestOutcome, EngineError>> {
        let mut outcomes = Vec::new();
        let auto = self.engine.drain_auto_publish();
        let gid = self.default_group.clone();
        for auto in auto {
            let routed = if let Some(gid) = &gid {
                route(auto.msg, gid)
            } else {
                auto.msg
            };
            self.bus.send(self.bus_id, routed);
            if let Err(e) = self.engine.confirm_published(auto.pending).await {
                outcomes.push(Err(e));
                continue;
            }
            self.capture_engine_events();
        }
        outcomes
    }

    pub fn drain_events(&mut self) -> Vec<GroupEvent> {
        self.capture_engine_events();
        std::mem::take(&mut self.pending_events)
    }

    pub fn epoch(&self) -> EpochId {
        let gid = self.default_group.clone().expect("group");
        self.engine.epoch(&gid).expect("epoch")
    }

    pub fn members(&self) -> Vec<cgka_traits::group::Member> {
        let gid = self.default_group.clone().expect("group");
        self.engine.members(&gid).expect("members")
    }

    /// Current app-facing group name mirrored from signed group-profile state.
    ///
    /// This is a branch-sensitive observable: a `marmot.group.profile.v1`
    /// (`UpdateGroupData`) commit changes only the group name/description, which
    /// epoch and member-count observations cannot distinguish. Two clients stuck
    /// on different competing group-data branches share the same epoch and member
    /// count but observe different names, so convergence oracles compare this to
    /// catch a permanent fork that epoch/member equality alone would miss.
    pub fn group_name(&self) -> String {
        let gid = self.default_group.clone().expect("group");
        self.engine.group_record(&gid).expect("group record").name
    }

    pub fn group_id(&self) -> GroupId {
        self.default_group.clone().expect("group")
    }

    fn next_app_payload(&mut self, payload: Vec<u8>) -> Vec<u8> {
        let seq = self.app_event_counter;
        self.app_event_counter = self
            .app_event_counter
            .checked_add(1)
            .expect("app event counter exhausted");
        encode_harness_app_payload(&self.engine.self_id(), seq, payload)
    }

    /// Return a clone of `msg` whose payload is the peeled MLS wire bytes.
    ///
    /// This keeps replay/projection tests honest about the transport boundary:
    /// harness delivery still uses Nostr-shaped events, while OpenMLS probes
    /// receive the same bytes the engine sees after peeling.
    pub async fn openmls_projection_message(
        &self,
        msg: &TransportMessage,
    ) -> Result<TransportMessage, String> {
        let group_id = match &msg.envelope {
            TransportEnvelope::GroupMessage { .. } => self
                .default_group
                .clone()
                .ok_or_else(|| "must create or join a group first".to_owned())?,
            TransportEnvelope::Welcome { .. } => {
                return Err("welcomes do not carry MLS group-message bytes".into());
            }
        };
        let ctx = self
            .engine
            .group_context(&group_id)
            .map_err(|e| format!("group context: {e}"))?;
        let snapshot = GroupContextSnapshot::from_context(
            ctx.as_ref(),
            &[transport_nostr_peeler::DEFAULT_EXPORTER_LABEL],
        );
        let peeled = NostrMlsPeeler::default()
            .peel_group_message(msg, &snapshot)
            .await
            .map_err(|e| format!("peel group message: {e}"))?;
        match peeled.content {
            PeeledContent::MlsMessage { bytes } => Ok(TransportMessage {
                payload: bytes,
                ..msg.clone()
            }),
            PeeledContent::Welcome { .. } => Err("group peeler returned a welcome".into()),
        }
    }
}

impl HarnessClient {
    fn capture_engine_events(&mut self) {
        for event in self.engine.drain_events() {
            if let GroupEvent::GroupJoined { group_id, .. } = &event
                && self.default_group.is_none()
            {
                self.default_group = Some(group_id.clone());
            }
            self.pending_events.push(event);
        }
    }
}

pub fn encode_harness_app_payload(sender: &MemberId, sequence: u64, payload: Vec<u8>) -> Vec<u8> {
    let (content, tags) = match String::from_utf8(payload) {
        Ok(content) => (content, Vec::new()),
        Err(err) => (
            hex::encode(err.into_bytes()),
            vec![vec![
                "harness-payload-encoding".to_owned(),
                "hex".to_owned(),
            ]],
        ),
    };
    MarmotAppEvent::new(
        hex::encode(sender.as_slice()),
        1_700_000_000 + sequence,
        MARMOT_APP_EVENT_KIND_CHAT,
        tags,
        content,
    )
    .encode()
    .expect("harness app event encodes")
}

pub fn decode_harness_app_payload(payload: &[u8]) -> Vec<u8> {
    let Ok(event) = MarmotAppEvent::decode(payload) else {
        return payload.to_vec();
    };
    if event
        .tags
        .iter()
        .any(|tag| tag.as_slice() == ["harness-payload-encoding", "hex"])
        && let Ok(bytes) = hex::decode(&event.content)
    {
        return bytes;
    }
    event.content.into_bytes()
}

fn route(msg: TransportMessage, _gid: &GroupId) -> TransportMessage {
    msg
}

fn encode_admin_policy(admins: Vec<MemberId>) -> Result<Vec<u8>, EngineError> {
    let mut admins = admins
        .into_iter()
        .map(|admin| {
            let bytes = admin.as_slice();
            let admin: [u8; 32] = bytes.try_into().map_err(|_| {
                EngineError::Other(format!(
                    "admin policy requires 32-byte member identities; got {}",
                    bytes.len()
                ))
            })?;
            Ok(admin)
        })
        .collect::<Result<Vec<_>, EngineError>>()?;
    admins.sort();
    admins.dedup();

    let mut admin_bytes = Vec::with_capacity(admins.len() * 32);
    for admin in admins {
        admin_bytes.extend_from_slice(&admin);
    }
    let mut out = Vec::new();
    cgka_traits::app_components::encode_quic_varint(admin_bytes.len() as u64, &mut out);
    out.extend_from_slice(&admin_bytes);
    Ok(out)
}
