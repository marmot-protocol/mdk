//! `HarnessClient` — wraps an `Engine<SqliteAccountStorage>` + Nostr peeler + bus
//! attachment. Provides scenario-level affordances: `send`, `tick`,
//! `confirm_all_pending`, `assert_at_epoch`.

use crate::audit_capture::{AuditCapture, CapturingRecorder};
use crate::bus::{ClientId, TransportBus};
use crate::decryptability::DecryptabilityProbeSendStatus;
use crate::pending_work::PendingWorkObservation;
use crate::scenario_input_ledger::{
    ScenarioInputKind, ScenarioInputLedgerEntry, ScenarioInputMetadata, ScenarioInputTracker,
};
use cgka_engine::account_identity_proof::{
    AccountIdentityProofRequest, AccountIdentityProofSigner,
};
use cgka_engine::canonicalization::{CanonicalizationPolicy, CanonicalizationResult};
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
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, PeeledContent};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{ConvergencePassStorage, MessageStorage, StorageProvider};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use cgka_traits::{ConvergenceCutoffCause, ConvergencePassPhase, DurableConvergencePass};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage, SqliteStorageOptions};
use transport_nostr_peeler::NostrMlsPeeler;

const STORAGE_MODE_ENV: &str = "MDK_CONFORMANCE_SQLITE_STORAGE";
const TEMP_FILE_KEY: &str = "marmot-conformance-sqlite-temp-key";
const HARNESS_CONVERGENCE_SETTLED_AT_MS: u64 = 1_000_000;
const HARNESS_CONVERGENCE_DRAIN_PASSES: usize = 8;

pub struct HarnessClient {
    engine: Option<Engine<SqliteAccountStorage>>,
    pub bus_id: ClientId,
    bus: TransportBus,
    storage: Option<SqliteAccountStorage>,
    storage_backing: HarnessStorageBacking,
    identity: Vec<u8>,
    signer: nostr::Keys,
    registry: FeatureRegistry,
    protocol_profile: ProtocolProfile,
    pending_events: Vec<GroupEvent>,
    /// Default MLS group id used by single-group scenarios. Set
    /// automatically after the first create/join.
    default_group: Option<GroupId>,
    app_event_counter: u64,
    scenario_input_counter: u64,
    next_scenario_input_id: Option<String>,
    scenario_input_tracker: ScenarioInputTracker,
    pending_scenario_inputs: HashMap<PendingStateRef, String>,
    /// Shared in-memory capture of the engine's forensic audit events, used to
    /// observe decisions no `GroupEvent` exposes (e.g. `convergence_decision`).
    audit_capture: AuditCapture,
    convergence_checkpoints: HashMap<String, (GroupId, DurableConvergencePass)>,
}

pub struct ClientBuilder {
    identity: Vec<u8>,
    signer: nostr::Keys,
    registry: FeatureRegistry,
    protocol_profile: ProtocolProfile,
    storage_mode: HarnessStorageMode,
    storage_options: SqliteStorageOptions,
    explicit_file_storage: Option<ExplicitFileStorage>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HarnessStorageMode {
    InMemorySqlite,
    TempFileBackedSqlite,
}

impl HarnessStorageMode {
    pub fn from_env() -> Self {
        match std::env::var(STORAGE_MODE_ENV) {
            Ok(value) => Self::parse(&value).unwrap_or_else(|err| panic!("{err}")),
            Err(_) => Self::InMemorySqlite,
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "file" | "file-backed" | "tempfile" => Ok(Self::TempFileBackedSqlite),
            "memory" | "in-memory" | "sqlite-memory" => Ok(Self::InMemorySqlite),
            _ => Err(format!(
                "{STORAGE_MODE_ENV} and --storage must be one of memory, in-memory, sqlite-memory, file, file-backed, or tempfile; got {value:?}"
            )),
        }
    }

    pub fn report_label(self) -> &'static str {
        match self {
            Self::InMemorySqlite => "in-memory-sqlite",
            Self::TempFileBackedSqlite => "encrypted-file-sqlite",
        }
    }
}

struct ExplicitFileStorage {
    path: PathBuf,
    key: SqlCipherKey,
    options: SqliteStorageOptions,
}

enum HarnessStorageBacking {
    InMemory,
    FileBacked {
        _storage_dir: Option<tempfile::TempDir>,
        path: PathBuf,
        key: SqlCipherKey,
        options: SqliteStorageOptions,
    },
}

impl HarnessStorageBacking {
    fn from_mode(mode: HarnessStorageMode, options: SqliteStorageOptions) -> Result<Self, String> {
        match mode {
            HarnessStorageMode::InMemorySqlite => Ok(Self::InMemory),
            HarnessStorageMode::TempFileBackedSqlite => {
                let storage_dir = tempfile::tempdir().map_err(|err| err.to_string())?;
                let path = storage_dir.path().join("client.sqlite3");
                let key = SqlCipherKey::new(TEMP_FILE_KEY).map_err(|err| err.to_string())?;
                Ok(Self::FileBacked {
                    _storage_dir: Some(storage_dir),
                    path,
                    key,
                    options,
                })
            }
        }
    }

    fn from_explicit(explicit: ExplicitFileStorage) -> Self {
        Self::FileBacked {
            _storage_dir: None,
            path: explicit.path,
            key: explicit.key,
            options: explicit.options,
        }
    }

    fn open(&self) -> Result<SqliteAccountStorage, String> {
        match self {
            Self::InMemory => SqliteAccountStorage::in_memory().map_err(|err| err.to_string()),
            Self::FileBacked {
                path, key, options, ..
            } => SqliteAccountStorage::open_encrypted_with_options(path, key, options.clone())
                .map_err(|err| err.to_string()),
        }
    }

    fn is_file_backed(&self) -> bool {
        matches!(self, Self::FileBacked { .. })
    }

    fn database_path(&self) -> Option<&Path> {
        match self {
            Self::InMemory => None,
            Self::FileBacked { path, .. } => Some(path),
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
            protocol_profile: ProtocolProfile::Legacy,
            storage_mode: HarnessStorageMode::from_env(),
            storage_options: SqliteStorageOptions::default(),
            explicit_file_storage: None,
        }
    }

    pub fn registry(mut self, r: FeatureRegistry) -> Self {
        self.registry = r;
        self
    }

    pub fn storage_mode(mut self, mode: HarnessStorageMode) -> Self {
        self.storage_mode = mode;
        self.explicit_file_storage = None;
        self
    }

    pub fn storage_options(mut self, options: SqliteStorageOptions) -> Self {
        self.storage_options = options;
        self
    }

    pub fn file_backed_storage(
        mut self,
        path: impl Into<PathBuf>,
        key: SqlCipherKey,
        options: SqliteStorageOptions,
    ) -> Self {
        self.storage_mode = HarnessStorageMode::TempFileBackedSqlite;
        self.explicit_file_storage = Some(ExplicitFileStorage {
            path: path.into(),
            key,
            options,
        });
        self
    }

    pub fn protocol_profile(mut self, profile: ProtocolProfile) -> Self {
        self.protocol_profile = profile;
        self
    }

    pub fn attach(self, bus: &TransportBus) -> HarnessClient {
        let storage_backing = match self.explicit_file_storage {
            Some(explicit) => HarnessStorageBacking::from_explicit(explicit),
            None => HarnessStorageBacking::from_mode(self.storage_mode, self.storage_options)
                .expect("storage backing opens"),
        };
        let storage = storage_backing.open().expect("storage opens");
        let audit_capture = AuditCapture::default();
        let engine = build_harness_engine(
            &storage,
            &self.identity,
            &self.signer,
            &self.registry,
            self.protocol_profile,
            &audit_capture,
        );
        let bus_id = bus.attach(MemberId::new(self.identity.clone()));
        HarnessClient {
            engine: Some(engine),
            bus_id,
            bus: bus.clone(),
            storage: Some(storage),
            storage_backing,
            identity: self.identity,
            signer: self.signer,
            registry: self.registry,
            protocol_profile: self.protocol_profile,
            pending_events: Vec::new(),
            default_group: None,
            app_event_counter: 0,
            scenario_input_counter: 0,
            next_scenario_input_id: None,
            scenario_input_tracker: ScenarioInputTracker::default(),
            pending_scenario_inputs: HashMap::new(),
            audit_capture,
            convergence_checkpoints: HashMap::new(),
        }
    }
}

/// Build an engine wired the way every harness client needs it, including the
/// [`CapturingRecorder`] that retains forensic events. `attach` and `restart`
/// both go through here so a rebuilt engine keeps recording into the same shared
/// buffer — otherwise a restart would silently drop captured decisions.
fn build_harness_engine(
    storage: &SqliteAccountStorage,
    identity: &[u8],
    signer: &nostr::Keys,
    registry: &FeatureRegistry,
    protocol_profile: ProtocolProfile,
    audit_capture: &AuditCapture,
) -> Engine<SqliteAccountStorage> {
    let peeler = NostrMlsPeeler::new().with_welcome_signer(signer.clone());
    let mut builder = EngineBuilder::new(storage.clone())
        .identity(identity.to_vec())
        .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner {
            keys: signer.clone(),
        }))
        .protocol_profile(protocol_profile)
        .feature_registry(registry.clone())
        .supported_app_components(harness_supported_app_components())
        .peeler(Box::new(peeler))
        .recorder(Box::new(CapturingRecorder::new(audit_capture.clone())));
    if protocol_profile == ProtocolProfile::Legacy {
        builder = builder.legacy_compatibility_profile();
    }
    builder.build().expect("engine builds")
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
    let protocol_profile = key_package.protocol_profile;
    KeyPackage::with_source_event_id(
        key_package.bytes().to_vec(),
        MessageId::new(hasher.finalize().to_vec()),
    )
    .with_protocol_profile(protocol_profile)
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
        let event = request.proof_event().and_then(|event| {
            event
                .sign_with_keys(&self.keys)
                .map_err(|err| err.to_string())
        })?;
        request.signature_from_signed_event(event)
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
    pub fn engine(&self) -> &Engine<SqliteAccountStorage> {
        self.engine.as_ref().expect("harness engine is available")
    }

    pub fn engine_mut(&mut self) -> &mut Engine<SqliteAccountStorage> {
        self.engine.as_mut().expect("harness engine is available")
    }

    pub fn storage(&self) -> &SqliteAccountStorage {
        self.storage.as_ref().expect("harness storage is available")
    }

    pub fn database_path(&self) -> Option<&Path> {
        self.storage_backing.database_path()
    }

    pub fn restart(&mut self) {
        drop(self.engine.take());
        let storage = if self.storage_backing.is_file_backed() {
            drop(self.storage.take());
            self.storage_backing.open().expect("file storage reopens")
        } else {
            self.storage().clone()
        };
        let mut engine = build_harness_engine(
            &storage,
            &self.identity,
            &self.signer,
            &self.registry,
            self.protocol_profile,
            &self.audit_capture,
        );
        engine
            .hydrate_stable_groups_from_storage()
            .expect("engine hydrates from storage");
        self.storage = Some(storage);
        self.engine = Some(engine);
        self.pending_events.clear();
    }

    /// Freeze the current durable pass at its quiescence boundary. This is a
    /// harness-level restart fault operation; scenarios should not reach into
    /// engine storage to manufacture the boundary themselves.
    pub fn freeze_convergence_pass(&mut self, group_id: &GroupId) {
        let mut pass = self
            .storage()
            .convergence_pass(group_id)
            .expect("load durable convergence pass")
            .expect("durable convergence pass exists");
        pass.phase = ConvergencePassPhase::Frozen;
        pass.cutoff_cause = Some(ConvergenceCutoffCause::Quiescence);
        pass.frozen_at_wall_ms = Some(pass.quiescence_deadline_wall_ms);
        self.storage()
            .put_convergence_pass(&pass)
            .expect("persist frozen convergence pass");
    }

    /// Snapshot group state and separately retain the pass row, which group
    /// epoch snapshots intentionally exclude.
    pub fn checkpoint_convergence(&mut self, group_id: &GroupId, name: &str) {
        let pass = self
            .storage()
            .convergence_pass(group_id)
            .expect("load convergence pass for checkpoint")
            .expect("checkpoint requires a convergence pass");
        self.storage()
            .create_group_snapshot(group_id, name)
            .expect("create convergence group snapshot");
        self.convergence_checkpoints
            .insert(name.to_owned(), (group_id.clone(), pass));
    }

    /// Restore a harness convergence checkpoint, including the pass row omitted
    /// from the group epoch snapshot, then rebuild the engine over the restored
    /// durable state.
    pub fn restore_convergence_checkpoint(&mut self, name: &str) {
        let (group_id, pass) = self
            .convergence_checkpoints
            .get(name)
            .cloned()
            .expect("convergence checkpoint exists");
        self.storage()
            .with_transaction(|storage| {
                storage.rollback_group_to_snapshot(&group_id, name)?;
                storage.put_convergence_pass(&pass)
            })
            .expect("atomically restore convergence checkpoint");
        self.restart();
    }

    pub fn converge_stored_at(
        &mut self,
        group_id: &GroupId,
        now_ms: u64,
    ) -> CanonicalizationResult {
        self.engine_mut()
            .converge_stored_openmls_messages(group_id, now_ms)
            .expect("stored convergence succeeds")
    }

    /// Drain the `convergence_decision` events the engine has emitted since the
    /// last call.
    ///
    /// The engine surfaces these only through its forensic recorder, so — unlike
    /// fork recoveries — no `GroupEvent` carries them and [`Self::drain_events`]
    /// never sees them. Returns them oldest-first; other captured audit records
    /// are left in place.
    pub fn drain_convergence_decisions(&mut self) -> Vec<marmot_forensics::AuditEventKind> {
        crate::audit_capture::drain_convergence_decisions(&self.audit_capture)
    }

    /// Discard captured convergence decisions, resetting the observation window.
    /// Mirrors what `ScenarioStep::ClearEvents` does for `GroupEvent`s so a
    /// scenario can isolate a decision that happens after setup.
    pub fn clear_audit_capture(&mut self) {
        crate::audit_capture::clear(&self.audit_capture);
    }

    pub fn member_id(&self) -> MemberId {
        self.engine().self_id()
    }

    /// Assign the stable synthetic id consumed by the next commit, proposal, or
    /// application input this client produces.
    pub fn name_next_scenario_input(&mut self, scenario_id: impl Into<String>) {
        assert!(
            self.next_scenario_input_id.is_none(),
            "previous scenario input id was not consumed"
        );
        self.next_scenario_input_id = Some(scenario_id.into());
    }

    pub async fn fresh_key_package(&mut self) -> KeyPackage {
        let key_package = self.engine_mut().fresh_key_package().await.expect("kp");
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
        let (group_id, pending) = self
            .try_create_group_with_admins_maybe_pending(
                name,
                invitees,
                required_features,
                initial_admins,
            )
            .await?;
        pending.map(|pending| (group_id, pending)).ok_or_else(|| {
            EngineError::Other("current founding creation has no pending state".into())
        })
    }

    pub async fn create_group_with_admins_maybe_pending(
        &mut self,
        name: &str,
        invitees: Vec<KeyPackage>,
        required_features: Vec<cgka_traits::capabilities::Feature>,
        initial_admins: Vec<MemberId>,
    ) -> (GroupId, Option<PendingStateRef>) {
        self.try_create_group_with_admins_maybe_pending(
            name,
            invitees,
            required_features,
            initial_admins,
        )
        .await
        .expect("create_group")
    }

    async fn try_create_group_with_admins_maybe_pending(
        &mut self,
        name: &str,
        invitees: Vec<KeyPackage>,
        required_features: Vec<cgka_traits::capabilities::Feature>,
        initial_admins: Vec<MemberId>,
    ) -> Result<(GroupId, Option<PendingStateRef>), EngineError> {
        let routing_component = harness_nostr_routing_component(&self.identity, name);
        let res = self
            .engine_mut()
            .create_group(CreateGroupRequest {
                name: name.into(),
                description: "".into(),
                members: invitees,
                required_features,
                app_components: vec![routing_component],
                initial_admins,
            })
            .await?;
        let (gid, pending, welcomes) = match res {
            (gid, SendResult::GroupCreated { pending, welcomes }) => (gid, Some(pending), welcomes),
            (gid, SendResult::FoundingGroupCreated { welcomes }) => (gid, None, welcomes),
            (_, other) => {
                return Err(EngineError::Other(format!(
                    "expected group creation result, got {other:?}"
                )));
            }
        };
        for w in welcomes {
            self.bus.send(self.bus_id, w);
        }
        self.default_group = Some(gid.clone());
        if pending.is_none() {
            self.capture_engine_events();
        }
        Ok((gid, pending))
    }

    /// Confirm a pending publish. Required after every commit-producing
    /// action (create, invite, upgrade) when the simulated transport
    /// "succeeds."
    pub async fn confirm(&mut self, pending: PendingStateRef) {
        self.try_confirm(pending).await.expect("confirm_published");
    }

    async fn try_confirm(&mut self, pending: PendingStateRef) -> Result<(), EngineError> {
        self.engine_mut().confirm_published(pending).await?;
        if let Some(scenario_id) = self.pending_scenario_inputs.remove(&pending) {
            self.scenario_input_tracker.record_confirmed(&scenario_id);
        }
        Ok(())
    }

    /// Report a publish failure for a pending operation. The engine
    /// discards the staged commit and rewinds to `Stable` at the prior
    /// epoch. Used by the rollback proptest property.
    pub async fn fail(&mut self, pending: PendingStateRef) {
        self.engine_mut()
            .publish_failed(pending)
            .await
            .expect("publish_failed");
        if let Some(scenario_id) = self.pending_scenario_inputs.remove(&pending) {
            self.scenario_input_tracker.record_rolled_back(&scenario_id);
        }
    }

    /// Issue a `SendIntent::UpgradeCapabilities` for the default group
    /// and bus-broadcast the resulting commit. Returns the
    /// `PendingStateRef` so the test can confirm or fail it.
    pub async fn upgrade(&mut self) -> PendingStateRef {
        let gid = self.default_group.clone().expect("group");
        let res = self
            .engine_mut()
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
                let routed = route(msg, &gid);
                self.publish_commit_scenario_input(&routed, pending).await;
                self.bus.send(self.bus_id, routed);
                pending
            }
            other => panic!("expected GroupEvolution from upgrade, got {other:?}"),
        }
    }

    pub async fn update_group_data(&mut self, name: impl Into<String>) -> PendingStateRef {
        let gid = self.default_group.clone().expect("group");
        let res = self
            .engine_mut()
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
                let routed = route(msg, &gid);
                self.publish_commit_scenario_input(&routed, pending).await;
                self.bus.send(self.bus_id, routed);
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
            .engine_mut()
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
                let routed = route(msg, &gid);
                self.publish_commit_scenario_input(&routed, pending).await;
                self.bus.send(self.bus_id, routed);
                Ok(pending)
            }
            other => Err(EngineError::Backend(format!(
                "expected GroupEvolution from update_admin_policy, got {other:?}"
            ))),
        }
    }

    pub fn admin_labels(&self) -> Vec<String> {
        let gid = self.default_group.clone().expect("group");
        self.engine()
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
        let (logical_id, logical_payload) = logical_message_fields(&payload);
        let scenario_input = self.next_scenario_input_metadata(
            ScenarioInputKind::Application,
            Some(logical_id),
            Some(logical_payload),
        );
        self.scenario_input_tracker
            .record_send_attempt(&scenario_input);
        let res = self
            .engine_mut()
            .send(SendIntent::AppMessage {
                group_id: gid.clone(),
                payload,
            })
            .await
            .expect("send app");
        match res {
            SendResult::ApplicationMessage { msg, .. } => {
                self.scenario_input_tracker
                    .record_send_accepted(&scenario_input, false);
                let routed = route(msg, &gid);
                self.register_published_scenario_input(&routed, scenario_input)
                    .await;
                self.bus.send(self.bus_id, routed.clone());
                routed
            }
            _ => panic!("expected ApplicationMessage"),
        }
    }

    /// Send an application message to the default group.
    pub async fn send_app(&mut self, payload: impl Into<Vec<u8>>) {
        let _ = self
            .try_send_app(payload)
            .await
            .expect("send app message through harness");
    }

    pub async fn request_disband(&mut self) -> Result<(), EngineError> {
        let group_id = self.default_group.clone().expect("group");
        match self
            .engine_mut()
            .send(SendIntent::Disband { group_id })
            .await?
        {
            SendResult::DisbandRequested { .. } => Ok(()),
            other => Err(EngineError::Backend(format!(
                "expected DisbandRequested, got {other:?}"
            ))),
        }
    }

    pub(crate) async fn try_send_app(
        &mut self,
        payload: impl Into<Vec<u8>>,
    ) -> Result<(DecryptabilityProbeSendStatus, String), EngineError> {
        let gid = self
            .default_group
            .clone()
            .ok_or_else(|| EngineError::Other("must create or join a group first".into()))?;
        let payload = self.next_app_payload(payload.into());
        let (logical_id, logical_payload) = logical_message_fields(&payload);
        let scenario_input = self.next_scenario_input_metadata(
            ScenarioInputKind::Application,
            Some(logical_id.clone()),
            Some(logical_payload),
        );
        self.scenario_input_tracker
            .record_send_attempt(&scenario_input);
        let res = self
            .engine_mut()
            .send(SendIntent::AppMessage {
                group_id: gid.clone(),
                payload,
            })
            .await?;
        match res {
            SendResult::ApplicationMessage { msg, .. } => {
                self.scenario_input_tracker
                    .record_send_accepted(&scenario_input, false);
                let routed = route(msg, &gid);
                self.register_published_scenario_input(&routed, scenario_input)
                    .await;
                self.bus.send(self.bus_id, routed);
                Ok((DecryptabilityProbeSendStatus::Published, logical_id))
            }
            SendResult::Queued { .. } => {
                self.scenario_input_tracker
                    .record_send_accepted(&scenario_input, true);
                Ok((DecryptabilityProbeSendStatus::Queued, logical_id))
            }
            other => Err(EngineError::Backend(format!(
                "expected ApplicationMessage or Queued, got {other:?}"
            ))),
        }
    }

    /// Invite new members to the default group.
    pub async fn invite(&mut self, kps: Vec<KeyPackage>) -> PendingStateRef {
        self.try_invite(kps).await.expect("send invite")
    }

    /// Invite new members to the default group, surfacing the engine error
    /// instead of panicking. Nothing reaches the bus on failure. Used by
    /// scenarios that deliberately fail an invite during commit staging
    /// (e.g. the phantom committed-from regression).
    pub async fn try_invite(
        &mut self,
        kps: Vec<KeyPackage>,
    ) -> Result<PendingStateRef, EngineError> {
        let gid = self.default_group.clone().expect("group");
        let res = self
            .engine_mut()
            .send(SendIntent::Invite {
                group_id: gid.clone(),
                key_packages: kps,
            })
            .await?;
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
                let routed = route(msg, &gid);
                self.publish_commit_scenario_input(&routed, pending).await;
                self.bus.send(self.bus_id, routed);
                Ok(pending)
            }
            other => Err(EngineError::Other(format!(
                "expected GroupEvolution, got {other:?}"
            ))),
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
            .engine_mut()
            .send(SendIntent::Leave {
                group_id: gid.clone(),
            })
            .await
            .expect("send leave");
        if let SendResult::Proposal { msg } = res {
            let scenario_input =
                self.next_scenario_input_metadata(ScenarioInputKind::Proposal, None, None);
            self.scenario_input_tracker
                .record_send_attempt(&scenario_input);
            self.scenario_input_tracker
                .record_send_accepted(&scenario_input, false);
            let routed = route(msg, &gid);
            self.register_published_scenario_input(&routed, scenario_input)
                .await;
            self.bus.send(self.bus_id, routed.clone());
            routed
        } else {
            panic!("expected Proposal");
        }
    }

    /// Drain the bus mailbox into the engine and simulate due convergence
    /// timer work. Returns ingest outcomes for each message in order.
    pub async fn tick(&mut self) -> Vec<Result<IngestOutcome, EngineError>> {
        let mut outcomes = self.tick_ingest_only().await;
        if let Some(gid) = self.default_group.clone() {
            match self
                .engine_mut()
                .advance_convergence_inputs_until_settled(&gid, HARNESS_CONVERGENCE_SETTLED_AT_MS)
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
        self.drive_due_convergence(&mut outcomes).await;
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
            let scenario_input = self.bus.scenario_input_for_transport(&msg.id);
            let result = self.engine_mut().ingest(msg).await;
            if let Some(scenario_input) = scenario_input {
                self.scenario_input_tracker
                    .record_ingest(&scenario_input, result.as_ref().map_err(|_| ()));
            }
            if result.is_ok() {
                self.capture_engine_events();
            }
            outcomes.push(result);
        }
        outcomes
    }

    /// Override the engine-wide convergence policy (quiescence window, etc.).
    ///
    /// Debug/test harness escape hatch; release builds reject non-v1 policies.
    pub fn set_convergence_policy(&mut self, policy: CanonicalizationPolicy) {
        self.engine_mut()
            .set_convergence_policy(policy)
            .expect("convergence policy accepted");
    }

    /// Run the same convergence entry point the app uses after a scheduled
    /// timer (`CgkaEngine::advance_convergence`), then capture emitted events.
    pub async fn advance_convergence(&mut self) -> Result<(), EngineError> {
        let gid = self.default_group.clone().expect("group");
        let results = self.engine_mut().advance_convergence(&gid).await?;
        self.capture_engine_events();
        for result in results {
            self.publish_send_result(result).await?;
        }
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
        self.engine()
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

    async fn drive_due_convergence(
        &mut self,
        outcomes: &mut Vec<Result<IngestOutcome, EngineError>>,
    ) {
        for _ in 0..HARNESS_CONVERGENCE_DRAIN_PASSES {
            let groups = self.engine_mut().drain_pending_convergence_groups();
            if groups.is_empty() {
                return;
            }
            for group_id in groups {
                let results = match self
                    .engine_mut()
                    .converge_and_drain_queued_outbound_intents(
                        &group_id,
                        HARNESS_CONVERGENCE_SETTLED_AT_MS,
                    )
                    .await
                {
                    Ok(results) => results,
                    Err(e) => {
                        outcomes.push(Err(e));
                        continue;
                    }
                };
                self.capture_engine_events();
                for result in results {
                    if let Err(e) = self.publish_send_result(result).await {
                        outcomes.push(Err(e));
                    }
                }
                outcomes.extend(self.drain_auto_publish_confirm().await);
            }
        }
        outcomes.push(Err(EngineError::Backend(
            "convergence drain did not settle within harness pass limit".into(),
        )));
    }

    async fn publish_send_result(&mut self, result: SendResult) -> Result<(), EngineError> {
        let gid = self.default_group.clone();
        match result {
            SendResult::ApplicationMessage {
                msg, app_event_id, ..
            } => {
                let routed = if let Some(gid) = &gid {
                    route(msg, gid)
                } else {
                    msg
                };
                let scenario_input = self
                    .scenario_input_tracker
                    .metadata_for_logical(&app_event_id)
                    .ok_or_else(|| {
                        EngineError::Backend(format!(
                            "missing scenario-input metadata for regenerated app event {app_event_id}"
                        ))
                    })?;
                self.register_published_scenario_input(&routed, scenario_input)
                    .await;
                self.bus.send(self.bus_id, routed);
            }
            SendResult::Proposal { msg } => {
                let routed = if let Some(gid) = &gid {
                    route(msg, gid)
                } else {
                    msg
                };
                let scenario_input =
                    self.next_scenario_input_metadata(ScenarioInputKind::Proposal, None, None);
                self.scenario_input_tracker
                    .record_send_attempt(&scenario_input);
                self.scenario_input_tracker
                    .record_send_accepted(&scenario_input, false);
                self.register_published_scenario_input(&routed, scenario_input)
                    .await;
                self.bus.send(self.bus_id, routed);
            }
            SendResult::GroupEvolution {
                msg,
                welcomes,
                pending,
            } => {
                for welcome in welcomes {
                    self.bus.send(self.bus_id, welcome);
                }
                let routed = if let Some(gid) = &gid {
                    route(msg, gid)
                } else {
                    msg
                };
                self.publish_commit_scenario_input(&routed, pending).await;
                self.bus.send(self.bus_id, routed);
                self.try_confirm(pending).await?;
                self.capture_engine_events();
            }
            SendResult::GroupCreated { welcomes, pending } => {
                for welcome in welcomes {
                    self.bus.send(self.bus_id, welcome);
                }
                self.engine_mut().confirm_published(pending).await?;
                self.capture_engine_events();
            }
            SendResult::FoundingGroupCreated { welcomes } => {
                for welcome in welcomes {
                    self.bus.send(self.bus_id, welcome);
                }
                self.capture_engine_events();
            }
            SendResult::NoChange { .. }
            | SendResult::DisbandRequested { .. }
            | SendResult::Queued { .. } => {}
        }
        Ok(())
    }

    async fn drain_auto_publish_confirm(&mut self) -> Vec<Result<IngestOutcome, EngineError>> {
        let mut outcomes = Vec::new();
        let auto = self.engine_mut().drain_auto_publish();
        let gid = self.default_group.clone();
        for auto in auto {
            let routed = if let Some(gid) = &gid {
                route(auto.msg, gid)
            } else {
                auto.msg
            };
            self.publish_commit_scenario_input(&routed, auto.pending)
                .await;
            self.bus.send(self.bus_id, routed);
            if let Err(e) = self.try_confirm(auto.pending).await {
                // A confirmation error is not evidence that the engine rolled
                // back the staged state. Keep the mapping pending so the
                // strict oracle exposes the unresolved publish lifecycle; an
                // actual rollback is recorded only through publish_failed or
                // the corresponding engine event.
                outcomes.push(Err(e));
                continue;
            }
            self.capture_engine_events();
        }
        let proposals = self.engine_mut().drain_auto_proposals();
        for msg in proposals {
            let routed = if let Some(gid) = &gid {
                route(msg, gid)
            } else {
                msg
            };
            let scenario_input =
                self.next_scenario_input_metadata(ScenarioInputKind::Proposal, None, None);
            self.scenario_input_tracker
                .record_send_attempt(&scenario_input);
            self.scenario_input_tracker
                .record_send_accepted(&scenario_input, false);
            self.register_published_scenario_input(&routed, scenario_input)
                .await;
            self.bus.send(self.bus_id, routed);
        }
        outcomes
    }

    pub fn drain_events(&mut self) -> Vec<GroupEvent> {
        self.capture_engine_events();
        std::mem::take(&mut self.pending_events)
    }

    pub fn epoch(&self) -> EpochId {
        let gid = self.default_group.clone().expect("group");
        self.engine().epoch(&gid).expect("epoch")
    }

    pub fn members(&self) -> Vec<cgka_traits::group::Member> {
        let gid = self.default_group.clone().expect("group");
        match self.engine().members(&gid) {
            Ok(members) => members,
            Err(error) => {
                let record = self.engine().group_record(&gid).unwrap_or_else(|_| {
                    panic!("members unavailable without terminal group record: {error}")
                });
                assert!(
                    record.disbanded.is_some(),
                    "members unavailable for non-disbanded group: {error}"
                );
                record.members
            }
        }
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
        self.engine().group_record(&gid).expect("group record").name
    }

    pub fn group_id(&self) -> GroupId {
        self.default_group.clone().expect("group")
    }

    /// Capture the conformance-only canonical state projection for the default
    /// group without exposing the wrapped engine to scenario code.
    pub fn canonical_group_snapshot(
        &self,
    ) -> cgka_engine::conformance_snapshot::ConformanceGroupSnapshot {
        let group_id = self.default_group.clone().expect("group");
        self.engine()
            .conformance_group_snapshot(&group_id)
            .expect("capture canonical group snapshot")
    }

    pub fn canonical_state_snapshot(
        &self,
    ) -> cgka_engine::conformance_snapshot::ConformanceCanonicalStateSnapshot {
        let group_id = self.default_group.clone().expect("group");
        self.engine()
            .conformance_canonical_state_snapshot(&group_id)
            .expect("capture canonical state snapshot")
    }

    pub fn scenario_input_ledger(&mut self) -> Vec<ScenarioInputLedgerEntry> {
        let observed_states = self
            .scenario_input_tracker
            .state_queries()
            .into_iter()
            .map(|(scenario_id, kind, aliases)| {
                let state = self
                    .engine()
                    .conformance_message_state(&aliases)
                    .expect("capture conformance message state");
                (scenario_id, kind, state)
            })
            .collect::<Vec<_>>();
        for (scenario_id, kind, state) in observed_states {
            if let Some(state) = state {
                self.scenario_input_tracker
                    .record_storage_state(&scenario_id, kind, state);
            }
        }
        self.scenario_input_tracker.snapshot()
    }

    pub fn pending_work_observation(&self) -> PendingWorkObservation {
        let group_id = self.default_group.clone().expect("group");
        let engine = self
            .engine()
            .conformance_pending_work_snapshot(&group_id)
            .expect("capture conformance pending work");
        let bus = self.bus.pending_work_snapshot(self.bus_id);
        PendingWorkObservation {
            engine,
            bus_queued_messages: bus.queued_messages,
            bus_delayed_messages: bus.delayed_messages,
            bus_mailbox_messages: bus.mailbox_messages,
            scenario_inputs_pending: self.scenario_input_tracker.pending_count(),
        }
    }

    fn next_app_payload(&mut self, payload: Vec<u8>) -> Vec<u8> {
        let seq = self.app_event_counter;
        self.app_event_counter = self
            .app_event_counter
            .checked_add(1)
            .expect("app event counter exhausted");
        encode_harness_app_payload(&self.engine().self_id(), seq, payload)
    }

    async fn publish_commit_scenario_input(
        &mut self,
        message: &TransportMessage,
        pending: PendingStateRef,
    ) {
        let scenario_input =
            self.next_scenario_input_metadata(ScenarioInputKind::Commit, None, None);
        self.scenario_input_tracker
            .record_send_attempt(&scenario_input);
        self.scenario_input_tracker
            .record_send_accepted(&scenario_input, false);
        let scenario_input = self
            .register_published_scenario_input(message, scenario_input)
            .await;
        self.remember_pending_scenario_input(pending, &scenario_input);
    }

    async fn register_published_scenario_input(
        &mut self,
        message: &TransportMessage,
        mut metadata: ScenarioInputMetadata,
    ) -> ScenarioInputMetadata {
        metadata.aliases = self
            .engine()
            .conformance_message_aliases(&message.id)
            .expect("sender exposes durable scenario-input aliases");
        let content_id = metadata
            .aliases
            .iter()
            .find(|alias| **alias != message.id)
            .cloned()
            .unwrap_or_else(|| message.id.clone());
        self.bus
            .register_scenario_input(message.id.clone(), content_id, metadata.clone());
        self.scenario_input_tracker.record_published(&metadata);
        metadata
    }

    fn next_scenario_input_metadata(
        &mut self,
        kind: ScenarioInputKind,
        logical_id: Option<String>,
        payload: Option<String>,
    ) -> ScenarioInputMetadata {
        let sequence = self.scenario_input_counter;
        self.scenario_input_counter = self
            .scenario_input_counter
            .checked_add(1)
            .expect("scenario input counter exhausted");
        let sender = logical_label_for_member_id(&self.identity)
            .unwrap_or_else(|| hex::encode(&self.identity));
        let scenario_id = self
            .next_scenario_input_id
            .take()
            .unwrap_or_else(|| format!("{sender}/{}-{sequence}", kind.label()));
        ScenarioInputMetadata {
            scenario_id,
            kind,
            sender,
            logical_id,
            payload,
            aliases: Vec::new(),
        }
    }

    fn remember_pending_scenario_input(
        &mut self,
        pending: PendingStateRef,
        metadata: &ScenarioInputMetadata,
    ) {
        self.pending_scenario_inputs
            .insert(pending, metadata.scenario_id.clone());
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
            .engine()
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
        let events = self.engine_mut().drain_events();
        for event in events {
            if let GroupEvent::GroupJoined { group_id, .. } = &event
                && self.default_group.is_none()
            {
                self.default_group = Some(group_id.clone());
            }
            match &event {
                GroupEvent::MessageReceived { payload, .. } => {
                    let (logical_id, _) = logical_message_fields(payload);
                    self.scenario_input_tracker
                        .record_delivered_logical(&logical_id);
                }
                GroupEvent::AppMessageInvalidated {
                    message_id, reason, ..
                } => {
                    if let Some(scenario_input) = self.bus.scenario_input_for_content(message_id) {
                        self.scenario_input_tracker
                            .record_app_invalidated(&scenario_input, *reason);
                    }
                }
                GroupEvent::ForkRecovered {
                    invalidated_commit_id,
                    ..
                } => {
                    if let Some(scenario_input) = self
                        .bus
                        .scenario_input_for_transport(invalidated_commit_id)
                        .or_else(|| self.bus.scenario_input_for_content(invalidated_commit_id))
                    {
                        self.scenario_input_tracker
                            .record_commit_invalidated(&scenario_input, "fork_recovered");
                    }
                }
                GroupEvent::CommitRolledBack {
                    invalidated_commit_id,
                    ..
                } => {
                    if let Some(scenario_input) = self
                        .bus
                        .scenario_input_for_transport(invalidated_commit_id)
                        .or_else(|| self.bus.scenario_input_for_content(invalidated_commit_id))
                    {
                        self.scenario_input_tracker
                            .record_commit_invalidated(&scenario_input, "commit_rolled_back");
                    }
                }
                GroupEvent::GroupStateInvalidated {
                    invalidated_commit_id,
                    ..
                } => {
                    if let Some(scenario_input) = self
                        .bus
                        .scenario_input_for_transport(invalidated_commit_id)
                        .or_else(|| self.bus.scenario_input_for_content(invalidated_commit_id))
                    {
                        self.scenario_input_tracker.record_commit_invalidated(
                            &scenario_input,
                            "group_state_invalidated_superseded",
                        );
                    }
                }
                _ => {}
            }
            self.pending_events.push(event);
        }
    }
}

fn logical_message_fields(payload: &[u8]) -> (String, String) {
    let event = MarmotAppEvent::decode(payload).expect("harness application payload decodes");
    (
        event.id,
        String::from_utf8_lossy(&decode_harness_app_payload(payload)).into_owned(),
    )
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
