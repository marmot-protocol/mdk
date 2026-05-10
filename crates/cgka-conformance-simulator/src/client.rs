//! `HarnessClient` — wraps an `Engine<MemoryStorage>` + Nostr peeler + bus
//! attachment. Provides scenario-level affordances: `send`, `tick`,
//! `confirm_all_pending`, `assert_at_epoch`.

use crate::bus::{ClientId, TransportBus};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::engine::{
    CgkaEngine, CreateGroupRequest, GroupEvent, KeyPackage, SendIntent, SendResult,
};
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::error::EngineError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, PeeledContent};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use storage_memory::MemoryStorage;
use transport_nostr_peeler::NostrMlsPeeler;

pub struct HarnessClient {
    pub engine: Engine<MemoryStorage>,
    pub bus_id: ClientId,
    bus: TransportBus,
    storage: MemoryStorage,
    pending_events: Vec<GroupEvent>,
    /// Default group_id used to set transport_group_id on outbound + inbound
    /// envelopes. Set automatically after the first create/join.
    default_group: Option<GroupId>,
}

pub struct ClientBuilder {
    identity: Vec<u8>,
    signer: nostr::Keys,
    registry: FeatureRegistry,
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
        }
    }

    pub fn registry(mut self, r: FeatureRegistry) -> Self {
        self.registry = r;
        self
    }

    pub fn attach(self, bus: &TransportBus) -> HarnessClient {
        let storage = MemoryStorage::new();
        let peeler =
            NostrMlsPeeler::new(self.signer.public_key().to_hex()).with_welcome_signer(self.signer);
        let engine = EngineBuilder::new(storage.clone())
            .identity(self.identity.clone())
            .feature_registry(self.registry)
            .peeler(Box::new(peeler))
            .build()
            .expect("engine builds");
        let bus_id = bus.attach(MemberId::new(self.identity));
        HarnessClient {
            engine,
            bus_id,
            bus: bus.clone(),
            storage,
            pending_events: Vec::new(),
            default_group: None,
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
    pub fn storage(&self) -> &MemoryStorage {
        &self.storage
    }

    pub fn member_id(&self) -> MemberId {
        self.engine.self_id()
    }

    pub async fn fresh_key_package(&mut self) -> KeyPackage {
        self.engine.fresh_key_package().await.expect("kp")
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
        let res = self
            .engine
            .create_group(CreateGroupRequest {
                name: name.into(),
                description: "".into(),
                members: invitees,
                required_features,
                initial_admins,
            })
            .await
            .expect("create_group");
        let (gid, pending, welcomes) = match res {
            (gid, SendResult::GroupCreated { pending, welcomes }) => (gid, pending, welcomes),
            (_, other) => panic!("expected GroupCreated, got {other:?}"),
        };
        for w in welcomes {
            self.bus.send(self.bus_id, w);
        }
        self.default_group = Some(gid.clone());
        (gid, pending)
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

    /// Send an application message and return the wrapped TransportMessage
    /// that was put on the bus. Useful for the same-id-replay proptest
    /// property which needs to re-inject that exact message.
    pub async fn send_app_capture(&mut self, payload: impl Into<Vec<u8>>) -> TransportMessage {
        let gid = self
            .default_group
            .clone()
            .expect("must create or join a group first");
        let res = self
            .engine
            .send(SendIntent::AppMessage {
                group_id: gid.clone(),
                payload: payload.into(),
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
        let res = self
            .engine
            .send(SendIntent::AppMessage {
                group_id: gid.clone(),
                payload: payload.into(),
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
        let inbound = self.bus.mailbox(self.bus_id);
        let mut outcomes = Vec::with_capacity(inbound.len());
        let mut buffered_groups = Vec::new();
        for msg in inbound {
            let result = self.engine.ingest(msg).await;
            if let Ok(IngestOutcome::Buffered { group_id, .. }) = &result
                && !buffered_groups.contains(group_id)
            {
                buffered_groups.push(group_id.clone());
            }
            if result.is_ok() {
                self.capture_engine_events();
            }
            outcomes.push(result);
        }
        for group_id in buffered_groups {
            match self
                .engine
                .advance_convergence_inputs_until_stable(&group_id, 1_000_000)
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    outcomes.push(Err(EngineError::Backend(format!(
                        "converge buffered group: {e}"
                    ))));
                    continue;
                }
            }
            self.capture_engine_events();
        }
        // Auto-publish: anything the engine queued in response goes back on
        // the bus.
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

    pub fn group_id(&self) -> GroupId {
        self.default_group.clone().expect("group")
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
            TransportEnvelope::GroupMessage { transport_group_id } => {
                GroupId::new(transport_group_id.clone())
            }
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

fn route(msg: TransportMessage, gid: &GroupId) -> TransportMessage {
    match msg.envelope {
        TransportEnvelope::Welcome { .. } => msg,
        TransportEnvelope::GroupMessage { .. } => TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: gid.as_slice().to_vec(),
            },
            ..msg
        },
    }
}
