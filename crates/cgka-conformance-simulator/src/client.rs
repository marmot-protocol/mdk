//! `HarnessClient` — wraps an `Engine<MemoryStorage>` + `MockPeeler` + bus
//! attachment. Provides scenario-level affordances: `send`, `tick`,
//! `confirm_all_pending`, `assert_at_epoch`.

use crate::bus::{ClientId, TransportBus};
use crate::peeler::MockPeeler;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::engine::{
    CgkaEngine, CreateGroupRequest, GroupEvent, KeyPackage, SendIntent, SendResult,
};
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::error::EngineError;
use cgka_traits::ingest::IngestOutcome;
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId};
use storage_memory::MemoryStorage;

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
    registry: FeatureRegistry,
}

impl ClientBuilder {
    pub fn new(identity: impl Into<Vec<u8>>) -> Self {
        Self {
            identity: identity.into(),
            registry: FeatureRegistry::new(),
        }
    }

    pub fn registry(mut self, r: FeatureRegistry) -> Self {
        self.registry = r;
        self
    }

    pub fn attach(self, bus: &TransportBus) -> HarnessClient {
        let storage = MemoryStorage::new();
        let engine = EngineBuilder::new(storage.clone())
            .identity(self.identity.clone())
            .feature_registry(self.registry)
            .peeler(Box::new(MockPeeler::new(self.identity.clone())))
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
                .converge_stored_openmls_messages(&group_id, 1_000_000)
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
        for m in auto {
            let routed = if let Some(gid) = &gid {
                route(m, gid)
            } else {
                m
            };
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
        self.engine.epoch(&gid).expect("epoch")
    }

    pub fn members(&self) -> Vec<cgka_traits::group::Member> {
        let gid = self.default_group.clone().expect("group");
        self.engine.members(&gid).expect("members")
    }

    pub fn group_id(&self) -> GroupId {
        self.default_group.clone().expect("group")
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
