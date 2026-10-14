//! Re-advertising newly supported app components in this device's own leaf
//! (spec `app-components/README.md`, "Enabling a Component in an Existing
//! Group").
//!
//! `marmot.group.avatar-url.v1` is the vehicle: it is optional for new
//! groups, so a group created by builds that did not support it does not
//! require it, which is exactly the shape a new component has in every existing
//! group. A "new build" is an engine reopened on the same storage with a
//! larger supported set.
//!
//! Covers:
//! - A self-update re-advertises newly supported components in the own leaf,
//!   and a peer accepts the refreshed leaf.
//! - A leaf is reported stale only while a self-update would change it.

use async_trait::async_trait;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::app_components::{
    APP_COMPONENTS_COMPONENT_ID, AppComponentId, GROUP_AVATAR_URL_COMPONENT_ID,
    decode_components_list, default_group_components,
};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{GroupId, MemberId, MessageId};
use sha2::{Digest, Sha256};
use storage_sqlite::SqliteAccountStorage;

mod support;
use support::proof_signer;

fn pad32(name: &[u8]) -> Vec<u8> {
    use k256::schnorr::SigningKey;
    let mut counter = 0u64;
    loop {
        let mut material = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-test-identity-v1");
        hasher.update(name);
        hasher.update(counter.to_be_bytes());
        material.copy_from_slice(&hasher.finalize());
        if let Ok(sk) = SigningKey::from_bytes(&material) {
            return sk.verifying_key().to_bytes().to_vec();
        }
        counter += 1;
    }
}

struct MockPeeler;

#[async_trait]
impl TransportPeeler for MockPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        _ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::MlsMessage {
                bytes: msg.payload.clone(),
            },
            origin: msg.clone(),
        })
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::Welcome {
                created_at: None,
                bytes: msg.payload.clone(),
            },
            origin: msg.clone(),
        })
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        _ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(TransportMessage {
            id: MessageId::new(Sha256::digest(&payload.ciphertext).to_vec()),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: vec![],
            },
        })
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(TransportMessage {
            id: MessageId::new(Sha256::digest(&payload.ciphertext).to_vec()),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

fn registry() -> FeatureRegistry {
    let mut r = FeatureRegistry::new();
    r.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    r
}

const NEW: AppComponentId = GROUP_AVATAR_URL_COMPONENT_ID;

/// The supported set of a build that predates the vehicle component.
fn old_components() -> Vec<AppComponentId> {
    default_group_components().into_iter().collect()
}

fn new_components() -> Vec<AppComponentId> {
    let mut components = old_components();
    components.push(NEW);
    components
}

fn open(
    id: &[u8],
    storage: SqliteAccountStorage,
    supported: Vec<AppComponentId>,
) -> Engine<SqliteAccountStorage> {
    let mut engine = EngineBuilder::new(storage)
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .protocol_profile(ProtocolProfile::Current)
        .feature_registry(registry())
        .supported_app_components(supported)
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    engine.hydrate_all_stored_groups().unwrap();
    engine
}

struct Device {
    id: &'static [u8],
    storage: SqliteAccountStorage,
    engine: Engine<SqliteAccountStorage>,
}

impl Device {
    fn old(id: &'static [u8]) -> Self {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let engine = open(id, storage.clone(), old_components());
        Self {
            id,
            storage,
            engine,
        }
    }

    /// Reopen on the same storage as a build that supports the vehicle.
    fn upgrade(&mut self) {
        self.engine = open(self.id, self.storage.clone(), new_components());
    }
}

/// A two-member group created by builds that predate the vehicle component.
/// Alice is the creator and only admin.
async fn old_group(alice: &mut Device, bob: &mut Device) -> GroupId {
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let (gid, create) = alice
        .engine
        .create_group(CreateGroupRequest {
            name: "predates the component".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcomes = match create {
        SendResult::FoundingGroupCreated { welcomes } => welcomes,
        other => panic!("expected FoundingGroupCreated, got {other:?}"),
    };
    bob.engine
        .join_welcome(welcomes.into_iter().next().unwrap())
        .await
        .unwrap();
    assert!(
        !required_components(&alice.engine, &gid).contains(&NEW),
        "the vehicle group must not require the component yet"
    );
    gid
}

fn required_components(
    engine: &Engine<SqliteAccountStorage>,
    gid: &GroupId,
) -> Vec<AppComponentId> {
    decode_components_list(
        &engine
            .app_component(gid, APP_COMPONENTS_COMPONENT_ID)
            .unwrap()
            .expect("current-profile groups carry app_components"),
    )
    .unwrap()
    .into_iter()
    .collect()
}

/// Send `intent` from `from`, confirm it, and deliver the commit to `to`.
async fn commit_and_deliver(
    from: &mut Engine<SqliteAccountStorage>,
    to: &mut Engine<SqliteAccountStorage>,
    gid: &GroupId,
    intent: SendIntent,
) {
    let (commit, pending) = match from.send(intent).await.unwrap() {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    from.confirm_published(pending).await.unwrap();
    let target = from.epoch(gid).unwrap();
    to.ingest(commit).await.unwrap();
    for _ in 0..24 {
        if to.epoch(gid).unwrap() == target {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        to.advance_convergence(gid).await.unwrap();
    }
    assert_eq!(to.epoch(gid).unwrap(), target, "peer applied the commit");
}

#[tokio::test]
async fn self_update_readvertises_newly_supported_components() {
    let mut alice = Device::old(b"alice-leaf-refresh");
    let mut bob = Device::old(b"bob-leaf-refresh");
    let gid = old_group(&mut alice, &mut bob).await;
    assert!(
        alice
            .engine
            .own_leaf_missing_app_components(&gid)
            .unwrap()
            .is_empty()
    );

    alice.upgrade();
    assert_eq!(
        alice
            .engine
            .own_leaf_missing_app_components(&gid)
            .unwrap()
            .ids
            .into_iter()
            .collect::<Vec<_>>(),
        vec![NEW],
        "the new build notices its leaf is stale"
    );

    commit_and_deliver(
        &mut alice.engine,
        &mut bob.engine,
        &gid,
        SendIntent::SelfUpdate {
            group_id: gid.clone(),
        },
    )
    .await;

    assert!(
        alice
            .engine
            .own_leaf_missing_app_components(&gid)
            .unwrap()
            .is_empty(),
        "the self-update re-advertised the supported set"
    );
    let bob_member = MemberId::new(pad32(b"bob-leaf-refresh"));
    assert_eq!(
        bob.engine
            .app_component_support_blockers(&gid, NEW)
            .unwrap(),
        vec![bob_member],
        "the peer accepted alice's refreshed leaf; only bob's own leaf is still stale"
    );
}

#[tokio::test]
async fn a_legacy_profile_leaf_is_refreshed_once_not_on_every_cycle() {
    // `own_leaf_missing_app_components` reports a leaf stale only when a
    // self-update would change it. Legacy-profile leaves carry the legacy proof
    // extension alongside an app_data_dictionary, so one self-update refreshes
    // them and the report clears; it must not stay stale and re-arm forever.
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let build = |storage: SqliteAccountStorage, supported: Vec<AppComponentId>| {
        let mut engine = EngineBuilder::new(storage)
            .legacy_compatibility_profile()
            .identity(pad32(b"legacy-leaf"))
            .account_identity_proof_signer(proof_signer(b"legacy-leaf"))
            .feature_registry(registry())
            .supported_app_components(supported)
            .peeler(Box::new(MockPeeler))
            .build()
            .unwrap();
        engine.hydrate_all_stored_groups().unwrap();
        engine
    };
    let mut engine = build(storage.clone(), old_components());
    let (gid, created) = engine
        .create_group(CreateGroupRequest {
            name: "legacy".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    if let SendResult::GroupCreated { pending, .. } = created {
        engine.confirm_published(pending).await.unwrap();
    }
    drop(engine);
    let mut engine = build(storage, new_components());
    assert_eq!(
        engine
            .own_leaf_missing_app_components(&gid)
            .unwrap()
            .ids
            .into_iter()
            .collect::<Vec<_>>(),
        vec![NEW]
    );
    match engine
        .send(SendIntent::SelfUpdate {
            group_id: gid.clone(),
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { pending, .. } => {
            engine.confirm_published(pending).await.unwrap();
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    }
    assert!(
        engine
            .own_leaf_missing_app_components(&gid)
            .unwrap()
            .is_empty(),
        "one self-update refreshes a legacy leaf"
    );
}
