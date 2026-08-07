//! Two-phase hydration (mdk#1161): the session-open cheap pass seeds every
//! stored group without loading MLS state, gated surfaces fail closed with
//! `GroupNotHydrated`, and full hydration runs per group — on demand from
//! `&mut` entry points or explicitly via `ensure_hydrated` — with failure
//! parity to open-time quarantine. Durable transport routes keep inbound
//! routing working for seeded groups, with a one-shot backfill for records
//! predating the route table.

use async_trait::async_trait;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::app_components::{
    AppComponentData, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, default_group_components,
    encode_nostr_routing_v1,
};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{
    CgkaEngine, CreateGroupRequest, GroupEvent, GroupHydrationQuarantineReason, SendResult,
};
use cgka_traits::error::{EngineError, PeelerError};
use cgka_traits::group::Group;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::GroupStorage;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use storage_sqlite::SqliteAccountStorage;

mod support;
use support::proof_signer;

fn pad32(name: &[u8]) -> Vec<u8> {
    use k256::schnorr::SigningKey;
    use sha2::{Digest, Sha256};

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

fn hash_id(bytes: &[u8]) -> MessageId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
}

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
            id: hash_id(&payload.ciphertext),
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
            id: hash_id(&payload.ciphertext),
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

fn build_engine(storage: SqliteAccountStorage) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .legacy_compatibility_profile()
        .identity(pad32(b"alice-two-phase"))
        .account_identity_proof_signer(proof_signer(b"alice-two-phase"))
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build engine")
}

const ROUTE_BYTES: [u8; 32] = [0x41; 32];

/// Current-profile engine whose key packages advertise the routing component,
/// for the transport-route tests (shape mirrors `update_group_data.rs`).
fn build_routed_engine(storage: SqliteAccountStorage) -> Engine<SqliteAccountStorage> {
    let mut registry = FeatureRegistry::new();
    registry.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    let mut components: Vec<_> = default_group_components().into_iter().collect();
    components.push(NOSTR_ROUTING_COMPONENT_ID);
    EngineBuilder::new(storage)
        .identity(pad32(b"alice-two-phase"))
        .account_identity_proof_signer(proof_signer(b"alice-two-phase"))
        .protocol_profile(cgka_traits::group::ProtocolProfile::Current)
        .feature_registry(registry)
        .supported_app_components(components)
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build routed engine")
}

async fn create_confirmed_group(
    engine: &mut Engine<SqliteAccountStorage>,
    with_route: bool,
) -> GroupId {
    let app_components = if with_route {
        let routing = NostrRoutingV1::new(ROUTE_BYTES, vec!["wss://relay.example".into()])
            .expect("routing component");
        vec![AppComponentData {
            component_id: NOSTR_ROUTING_COMPONENT_ID,
            data: encode_nostr_routing_v1(&routing).expect("encode routing"),
        }]
    } else {
        Vec::new()
    };
    let (group_id, send_result) = engine
        .create_group(CreateGroupRequest {
            name: "two-phase".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components,
            initial_admins: vec![],
        })
        .await
        .expect("create group");
    match send_result {
        SendResult::GroupCreated { pending, .. } => {
            engine.confirm_published(pending).await.expect("confirm");
        }
        // Current-profile founding creation is already canonical locally.
        SendResult::FoundingGroupCreated { .. } => {}
        other => panic!("expected group-created send result, got {other:?}"),
    }
    group_id
}

fn insert_marmot_group_without_openmls_state(
    storage: &SqliteAccountStorage,
    group_id: &GroupId,
    epoch: u64,
) {
    storage
        .put_group(&Group {
            id: group_id.clone(),
            name: "broken".into(),
            description: String::new(),
            members: Vec::new(),
            epoch: EpochId(epoch),
            required_capabilities: Default::default(),
            protocol_profile: cgka_traits::group::ProtocolProfile::Legacy,
            removed: false,
            unrecoverable: false,
            disbanded: None,
            join_epoch: EpochId(0),
        })
        .expect("insert marmot group record without openmls state");
}

#[tokio::test]
async fn seeded_group_is_listed_but_gated_until_hydrated() {
    let storage = SqliteAccountStorage::in_memory().expect("storage");
    let mut initial = build_engine(storage.clone());
    let group_id = create_confirmed_group(&mut initial, false).await;
    let stored_epoch = storage.get_group(&group_id).unwrap().epoch;
    drop(initial);

    let mut reopened = build_engine(storage);
    reopened
        .hydrate_stable_groups_from_storage()
        .expect("cheap pass");

    // The projection keeps listing the group while hydration is outstanding.
    assert_eq!(reopened.live_group_ids().unwrap(), vec![group_id.clone()]);
    assert_eq!(reopened.unhydrated_group_ids(), vec![group_id.clone()]);

    // Every gated accessor fails closed with the retryable variant — never a
    // partial view, never UnknownGroup.
    assert!(matches!(
        reopened.members(&group_id),
        Err(EngineError::GroupNotHydrated(id)) if id == group_id
    ));
    assert!(matches!(
        reopened.epoch(&group_id),
        Err(EngineError::GroupNotHydrated(id)) if id == group_id
    ));

    // Explicit promotion makes the group fully live.
    reopened.ensure_hydrated(&group_id).expect("hydrate");
    assert!(reopened.unhydrated_group_ids().is_empty());
    assert_eq!(reopened.epoch(&group_id).unwrap(), stored_epoch);
    assert!(reopened.members(&group_id).is_ok());
}

#[tokio::test]
async fn ensure_hydrated_failure_quarantines_with_open_time_parity() {
    let storage = SqliteAccountStorage::in_memory().expect("storage");
    let broken_group = GroupId::new(b"missing-openmls-state".to_vec());
    insert_marmot_group_without_openmls_state(&storage, &broken_group, 7);

    let mut engine = build_engine(storage);
    engine
        .hydrate_stable_groups_from_storage()
        .expect("cheap pass");
    // The cheap pass cannot see the missing MLS state, so the group seeds.
    assert_eq!(engine.live_group_ids().unwrap(), vec![broken_group.clone()]);

    assert!(matches!(
        engine.ensure_hydrated(&broken_group),
        Err(EngineError::UnknownGroup(id)) if id == broken_group
    ));

    // Quarantine parity with an open-time failure: reason recorded, event
    // emitted, and the group vanishes from every live surface including the
    // group list (the provisional seed is retracted).
    assert_eq!(
        engine.quarantined_groups(),
        vec![(
            broken_group.clone(),
            GroupHydrationQuarantineReason::OpenMlsGroupMissing
        )]
    );
    assert!(engine.live_group_ids().unwrap().is_empty());
    assert!(engine.unhydrated_group_ids().is_empty());
    assert!(matches!(
        engine.members(&broken_group),
        Err(EngineError::UnknownGroup(_))
    ));
    let events = engine.drain_events();
    assert!(
        events.iter().any(|event| matches!(
            event,
            GroupEvent::GroupHydrationQuarantined {
                group_id,
                reason: GroupHydrationQuarantineReason::OpenMlsGroupMissing,
            } if group_id == &broken_group
        )),
        "quarantine event missing: {events:?}"
    );
}

#[tokio::test]
async fn cheap_pass_is_idempotent_and_never_demotes_a_live_group() {
    let storage = SqliteAccountStorage::in_memory().expect("storage");
    let mut initial = build_engine(storage.clone());
    let group_id = create_confirmed_group(&mut initial, false).await;
    drop(initial);

    let mut reopened = build_engine(storage);
    reopened.hydrate_all_stored_groups().expect("eager hydrate");
    assert!(reopened.unhydrated_group_ids().is_empty());
    assert!(reopened.members(&group_id).is_ok());

    // A second cheap pass must not re-seed the already-live group back into
    // the unhydrated set.
    reopened
        .hydrate_stable_groups_from_storage()
        .expect("second cheap pass");
    assert!(reopened.unhydrated_group_ids().is_empty());
    assert!(reopened.members(&group_id).is_ok());
}

#[tokio::test]
async fn ingest_hydrates_seeded_group_resolved_through_durable_route() {
    let storage = SqliteAccountStorage::in_memory().expect("storage");
    let mut initial = build_routed_engine(storage.clone());
    let group_id = create_confirmed_group(&mut initial, true).await;
    drop(initial);

    // Group establishment persisted the transport route durably.
    assert_eq!(
        storage.list_transport_group_routes().unwrap(),
        vec![(ROUTE_BYTES.to_vec(), group_id.clone())]
    );

    let mut reopened = build_routed_engine(storage);
    reopened
        .hydrate_stable_groups_from_storage()
        .expect("cheap pass");
    assert_eq!(reopened.unhydrated_group_ids(), vec![group_id.clone()]);

    // An inbound message addressed to the transport route resolves through
    // the durably seeded index and promotes the group before the peel.
    let _ = reopened
        .ingest(TransportMessage {
            id: MessageId::new(b"inbound-two-phase".to_vec()),
            payload: b"not real mls bytes".to_vec(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: ROUTE_BYTES.to_vec(),
            },
        })
        .await;
    assert!(
        reopened.unhydrated_group_ids().is_empty(),
        "ingest must hydrate the routed group on demand"
    );
    assert!(reopened.members(&group_id).is_ok());
    assert!(reopened.quarantined_groups().is_empty());
}

#[tokio::test]
async fn ingest_backfills_route_for_record_predating_route_table() {
    let storage = SqliteAccountStorage::in_memory().expect("storage");
    let mut initial = build_routed_engine(storage.clone());
    let group_id = create_confirmed_group(&mut initial, true).await;
    drop(initial);

    // Simulate a store migrated from before the route table: the group
    // exists but has no durable route row.
    storage
        .delete_transport_group_routes_for_group(&group_id)
        .expect("drop route rows");
    assert!(storage.list_transport_group_routes().unwrap().is_empty());

    let mut reopened = build_routed_engine(storage.clone());
    reopened
        .hydrate_stable_groups_from_storage()
        .expect("cheap pass");

    // The routing miss triggers the one-shot backfill: the group's MLS state
    // is loaded once, its route persisted and indexed, and the message then
    // resolves and hydrates the group.
    let _ = reopened
        .ingest(TransportMessage {
            id: MessageId::new(b"inbound-backfill".to_vec()),
            payload: b"not real mls bytes".to_vec(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: ROUTE_BYTES.to_vec(),
            },
        })
        .await;
    assert!(
        reopened.unhydrated_group_ids().is_empty(),
        "backfilled route must resolve and hydrate the group"
    );
    assert_eq!(
        storage.list_transport_group_routes().unwrap(),
        vec![(ROUTE_BYTES.to_vec(), group_id.clone())],
        "backfill must repopulate the durable route table"
    );
    assert!(reopened.members(&group_id).is_ok());
}
