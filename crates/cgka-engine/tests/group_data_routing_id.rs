//! `marmot_group_data.nostr_group_id` privacy / non-correlation tests.
//!
//! Two routing-shaped fields exist in the engine today:
//!
//! 1. **`MlsGroup` id** — 16 bytes. OpenMLS generates this with secure
//!    randomness at create time. The current engine wraps this value into
//!    `TransportEnvelope::GroupMessage.transport_group_id`, so it IS the
//!    relay-visible h-tag in the current implementation.
//! 2. **`marmot_group_data.nostr_group_id`** — 32 bytes, embedded in the
//!    signed `marmot_group_data` (`0xF2EE`) extension that travels inside
//!    the MLS group context. Per MIP-01 this is the canonical routing
//!    tag; current engine code does not yet route off it, but a future
//!    spec-compliant implementation will. A previous version of the
//!    engine populated this field by copying the creator's pubkey, which
//!    would have leaked routing-correlatable metadata to every group
//!    member and (under spec-compliant routing) to relays. The fix
//!    populates it from a CSPRNG.
//!
//! These tests cover both surfaces: the MlsGroup-id property (already
//! true under OpenMLS) and the marmot_group_data.nostr_group_id property
//! (newly enforced).

use async_trait::async_trait;
use cgka_engine::EngineBuilder;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::group_data::read_marmot_group_data_for_test;
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{MemberId, MessageId};
use storage_memory::MemoryStorage;

fn pad32(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let n = name.len().min(32);
    out[..n].copy_from_slice(&name[..n]);
    out
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

fn build_storage_and_engine(identity: &[u8]) -> (MemoryStorage, Box<dyn CgkaEngine>) {
    let storage = MemoryStorage::new();
    let engine = EngineBuilder::new(storage.clone())
        .identity(pad32(identity))
        .feature_registry(FeatureRegistry::new())
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build engine");
    (storage, Box::new(engine))
}

#[tokio::test]
async fn two_groups_by_same_creator_get_distinct_mls_group_ids() {
    // Sanity: OpenMLS already auto-generates random MlsGroup ids. Two
    // creates by the same creator must yield distinct ones.
    let (_storage, mut alice) = build_storage_and_engine(b"alice-creator");

    let (g1, r1) = alice
        .create_group(CreateGroupRequest {
            name: "first".into(),
            description: "".into(),
            members: vec![],
            required_features: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    if let SendResult::GroupCreated { pending, .. } = r1 {
        alice.confirm_published(pending).await.unwrap();
    }

    let (g2, r2) = alice
        .create_group(CreateGroupRequest {
            name: "second".into(),
            description: "".into(),
            members: vec![],
            required_features: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    if let SendResult::GroupCreated { pending, .. } = r2 {
        alice.confirm_published(pending).await.unwrap();
    }

    assert_ne!(
        g1.as_slice(),
        g2.as_slice(),
        "MlsGroup ids must be distinct between two creates"
    );
}

#[tokio::test]
async fn marmot_group_data_nostr_group_id_is_not_creator_pubkey() {
    // The MIP-01 routing tag inside `marmot_group_data` MUST NOT be the
    // creator's pubkey. A previous engine version made the two equal,
    // which would have leaked correlatable routing metadata to every
    // group member (and, under spec-compliant relay routing, to relays).
    let creator_id = pad32(b"alice-routing-id-test");
    let (storage, mut alice) = build_storage_and_engine(b"alice-routing-id-test");

    let (group_id, send_result) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![],
            required_features: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    if let SendResult::GroupCreated { pending, .. } = send_result {
        alice.confirm_published(pending).await.unwrap();
    }

    let data = read_marmot_group_data_for_test(&storage, &group_id)
        .expect("marmot_group_data extension is present after create");
    assert_eq!(data.nostr_group_id.len(), 32);
    assert_ne!(
        data.nostr_group_id.as_slice(),
        creator_id.as_slice(),
        "marmot_group_data.nostr_group_id MUST NOT equal creator identity"
    );
    // No all-zero tags either.
    assert!(
        data.nostr_group_id.iter().any(|b| *b != 0),
        "nostr_group_id must not be the all-zero placeholder"
    );
}

#[tokio::test]
async fn three_creates_by_same_creator_produce_three_distinct_nostr_group_ids() {
    let (storage, mut alice) = build_storage_and_engine(b"alice");

    let mut routing_ids: Vec<[u8; 32]> = Vec::new();
    for i in 0..3 {
        let (group_id, result) = alice
            .create_group(CreateGroupRequest {
                name: format!("g{i}"),
                description: "".into(),
                members: vec![],
                required_features: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        if let SendResult::GroupCreated { pending, .. } = result {
            alice.confirm_published(pending).await.unwrap();
        }
        let data = read_marmot_group_data_for_test(&storage, &group_id).expect("marmot_group_data");
        routing_ids.push(data.nostr_group_id);
    }

    assert_ne!(
        routing_ids[0], routing_ids[1],
        "two consecutive creates must produce distinct nostr_group_ids"
    );
    assert_ne!(routing_ids[1], routing_ids[2]);
    assert_ne!(routing_ids[0], routing_ids[2]);
}
