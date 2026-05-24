//! Privacy regression for snapshot naming.
//!
//! Per `docs/marmot-architecture/overview/observability.md`, group ids,
//! account ids, and message ids must not appear as plaintext inside any
//! operational identifier. Snapshot names are operational identifiers —
//! they show up in storage error messages, can be enumerated by anyone
//! reading the encrypted DB, and may flow through future tracing. Hash
//! group-id-derived inputs into the snapshot name instead.

use async_trait::async_trait;
use cgka_engine::EngineBuilder;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::MessageStorage;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{MemberId, MessageId};
use storage_memory::MemoryStorage;

mod support;
use support::proof_signer;

fn pad32(name: &[u8]) -> Vec<u8> {
    // Marmot credential identities MUST be a valid 32-byte x-only secp256k1
    // public key (spec/foundation/identity.md). Derive one deterministically
    // from the ergonomic label so admin/member tracking stays stable across a
    // run while the engine accepts the identity.
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

fn hash_id(bytes: &[u8]) -> MessageId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
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

#[tokio::test]
async fn snapshot_names_do_not_embed_plaintext_group_id() {
    let storage = MemoryStorage::new();
    let mut alice = EngineBuilder::new(storage.clone())
        .identity(pad32(b"alice"))
        .account_identity_proof_signer(proof_signer(b"alice"))
        .feature_registry(FeatureRegistry::new())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();

    let mut bob = EngineBuilder::new(MemoryStorage::new())
        .identity(pad32(b"bob"))
        .account_identity_proof_signer(proof_signer(b"bob"))
        .feature_registry(FeatureRegistry::new())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (gid, create) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    if let SendResult::GroupCreated { pending, .. } = create {
        alice.confirm_published(pending).await.unwrap();
    }

    // Force a few snapshots: invite, app message, update_group_data.
    let mut carol = EngineBuilder::new(MemoryStorage::new())
        .identity(pad32(b"carol"))
        .account_identity_proof_signer(proof_signer(b"carol"))
        .feature_registry(FeatureRegistry::new())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .unwrap();
    if let SendResult::GroupEvolution { pending, .. } = invite {
        alice.confirm_published(pending).await.unwrap();
    }

    let update = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("renamed".into()),
            description: None,
        })
        .await
        .unwrap();
    if let SendResult::GroupEvolution { pending, .. } = update {
        alice.confirm_published(pending).await.unwrap();
    }

    let snapshots = storage.list_group_snapshots(&gid).unwrap();
    assert!(
        !snapshots.is_empty(),
        "we expect at least one retained-anchor snapshot"
    );

    let plaintext_id = hex::encode(gid.as_slice());
    for name in &snapshots {
        assert!(
            !name.contains(&plaintext_id),
            "snapshot name {name:?} must not embed plaintext hex(group_id) ({plaintext_id})"
        );
    }
}
