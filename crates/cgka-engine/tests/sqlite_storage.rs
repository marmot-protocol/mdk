//! SQLite-backed engine integration smoke.
//!
//! This keeps the production storage backend on the same engine test rail as
//! `MemoryStorage` without trying to turn this crate into a full persistence
//! reload suite. The behavior under test is: a real OpenMLS engine can create
//! and confirm a group while all Marmot + OpenMLS state is backed by an
//! encrypted SQLite database.

use async_trait::async_trait;
use cgka_engine::EngineBuilder;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::GroupStorage;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, MemberId, MessageId};
use storage_sqlite::{SqlCipherKey, SqliteStorage};

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
            source: TransportSource("sqlite-smoke".into()),
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
            source: TransportSource("sqlite-smoke".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

fn build_client(storage: SqliteStorage, identity: &[u8]) -> impl CgkaEngine {
    EngineBuilder::new(storage)
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .feature_registry(FeatureRegistry::new())
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build engine")
}

#[tokio::test]
async fn create_group_confirm_and_reopen_with_encrypted_sqlite_storage() {
    let dir = tempfile::tempdir().unwrap();
    let alice_path = dir.path().join("alice.sqlite");
    let bob_path = dir.path().join("bob.sqlite");
    let key = SqlCipherKey::new("sqlite engine smoke key").unwrap();

    let alice_store = SqliteStorage::open_encrypted(&alice_path, &key).unwrap();
    let bob_store = SqliteStorage::open_encrypted(&bob_path, &key).unwrap();
    let mut alice = build_client(alice_store, b"alice-sqlite");
    let mut bob = build_client(bob_store, b"bob-sqlite");

    let bob_key_package = bob.fresh_key_package().await.expect("bob key package");
    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "sqlite-backed".into(),
            description: "engine integration smoke".into(),
            members: vec![bob_key_package],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .expect("create group");

    let pending = match result {
        SendResult::GroupCreated { pending, welcomes } => {
            assert_eq!(welcomes.len(), 1);
            pending
        }
        other => panic!("expected group creation result, got {other:?}"),
    };
    alice.confirm_published(pending).await.expect("confirm");

    assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(1));
    assert_eq!(alice.members(&group_id).unwrap().len(), 2);

    drop(alice);
    drop(bob);

    let file_bytes = std::fs::read(&alice_path).unwrap();
    assert!(!file_bytes.starts_with(b"SQLite format 3\0"));

    let reopened = SqliteStorage::open_encrypted(&alice_path, &key).unwrap();
    assert_eq!(reopened.get_group(&group_id).unwrap().epoch, EpochId(1));
}
