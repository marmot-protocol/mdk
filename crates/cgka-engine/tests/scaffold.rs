//! Engine construction and trait-object scaffold tests.
//!
//! Proves the engine can be built, implements `CgkaEngine`, and can be wrapped
//! in `Box<dyn CgkaEngine + Send + Sync>` without async-trait lifetime
//! regressions. Behavior-level coverage lives in the focused integration tests.

use async_trait::async_trait;
use cgka_engine::EngineBuilder;
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::PeeledMessage;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{EncryptedPayload, TransportMessage};
use cgka_traits::types::MemberId;
use cgka_traits::{CgkaEngine, EngineError};
use storage_sqlite::SqliteStorage;

mod support;
use support::proof_signer;

/// Deterministic, spec-valid x-only secp256k1 identity derived from a label.
fn valid_identity(seed: &[u8]) -> Vec<u8> {
    use k256::schnorr::SigningKey;
    use sha2::{Digest, Sha256};
    let mut counter = 0u64;
    loop {
        let mut material = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-test-identity-v1");
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        material.copy_from_slice(&hasher.finalize());
        if let Ok(sk) = SigningKey::from_bytes(&material) {
            return sk.verifying_key().to_bytes().to_vec();
        }
        counter += 1;
    }
}

struct StubPeeler;

#[async_trait]
impl TransportPeeler for StubPeeler {
    async fn peel_group_message(
        &self,
        _msg: &TransportMessage,
        _ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        Err(PeelerError::Backend("test peeler".into()))
    }

    async fn peel_welcome(&self, _msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        Err(PeelerError::Backend("test peeler".into()))
    }

    async fn wrap_group_message(
        &self,
        _payload: &EncryptedPayload,
        _ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Err(PeelerError::Backend("test peeler".into()))
    }

    async fn wrap_welcome(
        &self,
        _payload: &EncryptedPayload,
        _recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        Err(PeelerError::Backend("test peeler".into()))
    }
}

#[test]
fn engine_can_be_built_and_boxed_as_trait_object() {
    let identity = valid_identity(b"self-identity");
    let engine = EngineBuilder::new(SqliteStorage::in_memory().unwrap())
        .identity(identity.clone())
        .account_identity_proof_signer(proof_signer(b"self-identity"))
        .peeler(Box::new(StubPeeler))
        .build()
        .expect("build");

    // self_id is real from the start.
    assert_eq!(engine.self_id().as_slice(), identity.as_slice());

    // Witness: this line stops compiling if async-trait lifetimes regress.
    let _boxed: Box<dyn CgkaEngine + Send + Sync> = Box::new(engine);
}

#[test]
fn builder_rejects_missing_identity() {
    let res = EngineBuilder::new(SqliteStorage::in_memory().unwrap())
        .peeler(Box::new(StubPeeler))
        .build();
    assert!(matches!(res, Err(EngineError::Other(_))));
}

#[test]
fn builder_rejects_missing_peeler() {
    let res = EngineBuilder::new(SqliteStorage::in_memory().unwrap())
        .identity(b"id".to_vec())
        .build();
    assert!(matches!(res, Err(EngineError::Other(_))));
}

#[test]
fn builder_rejects_non_mandatory_ciphersuite() {
    // spec/foundation/mls-protocol.md:11-15 — only
    // MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001) is permitted.
    let res = EngineBuilder::new(SqliteStorage::in_memory().unwrap())
        .identity(valid_identity(b"self-identity"))
        .account_identity_proof_signer(proof_signer(b"self-identity"))
        .peeler(Box::new(StubPeeler))
        .ciphersuite(cgka_engine::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)
        .build();
    assert!(matches!(
        res,
        Err(EngineError::UnsupportedCiphersuite {
            got: 0x0003,
            required: 0x0001,
        })
    ));
}

#[test]
fn builder_accepts_mandatory_ciphersuite_explicitly() {
    let res = EngineBuilder::new(SqliteStorage::in_memory().unwrap())
        .identity(valid_identity(b"self-identity"))
        .account_identity_proof_signer(proof_signer(b"self-identity"))
        .peeler(Box::new(StubPeeler))
        .ciphersuite(cgka_engine::DEFAULT_CIPHERSUITE)
        .build();
    assert!(res.is_ok());
}

#[tokio::test]
async fn empty_engine_methods_return_typed_results() {
    let mut engine = EngineBuilder::new(SqliteStorage::in_memory().unwrap())
        .identity(valid_identity(b"id"))
        .account_identity_proof_signer(proof_signer(b"id"))
        .peeler(Box::new(StubPeeler))
        .build()
        .unwrap();

    // Drain methods return empty before any events are emitted.
    assert!(engine.drain_events().is_empty());
    assert!(engine.drain_auto_publish().is_empty());

    // Sending to an unknown group returns a typed error, not a panic.
    let res = engine
        .send(cgka_traits::engine::SendIntent::AppMessage {
            group_id: cgka_traits::GroupId::new(vec![0; 4]),
            payload: vec![],
        })
        .await;
    assert!(res.is_err());
}
