//! Default-build convergence policy pin proofs (mdk#970).
//!
//! This target deliberately runs without the `test-policy-overrides` feature,
//! proving that ordinary debug and release consumers both reject non-v1 policy:
//!
//! ```sh
//! just test-convergence-policy-pin
//! ```
//!
//! CI and `just fast-ci` / `just ci` invoke that recipe separately from the
//! feature-enabled integration-test matrix.

use async_trait::async_trait;
use cgka_engine::canonicalization::CanonicalizationPolicy;
#[cfg(not(feature = "test-policy-overrides"))]
use cgka_engine::openmls_projection::OpenMlsProjectionError;
use cgka_engine::{DEFAULT_MAX_PAST_EPOCHS, EngineBuilder};
#[cfg(not(feature = "test-policy-overrides"))]
use cgka_traits::error::EngineError;
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::PeeledMessage;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{EncryptedPayload, TransportMessage};
use cgka_traits::types::MemberId;
use storage_sqlite::SqliteAccountStorage;

mod support;
use support::proof_signer;

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

fn build_engine() -> cgka_engine::Engine<SqliteAccountStorage> {
    EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(valid_identity(b"pin-policy"))
        .account_identity_proof_signer(proof_signer(b"pin-policy"))
        .peeler(Box::new(StubPeeler))
        .build()
        .expect("pinned default engine builds")
}

#[test]
fn ensure_acceptable_accepts_pinned_v1_baseline() {
    CanonicalizationPolicy::default()
        .ensure_acceptable(DEFAULT_MAX_PAST_EPOCHS)
        .expect("pinned v1 baseline must be acceptable");
}

#[test]
fn set_convergence_policy_accepts_pinned_v1_baseline() {
    let mut engine = build_engine();
    engine
        .set_convergence_policy(CanonicalizationPolicy::default())
        .expect("pinned v1 baseline must be accepted");
}

#[cfg(not(feature = "test-policy-overrides"))]
#[test]
fn default_build_set_convergence_policy_rejects_non_pinned() {
    let mut engine = build_engine();
    let err = engine
        .set_convergence_policy(CanonicalizationPolicy {
            settlement_quiescence_ms: 0,
            ..CanonicalizationPolicy::default()
        })
        .expect_err("normal builds must reject non-v1 policies");
    assert!(
        matches!(err, OpenMlsProjectionError::InvalidPolicy(_)),
        "expected InvalidPolicy, got {err:?}"
    );
}

#[cfg(not(feature = "test-policy-overrides"))]
#[test]
fn default_build_builder_rejects_non_default_max_past_epochs() {
    let result = EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(valid_identity(b"pin-policy-epochs"))
        .account_identity_proof_signer(proof_signer(b"pin-policy-epochs"))
        .peeler(Box::new(StubPeeler))
        .max_past_epochs(1)
        .build();
    match result {
        Err(EngineError::Other(_)) => {}
        Ok(_) => panic!("normal builds must pin max_past_epochs to v1"),
        Err(err) => panic!("expected EngineError::Other, got {err:?}"),
    }
}
